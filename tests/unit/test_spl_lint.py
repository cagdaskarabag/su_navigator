import contextlib
import dataclasses
import io
import json
import os
import sys
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.spl.lint import RULES, lint, lint_search
from splunk_ucm.util import git_blob_sha
from splunk_ucm.validation.service import ValidationService
from unit.test_selection_validation import FakeParser, discovered

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import spl_lint_corpus  # noqa: E402


def rules(spl):
    return [f["rule"] for f in lint(spl)]


def only(spl, rule):
    found = [f for f in lint(spl) if f["rule"] == rule]
    assert len(found) == 1, (spl, lint(spl))
    return found[0]


class SearchTermFunctionTest(unittest.TestCase):
    def test_match_in_the_base_search(self):
        spl = ('index=xd (sourcetype="citrix:broker:events" event_type=Provisioning* '
               'OR match(_raw, "(?i)identity|prep|MCS")) OR (index=xd source=x) | stats count')
        f = only(spl, "L001")
        self.assertEqual((f["segment"], f["command"], f["severity"], f["in_map"]), (1, "search", "warning", 0))
        self.assertEqual(f["call"], 'match(_raw, "(?i)identity|prep|MCS")')
        self.assertIn('| where match(_raw, "(?i)identity|prep|MCS")', f["suggestion"])
        self.assertEqual(f["name"], RULES["L001"])

    def test_match_in_a_search_command(self):
        f = only('index=a | search match(_raw, "x") | stats count', "L001")
        self.assertEqual((f["segment"], f["command"]), (2, "search"))

    def test_other_eval_functions_are_read_as_words_too(self):
        for call in ('like(_raw,"%x%")', 'cidrmatch("10.0.0.0/8", src)', "isnotnull(user)", "isnull(user)",
                     'lower(user)="a"', 'len(user)>3', 'searchmatch("a b")'):
            self.assertEqual(rules("index=a %s | stats count" % call), ["L001"], call)

    def test_not_and_or_forms(self):
        self.assertEqual(rules('index=a NOT match(_raw,"x")'), ["L001"])
        self.assertEqual(rules('index=a (user=b OR match(_raw,"x"))'), ["L001"])

    def test_subsearch_and_multisearch_clauses(self):
        spl = ('| multisearch [ search index=a match(_raw,"x") | eval k=1 ] '
               '[ search index=b user=u | eval k=2 ] | stats count')
        f = only(spl, "L001")
        self.assertEqual(f["segment"], 1)
        f = only('index=a [ search index=b match(_raw,"x") | fields host ] | stats count', "L001")
        self.assertEqual(f["segment"], 1)
        self.assertEqual(rules('index=a [ search index=b | fields host ] | stats count'), [])

    def test_clause_after_a_subsearch_belongs_to_the_same_command(self):
        self.assertEqual(rules('index=a [ search index=b | fields host ] match(_raw,"x")'), ["L001"])
        self.assertEqual(rules('index=a | where host IN [ search index=b | fields host ] AND match(_raw,"x")'), [])

    def test_nested_calls_are_one_finding(self):
        f = only('index=a | search match(lower(_raw), "x")', "L001")
        self.assertEqual(f["call"], 'match(lower(_raw), "x")')

    def test_repeated_calls_count_once_per_segment_and_function(self):
        f = only('index=a (match(_raw,"x") OR match(_raw,"y") OR match(_raw,"z"))', "L001")
        self.assertEqual(f["count"], 3)

    def test_no_findings_where_the_function_is_evaluated(self):
        for spl in ('index=a | where match(_raw, "x")',
                    'index=a | eval hit=match(_raw, "x")',
                    'index=a | eval hit=if(match(_raw, "x"), 1, 0) | stats count',
                    'index=a | where like(user, "a%") OR cidrmatch("10.0.0.0/8", src)',
                    'index=a | where isnotnull(user) AND len(user)>2',
                    'index=a | eval x=case(match(_raw,"a"),1,true(),0) | where lower(user)="a"',
                    '| tstats count where index=a by host | where match(host, "^x")',
                    '| makeresults | eval t=match("abc","b")',
                    'index=a | stats count by user | where match(user,"x") | eval f=if(isnull(user),1,0)',
                    'index=a | eval f=mvfilter(match(tags,"x"))',
                    'index=a | foreach * [ eval <<FIELD>>=lower(<<FIELD>>) ]'):
            self.assertEqual(rules(spl), [], spl)

    def test_quoted_text_and_macros_are_not_code(self):
        for spl in ('index=a "match(_raw, x)" | stats count',
                    'index=a msg="isnull(x) and like(y)" | stats count',
                    '`my_macro(match(a,b))` index=a',
                    '`comment("match(_raw,\\"x\\") timechart count by a, b")` index=a | stats count',
                    'index=a | rex field=_raw "(?<m>match\\(x\\))" | stats count',
                    'index=a field=lower(x)',
                    'index=a user=*match(x)'):
            self.assertEqual(rules(spl), [], spl)

    def test_a_term_named_like_a_function_without_a_call_is_not_flagged(self):
        self.assertEqual(rules("index=a match=1 like=2 lower"), [])
        self.assertEqual(rules("index=a rematch(x) user.lower(y)"), [])

    def test_in_is_not_treated_as_a_function(self):
        self.assertEqual(rules('index=a user IN("a","b") | stats count'), [])
        self.assertEqual(rules('index=a case(x)=y TERM(a)'), [])

    def test_map_search_is_linted_as_its_own_search(self):
        spl = 'index=a | map search="search index=b match(_raw,\\"x\\") user=$user$" maxsearches=5'
        f = only(spl, "L001")
        self.assertEqual((f["segment"], f["in_map"]), (2, 1))
        spl = 'index=a | map search="search index=b | where match(_raw,\\"x\\") user=$user$"'
        self.assertEqual(rules(spl), [])
        deep = ('index=a | map search="search index=b | map search=\\"search index=c like(_raw,\\\\\\"%x%\\\\\\")\\""')
        self.assertEqual([f["in_map"] for f in lint(deep) if f["rule"] == "L001"], [2])

    def test_sample_corpus_cases(self):
        uc_2_6_39 = 'index=xd sourcetype="citrix:x" earliest=-4h | search match(_raw, "(?i)restart|reboot")\n| stats count by host'
        self.assertEqual(rules(uc_2_6_39), ["L001"])
        uc_5_7_18 = 'index=netflow earliest=-24h (protocol=6 OR upper(protocol)="TCP")\n| stats count'
        self.assertEqual(rules(uc_5_7_18), ["L001"])


class TimechartTest(unittest.TestCase):
    def test_two_split_by_fields(self):
        f = only("index=a | timechart span=1h count by reason, user_principal", "L002")
        self.assertEqual((f["segment"], f["command"], f["call"]), (2, "timechart", "by reason, user_principal"))
        self.assertIn("stats <same aggregation> by _time, reason, user_principal", f["suggestion"])

    def test_forms_splunk_rejects(self):
        for tail in ("by a b", "by a,b", "by a, b, c", 'by "a", "b"', "by a, b limit=3", "by a b useother=f"):
            self.assertEqual(rules("index=x | timechart span=5m count %s" % tail), ["L002"], tail)
        self.assertEqual(rules("index=x | sitimechart span=5m count by a, b"), ["L002"])

    def test_valid_forms(self):
        for spl in ("index=x | timechart span=1h count by a",
                    "index=x | timechart span=1h count by a limit=3 useother=f",
                    "index=x | timechart span=1h count by a where count in top5",
                    "index=x | timechart span=1h count by eval(a . \",\" . b)",
                    "index=x | timechart span=1h count, avg(v) by a",
                    "index=x | timechart span=1h count(eval(a=\"by x, y\")) by z",
                    "index=x | timechart span=1h count",
                    "index=x | chart count by a, b",
                    "index=x | chart count over a by b",
                    "index=x | stats count by a, b"):
            self.assertEqual(rules(spl), [], spl)

    def test_inside_map(self):
        spl = 'index=a | map search="search index=b | timechart count by x, y"'
        f = only(spl, "L002")
        self.assertEqual((f["segment"], f["in_map"]), (2, 1))


class ArgumentCountTest(unittest.TestCase):
    def test_wrong_number_of_arguments(self):
        f = only('index=a | where match(VolumeName, "Cache|WCD", "i") OR 1=1', "L003")
        self.assertEqual((f["segment"], f["command"]), (2, "where"))
        self.assertIn("called with 3", f["message"])
        self.assertIn("(?i)", f["suggestion"])
        self.assertEqual(rules("index=a | eval x=match(a)"), ["L003"])
        self.assertEqual(rules('index=a | eval x=like(a, "b%", "c")'), ["L003"])
        self.assertEqual(rules('index=a | where cidrmatch("10.0.0.0/8")'), ["L003"])
        self.assertEqual(rules("index=a | eval x=match()"), ["L003"])

    def test_correct_calls(self):
        for spl in ('index=a | where match(f, "x")', 'index=a | where match(f, "a,b") ',
                    'index=a | eval x=match(coalesce(a,b), "x")', 'index=a | where like(f, "a%")',
                    'index=a | where cidrmatch("10.0.0.0/8", src)',
                    'index=a | where match(f, "x") AND match(g, if(a, "b", "c"))'):
            self.assertEqual(rules(spl), [], spl)

    def test_in_a_search_clause_only_the_search_term_finding_applies(self):
        self.assertEqual(rules('index=a match(_raw, "x", "i")'), ["L001"])
        self.assertEqual(rules('index=a | search match(path, "abc\\\\")'), ["L001"])


class TrailingBackslashTest(unittest.TestCase):
    def test_regex_ending_in_one_backslash(self):
        f = only('index=a | eval n=replace(TargetObject,"^.*\\\\","")', "L004")
        self.assertEqual(f["command"], "eval")
        self.assertIn('"...\\\\\\\\"', f["suggestion"])
        self.assertEqual(rules('index=a | where match(path,"abc\\\\")'), ["L004"])
        self.assertEqual(rules('index=a | eval n=replace(x,"a\\\\\\\\\\\\","")'), ["L004"])
        self.assertEqual(rules('index=a | eval n=replace(x,"a\\\\","b")'), ["L004"])

    def test_valid_endings(self):
        for spl in ('index=a | eval n=replace(x,"^.*\\\\\\\\","")',
                    'index=a | eval n=replace(x,"\\\\[^\\\\]+$","")',
                    'index=a | eval n=replace(x,"\\\\d+","")',
                    'index=a | eval n=replace(x,"a","\\\\")',
                    'index=a | eval n=replace(x,"a\\\\\\\\\\\\\\\\","")',
                    'index=a | where match(path,"abc\\"")',
                    'index=a | where match(path, pattern_field)',
                    'index=a | rex field=_raw "a\\\\"'):
            self.assertEqual(rules(spl), [], spl)


class TimeSnapTest(unittest.TestCase):
    def test_snap_to_a_count_of_units(self):
        f = only("| tstats count where index=a earliest=-6h@5m latest=now by host", "L005")
        self.assertEqual((f["command"], f["call"]), ("tstats", "earliest=-6h@5m"))
        self.assertIn("-6h@m", f["suggestion"])
        self.assertEqual(rules("index=a earliest=-1d@1d | stats count"), ["L005"])
        self.assertEqual(rules('index=a latest="-1h@15m" | stats count'), ["L005"])
        self.assertEqual(rules("index=a earliest=-1w@w8 | stats count"), ["L005"])
        self.assertEqual(rules("index=a | search earliest=-30d@0d"), ["L005"])

    def test_valid_modifiers(self):
        for spl in ("index=a earliest=-6h@m latest=now", "index=a earliest=-1d@d+2h latest=@d",
                    "index=a earliest=-1w@w1 latest=-1w@w7", "index=a earliest=-1mon@mon", "index=a earliest=-1y@y",
                    "index=a earliest=-24h latest=-5m@m", "index=a earliest=-1d@qtr",
                    '| tstats count where index=a earliest=-15m@m',
                    'index=a msg="earliest=-6h@5m"', 'index=a | eval x="latest=-1h@5m"',
                    "index=a user=a@5m.example.com"):
            self.assertEqual(rules(spl), [], spl)


class ShapeTest(unittest.TestCase):
    def test_empty_and_clean_searches(self):
        for spl in ("", "   ", None, "index=a | stats count by host", "| makeresults", "`macro`"):
            self.assertEqual(lint(spl), [], spl)

    def test_findings_are_ordered_and_json_ready(self):
        spl = ('index=a match(_raw,"x") earliest=-1h@5m | timechart count by a, b | where match(a,"x","i")')
        found = lint(spl)
        self.assertEqual([f["rule"] for f in found], ["L001", "L005", "L002", "L003"])
        self.assertEqual([f["segment"] for f in found], [1, 1, 2, 3])
        json.dumps(found)
        for f in found:
            self.assertEqual(sorted(f), ["call", "command", "count", "in_map", "message", "name", "rule",
                                         "segment", "severity", "suggestion"])
            self.assertEqual(f["severity"], "warning")

    def test_long_calls_are_shortened(self):
        f = only('index=a match(_raw, "%s")' % ("x" * 400), "L001")
        self.assertLessEqual(len(f["call"]), 120)

    def test_lint_search_marks_the_search_and_keeps_going(self):
        found = lint_search('index=a match(_raw,"x")', 'index=b | timechart count by a, b')
        self.assertEqual([(f["search"], f["rule"]) for f in found], [("primary", "L001"), ("cim", "L002")])
        self.assertEqual(lint_search(None, None), [])

    def test_unbalanced_input_does_not_raise(self):
        for spl in ('index=a match(_raw,', 'index=a ] [ match(x', 'index=a "unterminated match(x', '|||', '`', '[[[',
                    'index=a | map search="search index=b match(_raw,'):
            lint_search(spl)

    def test_lint_leaves_the_tokenizer_helpers_alone(self):
        from splunk_ucm.spl.analysis import analyze
        before = analyze('index=a match(_raw,"x") | stats count').commands
        lint('index=a match(_raw,"x") | stats count')
        self.assertEqual(analyze('index=a match(_raw,"x") | stats count').commands, before)


class ValidationServiceLintTest(unittest.TestCase):
    def setUp(self):
        self.store = discovered()
        self.svc = ValidationService(self.store, AuditService(self.store), FakeParser())

    def parse(self, spl, cim=None):
        uc = self.svc._load("fenre:UC-9.1.1")
        return self.svc._parse_use_case(dataclasses.replace(uc, spl=spl, cim_spl=cim or ""))

    def test_findings_are_in_the_validation_result_and_do_not_touch_gates(self):
        clean = self.parse('index=a | where match(_raw, "x") | stats count')
        dirty = self.parse('index=a match(_raw, "x") | timechart count by a, b')
        self.assertEqual(clean["lint"], [])
        self.assertEqual([f["rule"] for f in dirty["lint"]], ["L001", "L002"])
        for key in ("parse_ok", "side_effects", "review_commands", "unknown_commands", "indirect_commands",
                    "high_cost", "commands"):
            self.assertEqual(clean[key], dirty[key], key)
        self.assertEqual(clean["warnings"], dirty["warnings"])

    def test_cim_search_is_linted_and_marked(self):
        doc = self.parse('index=a | stats count', cim='index=b match(_raw,"x")')
        self.assertEqual([(f["search"], f["rule"]) for f in doc["lint"]], [("cim", "L001")])

    def test_findings_are_stored_and_served(self):
        uc = self.svc._load("fenre:UC-9.1.1")
        self.assertEqual(self.svc.parse_only("fenre:UC-9.1.1", "alice")["lint"], lint_search(uc.spl, uc.cim_spl))
        self.assertEqual(self.svc.get("fenre:UC-9.1.1")["lint"], lint_search(uc.spl, uc.cim_spl))

    def test_search_without_spl_has_an_empty_list(self):
        self.assertEqual(self.parse("")["lint"], [])


class ApiLintTest(unittest.TestCase):
    def test_validate_and_get_validation_return_the_findings(self):
        from splunk_ucm.api.app import CAP_RUN_DISCOVERY
        from unit.test_api_worker import call, make_ctx
        store = discovered()
        svc = ValidationService(store, AuditService(store), FakeParser())
        uc = svc._load("fenre:UC-9.1.1")
        dirty = dataclasses.replace(uc, spl='index=a match(_raw, "x") | timechart count by a, b', cim_spl="")
        svc._load = lambda use_case_id: dirty
        ctx = make_ctx(store, [CAP_RUN_DISCOVERY])
        ctx.validation_service = lambda: svc
        status, body = call(ctx, "POST", "validate", body={"id": "fenre:UC-9.1.1", "sample": False})
        self.assertEqual(status, 200, body)
        self.assertEqual([f["rule"] for f in body["lint"]], ["L001", "L002"])
        status, stored = call(ctx, "GET", "validation", {"id": "fenre:UC-9.1.1"})
        self.assertEqual((status, stored["lint"]), (200, body["lint"]))
        for finding in body["lint"]:
            self.assertEqual(finding["severity"], "warning")
            self.assertTrue(finding["message"] and finding["suggestion"])


class DeploymentLintTest(unittest.TestCase):
    def test_revision_keeps_the_findings_and_submit_is_not_blocked(self):
        from unit.test_deployment import UC, service
        svc, store, saved = service()
        view = svc.save_draft("alice", UC, {"spl_source": "custom",
                                            "custom_spl": 'index=main match(_raw, "x") | timechart count by a, b'})
        rev = view["revisions"][-1]
        self.assertEqual([f["rule"] for f in rev["lint"]], ["L001", "L002"])
        clean = svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": "index=main | stats count"})
        self.assertEqual(clean["revisions"][-1]["lint"], [])
        svc.save_draft("alice", UC, {"spl_source": "custom",
                                     "custom_spl": 'index=main match(_raw, "x") | stats count'})
        self.assertEqual(svc.submit("alice", UC)["state"], "pending_approval")


class CorpusToolTest(unittest.TestCase):
    def test_bundle_measurement_over_the_fixture_records(self):
        bundle = helpers.fixture_bundle()
        report = spl_lint_corpus.measure("fixture", bundle, 2)
        self.assertGreater(report["searches"], 5)
        self.assertEqual(set(report["searches_per_rule"]), set(RULES))
        self.assertEqual(report["searches_with_findings"], len({
            (f["use_case"], f["search"]) for f in report["findings"]}))

    def test_cli_writes_the_findings(self):
        bundle = helpers.fixture_bundle()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "b.json")
            out = os.path.join(tmp, "out.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(spl_lint_corpus.main(["--bundle", path, "--output", out]), 0)
            with open(out, "r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)[0]["source"], "b.json")

    def test_a_synthetic_bundle_counts_each_search_once_per_rule(self):
        bundle = helpers.fixture_bundle(record_ids=["9.1.1"])
        for record in bundle["records"]:
            content = json.loads(record["content"])
            content["spl"] = 'index=a (match(_raw,"x") OR match(_raw,"y")) | timechart count by a, b'
            record["content"] = json.dumps(content)
            record["blob_sha"] = git_blob_sha(record["content"].encode("utf-8"))
        report = spl_lint_corpus.measure("synthetic", bundle, 1)
        self.assertEqual(report["searches_per_rule"]["L001"], 1)
        self.assertEqual(report["searches_per_rule"]["L002"], 1)
        self.assertEqual(report["findings_per_rule"]["L001"], 1)


if __name__ == "__main__":
    unittest.main()

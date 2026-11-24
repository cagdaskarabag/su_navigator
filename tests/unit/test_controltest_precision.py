import calendar
import json
import os
import shutil
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.deployment import controltest as ct
from splunk_ucm.deployment.service import DeploymentService, DeploymentSettings
from splunk_ucm.errors import StorageError, UcmError, UnsupportedOperation, ValidationError
from splunk_ucm.platform.search import SearchClient, SearchFailed
from splunk_ucm.storage import collections as C
from unit.test_controltest import CLOCK, FakeSplunk, fixture, runner
from unit.test_deployment import FakeSavedSearches, UC, approved
from unit.test_discovery import loaded_catalog
from unit.test_platform_search import SplunkdOneshot
from unit.test_selection_validation import FakeParser

SPL = 'index=ids sourcetype=snort:alert | search "hit" | stats count'


def epoch(y, mo, d, h=0, mi=0, s=0):
    return calendar.timegm((y, mo, d, h, mi, s))


class ContentErrorVerdictTest(unittest.TestCase):
    def test_a_search_error_on_the_positive_data_is_a_content_error(self):
        run, splunk = runner(splunk=FakeSplunk(error=ct.ContentError("Error in 'eval' command: bad")))
        result = run.run(SPL, fixture())
        self.assertEqual(result["status"], "content_error")
        self.assertEqual(result["phase"], "positive")
        self.assertEqual(result["reason"], "the search failed on the positive test data: Error in 'eval' command: bad")
        self.assertEqual(len(splunk.searches), 1)
        self.assertNotEqual(ct.verdict(result["positive"], result["negative"]), "content_error")

    def test_a_search_error_on_the_negative_data_names_that_phase(self):
        splunk = FakeSplunk()
        original = splunk.search

        def search(spl, marker, earliest, latest):
            if len(splunk.searches) >= 1:
                raise ct.ContentError("boom")
            return original(spl, marker, earliest, latest)
        splunk.search = search
        run, _ = runner(splunk=splunk)
        result = run.run(SPL, fixture(min_count=1))
        self.assertEqual(result["status"], "content_error")
        self.assertEqual(result["phase"], "negative")
        self.assertIsNotNone(result["positive"])
        self.assertIsNone(result["negative"])

    def test_timeouts_and_transport_errors_stay_inconclusive(self):
        for error in (TimeoutError("search timed out"), UcmError("splunkd unavailable")):
            run, _ = runner(splunk=FakeSplunk(error=error))
            result = run.run(SPL, fixture())
            self.assertEqual(result["status"], "inconclusive", error)
            self.assertNotIn("phase", result)

    def test_unindexed_data_stays_inconclusive_not_content_error(self):
        run, _ = runner(splunk=FakeSplunk(indexed=False))
        self.assertEqual(run.run(SPL, fixture())["status"], "inconclusive")

    def test_search_error_text_reads_splunkd_messages(self):
        failed = SearchFailed("search failed: x", {"messages": ["Error in 'rex' command", "second"]})
        self.assertEqual(ct._search_error_text(failed), "Error in 'rex' command; second")
        self.assertEqual(ct._search_error_text(SearchFailed("search failed: only")), "search failed: only")
        body = json.dumps({"messages": [{"type": "FATAL", "text": "Unknown search command 'zzz'."}]})
        rejected = StorageError("HTTP 400", 400, {"body": body})
        self.assertEqual(ct._search_error_text(rejected), "Unknown search command 'zzz'.")
        garbled = StorageError("HTTP 400", 400, {"body": '{"messages":[{"text":"cut \\"off\\""'})
        self.assertEqual(ct._search_error_text(garbled), 'cut "off"')
        empty = StorageError("HTTP 400", 400, {"body": ""})
        self.assertIn("rejected the search", ct._search_error_text(empty))
        server = StorageError("HTTP 500", 500)
        self.assertIsNone(ct._search_error_text(server))
        self.assertIsNone(ct._search_error_text(UnsupportedOperation("other")))

    def test_oneshot_error_messages_raise_search_failed(self):
        transport = SplunkdOneshot(messages=[{"type": "ERROR", "text": "Error in 'stats' command"}])
        with self.assertRaises(SearchFailed) as ctx:
            SearchClient(transport).preview("search index=x | stats", level="smart")
        self.assertEqual(transport.forms[0]["adhoc_search_level"], "smart")
        self.assertIsInstance(ctx.exception, UnsupportedOperation)
        plain = SplunkdOneshot()
        SearchClient(plain).preview("search index=x")
        self.assertEqual(plain.forms[0]["adhoc_search_level"], "fast")


class WindowTest(unittest.TestCase):
    def test_iso_with_zone_pads_one_hour_each_way(self):
        w = ct.derive_window(["2026-04-16T08:00:00Z a", "2026-04-16T09:30:00+02:00 b"], CLOCK)
        self.assertEqual(w, {"earliest": str(epoch(2026, 4, 16, 6, 30)), "latest": str(epoch(2026, 4, 16, 9)),
                             "derived": True})

    def test_zoneless_times_are_read_as_utc_and_padded_a_day(self):
        w = ct.derive_window(["2026-04-16 08:00:00 login"], CLOCK)
        self.assertEqual(w["earliest"], str(epoch(2026, 4, 15, 8)))
        self.assertEqual(w["latest"], str(epoch(2026, 4, 17, 8)))

    def test_formats_seen_in_fixtures(self):
        cases = {
            "2026-04-16T08:00:00.123Z x": epoch(2026, 4, 16, 8),
            "16-04-2026 x": None,
            "04-16-2026 08:00:00.000 +0000 x": epoch(2026, 4, 16, 8),
            "2026/04/16 08:00:00 x": epoch(2026, 4, 16, 8),
            "04/16/2026 08:10:15 AM x": epoch(2026, 4, 16, 8, 10, 15),
            "04/16/2026 12:10:15 AM x": epoch(2026, 4, 16, 0, 10, 15),
            "04/16/2026 01:10:15 PM x": epoch(2026, 4, 16, 13, 10, 15),
            "04/16/26-08:00:01.123456 [**] snort": epoch(2026, 4, 16, 8, 0, 1),
            "04/16-08:00:01 x": None,
            "Thu Apr 16 08:00:00 2026 x": epoch(2026, 4, 16, 8),
            "Apr 16 08:00:00 host sshd": epoch(2026, 4, 16, 8),
        }
        for text, want in cases.items():
            got = ct._event_time(text, epoch(2026, 6, 1))
            if want is None:
                self.assertIsNone(got, text)
            else:
                self.assertEqual(got[0], want, text)

    def test_zone_is_reported_with_the_time(self):
        self.assertTrue(ct._event_time("2026-04-16T08:00:00Z", CLOCK)[1])
        self.assertFalse(ct._event_time("2026/04/16 08:00:00", CLOCK)[1])

    def test_yearless_syslog_uses_the_current_year_or_the_previous_one(self):
        now = epoch(2026, 4, 20)
        self.assertEqual(ct._event_time("Apr 16 08:00:00 h", now)[0], epoch(2026, 4, 16, 8))
        self.assertEqual(ct._event_time("Dec 31 23:00:00 h", now)[0], epoch(2025, 12, 31, 23))

    def test_a_time_beyond_the_first_128_characters_is_ignored(self):
        self.assertIsNone(ct._event_time("x" * 130 + " 2026-04-16T08:00:00Z", CLOCK))
        self.assertIsNotNone(ct._event_time("x" * 100 + " 2026-04-16T08:00:00Z", CLOCK))

    def test_an_event_without_a_time_is_indexed_now_so_the_window_stays_open_ahead(self):
        w = ct.derive_window(["2026-04-16T08:00:00Z a", "no time here"], CLOCK)
        self.assertTrue(w["derived"])
        self.assertEqual(w["earliest"], str(epoch(2026, 4, 16, 7)))
        self.assertEqual(w["latest"], ct.WINDOW_LATEST)

    def test_no_parseable_time_gives_todays_wide_window(self):
        self.assertEqual(ct.derive_window(["a", "b"], CLOCK),
                         {"earliest": ct.WINDOW_EARLIEST, "latest": ct.WINDOW_LATEST, "derived": False})
        self.assertFalse(ct.derive_window([], CLOCK)["derived"])

    def test_an_impossible_date_is_not_a_time(self):
        self.assertIsNone(ct._event_time("2026-13-45T08:00:00Z", CLOCK))
        self.assertIsNone(ct._event_time("Foo 16 08:00:00 x", CLOCK))

    def test_the_runner_passes_the_derived_window_to_the_search(self):
        run, splunk = runner()
        run.run(SPL, fixture(positive="2026-04-16T08:00:00Z hit\n2026-04-16T09:00:00Z hit\n", negative="", min_count=1))
        self.assertEqual(splunk.windows[0], (str(epoch(2026, 4, 16, 7)), str(epoch(2026, 4, 16, 10))))

    def test_the_runner_falls_back_when_the_fixture_has_no_times(self):
        run, splunk = runner()
        result = run.run(SPL, fixture(negative="", min_count=1))
        self.assertEqual(splunk.windows[0], (ct.WINDOW_EARLIEST, ct.WINDOW_LATEST))
        self.assertFalse(result["positive"]["window"]["derived"])

    def test_the_window_is_recorded_for_both_runs(self):
        run, _ = runner()
        result = run.run(SPL, fixture(positive="2026-04-16T08:00:00Z hit\n", negative="2026-04-16T08:00:00Z miss\n",
                                      min_count=1))
        self.assertTrue(result["positive"]["window"]["derived"])
        self.assertTrue(result["negative"]["window"]["derived"])


class SplitEventsTest(unittest.TestCase):
    def test_a_block_without_a_time_continues_the_event_when_the_file_starts_with_one(self):
        text = ("04/16/2026 08:10:15 AM\nLogName=Security\nMessage=failed\n\nSubject:\n  Account: x\n\n"
                "04/16/2026 08:11:00 AM\nLogName=Security\n\nSubject:\n  Account: y\n")
        events = ct.split_events(text)
        self.assertEqual(len(events), 2)
        self.assertIn("Subject:\n  Account: x", events[0])
        self.assertTrue(events[1].startswith("04/16/2026 08:11:00 AM"))

    def test_blocks_stay_separate_when_the_file_does_not_start_with_a_time(self):
        self.assertEqual(ct.split_events("alpha\nline\n\nbeta\n"), ["alpha\nline", "beta"])

    def test_single_line_events_are_unchanged(self):
        self.assertEqual(ct.split_events("2026-04-16T08:00:00Z a\n2026-04-16T08:00:01Z b\n"),
                         ["2026-04-16T08:00:00Z a", "2026-04-16T08:00:01Z b"])


class FieldAssertionTest(unittest.TestCase):
    def test_values_pass_on_any_overlap_and_fail_otherwise(self):
        rows = [{"host": "a"}, {"host": "b"}]
        ok = ct.assert_fields(rows, [{"name": "host", "values": ["b", "z"]}])
        self.assertTrue(ok[0]["pass"])
        bad = ct.assert_fields(rows, [{"name": "host", "values": ["z"]}])
        self.assertFalse(bad[0]["pass"])
        self.assertIn("expected one of ['z'], saw ['a', 'b']", bad[0]["failures"][0])
        self.assertTrue(bad[0]["present"])

    def test_numeric_bounds_run_over_the_numeric_values(self):
        rows = [{"n": "5"}, {"n": "oops"}, {"n": 12.5}]
        self.assertTrue(ct.assert_fields(rows, [{"name": "n", "min": 5, "max": 13}])[0]["pass"])
        low = ct.assert_fields(rows, [{"name": "n", "min": 6}])[0]
        self.assertIn("min=5.0 is below expected min 6", low["failures"][0])
        high = ct.assert_fields(rows, [{"name": "n", "max": 10}])[0]
        self.assertIn("max=12.5 is above expected max 10", high["failures"][0])
        none = ct.assert_fields([{"n": "x"}], [{"name": "n", "min": 1}])[0]
        self.assertEqual(none["failures"], ["no numeric values in 1 results"])

    def test_regex_passes_on_any_match(self):
        rows = [{"p": "C:\\Windows\\a.exe"}, {"p": "other"}]
        self.assertTrue(ct.assert_fields(rows, [{"name": "p", "regex": r"\\Windows\\"}])[0]["pass"])
        miss = ct.assert_fields(rows, [{"name": "p", "regex": "^zzz"}])[0]
        self.assertEqual(miss["failures"], ["no value matched regex ^zzz"])

    def test_multivalue_results_count_every_value(self):
        rows = [{"host": ["a", "b"]}]
        self.assertTrue(ct.assert_fields(rows, [{"name": "host", "values": ["b"]}])[0]["pass"])

    def test_a_missing_field_fails_and_is_reported_absent(self):
        out = ct.assert_fields([{"x": "1"}], [{"name": "host", "values": ["a"]}])[0]
        self.assertFalse(out["pass"])
        self.assertFalse(out["present"])

    def test_very_long_values_are_capped(self):
        out = ct._seen_values([{"v": "x" * 5000}], "v")
        self.assertEqual(len(out[0]), ct.MAX_VALUE_LENGTH)


class RunnerAssertionTest(unittest.TestCase):
    def row(self, event):
        return {"host": "sensor-1", "count": "7"}

    def test_field_assertions_make_a_passing_run_fail_with_the_reason(self):
        run, _ = runner(splunk=FakeSplunk(row_fields=self.row))
        fx = dict(fixture(negative="", min_count=1), fields=[{"name": "host", "values": ["other"]},
                                                              {"name": "count", "min": 1, "max": 10}])
        result = run.run(SPL, fx)
        self.assertEqual(result["status"], "failed")
        self.assertIn("field host: expected one of ['other'], saw ['sensor-1']", result["reason"])
        by_name = {f["name"]: f for f in result["positive"]["fields"]}
        self.assertFalse(by_name["host"]["pass"])
        self.assertTrue(by_name["count"]["pass"])
        self.assertFalse(result["positive"]["pass"])

    def test_passing_assertions_keep_the_pass(self):
        run, _ = runner(splunk=FakeSplunk(row_fields=self.row))
        fx = dict(fixture(negative="", min_count=1), fields=[{"name": "host", "values": ["sensor-1"]}])
        result = run.run(SPL, fx)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["positive"]["fields"][0]["pass"])

    def test_max_count_fails_when_there_are_too_many_rows(self):
        run, _ = runner()
        fx = dict(fixture(positive="hit\nhit\nhit\n", negative="", min_count=1), max_count=2)
        result = run.run(SPL, fx)
        self.assertEqual(result["status"], "failed")
        self.assertIn("positive run returned 3 rows, expected at most 2", result["reason"])
        self.assertEqual(result["positive"]["max_count"], 2)
        ok = run.run(SPL, dict(fx, max_count=3))
        self.assertEqual(ok["status"], "passed")

    def test_fixtures_stored_before_these_keys_run_as_before(self):
        run, _ = runner()
        result = run.run(SPL, fixture(negative="", min_count=1))
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("fields", result["positive"])
        self.assertNotIn("max_count", result["positive"])

    def test_field_assertions_do_not_apply_to_the_negative_run(self):
        run, _ = runner(splunk=FakeSplunk(row_fields=self.row))
        fx = dict(fixture(positive="hit\n", negative="miss\n", min_count=1), fields=[{"name": "host", "values": ["sensor-1"]}])
        result = run.run(SPL, fx)
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("fields", result["negative"])


class ManifestSubsetTest(unittest.TestCase):
    def test_flow_lists_of_quoted_and_plain_scalars(self):
        m = ct.parse_manifest('a: [x, "y, z", 3, 4.5, \'q\']\n')
        self.assertEqual(m["a"], ["x", "y, z", 3, 4.5, "q"])
        self.assertEqual(ct.parse_manifest("a: []\n")["a"], [])

    def test_double_quoted_escapes_are_yaml_escapes(self):
        m = ct.parse_manifest('r: "\\\\CurrentVersion\\\\Run"\nq: "say \\"hi\\""\nt: "a\\tb"\nu: "\\u0041"\n')
        self.assertEqual(m["r"], "\\CurrentVersion\\Run")
        self.assertEqual(m["q"], 'say "hi"')
        self.assertEqual(m["t"], "a\tb")
        self.assertEqual(m["u"], "A")

    def test_single_quotes_double_the_quote_and_keep_backslashes(self):
        self.assertEqual(ct.parse_manifest("r: 'it''s \\d'\n")["r"], "it's \\d")

    def test_comments_are_dropped_but_not_inside_quotes(self):
        m = ct.parse_manifest('a: 1 # note\nb: "x # y" # note\n# whole line\nc: [1, "#"] # t\n')
        self.assertEqual((m["a"], m["b"], m["c"]), (1, "x # y", [1, "#"]))

    def test_block_lists_of_mappings(self):
        text = ("expected:\n  fields:\n    - name: host\n      values: [a, b]\n    - name: n\n      min: 1\n"
                "      max: 2.5\n  min_count: 2\norigin: x\n")
        m = ct.parse_manifest(text)
        self.assertEqual(m["expected"]["fields"], [{"name": "host", "values": ["a", "b"]},
                                                   {"name": "n", "min": 1, "max": 2.5}])
        self.assertEqual(m["expected"]["min_count"], 2)
        self.assertEqual(m["origin"], "x")

    def test_block_lists_of_scalars_and_block_scalars_are_skipped(self):
        m = ct.parse_manifest("tags:\n  - a\n  - \"b\"\nnotes: |\n  some: text\n  more\nafter: 1\n")
        self.assertEqual(m["tags"], ["a", "b"])
        self.assertEqual(m["after"], 1)

    def test_unsupported_constructs_are_refused_not_misread(self):
        for text in ("a: &x 1\n", "a: {b: 1}\n", "a: [x, [y]]\n", "a: [x,\n  y]\n", "a:\n\tb: 1\n", "a: *x\n",
                     "a: !tag 1\n", '- x\n', 'a: ["open]\n'):
            with self.assertRaises(ct.ManifestSyntaxError, msg=text):
                ct.parse_manifest(text)

    def test_empty_manifest_is_an_empty_mapping(self):
        self.assertEqual(ct.parse_manifest("# nothing\n"), {})


class FixtureDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def make(self, expected_block, name="UC-9.1.1"):
        path = os.path.join(self.dir, name)
        os.makedirs(path)
        with open(os.path.join(path, "manifest.yaml"), "w") as fh:
            fh.write('uc_id: "9.1.1"\nsourcetype: "snort:alert"\n' + expected_block)
        with open(os.path.join(path, "positive.log"), "w") as fh:
            fh.write("hit\n")
        return path

    def test_max_count_and_fields_are_read_from_the_manifest(self):
        path = self.make("expected:\n  min_count: 2\n  max_count: 6\n  fields:\n    - name: host\n      values: [a]\n"
                         "    - name: n\n      min: 1\n    - name: bare\n")
        fx = ct.fixture_from_directory(path, "9.1.1")
        self.assertEqual((fx["min_count"], fx["max_count"]), (2, 6))
        self.assertEqual(fx["fields"], [{"name": "host", "values": ["a"]}, {"name": "n", "min": 1}])

    def test_a_manifest_without_expectations_gets_min_count_one(self):
        fx = ct.fixture_from_directory(self.make(""), "9.1.1")
        self.assertEqual(fx["min_count"], 1)
        self.assertNotIn("fields", fx)
        self.assertNotIn("max_count", fx)

    def test_unsupported_expectations_skip_the_fixture_with_a_reason(self):
        cases = {
            "expected:\n  surprise: 1\n": "unsupported keys: surprise",
            "expected:\n  max_count: -1\n": "max_count",
            "expected:\n  max_count: x\n": "max_count",
            "expected:\n  fields:\n    - name: a\n      weird: 1\n": "unsupported keys: weird",
            "expected:\n  fields:\n    - values: [a]\n": "needs a name",
            "expected:\n  fields:\n    - name: a\n      min: x\n": "min must be a number",
            "expected:\n  fields:\n    - name: a\n      regex: \"(\"\n": "does not compile",
            "expected:\n  fields:\n    - name: a\n      regex: \"(a+)+\"\n": "nested repetition",
            "expected:\n  fields:\n    - name: a\n      values: a\n": "list of scalars",
            "origin: &x 1\n": "unsupported YAML",
        }
        for block, reason in cases.items():
            root = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, root, True)
            self.dir = root
            self.make(block)
            _, report = ct.build_fixture_bundle(root)
            self.assertEqual(report["fixtures"], 0, block)
            self.assertIn(reason, report["skipped"][0]["reason"], block)

    def test_validate_bundle_checks_the_new_keys(self):
        bundle, _ = ct.build_fixture_bundle(self._built())
        good = dict(bundle["fixtures"][0], max_count=3, fields=[{"name": "host", "values": ["a"]}])
        ct.validate_bundle(dict(bundle, fixtures=[good]))
        for bad in (dict(good, max_count=-1), dict(good, max_count="3"), dict(good, fields="host"),
                    dict(good, fields=[{"name": "a", "regex": "("}]), dict(good, fields=[{"nme": "a"}]),
                    dict(good, fields=[{"name": "a", "extra": 1}])):
            with self.assertRaises(ValidationError, msg=str(bad)):
                ct.validate_bundle(dict(bundle, fixtures=[bad]))

    def _built(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        self.dir = root
        self.make("")
        return root

    def test_expectations_keep_only_the_optional_keys(self):
        self.assertEqual(ct.expectations({"uc_id": "1"}), {})
        out = ct.expectations({"uc_id": "1", "max_count": 4, "fields": [{"name": "a", "min": 1}]})
        self.assertEqual(out, {"max_count": 4, "fields": [{"name": "a", "min": 1}]})


class ScopeClauseTest(unittest.TestCase):
    def scope(self, spl):
        return ct.scope_to_test_index(spl, "t", "m")

    def test_eval_where_and_fields_keep_their_index_text(self):
        out = self.scope('index=ids x | eval index=lower(index) | where index="a" | fields index host | stats count')
        self.assertEqual(out, 'index=t source="m" x | eval index=lower(index) | where index="a" | fields index host | stats count')

    def test_quoted_index_text_is_untouched(self):
        out = self.scope('index=ids msg="index=foo bar" | stats count')
        self.assertEqual(out, 'index=t source="m" msg="index=foo bar" | stats count')

    def test_a_subsearch_search_clause_is_scoped_too(self):
        out = self.scope('index=a [ search index=b | fields user ] | stats count')
        self.assertEqual(out, 'index=t source="m" [ search index=t source="m" | fields user ] | stats count')
        out = self.scope('index=a [ index=b | head 1 | fields user ]')
        self.assertEqual(out, 'index=t source="m" [ index=t source="m" | head 1 | fields user ]')

    def test_an_index_only_in_a_non_search_command_is_refused(self):
        with self.assertRaises(ct.NotRunnable):
            self.scope('| makeresults | eval index="a"')
        with self.assertRaises(ct.NotRunnable):
            self.scope('sourcetype=x | eval index=1')

    def test_the_explicit_search_command_is_a_search_clause(self):
        out = self.scope('index=a | search index=b host=h')
        self.assertEqual(out, 'index=t source="m" | search index=t source="m" host=h')

    def test_macros_are_refused_except_comment(self):
        with self.assertRaises(ct.NotRunnable) as ctx:
            self.scope('`ids_index` index=a | stats count')
        self.assertIn("macro", str(ctx.exception))
        self.assertIn('index=t source="m"', self.scope('index=a `comment("x")` | stats count'))

    def test_breaker_words_inside_quotes_do_not_refuse_the_search(self):
        out = self.scope('index=a msg="map reduce | REST audit" | stats count by "metadata"')
        self.assertIn('index=t source="m"', out)

    def test_breaker_commands_are_refused_by_position(self):
        for spl in ('index=a | map search="search index=b"', 'index=a | rest /services/x', 'index=a | inputlookup t.csv',
                    'index=a | append [ | tstats count where index=b ]', 'index=a | join x [ | from datamodel:y ]',
                    'index=a | MAP search=x'):
            with self.assertRaises(ct.NotRunnable, msg=spl):
                self.scope(spl)

    def test_negated_and_listed_indexes_and_source_filters_are_still_refused(self):
        for spl in ('index=a NOT index=b', 'index!=a x', 'index IN (a, b) x', 'index=a source=x', 'index=a | search source="y"',
                    'index=a NOT (index=b)'):
            with self.assertRaises(ct.NotRunnable, msg=spl):
                self.scope(spl)

    def test_a_field_named_with_index_as_suffix_is_not_an_index_filter(self):
        with self.assertRaises(ct.NotRunnable):
            self.scope("my_index=a x")
        with self.assertRaises(ct.NotRunnable):
            self.scope("a.index=b x")

    def test_strip_time_terms_only_touches_search_clauses(self):
        out = ct.strip_time_terms('index=a earliest=-1h latest=now x | eval earliest=1 | search latest=-5m y')
        self.assertNotIn("earliest=-1h", out)
        self.assertIn("eval earliest=1", out)
        self.assertNotIn("latest=-5m", out)
        self.assertEqual(ct.strip_time_terms('index=a msg="earliest=-1h" x').strip(), 'index=a msg="earliest=-1h" x')

    def test_pipeline_stages_respect_quotes_and_subsearches(self):
        self.assertEqual(ct.pipeline_stages('index=a "x|y" | search [ search b | head 1 ] | stats count'),
                         ['index=a "x|y"', 'search [ search b | head 1 ]', 'stats count'])


class ServiceFieldsTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.splunk = FakeSplunk(row_fields=lambda event: {"host": "sensor-1"})
        run, _ = runner(splunk=self.splunk)
        self.svc = DeploymentService(self.store, AuditService(self.store), FakeParser(), FakeSavedSearches(),
                                     DeploymentSettings(), control_runner=run)
        approved(self.svc)
        self.svc.deploy("bob", UC)
        self.bundle = {"format": ct.FIXTURE_FORMAT, "format_version": ct.FIXTURE_VERSION, "provider": "fenre",
                       "fixtures": [{"uc_id": "9.1.1", "sourcetype": "snort:alert", "host": "sensor-1", "min_count": 1,
                                     "max_count": 5, "fields": [{"name": "host", "values": ["nope"]}],
                                     "positive": "hit\n", "negative": ""}]}

    def test_import_stores_the_assertions_and_the_test_applies_them(self):
        self.svc.import_fixtures("carol", self.bundle)
        stored = self.store.get(C.CONTROL_FIXTURES, "cf_fenre_UC-9.1.1")
        self.assertEqual(stored["max_count"], 5)
        self.assertEqual(stored["fields"], [{"name": "host", "values": ["nope"]}])
        result = self.svc.control_test("dave", UC)["control_test"]
        self.assertEqual(result["status"], "failed")
        self.assertIn("field host", result["reason"])

    def test_a_content_error_is_recorded_and_audited_as_a_failure(self):
        self.splunk.error = ct.ContentError("Error in 'eval' command")
        self.svc.import_fixtures("carol", dict(self.bundle, fixtures=[dict(self.bundle["fixtures"][0], fields=None)]))
        result = self.svc.control_test("dave", UC)["control_test"]
        self.assertEqual(result["status"], "content_error")
        self.assertEqual(result["phase"], "positive")
        events = [e for e in self.store.query(C.AUDIT, {}) if e.get("action") == "deployment.controltest"]
        self.assertEqual(events[-1]["details"]["status"], "content_error")
        self.assertEqual(events[-1]["outcome"], "failure")


if __name__ == "__main__":
    unittest.main()

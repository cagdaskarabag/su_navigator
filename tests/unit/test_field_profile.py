import unittest

import helpers  # noqa: F401

from splunk_ucm.audit import AuditService
from splunk_ucm.discovery.profile import (DEFAULT_PLACEHOLDERS, ProfileSettings, parse_placeholders, parse_profile,
                                          profile_key, profile_spl, run_profile)
from splunk_ucm.errors import ValidationError
from splunk_ucm.platform.search import SearchResult
from splunk_ucm.readiness.evidence import data_evidence, requirement_evidence
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import CategoryRepository
from unit.test_discovery import loaded_catalog


class SplTest(unittest.TestCase):
    def test_counts_filled_and_placeholder_events_per_field(self):
        spl = profile_spl("wineventlog", "WinEventLog:Security", ["EventCode", "src_ip"], ["-", "0.0.0.0"], 500)
        self.assertTrue(spl.startswith('search index=wineventlog sourcetype="WinEventLog:Security" earliest=-24h '
                                       'latest=now | head 500 | stats count as sun_events'))
        self.assertIn("sum(eval(if(isnotnull('EventCode') AND trim('EventCode')!=\"\",1,0))) as f0_filled", spl)
        self.assertIn("trim('src_ip')=\"0.0.0.0\"", spl)
        self.assertIn("as f1_placeholder", spl)

    def test_rejects_unsafe_names(self):
        ok = ["EventCode"]
        cases = [
            lambda: profile_spl("main", 'x" | delete', ok, ["-"], 10),
            lambda: profile_spl("main", "ok", ["a'b"], ["-"], 10),
            lambda: profile_spl("main", "ok", ["a) | delete"], ["-"], 10),
            lambda: profile_spl("bad index", "ok", ok, ["-"], 10),
            lambda: profile_spl("main", "ok", [], ["-"], 10),
            lambda: profile_spl("main", "ok", ok, ['x"y'], 10),
        ]
        for case in cases:
            with self.assertRaises(ValidationError):
                case()

    def test_sample_is_bounded(self):
        self.assertIn("| head 10000 |", profile_spl("main", "ok", ["a"], ["-"], 10 ** 9))
        self.assertIn("| head 1 |", profile_spl("main", "ok", ["a"], ["-"], 0))

    def test_placeholder_config(self):
        self.assertEqual(parse_placeholders(""), DEFAULT_PLACEHOLDERS)
        self.assertEqual(parse_placeholders(" -, n/a ,"), ("-", "n/a"))
        with self.assertRaises(ValidationError):
            parse_placeholders('a"b')


class ParseTest(unittest.TestCase):
    def test_rates(self):
        row = {"sun_events": "200", "f0_filled": "150", "f0_placeholder": "20", "f1_filled": "0", "f1_placeholder": "0"}
        out = parse_profile(row, ["src", "dest"])
        self.assertEqual(out[0], {"field": "src", "sample_size": 200, "fill_rate": 0.75, "placeholder_rate": 0.1})
        self.assertEqual(out[1]["fill_rate"], 0.0)

    def test_no_events_means_no_profile(self):
        self.assertEqual(parse_profile({"sun_events": "0"}, ["a"]), [])

    def test_keys_are_stable_and_safe(self):
        self.assertEqual(profile_key("i", "s", "f"), profile_key("i", "s", "f"))
        self.assertNotEqual(profile_key("i", "s", "f"), profile_key("i", "s", "g"))
        self.assertRegex(profile_key("i", "s", "f"), r"^fp_[0-9a-f]{40}$")


class FakeSearch:
    def __init__(self, fill=0.9, fail=False):
        self.calls = []
        self.fill = fill
        self.fail = fail

    def oneshot(self, spl, timeout=60.0, max_count=5000, **kw):
        self.calls.append(spl)
        if self.fail:
            from splunk_ucm.errors import UnsupportedOperation
            raise UnsupportedOperation("no search")
        events = 100
        return SearchResult([{"sun_events": str(events), "f0_filled": str(int(events * self.fill)),
                              "f0_placeholder": "0"}], [], False)


class RunTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "pair:x", "kind": "pair", "status": "active",
                                                  "index": "os", "sourcetype": "cpu", "window_count": 42})
        self.store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "pair:y", "kind": "pair", "status": "active",
                                                  "index": "other", "sourcetype": "cpu", "window_count": 1})

    def run_job(self, search, job="job1", **kw):
        cats = CategoryRepository(self.store)
        return run_profile(self.store, search, cats, ProfileSettings(**kw), job)

    def test_targets_come_from_active_use_cases_and_profile_the_busiest_index(self):
        search = FakeSearch()
        summary = self.run_job(search)
        self.assertGreaterEqual(summary["sourcetypes"], 1, summary)
        self.assertTrue(all("index=os " in c for c in search.calls), search.calls)
        rows = self.store.query(C.FIELD_PROFILE, {"sourcetype": "cpu"})
        self.assertTrue(rows)
        self.assertEqual({r["index"] for r in rows}, {"os"})
        self.assertEqual(rows[0]["fill_rate"], 0.9)
        self.assertEqual(rows[0]["job_id"], "job1")
        self.assertNotIn("raw", rows[0])

    def test_disabled_runs_nothing(self):
        search = FakeSearch()
        summary = self.run_job(search, enabled=False)
        self.assertEqual(search.calls, [])
        self.assertFalse(summary["enabled"])

    def test_sourcetype_cap_and_budget(self):
        search = FakeSearch()
        summary = self.run_job(search, max_sourcetypes=0)
        self.assertEqual(search.calls, [])
        summary = self.run_job(FakeSearch(), budget_seconds=-1)
        self.assertTrue(summary["budget_exhausted"] or summary["sourcetypes"] == 0)

    def test_failed_search_is_counted_and_nothing_stored(self):
        summary = self.run_job(FakeSearch(fail=True))
        self.assertGreaterEqual(summary["errors"], 1)
        self.assertEqual(self.store.query(C.FIELD_PROFILE, {}), [])

    def test_reprofiling_replaces_old_rows_for_the_sourcetype(self):
        self.run_job(FakeSearch(fill=0.9), job="job1")
        first = self.store.query(C.FIELD_PROFILE, {"sourcetype": "cpu"})
        self.run_job(FakeSearch(fill=0.2), job="job2")
        rows = self.store.query(C.FIELD_PROFILE, {"sourcetype": "cpu"})
        self.assertEqual(len(rows), len(first))
        self.assertTrue(all(r["job_id"] == "job2" for r in rows), rows)


class EvidenceTest(unittest.TestCase):
    def field(self, fill, placeholder=0.0):
        return {"type": "field", "value": "src_ip", "status": "unverified", "code": "not_sampled",
                "level": "required", "profile": {"fill_rate": fill, "placeholder_rate": placeholder,
                                                 "sample_size": 100, "sourcetype": "s", "index": "i"}}

    def test_profile_decides_when_present(self):
        self.assertEqual(requirement_evidence(self.field(0.9)), "seen")
        self.assertEqual(requirement_evidence(self.field(0.3)), "missing")
        self.assertEqual(requirement_evidence(self.field(0.9, placeholder=0.5)), "missing")

    def test_missing_fields_are_listed(self):
        ev = data_evidence([self.field(0.1), {"type": "field", "value": "ok", "status": "met", "code": "x",
                                             "level": "required"}])
        self.assertEqual(ev["missing_fields"], ["src_ip"])
        self.assertEqual(ev["state"], "partial")
        self.assertEqual(ev["missing"][0]["fill_rate"], 0.1)

    def test_without_a_profile_the_old_rule_applies(self):
        r = {"type": "field", "value": "a", "status": "unverified", "code": "not_sampled", "level": "required"}
        self.assertEqual(requirement_evidence(r), "unverified")


if __name__ == "__main__":
    unittest.main()

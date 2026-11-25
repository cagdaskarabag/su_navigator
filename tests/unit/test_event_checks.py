import unittest
from unittest import mock

import helpers  # noqa: F401

from splunk_ucm.discovery import events as E
from splunk_ucm.discovery.events import EventCheckSettings, event_key, event_spl, run_event_checks
from splunk_ucm.errors import UnsupportedOperation, ValidationError
from splunk_ucm.platform.search import SearchResult
from splunk_ucm.readiness.evaluators import EvaluationSettings, MET, PARTIAL, UNVERIFIED, eval_event_condition
from splunk_ucm.readiness.evidence import data_evidence, requirement_evidence
from splunk_ucm.readiness.snapshot import EnvironmentSnapshot
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore

STATE = {"last_completed_at": "2026-11-20T09:00:00Z", "splunk_version": "10.2.9", "earliest": "-7d", "latest": "now"}
TRIPLE = ("aws:cloudtrail", "eventName", "DescribeImageScanFindings")


def req(**over):
    attrs = {"sourcetype": TRIPLE[0], "field": TRIPLE[1], "value": TRIPLE[2]}
    attrs.update(over)
    return {"req_id": "e1", "type": "event_condition", "value": "x", "level": "recommended",
            "source": "provider_structured", "confidence": "low", "attributes": attrs}


def pair(st=TRIPLE[0], index="aws", count=500):
    return {"kind": "pair", "index": index, "sourcetype": st, "window_count": count, "age_seconds": 60, "status": "active"}


def checked(count, window=7):
    return {"index": "aws", "sourcetype": TRIPLE[0], "field": TRIPLE[1], "value": TRIPLE[2], "count": count,
            "window_days": window, "evaluated_at": "2026-11-20T09:00:00Z"}


class SplTest(unittest.TestCase):
    def test_search_is_bounded_and_narrowed_by_the_text_term(self):
        spl = event_spl("aws", *TRIPLE, 7)
        self.assertEqual(spl, '| search index=aws sourcetype="aws:cloudtrail" "DescribeImageScanFindings" '
                              'eventName="DescribeImageScanFindings" earliest=-7d latest=now | head 100 | '
                              'stats count as sun_hits')

    def test_window_is_clamped(self):
        self.assertIn("earliest=-365d", event_spl("aws", *TRIPLE, 10 ** 6))
        self.assertIn("earliest=-1d", event_spl("aws", *TRIPLE, 0))

    def test_rejects_unsafe_input(self):
        cases = [("bad index", "s", "f", "v"), ("aws", 'a" | delete', "f", "v"), ("aws", "s", "f) | x", "v"),
                 ("aws", "s", "f", 'v" OR 1=1'), ("aws", "s", "f", "v|x"), ("aws", "s", "f", "")]
        for args in cases:
            with self.assertRaises(ValidationError, msg=args):
                event_spl(args[0], args[1], args[2], args[3], 7)

    def test_keys_are_stable_and_case_insensitive(self):
        self.assertEqual(event_key("A", "f", "V"), event_key("a", "F", "v"))
        self.assertRegex(event_key(*TRIPLE), r"^ev_[0-9a-f]{40}$")


class FakeSearch:
    def __init__(self, hits=12, fail=False, empty=False):
        self.calls, self.hits, self.fail, self.empty = [], hits, fail, empty

    def oneshot(self, spl, timeout=60.0, max_count=5000, **kw):
        self.calls.append(spl)
        if self.fail:
            raise UnsupportedOperation("no search")
        return SearchResult([] if self.empty else [{"sun_hits": str(self.hits)}], [], False)


class RunTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "p1", "kind": "pair", "status": "active", "index": "aws",
                                                  "sourcetype": TRIPLE[0], "window_count": 90})
        self.store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "p2", "kind": "pair", "status": "active", "index": "other",
                                                  "sourcetype": TRIPLE[0], "window_count": 1})
        self.patch = mock.patch.object(E, "targets", return_value=[(TRIPLE, 3), (("not:seen", "f", "v"), 1)])
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def run_job(self, search, **kw):
        return run_event_checks(self.store, search, None, EventCheckSettings(**kw), "job1", 7)

    def test_busiest_index_is_searched_and_only_the_count_is_stored(self):
        search = FakeSearch(hits=12)
        summary = self.run_job(search)
        self.assertEqual((summary["checked"], summary["seen"], summary["skipped"]), (1, 1, 1))
        self.assertTrue(all("index=aws " in c for c in search.calls), search.calls)
        rows = self.store.query(C.EVENT_CHECK, {})
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["count"], rows[0]["window_days"], rows[0]["job_id"]), (12, 7, "job1"))

    def test_zero_hits_is_stored_as_not_seen(self):
        summary = self.run_job(FakeSearch(hits=0))
        self.assertEqual((summary["seen"], summary["not_seen"]), (0, 1))
        self.assertEqual(self.store.query(C.EVENT_CHECK, {})[0]["count"], 0)

    def test_count_is_capped_at_the_search_limit(self):
        self.run_job(FakeSearch(hits=10 ** 6))
        self.assertEqual(self.store.query(C.EVENT_CHECK, {})[0]["count"], 100)

    def test_disabled_budget_and_failures(self):
        search = FakeSearch()
        self.assertFalse(self.run_job(search, enabled=False)["enabled"])
        self.assertEqual(search.calls, [])
        self.assertTrue(self.run_job(search, budget_seconds=-1)["budget_exhausted"])
        self.assertEqual(search.calls, [])
        self.assertEqual(self.run_job(FakeSearch(fail=True))["errors"], 1)
        self.assertEqual(self.run_job(FakeSearch(empty=True))["errors"], 1)
        self.assertEqual(self.store.query(C.EVENT_CHECK, {}), [])


class EvaluatorTest(unittest.TestCase):
    def evaluate(self, requirement, sources=(), events=()):
        snap = EnvironmentSnapshot(list(sources), [], STATE, events=list(events))
        return eval_event_condition(requirement, snap, EvaluationSettings(stale_hours=24))

    def test_seen_is_met(self):
        r = self.evaluate(req(), [pair()], [checked(40)])
        self.assertEqual((r["status"], r["code"]), (MET, "event_seen"))
        self.assertEqual(r["observed"][0]["count"], 40)

    def test_sourcetype_without_the_event_is_partial_not_missing(self):
        r = self.evaluate(req(), [pair()], [checked(0)])
        self.assertEqual((r["status"], r["code"]), (PARTIAL, "event_not_seen"))
        self.assertIn("rare event", r["detail"])

    def test_sourcetype_not_seen_or_not_checked_is_unverified(self):
        self.assertEqual(self.evaluate(req(), [], [])["code"], "sourcetype_not_seen")
        self.assertEqual(self.evaluate(req(), [], [])["status"], UNVERIFIED)
        self.assertEqual(self.evaluate(req(), [pair()], [])["code"], "not_checked")

    def test_incomplete_requirement_is_unknown(self):
        self.assertEqual(self.evaluate(req(value=""), [pair()])["code"], "empty_value")

    def test_matching_is_case_insensitive(self):
        r = self.evaluate(req(sourcetype="AWS:CloudTrail", value="describeimagescanfindings"), [pair()], [checked(3)])
        self.assertEqual(r["status"], MET)


class EvidenceTest(unittest.TestCase):
    def row(self, status, code):
        return {"type": "event_condition", "value": "eventName=X", "status": status, "code": code, "level": "recommended"}

    def test_event_types_feed_data_evidence(self):
        self.assertEqual(requirement_evidence(self.row("met", "event_seen")), "seen")
        self.assertEqual(requirement_evidence(self.row("partial", "event_not_seen")), "missing")
        self.assertEqual(requirement_evidence(self.row("unverified", "not_checked")), "unverified")
        ev = data_evidence([self.row("partial", "event_not_seen")])
        self.assertEqual(ev["state"], "none")
        self.assertEqual(ev["missing"][0]["type"], "event_condition")


if __name__ == "__main__":
    unittest.main()

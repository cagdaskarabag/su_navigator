import unittest

import helpers  # noqa: F401

from splunk_ucm.audit import AuditService
from splunk_ucm.discovery.service import DiscoveryService, DiscoverySettings, new_job
from splunk_ucm.discovery.spl import tstats_future, tstats_volume
from splunk_ucm.errors import UcmError, ValidationError
from splunk_ucm.platform.search import SearchResult
from splunk_ucm.readiness.evaluators import EvaluationSettings, eval_sourcetype
from splunk_ucm.readiness.snapshot import EnvironmentSnapshot
from splunk_ucm.storage import collections as C
from unit.test_discovery import APPS, INDEXES, MODELS, ROWS, FakeInventory, loaded_catalog

NOW = 1795163600
VOLUME = ROWS + [{"index": "wineventlog", "sourcetype": "WinEventLog:Old", "count": "900",
                  "first_time": "1793000000", "last_time": "1794000000"}]
FUTURE = [{"index": "wineventlog", "sourcetype": "WinEventLog:System", "count": "7", "last_time": "1999999999"},
          {"index": "wineventlog", "sourcetype": "clock_skew", "count": "2", "last_time": "1999999999"}]


class PassSearch:
    def __init__(self, fail_volume=False):
        self.calls = []
        self.fail_volume = fail_volume

    def oneshot(self, search, timeout=120.0, max_count=5000, **kw):
        self.calls.append(search)
        if "earliest=-30d" in search:
            if self.fail_volume:
                raise UcmError("search_failed", "boom")
            rows = VOLUME
        elif "earliest=+5m" in search:
            rows = FUTURE
        elif "datamodel=" in search:
            rows = []
        else:
            rows = ROWS
        return SearchResult(list(rows[:max_count]), [], False)


def run(search, **settings):
    store = loaded_catalog()
    inv = FakeInventory(INDEXES, APPS, MODELS)
    inv.list_knowledge_objects = lambda: []
    inv.server_version = lambda: "10.2.9"
    job = DiscoveryService(store, AuditService(store), inv, search, DiscoverySettings(**settings),
                           now_epoch=lambda: NOW).run(new_job("alice"))
    return store, job


def pair(store, index, sourcetype):
    rows = store.query(C.ENVIRONMENT_SOURCES, {"kind": "pair", "index": index, "sourcetype": sourcetype})
    return rows[0] if rows else None


class FreshnessSplTest(unittest.TestCase):
    def test_searches_are_bounded_tstats(self):
        self.assertEqual(tstats_volume(["a", "b"], 30),
                         "| tstats count min(_time) as first_time max(_time) as last_time "
                         "where (index=a OR index=b) earliest=-30d latest=now by index, sourcetype")
        self.assertIn("earliest=+5m latest=+10y", tstats_future(["a"]))
        for bad in ((["a"], 0), (["a"], 400), ([], 30), (["a b"], 30)):
            with self.assertRaises(ValidationError):
                tstats_volume(*bad)


class FreshnessPassTest(unittest.TestCase):
    def test_volume_stale_from_start_and_future_dated(self):
        store, job = run(PassSearch())
        self.assertEqual(job["status"], "succeeded")
        fresh = job["totals"]["freshness"]
        self.assertEqual((fresh["stale_from_start"], fresh["future_dated"], fresh["errors"]), (1, 1, 0))
        self.assertEqual(fresh["future_only"], [{"index": "wineventlog", "sourcetype": "clock_skew", "count": 2}])
        sec = pair(store, "wineventlog", "WinEventLog:Security")
        self.assertEqual((sec["volume_30d"], sec["future_count"], sec["stale_from_start"]), (42, 0, False))
        system = pair(store, "wineventlog", "WinEventLog:System")
        self.assertEqual((system["future_count"], system["future_last_time"]), (7, 1999999999))
        old = pair(store, "wineventlog", "WinEventLog:Old")
        self.assertEqual((old["status"], old["window_count"], old["volume_30d"], old["stale_from_start"]),
                         ("active", 0, 900, True))
        self.assertEqual(old["age_seconds"], NOW - 1794000000)
        index = store.get(C.ENVIRONMENT_SOURCES, [d for d in store.query(C.ENVIRONMENT_SOURCES, {"kind": "index"})
                                                  if d["name"] == "wineventlog"][0]["_key"])
        self.assertEqual((index["window_count"], index["volume_30d"], index["future_count"]), (45, 945, 7))
        self.assertIsNone(pair(store, "wineventlog", "clock_skew"))

    def test_a_source_that_stopped_before_the_window_reads_as_stale(self):
        store, _ = run(PassSearch())
        snap = EnvironmentSnapshot.load(store)
        out = eval_sourcetype({"value": "WinEventLog:Old"}, snap, EvaluationSettings())
        self.assertEqual((out["status"], out["code"]), ("partial", "stale"))
        store, _ = run(PassSearch(), freshness_days=0)
        out = eval_sourcetype({"value": "WinEventLog:Old"}, EnvironmentSnapshot.load(store), EvaluationSettings())
        self.assertEqual((out["status"], out["code"]), ("not_met", "not_found"))

    def test_disabled_runs_no_extra_search(self):
        search = PassSearch()
        _, job = run(search, freshness_days=0)
        self.assertFalse(any("-30d" in c or "+5m" in c for c in search.calls))
        self.assertFalse(job["totals"]["freshness"]["enabled"])

    def test_failed_pass_is_counted_and_does_not_make_the_job_partial(self):
        store, job = run(PassSearch(fail_volume=True))
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["totals"]["freshness"]["errors"], 1)
        self.assertIsNone(pair(store, "wineventlog", "WinEventLog:Old"))
        self.assertIsNone(pair(store, "wineventlog", "WinEventLog:Security")["volume_30d"])

    def test_cap_applies_to_added_pairs(self):
        store, job = run(PassSearch(), max_pairs=2)
        self.assertEqual(job["totals"]["freshness"]["stale_from_start"], 0)
        self.assertIsNone(pair(store, "wineventlog", "WinEventLog:Old"))


if __name__ == "__main__":
    unittest.main()

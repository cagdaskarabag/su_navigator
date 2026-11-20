import json
import unittest

import helpers
from splunk_ucm.api.app import CAP_RUN_DISCOVERY, Context, Request, build_router
from splunk_ucm.audit import AuditService
from splunk_ucm.catalog.detail import UseCaseDetailService
from splunk_ucm.config import AppConfig
from splunk_ucm.content.registry import bundle_provider
from splunk_ucm.content.sync import SyncService, new_job
from splunk_ucm.discovery.inventory import SplunkInventory
from splunk_ucm.discovery.keys import source_key
from splunk_ucm.discovery.mapping import MappingService
from splunk_ucm.discovery.overlay import attach_environment
from splunk_ucm.discovery.query import InventoryFilter, InventoryQueryService
from splunk_ucm.discovery.service import DiscoveryService, DiscoverySettings, new_job as new_djob
from splunk_ucm.discovery.spl import tstats_by_index_sourcetype, tstats_searches, validate_index_name
from splunk_ucm.discovery.worker import DiscoveryWorker
from splunk_ucm.errors import ValidationError
from splunk_ucm.platform.search import SearchResult
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
from splunk_ucm.storage.transport import SplunkdTransport
from unit.test_api_worker import call, make_ctx


class SplConstructionTest(unittest.TestCase):
    def test_rejects_injection_in_index_names(self):
        for bad in ("main; | delete", "main OR index=*", "../etc", "main$", "index=main", ""):
            with self.assertRaises(ValidationError):
                validate_index_name(bad)

    def test_tstats_uses_only_validated_indexes_and_relative_time(self):
        spl = tstats_by_index_sourcetype(["main", "_internal"], "-7d", "now")
        self.assertTrue(spl.startswith("| tstats "))
        self.assertIn("index=main OR index=_internal", spl)
        self.assertIn("earliest=-7d", spl)
        self.assertIn("latest=now", spl)
        self.assertIn("by index, sourcetype", spl)
        self.assertNotIn("sourcetype=", spl.split("by")[0])

    def test_rejects_bad_time_and_chunks(self):
        with self.assertRaises(ValidationError):
            tstats_by_index_sourcetype(["main"], "-7 days", "now")
        with self.assertRaises(ValidationError):
            tstats_by_index_sourcetype(["main"], "-7d", "later")
        groups = tstats_searches(["i%s" % i for i in range(45)], "-1h", "now", chunk=40)
        self.assertEqual(len(groups), 2)
        self.assertEqual(len(groups[0][0]), 40)


class FakeInventory:
    def __init__(self, indexes=None, apps=None, models=None):
        self.indexes = indexes or []
        self.apps = apps or []
        self.models = models or []

    def list_indexes(self):
        return list(self.indexes)

    def list_apps(self):
        return list(self.apps)

    def list_datamodels(self):
        return list(self.models)

    def list_knowledge_objects(self):
        return []

    def server_version(self):
        return "10.2.9"


class FakeSearch:
    def __init__(self, rows=None, error=None, truncated=False):
        self.rows = rows or []
        self.error = error
        self.truncated = truncated
        self.calls = []

    def oneshot(self, search, timeout=120.0, max_count=5000):
        self.calls.append(search)
        if self.error:
            raise self.error
        return SearchResult(list(self.rows), [], self.truncated or len(self.rows) >= max_count)


INDEXES = [
    {"name": "main", "disabled": False, "is_internal": False, "is_ready": True, "datatype": "event",
     "total_event_count": 0, "min_time": "", "max_time": ""},
    {"name": "wineventlog", "disabled": False, "is_internal": False, "is_ready": True, "datatype": "event",
     "total_event_count": 10, "min_time": "2026-11-20T08:00:00+0000", "max_time": "2026-11-20T09:00:00+0000"},
    {"name": "_internal", "disabled": False, "is_internal": True, "is_ready": True, "datatype": "event",
     "total_event_count": 100, "min_time": "", "max_time": "2026-11-20T09:00:00+0000"},
    {"name": "off", "disabled": True, "is_internal": False, "is_ready": False, "datatype": "event",
     "total_event_count": 0, "min_time": "", "max_time": ""},
]
APPS = [
    {"name": "Splunk_TA_windows", "label": "Windows TA", "version": "9.0", "disabled": False, "visible": True},
    {"name": "search", "label": "Search", "version": "10", "disabled": False, "visible": True},
    {"name": "hidden_ta", "label": "x", "version": "1", "disabled": True, "visible": False},
]
MODELS = [
    {"name": "Authentication", "app": "Splunk_SA_CIM", "disabled": False, "display_name": "Authentication",
     "objects": ["Authentication"], "accelerated": True},
]
ROWS = [
    {"index": "wineventlog", "sourcetype": "WinEventLog:Security", "count": "42",
     "first_time": "1795100000", "last_time": "1795160000"},
    {"index": "wineventlog", "sourcetype": "WinEventLog:System", "count": "3",
     "first_time": "1795100000", "last_time": "1795120000"},
]


def loaded_catalog():
    store = InMemoryStore()
    bundle = helpers.fixture_bundle()
    cats = [c["category_id"] for c in bundle["categories"]]
    SyncService(store, AuditService(store)).run(new_job("t", "fenre", cats), bundle_provider(bundle))
    return store


class DiscoveryServiceTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.search = FakeSearch(ROWS)
        self.inv = FakeInventory(INDEXES, APPS, MODELS)
        self.svc = DiscoveryService(self.store, AuditService(self.store), self.inv, self.search,
                                    DiscoverySettings(include_internal=False),
                                    now_epoch=lambda: 1795163600)

    def run_job(self, **kw):
        job = new_djob("alice", **kw)
        return self.svc.run(job)

    def test_skips_internal_and_disabled_indexes_in_tstats(self):
        job = self.run_job()
        self.assertEqual(job["status"], "succeeded")
        spl = self.search.calls[0]
        self.assertIn("index=wineventlog", spl)
        self.assertIn("index=main", spl)
        self.assertNotIn("index=_internal", spl)
        self.assertNotIn("index=off", spl)
        pairs = self.store.query(C.ENVIRONMENT_SOURCES, {"kind": "pair", "status": "active"})
        self.assertEqual(len(pairs), 2)
        sec = next(p for p in pairs if p["sourcetype"] == "WinEventLog:Security")
        self.assertEqual(sec["window_count"], 42)
        self.assertEqual(sec["index"], "wineventlog")
        self.assertIsInstance(sec["age_seconds"], int)

    def test_include_internal_adds_internal_indexes_to_tstats(self):
        self.run_job(include_internal=True)
        self.assertTrue(any("index=_internal" in s for s in self.search.calls))

    def test_no_tstats_when_no_eligible_indexes(self):
        self.inv.indexes = [INDEXES[-1]]
        job = self.run_job()
        self.assertEqual(self.search.calls, [])
        self.assertEqual(job["totals"]["pairs"], 0)

    def test_marks_missing_without_deleting(self):
        self.run_job()
        key = source_key("pair", "wineventlog", "WinEventLog:System")
        self.assertEqual(self.store.get(C.ENVIRONMENT_SOURCES, key)["status"], "active")
        self.search.rows = [ROWS[0]]
        self.run_job()
        doc = self.store.get(C.ENVIRONMENT_SOURCES, key)
        self.assertEqual(doc["status"], "missing")
        self.assertTrue(doc["window_count"])

    def test_auto_mapping_exact_and_skips_local(self):
        MappingService(self.store).upsert_local("sourcetype", "WinEventLog:Security",
                                                "WinEventLog:Security", "bob")
        self.run_job()
        local = MappingService(self.store).get("sourcetype", "WinEventLog:Security")
        self.assertEqual(local["origin"], "local")
        self.assertEqual(local["updated_by"], "bob")
        auto = MappingService(self.store).get("datamodel", "Authentication")
        if auto:
            self.assertEqual(auto["origin"], "auto_exact")
            self.assertEqual(auto["confidence"], "medium")

    def test_local_mapping_cannot_be_deleted_if_auto(self):
        self.run_job()
        auto = MappingService(self.store).get("datamodel", "Authentication")
        self.assertIsNotNone(auto)
        self.assertEqual(auto["origin"], "auto_exact")
        with self.assertRaises(ValidationError):
            MappingService(self.store).delete_local("datamodel", "Authentication", "alice")

    def test_enqueue_blocks_concurrent(self):
        self.svc.enqueue(new_djob("a"))
        with self.assertRaises(ValidationError):
            self.svc.enqueue(new_djob("b"))

    def test_search_failure_is_partial_not_silent(self):
        from splunk_ucm.errors import UnsupportedOperation
        self.search.error = UnsupportedOperation("search failed")
        job = self.run_job()
        self.assertEqual(job["status"], "partial")
        self.assertTrue(job["errors"])

    def test_failed_or_truncated_search_does_not_mark_pairs_missing(self):
        from splunk_ucm.errors import UnsupportedOperation
        self.run_job()
        key = source_key("pair", "wineventlog", "WinEventLog:System")
        self.search.error = UnsupportedOperation("search failed")
        self.run_job()
        self.assertEqual(self.store.get(C.ENVIRONMENT_SOURCES, key)["status"], "active")
        self.search.error = None
        self.search.rows = [ROWS[0]]
        self.search.truncated = True
        self.run_job()
        self.assertEqual(self.store.get(C.ENVIRONMENT_SOURCES, key)["status"], "active")

    def test_knowledge_objects_and_version_recorded(self):
        self.inv.list_knowledge_objects = lambda: [
            {"kind": "macro", "name": "sec_idx", "app": "TA", "sharing": "global", "disabled": False,
             "lookup_type": ""}]
        self.run_job()
        macros = self.store.query(C.ENVIRONMENT_SOURCES, {"kind": "macro"})
        self.assertEqual(macros[0]["sharing"], "global")
        self.assertEqual(self.store.get(C.SYNC_STATE, "discovery::local")["splunk_version"], "10.2.9")

    def test_imported_spl_never_reaches_search(self):
        self.run_job()
        joined = "\n".join(self.search.calls)
        self.assertNotIn("WinEventLog", joined.split("by")[0] if "by" in joined else joined)
        self.assertNotIn("delete", joined)


class InventoryQueryAndOverlayTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        DiscoveryService(self.store, AuditService(self.store), FakeInventory(INDEXES, APPS, MODELS),
                         FakeSearch(ROWS), now_epoch=lambda: 1795163600).run(new_djob("alice"))

    def test_inventory_query(self):
        svc = InventoryQueryService(self.store)
        page = svc.search(InventoryFilter(kind="pair", count=10, sort="count"))
        self.assertEqual(page["items"][0]["sourcetype"], "WinEventLog:Security")
        with self.assertRaises(ValidationError):
            svc.search(InventoryFilter(kind="pair;drop"))

    def test_overlay_marks_present_sourcetype(self):
        detail = UseCaseDetailService(ContentRepository(self.store),
                                      CategoryRepository(self.store)).get("fenre:UC-9.1.1")
        attach_environment(detail, self.store)
        st = [r for r in detail["requirements"] if r["type"] == "sourcetype"]
        self.assertTrue(st)
        self.assertTrue(st[0]["environment"]["present"])
        self.assertGreater(detail["environment_summary"]["requirements_present"], 0)


class RouterDiscoveryTest(unittest.TestCase):
    def test_viewer_denied_discovery_write(self):
        ctx = make_ctx(InMemoryStore(), [])
        self.assertEqual(call(ctx, "GET", "inventory")[0], 200)
        self.assertEqual(call(ctx, "POST", "discovery", body={"include_internal": True})[0], 403)
        self.assertEqual(call(ctx, "POST", "mappings", body={"kind": "index", "value": "main"})[0], 403)

    def test_analyst_can_enqueue(self):
        ctx = make_ctx(InMemoryStore(), [CAP_RUN_DISCOVERY])
        status, body = call(ctx, "POST", "discovery", body={"include_internal": True, "earliest": "-1h"})
        self.assertEqual(status, 202)
        self.assertEqual(body["job"]["status"], "queued")
        self.assertTrue(body["job"]["include_internal"])


class WorkerDiscoveryTest(unittest.TestCase):
    def test_runs_queued_job(self):
        store = InMemoryStore()
        cfg = AppConfig({})
        search = FakeSearch(ROWS)
        inv = FakeInventory(INDEXES, APPS, MODELS)
        worker = DiscoveryWorker(store, cfg, None, lambda: True, inventory=inv, search=search)
        svc = worker._service()
        svc.enqueue(new_djob("alice"))
        result = worker.run_once()
        self.assertEqual(result["action"], "ran")
        self.assertEqual(result["status"], "succeeded")

    def test_non_captain_skips(self):
        worker = DiscoveryWorker(InMemoryStore(), AppConfig({}), None, lambda: False)
        self.assertEqual(worker.run_once()["action"], "skipped")


class InventoryRestParseTest(unittest.TestCase):
    def test_parses_index_and_model_payloads(self):
        class T(SplunkdTransport):
            def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
                if "indexes" in path:
                    body = {"entry": [{"name": "main", "content": {
                        "disabled": False, "isInternal": False, "isReady": True, "datatype": "event",
                        "totalEventCount": "12", "minTime": "", "maxTime": ""}}]}
                elif "apps/local" in path:
                    body = {"entry": [{"name": "TA-foo", "content": {
                        "label": "Foo", "version": "1", "disabled": False, "visible": True}}]}
                else:
                    body = {"entry": [{"name": "Network_Traffic", "content": {
                        "disabled": False, "eai:appName": "Splunk_SA_CIM",
                        "eai:data": json.dumps({"displayName": "Network Traffic",
                                                "objectNameList": ["All_Traffic"],
                                                "acceleration": {"enabled": True}})}}]}
                return 200, json.dumps(body).encode("utf-8")

        inv = SplunkInventory(T())
        self.assertEqual(inv.list_indexes()[0]["total_event_count"], 12)
        self.assertEqual(inv.list_apps()[0]["name"], "TA-foo")
        models = inv.list_datamodels()
        self.assertEqual(models[0]["display_name"], "Network Traffic")
        self.assertTrue(models[0]["accelerated"])


if __name__ == "__main__":
    unittest.main()

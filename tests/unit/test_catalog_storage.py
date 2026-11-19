import json
import unittest

import helpers
from splunk_ucm.audit import AuditService
from splunk_ucm.catalog.detail import UseCaseDetailService, key_from_id
from splunk_ucm.catalog.query import CatalogFilter, CatalogQueryService, build_query
from splunk_ucm.content.registry import bundle_provider
from splunk_ucm.content.reindex import ReindexService
from splunk_ucm.content.sync import SyncService, new_job
from splunk_ucm.errors import NotFoundError, StorageError, ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore, KVStore, matches
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
from splunk_ucm.storage.transport import SplunkdTransport


def loaded_store():
    store = InMemoryStore()
    bundle = helpers.fixture_bundle()
    cats = [c["category_id"] for c in bundle["categories"]]
    SyncService(store, AuditService(store)).run(new_job("t", "fenre", cats), bundle_provider(bundle))
    return store


class CatalogQueryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = loaded_store()
        cls.svc = CatalogQueryService(cls.store, max_page_size=5)

    def ids(self, **kw):
        return [i["record_id"] for i in self.svc.search(CatalogFilter(**kw))["items"]]

    def test_default_listing_sorted_numerically_and_paged(self):
        page = self.svc.search(CatalogFilter(count=5))
        self.assertEqual(page["total"], 10)
        self.assertTrue(page["has_more"])
        self.assertEqual([i["record_id"] for i in page["items"]], ["1.1.1", "5.2.14", "7.1.1", "8.1.1", "9.1.1"])
        page2 = self.svc.search(CatalogFilter(count=5, offset=5))
        self.assertFalse(page2["has_more"])
        self.assertEqual(page2["items"][-1]["record_id"], "18.2.1")

    def test_page_size_capped(self):
        self.assertEqual(self.svc.search(CatalogFilter(count=1000))["count"], 5)

    def test_filters(self):
        self.assertEqual(self.ids(mitre="T1110"), ["9.1.1", "9.1.2"])
        self.assertEqual(self.ids(sourcetype="WinEventLog:Security", count=5)[:1], ["9.1.1"])
        self.assertIn("14.1.1", self.ids(domains=["ot_ics"]))
        self.assertEqual(self.ids(category_keys=["fenre_cat-09"]), ["9.1.1", "9.1.2"])
        crit = self.svc.search(CatalogFilter(criticality=["critical"], count=5))["items"]
        self.assertTrue(all(i["criticality"] == "critical" for i in crit))

    def test_free_text_is_escaped_and_and_combined(self):
        self.assertEqual(self.ids(q="brute force"), ["9.1.1"])
        self.assertEqual(self.ids(q="brute.*"), [])
        query = build_query(CatalogFilter(q="a.b (c"))
        regexes = [c["search_text"]["$regex"] for c in query["$and"] if "search_text" in c]
        self.assertEqual(regexes, ["a\\.b", "\\(c"])

    def test_rejects_unlisted_values(self):
        for kw in ({"sort": "title; drop"}, {"domains": ["$where"]}, {"criticality": ["x"]},
                   {"category_keys": ["fenre_cat-09\"}"]}, {"mitre": "T1110'"}, {"offset": -1},
                   {"provider_status": "deleted"}, {"q": "x" * 500}):
            with self.assertRaises(ValidationError, msg=kw):
                self.svc.search(CatalogFilter(**kw))

    def test_withdrawn_hidden_by_default(self):
        store = loaded_store()
        ContentRepository(store).mark_status(["fenre_UC-9.1.2"], "withdrawn")
        svc = CatalogQueryService(store)
        self.assertNotIn("9.1.2", [i["record_id"] for i in svc.search(CatalogFilter(count=50))["items"]])
        withdrawn = svc.search(CatalogFilter(provider_status="withdrawn"))["items"]
        self.assertEqual([i["record_id"] for i in withdrawn], ["9.1.2"])


class DetailAndReindexTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_store()
        self.detail = UseCaseDetailService(ContentRepository(self.store), CategoryRepository(self.store))

    def test_detail_derived_on_read(self):
        d = self.detail.get("fenre:UC-9.1.1")
        self.assertEqual(d["title"], "Brute-Force Login Detection")
        self.assertEqual(d["requirement_summary"]["assessment"], "not_assessed")
        self.assertEqual(d["provider_status"], "active")
        self.assertEqual(d, self.detail.get("fenre_UC-9.1.1"))

    def test_detail_errors(self):
        with self.assertRaises(NotFoundError):
            self.detail.get("fenre:UC-99.1.1")
        for bad in ("../../etc", "fenre:UC-9.1.1\" OR 1", ""):
            with self.assertRaises((ValidationError, NotFoundError)):
                key_from_id(bad) if bad else self.detail.get(bad)

    def test_reindex_rebuilds_catalog_from_content_only(self):
        self.store.collections[C.CATALOG] = {}
        result = ReindexService(self.store).reindex()
        self.assertEqual(result, {"reindexed": 10, "skipped": 0})
        self.assertEqual(self.store.count(C.CATALOG), 10)
        self.assertEqual(self.store.get(C.CATALOG, "fenre_UC-9.1.1")["title"], "Brute-Force Login Detection")


class InMemoryMatchesTest(unittest.TestCase):
    def test_operators(self):
        doc = {"a": 1, "tags": ["x", "y"], "s": "Hello World"}
        self.assertTrue(matches(doc, {"tags": "x"}))
        self.assertTrue(matches(doc, {"tags": {"$in": ["z", "y"]}}))
        self.assertFalse(matches(doc, {"tags": {"$in": ["z"]}}))
        self.assertTrue(matches(doc, {"s": {"$regex": "world", "$options": "i"}}))
        self.assertTrue(matches(doc, {"$and": [{"a": {"$gte": 1}}, {"$or": [{"a": 2}, {"s": "Hello World"}]}]}))

    def test_rejects_illegal_keys_like_kvstore(self):
        with self.assertRaises(StorageError):
            InMemoryStore().batch_save("c", [{"_key": "k", "raw": {"$schema": "x"}}])
        with self.assertRaises(StorageError):
            InMemoryStore().batch_save("c", [{"_key": "k", "a": [{"b.c": 1}]}])


class RecordingTransport(SplunkdTransport):
    def __init__(self):
        self.calls = []

    def request(self, method, path, params=None, json_body=None, form=None, timeout=60.0):
        self.calls.append((method, path, params, json_body))
        if path.endswith("/batch_save"):
            return 200, json.dumps([d["_key"] for d in json_body]).encode("utf-8")
        return 200, b"[]"


class KVStoreRestTest(unittest.TestCase):
    def test_query_parameters(self):
        t = RecordingTransport()
        KVStore(t).query("uc_catalog", {"a": 1}, sort=[("sort_key", 1), ("t", -1)], skip=5, limit=10,
                         fields=["_key", "title"])
        method, path, params, _ = t.calls[0]
        self.assertEqual(path, "/servicesNS/nobody/splunk_use_case_manager/storage/collections/data/uc_catalog")
        self.assertEqual(params["sort"], "sort_key:1,t:-1")
        self.assertEqual(json.loads(params["query"]), {"a": 1})
        self.assertEqual((params["skip"], params["limit"], params["fields"]), (5, 10, "_key,title"))

    def test_batch_save_chunks(self):
        t = RecordingTransport()
        keys = KVStore(t, max_batch_docs=3).batch_save("c", [{"_key": str(i)} for i in range(7)])
        self.assertEqual(keys, [str(i) for i in range(7)])
        self.assertEqual([len(c[3]) for c in t.calls], [3, 3, 1])
        self.assertTrue(all(c[1].endswith("/c/batch_save") for c in t.calls))

    def test_key_quoting(self):
        t = RecordingTransport()
        KVStore(t).get("c", "job::a/b")
        self.assertTrue(t.calls[0][1].endswith("/c/job%3A%3Aa%2Fb"))

    def test_delete_query_requires_query(self):
        with self.assertRaises(StorageError):
            KVStore(RecordingTransport()).delete_query("c", {})


if __name__ == "__main__":
    unittest.main()

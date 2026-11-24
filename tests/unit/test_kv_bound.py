import unittest

import helpers  # noqa: F401  (sets sys.path)

from splunk_ucm.catalog.query import DEFAULT_KV_ROW_LIMIT, CatalogFilter, CatalogQueryService
from splunk_ucm.errors import ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_catalog_storage import loaded_store
from unit.test_catalog_filters import seed


class BoundedStore(InMemoryStore):
    """A KV Store that, like the real one, returns at most ``cap`` rows per query whatever ``limit`` says."""

    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def query(self, collection, query=None, sort=(), skip=0, limit=0, fields=None):
        rows = super().query(collection, query, sort, skip, min(limit, self.cap) if limit else self.cap, fields)
        return rows[:self.cap]


def filled(cap, rows):
    store = BoundedStore(cap)
    store.batch_save(C.CATALOG, [{"_key": "k%05d" % i, "provider_status": "active", "sort_key": "k%05d" % i,
                                  "title": "t"} for i in range(rows)])
    return store


class TotalBoundTest(unittest.TestCase):
    def search(self, store, cap, **kw):
        return CatalogQueryService(store, 100, max_scan=cap - 1, kv_row_limit=cap).search(CatalogFilter(**kw))

    def test_a_total_below_the_bound_is_exact(self):
        out = self.search(filled(50, 49), 50)
        self.assertEqual((out["total"], out["total_capped"]), (49, False))

    def test_a_total_at_the_bound_is_flagged_as_a_lower_bound(self):
        out = self.search(filled(50, 70), 50)
        self.assertEqual(out["total"], 50)
        self.assertTrue(out["total_capped"])
        self.assertEqual(self.search(filled(50, 50), 50)["total_capped"], True)

    def test_no_total_requested_means_no_flag(self):
        out = self.search(filled(50, 70), 50, with_total=False)
        self.assertEqual((out["total"], out["total_capped"]), (None, False))

    def test_default_limit_matches_the_kv_store_default(self):
        self.assertEqual(DEFAULT_KV_ROW_LIMIT, 50000)

    def test_a_scan_that_hits_the_bound_is_refused_not_cut_off(self):
        store = loaded_store()
        keys, _ = seed(store)
        svc = CatalogQueryService(store, 100, max_scan=len(keys) - 4, kv_row_limit=len(keys) - 3)
        for filters in ({"availability": ["ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"]},
                        {"availability": ["not_assessed"]}):
            with self.assertRaises(ValidationError) as ctx:
                svc.search(CatalogFilter(**filters))
            self.assertEqual(ctx.exception.details["limit"], len(keys) - 4)

    def test_bookmark_scan_is_bounded_too(self):
        store = loaded_store()
        keys, _ = seed(store)
        from unit.test_catalog_filters import bookmark
        for key in keys[:6]:
            bookmark(store, "alice", key)
        svc = CatalogQueryService(store, 100, max_scan=5, kv_row_limit=6)
        with self.assertRaises(ValidationError):
            svc.search(CatalogFilter(bookmarked=True), "alice")
        ok = CatalogQueryService(store, 100, max_scan=6, kv_row_limit=7).search(CatalogFilter(bookmarked=True), "alice")
        self.assertEqual(ok["total"], 6)


class ApiBoundTest(unittest.TestCase):
    def test_catalogue_and_sync_responses_carry_the_bound(self):
        store = loaded_store()
        ctx = make_ctx(store, [])
        status, body = call(ctx, "GET", "catalog")
        self.assertEqual(status, 200)
        self.assertFalse(body["total_capped"])
        status, body = call(ctx, "GET", "sync")
        self.assertEqual(body["kv_row_limit"], 50000)

    def test_the_configured_limit_is_used(self):
        from splunk_ucm.config import AppConfig
        store = loaded_store()
        ctx = make_ctx(store, [], config=AppConfig({"catalog": {"kv_row_limit": "5000"}}))
        self.assertEqual(call(ctx, "GET", "sync")[1]["kv_row_limit"], 5000)
        ctx = make_ctx(store, [], config=AppConfig({"catalog": {"kv_row_limit": "5"}}))
        self.assertEqual(call(ctx, "GET", "sync")[1]["kv_row_limit"], 1000)


if __name__ == "__main__":
    unittest.main()

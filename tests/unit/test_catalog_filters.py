import unittest

import helpers  # noqa: F401  (sets sys.path)

from splunk_ucm.catalog.derived import FACETS_KEY, FACETS_VERSION, get_facets, refresh_derived
from splunk_ucm.catalog.query import AVAILABILITY, SORTS, CatalogFilter, CatalogQueryService
from splunk_ucm.errors import ValidationError
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_catalog_storage import loaded_store

STATES = ("ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence")


def seed(store):
    """Readiness rows for part of the catalogue, cycling through every state; the rest stay unassessed."""
    keys = sorted(d["_key"] for d in store.query(C.CATALOG, None, fields=["_key"]))
    assessed = keys[: len(keys) - 3]
    store.batch_save(C.READINESS, [{"_key": k, "state": STATES[i % len(STATES)]} for i, k in enumerate(assessed)])
    return keys, {k: STATES[i % len(STATES)] for i, k in enumerate(assessed)}


def bookmark(store, user, key, intent="bookmark"):
    store.upsert(C.SELECTIONS, {"_key": "sel_%s_%s" % (user, key), "user": user, "catalog_key": key,
                                "content_id": key, "intent": intent})


class AvailabilityFilterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = loaded_store()
        cls.keys, cls.state = seed(cls.store)
        cls.svc = CatalogQueryService(cls.store, max_page_size=100)

    def found(self, svc=None, **kw):
        out = (svc or self.svc).search(CatalogFilter(count=100, **kw))
        return [i["_key"] for i in out["items"]]

    def test_catalogue_is_big_enough_to_exercise_the_filter(self):
        self.assertGreaterEqual(len(self.keys), 8)
        self.assertEqual(set(self.state.values()), set(STATES))

    def test_each_state_returns_exactly_its_use_cases(self):
        for st in STATES:
            expected = sorted(k for k, v in self.state.items() if v == st)
            self.assertEqual(sorted(self.found(availability=[st])), expected, st)

    def test_several_states_and_not_assessed(self):
        both = sorted(k for k, v in self.state.items() if v in ("ready", "partially_ready"))
        self.assertEqual(sorted(self.found(availability=["ready", "partially_ready"])), both)
        unassessed = sorted(set(self.keys) - set(self.state))
        self.assertEqual(len(unassessed), 3)
        self.assertEqual(sorted(self.found(availability=["not_assessed"])), unassessed)
        mixed = sorted(set(unassessed) | {k for k, v in self.state.items() if v == "blocked"})
        self.assertEqual(sorted(self.found(availability=["blocked", "not_assessed"])), mixed)

    def test_withdrawn_entries_are_not_counted_as_not_assessed(self):
        store = loaded_store()
        keys, state = seed(store)
        withdrawn = keys[0]
        store.upsert(C.CATALOG, dict(store.get(C.CATALOG, withdrawn), provider_status="withdrawn"))
        svc = CatalogQueryService(store, max_page_size=100)
        found = [i["_key"] for i in svc.search(CatalogFilter(availability=["not_assessed"], count=100))["items"]]
        self.assertEqual(sorted(found), sorted(set(keys) - set(state) - {withdrawn}))
        scan = CatalogQueryService(store, max_page_size=100, max_join_keys=1)
        self.assertEqual(sorted(i["_key"] for i in scan.search(CatalogFilter(availability=["not_assessed"], count=100))["items"]), sorted(found))
        any_status = svc.search(CatalogFilter(availability=["not_assessed"], provider_status="any", count=100))
        self.assertEqual(len(any_status["items"]), len(set(keys) - set(state)))

    def test_no_request_exceeds_the_kv_store_row_limit(self):
        """A lab run found the scan asking for limit=50001; splunkd refuses anything above 50000."""
        from splunk_ucm.errors import StorageError
        from splunk_ucm.storage.kvstore import InMemoryStore

        class StrictStore(InMemoryStore):
            def query(self, collection, query=None, sort=(), skip=0, limit=0, fields=None):
                if limit > 50000:
                    raise StorageError("limit %d exceeds max_rows_per_query" % limit, 400)
                return super().query(collection, query, sort, skip, limit, fields)

        strict = StrictStore()
        for coll, docs in self.store.collections.items():
            strict.collections[coll] = {k: dict(v) for k, v in docs.items()}
        bookmark(strict, "alice", self.keys[0])
        for join in (1000, 1):
            svc = CatalogQueryService(strict, max_join_keys=join)
            for availability in (["ready"], ["not_assessed"], list(AVAILABILITY)):
                out = svc.search(CatalogFilter(availability=availability, count=5), "alice")
                self.assertIsNotNone(out["total"])
            self.assertEqual(svc.search(CatalogFilter(bookmarked=True, count=5), "alice")["total"], 1)

    def test_combines_with_other_filters(self):
        domain = self.store.get(C.CATALOG, self.keys[0])["domains"][0]
        expected = sorted(d["_key"] for d in self.store.query(C.CATALOG, {"domains": domain})
                          if self.state.get(d["_key"]) == "ready")
        self.assertEqual(sorted(self.found(availability=["ready"], domains=[domain])), expected)

    def test_unknown_value_is_rejected(self):
        for bad in (["done"], ["ready", "x"], ["READY"]):
            with self.assertRaises(ValidationError):
                self.svc.search(CatalogFilter(availability=bad))
        self.assertEqual(AVAILABILITY[-1], "not_assessed")

    def test_no_match_gives_an_empty_page(self):
        empty = CatalogQueryService(loaded_store(), max_page_size=100)
        out = empty.search(CatalogFilter(availability=["ready"], count=10))
        self.assertEqual((out["items"], out["total"], out["has_more"]), ([], 0, False))

    def test_in_clause_and_scan_path_agree_for_every_sort_and_page(self):
        join = CatalogQueryService(self.store, max_page_size=3, max_join_keys=1000)
        scan = CatalogQueryService(self.store, max_page_size=3, max_join_keys=1)
        for availability in (["ready"], ["ready", "not_ready", "not_assessed"], list(AVAILABILITY)):
            for sort in SORTS:
                offset = 0
                while True:
                    f = CatalogFilter(availability=availability, sort=sort, offset=offset, count=3)
                    a, b = join.search(f), scan.search(f)
                    self.assertEqual([i["_key"] for i in a["items"]], [i["_key"] for i in b["items"]], (availability, sort, offset))
                    self.assertEqual((a["total"], a["has_more"]), (b["total"], b["has_more"]))
                    if not a["has_more"]:
                        break
                    offset += 3

    def test_scan_path_returns_the_same_fields_as_the_normal_path(self):
        join = CatalogQueryService(self.store, max_join_keys=1000).search(CatalogFilter(availability=["ready"], count=2))
        scan = CatalogQueryService(self.store, max_join_keys=1).search(CatalogFilter(availability=["ready"], count=2))
        self.assertEqual(join["items"], scan["items"])

    def test_scan_path_refuses_an_unbounded_catalogue(self):
        small = CatalogQueryService(self.store, max_join_keys=1, max_scan=5)
        with self.assertRaises(ValidationError):
            small.search(CatalogFilter(availability=["ready"]))


class BookmarkFilterTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_store()
        self.keys, self.state = seed(self.store)
        self.svc = CatalogQueryService(self.store, max_page_size=100)
        a, b, c, d = self.keys[:4]
        bookmark(self.store, "alice", a)
        bookmark(self.store, "alice", b)
        bookmark(self.store, "alice", c, intent="select")
        bookmark(self.store, "bob", d)
        bookmark(self.store, "bob", a, intent="reject")
        self.a, self.b, self.c, self.d = a, b, c, d

    def found(self, user, **kw):
        return sorted(i["_key"] for i in self.svc.search(CatalogFilter(count=100, bookmarked=True, **kw), user)["items"])

    def test_only_the_callers_bookmarks_count(self):
        self.assertEqual(self.found("alice"), sorted([self.a, self.b]))
        self.assertEqual(self.found("bob"), [self.d])
        self.assertEqual(self.found("carol"), [])

    def test_other_intents_are_not_bookmarks(self):
        self.assertNotIn(self.c, self.found("alice"))
        self.assertNotIn(self.a, self.found("bob"))

    def test_without_the_flag_nothing_is_filtered(self):
        out = self.svc.search(CatalogFilter(count=100), "alice")
        self.assertEqual(out["total"], len(self.keys))

    def test_needs_a_user(self):
        with self.assertRaises(ValidationError):
            self.svc.search(CatalogFilter(bookmarked=True), "")

    def test_combines_with_availability(self):
        wanted = sorted(k for k in (self.a, self.b) if self.state.get(k) == "ready")
        self.assertEqual(self.found("alice", availability=["ready"]), wanted)
        not_ready = sorted(k for k in (self.a, self.b) if self.state.get(k) != "ready")
        self.assertEqual(self.found("alice", availability=[s for s in AVAILABILITY if s != "ready"]), not_ready)

    def test_scan_path_gives_the_same_answer(self):
        scan = CatalogQueryService(self.store, max_page_size=100, max_join_keys=1)
        out = scan.search(CatalogFilter(count=100, bookmarked=True), "alice")
        self.assertEqual(sorted(i["_key"] for i in out["items"]), sorted([self.a, self.b]))
        self.assertEqual(out["total"], 2)

    def test_api_takes_the_user_from_the_session_never_from_a_parameter(self):
        for user, expected in (("alice", [self.a, self.b]), ("bob", [self.d])):
            ctx = make_ctx(self.store, [], user=user)
            status, body = call(ctx, "GET", "catalog", query={"bookmarked": "1", "count": "100"})
            self.assertEqual(status, 200)
            self.assertEqual(sorted(i["_key"] for i in body["items"]), sorted(expected))
        ctx = make_ctx(self.store, [], user="bob")
        status, body = call(ctx, "GET", "catalog", query={"bookmarked": "1", "user": "alice", "count": "100"})
        self.assertEqual([i["_key"] for i in body["items"]], [self.d])
        status, body = call(ctx, "GET", "catalog", query={"bookmarked": "0", "count": "100"})
        self.assertEqual(body["total"], len(self.keys))

    def test_api_availability_values_and_errors(self):
        ctx = make_ctx(self.store, [])
        status, body = call(ctx, "GET", "catalog", query={"availability": "ready,partially_ready", "count": "100"})
        self.assertEqual(status, 200)
        self.assertEqual(sorted(i["_key"] for i in body["items"]),
                         sorted(k for k, v in self.state.items() if v in ("ready", "partially_ready")))
        status, body = call(ctx, "GET", "catalog", query={"availability": "nope"})
        self.assertEqual(status, 400)


class MultiValueAndFacetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = loaded_store()
        cls.svc = CatalogQueryService(cls.store, max_page_size=100)
        cls.all = [d for d in cls.store.query(C.CATALOG, None) if d["provider_status"] == "active"]

    def keys(self, **kw):
        return sorted(i["_key"] for i in self.svc.search(CatalogFilter(count=100, **kw))["items"])

    def test_every_facet_accepts_several_values(self):
        crits = sorted({d["criticality"] for d in self.all})
        diffs = sorted({d["difficulty"] for d in self.all})
        cats = sorted({d["category_key"] for d in self.all})
        for kw, field, values in (("criticality", "criticality", crits[:2]), ("difficulty", "difficulty", diffs[:2]),
                                  ("category_keys", "category_key", cats[:2])):
            expected = sorted(d["_key"] for d in self.all if d[field] in values)
            self.assertEqual(self.keys(**{kw: values}), expected, kw)
        regs = sorted({fw for d in self.all for fw in d["frameworks"] if fw.startswith("regulation:")})[:2]
        expected = sorted(d["_key"] for d in self.all if set(regs) & set(d["frameworks"]))
        self.assertEqual(self.keys(regulation=[r[len("regulation:"):] for r in regs]), expected)

    def test_facet_counts_are_global_and_match_the_filters(self):
        self.store.delete(C.SYNC_STATE, FACETS_KEY)
        refresh_derived(self.store)
        facets = get_facets(self.store)
        self.assertEqual(self.store.get(C.SYNC_STATE, FACETS_KEY)["facets_version"], FACETS_VERSION)
        self.assertEqual(facets["active"], len(self.all))
        for name, field in (("criticality", "criticality"), ("difficulty", "difficulty"), ("categories", "category_key")):
            self.assertTrue(facets[name], name)
            for value, count in facets[name].items():
                kw = {"category_keys": [value]} if name == "categories" else {name: [value]}
                self.assertEqual(count, len(self.keys(**kw)), (name, value))
        for domain, count in facets["domains"].items():
            self.assertEqual(count, len(self.keys(domains=[domain])), domain)
        self.assertEqual(sum(facets["difficulty"].values()), len([d for d in self.all if d.get("difficulty")]))

    def test_old_stored_facets_are_recomputed_on_demand(self):
        store = loaded_store()
        store.upsert(C.SYNC_STATE, {"_key": FACETS_KEY, "review_statuses": [], "regulations": [], "quality_flags": []})
        facets = get_facets(store)
        self.assertTrue(facets["domains"])
        status, body = call(make_ctx(store, []), "GET", "catalog/facets")
        self.assertEqual((status, body["active"]), (200, facets["active"]))


if __name__ == "__main__":
    unittest.main()

import unittest

from splunk_ucm.catalog.derived import FACETS_KEY, get_facets, refresh_derived
from splunk_ucm.catalog.query import SORTS, CatalogFilter, CatalogQueryService
from splunk_ucm.errors import ValidationError
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_catalog_storage import loaded_store


class CatalogSearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = loaded_store()
        cls.svc = CatalogQueryService(cls.store, max_page_size=100)
        cls.all = cls.store.query(C.CATALOG, None)

    def ids(self, **kw):
        return [i["content_id"] for i in self.svc.search(CatalogFilter(count=100, **kw))["items"]]

    def test_description_terms_are_searchable_and_bounded(self):
        doc = self.store.get(C.CATALOG, "fenre_UC-9.1.1")
        self.assertIn("brute", doc["search_text"])
        word = next(w for w in doc["search_text"].split()[-5:] if len(w) > 4)
        self.assertIn("fenre:UC-9.1.1", self.ids(q=word))
        from splunk_ucm.catalog.summary import SEARCH_DESCRIPTION_CHARS, catalog_summary
        from unit import test_normalizer
        test_normalizer.FenreNormalizerTest.setUpClass()
        n = test_normalizer.FenreNormalizerTest("test_deterministic")
        uc = n.normalize("9.1.1", lambda raw: raw.update(description="alpha " * 400 + "omegaword"))
        text = catalog_summary(uc)["search_text"]
        self.assertIn("alpha", text)
        self.assertNotIn("omegaword", text)
        self.assertLess(len(text), SEARCH_DESCRIPTION_CHARS + 1000)

    def test_review_filter(self):
        statuses = sorted({d["review_status"] for d in self.all})
        for status in statuses:
            expected = sorted(d["content_id"] for d in self.all if d["review_status"] == status)
            self.assertEqual(sorted(self.ids(review=[status])), expected, status)
        both = sorted(d["content_id"] for d in self.all if d["review_status"] in statuses[:2])
        self.assertEqual(sorted(self.ids(review=statuses[:2])), both)
        for bad in (["Verified!"], ["x" * 100], ["a b"]):
            with self.assertRaises(ValidationError):
                self.svc.search(CatalogFilter(review=bad))

    def test_regulation_filter(self):
        regs = sorted({fw[len("regulation:"):] for d in self.all for fw in d["frameworks"]
                       if fw.startswith("regulation:")})
        self.assertTrue(regs)
        for reg in regs:
            expected = sorted(d["content_id"] for d in self.all if "regulation:" + reg in d["frameworks"])
            self.assertEqual(sorted(self.ids(regulation=reg)), expected, reg)
        with self.assertRaises(ValidationError):
            self.svc.search(CatalogFilter(regulation="../x"))

    def test_paging_is_stable_for_every_sort(self):
        reg = next(fw[len("regulation:"):] for d in self.all for fw in d["frameworks"] if fw.startswith("regulation:"))
        small = CatalogQueryService(self.store, max_page_size=2)
        for f in ({}, {"review": ["unknown"]}, {"regulation": reg}):
            for sort in SORTS:
                full = self.ids(sort=sort, **f)
                paged, offset = [], 0
                while True:
                    page = small.search(CatalogFilter(sort=sort, offset=offset, count=2, **f))
                    paged.extend(i["content_id"] for i in page["items"])
                    if not page["has_more"]:
                        break
                    offset += 2
                self.assertEqual(paged, full, (f, sort))
                self.assertEqual(len(set(paged)), len(paged))
                self.assertEqual(page["total"], len(full))

    def test_facets_match_the_catalogue(self):
        self.store.delete(C.SYNC_STATE, FACETS_KEY)
        on_demand = get_facets(self.store)
        self.assertIsNone(on_demand["computed_at"])
        refresh_derived(self.store)
        facets = get_facets(self.store)
        self.assertTrue(facets["computed_at"])
        self.assertEqual({r["id"]: r["count"] for r in facets["review_statuses"]},
                         {s: sum(1 for d in self.all if d["review_status"] == s) for s in {d["review_status"] for d in self.all}})
        for reg in facets["regulations"]:
            self.assertEqual(reg["count"], len(self.ids(regulation=reg["id"])), reg)
            self.assertTrue(reg["label"])
        self.assertEqual(on_demand["regulations"], facets["regulations"])
        status, body = call(make_ctx(self.store, []), "GET", "catalog/facets")
        self.assertEqual((status, body["regulations"]), (200, facets["regulations"]))
        status, body = call(make_ctx(self.store, []), "GET", "catalog", query={"regulation": facets["regulations"][0]["id"]})
        self.assertEqual((status, body["total"]), (200, facets["regulations"][0]["count"]))


if __name__ == "__main__":
    unittest.main()

import unittest

import helpers
from splunk_ucm.catalog.detail import UseCaseDetailService
from splunk_ucm.catalog.derived import refresh_derived
from splunk_ucm.catalog.quality import FLAG_ORDER, spl_hash
from splunk_ucm.catalog.query import CatalogFilter, CatalogQueryService
from splunk_ucm.errors import ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
from splunk_ucm.util import git_blob_sha
from unit import test_normalizer
from unit.test_catalog_storage import loaded_store


class QualityFlagTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_normalizer.FenreNormalizerTest.setUpClass()
        cls.n = test_normalizer.FenreNormalizerTest("test_deterministic")

    def flags(self, **changes):
        def mutate(raw):
            for key, value in changes.items():
                if value is None:
                    raw.pop(key, None)
                else:
                    raw[key] = value
        return self.n.normalize("9.1.1", mutate).quality_flags

    def test_review_signals(self):
        self.assertIn("unreviewed", self.flags(status=None))
        self.assertIn("unreviewed", self.flags(status="draft"))
        self.assertNotIn("unreviewed", self.flags(status="verified"))
        self.assertIn("reviewer_na", self.flags(reviewer="N/A"))
        for name in ("agent-handcraft-2026-04-29", "documentation-only Cursor AI editorial review",
                     "Claude (anthropic)", "Maintainer (AI-assisted review)"):
            self.assertIn("ai_reviewed", self.flags(reviewer=name), name)
        for name in ("Compliance SME Panel", "@splunk-monitoring-use-cases", "catalog-team"):
            flags = self.flags(reviewer=name)
            self.assertNotIn("ai_reviewed", flags, name)
            self.assertNotIn("reviewer_na", flags, name)

    def test_spl_dependency_and_compliance_signals(self):
        self.assertIn("unbounded_index", self.flags(spl="index=* sourcetype=x | stats count"))
        self.assertNotIn("unbounded_index", self.flags(spl="index=main sourcetype=x | stats count"))
        self.assertIn("es_required", self.flags(premiumApps=["Splunk Enterprise Security"]))
        self.assertIn("es_required", self.flags(premiumApps=[{"name": "Splunk Enterprise Security"}]))
        self.assertNotIn("es_required", self.flags(
            premiumApps=[{"name": "Splunk Enterprise Security", "note": "optional - for notables"}]))
        comp = {"regulation": "GDPR", "version": "2016/679", "clause": "Art.32", "mode": "satisfies",
                "assurance": "partial", "assurance_rationale": "Supports security of processing."}
        self.assertNotIn("sme_review_pending", self.flags(compliance=[comp]))
        self.assertIn("sme_review_pending", self.flags(compliance=[dict(comp, requires_sme_review=True)]))

    def test_flags_are_deterministic_and_ordered(self):
        flags = self.flags(status=None, reviewer="N/A", spl="index=* | stats count",
                           premiumApps=["Splunk Enterprise Security"])
        self.assertEqual(flags, [f for f in FLAG_ORDER if f in flags])
        self.assertEqual(flags, ["unreviewed", "reviewer_na", "unbounded_index", "es_required"])

    def test_view_labels_match_flags(self):
        import os
        import re
        path = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "appserver", "static", "ucm_common.js")
        with open(path, encoding="utf-8") as handle:
            block = handle.read().split("var QUALITY_FLAGS = {", 1)[1].split("};", 1)[0]
        self.assertEqual(re.findall(r"^\s*(\w+):", block, re.M), list(FLAG_ORDER))

    def test_spl_hash_ignores_whitespace(self):
        self.assertEqual(spl_hash("index=a  |\n stats count"), spl_hash("index=a | stats count"))
        self.assertEqual(spl_hash("  "), "")


class DuplicateSplTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_store()
        for key in ("fenre_UC-9.1.1", "fenre_UC-9.1.2"):
            doc = self.store.get(C.CATALOG, key)
            doc["spl_hash"] = "f" * 64
            self.store.upsert(C.CATALOG, doc)

    def flagged(self):
        return sorted(d["_key"] for d in self.store.query(C.CATALOG, {"quality_flags": "duplicate_spl"}))

    def test_shared_hash_is_flagged_and_cleared(self):
        self.assertEqual(refresh_derived(self.store), {"duplicate_groups": 1, "updated": 2})
        self.assertEqual(self.flagged(), ["fenre_UC-9.1.1", "fenre_UC-9.1.2"])
        self.assertEqual(refresh_derived(self.store)["updated"], 0)
        doc = self.store.get(C.CATALOG, "fenre_UC-9.1.2")
        doc["provider_status"] = "withdrawn"
        self.store.upsert(C.CATALOG, doc)
        refresh_derived(self.store)
        self.assertEqual(self.flagged(), [])

    def test_filter_badges_and_detail(self):
        refresh_derived(self.store)
        svc = CatalogQueryService(self.store, max_page_size=1)
        first = svc.search(CatalogFilter(quality=["duplicate_spl"], count=1))
        second = svc.search(CatalogFilter(quality=["duplicate_spl"], count=1, offset=1))
        self.assertEqual((first["total"], first["has_more"], second["has_more"]), (2, True, False))
        self.assertEqual([first["items"][0]["content_id"], second["items"][0]["content_id"]],
                         ["fenre:UC-9.1.1", "fenre:UC-9.1.2"])
        self.assertIn("duplicate_spl", first["items"][0]["quality_flags"])
        with self.assertRaises(ValidationError):
            svc.search(CatalogFilter(quality=["nonsense"]))
        detail = UseCaseDetailService(ContentRepository(self.store), CategoryRepository(self.store))
        d = detail.get("fenre:UC-9.1.1")
        self.assertIn("duplicate_spl", d["quality_flags"])
        self.assertEqual(d["spl_duplicates"], ["fenre:UC-9.1.2"])

    def test_sync_recomputes_duplicates(self):
        from splunk_ucm.audit import AuditService
        from splunk_ucm.content.registry import bundle_provider
        from splunk_ucm.content.sync import SyncService, new_job
        import json
        bundle = helpers.fixture_bundle()
        for rec in bundle["records"][:2]:
            raw = json.loads(rec["content"])
            raw["spl"] = "index=dup sourcetype=dup | stats count"
            rec["content"] = json.dumps(raw)
            rec["blob_sha"] = git_blob_sha(rec["content"].encode("utf-8"))
        SyncService(self.store, AuditService(self.store)).run(
            new_job("t", "fenre", [c["category_id"] for c in bundle["categories"]], force=True),
            bundle_provider(bundle))
        ids = sorted("fenre_UC-" + r["record_id"] for r in bundle["records"][:2])
        self.assertEqual(self.flagged(), ids)


if __name__ == "__main__":
    unittest.main()

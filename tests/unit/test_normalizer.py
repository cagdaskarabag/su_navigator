import copy
import json
import unittest

import helpers
from splunk_ucm.content.fenre.normalizer import NORMALIZER_VERSION, FenreNormalizer
from splunk_ucm.content.provider import ProviderRecord
from splunk_ucm.content.registry import bundle_provider
from splunk_ucm.util import canonical_json

IMPORTED = "2026-01-01T00:00:00Z"


class FenreNormalizerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = bundle_provider(helpers.fixture_bundle())
        cls.manifest = cls.provider.get_manifest()
        cls.normalizer = FenreNormalizer()

    def normalize(self, record_id, mutate=None):
        rec = self.provider.get_use_case(self.manifest, record_id)
        if mutate:
            raw = copy.deepcopy(rec.raw)
            mutate(raw)
            rec = ProviderRecord(rec.provider, rec.record_id, rec.category_id, rec.path, raw, rec.raw_size,
                                 rec.blob_sha, rec.source_url)
        cat = self.normalizer.normalize_category(self.manifest.category(rec.category_id))
        return self.normalizer.normalize(rec, cat, self.manifest, IMPORTED)

    def reqs(self, uc):
        return {r.req_id: r for r in uc.requirements}

    def test_identity_and_provenance(self):
        uc = self.normalize("9.1.1")
        self.assertEqual(uc.content_id, "fenre:UC-9.1.1")
        self.assertEqual(uc.key, "fenre_UC-9.1.1")
        p = uc.provenance
        self.assertEqual(p.provider_record_id, "9.1.1")
        self.assertEqual(p.provider_version, "8.28.0")
        self.assertEqual(p.source_path, "content/cat-09-identity-access-management/UC-9.1.1.json")
        self.assertEqual(len(p.source_blob_sha), 40)
        self.assertEqual(p.normalizer_version, NORMALIZER_VERSION)
        self.assertEqual(p.source_schema, "uc.schema.json@1.11.0")

    def test_deterministic(self):
        a = canonical_json(self.normalize("10.4.24").to_dict())
        b = canonical_json(self.normalize("10.4.24").to_dict())
        self.assertEqual(a, b)

    def test_domains_and_subcategory(self):
        uc = self.normalize("9.1.1")
        self.assertEqual(set(uc.domains), {"security", "identity"})
        self.assertEqual(uc.subcategory, "Active Directory / Entra ID")

    def test_mitre_mappings(self):
        uc = self.normalize("9.1.1")
        mitre = [(m.object_id, m.object_type, m.domain) for m in uc.framework_mappings
                 if m.framework == "mitre_attack"]
        self.assertIn(("T1110", "technique", "enterprise"), mitre)
        self.assertIn(("T1110.001", "sub-technique", "enterprise"), mitre)

    def test_mitre_ics_tactic_and_na(self):
        uc = self.normalize("9.1.1", lambda r: r.update(mitreAttack=["T0855", "TA0006", "N/A (not a detection)"]))
        by_id = {m.object_id: m for m in uc.framework_mappings if m.framework == "mitre_attack"}
        self.assertEqual(by_id["T0855"].domain, "ics")
        self.assertEqual(by_id["TA0006"].object_type, "tactic")
        self.assertEqual(uc.framework_na_reasons, ["not a detection"])

    def test_regulation_ids_use_obligation_ref_and_dedupe(self):
        uc = self.normalize("9.1.1")
        regs = [(m.framework, m.object_id, m.framework_version) for m in uc.framework_mappings
                if m.framework.startswith("regulation:")]
        self.assertNotIn("regulation:Cyber Essentials", [r[0] for r in regs])
        self.assertEqual(regs.count(("regulation:uk-cyber-essentials", "CE.SAU.1", "Montpellier (2025)")), 1)
        self.assertEqual(len(regs), len(set(regs)))
        ce = next(m for m in uc.framework_mappings if m.framework == "regulation:uk-cyber-essentials")
        self.assertEqual(ce.attributes["mode"], "detects-violation-of")
        self.assertEqual(ce.attributes["assurance"], "partial")

    def test_regulation_id_fallback_slug(self):
        def mutate(r):
            r["compliance"] = [{"regulation": "HIPAA Security", "version": "2013", "clause": "164.312(b)",
                                "mode": "satisfies", "assurance": "full", "assurance_rationale": "x"}]
        uc = self.normalize("9.1.1", mutate)
        self.assertEqual([m.framework for m in uc.framework_mappings if m.object_type == "control"],
                         ["regulation:hipaa-security"])

    def test_requirements_derived_from_spl_are_labelled(self):
        reqs = self.reqs(self.normalize("9.1.1"))
        st = reqs["sourcetype:WinEventLog:Security"]
        self.assertEqual((st.level, st.source), ("required", "derived_spl"))
        self.assertNotEqual(st.confidence, "high")
        idx = reqs["index:wineventlog"]
        self.assertEqual(idx.level, "informational")
        self.assertEqual(reqs["cim_model:Authentication"].source, "provider_structured")

    def test_fields_produced_by_the_search_are_informational(self):
        spl = ('index=itsm sourcetype=snow:incident priority=1 | eval opened=strptime(opened_at,"%F") '
               '| eval age_days=round((now()-opened)/86400,1) | eval user=lower(user) '
               '| stats count as breaches by assignment_group user')
        uc = self.normalize("9.1.1", lambda r: r.update(
            spl=spl, requiredFields=["opened_at", "priority", "age_days", "user", "breaches", "assignment_group"]))
        reqs = self.reqs(uc)
        for name, command in (("age_days", "eval"), ("breaches", "stats")):
            req = reqs["field:" + name]
            self.assertEqual((req.level, req.confidence, req.attributes), ("informational", "medium",
                                                                           {"derived_in_spl": command}))
            self.assertIn("derived_in_spl", req.notes)
        for name in ("opened_at", "priority", "user", "assignment_group"):
            self.assertEqual((reqs["field:" + name].level, reqs["field:" + name].confidence), ("required", "high"))

    def test_missing_spl_is_a_critical_gap(self):
        uc = self.normalize("9.1.1", lambda r: (r.pop("spl", None), r.pop("cimSpl", None)))
        types = {r.type: r for r in uc.requirements}
        self.assertIn("spl_validity", types)
        self.assertEqual(types["spl_validity"].level, "critical")

    def test_references_safe_and_relative_links_become_repo_paths(self):
        def mutate(r):
            r["references"] = [{"url": "javascript:alert(1)", "title": "bad"},
                               {"url": "../../docs/guide.md", "title": "rel"},
                               {"url": "https://example.com/x", "title": "ok"}]
        uc = self.normalize("9.1.1", mutate)
        urls = [ref.url for ref in uc.references]
        self.assertNotIn("javascript:alert(1)", urls)
        self.assertIn("https://example.com/x", urls)
        rel = [ref for ref in uc.references if ref.title == "rel"]
        self.assertEqual(rel[0].url, "")
        self.assertEqual(rel[0].repo_path, "docs/guide.md")

    def test_unmapped_fields_preserved_in_extras(self):
        uc = self.normalize("9.1.1", lambda r: r.update(brandNewField=[1, 2]))
        self.assertEqual(uc.provider_extras.get("brandNewField"), [1, 2])

    def test_every_fixture_normalizes_and_serializes(self):
        for pcat in self.manifest.categories:
            for listing in self.provider.list_records(self.manifest, pcat):
                uc = self.normalize(listing.record_id)
                json.dumps(uc.to_dict())
                self.assertTrue(uc.title)
                self.assertTrue(uc.domains, listing.record_id)

    def test_compliance_substance_is_kept(self):
        def mutate(raw):
            raw["compliance"] = [
                dict(raw["compliance"][0], clauseUrl="https://gdpr-info.eu/art-7-gdpr/", requires_sme_review=True,
                     smeCaveat="Confirm the regulator expectation before uplifting assurance."),
                dict(raw["compliance"][0], clause="Art.32", clauseUrl="javascript:alert(1)",
                     requires_sme_review="yes")]
        uc = self.normalize("10.4.24", mutate)
        regs = [m for m in uc.framework_mappings if m.framework.startswith("regulation:")]
        first, second = regs[0].attributes, regs[1].attributes
        self.assertTrue(first["control_objective"].startswith("Evidence that GDPR"))
        self.assertIn("Saved search 'UC-10.4.24'", first["evidence_artifact"])
        self.assertTrue(first["assurance_rationale"].startswith("Auto-generated"))
        self.assertEqual((first["clause_url"], first["requires_sme_review"]), ("https://gdpr-info.eu/art-7-gdpr/", True))
        self.assertTrue(first["sme_caveat"].startswith("Confirm"))
        self.assertNotIn("clause_url", second)
        self.assertNotIn("requires_sme_review", second)

    def test_scope_testing_and_hardware_are_mapped(self):
        uc = self.normalize("10.4.24", lambda raw: raw.update(
            hardware="Edge sensors with BMC access", equipment=["azure", "splunk-es"], exclusions="x" * 5000))
        self.assertEqual(uc.wave, "crawl")
        self.assertTrue(uc.control_test["positiveScenario"].startswith("UC-10.4.24 positive"))
        self.assertIn("negativeScenario", uc.control_test)
        self.assertEqual(len(uc.exclusions), 4000)
        self.assertEqual((uc.hardware, uc.equipment), ("Edge sensors with BMC access", ["azure", "splunk-es"]))
        self.assertIn("azure", uc.tags)
        for key in ("wave", "controlTest", "exclusions", "hardware"):
            self.assertNotIn(key, uc.provider_extras)
        self.assertIn("grandmaExplanation", uc.provider_extras)
        odd = self.normalize("10.4.24", lambda raw: raw.update(wave="sprint", controlTest="text"))
        self.assertEqual((odd.wave, odd.control_test), ("", {}))


if __name__ == "__main__":
    unittest.main()

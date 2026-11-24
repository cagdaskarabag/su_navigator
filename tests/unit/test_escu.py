import copy
import io
import json
import os
import tarfile
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.catalog.detail import UseCaseDetailService
from splunk_ucm.content.bundle import parse_bundle
from splunk_ucm.content.escu.package import build_bundle
from splunk_ucm.content.importer import BundleImportService
from splunk_ucm.content.registry import bundle_provider
from splunk_ucm.content.sync import SyncService
from splunk_ucm.errors import ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "escu", "DA-ESS-ContentUpdate")
DEFENDER = "escu:UC-11111111-2222-4333-8444-555555555501"
SCANNING = "escu:UC-11111111-2222-4333-8444-555555555502"
LOGONS = "escu:UC-11111111-2222-4333-8444-555555555503"
POWERSHELL = "escu:UC-11111111-2222-4333-8444-555555555505"
RETIRED = "11111111-2222-4333-8444-555555555504"


def _archive(path):
    with tarfile.open(path, "w:gz") as tar:
        for root, _, files in os.walk(FIXTURE):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, os.path.dirname(FIXTURE))
                tar.add(full, arcname=rel)


class PackageTest(unittest.TestCase):
    def test_directory_build_skips_deprecated_and_non_detections(self):
        bundle, report = build_bundle(FIXTURE)
        parse_bundle(bundle)
        self.assertEqual(report["records"], 4)
        self.assertEqual(report["skipped"], {"deprecated": 1})
        self.assertEqual(report["provider_version"], "6.11.1-fixture")
        self.assertEqual(report["categories"], {"endpoint": 1, "network": 1, "identity": 1, "unassigned": 1})
        self.assertNotIn(RETIRED, json.dumps(bundle))
        self.assertTrue(bundle["source_ref"].startswith("local:"))

    def test_output_is_deterministic(self):
        first, _ = build_bundle(FIXTURE)
        second, _ = build_bundle(FIXTURE)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_archive_and_directory_give_the_same_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "escu.tgz")
            _archive(archive)
            from_archive, report = build_bundle(archive)
        from_dir, _ = build_bundle(FIXTURE)
        self.assertEqual(from_archive["records"], from_dir["records"])
        self.assertTrue(report["source_ref"].startswith("escu-package:sha256:"))

    def test_unreadable_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            bogus = os.path.join(tmp, "bogus.tgz")
            with open(bogus, "wb") as fh:
                fh.write(b"not a tarball")
            with self.assertRaises(ValidationError):
                build_bundle(bogus)
            empty = os.path.join(tmp, "empty.tgz")
            with tarfile.open(empty, "w:gz") as tar:
                info = tarfile.TarInfo("x.txt")
                info.size = 0
                tar.addfile(info, io.BytesIO(b""))
            with self.assertRaises(ValidationError):
                build_bundle(empty)
        with self.assertRaises(ValidationError):
            build_bundle(os.path.join(FIXTURE, "missing"))


class ImportTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.service = BundleImportService(SyncService(self.store, AuditService(self.store)), 5 * 1024 * 1024)
        self.bundle, _ = build_bundle(FIXTURE)

    def content(self, content_id):
        return UseCaseDetailService(ContentRepository(self.store), CategoryRepository(self.store)).get(content_id)

    def test_import_normalizes_detections(self):
        job = self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["totals"]["added"], 4)
        rows = self.store.query(C.CATALOG, {"provider": "escu"})
        self.assertEqual(len(rows), 4)
        self.assertEqual({r["content_id"] for r in rows}, {DEFENDER, SCANNING, LOGONS, POWERSHELL})
        self.assertEqual(self.store.query(C.CATALOG, {"provider": "escu", "provider_status": "withdrawn"}), [])

    def test_fields_are_mapped_from_the_package(self):
        self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        uc = self.content(DEFENDER)
        self.assertEqual(uc["title"], "Disable Windows Defender Real-time Protection")
        self.assertEqual(uc["criticality"], "high")
        self.assertEqual(uc["tags"], ["Windows Defender Tampering"])
        self.assertEqual(uc["subcategory"], "Windows Defender Tampering")
        self.assertEqual(uc["monitoring_types"], ["TTP"])
        self.assertEqual(uc["products"], ["Splunk Enterprise Security"])
        self.assertEqual(uc["review_status"], "released")
        self.assertIn("Sysmon EventID 13", uc["data_sources_text"])
        self.assertEqual(uc["schedule"]["cron"], "0 * * * *")
        self.assertIn("tstats", uc["spl"])
        self.assertIn("security_content_summariesonly", uc["macros"])
        self.assertEqual(uc["provider_extras"]["cis20"], ["CIS 8"])
        self.assertEqual(uc["provider_extras"]["stanza"], "ESCU - Disable Windows Defender Real-time Protection - Rule")
        self.assertEqual(uc["domains"], ["endpoint"])
        self.assertEqual(uc["provenance"]["provider"], "escu")
        self.assertEqual(uc["provenance"]["provider_version"], "6.11.1-fixture")
        mapping = [(m["framework"], m["object_id"], m["object_type"]) for m in uc["framework_mappings"]]
        self.assertEqual(mapping, [("mitre_attack", "T1562.001", "sub-technique")])

    def test_requirements_come_from_the_spl(self):
        self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        reqs = {(r["type"], r["value"]) for r in self.content(LOGONS)["requirements"]}
        self.assertIn(("index", "wineventlog"), reqs)
        self.assertIn(("sourcetype", "pan:traffic"), {(r["type"], r["value"]) for r in self.content(SCANNING)["requirements"]})
        self.assertEqual([m["object_type"] for m in self.content(LOGONS)["framework_mappings"]],
                         ["sub-technique", "technique"])

    def test_unassigned_domain_and_no_notable(self):
        self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        uc = self.content(POWERSHELL)
        self.assertEqual(uc["category_name"], "Unassigned")
        self.assertEqual(uc["domains"], ["other"])
        self.assertEqual(uc["criticality"], "unknown")

    def test_reimport_is_unchanged_and_other_providers_are_untouched(self):
        self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        again = self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        self.assertEqual(again["totals"]["added"], 0)
        self.assertEqual(again["totals"]["withdrawn"], 0)
        fenre = copy.deepcopy(helpers.fixture_bundle())
        self.service.import_bundle(fenre, "admin")
        self.assertEqual(len(self.store.query(C.CATALOG, {"provider": "fenre", "provider_status": "active"})), 10)
        self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        self.assertEqual(len(self.store.query(C.CATALOG, {"provider": "fenre", "provider_status": "active"})), 10)
        self.assertEqual(len(self.store.query(C.CATALOG, {"provider": "escu", "provider_status": "active"})), 4)

    def test_partial_escu_bundle_withdraws_only_within_its_categories(self):
        self.service.import_bundle(copy.deepcopy(self.bundle), "admin")
        smaller = copy.deepcopy(self.bundle)
        smaller["records"] = [r for r in smaller["records"] if "555555555505" not in r["path"]]
        job = self.service.import_bundle(smaller, "admin")
        self.assertEqual(job["totals"]["withdrawn"], 1)
        self.assertEqual(len(self.store.query(C.CATALOG, {"provider": "escu", "provider_status": "active"})), 3)

    def test_bad_record_id_is_rejected_by_validation(self):
        bundle = copy.deepcopy(self.bundle)
        record = bundle["records"][0]
        raw = json.loads(record["content"])
        raw["id"] = "not-a-uuid"
        content = json.dumps(raw, sort_keys=True, indent=2) + "\n"
        from splunk_ucm.util import git_blob_sha
        record.update(content=content, blob_sha=git_blob_sha(content.encode("utf-8")),
                      record_id="not-a-uuid")
        job = self.service.import_bundle(bundle, "admin")
        self.assertEqual(job["totals"]["added"], 3)
        self.assertEqual(job["totals"]["invalid"], 1)
        self.assertEqual(len(self.store.query(C.CATALOG, {"provider": "escu", "provider_status": "active"})), 3)

    def test_provider_is_registered(self):
        provider = bundle_provider(self.bundle)
        self.assertEqual(provider.provider_id, "escu")
        manifest = provider.get_manifest()
        self.assertEqual(manifest.schema_version, "1.0")
        self.assertEqual([c.slug for c in manifest.categories], ["endpoint", "network", "identity", "unassigned"])


if __name__ == "__main__":
    unittest.main()

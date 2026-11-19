import json
import unittest

import helpers
from splunk_ucm.audit import AuditService
from splunk_ucm.content.bundle import parse_bundle
from splunk_ucm.content.importer import BundleImportService
from splunk_ucm.content.registry import bundle_provider
from splunk_ucm.content.sync import SyncService
from splunk_ucm.errors import IntegrityError, ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.service = BundleImportService(SyncService(self.store, AuditService(self.store)), 5 * 1024 * 1024)

    def test_builder_output_parses(self):
        bundle = helpers.fixture_bundle()
        parse_bundle(bundle)
        self.assertEqual(len(bundle["records"]), 10)
        self.assertFalse(bundle["partial"])
        self.assertTrue(helpers.fixture_bundle(record_ids=["9.1.1"])["partial"])

    def test_structural_rejections(self):
        good = helpers.fixture_bundle(record_ids=["9.1.1"])
        cases = [
            [],
            dict(good, format="other"),
            dict(good, format_version=2),
            dict(good, provider="../etc"),
            dict(good, categories=[]),
            dict(good, records=[dict(good["records"][0], category_id="999")]),
            dict(good, records=[{k: v for k, v in good["records"][0].items() if k != "blob_sha"}]),
            dict(good, schema="not-an-object"),
        ]
        for case in cases:
            with self.assertRaises(ValidationError):
                parse_bundle(case)
        with self.assertRaises(ValidationError):
            parse_bundle(dict(good, records=good["records"] * 3), max_records=2)

    def test_tampered_content_rejected(self):
        bundle = helpers.fixture_bundle(record_ids=["9.1.1"])
        bundle["records"][0]["content"] = bundle["records"][0]["content"].replace("Brute", "Evil")
        provider = bundle_provider(bundle)
        m = provider.get_manifest()
        with self.assertRaises(IntegrityError):
            provider.get_use_case(m, "9.1.1")

    def test_import_bytes_end_to_end_and_idempotent(self):
        payload = json.dumps(helpers.fixture_bundle()).encode("utf-8")
        job = self.service.import_bytes(payload, "admin")
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["source"], "offline_bundle")
        self.assertEqual(job["totals"]["added"], 10)
        self.assertEqual(len(self.store.query(C.CATALOG)), 10)
        again = self.service.import_bytes(payload, "admin")
        self.assertEqual(again["totals"]["unchanged"], 10)

    def test_import_category_subset(self):
        payload = json.dumps(helpers.fixture_bundle()).encode("utf-8")
        job = self.service.import_bytes(payload, "admin", categories=["9"])
        self.assertEqual(job["categories"], ["9"])
        self.assertEqual(job["totals"]["added"], 2)
        with self.assertRaises(ValidationError):
            self.service.import_bytes(payload, "admin", categories=["99"])

    def test_size_and_encoding_limits(self):
        small = BundleImportService(SyncService(self.store, AuditService(self.store)), 100)
        with self.assertRaises(ValidationError):
            small.import_bytes(b"{" + b" " * 200 + b"}", "admin")
        for payload in (b"\xff\xfe", b"not json", b"[]"):
            with self.assertRaises(ValidationError):
                self.service.import_bytes(payload, "admin")

    def test_import_job_never_left_queued_for_worker(self):
        payload = json.dumps(helpers.fixture_bundle(record_ids=["9.1.1"])).encode("utf-8")
        self.service.import_bytes(payload, "admin")
        self.assertIsNone(self.service.sync.state.next_queued())


if __name__ == "__main__":
    unittest.main()

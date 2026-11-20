import json
import unittest

import helpers
from splunk_ucm.audit import AuditService
from splunk_ucm.content import sync as S
from splunk_ucm.content.registry import bundle_provider
from splunk_ucm.errors import ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import decode_raw


class SyncServiceTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.gh = helpers.FakeGitHub()
        self.svc = S.SyncService(self.store, AuditService(self.store), S.SyncSettings(fetch_concurrency=2))

    def run_sync(self, categories=("9", "10"), provider=None, **kw):
        job = S.new_job("tester", "fenre", list(categories), **kw)
        return self.svc.run(job, provider or helpers.fenre_provider(self.gh))

    def catalog(self, key):
        return self.store.get(C.CATALOG, key)

    def raw_record_downloads(self):
        return [u for u in self.gh.requests if u.startswith(helpers.RAW) and "/UC-" in u]

    def test_initial_sync_imports_and_records_state(self):
        job = self.run_sync()
        self.assertEqual(job["status"], S.JOB_SUCCEEDED)
        self.assertEqual(job["totals"]["added"], 3)
        self.assertEqual(job["source_ref"], self.gh.commit)
        doc = self.catalog("fenre_UC-9.1.1")
        self.assertEqual(doc["provider_status"], "active")
        content = self.store.get(C.CONTENT, "fenre_UC-9.1.1")
        self.assertEqual(decode_raw(content), helpers.load_fixture_record("9.1.1"))
        self.assertNotIn("raw_record", content)
        state = self.svc.state.provider_state("fenre")
        self.assertEqual(state["last_good_ref"], self.gh.commit)
        self.assertEqual(state["schema_version"], "1.11.0")
        self.assertEqual(state["last_good_source"], "manual")
        audit = [a["action"] for a in self.store.query(C.AUDIT)]
        self.assertIn("content.sync.completed", audit)

    def test_resync_unchanged_downloads_nothing(self):
        self.run_sync()
        self.gh.requests.clear()
        job = self.run_sync()
        self.assertEqual(job["totals"]["unchanged"], 3)
        self.assertEqual(job["totals"]["added"] + job["totals"]["updated"], 0)
        self.assertEqual(self.raw_record_downloads(), [])

    def test_updated_record_detected_by_blob_sha(self):
        self.run_sync()
        path = helpers.record_path("9.1.1", self.gh.files)
        rec = json.loads(self.gh.files[path])
        rec["title"] = "Brute-Force Login Detection (revised)"
        self.gh.put(path, rec)
        self.gh.requests.clear()
        job = self.run_sync()
        self.assertEqual(job["totals"]["updated"], 1)
        self.assertEqual(job["totals"]["unchanged"], 2)
        self.assertEqual(len(self.raw_record_downloads()), 1)
        self.assertEqual(self.catalog("fenre_UC-9.1.1")["title"], "Brute-Force Login Detection (revised)")

    def test_removed_record_marked_withdrawn_not_deleted(self):
        self.run_sync()
        self.gh.delete(helpers.record_path("9.1.2", self.gh.files))
        job = self.run_sync()
        self.assertEqual(job["totals"]["withdrawn"], 1)
        doc = self.catalog("fenre_UC-9.1.2")
        self.assertEqual(doc["provider_status"], "withdrawn")
        self.assertIsNotNone(self.store.get(C.CONTENT, "fenre_UC-9.1.2"))

    def test_fetch_failure_keeps_last_known_good(self):
        self.run_sync()
        path = helpers.record_path("9.1.1", self.gh.files)
        rec = json.loads(self.gh.files[path])
        rec["title"] = "new title"
        self.gh.put(path, rec)
        self.gh.fail_paths.add(path)
        job = self.run_sync()
        self.assertEqual(job["status"], S.JOB_PARTIAL)
        failed = [r for r in job["results"] if r["status"] == S.CAT_FAILED]
        self.assertEqual([r["category_id"] for r in failed], ["9"])
        self.assertEqual(self.catalog("fenre_UC-9.1.1")["title"], "Brute-Force Login Detection")
        self.gh.fail_paths.clear()
        job = self.run_sync()
        self.assertEqual(job["status"], S.JOB_SUCCEEDED)
        self.assertEqual(self.catalog("fenre_UC-9.1.1")["title"], "new title")

    def test_invalid_ratio_fails_category_atomically(self):
        self.run_sync()
        path = helpers.record_path("9.1.2", self.gh.files)
        self.gh.put(path, {"id": "9.1.2"})
        good = helpers.record_path("9.1.1", self.gh.files)
        rec = json.loads(self.gh.files[good])
        rec["title"] = "should not land"
        self.gh.put(good, rec)
        job = self.run_sync(categories=["9"])
        result = job["results"][0]
        self.assertEqual(result["status"], S.CAT_FAILED)
        self.assertEqual(result["errors"][0]["code"], "invalid_ratio_exceeded")
        self.assertEqual(self.catalog("fenre_UC-9.1.1")["title"], "Brute-Force Login Detection")

    def test_invalid_record_below_ratio_keeps_previous_version(self):
        self.svc.settings.max_invalid_ratio = 0.6
        self.run_sync(categories=["9"])
        path = helpers.record_path("9.1.2", self.gh.files)
        self.gh.put(path, {"id": "9.1.2", "title": ""})
        job = self.run_sync(categories=["9"])
        result = job["results"][0]
        self.assertEqual(result["status"], S.CAT_OK)
        self.assertEqual(result["invalid"], 1)
        self.assertEqual(self.catalog("fenre_UC-9.1.2")["provider_status"], "active")
        self.assertTrue(self.catalog("fenre_UC-9.1.2")["title"])

    def test_id_path_mismatch_rejected(self):
        self.svc.settings.max_invalid_ratio = 0.6
        path = helpers.record_path("9.1.2", self.gh.files)
        rec = json.loads(self.gh.files[path])
        rec["id"] = "9.1.1"
        self.gh.put(path, rec)
        job = self.run_sync(categories=["9"])
        self.assertEqual(job["results"][0]["invalid"], 1)
        self.assertIsNone(self.catalog("fenre_UC-9.1.2"))

    def test_schema_major_change_requires_confirmation(self):
        self.run_sync()
        schema = json.loads(self.gh.files["schemas/uc.schema.json"])
        schema["version"] = "2.0.0"
        self.gh.put("schemas/uc.schema.json", schema)
        job = self.run_sync()
        self.assertEqual(job["status"], S.JOB_FAILED)
        self.assertEqual(job["errors"][0]["code"], "schema_incompatible")
        job = self.run_sync(allow_schema_change=True)
        self.assertNotEqual(job["status"], S.JOB_FAILED)
        self.assertEqual(self.svc.state.provider_state("fenre")["schema_version"], "2.0.0")

    def test_normalizer_upgrade_renormalizes_without_download(self):
        self.run_sync()
        for doc in self.store.query(C.CATALOG):
            doc["normalizer_version"] = "fenre-0.0.1"
            self.store.batch_save(C.CATALOG, [doc])
        for doc in self.store.query(C.CATEGORIES):
            doc["normalizer_version"] = "fenre-0.0.1"
            self.store.batch_save(C.CATEGORIES, [doc])
        self.gh.requests.clear()
        job = self.run_sync()
        self.assertEqual(job["totals"]["renormalized"], 3)
        self.assertEqual(self.raw_record_downloads(), [])

    def test_unknown_category_reported(self):
        job = self.run_sync(categories=["9", "77"])
        self.assertEqual(job["status"], S.JOB_PARTIAL)
        self.assertEqual([r["status"] for r in job["results"] if r["category_id"] == "77"], [S.CAT_FAILED])

    def test_enqueue_blocks_concurrent_jobs(self):
        self.svc.enqueue(S.new_job("a", "fenre", ["9"]))
        with self.assertRaises(ValidationError):
            self.svc.enqueue(S.new_job("b", "fenre", ["10"]))

    def test_customer_owned_collections_untouched(self):
        user_doc = {"_key": "sel1", "content_id": "fenre:UC-9.1.2", "note": "my selection"}
        self.store.batch_save(C.SELECTIONS, [user_doc])
        self.run_sync()
        self.gh.delete(helpers.record_path("9.1.2", self.gh.files))
        self.run_sync()
        self.assertEqual(self.store.get(C.SELECTIONS, "sel1"), user_doc)

    def test_partial_bundle_never_withdraws(self):
        self.run_sync(categories=["9"])
        provider = bundle_provider(helpers.fixture_bundle(record_ids=["9.1.1"]))
        job = self.run_sync(categories=["9"], provider=provider)
        self.assertEqual(job["status"], S.JOB_SUCCEEDED)
        self.assertEqual(job["totals"]["withdrawn"], 0)
        self.assertEqual(self.catalog("fenre_UC-9.1.2")["provider_status"], "active")

    def test_full_bundle_and_remote_agree(self):
        self.run_sync(categories=["9"])
        remote = {d["_key"]: d["source_blob_sha"] for d in self.store.query(C.CATALOG)}
        store2 = InMemoryStore()
        svc2 = S.SyncService(store2, AuditService(store2))
        svc2.run(S.new_job("t", "fenre", ["9"]), bundle_provider(helpers.fixture_bundle(category_ids=["9"])))
        offline = {d["_key"]: d["source_blob_sha"] for d in store2.query(C.CATALOG)}
        self.assertEqual(remote, offline)


if __name__ == "__main__":
    unittest.main()

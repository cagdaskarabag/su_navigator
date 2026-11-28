"""Reindex as a background job (issue #25)."""

import datetime
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.api.app import CAP_MANAGE_CONTENT
from splunk_ucm.audit import AuditService
from splunk_ucm.config import AppConfig
from splunk_ucm.content.reindex_job import KEY, STALE_SECONDS, ReindexJobs
from splunk_ucm.errors import ConflictError, ValidationError
from splunk_ucm.maintenance.worker import MaintenanceWorker
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog

T0 = datetime.datetime(2026, 11, 28, 10, 0, 0, tzinfo=datetime.timezone.utc)


def at(seconds):
    return lambda: T0 + datetime.timedelta(seconds=seconds)


class JobTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.audit = AuditService(self.store)

    def test_queued_then_run_records_result_and_audit(self):
        jobs = ReindexJobs(self.store, at(0))
        job = jobs.enqueue("alice")
        self.assertEqual((job["status"], job["requested_by"]), ("queued", "alice"))
        done = jobs.run_queued(self.audit)
        self.assertEqual(done["status"], "succeeded")
        self.assertGreater(done["result"]["reindexed"], 0)
        self.assertEqual(self.store.get(C.SYNC_STATE, KEY)["status"], "succeeded")
        rows = [r for r in self.store.query(C.AUDIT, {"action": "content.reindex"}, limit=10)]
        self.assertEqual([(r["actor"], r["outcome"]) for r in rows], [("alice", "success")])
        self.assertIsNone(jobs.run_queued(self.audit))

    def test_second_request_is_refused_while_active_and_allowed_after(self):
        jobs = ReindexJobs(self.store, at(0))
        jobs.enqueue("alice")
        with self.assertRaises(ConflictError):
            jobs.enqueue("bob")
        jobs.run_queued(self.audit)
        self.assertEqual(jobs.enqueue("bob")["requested_by"], "bob")

    def test_a_running_job_that_outlives_the_worker_is_reported_failed_and_can_be_replaced(self):
        jobs = ReindexJobs(self.store, at(0))
        jobs.enqueue("alice")
        doc = self.store.get(C.SYNC_STATE, KEY)
        self.store.upsert(C.SYNC_STATE, dict(doc, status="running", started_at="2026-11-28T10:00:00Z"))
        self.assertEqual(ReindexJobs(self.store, at(60)).current()["status"], "running")
        late = ReindexJobs(self.store, at(STALE_SECONDS + 1))
        self.assertEqual(late.current()["status"], "failed")
        self.assertEqual(late.enqueue("bob")["status"], "queued")

    def test_bad_category_is_refused(self):
        with self.assertRaises(ValidationError):
            ReindexJobs(self.store, at(0)).enqueue("alice", "../x")

    def test_worker_runs_it_after_migrations_and_before_retention(self):
        ReindexJobs(self.store, at(0)).enqueue("alice")
        worker = MaintenanceWorker(self.store, AppConfig({}), lambda: None, at(0), lambda: 0.0)
        results = []
        for _ in range(4):
            result = worker.run_once()
            results.append(result)
            if result.get("job") == "reindex":
                break
        self.assertEqual(results[-1]["job"], "reindex")
        self.assertEqual(results[-1]["status"], "succeeded")


class RouteTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()

    def test_background_flag_queues_and_status_route_reports(self):
        ctx = make_ctx(self.store, [CAP_MANAGE_CONTENT])
        status, body = call(ctx, "POST", "catalog/reindex", {"background": "1"}, b"{}")
        self.assertEqual((status, body["job"]["status"]), (200, "queued"), body)
        status, body = call(ctx, "GET", "catalog/reindex")
        self.assertEqual((status, body["job"]["status"]), (200, "queued"), body)
        status, body = call(ctx, "POST", "catalog/reindex", {"background": "1"}, b"{}")
        self.assertEqual(status, 409, body)

    def test_default_stays_synchronous(self):
        ctx = make_ctx(self.store, [CAP_MANAGE_CONTENT])
        status, body = call(ctx, "POST", "catalog/reindex", None, b"{}")
        self.assertEqual(status, 200, body)
        self.assertIn("reindexed", body)

    def test_both_need_the_content_capability(self):
        ctx = make_ctx(self.store, [])
        self.assertEqual(call(ctx, "POST", "catalog/reindex", {"background": "1"}, b"{}")[0], 403)
        self.assertEqual(call(ctx, "GET", "catalog/reindex")[0], 403)


if __name__ == "__main__":
    unittest.main()

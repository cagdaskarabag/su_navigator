"""KV write paths (D-039): evidence and job collections are written only with the system token."""

import datetime
import unittest

import helpers  # noqa: F401  (sets sys.path)
import splunk_ucm.api.app as app_module
from splunk_ucm.api.app import CAP_DEPLOY, CAP_MANAGE_CONTENT, CAP_RUN_DISCOVERY, Context
from splunk_ucm.config import AppConfig
from splunk_ucm.content.worker import SyncWorker
from splunk_ucm.discovery.service import new_job as new_discovery_job
from splunk_ucm.discovery.worker import DiscoveryWorker
from splunk_ucm.errors import PermissionDenied
from splunk_ucm.readiness.service import new_job as new_readiness_job
from splunk_ucm.selection.service import selection_key
from splunk_ucm.readiness.worker import ReadinessWorker
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.jobs import job_problem
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.content.sync import new_job as new_sync_job
from unit.test_api_worker import NoSplunkd, call
from unit.test_selection_validation import FakeParser, discovered

USER_WRITABLE = set()


class UserSessionStore:
    """The caller's KV view: reads pass through; writes follow default.meta for an analyst."""

    def __init__(self, backend):
        self.backend = backend
        self.writes = []

    def get(self, collection, key):
        return self.backend.get(collection, key)

    def query(self, *a, **kw):
        return self.backend.query(*a, **kw)

    def count(self, *a, **kw):
        return self.backend.count(*a, **kw)

    def _write(self, collection):
        self.writes.append(collection)
        if collection not in USER_WRITABLE:
            raise PermissionDenied("403 writing %s with the user session" % collection)

    def upsert(self, collection, doc):
        self._write(collection)
        return self.backend.upsert(collection, doc)

    def batch_save(self, collection, docs):
        self._write(collection)
        return self.backend.batch_save(collection, docs)

    def delete(self, collection, key):
        self._write(collection)
        return self.backend.delete(collection, key)

    def delete_query(self, collection, query):
        self._write(collection)
        return self.backend.delete_query(collection, query)


def contexts(caps):
    backend = discovered()
    user = UserSessionStore(backend)
    ctx = Context(NoSplunkd(), None, "alice", store=user, audit_store=backend, config=AppConfig({}),
                  record_store=backend)
    ctx._caps = list(caps)
    return ctx, user, backend


class StoreWiringTest(unittest.TestCase):
    def setUp(self):
        self.ctx, self.user, self.backend = contexts([CAP_RUN_DISCOVERY, CAP_DEPLOY, CAP_MANAGE_CONTENT])
        parser = FakeParser()
        self._orig = app_module.SearchClient
        app_module.SearchClient = lambda transport: parser

    def tearDown(self):
        app_module.SearchClient = self._orig

    def ok(self, method, path, body=None, query=None):
        status, out = call(self.ctx, method, path, query, body if body is not None else b"")
        self.assertLess(status, 300, (path, out))
        return out

    def test_analyst_flows_never_write_with_the_user_session(self):
        uc = "fenre:UC-9.1.1"
        self.ok("POST", "validate", {"id": uc, "sample": False})
        self.ok("POST", "preview", {"id": uc})
        self.ok("POST", "readiness/assess", {"id": uc})
        self.ok("POST", "readiness", {})
        self.ok("POST", "discovery", {"earliest": "-24h"})
        self.ok("POST", "mappings", {"kind": "sourcetype", "value": "wineventlog", "canonical_value": "WinEventLog"})
        self.ok("POST", "mappings/delete", {"kind": "sourcetype", "value": "wineventlog"})
        self.ok("POST", "deployment/draft", {"id": uc})
        self.ok("POST", "selections", {"id": uc, "intent": "select"})
        self.assertEqual(self.user.writes, [])
        self.assertIsNotNone(self.backend.get(C.SELECTIONS, selection_key("alice", uc)))
        self.assertIsNotNone(self.backend.get(C.VALIDATION, "fenre_UC-9.1.1"))
        self.assertIsNotNone(self.backend.get(C.READINESS, "fenre_UC-9.1.1"))
        kinds = {j.get("doc_type") for j in self.backend.query(C.SYNC_STATE)}
        self.assertTrue({"discovery_job", "readiness_job"} <= kinds)

    def test_selection_writes_use_the_system_store_for_the_session_user(self):
        uc = "fenre:UC-9.1.1"
        self.ok("POST", "selections", {"id": uc, "intent": "bookmark", "user": "mallory"})
        self.ok("POST", "selections/delete", {"id": uc, "user": "mallory"})
        self.assertEqual(self.user.writes, [])
        self.ok("POST", "selections", {"id": uc, "intent": "reject", "user": "mallory"})
        users = {row["user"] for row in self.backend.query(C.SELECTIONS)}
        self.assertEqual(users, {"alice"})

    def test_sync_enqueue_uses_the_system_store(self):
        self.ok("POST", "sync", {"categories": ["cat-09-identity-access-management"]})
        self.assertEqual(self.user.writes, [])
        self.assertTrue(any(j.get("doc_type") == "job" for j in self.backend.query(C.SYNC_STATE)))


class JobValidationTest(unittest.TestCase):
    def test_constructed_jobs_are_valid(self):
        for job in (new_sync_job("alice", "fenre", ["cat-01"], ref="v1.2.3"),
                    new_sync_job("scheduler", "fenre", None, source="schedule"),
                    new_discovery_job("alice", include_internal=True, earliest="-7d", latest="now"),
                    new_discovery_job("scheduler", source="schedule"),
                    new_readiness_job("system", source="auto")):
            self.assertIsNone(job_problem(job), job)

    def test_malformed_jobs(self):
        cases = [
            (dict(new_sync_job("a", "fenre", []), provider="evil"), "unknown provider"),
            (dict(new_sync_job("a", "fenre", []), categories=["../x"]), "malformed categories"),
            (dict(new_sync_job("a", "fenre", []), ref="main; rm -rf"), "malformed ref"),
            (dict(new_sync_job("a", "fenre", []), force="yes"), "malformed flags"),
            (dict(new_discovery_job("a"), earliest="-7d | delete"), "malformed earliest"),
            (dict(new_discovery_job("a"), include_internal="1"), "malformed include_internal"),
            (dict(new_readiness_job("a"), _key="rjob::other"), "malformed job id"),
            (dict(new_readiness_job("a"), requested_by=""), "malformed requested_by"),
            (dict(new_readiness_job("a"), source="cli"), "unknown job source"),
            ({"doc_type": "shell_job"}, "unknown job type"),
        ]
        for job, problem in cases:
            self.assertEqual(job_problem(job), problem)


class WorkerRejectsMalformedJobsTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.now = lambda: datetime.datetime(2026, 11, 24, tzinfo=datetime.timezone.utc)

    def assert_rejected(self, result, key):
        self.assertEqual(result["action"], "rejected")
        job = self.store.get(C.SYNC_STATE, key)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["errors"][-1]["code"], "invalid_job")

    def test_sync_worker(self):
        job = dict(new_sync_job("a", "fenre", []), ref="x y")
        self.store.upsert(C.SYNC_STATE, job)
        worker = SyncWorker(self.store, AppConfig({}), lambda *a: self.fail("provider built"),
                            lambda: "", lambda: True, now=self.now)
        self.assert_rejected(worker.run_once(), job["_key"])

    def test_discovery_worker(self):
        job = dict(new_discovery_job("a"), latest="now|delete")
        self.store.upsert(C.SYNC_STATE, job)
        worker = DiscoveryWorker(self.store, AppConfig({}), NoSplunkd(), lambda: True, now=self.now,
                                 inventory=object(), search=object())
        self.assert_rejected(worker.run_once(), job["_key"])

    def test_readiness_worker(self):
        job = dict(new_readiness_job("a"), source="forged")
        self.store.upsert(C.SYNC_STATE, job)
        worker = ReadinessWorker(self.store, AppConfig({"readiness": {"auto_assess": "0"}}), lambda: True,
                                 now=self.now)
        self.assert_rejected(worker.run_once(), job["_key"])


if __name__ == "__main__":
    unittest.main()

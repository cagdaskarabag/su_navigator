import datetime
import importlib.util
import json
import os
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm import __version__
from splunk_ucm.api.app import build_router
from splunk_ucm.catalog.summary import SUMMARY_VERSION
from splunk_ucm.config import AppConfig
from splunk_ucm.content.worker import SyncWorker
from splunk_ucm.deployment.worker import DeploymentWorker
from splunk_ucm.discovery.worker import DiscoveryWorker
from splunk_ucm.maintenance.migrations import MIGRATIONS, STATE_KEY, MigrationRunner
from splunk_ucm.maintenance.retention import RetentionService, RetentionSettings
from splunk_ucm.maintenance.worker import MaintenanceWorker
from splunk_ucm.platform.capabilities import PlatformProbe
from splunk_ucm.readiness.worker import ReadinessWorker
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog

NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=datetime.timezone.utc)
EPOCH = NOW.timestamp()

# POST routes any authenticated app user may call; everything else needs a capability.
CALLER_SCOPED_POSTS = {"selections", "selections/delete", "dashboards/preview"}
RESTRICTED_GETS = {"audit", "provider/manifest"}


def _load_worker_module():
    path = os.path.join(helpers.ROOT, "sunavigator", "bin", "ucm_sync_worker.py")
    spec = importlib.util.spec_from_file_location("ucm_sync_worker", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RbacReviewTest(unittest.TestCase):
    def test_every_post_route_needs_a_capability(self):
        store = loaded_catalog()
        viewer = make_ctx(store, [])
        posts = sorted(p for (m, p) in build_router().routes if m == "POST")
        self.assertGreater(len(posts), 20)
        for path in posts:
            status, body = call(viewer, "POST", path, body={"id": "fenre:UC-9.1.1"})
            if path in CALLER_SCOPED_POSTS:
                self.assertNotEqual(status, 403, path)
            else:
                self.assertEqual(status, 403, (path, body))
        self.assertEqual(store.count(C.DEPLOYMENTS), 0)
        self.assertEqual(store.count(C.DASHBOARDS), 0)

    def test_reads_open_except_restricted(self):
        viewer = make_ctx(loaded_catalog(), [])
        for (method, path) in build_router().routes:
            if method != "GET":
                continue
            status, _ = call(viewer, "GET", path)
            if path in RESTRICTED_GETS:
                self.assertEqual(status, 403, path)
            else:
                self.assertNotEqual(status, 403, path)


class FakeShcTransport:
    def __init__(self, member_status=200, member_label="sh1", captain_label="sh1", fail=False):
        self.member_status = member_status
        self.member_label = member_label
        self.captain_label = captain_label
        self.fail = fail

    def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        from splunk_ucm.errors import StorageError
        if self.fail:
            raise StorageError("splunkd unreachable", 0)
        if path.endswith("member/info"):
            if self.member_status != 200:
                return self.member_status, b"{}"
            return 200, json.dumps({"entry": [{"content": {"label": self.member_label}}]}).encode()
        if path.endswith("captain/info"):
            return 200, json.dumps({"entry": [{"content": {"label": self.captain_label}}]}).encode()
        return 404, b"{}"

    def json(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        status, body = self.request(method, path, query, json_body, form, timeout)
        if status != 200:
            from splunk_ucm.errors import StorageError
            raise StorageError("failed", status)
        return json.loads(body)


class LeaderElectionTest(unittest.TestCase):
    def setUp(self):
        self.leader = _load_worker_module()._leader

    def test_standalone_is_leader(self):
        self.assertTrue(self.leader(PlatformProbe(FakeShcTransport(member_status=503))))
        self.assertTrue(self.leader(PlatformProbe(FakeShcTransport(member_status=404))))

    def test_captain_runs_and_members_do_not(self):
        self.assertTrue(self.leader(PlatformProbe(FakeShcTransport())))
        self.assertFalse(self.leader(PlatformProbe(FakeShcTransport(captain_label="sh2"))))

    def test_unknown_when_splunkd_fails(self):
        self.assertIsNone(self.leader(PlatformProbe(FakeShcTransport(fail=True))))
        self.assertIsNone(self.leader(PlatformProbe(FakeShcTransport(captain_label=""))))

    def test_every_worker_skips_on_non_captain(self):
        store, config = loaded_catalog(), AppConfig({})
        not_leader = lambda: False
        workers = [
            MaintenanceWorker(store, config, not_leader),
            SyncWorker(store, config, lambda *a: None, lambda: "", not_leader),
            DiscoveryWorker(store, config, None, not_leader),
            ReadinessWorker(store, config, not_leader),
            DeploymentWorker(store, config, None, not_leader),
        ]
        for w in workers:
            self.assertEqual(w.run_once(), {"action": "skipped", "reason": "not_shc_captain"}, type(w).__name__)


class MigrationTest(unittest.TestCase):
    def outdate(self, store):
        for key, doc in list(store.collections[C.CATALOG].items()):
            doc = dict(doc)
            doc.pop("summary_version", None)
            doc.pop("framework_controls", None)
            store.collections[C.CATALOG][key] = doc

    def test_reindexes_old_summaries_once(self):
        store = loaded_catalog()
        self.outdate(store)
        runner = MigrationRunner(store, lambda: "2026-11-20T12:00:00Z")
        self.assertEqual(runner.pending(), [m[0] for m in MIGRATIONS])
        results = runner.run()
        self.assertEqual(results[0]["details"]["reindexed"], store.count(C.CATALOG))
        self.assertEqual(results[1]["details"], {"not_needed": True})
        doc = store.get(C.CATALOG, "fenre_UC-9.1.1")
        self.assertEqual(doc["summary_version"], SUMMARY_VERSION)
        self.assertIn("regulation:cjis#5.5.1", doc["framework_controls"])
        state = store.get(C.SYNC_STATE, STATE_KEY)
        self.assertEqual(state["applied"], [m[0] for m in MIGRATIONS])
        self.assertEqual(state["app_version"], __version__)
        self.assertEqual(runner.pending(), [])
        self.assertEqual(runner.run(), [])

    def test_normalizer_upgrade_reindexes_a_071_catalog(self):
        from splunk_ucm.content.fenre.normalizer import NORMALIZER_VERSION
        store = loaded_catalog()
        for key, doc in list(store.collections[C.CATALOG].items()):
            store.collections[C.CATALOG][key] = dict(doc, normalizer_version="fenre-1.1.0")
        store.upsert(C.SYNC_STATE, {"_key": STATE_KEY, "doc_type": "app_state", "app_version": "0.7.1",
                                    "applied": [MIGRATIONS[0][0]]})
        runner = MigrationRunner(store, lambda: "t")
        self.assertEqual(runner.pending(), ["0002_normalizer_" + NORMALIZER_VERSION])
        results = runner.run()
        self.assertEqual(results[0]["details"]["reindexed"], store.count(C.CATALOG))
        self.assertEqual(store.count(C.CATALOG, {"normalizer_version": NORMALIZER_VERSION}), store.count(C.CATALOG))
        self.assertEqual(runner.run(), [])

    def test_fresh_install_marks_not_needed(self):
        store = loaded_catalog()
        results = MigrationRunner(store).run()
        self.assertEqual(results[0]["details"], {"not_needed": True})

    def test_records_version_change(self):
        store = InMemoryStore()
        store.upsert(C.SYNC_STATE, {"_key": STATE_KEY, "doc_type": "app_state", "applied": [m[0] for m in MIGRATIONS],
                                    "app_version": "0.4.0"})
        MigrationRunner(store, lambda: "t").run()
        state = store.get(C.SYNC_STATE, STATE_KEY)
        self.assertEqual((state["previous_app_version"], state["app_version"]), ("0.4.0", __version__))

    def test_worker_records_upgrade_without_pending_migrations(self):
        store = InMemoryStore()
        store.upsert(C.SYNC_STATE, {"_key": STATE_KEY, "doc_type": "app_state", "applied": [m[0] for m in MIGRATIONS],
                                    "app_version": "0.4.0"})
        worker = MaintenanceWorker(store, AppConfig({}), lambda: None, lambda: NOW, lambda: EPOCH)
        self.assertEqual(worker.run_once(), {"action": "ran", "job": "migrations", "applied": []})
        self.assertEqual(store.get(C.SYNC_STATE, STATE_KEY)["app_version"], __version__)
        self.assertFalse(worker.migrations.outdated())


class RetentionTest(unittest.TestCase):
    def seed(self):
        store = InMemoryStore()
        for i, age_days in enumerate((400, 366, 364, 1)):
            store.upsert(C.AUDIT, {"_key": "a%d" % i, "time": EPOCH - age_days * 86400, "action": "x"})
        for i in range(15):
            status = "queued" if i == 14 else "succeeded"
            store.upsert(C.SYNC_STATE, {"_key": "job::%02d" % i, "doc_type": "job", "status": status,
                                        "requested_at": "2026-11-%02dT00:00:00Z" % (i + 1)})
        store.upsert(C.SYNC_STATE, {"_key": "provider::fenre", "doc_type": "provider"})
        return store

    def test_purges_old_audit_and_jobs(self):
        store = self.seed()
        out = RetentionService(store, RetentionSettings(audit_days=365, job_history=10), lambda: EPOCH).purge()
        self.assertEqual(out, {"audit": 2, "jobs": 5})
        self.assertEqual(sorted(store.collections[C.AUDIT]), ["a2", "a3"])
        jobs = sorted(k for k in store.collections[C.SYNC_STATE] if k.startswith("job::"))
        self.assertEqual(jobs, ["job::%02d" % i for i in range(5, 15)])
        self.assertIsNotNone(store.get(C.SYNC_STATE, "provider::fenre"))

    def test_queued_jobs_survive_and_zero_keeps_audit(self):
        store = self.seed()
        for i in range(14):
            store.collections[C.SYNC_STATE]["job::%02d" % i]["status"] = "queued"
        out = RetentionService(store, RetentionSettings(audit_days=0, job_history=10), lambda: EPOCH).purge()
        self.assertEqual(out, {"audit": 0, "jobs": 0})
        self.assertEqual(len(store.collections[C.AUDIT]), 4)

    def test_worker_order_interval_and_audit(self):
        store = self.seed()
        clock = {"now": NOW}
        config = AppConfig({"retention": {"audit_days": "365", "job_history": "10"}})
        worker = MaintenanceWorker(store, config, lambda: None, lambda: clock["now"], lambda: EPOCH)
        first = worker.run_once()
        self.assertEqual(first["job"], "migrations")
        second = worker.run_once()
        self.assertEqual((second["job"], second["totals"]), ("retention", {"audit": 2, "jobs": 5}))
        actions = [d["action"] for d in store.collections[C.AUDIT].values()]
        self.assertIn("retention.purged", actions)
        self.assertIn("app.migration", actions)
        self.assertEqual(worker.run_once(), {"action": "idle"})
        clock["now"] = NOW + datetime.timedelta(hours=25)
        self.assertEqual(worker.run_once(), {"action": "idle"})
        self.assertEqual(store.get(C.SYNC_STATE, "maintenance::retention")["last_run_at"], "2026-11-21T13:00:00Z")


if __name__ == "__main__":
    unittest.main()

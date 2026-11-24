import datetime
import json
import unittest

import helpers
from splunk_ucm.api.app import CAP_MANAGE_CONTENT, Context, Request, build_router
from splunk_ucm.config import AppConfig
from splunk_ucm.content import sync as S
from splunk_ucm.content.worker import SyncWorker
from splunk_ucm.errors import ProviderError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.transport import SplunkdTransport


class NoSplunkd(SplunkdTransport):
    def request(self, *a, **kw):
        raise AssertionError("unexpected splunkd call in unit test")


def make_ctx(store, caps, config=None, user="alice"):
    ctx = Context(NoSplunkd(), None, user, store=store, audit_store=store, config=config or AppConfig({}),
                  provider_factory=lambda *a: helpers.fenre_provider(helpers.FakeGitHub()))
    ctx._caps = list(caps)
    return ctx


def call(ctx, method, path, query=None, body=b""):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode("utf-8")
    resp = build_router().dispatch(ctx, Request(method, path, {k: [v] for k, v in (query or {}).items()},
                                                body, ctx.user))
    return resp.status, resp.body


class RouterTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.bundle = json.dumps(helpers.fixture_bundle()).encode("utf-8")

    def test_unknown_and_wrong_method(self):
        ctx = make_ctx(self.store, [])
        self.assertEqual(call(ctx, "GET", "nope")[0], 404)
        self.assertEqual(call(ctx, "DELETE", "catalog")[0], 405)

    def test_viewer_can_read_but_not_change(self):
        ctx = make_ctx(self.store, [])
        self.assertEqual(call(ctx, "GET", "catalog")[0], 200)
        for method, path, body in (("POST", "sync", {"categories": ["9"]}), ("POST", "import", self.bundle),
                                   ("POST", "catalog/reindex", b"{}"), ("GET", "provider/manifest", b""),
                                   ("GET", "audit", b""), ("POST", "discovery", {"include_internal": True}),
                                   ("POST", "mappings", {"kind": "index", "value": "main"})):
            status, payload = call(ctx, method, path, body=body)
            self.assertEqual(status, 403, path)
            self.assertEqual(payload["error"]["code"], "permission_denied")
        self.assertEqual(self.store.count(C.CATALOG), 0)
        self.assertIsNone(self.store.collections.get(C.SYNC_STATE, {}).get("provider::fenre"))

    def test_content_manager_flow(self):
        ctx = make_ctx(self.store, [CAP_MANAGE_CONTENT])
        status, body = call(ctx, "POST", "import", body=self.bundle)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["job"]["totals"]["added"], 10)
        status, body = call(ctx, "GET", "catalog", {"mitre": "t1110"})
        self.assertEqual([i["record_id"] for i in body["items"]], ["9.1.1", "9.1.2"])
        status, body = call(ctx, "GET", "usecase", {"id": "fenre:UC-9.1.1"})
        self.assertEqual(body["content_id"], "fenre:UC-9.1.1")
        status, body = call(ctx, "GET", "categories")
        self.assertEqual(len(body["categories"]), 9)
        status, body = call(ctx, "GET", "audit")
        actions = [e["action"] for e in body["events"]]
        self.assertIn("content.sync.completed", actions)
        self.assertTrue(all(e["actor"] == "alice" for e in body["events"]))

    def test_post_sync_queues_job_and_validates_input(self):
        ctx = make_ctx(self.store, [CAP_MANAGE_CONTENT])
        status, body = call(ctx, "POST", "sync", body={"categories": ["9", 10], "ref": "v8.25.0"})
        self.assertEqual((status, body["error"]["message"]), (400, "ref is not in allowed_refs"))
        cfg = AppConfig({"provider:fenre": {"allowed_refs": "main, v*"}})
        ctx = make_ctx(self.store, [CAP_MANAGE_CONTENT], config=cfg)
        self.assertEqual(call(ctx, "GET", "sync")[1]["allowed_refs"], ["main", "v*"])
        status, body = call(ctx, "POST", "sync", body={"categories": ["9", 10], "ref": "v8.25.0"})
        self.assertEqual(status, 202)
        self.assertEqual(body["job"]["status"], "queued")
        self.assertEqual(body["job"]["categories"], ["9", "10"])
        self.assertEqual(call(ctx, "POST", "sync", body={"categories": ["9"]})[0], 400)
        for bad in ({"categories": "9"}, {"categories": [{"x": 1}]}, {"ref": "main; rm -rf"},
                    {"provider": "other"}, b"not json", b"[1]"):
            self.assertEqual(call(make_ctx(InMemoryStore(), [CAP_MANAGE_CONTENT]), "POST", "sync",
                                  body=bad)[0], 400, bad)

    def test_remote_sync_disabled(self):
        cfg = AppConfig({"provider:fenre": {"remote_sync_enabled": "false"}})
        ctx = make_ctx(self.store, [CAP_MANAGE_CONTENT], config=cfg)
        status, body = call(ctx, "POST", "sync", body={"categories": ["9"]})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "unsupported")
        self.assertEqual(call(ctx, "POST", "import", body=self.bundle)[0], 200)

    def test_bad_parameters_return_400_not_500(self):
        ctx = make_ctx(self.store, [])
        for q in ({"count": "x"}, {"sort": "bogus"}, {"domain": "nope"}, {"offset": "-5"}):
            self.assertEqual(call(ctx, "GET", "catalog", q)[0], 400, q)
        self.assertEqual(call(ctx, "GET", "usecase", {"id": "fenre:UC-1.2.3"})[0], 404)

    def test_unexpected_exception_is_masked(self):
        ctx = make_ctx(self.store, [])
        router = build_router()
        router.add("GET", "boom", lambda c, r: 1 / 0)
        resp = router.dispatch(ctx, Request("GET", "boom", {}, b"", "alice"))
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.body["error"]["message"], "internal error")


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.gh = helpers.FakeGitHub()
        self.now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        self.factory_calls = []

    def worker(self, config=None, leader=True, factory=None):
        def default_factory(pid, settings, token, ref):
            self.factory_calls.append((pid, token, ref))
            return helpers.fenre_provider(self.gh, ref=ref or "main")
        return SyncWorker(self.store, config or AppConfig({}), factory or default_factory,
                          lambda: "tok", lambda: leader, now=lambda: self.now)

    def service(self):
        from splunk_ucm.audit import AuditService
        return S.SyncService(self.store, AuditService(self.store))

    def test_idle_without_jobs(self):
        self.assertEqual(self.worker().run_once()["action"], "idle")

    def test_runs_queued_job(self):
        self.service().enqueue(S.new_job("alice", "fenre", ["9"], ref="main"))
        result = self.worker().run_once()
        self.assertEqual((result["action"], result["status"]), ("ran", "succeeded"))
        self.assertEqual(self.factory_calls, [("fenre", "tok", "main")])
        self.assertEqual(self.store.count(C.CATALOG), 2)

    def test_non_captain_skips(self):
        self.service().enqueue(S.new_job("alice", "fenre", ["9"]))
        self.assertEqual(self.worker(leader=False).run_once()["action"], "skipped")
        self.assertIsNotNone(self.service().state.next_queued())

    def test_provider_construction_failure_fails_job(self):
        def broken(*a):
            raise ProviderError("invalid ref")
        self.service().enqueue(S.new_job("alice", "fenre", ["9"]))
        self.worker(factory=broken).run_once()
        job = self.service().state.jobs(limit=1)[0]
        self.assertEqual(job["status"], "failed")

    def test_stale_running_job_expires(self):
        job = S.new_job("alice", "fenre", ["9"])
        job.update(status="running", started_at="2025-12-31T00:00:00Z")
        self.service().state.save_job(job)
        self.assertEqual(self.worker().expire_stale(), 1)
        self.assertEqual(self.service().state.get_job(job["job_id"])["status"], "failed")

    def test_schedule(self):
        cfg = AppConfig({"sync": {"schedule_interval_hours": "24"}})
        self.assertIsNone(self.worker(cfg).maybe_schedule())
        self.service().state.store.batch_save(C.SYNC_STATE, [{
            "_key": "provider::fenre", "doc_type": "provider_state", "provider": "fenre",
            "selected_categories": ["9"], "last_attempt_at": "2025-12-31T12:00:00Z"}])
        self.assertIsNone(self.worker(cfg).maybe_schedule())
        self.now += datetime.timedelta(days=1)
        job = self.worker(cfg).maybe_schedule()
        self.assertEqual(job["source"], "schedule")
        self.assertIsNone(self.worker(cfg).maybe_schedule())


class WebExposureTest(unittest.TestCase):
    """Splunk Web proxies only paths and methods listed in default/web.conf."""

    def exposures(self):
        import configparser
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "default", "web.conf")
        parser = configparser.ConfigParser()
        parser.read(path)
        return [(parser[s]["pattern"].split("/"), {m.strip() for m in parser[s]["methods"].split(",")})
                for s in parser.sections() if s.startswith("expose:")]

    def test_every_route_is_reachable_through_splunk_web(self):
        exposures = self.exposures()

        def exposed(method, path):
            parts = ("ucm/" + path).split("/")
            return any(method in methods and len(pattern) == len(parts)
                       and all(p == "*" or p == q for p, q in zip(pattern, parts))
                       for pattern, methods in exposures)
        missing = [(m, p) for (m, p) in build_router().routes if not exposed(m, p)]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()

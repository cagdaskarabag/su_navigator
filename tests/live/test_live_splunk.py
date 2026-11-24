"""Integration tests against a REAL Splunk instance with the app installed.

Skipped unless UCM_LIVE_SPLUNK=1. Configure with:
  UCM_SPLUNK_URL       (default https://localhost:8089)
  UCM_SPLUNK_USER / UCM_SPLUNK_PASSWORD   (an admin account)
  UCM_SPLUNK_VERIFY_TLS=0                 (self-signed development instances)
  UCM_LIVE_REMOTE=1                       (also exercise GitHub through splunkd)

Tests write only test-prefixed documents, a partial fixture bundle (records
from tests/fixtures) and a temporary viewer user; they clean up after themselves.
"""

import json
import os
import time
import unittest
import uuid

import helpers
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import KVStore
from splunkd_http import HttpTransport

LIVE = os.environ.get("UCM_LIVE_SPLUNK") == "1"
URL = os.environ.get("UCM_SPLUNK_URL", "https://localhost:8089")
VERIFY = os.environ.get("UCM_SPLUNK_VERIFY_TLS", "1") != "0"


def transport(user=None, password=None):
    return HttpTransport(URL, username=user or os.environ.get("UCM_SPLUNK_USER", "admin"),
                         password=password if password is not None else os.environ.get("UCM_SPLUNK_PASSWORD", ""),
                         verify_tls=VERIFY)


def api(t, method, path, query=None, body=None, raw=None):
    if raw is not None:
        import urllib.request
        req = urllib.request.Request(URL + "/services/ucm/" + path, data=raw, method=method,
                                     headers={"Authorization": t._auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, context=t._ctx, timeout=300) as resp:  # nosec - test target
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")
    status, content = t.request(method, "/services/ucm/" + path, query, body, timeout=300)
    return status, json.loads(content or b"{}")


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveKVStoreParityTest(unittest.TestCase):
    """The InMemoryStore used by unit tests must agree with the real KV Store."""

    @classmethod
    def setUpClass(cls):
        cls.kv = KVStore(transport())
        cls.prefix = "test::" + uuid.uuid4().hex[:8] + "::"
        cls.kv.batch_save(C.SYNC_STATE, [
            {"_key": cls.prefix + "a", "doc_type": "test", "tags": ["x", "y"], "n": 1, "s": "Alpha Beta"},
            {"_key": cls.prefix + "b", "doc_type": "test", "tags": ["z"], "n": 2, "s": "gamma"},
            {"_key": cls.prefix + "c", "doc_type": "test", "tags": [], "n": 3, "s": "beta.gamma"},
        ])

    @classmethod
    def tearDownClass(cls):
        cls.kv.delete_query(C.SYNC_STATE, {"doc_type": "test"})

    def keys(self, query, **kw):
        q = {"$and": [{"doc_type": "test"}, query]}
        return [d["_key"][len(self.prefix):] for d in self.kv.query(C.SYNC_STATE, q, **kw)
                if d["_key"].startswith(self.prefix)]

    def test_operators_match_in_memory_semantics(self):
        self.assertEqual(self.keys({"tags": "x"}), ["a"])
        self.assertEqual(sorted(self.keys({"tags": {"$in": ["y", "z"]}})), ["a", "b"])
        self.assertEqual(self.keys({"s": {"$regex": "beta", "$options": "i"}}, sort=[("n", 1)]), ["a", "c"])
        self.assertEqual(self.keys({"s": {"$regex": "beta\\.gamma"}}), ["c"])
        self.assertEqual(self.keys({"n": {"$gte": 2}}, sort=[("n", -1)]), ["c", "b"])
        self.assertEqual(self.keys({"$or": [{"n": 1}, {"n": 3}]}, sort=[("n", 1)]), ["a", "c"])
        self.assertEqual(self.keys({}, sort=[("n", 1)], skip=1, limit=1), ["b"])

    def test_kvstore_rejects_dollar_and_dot_keys(self):
        from splunk_ucm.errors import StorageError
        with self.assertRaises(StorageError) as ctx:
            self.kv.batch_save(C.SYNC_STATE, [{"_key": self.prefix + "bad", "doc_type": "test",
                                               "raw": {"$schema": "x"}}])
        self.assertEqual(ctx.exception.status, 400)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveOneshotContractTest(unittest.TestCase):
    """splunkd returns 100 oneshot rows unless ``count`` is sent; the client must not lose rows."""

    def test_rows_beyond_100_and_exact_truncation(self):
        from splunk_ucm.platform.search import SearchClient
        client = SearchClient(transport())
        full = client.oneshot("| makeresults count=250", max_count=5000)
        self.assertEqual((len(full.rows), full.truncated), (250, False))
        exact = client.oneshot("| makeresults count=250", max_count=250)
        self.assertEqual((len(exact.rows), exact.truncated), (250, False))
        cut = client.oneshot("| makeresults count=250", max_count=100)
        self.assertEqual((len(cut.rows), cut.truncated), (100, True))

    def test_app_scoped_macro_resolves_in_parse_and_preview(self):
        from splunk_ucm.platform.search import SearchClient
        t = transport()
        name = "sun_live_macro_" + uuid.uuid4().hex[:6]
        base = "/servicesNS/nobody/sunavigator/admin/macros"
        status, _ = t.request("POST", base, None, None, form={"name": name, "definition": "makeresults count=3"})
        self.assertIn(status, (200, 201))
        try:
            t.request("POST", base + "/" + name + "/acl", None, None, form={"sharing": "app", "owner": "nobody"})
            client = SearchClient(t)
            q = "| `%s` | stats count" % name
            self.assertFalse(client.parse(q).ok)
            self.assertTrue(client.parse(q, app="sunavigator").ok)
            rows = client.preview(q, app="sunavigator").rows
            self.assertEqual(rows[0]["count"], "3")
        finally:
            t.request("DELETE", base + "/" + name)

    def test_policy_sees_commands_in_macros_inside_subsearches(self):
        from splunk_ucm.platform.search import SearchClient
        from splunk_ucm.spl.parser import parse
        from splunk_ucm.spl.policy import classify, command_exists
        t = transport()
        name = "sun_live_se_" + uuid.uuid4().hex[:6]
        base = "/servicesNS/nobody/sunavigator/admin/macros"
        status, _ = t.request("POST", base, None, None,
                              form={"name": name, "definition": "| makeresults | outputlookup sun_live_probe.csv"})
        self.assertIn(status, (200, 201))
        try:
            t.request("POST", base + "/" + name + "/acl", None, None, form={"sharing": "app", "owner": "nobody"})
            client = SearchClient(t)
            spl = '| makeresults | append [ `%s` ] | append [| makeresults | map search="| makeresults"]' % name
            parsed = parse(client, spl, app="sunavigator")
            self.assertTrue(parsed.ok, parsed.messages)
            self.assertEqual(classify(spl).side_effects, [])
            policy = classify(spl, parsed, exists=lambda n: command_exists(client, n, "sunavigator"))
            self.assertEqual(policy.side_effects, ["outputlookup"])
            self.assertEqual(policy.indirect, ["map"])
            self.assertFalse(command_exists(client, "sun_no_such_command", "sunavigator"))
            self.assertTrue(command_exists(client, "stats", "sunavigator"))
        finally:
            t.request("DELETE", base + "/" + name)

    def test_map_probe_is_refused_and_writes_nothing(self):
        import json as _json
        from splunk_ucm.audit import AuditService
        from splunk_ucm.errors import ValidationError
        from splunk_ucm.platform.search import SearchClient
        from splunk_ucm.storage.repositories import encode_raw
        from splunk_ucm.validation.service import ValidationService
        from unit.test_discovery import loaded_catalog
        t = transport()
        lookup = "sun_t02_probe_%s.csv" % uuid.uuid4().hex[:6]
        store = loaded_catalog()
        doc = store.get(C.CONTENT, "fenre_UC-9.1.1")
        raw = _json.loads(doc["raw_json"])
        raw["spl"] = '| makeresults | map search="| makeresults | outputlookup %s"' % lookup
        doc["raw_json"] = encode_raw(raw)
        store.upsert(C.CONTENT, doc)
        svc = ValidationService(store, AuditService(store), SearchClient(t))
        with self.assertRaises(ValidationError) as cm:
            svc.preview("fenre:UC-9.1.1", "live")
        self.assertEqual(cm.exception.details["indirect"], ["map"])
        status, _ = t.request("GET", "/servicesNS/nobody/sunavigator/data/lookup-table-files/" + lookup, None, None)
        self.assertEqual(status, 404)

    def test_idle_sourcetype_sampled_at_its_newest_event(self):
        """Indexes three events three hours old into main under a unique test sourcetype."""
        from datetime import datetime, timezone
        from splunk_ucm.audit import AuditService
        from splunk_ucm.discovery.keys import source_key
        from splunk_ucm.platform.search import SearchClient
        from splunk_ucm.storage.kvstore import InMemoryStore
        from splunk_ucm.validation.service import ValidationService
        t = transport()
        st = "sun:idle:" + uuid.uuid4().hex[:8]
        stamp = datetime.fromtimestamp(time.time() - 3 * 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        for i in range(3):
            import urllib.parse
            import urllib.request
            query = urllib.parse.urlencode({"index": "main", "sourcetype": st, "host": "sun-live"})
            req = urllib.request.Request(URL + "/services/receivers/simple?" + query, method="POST",
                                         data=("%s user=u%d action=login" % (stamp, i)).encode(),
                                         headers={"Authorization": t._auth})
            with urllib.request.urlopen(req, context=t._ctx, timeout=60) as resp:  # nosec - test target
                self.assertEqual(resp.status, 200)
        client = SearchClient(t)
        last = None
        for _ in range(30):
            rows = client.oneshot('| tstats max(_time) as last where index=main sourcetype="%s"' % st,
                                  earliest="-1d").rows
            if rows and rows[0].get("last"):
                last = int(float(rows[0]["last"]))
                break
            time.sleep(2)
        self.assertIsNotNone(last, "test events were not indexed")
        self.assertLess(last, time.time() - 2 * 3600)
        store = InMemoryStore()
        pair = {"_key": source_key("pair", "main", st), "kind": "pair", "status": "active",
                "index": "main", "sourcetype": st, "window_count": 3}
        svc = ValidationService(store, AuditService(store), client)
        store.upsert(C.ENVIRONMENT_SOURCES, pair)
        out = {r["field"]: r for r in svc._sample(["user", "action", "sun_no_such_field"], [st])}
        self.assertEqual(out["user"]["reason"], "sample_empty")
        store.upsert(C.ENVIRONMENT_SOURCES, dict(pair, last_time=last))
        out = {r["field"]: r for r in svc._sample(["user", "action", "sun_no_such_field"], [st])}
        self.assertEqual((out["user"]["present"], out["user"]["count"]), (True, 3))
        self.assertTrue(out["action"]["present"])
        self.assertEqual((out["sun_no_such_field"]["sampled"], out["sun_no_such_field"]["present"]), (True, False))

    def test_event_search_truncation(self):
        from splunk_ucm.platform.search import SearchClient
        cut = SearchClient(transport()).preview("search index=_internal", max_count=5, earliest="-24h")
        self.assertEqual((len(cut.rows), cut.truncated), (5, True))


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveWritePathTest(unittest.TestCase):
    """D-039: analysts cannot write evidence or jobs directly; REST flows still work."""
    ANALYST = "ucm_test_analyst_" + uuid.uuid4().hex[:6]
    ANALYST_PW = "T3st!" + uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.ANALYST, "password": cls.ANALYST_PW, "roles": "ucm_analyst"})
        assert status in (200, 201), status
        cls.analyst = transport(cls.ANALYST, cls.ANALYST_PW)
        bundle = helpers.fixture_bundle(record_ids=["9.1.1"])
        status, body = api(cls.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        assert status == 200, body

    @classmethod
    def tearDownClass(cls):
        api(cls.admin, "POST", "mappings/delete", body={"kind": "sourcetype", "value": "sun_live_st"})
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.ANALYST)

    def test_direct_kv_writes_are_refused(self):
        for coll in (C.SYNC_STATE, C.READINESS, C.VALIDATION, C.ENVIRONMENT_SOURCES, C.SOURCE_MAPPINGS):
            path = "/servicesNS/nobody/sunavigator/storage/collections/data/" + coll
            status, _ = self.analyst.request("POST", path, None, {"_key": "forged", "state": "ready"})
            self.assertEqual(status, 403, coll)
        status, _ = self.analyst.request("POST", "/servicesNS/nobody/sunavigator/storage/collections/data/"
                                         + C.SELECTIONS, None, {"_key": "sel_live_probe", "user": self.ANALYST})
        self.assertIn(status, (200, 201))
        self.admin.request("DELETE", "/servicesNS/nobody/sunavigator/storage/collections/data/"
                           + C.SELECTIONS + "/sel_live_probe")

    def test_analyst_rest_flows_still_work(self):
        uc = "fenre:UC-9.1.1"
        status, body = api(self.analyst, "POST", "validate", body={"id": uc, "sample": False})
        self.assertEqual(status, 200, body)
        self.assertEqual(KVStore(self.admin).get(C.VALIDATION, "fenre_UC-9.1.1")["parsed_at"], body["parsed_at"])
        status, body = api(self.analyst, "POST", "mappings",
                           body={"kind": "sourcetype", "value": "sun_live_st", "canonical_value": "WinEventLog"})
        self.assertEqual(status, 200, body)
        status, body = api(self.analyst, "POST", "readiness", body={})
        if status == 400:
            # The worker may have queued a readiness job after an earlier sync; the write itself was allowed.
            self.assertIn("already queued or running", body["error"]["message"])
        else:
            self.assertEqual(status, 202, body)
        status, body = api(self.analyst, "POST", "readiness/assess", body={"id": uc})
        self.assertIn(status, (200, 400), body)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveApiTest(unittest.TestCase):
    VIEWER = "ucm_test_viewer_" + uuid.uuid4().hex[:6]
    VIEWER_PW = "T3st!" + uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.VIEWER, "password": cls.VIEWER_PW, "roles": "ucm_viewer"})
        assert status in (200, 201), status
        cls.viewer = transport(cls.VIEWER, cls.VIEWER_PW)

    @classmethod
    def tearDownClass(cls):
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.VIEWER)

    def wait_idle(self):
        for _ in range(60):
            _, body = api(self.admin, "GET", "sync")
            if not any(j["status"] in ("queued", "running") for j in body["jobs"]):
                return
            time.sleep(5)
        self.fail("sync jobs did not finish")

    def test_offline_import_and_read_paths(self):
        self.wait_idle()
        bundle = helpers.fixture_bundle(record_ids=["9.1.1", "9.1.2", "14.1.1"])
        status, body = api(self.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["job"]["status"], "succeeded", body)
        self.assertEqual(body["job"]["totals"]["invalid"], 0)
        status, body = api(self.viewer, "GET", "catalog", {"mitre": "T1110", "count": "50"})
        self.assertEqual(status, 200)
        self.assertTrue({"9.1.1", "9.1.2"} <= {i["record_id"] for i in body["items"]})
        status, body = api(self.viewer, "GET", "usecase", {"id": "fenre:UC-9.1.1"})
        self.assertEqual(status, 200)
        self.assertIn(body["requirement_summary"]["assessment"],
                      ("not_assessed", "not_ready", "partially_ready", "ready",
                       "blocked", "insufficient_evidence"))
        self.assertEqual(body["provenance"]["source_blob_sha"], bundle["records"][0]["blob_sha"])

    def test_viewer_denied_changes(self):
        for method, path, body in (("POST", "sync", {"categories": ["9"]}), ("POST", "catalog/reindex", {}),
                                   ("GET", "audit", None), ("GET", "provider/manifest", None),
                                   ("POST", "discovery", {"include_internal": True}),
                                   ("POST", "mappings", {"kind": "index", "value": "main"})):
            status, payload = api(self.viewer, method, path, body=body)
            self.assertEqual(status, 403, (path, payload))
        status, _ = self.viewer.request(
            "POST", "/servicesNS/nobody/sunavigator/storage/collections/data/uc_catalog",
            json_body={"_key": "x", "title": "tamper"})
        self.assertEqual(status, 403)

    def test_errors_are_json(self):
        status, body = api(self.admin, "GET", "catalog", {"sort": "bogus"})
        self.assertEqual((status, body["error"]["code"]), (400, "validation_error"))
        status, body = api(self.admin, "GET", "usecase", {"id": "fenre:UC-99.99.99"})
        self.assertEqual(status, 404)

    def test_platform_report(self):
        status, body = api(self.admin, "GET", "platform")
        self.assertEqual(status, 200)
        caps = {c["name"]: c["status"] for c in body["capabilities"]}
        self.assertEqual(caps.get("kvstore"), "available")
        self.assertIn("offline_import", caps)
        self.assertEqual(caps.get("index_listing"), "available")
        self.assertEqual(caps.get("adhoc_search"), "available")
        self.assertEqual(caps.get("run_discovery"), "available")

    def test_discovery_inventory_and_local_mapping(self):
        self.wait_idle()
        for _ in range(60):
            _, body = api(self.admin, "GET", "discovery")
            if not any(j["status"] in ("queued", "running") for j in body["jobs"]):
                break
            time.sleep(5)
        else:
            self.fail("existing discovery job did not finish")
        status, body = api(self.admin, "POST", "discovery", body={"include_internal": True, "earliest": "-15m"})
        self.assertEqual(status, 202, body)
        job_id = body["job"]["job_id"]
        for _ in range(60):
            _, state = api(self.admin, "GET", "discovery")
            job = next((j for j in state["jobs"] if j["job_id"] == job_id), None)
            if job and job["status"] not in ("queued", "running"):
                break
            time.sleep(5)
        else:
            self.fail("discovery job did not finish")
        self.assertEqual(job["status"], "succeeded", job)
        self.assertGreater(job["totals"]["pairs"], 0)
        status, inv = api(self.admin, "GET", "inventory", {"kind": "pair", "count": "50"})
        self.assertEqual(status, 200)
        self.assertGreater(inv["total"], 0)
        self.assertTrue(any(i.get("index", "").startswith("_") for i in inv["items"]))
        marker = "ucm_test_st_" + uuid.uuid4().hex[:8]
        status, mapped = api(self.admin, "POST", "mappings",
                             body={"kind": "sourcetype", "value": marker, "canonical_value": marker,
                                   "notes": "live test"})
        self.assertEqual(status, 200, mapped)
        self.assertEqual(mapped["mapping"]["origin"], "local")
        status, body = api(self.admin, "POST", "mappings/delete", body={"kind": "sourcetype", "value": marker})
        self.assertEqual(status, 200, body)
        status, usecase = api(self.admin, "GET", "usecase", {"id": "fenre:UC-9.1.1"})
        if status == 200:
            self.assertIn("environment_summary", usecase)
        status, macros = api(self.admin, "GET", "inventory", {"kind": "macro", "count": "5"})
        self.assertEqual(status, 200)
        self.assertGreater(macros["total"], 0)

    def test_readiness_assess_and_rbac(self):
        self.wait_idle()
        bundle = helpers.fixture_bundle(record_ids=["9.1.1", "13.1.1"])
        status, body = api(self.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        self.assertEqual(status, 200, body)
        _, disc = api(self.admin, "GET", "discovery")
        if not disc["state"].get("last_completed_at"):
            self.skipTest("no completed discovery on this instance")
        status, body = api(self.viewer, "POST", "readiness/assess", body={"id": "fenre:UC-9.1.1"})
        self.assertEqual(status, 403)
        status, doc = api(self.admin, "POST", "readiness/assess", body={"id": "fenre:UC-13.1.1"})
        self.assertEqual(status, 200, doc)
        self.assertIn(doc["state"], ("ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"))
        self.assertEqual(len(doc["results"]), doc["requirement_count"])
        self.assertTrue(all(r["status"] for r in doc["results"]))
        status, detail = api(self.viewer, "GET", "usecase", {"id": "fenre:UC-13.1.1"})
        self.assertEqual(detail["readiness"]["state"], doc["state"])
        self.assertEqual(detail["requirement_summary"]["assessment"], doc["state"])
        status, summary = api(self.viewer, "GET", "readiness/summary")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(summary["total"], 1)
        status, page = api(self.viewer, "GET", "readiness", {"sort": "score", "count": "10"})
        self.assertEqual(status, 200)
        self.assertTrue(page["items"])

    def test_selection_and_spl_validation(self):
        status, body = api(self.viewer, "POST", "selections",
                           body={"id": "fenre:UC-13.1.1", "intent": "select", "priority": 70})
        self.assertEqual(status, 200, body)
        status, listed = api(self.viewer, "GET", "selections", {"intent": "backlog"})
        self.assertTrue(any(i["content_id"] == "fenre:UC-13.1.1" for i in listed["items"]))
        status, _ = api(self.viewer, "POST", "preview", body={"id": "fenre:UC-13.1.1"})
        self.assertEqual(status, 403)
        status, parsed = api(self.admin, "POST", "validate", body={"id": "fenre:UC-13.1.1", "sample": True})
        self.assertEqual(status, 200, parsed)
        self.assertTrue(parsed.get("parse_ok"), parsed)
        self.assertFalse(parsed.get("side_effects"))
        fields = {r["field"]: r for r in parsed.get("field_samples") or []}
        self.assertIn("_time", fields)
        status, preview = api(self.admin, "POST", "preview", body={"id": "fenre:UC-13.1.1"})
        self.assertEqual(status, 200, preview)
        self.assertIn("preview", preview)
        self.assertNotIn("rows", preview.get("preview") or {})
        # 13.1.1 needs a lookup this instance does not have; that is recorded, not a 5xx.
        self.assertIn(preview["preview"].get("ok"), (True, False))
        api(self.viewer, "POST", "selections/delete", body={"id": "fenre:UC-13.1.1"})

    @unittest.skipUnless(os.environ.get("UCM_LIVE_REMOTE") == "1", "set UCM_LIVE_REMOTE=1 for GitHub access")
    def test_remote_manifest_through_splunkd(self):
        status, body = api(self.admin, "GET", "provider/manifest")
        self.assertEqual(status, 200, body)
        self.assertRegex(body["source_ref"], "^[0-9a-f]{40}$")
        self.assertGreaterEqual(len(body["categories"]), 20)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveDeploymentTest(unittest.TestCase):
    """WP5: four-eyes approval, disabled-first saved search, enable gate, drift, rollback, retire."""

    OPERATOR = "ucm_test_operator_" + uuid.uuid4().hex[:6]
    OPERATOR_PW = "T3st!" + uuid.uuid4().hex
    UC = "fenre:UC-9.1.2"
    SAVED = "/servicesNS/nobody/sunavigator/saved/searches/"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.OPERATOR, "password": cls.OPERATOR_PW,
                                            "roles": "ucm_deployment_operator"})
        assert status in (200, 201), status
        cls.operator = transport(cls.OPERATOR, cls.OPERATOR_PW)
        bundle = helpers.fixture_bundle(record_ids=["9.1.2"])
        status, body = api(cls.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        assert status == 200, body
        cls.kv = KVStore(cls.admin)
        cls.kv.delete(C.DEPLOYMENTS, "dep_fenre_UC-9.1.2")

    @classmethod
    def tearDownClass(cls):
        doc = cls.kv.get(C.DEPLOYMENTS, "dep_fenre_UC-9.1.2")
        if doc:
            from urllib.parse import quote
            cls.admin.request("DELETE", cls.SAVED + quote(doc["saved_search"]["name"], safe=""))
            cls.kv.delete(C.DEPLOYMENTS, "dep_fenre_UC-9.1.2")
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.OPERATOR)

    def act(self, who, action, **body):
        body["id"] = self.UC
        return api(who, "POST", "deployment/" + action, body=body)

    def saved(self, name):
        from urllib.parse import quote
        status, content = self.admin.request("GET", self.SAVED + quote(name, safe=""), {"output_mode": "json"})
        if status == 404:
            return None
        entry = json.loads(content)["entry"][0]
        return dict(entry["content"], owner=entry["acl"]["owner"])

    def test_lifecycle(self):
        status, body = self.act(self.operator, "draft", cron="*/30 * * * *", earliest="-30m@m", latest="@m",
                                schedule_window="7", suppress_period="1h", suppress_fields="user, src")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["deployment"]["revisions"][0]["parse_ok"], body)
        name = body["deployment"]["saved_search"]["name"]
        self.assertEqual(self.act(self.operator, "submit")[0], 200)
        status, body = self.act(self.operator, "approve")
        self.assertEqual(status, 403, body)
        status, _ = self.operator.request(
            "POST", "/servicesNS/nobody/sunavigator/storage/collections/data/uc_deployments",
            json_body={"_key": "dep_fenre_UC-9.1.2", "state": "approved"})
        self.assertEqual(status, 403)
        self.assertEqual(self.act(self.admin, "approve", note="live test")[0], 200)
        status, body = self.act(self.operator, "deploy")
        self.assertEqual(status, 200, body)
        dep = body["deployment"]
        self.assertEqual((dep["state"], dep["live"]["status"], dep["live"]["drift"]), ("deployed", "disabled", []))
        live = self.saved(name)
        self.assertTrue(live["disabled"])
        self.assertEqual(live["owner"], self.OPERATOR)
        self.assertEqual(live["cron_schedule"], "*/30 * * * *")
        self.assertEqual((live["schedule_window"], live["alert.suppress"], live["alert.suppress.period"],
                          live["alert.suppress.fields"]), ("7", True, "1h", "user,src"))
        status, body = self.act(self.operator, "enable", override_reason="live test override reason")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["status"], "enabled")
        self.assertFalse(self.saved(name)["disabled"])
        from urllib.parse import quote
        self.admin.request("POST", self.SAVED + quote(name, safe=""), form={"cron_schedule": "*/5 * * * *"})
        status, body = self.act(self.operator, "verify")
        self.assertEqual([d["field"] for d in body["deployment"]["live"]["drift"]], ["cron_schedule"])
        self.act(self.operator, "draft", cron="0 * * * *")
        self.act(self.operator, "submit")
        self.act(self.admin, "approve")
        status, body = self.act(self.operator, "deploy")
        self.assertEqual(body["deployment"]["deployed_revision"], 2)
        self.assertEqual(body["deployment"]["live"]["drift"], [])
        live = self.saved(name)
        self.assertTrue(live["disabled"])
        self.assertEqual((live["schedule_window"], live["alert.suppress"], live["dispatch.latest_time"]),
                         ("auto", False, "-5m@m"))
        status, body = self.act(self.operator, "rollback", note="live test")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["deployed_revision"], 1)
        self.assertEqual(self.saved(name)["cron_schedule"], "*/30 * * * *")
        status, body = self.act(self.operator, "retire")
        self.assertEqual((status, body["deployment"]["state"]), (200, "retired"))
        self.assertIsNone(self.saved(name))
        _, audit = api(self.admin, "GET", "audit", {"prefix": "deployment.", "limit": "50"})
        mine = [e["action"] for e in audit["events"] if e["object_id"] == self.UC]
        for action in ("deployment.approve", "deployment.deploy", "deployment.enable", "deployment.rollback",
                       "deployment.retire"):
            self.assertIn(action, mine)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveFrameworksDashboardsTest(unittest.TestCase):
    """WP6: bundled ATT&CK coverage, scheduler run status, generated dashboards and their RBAC."""

    VIEWER = "ucm_test_fwviewer_" + uuid.uuid4().hex[:6]
    VIEWER_PW = "T3st!" + uuid.uuid4().hex
    VIEW = "/servicesNS/nobody/sunavigator/data/ui/views/"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.VIEWER, "password": cls.VIEWER_PW, "roles": "ucm_viewer"})
        assert status in (200, 201), status
        cls.viewer = transport(cls.VIEWER, cls.VIEWER_PW)

    @classmethod
    def tearDownClass(cls):
        api(cls.admin, "POST", "dashboards/delete", body={"name": "ucm_gen_domain_overview_ot_ics"})
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.VIEWER)

    def test_bundled_attack_matrix(self):
        status, body = api(self.viewer, "GET", "frameworks")
        self.assertEqual(status, 200, body)
        ids = {(d["framework_id"], d["version"]) for d in body["definitions"]}
        self.assertIn(("mitre_attack_enterprise", "20.1"), ids)
        self.assertIn(("mitre_attack_ics", "20.1"), ids)
        status, body = api(self.viewer, "GET", "frameworks/matrix", {"framework_id": "mitre_attack_enterprise"})
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body["tactics"]), 15)
        self.assertGreater(body["totals"]["techniques"], 150)
        self.assertEqual(api(self.viewer, "POST", "frameworks/import", raw=b"{}")[0], 403)

    def test_run_status_degrades_without_internal_access(self):
        status, body = api(self.admin, "GET", "operations", {"hours": "24"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["available"])
        status, body = api(self.viewer, "GET", "operations", {"hours": "24"})
        self.assertEqual(status, 200, body)
        if body["items"]:
            self.assertFalse(body["available"])
            self.assertIn("_internal", body["reason"])

    def test_generated_dashboard_lifecycle(self):
        params = {"template": "domain_overview", "params": {"domain": "ot_ics"}}
        self.assertEqual(api(self.viewer, "POST", "dashboards/create", body=params)[0], 403)
        status, body = api(self.admin, "POST", "dashboards/create", body=params)
        self.assertEqual(status, 200, body)
        name = body["dashboard"]["name"]
        status, content = self.admin.request("GET", self.VIEW + name, {"output_mode": "json"})
        self.assertEqual(status, 200)
        self.assertIn("Generated by SUNavigator", json.loads(content)["entry"][0]["content"]["eai:data"])
        status, _ = self.viewer.request("POST", "/servicesNS/nobody/sunavigator/storage/collections/data/"
                                        + C.DASHBOARDS, json_body={"name": "x"})
        self.assertEqual(status, 403)
        self.assertEqual(api(self.admin, "POST", "dashboards/delete", body={"name": name})[0], 200)
        self.assertEqual(self.admin.request("GET", self.VIEW + name, {"output_mode": "json"})[0], 404)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveMaintenanceTest(unittest.TestCase):
    """WP7: the worker has applied every migration and recorded the installed version."""

    def test_app_state_is_current(self):
        from splunk_ucm import __version__
        from splunk_ucm.catalog.summary import SUMMARY_VERSION
        from splunk_ucm.maintenance.migrations import MIGRATIONS, STATE_KEY
        kv = KVStore(transport())
        deadline = time.time() + 150
        state = {}
        while time.time() < deadline:
            state = kv.get(C.SYNC_STATE, STATE_KEY) or {}
            if state.get("app_version") == __version__:
                break
            time.sleep(10)
        self.assertEqual(state.get("app_version"), __version__, "worker did not record the version in time")
        self.assertEqual(state.get("applied"), [m[0] for m in MIGRATIONS])
        total = kv.count(C.CATALOG)
        self.assertEqual(kv.count(C.CATALOG, {"summary_version": {"$gte": SUMMARY_VERSION}}), total)

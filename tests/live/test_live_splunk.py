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
        self.assertEqual(body["requirement_summary"]["assessment"], "not_assessed")
        self.assertEqual(body["provenance"]["source_blob_sha"], bundle["records"][0]["blob_sha"])

    def test_viewer_denied_changes(self):
        for method, path, body in (("POST", "sync", {"categories": ["9"]}), ("POST", "catalog/reindex", {}),
                                   ("GET", "audit", None), ("GET", "provider/manifest", None)):
            status, payload = api(self.viewer, method, path, body=body)
            self.assertEqual(status, 403, (path, payload))
        status, _ = self.viewer.request(
            "POST", "/servicesNS/nobody/splunk_use_case_manager/storage/collections/data/uc_catalog",
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

    @unittest.skipUnless(os.environ.get("UCM_LIVE_REMOTE") == "1", "set UCM_LIVE_REMOTE=1 for GitHub access")
    def test_remote_manifest_through_splunkd(self):
        status, body = api(self.admin, "GET", "provider/manifest")
        self.assertEqual(status, 200, body)
        self.assertRegex(body["source_ref"], "^[0-9a-f]{40}$")
        self.assertGreaterEqual(len(body["categories"]), 20)


if __name__ == "__main__":
    unittest.main()

"""Integration tests against a REAL Splunk instance with the app installed.

Skipped unless UCM_LIVE_SPLUNK=1. Configure with:
  UCM_SPLUNK_URL       (default https://localhost:8089)
  UCM_SPLUNK_USER / UCM_SPLUNK_PASSWORD   (an admin account)
  UCM_SPLUNK_VERIFY_TLS=0                 (self-signed development instances)
  UCM_LIVE_REMOTE=1                       (also exercise GitHub through splunkd)

Tests write only test-prefixed documents, a partial fixture bundle (records
from tests/fixtures) and a temporary viewer user; they clean up after themselves.
"""

import hashlib
import json
import os
import time
import unittest
import uuid

import helpers
from splunk_ucm import conf
from splunk_ucm.deployment.export import conf_search
from splunk_ucm.platform.search import SearchClient
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import KVStore
from splunk_ucm.util import sha256_text
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


SCHEDULED_OWNER = os.environ.get("UCM_LIVE_SCHEDULED_OWNER", "ucm_scheduler")


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
        lookup = "sun_live_probe_%s.csv" % uuid.uuid4().hex[:6]
        base = "/servicesNS/nobody/sunavigator/admin/macros"
        status, _ = t.request("POST", base, None, None,
                              form={"name": name, "definition": "| makeresults | outputlookup %s" % lookup})
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
            t.request("DELETE", "/servicesNS/nobody/sunavigator/data/lookup-table-files/" + lookup)
            status, _ = t.request("GET", "/servicesNS/nobody/sunavigator/data/lookup-table-files/" + lookup, None, None)
            self.assertEqual(status, 404, "the probe lookup must not be left behind")

    def test_backtick_in_a_comment_does_not_hide_a_subsearch_outputlookup(self):
        """Issue #51, item 6, and the parse guard. Splunk runs subsearches while it parses, so a subsearch that writes must
        not reach the parser at all, whatever a comment or macro quote before it looks like."""
        from splunk_ucm.errors import ValidationError
        from splunk_ucm.platform.search import SearchClient
        from splunk_ucm.spl.parser import parse
        from splunk_ucm.spl.policy import classify
        client = SearchClient(transport())
        lookup = "sun_live_never_written_%s.csv" % uuid.uuid4().hex[:6]
        spl = "| makeresults | append [ ```a`b``` | makeresults | outputlookup %s ]" % lookup
        self.assertEqual(classify(spl).side_effects, ["outputlookup"])
        with self.assertRaises(ValidationError):
            parse(client, spl, app="sunavigator")
        status, _ = transport().request("GET", "/servicesNS/nobody/sunavigator/data/lookup-table-files/" + lookup,
                                        None, None)
        self.assertEqual(status, 404)

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
        self.assertEqual(cm.exception.details["commands"], ["outputlookup"])
        status, _ = t.request("GET", "/servicesNS/nobody/sunavigator/data/lookup-table-files/" + lookup, None, None)
        self.assertEqual(status, 404)
        raw["spl"] = '| makeresults | map search="| makeresults | eval a=1"'
        doc["raw_json"] = encode_raw(raw)
        store.upsert(C.CONTENT, doc)
        with self.assertRaises(ValidationError) as cm:
            svc.preview("fenre:UC-9.1.1", "live")
        self.assertEqual(cm.exception.details["indirect"], ["map"])

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
        self.assertNotIn("u0", json.dumps(out), "sampled event values must not be kept")

    def test_event_search_truncation(self):
        from splunk_ucm.platform.search import SearchClient
        cut = SearchClient(transport()).preview("search index=_internal", max_count=5, earliest="-24h")
        self.assertEqual((len(cut.rows), cut.truncated), (5, True))


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveLintTest(unittest.TestCase):
    """D-065: a use case whose SPL uses match() as a search term is validated by the real parser and shows L001."""

    RECORD = "9.99.901"
    UC = "fenre:UC-9.99.901"
    KEY = "fenre_UC-9.99.901"
    SPL = 'index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR match(_raw, "(?i)brute")) | stats count by Account_Name'

    @classmethod
    def setUpClass(cls):
        from splunk_ucm.util import git_blob_sha
        cls.admin = transport()
        bundle = helpers.fixture_bundle(record_ids=["9.1.1"])
        record = bundle["records"][0]
        content = json.loads(record["content"])
        content.update({"id": cls.RECORD, "title": "Lint probe %s: match used as a search term" % uuid.uuid4().hex[:8], "spl": cls.SPL, "cimSpl": ""})
        text = json.dumps(content, indent=2) + "\n"
        record.update({"record_id": cls.RECORD, "content": text, "blob_sha": git_blob_sha(text.encode("utf-8")),
                       "path": record["path"].replace("UC-9.1.1.json", "UC-%s.json" % cls.RECORD)})
        bundle["records"] = [record]
        status, body = api(cls.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        assert status == 200 and body["job"]["totals"]["invalid"] == 0, body
        cls.kv = KVStore(cls.admin)

    @classmethod
    def tearDownClass(cls):
        for coll in (C.VALIDATION, C.READINESS, C.CATALOG, C.CONTENT):
            cls.kv.delete_query(coll, {"_key": cls.KEY})
        api(cls.admin, "POST", "catalog/reindex", body={})

    def test_validation_shows_the_finding_and_gates_are_unchanged(self):
        status, body = api(self.admin, "POST", "validate", body={"id": self.UC, "sample": False})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["parse_ok"], body)
        self.assertEqual([(f["rule"], f["segment"], f["severity"]) for f in body["lint"]], [("L001", 1, "warning")], body["lint"])
        self.assertIn("match(", body["lint"][0]["call"])
        self.assertIn("where", body["lint"][0]["suggestion"])
        status, stored = api(self.admin, "GET", "validation", {"id": self.UC})
        self.assertEqual((status, stored["lint"]), (200, body["lint"]))
        self.assertEqual(self.kv.get(C.VALIDATION, self.KEY)["lint"], body["lint"])

    def test_a_clean_search_has_no_finding(self):
        status, body = api(self.admin, "POST", "validate", body={"id": "fenre:UC-9.1.1", "sample": False})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["lint"], [])


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
        for coll in (C.SYNC_STATE, C.READINESS, C.VALIDATION, C.ENVIRONMENT_SOURCES, C.SOURCE_MAPPINGS,
                     C.SELECTIONS):
            path = "/servicesNS/nobody/sunavigator/storage/collections/data/" + coll
            status, _ = self.analyst.request("POST", path, None, {"_key": "forged", "state": "ready"})
            self.assertEqual(status, 403, coll)

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
        status, body = api(self.admin, "GET", "catalog", {"quality": "bogus"})
        self.assertEqual((status, body["error"]["message"]), (400, "invalid quality flag"))
        status, body = api(self.admin, "GET", "catalog", {"quality": "unreviewed", "count": "5"})
        self.assertEqual(status, 200, body)
        self.assertTrue(all("unreviewed" in i["quality_flags"] for i in body["items"]), body)
        status, body = api(self.admin, "GET", "catalog", {"regulation": "Bad Id"})
        self.assertEqual((status, body["error"]["message"]), (400, "invalid regulation"))

    def test_facets_match_filters(self):
        status, facets = api(self.viewer, "GET", "catalog/facets")
        self.assertEqual(status, 200, facets)
        for key, param in (("review_statuses", "review"), ("regulations", "regulation")):
            for facet in facets[key][:3]:
                status, body = api(self.viewer, "GET", "catalog", {param: facet["id"], "count": "1"})
                self.assertEqual((status, body["total"]), (200, facet["count"]), (key, facet))

    def test_evidence_pack_is_deterministic_and_matches_clause_gaps(self):
        status, fw = api(self.viewer, "GET", "frameworks")
        regs = [c["framework"] for c in fw["coverage"] if c["kind"] == "regulation"]
        if not regs:
            self.skipTest("no regulation mappings imported")
        framework = regs[0]
        for _ in range(3):
            status, first = api(self.viewer, "GET", "frameworks/evidence", {"framework": framework, "format": "csv"})
            self.assertEqual(status, 200, first)
            _, again = api(self.viewer, "GET", "frameworks/evidence", {"framework": framework, "format": "csv"})
            if first["sha256"] == again["sha256"]:
                break
        self.assertEqual(first["sha256"], again["sha256"], "the pack embeds readiness timestamps; three tries all raced a readiness update")
        self.assertEqual(first["sha256"], hashlib.sha256(first["content"].encode("utf-8")).hexdigest())
        _, pack = api(self.viewer, "GET", "frameworks/evidence", {"framework": framework})
        gaps = {c["clause"] for c in json.loads(pack["content"])["clauses"] if c["gap"]}
        _, controls = api(self.viewer, "GET", "frameworks/controls", {"framework": framework})
        self.assertEqual(gaps, {c["control"] for c in controls["controls"] if c["gap"]})
        clause = controls["controls"][0]["control"]
        status, body = api(self.viewer, "GET", "frameworks/clause", {"framework": framework, "clause": clause})
        self.assertEqual(status, 200, body)
        self.assertEqual(len({u["content_id"] for u in body["use_cases"]}),
                         controls["controls"][0]["counts"]["catalogue"])

    def test_platform_report(self):
        status, body = api(self.admin, "GET", "platform")
        self.assertEqual(status, 200)
        caps = {c["name"]: c["status"] for c in body["capabilities"]}
        self.assertEqual(caps.get("kvstore"), "available")
        self.assertIn("offline_import", caps)
        self.assertEqual(caps.get("index_listing"), "available")
        self.assertEqual(caps.get("adhoc_search"), "available")
        self.assertEqual(caps.get("run_discovery"), "available")

    def wait_discovery_idle(self):
        for _ in range(60):
            _, body = api(self.admin, "GET", "discovery")
            if not any(j["status"] in ("queued", "running") for j in body["jobs"]):
                return
            time.sleep(5)
        self.fail("existing discovery job did not finish")

    def run_discovery(self):
        self.wait_discovery_idle()
        status, body = api(self.admin, "POST", "discovery", body={"include_internal": True, "earliest": "-15m"})
        self.assertEqual(status, 202, body)
        job_id = body["job"]["job_id"]
        for _ in range(60):
            _, state = api(self.admin, "GET", "discovery")
            job = next((j for j in state["jobs"] if j["job_id"] == job_id), None)
            if job and job["status"] not in ("queued", "running"):
                self.assertEqual(job["status"], "succeeded", job)
                return job
            time.sleep(5)
        self.fail("discovery job did not finish")

    def test_addon_detected_by_splunkbase_id_and_package_id(self):
        self.wait_idle()
        bundle = helpers.fixture_bundle(record_ids=["1.1.1"])
        status, body = api(self.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        self.assertEqual(status, 200, body)
        probe = "ucm_probe_ta_" + uuid.uuid4().hex[:6]
        status, _ = self.admin.request("POST", "/services/apps/local",
                                       form={"name": probe, "template": "barebones", "visible": "false"})
        self.assertEqual(status, 201)
        try:
            status, _ = self.admin.request("POST", "/servicesNS/nobody/%s/configs/conf-app" % probe,
                                           form={"name": "package", "id": "Splunk_TA_nix"})
            self.assertEqual(status, 201)
            status, _ = self.admin.request("POST", "/servicesNS/nobody/%s/configs/conf-app/launcher" % probe,
                                           form={"version": "10.2.0"})
            self.assertEqual(status, 200)
            self.admin.request("POST", "/services/apps/local/_reload")
            self.run_discovery()
            status, inv = api(self.admin, "GET", "inventory", {"kind": "app", "q": probe})
            self.assertEqual(status, 200, inv)
            self.assertEqual([i.get("package_id") for i in inv["items"]], ["Splunk_TA_nix"], inv)
            status, doc = api(self.admin, "POST", "readiness/assess", body={"id": "fenre:UC-1.1.1"})
            self.assertEqual(status, 200, doc)
            addon = [r for r in doc["results"] if r["req_id"].startswith("addon:")]
            self.assertEqual([(r["status"], r["observed"][0]["name"], r["observed"][0]["matched_by"])
                              for r in addon], [("met", probe, "splunkbase_id")], addon)
            status, detail = api(self.viewer, "GET", "usecase", {"id": "fenre:UC-1.1.1"})
            env = [r["environment"] for r in detail["requirements"] if r["type"] == "addon"]
            self.assertEqual([e["sources"][0]["name"] for e in env], [probe], env)
        finally:
            self.admin.request("DELETE", "/services/apps/local/" + probe)
            self.run_discovery()

    def test_escu_provider_import_and_detail(self):
        self.wait_idle()
        status, body = api(self.admin, "POST", "import", raw=json.dumps(helpers.escu_fixture_bundle()).encode("utf-8"))
        self.assertEqual(status, 200, body)
        self.assertEqual((body["job"]["status"], body["job"]["provider"], body["job"]["totals"]["invalid"]),
                         ("succeeded", "escu", 0), body)
        status, detail = api(self.viewer, "GET", "usecase", {"id": "escu:UC-11111111-2222-4333-8444-555555555501"})
        self.assertEqual(status, 200, detail)
        self.assertEqual((detail["criticality"], detail["category_name"], detail["domains"]),
                         ("high", "Endpoint", ["endpoint"]), detail)
        self.assertEqual([(m["framework"], m["object_id"], m["object_type"]) for m in detail["framework_mappings"]],
                         [("mitre_attack", "T1562.001", "sub-technique")])
        self.assertIn("security_content_summariesonly",
                      [r["value"] for r in detail["requirements"] if r["type"] == "macro"])

    def test_escu_package_detected_as_addon_when_installed(self):
        self.wait_idle()
        self.run_discovery()
        status, inv = api(self.admin, "GET", "inventory", {"kind": "app", "q": "DA-ESS-ContentUpdate"})
        self.assertEqual(status, 200, inv)
        installed = [i for i in inv["items"] if i.get("package_id") == "DA-ESS-ContentUpdate"]
        if not installed:
            self.skipTest("DA-ESS-ContentUpdate (ESCU) is not installed on this Splunk instance")
        self.assertEqual(installed[0].get("name"), "DA-ESS-ContentUpdate", installed[0])


    def test_discovery_inventory_and_local_mapping(self):
        self.wait_idle()
        job = self.run_discovery()
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

    def test_availability_filter_matches_readiness_counts(self):
        status, summary = api(self.admin, "GET", "readiness/summary")
        self.assertEqual(status, 200, summary)
        for state, count in summary["by_state"].items():
            status, body = api(self.viewer, "GET", "catalog", {"availability": state, "count": "1"})
            self.assertEqual(status, 200, body)
            self.assertEqual(body["total"], count, state)
        status, body = api(self.viewer, "GET", "catalog", {"availability": "not_assessed", "count": "1"})
        status_all, every = api(self.viewer, "GET", "catalog", {"count": "1"})
        self.assertEqual(body["total"], max(0, every["total"] - sum(summary["by_state"].values())))
        status, body = api(self.viewer, "GET", "catalog", {"availability": "bogus"})
        self.assertEqual((status, body["error"]["message"]), (400, "invalid availability"))

    def test_bookmark_filter_is_per_user(self):
        mine, theirs = "fenre:UC-9.1.1", "fenre:UC-9.1.2"
        try:
            self.assertEqual(api(self.viewer, "POST", "selections", body={"id": mine, "intent": "bookmark"})[0], 200)
            self.assertEqual(api(self.admin, "POST", "selections", body={"id": theirs, "intent": "bookmark"})[0], 200)
            _, v = api(self.viewer, "GET", "catalog", {"bookmarked": "1", "count": "50"})
            _, a = api(self.admin, "GET", "catalog", {"bookmarked": "1", "count": "50", "user": self.VIEWER})
            self.assertEqual([i["content_id"] for i in v["items"]], [mine])
            self.assertNotIn(mine, [i["content_id"] for i in a["items"]])
            self.assertIn(theirs, [i["content_id"] for i in a["items"]])
        finally:
            api(self.viewer, "POST", "selections/delete", body={"id": mine})
            api(self.admin, "POST", "selections/delete", body={"id": theirs})

    def test_recommendations_follow_readiness_and_the_callers_rejects(self):
        status, base = api(self.viewer, "GET", "readiness/recommendations")
        self.assertEqual(status, 200, base)
        self.assertLessEqual(len(base["items"]), 10)
        for item in base["items"]:
            self.assertIn(item["state"], ("ready", "partially_ready"))
            self.assertTrue(item["reasons"])
        if not base["items"]:
            self.assertIn(base["empty"], ("no_catalogue", "no_discovery", "no_assessment", "none_eligible"))
            return
        pick = base["items"][0]["content_id"]
        try:
            self.assertEqual(api(self.viewer, "POST", "selections", body={"id": pick, "intent": "reject"})[0], 200)
            _, mine = api(self.viewer, "GET", "readiness/recommendations")
            _, other = api(self.admin, "GET", "readiness/recommendations", {"user": self.VIEWER})
            self.assertNotIn(pick, [i["content_id"] for i in mine["items"]])
            self.assertEqual(mine["excluded"].get("rejected_by_you"), 1)
            self.assertNotIn("rejected_by_you", other["excluded"])
            self.assertNotIn(self.VIEWER, json.dumps(other))
        finally:
            api(self.viewer, "POST", "selections/delete", body={"id": pick})

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
        self.assertTrue(fields)
        self.assertFalse({"_time", "host", "sourcetype", "_raw"} & set(fields), fields)
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
        if status != 200 and "rate_limited" in json.dumps(body):
            self.skipTest("GitHub rate-limited the unauthenticated requests from this machine; rerun later")
        self.assertEqual(status, 200, body)
        self.assertRegex(body["source_ref"], "^[0-9a-f]{40}$")
        self.assertGreaterEqual(len(body["categories"]), 20)
        status, pinned = api(self.admin, "GET", "provider/manifest", {"ref": body["source_ref"]})
        self.assertEqual((status, pinned.get("source_ref")), (200, body["source_ref"]), pinned)
        for ref, message in (("dev", "ref is not in allowed_refs"),
                             ("0" * 40, "commit is not reachable from an allowed ref")):
            status, err = api(self.admin, "GET", "provider/manifest", {"ref": ref})
            self.assertEqual((status, err["error"]["message"]), (400, message), err)


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
        self.assertEqual(live["owner"], SCHEDULED_OWNER)
        self.assertEqual(live["cron_schedule"], "*/30 * * * *")
        self.assertEqual((live["schedule_window"], live["alert.suppress"], live["alert.suppress.period"],
                          live["alert.suppress.fields"]), ("7", True, "1h", "user,src"))
        status, body = self.act(self.operator, "enable", override_reason="live test override reason")
        self.assertEqual(status, 200, body)
        if body["deployment"]["live"]["status"] != "enabled":
            self.assertEqual(body["deployment"]["enable_request"]["by"], self.OPERATOR, body)
            status, body = self.act(self.operator, "enable", override_reason="live test override reason")
            self.assertEqual((status, body["error"]["details"]["code"]), (409, "second_person_required"), body)
            status, body = self.act(self.admin, "enable", override_reason="live test override reason")
            self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["status"], "enabled")
        self.assertFalse(self.saved(name)["disabled"])
        from urllib.parse import quote
        status, _ = self.operator.request("POST", self.SAVED + quote(name, safe=""), form={"disabled": "0"})
        self.assertEqual(status, 403)
        status, _ = self.operator.request("DELETE", self.SAVED + quote(name, safe=""))
        self.assertNotEqual(status, 200)
        self.assertFalse(self.saved(name)["disabled"])
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
        status, bundle = api(self.operator, "GET", "deployments/export")
        self.assertEqual(status, 200, bundle)
        again = api(self.operator, "GET", "deployments/export")[1]
        self.assertEqual(again["sha256"], bundle["sha256"])
        self.assertEqual(again["content"], bundle["content"])
        stanzas = dict(conf.parse(bundle["content"]))
        self.assertEqual(stanzas[name]["cron_schedule"], "*/30 * * * *")
        self.assertEqual(stanzas[name]["disabled"], "1")
        self.assertEqual(stanzas[name]["alert.suppress.period"], "1h")
        entry = [e for e in bundle["manifest"]["entries"] if e["saved_search"] == name][0]
        self.assertEqual((entry["revision"], entry["approved_by"]), (1, os.environ.get("UCM_SPLUNK_USER", "admin")))
        self.assertEqual(entry["conf_search_sha256"], sha256_text(conf_search(stanzas[name]["search"])))
        status, body = self.act(self.operator, "retire")
        self.assertEqual((status, body["deployment"]["state"]), (200, "retired"))
        self.assertIsNone(self.saved(name))
        _, audit = api(self.admin, "GET", "audit", {"prefix": "deployment.", "limit": "50"})
        mine = [e["action"] for e in audit["events"] if e["object_id"] == self.UC]
        for action in ("deployment.approve", "deployment.deploy", "deployment.enable", "deployment.rollback",
                       "deployment.retire"):
            self.assertIn(action, mine)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveControlTestTest(unittest.TestCase):
    """T-23 (D-054): fixture events go to the test index and the deployed SPL runs against them.

    Uses fenre:UC-9.1.2 (index=wineventlog, EventCode=4740). The test replaces every
    fenre control fixture on the instance with its own bundle, which is lab-only.
    """

    OPERATOR = "ucm_ct_operator_" + uuid.uuid4().hex[:6]
    OPERATOR_PW = "T3st!" + uuid.uuid4().hex
    UC = "fenre:UC-9.1.2"
    KEY = "cf_fenre_UC-9.1.2"
    DEP_KEY = "dep_fenre_UC-9.1.2"
    INDEX = "ucm_controltest"
    SAVED = "/servicesNS/nobody/sunavigator/saved/searches/"
    POSITIVE = "".join("EventCode=4740 Account_Name=alice CallerComputerName=dc-lab-1\n" for _ in range(3))
    NEGATIVE = "EventCode=4624 Account_Name=bob CallerComputerName=ws-lab-1\n"

    @staticmethod
    def bundle(positive=None, negative=None, min_count=2, **extra):
        return {"format": "ucm-control-fixtures", "format_version": 1, "provider": "fenre",
                "fixtures": [dict({"uc_id": "9.1.2", "sourcetype": "WinEventLog:Security", "host": "dc-lab-1",
                                   "min_count": min_count,
                                   "positive": LiveControlTestTest.POSITIVE if positive is None else positive,
                                   "negative": LiveControlTestTest.NEGATIVE if negative is None else negative},
                                  **extra)]}

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        if _app_state(cls.admin, "Splunk_TA_windows") is not None:
            raise unittest.SkipTest("Splunk_TA_windows rewrites sourcetype WinEventLog:Security to WinEventLog on "
                                    "ingest, so the fixture events cannot match this use case's sourcetype filter "
                                    "(Fenre upstream report, section 4)")
        cls.admin.request("POST", "/services/data/indexes", form={"name": cls.INDEX})
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.OPERATOR, "password": cls.OPERATOR_PW,
                                            "roles": "ucm_deployment_operator"})
        assert status in (200, 201), status
        cls.operator = transport(cls.OPERATOR, cls.OPERATOR_PW)
        status, body = api(cls.admin, "POST", "import", raw=json.dumps(helpers.fixture_bundle(record_ids=["9.1.2"])).encode("utf-8"))
        assert status == 200, body
        cls.kv = KVStore(cls.admin)
        cls.kv.delete(C.DEPLOYMENTS, cls.DEP_KEY)
        assert api(cls.operator, "POST", "deployment/draft", body={"id": cls.UC})[0] == 200
        assert api(cls.operator, "POST", "deployment/submit", body={"id": cls.UC})[0] == 200
        assert api(cls.admin, "POST", "deployment/approve", body={"id": cls.UC, "note": "live control test"})[0] == 200
        status, body = api(cls.operator, "POST", "deployment/deploy", body={"id": cls.UC})
        assert status == 200, body

    @classmethod
    def tearDownClass(cls):
        from urllib.parse import quote
        doc = cls.kv.get(C.DEPLOYMENTS, cls.DEP_KEY)
        if doc:
            cls.admin.request("DELETE", cls.SAVED + quote(doc["saved_search"]["name"], safe=""))
            cls.kv.delete(C.DEPLOYMENTS, cls.DEP_KEY)
        cls.kv.delete(C.CONTROL_FIXTURES, cls.KEY)
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.OPERATOR)

    def load(self, bundle=None):
        status, body = api(self.admin, "POST", "controltest/import", body=bundle or self.bundle())
        self.assertEqual(status, 200, body)
        return body

    def run_control_test(self, who=None):
        return api(who or self.admin, "POST", "deployment/controltest", body={"id": self.UC})

    def test_import_is_restricted_to_content_managers(self):
        status, body = api(self.operator, "POST", "controltest/import", body=self.bundle())
        self.assertEqual(status, 403, body)
        self.assertEqual(self.load()["count"], 1)
        stored = self.kv.get(C.CONTROL_FIXTURES, self.KEY)
        self.assertEqual((stored["sourcetype"], stored["min_count"]), ("WinEventLog:Security", 2))

    def test_negative_matches_fail_the_control_test(self):
        self.load(self.bundle(negative="EventCode=4740 Account_Name=eve CallerComputerName=dc-lab-1\n"))
        status, body = self.run_control_test(self.operator)
        self.assertEqual(status, 200, body)
        ct = body["deployment"]["control_test"]
        self.assertEqual(ct["status"], "failed", ct)
        self.assertGreaterEqual(ct["negative"]["rows"], 1)
        self.assertIn("negative run", ct["reason"])

    def test_positive_and_negative_runs_pass_on_the_deployed_search(self):
        self.load()
        status, body = self.run_control_test()
        self.assertEqual(status, 200, body)
        ct = body["deployment"]["control_test"]
        self.assertEqual(ct["status"], "passed", ct)
        self.assertEqual(ct["test_index"], self.INDEX)
        self.assertGreaterEqual(ct["positive"]["rows"], 2)
        self.assertEqual(ct["negative"]["rows"], 0)
        self.assertEqual(body["deployment"]["control_test"]["revision"], body["deployment"]["deployed_revision"])
        _, audit = api(self.admin, "GET", "audit", {"prefix": "deployment.controltest", "limit": "20"})
        self.assertIn(self.UC, [e["object_id"] for e in audit["events"]])

    def test_field_assertions_run_on_the_deployed_search_results(self):
        self.load(self.bundle(negative="", fields=[{"name": "Account_Name", "values": ["alice"]}], max_count=10))
        ct = self.run_control_test()[1]["deployment"]["control_test"]
        self.assertEqual(ct["status"], "passed", ct)
        self.assertEqual([f["pass"] for f in ct["positive"]["fields"]], [True])
        self.load(self.bundle(negative="", fields=[{"name": "Account_Name", "values": ["zed"]}]))
        ct = self.run_control_test()[1]["deployment"]["control_test"]
        self.assertEqual(ct["status"], "failed", ct)
        self.assertIn("field Account_Name: expected one of ['zed']", ct["reason"])
        self.load(self.bundle(negative="", max_count=1))
        ct = self.run_control_test()[1]["deployment"]["control_test"]
        self.assertEqual(ct["status"], "failed", ct)
        self.assertIn("expected at most 1", ct["reason"])

    def test_the_search_window_follows_the_fixture_timestamps(self):
        positive = "".join("2026-04-16T08:00:0%dZ EventCode=4740 Account_Name=alice CallerComputerName=dc-lab-1\n" % i
                           for i in range(3))
        self.load(self.bundle(positive=positive, negative=""))
        ct = self.run_control_test()[1]["deployment"]["control_test"]
        self.assertEqual(ct["status"], "passed", ct)
        window = ct["positive"]["window"]
        self.assertTrue(window["derived"], window)
        self.assertEqual(int(window["latest"]) - int(window["earliest"]), 7202)

    def test_missing_fixture_is_reported_without_running(self):
        self.kv.delete(C.CONTROL_FIXTURES, self.KEY)
        status, body = self.run_control_test()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["control_test"]["status"], "no_fixture")


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
        covered = {t["id"] for tac in body["tactics"] for t in tac["techniques"] if t["level"]}
        status, nav = api(self.viewer, "GET", "frameworks/navigator", {"framework_id": "mitre_attack_enterprise"})
        self.assertEqual((status, nav["layer"]["versions"]["attack"]), (200, "20"))
        self.assertTrue(covered <= {t["techniqueID"] for t in nav["layer"]["techniques"]})
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
class LiveProviderNavigationTest(unittest.TestCase):
    """D-066: provider, wave, story and data-source facets, quality exclusion, twin links and Reindex."""

    RECORD = "9.99.902"
    UC = "fenre:UC-9.99.902"
    KEY = "fenre_UC-9.99.902"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.kv = KVStore(cls.admin)
        status, body = api(cls.admin, "POST", "catalog/reindex", body={})
        assert status == 200, body

    @classmethod
    def tearDownClass(cls):
        cls.remove_twin()

    @classmethod
    def remove_twin(cls):
        for coll in (C.VALIDATION, C.READINESS, C.CATALOG, C.CONTENT):
            cls.kv.delete_query(coll, {"_key": cls.KEY})
        api(cls.admin, "POST", "catalog/reindex", body={})

    def catalog(self, **query):
        query.setdefault("count", "1")
        status, body = api(self.admin, "GET", "catalog", query)
        self.assertEqual(status, 200, body)
        return body

    def facets(self):
        status, body = api(self.admin, "GET", "catalog/facets")
        self.assertEqual(status, 200, body)
        return body

    def test_facets_after_reindex_say_the_summaries_are_current(self):
        from splunk_ucm.catalog.summary import SUMMARY_VERSION
        facets = self.facets()
        self.assertEqual(facets["summary"], {"version": SUMMARY_VERSION, "outdated": 0, "normalizer_outdated": 0}, facets["summary"])
        self.assertEqual(sum(facets["providers"].values()), facets["active"])

    def test_provider_facet_counts_equal_filter_totals(self):
        facets = self.facets()
        self.assertTrue(facets["providers"], facets)
        for provider, count in facets["providers"].items():
            self.assertEqual(self.catalog(provider=provider)["total"], count, provider)
        both = ",".join(sorted(facets["providers"]))
        self.assertEqual(self.catalog(provider=both)["total"], facets["active"])
        self.assertEqual(self.catalog(provider="nothing")["total"], 0)

    def test_wave_story_and_data_source_facets_equal_filter_totals(self):
        facets = self.facets()
        for wave, count in facets["waves"].items():
            self.assertEqual(self.catalog(wave=wave)["total"], count, wave)
        for key, param in (("analytic_stories", "story"), ("data_sources", "data_source")):
            for item in facets[key][:5]:
                self.assertEqual(self.catalog(**{param: item["id"]})["total"], item["count"], (param, item))
        status, body = api(self.admin, "GET", "catalog", {"wave": "bogus"})
        self.assertEqual((status, body["error"]["message"]), (400, "invalid wave"))

    def test_unassigned_escu_use_cases_stay_listed_and_are_found_by_story(self):
        facets = self.facets()
        if not facets["providers"].get("escu"):
            self.skipTest("no ESCU content on this instance")
        unassigned = self.catalog(category="escu_cat-unassigned", count="50")
        self.assertEqual(unassigned["total"], facets["categories"].get("escu_cat-unassigned", 0))
        stories = [i for i in facets["analytic_stories"]]
        self.assertTrue(stories, "ESCU content without any analytic story facet")
        story = self.catalog(story=stories[0]["id"], provider="escu", count="50")
        self.assertTrue(all(i["provider"] == "escu" for i in story["items"]))

    def test_filters_combine_and_old_urls_keep_their_meaning(self):
        facets = self.facets()
        domain = sorted(facets["domains"])[0]
        every = self.catalog(domain=domain)["total"]
        split = sum(self.catalog(domain=domain, provider=p)["total"] for p in facets["providers"])
        self.assertEqual(split, every)
        self.assertEqual(self.catalog(category=sorted(facets["categories"])[0])["total"],
                         facets["categories"][sorted(facets["categories"])[0]])

    def test_exclude_quality_removes_exactly_the_flagged_use_cases(self):
        total = self.catalog()["total"]
        for flag in ("unreviewed", "ai_reviewed", "duplicate_spl"):
            flagged = self.catalog(quality=flag)["total"]
            self.assertEqual(self.catalog(exclude_quality=flag)["total"], total - flagged, flag)
        both = self.catalog(quality="unreviewed,ai_reviewed")["total"]
        self.assertEqual(self.catalog(exclude_quality="unreviewed,ai_reviewed")["total"], total - both)
        status, body = api(self.admin, "GET", "catalog", {"exclude_quality": "bogus"})
        self.assertEqual((status, body["error"]["message"]), (400, "invalid quality flag"))

    def test_recommendations_exclusion_is_opt_in(self):
        status, default = api(self.admin, "GET", "readiness/recommendations")
        self.assertEqual(status, 200, default)
        self.assertEqual(default["exclude_quality"], [])
        status, strict = api(self.admin, "GET", "readiness/recommendations", {"exclude_quality": "ai_reviewed,unreviewed"})
        self.assertEqual(status, 200, strict)
        self.assertEqual(strict["exclude_quality"], ["ai_reviewed", "unreviewed"])
        self.assertLessEqual(strict["eligible_total"], default["eligible_total"])
        flagged = {i["content_id"] for i in default["items"]} - {i["content_id"] for i in strict["items"]}
        for content_id in flagged:
            status, detail = api(self.admin, "GET", "usecase", {"id": content_id})
            self.assertTrue({"ai_reviewed", "unreviewed"} & set(detail["quality_flags"]), content_id)

    def test_twin_links_both_ways_with_and_without_the_twin(self):
        from splunk_ucm.util import git_blob_sha
        status, escu = api(self.admin, "GET", "catalog", {"provider": "escu", "count": "1", "sort": "id"})
        if not escu["items"]:
            self.skipTest("no ESCU content on this instance")
        escu_id, escu_key = escu["items"][0]["content_id"], escu["items"][0]["_key"]
        status, escu_detail = api(self.admin, "GET", "usecase", {"id": escu_id})
        self.assertEqual((status, escu_detail["spl_twins"]), (200, []), "no twin before the Fenre record exists")
        bundle = helpers.fixture_bundle(record_ids=["9.1.1"])
        record = bundle["records"][0]
        content = json.loads(record["content"])
        content.update({"id": self.RECORD, "title": "Twin probe %s" % uuid.uuid4().hex[:8], "spl": escu_detail["spl"], "cimSpl": ""})
        text = json.dumps(content, indent=2) + "\n"
        record.update({"record_id": self.RECORD, "content": text, "blob_sha": git_blob_sha(text.encode("utf-8")),
                       "path": record["path"].replace("UC-9.1.1.json", "UC-%s.json" % self.RECORD)})
        status, body = api(self.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        self.assertEqual((status, body["job"]["totals"]["invalid"]), (200, 0), body)
        try:
            status, fen = api(self.admin, "GET", "usecase", {"id": self.UC})
            self.assertEqual(status, 200, fen)
            self.assertEqual([(t["content_id"], t["provider"]) for t in fen["spl_twins"]], [(escu_id, "escu")])
            self.assertEqual(fen["spl_twins"][0]["authority"]["role"], "detection")
            self.assertEqual(fen["authority"]["role"], "compliance")
            self.assertIn("provider_twin", fen["quality_flags"])
            status, escu_detail = api(self.admin, "GET", "usecase", {"id": escu_id})
            self.assertEqual([(t["content_id"], t["provider"]) for t in escu_detail["spl_twins"]], [(self.UC, "fenre")])
            self.assertEqual(escu_detail["authority"]["role"], "detection")
            self.assertIn("provider_twin", escu_detail["quality_flags"])
            twins = self.catalog(quality="provider_twin", count="50")
            self.assertTrue({self.UC, escu_id} <= {i["content_id"] for i in twins["items"]}, twins["total"])
            facets = self.facets()
            self.assertEqual({q["id"]: q["count"] for q in facets["quality_flags"]}["provider_twin"], twins["total"])
        finally:
            self.remove_twin()
        status, escu_detail = api(self.admin, "GET", "usecase", {"id": escu_id})
        self.assertEqual(escu_detail["spl_twins"], [], "the link disappears with the twin")
        self.assertNotIn("provider_twin", escu_detail["quality_flags"])
        self.assertEqual(self.catalog(quality="provider_twin")["total"], 0)

    def test_reindex_is_idempotent(self):
        def snapshot():
            rows = self.kv.query(C.CATALOG, {}, fields=None)
            return {r["_key"]: {k: v for k, v in r.items() if not k.startswith("_user")} for r in rows}
        status, first = api(self.admin, "POST", "catalog/reindex", body={})
        self.assertEqual(status, 200, first)
        before = snapshot()
        facets_before = self.facets()
        status, second = api(self.admin, "POST", "catalog/reindex", body={})
        self.assertEqual(status, 200, second)
        self.assertEqual((second["reindexed"], second["twin_groups"], second["duplicate_groups"]),
                         (first["reindexed"], first["twin_groups"], first["duplicate_groups"]))
        self.assertEqual(snapshot(), before)
        after = self.facets()
        for key in ("providers", "waves", "analytic_stories", "data_sources", "summary", "active"):
            self.assertEqual(after[key], facets_before[key], key)


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
        missing = [m[0] for m in MIGRATIONS if m[0] not in (state.get("applied") or [])]
        self.assertEqual(missing, [], state.get("applied"))
        # D-066: a new summary version is not applied by an upgrade. The facets document says how many
        # active summaries are older, and that number is the real count.
        facets = kv.get(C.SYNC_STATE, "catalog::facets") or {}
        stale = kv.count(C.CATALOG, {"$and": [{"provider_status": "active"}, {"summary_version": {"$lt": SUMMARY_VERSION}}]})
        self.assertEqual(facets.get("summary"), {"version": SUMMARY_VERSION, "outdated": stale, "normalizer_outdated": 0}, facets.get("summary"))


def oneshot(t, spl, earliest="-15m", latest="now"):
    status, content = t.request("POST", "/services/search/jobs",
                                form={"search": spl, "exec_mode": "oneshot", "earliest_time": earliest,
                                      "latest_time": latest, "output_mode": "json", "count": "50"}, timeout=120)
    assert status == 200, (status, content[:300])
    return json.loads(content).get("results", [])


def conf_value(t, stanza, key):
    status, content = t.request("GET", "/servicesNS/nobody/sunavigator/configs/conf-ucm/" + stanza,
                                {"output_mode": "json"})
    if status != 200:
        return ""
    return json.loads(content)["entry"][0]["content"].get(key, "")


def set_conf_value(t, stanza, key, value):
    status, content = t.request("POST", "/servicesNS/nobody/sunavigator/configs/conf-ucm/" + stanza,
                                form={key: value})
    assert status == 200, (status, content[:300])


def _internalised(record_id, spl):
    """A copy of one fixture record whose search reads only _internal (no macros, no datamodel)."""
    from splunk_ucm.util import git_blob_sha
    bundle = helpers.fixture_bundle(record_ids=[record_id])
    entry = bundle["records"][0]
    record = json.loads(entry["content"])
    record["spl"] = spl
    record.pop("cimSpl", None)
    entry["content"] = json.dumps(record, indent=2) + "\n"
    entry["blob_sha"] = git_blob_sha(entry["content"].encode("utf-8"))
    return bundle


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveSchedulerVisibilityTest(unittest.TestCase):
    """B-03 (D-063): the scheduled owner's index access is read with the handler's system token.

    A throw-away role imports ``user`` (so it holds ``*``, which excludes internal indexes) and a throw-away
    user holds the role. The test points ``[deployment] scheduled_owner`` at that user, shows ``not_met`` for
    ``_internal``, grants it and shows ``met``, disallows it again, and restores the configuration.
    """

    ID = uuid.uuid4().hex[:6]
    ROLE = "ucm_test_rr_" + ID
    SCHED = "ucm_test_sch_" + ID
    OPERATOR = "ucm_test_op_" + ID
    PW = "T3st!" + uuid.uuid4().hex
    UC = "fenre:UC-5.2.14"
    SPL = "index=_internal sourcetype=scheduler | stats count by status"
    SAVED = "/servicesNS/nobody/sunavigator/saved/searches/"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.kv = KVStore(cls.admin)
        cls.original_owner = conf_value(cls.admin, "deployment", "scheduled_owner")
        try:
            cls._create()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _create(cls):
        status, body = cls.admin.request("POST", "/services/authorization/roles",
                                         form={"name": cls.ROLE, "imported_roles": "user",
                                               "capabilities": "schedule_search"})
        assert status in (200, 201), (status, body[:300])
        for name, roles in ((cls.SCHED, cls.ROLE), (cls.OPERATOR, "ucm_deployment_operator")):
            status, body = cls.admin.request("POST", "/services/authentication/users",
                                             form={"name": name, "password": cls.PW, "roles": roles})
            assert status in (200, 201), (status, body[:300])
        cls.operator = transport(cls.OPERATOR, cls.PW)
        set_conf_value(cls.admin, "deployment", "scheduled_owner", cls.SCHED)
        status, body = api(cls.admin, "POST", "import",
                           raw=json.dumps(_internalised("5.2.14", cls.SPL)).encode("utf-8"))
        assert status == 200, body
        cls.kv.delete(C.DEPLOYMENTS, "dep_fenre_UC-5.2.14")

    @classmethod
    def tearDownClass(cls):
        from urllib.parse import quote
        doc = cls.kv.get(C.DEPLOYMENTS, "dep_fenre_UC-5.2.14")
        if doc:
            cls.admin.request("DELETE", cls.SAVED + quote(doc["saved_search"]["name"], safe=""))
            cls.kv.delete(C.DEPLOYMENTS, "dep_fenre_UC-5.2.14")
        set_conf_value(cls.admin, "deployment", "scheduled_owner", cls.original_owner)
        for name in (cls.SCHED, cls.OPERATOR):
            cls.admin.request("DELETE", "/services/authentication/users/" + name)
        cls.admin.request("DELETE", "/services/authorization/roles/" + cls.ROLE)
        api(cls.admin, "POST", "import", raw=json.dumps(helpers.fixture_bundle(record_ids=["5.2.14"])).encode("utf-8"))

    def role(self, **form):
        status, body = self.admin.request("POST", "/services/authorization/roles/" + self.ROLE, form=form)
        self.assertEqual(status, 200, body[:300])

    def permission(self):
        status, doc = api(self.admin, "POST", "readiness/assess", body={"id": self.UC})
        self.assertEqual(status, 200, doc)
        rows = [r for r in doc["results"] if r["type"] == "permission"]
        self.assertEqual(len(rows), 1, doc["results"])
        return rows[0]

    def act(self, who, action, **body):
        body["id"] = self.UC
        return api(who, "POST", "deployment/" + action, body=body)

    def second_person_refusals(self):
        _, audit = api(self.admin, "GET", "audit", {"prefix": "refused.", "limit": "500"})
        return len([e for e in audit["events"] if e["object_id"] == self.UC and e["outcome"] == "refused"
                    and e["details"].get("code") == "second_person_required"])

    def test_restricted_role_then_granted(self):
        second_person_before = self.second_person_refusals()
        status, summary = api(self.operator, "GET", "readiness/summary")
        self.assertEqual(status, 200, summary)
        card = summary["scheduler"]
        self.assertEqual((card["owner"], card["status"], card["roles"]), (self.SCHED, "ok", [self.ROLE]), card)
        self.assertFalse(card["internal_access"])
        self.assertTrue(card["all_indexes_access"])
        self.assertNotIn("allowed", card)
        row = self.permission()
        self.assertEqual((row["status"], row["code"]), ("not_met", "index_not_accessible"), row)
        self.assertIn(self.SCHED, row["value"])
        self.assertIn("_internal", row["detail"])
        self.assertIn("'_*' does", row["detail"])

        status, body = self.act(self.operator, "draft", spl_source="custom", custom_spl=self.SPL,
                                cron="*/30 * * * *")
        self.assertEqual(status, 200, body)
        dep = body["deployment"]
        self.assertEqual(body["scheduler_access"]["status"], "not_met", body["scheduler_access"])
        name = dep["saved_search"]["name"]
        status, body = self.act(self.operator, "submit")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["revisions"][-1]["scheduler_access"]["status"], "not_met")
        status, body = self.act(self.admin, "approve", note="live test")
        self.assertEqual((status, body["error"]["details"]["code"]), (409, "access_gap_reason_required"), body)
        status, body = self.act(self.admin, "approve", note="live test", access_reason="live test: role is being changed")
        self.assertEqual(status, 200, body)
        status, body = self.act(self.operator, "deploy")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["drift"], [])

        status, body = self.act(self.operator, "enable")
        self.assertEqual(status, 409, body)
        self.assertIn("cannot search _internal", json.dumps(body))
        self.assertIn("override", json.dumps(body))
        status, body = self.act(self.operator, "enable", override_reason="live test: accept blind run")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["status"], "disabled")
        self.assertEqual(body["deployment"]["enable_request"]["by"], self.OPERATOR, body)
        status, body = self.act(self.operator, "enable", override_reason="live test: accept blind run")
        self.assertEqual((status, body["error"]["details"]["code"]), (409, "second_person_required"), body)
        status, body = self.act(self.admin, "enable", override_reason="live test: accept blind run")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["status"], "enabled")
        self.assertEqual(self.act(self.operator, "disable")[0], 200)
        _, audit = api(self.admin, "GET", "audit", {"prefix": "deployment.enable", "limit": "20"})
        mine = [e for e in audit["events"] if e["object_id"] == self.UC]
        self.assertTrue(mine, audit)
        self.assertEqual(mine[0]["action"], "deployment.enable", mine[0])
        self.assertEqual(mine[0]["details"]["scheduler_access"], "not_met", mine[0])
        self.assertEqual(mine[0]["details"]["override_reason"], "live test: accept blind run")
        self.assertEqual(mine[0]["details"]["requested_by"], self.OPERATOR, mine[0])
        _, audit = api(self.admin, "GET", "audit", {"prefix": "deployment.approve", "limit": "20"})
        approvals = [e for e in audit["events"] if e["object_id"] == self.UC]
        self.assertTrue(any(e["details"].get("access_gap_reason") for e in approvals), approvals)
        _, audit = api(self.admin, "GET", "audit", {"prefix": "refused.", "limit": "500"})
        refused = [e for e in audit["events"] if e["object_id"] == self.UC and e["outcome"] == "refused"]
        codes = {e["details"]["code"] for e in refused}
        self.assertTrue({"access_gap_reason_required", "second_person_required"} <= codes, refused)
        self.assertEqual(self.second_person_refusals() - second_person_before, 1, refused)

        self.role(srchIndexesAllowed="_internal")
        status, summary = api(self.operator, "GET", "readiness/summary")
        self.assertTrue(summary["scheduler"]["internal_access"], summary["scheduler"])
        row = self.permission()
        self.assertEqual((row["status"], row["code"]), ("met", "index_accessible"), row)
        status, view = api(self.operator, "GET", "deployment", {"id": self.UC})
        self.assertEqual(view["scheduler_access"]["status"], "met", view["scheduler_access"])
        status, body = self.act(self.operator, "enable", override_reason="")
        if status == 409:
            self.assertNotEqual(body.get("code"), "scheduler_access_gate", body)
        else:
            self.assertEqual(status, 200, body)
            self.assertEqual(self.act(self.operator, "disable")[0], 200)

        self.role(srchIndexesDisallowed="_internal")
        row = self.permission()
        self.assertEqual(row["status"], "not_met", row)
        self.assertIn("disallowed", row["detail"])
        # splunkd drops an index from srchIndexesAllowed when it is added to srchIndexesDisallowed
        self.role(srchIndexesDisallowed="", srchIndexesAllowed="_internal")
        row = self.permission()
        self.assertEqual(row["status"], "met", row)

        self.assertEqual(self.act(self.operator, "retire")[0], 200)
        status, _ = self.admin.request("GET", self.SAVED + name.replace(" ", "%20"), {"output_mode": "json"})
        self.assertEqual(status, 404)

    def test_unknown_owner_is_unverified_and_never_blocks(self):
        set_conf_value(self.admin, "deployment", "scheduled_owner", "ucm_test_nobody_" + self.ID)
        try:
            status, summary = api(self.operator, "GET", "readiness/summary")
            self.assertEqual(summary["scheduler"]["status"], "user_not_found", summary["scheduler"])
            row = self.permission()
            self.assertEqual((row["status"], row["code"]), ("unverified", "owner_not_found"), row)
        finally:
            set_conf_value(self.admin, "deployment", "scheduled_owner", self.SCHED)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveScheduledRunTest(unittest.TestCase):
    """B-04 / issue #7 (D-063): a deployed search really runs on the scheduler as the scheduled owner.

    Two temporary users (four-eyes), a one-minute schedule, one real scheduled run. The test reads
    ``scheduler.log`` for the run's user and status and checks that the saved search's owner is unchanged.
    """

    ID = uuid.uuid4().hex[:6]
    SUBMITTER = "ucm_test_sub_" + ID
    APPROVER = "ucm_test_apr_" + ID
    PW = "T3st!" + uuid.uuid4().hex
    UC = "fenre:UC-18.2.1"
    DEP_KEY = "dep_fenre_UC-18.2.1"
    SPL = '| makeresults count=1 | eval sun_probe="scheduled-run"'
    SAVED = "/servicesNS/nobody/sunavigator/saved/searches/"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.kv = KVStore(cls.admin)
        if conf_value(cls.admin, "deployment", "scheduled_owner") != SCHEDULED_OWNER:
            raise unittest.SkipTest("[deployment] scheduled_owner is not %s on this instance" % SCHEDULED_OWNER)
        try:
            cls._create()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _create(cls):
        for name in (cls.SUBMITTER, cls.APPROVER):
            status, body = cls.admin.request("POST", "/services/authentication/users",
                                             form={"name": name, "password": cls.PW,
                                                   "roles": "ucm_deployment_operator"})
            assert status in (200, 201), (status, body[:300])
        cls.submitter = transport(cls.SUBMITTER, cls.PW)
        cls.approver = transport(cls.APPROVER, cls.PW)
        status, body = api(cls.admin, "POST", "import",
                           raw=json.dumps(helpers.fixture_bundle(record_ids=["18.2.1"])).encode("utf-8"))
        assert status == 200, body
        cls.kv.delete(C.DEPLOYMENTS, cls.DEP_KEY)

    @classmethod
    def tearDownClass(cls):
        from urllib.parse import quote
        doc = cls.kv.get(C.DEPLOYMENTS, cls.DEP_KEY)
        if doc:
            cls.admin.request("DELETE", cls.SAVED + quote(doc["saved_search"]["name"], safe=""))
            cls.kv.delete(C.DEPLOYMENTS, cls.DEP_KEY)
        for name in (cls.SUBMITTER, cls.APPROVER):
            cls.admin.request("DELETE", "/services/authentication/users/" + name)

    def act(self, who, action, **body):
        body["id"] = self.UC
        return api(who, "POST", "deployment/" + action, body=body)

    def saved(self, name):
        from urllib.parse import quote
        status, content = self.admin.request("GET", self.SAVED + quote(name, safe=""), {"output_mode": "json"})
        if status == 404:
            return None
        entry = json.loads(content)["entry"][0]
        return dict(entry["content"], owner=entry["acl"]["owner"], sharing=entry["acl"]["sharing"])

    def test_scheduled_run_executes_as_scheduler_account(self):
        status, body = self.act(self.submitter, "draft", spl_source="custom", custom_spl=self.SPL, cron="* * * * *",
                                earliest="-5m@m", latest="@m")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["deployment"]["revisions"][0]["parse_ok"], body)
        name = body["deployment"]["saved_search"]["name"]
        self.assertEqual(self.act(self.submitter, "submit")[0], 200)
        self.assertEqual(self.act(self.submitter, "approve")[0], 403)
        self.assertEqual(self.act(self.approver, "approve", note="live test: scheduled run")[0], 200)
        status, body = self.act(self.approver, "deploy")
        self.assertEqual(status, 200, body)
        before = self.saved(name)
        self.assertTrue(before["disabled"])
        self.assertEqual((before["owner"], before["sharing"]), (SCHEDULED_OWNER, "app"))
        self.assertEqual(before["cron_schedule"], "* * * * *")
        status, body = self.act(self.approver, "enable", override_reason="live test: scheduled run evidence")
        self.assertEqual(status, 200, body)
        if body["deployment"]["live"]["status"] != "enabled":
            status, body = self.act(self.submitter, "enable", override_reason="live test: scheduled run evidence")
            self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["status"], "enabled")
        enabled_at = time.time()
        try:
            rows = []
            deadline = enabled_at + 240
            spl = ('search index=_internal sourcetype=scheduler savedsearch_name="%s" | '
                   'table _time user app status result_count savedsearch_name' % name)
            while time.time() < deadline and not rows:
                time.sleep(15)
                rows = oneshot(self.admin, spl, earliest="-10m")
            self.assertTrue(rows, "no scheduler.log entry for %s within 4 minutes" % name)
            first = rows[-1]
            if os.environ.get("UCM_LIVE_VERBOSE") == "1":
                print("\nscheduler.log:", json.dumps(first, sort_keys=True))
            self.assertEqual(first["user"], SCHEDULED_OWNER, first)
            self.assertNotIn(first["user"], (self.SUBMITTER, self.APPROVER))
            self.assertEqual(first["status"], "success", first)
            self.assertEqual(first["app"], "sunavigator", first)
            self.assertEqual(first["result_count"], "1", first)
            after = self.saved(name)
            self.assertEqual((after["owner"], after["sharing"]), (SCHEDULED_OWNER, "app"))
            self.assertFalse(after["disabled"])
        finally:
            self.act(self.approver, "disable")
        status, body = self.act(self.approver, "retire")
        self.assertEqual((status, body["deployment"]["state"]), (200, "retired"))
        self.assertIsNone(self.saved(name))


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveSchedulerRoleTest(unittest.TestCase):
    """D-068: an account with only ``ucm_scheduler`` searches, but cannot write or send data."""

    USER = "ucm_test_sched_" + uuid.uuid4().hex[:6]
    PW = "T3st!" + uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        status, body = cls.admin.request("POST", "/services/authentication/users",
                                         form={"name": cls.USER, "password": cls.PW, "roles": "ucm_scheduler"})
        assert status in (200, 201), (status, body[:300])
        cls.user = transport(cls.USER, cls.PW)

    @classmethod
    def tearDownClass(cls):
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.USER)

    def run_as_scheduler(self, spl):
        status, content = self.user.request("POST", "/services/search/jobs",
                                            form={"search": spl, "exec_mode": "oneshot", "output_mode": "json",
                                                  "earliest_time": "-5m", "latest_time": "now"}, timeout=120)
        doc = json.loads(content or b"{}")
        return status, doc.get("results", []), " ".join(m.get("text", "") for m in doc.get("messages", []))

    def test_role_imports_nothing_and_holds_no_write_capability(self):
        status, content = self.admin.request("GET", "/services/authorization/roles/ucm_scheduler",
                                             {"output_mode": "json"})
        self.assertEqual(status, 200)
        role = json.loads(content)["entry"][0]["content"]
        self.assertEqual(role.get("imported_roles") or [], [])
        status, content = self.user.request("GET", "/services/authentication/current-context",
                                            {"output_mode": "json"})
        caps = json.loads(content)["entry"][0]["content"]["capabilities"]
        for capability in ("run_collect", "run_mcollect", "output_file", "run_dump", "run_sendalert"):
            self.assertNotIn(capability, caps)
        self.assertIn("schedule_search", caps)

    def test_side_effect_commands_are_refused_by_splunk(self):
        for spl in ("| makeresults count=2 | appendpipe [ collect index=main sourcetype=ucm_test_probe ]",
                    "| makeresults count=2 | outputlookup ucm_test_probe.csv",
                    "| makeresults count=1 | sendalert ucm_test_probe"):
            with self.subTest(spl=spl):
                _, results, messages = self.run_as_scheduler(spl)
                self.assertEqual(results, [])
                self.assertRegex(messages.lower(), "insufficient privileges|capability")

    def test_read_only_search_runs(self):
        status, results, _ = self.run_as_scheduler('| makeresults count=2 | eval sun_probe="role"')
        self.assertEqual(status, 200)
        self.assertEqual(len(results), 2)


def _app_state(t, app):
    status, content = t.request("GET", "/services/apps/local/" + app, {"output_mode": "json"})
    if status == 404:
        return None
    return json.loads(content)["entry"][0]["content"]


def _wait_discovery(admin, **body):
    for _ in range(60):
        _, state = api(admin, "GET", "discovery")
        if not any(j["status"] in ("queued", "running") for j in state["jobs"]):
            break
        time.sleep(5)
    status, posted = api(admin, "POST", "discovery", body=body)
    assert status == 202, posted
    job_id = posted["job"]["job_id"]
    for _ in range(90):
        _, state = api(admin, "GET", "discovery")
        job = next((j for j in state["jobs"] if j["job_id"] == job_id), None)
        if job and job["status"] not in ("queued", "running"):
            return job
        time.sleep(5)
    raise AssertionError("discovery job did not finish")


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveSecurityContentTest(unittest.TestCase):
    """D-067: ES/ESCU read-only hand-off on a lab with ESCU and without ES. The ES-present branch is not covered here."""

    VIEWER = "ucm_test_sc_viewer_" + uuid.uuid4().hex[:6]
    VIEWER_PW = "T3st!" + uuid.uuid4().hex
    RECORDS = ("99999999-0000-4000-8000-000000000001", "99999999-0000-4000-8000-000000000002")

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.escu = _app_state(cls.admin, "DA-ESS-ContentUpdate")
        cls.es = _app_state(cls.admin, "SplunkEnterpriseSecuritySuite")
        if cls.escu is None:
            raise unittest.SkipTest("ESCU (DA-ESS-ContentUpdate) is not installed on this Splunk instance")
        cls.kv = KVStore(cls.admin)
        status, content = cls.admin.request("GET", "/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches",
                                            {"output_mode": "json", "count": "0", "search": "ESCU"})
        entries = [e for e in json.loads(content)["entry"] if e["name"].startswith("ESCU - ") and e["name"].endswith(" - Rule")]
        assert entries, "no ESCU saved search on the lab"
        cls.stanza = entries[0]["name"]
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.VIEWER, "password": cls.VIEWER_PW, "roles": "ucm_viewer"})
        assert status in (200, 201), status
        cls.viewer = transport(cls.VIEWER, cls.VIEWER_PW)
        cls.imported = False

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "VIEWER", None) and cls.escu is not None:
            cls.admin.request("DELETE", "/services/authentication/users/" + cls.VIEWER)
        if getattr(cls, "imported", False):
            for rid in cls.RECORDS:
                key = "escu_UC-" + rid
                for coll in (C.DEPLOYMENTS, ):
                    cls.kv.delete_query(coll, {"catalog_key": key})
                for coll in (C.VALIDATION, C.READINESS, C.CATALOG, C.CONTENT):
                    cls.kv.delete_query(coll, {"_key": key})
            # The category's tree hash is what makes an import "unchanged"; restore the fixture bundle's.
            api(cls.admin, "POST", "import", raw=json.dumps(helpers.escu_fixture_bundle()).encode("utf-8"))
            api(cls.admin, "POST", "catalog/reindex", body={})

    def stanza_rest(self, name):
        from urllib.parse import quote
        status, content = self.admin.request(
            "GET", "/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/" + quote(name, safe=""), {"output_mode": "json"})
        self.assertEqual(status, 200)
        return json.loads(content)["entry"][0]["content"]

    def import_records(self):
        from splunk_ucm.util import git_blob_sha
        bundle = helpers.escu_fixture_bundle()
        keep = []
        for rid, stanza in zip(self.RECORDS, (self.stanza, "ESCU - SUN live missing stanza - Rule")):
            entry = dict(bundle["records"][0])
            raw = json.loads(entry["content"])
            raw.update({"id": rid, "stanza": stanza, "title": "SUN live hand-off " + rid[-1]})
            entry.update({"record_id": rid, "path": "detections/endpoint/%s.json" % rid,
                          "content": json.dumps(raw, indent=2) + "\n"})
            entry["blob_sha"] = git_blob_sha(entry["content"].encode("utf-8"))
            keep.append(entry)
        bundle["records"] = keep
        status, body = api(self.admin, "POST", "import", raw=json.dumps(bundle).encode("utf-8"))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["job"]["status"], "succeeded", body)
        type(self).imported = True

    def test_platform_card_data_for_a_viewer(self):
        status, body = api(self.viewer, "GET", "platform")
        self.assertEqual(status, 200, body)
        sc = body["security_content"]
        self.assertEqual((sc["escu"]["state"], sc["escu"]["version"]), ("installed", self.escu["version"]), sc)
        if self.es is None:
            self.assertEqual(sc["es"]["state"], "not_installed", sc)
            self.assertEqual(sc["es"]["app_id"], "SplunkEnterpriseSecuritySuite")
        else:
            self.assertEqual((sc["es"]["state"], sc["es"]["version"]), ("installed", self.es["version"]))

    def test_card_shows_the_stanza_state_read_from_the_real_escu_app(self):
        self.import_records()
        rest = self.stanza_rest(self.stanza)
        status, detail = api(self.viewer, "GET", "usecase", {"id": "escu:UC-" + self.RECORDS[0]})
        self.assertEqual(status, 200, detail)
        card = detail["escu_handoff"]
        stanza = card["stanza"]
        self.assertEqual(stanza["name"], self.stanza)
        self.assertEqual(stanza["state"], "disabled" if rest["disabled"] in (True, "1", 1) else "enabled")
        self.assertEqual(stanza["cron"], rest.get("cron_schedule"))
        self.assertEqual(stanza["earliest"], rest.get("dispatch.earliest_time"))
        self.assertEqual(stanza["notable"], str(rest.get("action.notable")) == "1" or "notable" in str(rest.get("actions")))
        self.assertEqual(stanza["risk"], str(rest.get("action.risk")) == "1" or "risk" in str(rest.get("actions")))
        self.assertEqual(card["escu"]["version"], self.escu["version"])
        if self.es is None:
            self.assertEqual(card["es"]["state"], "not_installed")
            self.assertIsNone(card["es_link"])
            self.assertEqual(card["code"], "escu_without_es")
            self.assertEqual(card["parallel_copy"]["warn"], stanza["state"] == "enabled")
        self.assertIn("does not count as enabled in SUN coverage", card["coverage_note"])

    def test_missing_stanza_and_other_providers(self):
        self.import_records()
        status, detail = api(self.viewer, "GET", "usecase", {"id": "escu:UC-" + self.RECORDS[1]})
        self.assertEqual(status, 200, detail)
        self.assertEqual((detail["escu_handoff"]["code"], detail["escu_handoff"]["stanza"]["state"]),
                         ("stanza_not_found", "not_found"))
        status, fenre = api(self.admin, "POST", "import",
                            raw=json.dumps(helpers.fixture_bundle(record_ids=["9.1.1"])).encode("utf-8"))
        self.assertEqual(status, 200, fenre)
        status, detail = api(self.viewer, "GET", "usecase", {"id": "fenre:UC-9.1.1"})
        self.assertEqual(status, 200, detail)
        self.assertIsNone(detail["escu_handoff"])

    def test_draft_records_nothing_when_there_is_no_parallel_copy_to_warn_about(self):
        self.import_records()
        rest = self.stanza_rest(self.stanza)
        status, body = api(self.admin, "POST", "deployment/draft", body={"id": "escu:UC-" + self.RECORDS[0]})
        self.assertEqual(status, 200, body)
        rev = body["deployment"]["revisions"][-1]
        warns = self.es is not None or rest["disabled"] not in (True, "1", 1)
        self.assertEqual("parallel_copy" in rev, warns, rev.get("parallel_copy"))
        self.assertEqual(body["deployment"]["state"], "draft")


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LivePopulatedTest(unittest.TestCase):
    """D-067 / issue #13: the populated check on real data models. The lab has no CIM add-on, so two temporary
    models stand in: one that matches events and one that matches none."""

    YES = "sun_live_pop_yes_" + uuid.uuid4().hex[:6]
    NO = "sun_live_pop_no_" + uuid.uuid4().hex[:6]

    @staticmethod
    def model_json(name, constraint):
        return json.dumps({
            "modelName": name, "displayName": name, "description": "temporary SUN live test model",
            "objectSummary": {"Event-Based": 1, "Transaction-Based": 0, "Search-Based": 0},
            "objects": [{"objectName": "Events", "displayName": "Events", "parentName": "BaseEvent", "comment": "",
                         "fields": [{"fieldName": "_time", "owner": "BaseEvent", "type": "timestamp", "fieldSearch": "",
                                     "required": True, "multivalue": False, "hidden": False, "editable": False,
                                     "displayName": "_time", "comment": ""}],
                         "calculations": [], "constraints": [{"search": constraint, "owner": "Events"}],
                         "lineage": "Events"}]})

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        if _app_state(cls.admin, "Splunk_SA_CIM") is not None:
            raise unittest.SkipTest("Splunk_SA_CIM is installed: readiness resolves the native Authentication model, "
                                    "so the stand-in model mapping this test relies on is never consulted")
        for name, constraint in ((cls.YES, "index=_internal"), (cls.NO, "index=_internal sourcetype=sun_live_no_such_sourcetype")):
            status, content = cls.admin.request("POST", "/servicesNS/nobody/search/data/models", None, None,
                                                form={"name": name, "eai:data": cls.model_json(name, constraint)})
            assert status in (200, 201), (status, content[:300])
        status, body = api(cls.admin, "POST", "import",
                           raw=json.dumps(helpers.fixture_bundle(record_ids=["9.1.1"])).encode("utf-8"))
        assert status == 200, body
        cls.mapped = []

    @classmethod
    def tearDownClass(cls):
        for value in list(cls.mapped):
            api(cls.admin, "POST", "mappings/delete", body={"kind": "datamodel", "value": value})
        for name in (cls.YES, cls.NO):
            cls.admin.request("DELETE", "/servicesNS/nobody/search/data/models/" + name)

    def map(self, value, canonical="Authentication"):
        status, body = api(self.admin, "POST", "mappings", body={"kind": "datamodel", "value": value,
                                                                  "canonical_value": canonical, "notes": "live test"})
        self.assertEqual(status, 200, body)
        self.mapped.append(value)

    def unmap(self, value):
        status, body = api(self.admin, "POST", "mappings/delete", body={"kind": "datamodel", "value": value})
        self.assertEqual(status, 200, body)
        self.mapped.remove(value)

    def model_doc(self, name):
        status, inv = api(self.admin, "GET", "inventory", {"kind": "datamodel", "q": name})
        self.assertEqual(status, 200, inv)
        docs = [i for i in inv["items"] if i["name"] == name]
        self.assertEqual(len(docs), 1, inv)
        return docs[0]

    def cim_result(self):
        status, doc = api(self.admin, "POST", "readiness/assess", body={"id": "fenre:UC-9.1.1"})
        self.assertEqual(status, 200, doc)
        rows = [r for r in doc["results"] if r["type"] == "cim_model"]
        self.assertEqual(len(rows), 1, rows)
        return doc, rows[0]

    def test_populated_yes_no_unverified_and_readiness_unchanged(self):
        self.map(self.YES)
        self.map(self.NO)
        job = _wait_discovery(self.admin, include_internal=True, earliest="-15m")
        self.assertEqual(job["status"], "succeeded", job)
        pop = job["totals"]["populated"]
        self.assertTrue(pop["enabled"])
        self.assertEqual(pop["models"], pop["yes"] + pop["no"] + pop["unverified"])
        yes, no = self.model_doc(self.YES), self.model_doc(self.NO)
        self.assertEqual(yes["populated"], "yes", yes)
        self.assertGreater(yes["populated_count"], 0)
        self.assertEqual((no["populated"], no["populated_count"]), ("no", 0), no)
        self.assertEqual(yes["populated_window"], "-24h")
        status, inv = api(self.admin, "GET", "inventory", {"kind": "datamodel", "q": "internal_server"})
        reasons = {i["name"]: (i["populated"], i["populated_reason"]) for i in inv["items"]}
        self.assertEqual(reasons.get("internal_server"), ("unverified", "not_referenced"), reasons)

        self.unmap(self.NO)
        doc_yes, res_yes = self.cim_result()
        self.assertEqual((res_yes["status"], res_yes["code"], res_yes["populated"]), ("met", "model_present", "yes"), res_yes)
        self.assertEqual(res_yes["via_mapping"]["value"], self.YES)
        self.map(self.NO)
        self.unmap(self.YES)
        doc_no, res_no = self.cim_result()
        self.assertEqual((res_no["status"], res_no["code"], res_no["populated"]), ("partial", "model_empty", "no"), res_no)
        self.assertLess(doc_no["score"], doc_yes["score"])

    @unittest.skipUnless(os.environ.get("UCM_LIVE_CONF_WRITE") == "1",
                         "set UCM_LIVE_CONF_WRITE=1: the test leaves a local [discovery] populated_check line in local/ucm.conf")
    def test_setting_off_records_unverified_and_runs_no_check(self):
        old = conf_value(self.admin, "discovery", "populated_check")
        self.map(self.YES)
        set_conf_value(self.admin, "discovery", "populated_check", "false")
        try:
            job = _wait_discovery(self.admin, include_internal=True, earliest="-15m")
            self.assertEqual(job["status"], "succeeded", job)
            self.assertFalse(job["totals"]["populated"]["enabled"])
            doc = self.model_doc(self.YES)
            self.assertEqual((doc["populated"], doc["populated_reason"]), ("unverified", "check_disabled"), doc)
        finally:
            set_conf_value(self.admin, "discovery", "populated_check", old or "true")


class LiveDispatchHealthTest(unittest.TestCase):
    """D-069: a scheduled search Splunk refuses before it runs is reported as failing at dispatch."""

    NAME = "SUN - ucm_test_dispatch_" + uuid.uuid4().hex[:6]

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        status, body = cls.admin.request("POST", "/servicesNS/nobody/sunavigator/saved/searches", form={
            "name": cls.NAME, "search": "| makeresults | lookup ucm_test_no_such_lookup foo OUTPUT bar",
            "cron_schedule": "* * * * *", "is_scheduled": "1",
            "dispatch.earliest_time": "-1m", "dispatch.latest_time": "now"})
        assert status in (200, 201), (status, body[:300])

    @classmethod
    def tearDownClass(cls):
        cls.admin.request("DELETE", "/servicesNS/nobody/sunavigator/saved/searches/" + cls.NAME.replace(" ", "%20"))

    def test_missing_lookup_is_a_dispatch_failure(self):
        from splunk_ucm.frameworks.operations import HEALTH_SPL, advisories, classify
        spl = HEALTH_SPL + ' | search savedsearch_name="%s"' % self.NAME
        rows = []
        for _ in range(36):
            rows = oneshot(self.admin, spl, earliest="-15m")
            if rows and int(rows[0].get("dispatch_errors") or 0) > 0:
                break
            time.sleep(5)
        self.assertTrue(rows, "no scheduler log line within 3 minutes")
        row = rows[0]
        self.assertEqual(row.get("runs"), "0", row)
        self.assertIn("lookup", row.get("last_error", "").lower())
        self.assertEqual(classify(True, row), "failing_dispatch")
        self.assertEqual([f["code"] for f in advisories(row, "* * * * *")], ["H001"])


class LiveFieldProfileTest(unittest.TestCase):
    """D-070: the field-profile search runs on Splunk and returns rates, never values."""

    def test_profile_search_counts_filled_and_placeholder_events(self):
        from splunk_ucm.discovery.profile import profile_spl, parse_profile
        spl = profile_spl("_internal", "splunkd", ["log_level", "component"], ["-", "N/A"], 500)
        rows = SearchClient(transport()).oneshot(spl, timeout=60, max_count=1).rows
        self.assertEqual(len(rows), 1, rows)
        profiled = parse_profile(rows[0], ["log_level", "component"])
        self.assertTrue(profiled, rows)
        for item in profiled:
            self.assertGreater(item["sample_size"], 0)
            self.assertTrue(0 <= item["fill_rate"] <= 1 and 0 <= item["placeholder_rate"] <= 1, item)
        self.assertGreater(profiled[0]["fill_rate"], 0.5, profiled)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveEventCheckTest(unittest.TestCase):
    """D-073: the bounded event-type search runs on Splunk and answers with a capped count."""

    def hits(self, value):
        from splunk_ucm.discovery.events import event_spl
        spl = event_spl("_internal", "splunkd", "log_level", value, 1)
        rows = SearchClient(transport()).oneshot(spl, timeout=60, max_count=1).rows
        self.assertEqual(len(rows), 1, rows)
        return int(float(rows[0]["sun_hits"]))

    def test_event_type_that_exists_is_counted_and_capped(self):
        self.assertEqual(self.hits("INFO"), 100)

    def test_event_type_that_never_occurs_is_zero(self):
        self.assertEqual(self.hits("NOSUCHLEVELXYZ"), 0)

    def test_discovery_passes_run_through_the_real_search_client(self):
        """The leading-pipe rule of SearchClient.oneshot once made both passes count only errors."""
        from unittest import mock
        from splunk_ucm.discovery import events, profile
        from splunk_ucm.storage.kvstore import InMemoryStore
        store = InMemoryStore()
        store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "p", "kind": "pair", "status": "active", "index": "_internal",
                                             "sourcetype": "splunkd", "window_count": 10})
        client = SearchClient(transport())
        triples = [(("splunkd", "log_level", "INFO"), 1), (("splunkd", "log_level", "NOSUCHLEVELXYZ"), 1)]
        with mock.patch.object(events, "targets", return_value=triples):
            summary = events.run_event_checks(store, client, None, events.EventCheckSettings(), "j", 1)
        self.assertEqual((summary["checked"], summary["seen"], summary["not_seen"], summary["errors"]), (2, 1, 1, 0), summary)
        wanted = {"splunkd": {"fields": {"log_level", "component"}}}
        with mock.patch.object(profile, "targets", return_value=wanted):
            summary = profile.run_profile(store, client, None, profile.ProfileSettings(), "j")
        self.assertEqual((summary["sourcetypes"], summary["errors"]), (1, 0), summary)
        self.assertGreater(store.query(C.FIELD_PROFILE, {"field": "log_level"})[0]["fill_rate"], 0.5)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveExternalMatchTest(unittest.TestCase):
    """D-074: a saved search in another app is found by the hash of its text, matched, accepted and counted."""

    NAME = "SUN live external " + uuid.uuid4().hex[:6]
    APP = "DA-ESS-ContentUpdate"
    SAVED = "/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches"

    @classmethod
    def setUpClass(cls):
        from urllib.parse import quote
        cls.admin = transport()
        if _app_state(cls.admin, cls.APP) is None:
            raise unittest.SkipTest("ESCU (DA-ESS-ContentUpdate) is not installed on this Splunk instance")
        cls.kv = KVStore(cls.admin)
        rows = [r for r in cls.kv.query(C.CATALOG, {"provider": "escu", "provider_status": "active"}, limit=300)
                if r.get("spl_hash") and r.get("mitre_ids")]
        assert rows, "import the ESCU bundle first"
        from splunk_ucm.catalog.quality import spl_hash
        cls.row = None
        for row in rows[:40]:
            status, body = api(cls.admin, "GET", "usecase", {"id": row["content_id"]})
            if status == 200 and body.get("spl") and "`" not in body["spl"]:
                cls.row = row
                break
        assert cls.row, "no use case without macros to copy; the lab has no macro definitions"
        assert spl_hash(body["spl"]) == cls.row["spl_hash"], "catalogue hash is not the hash of the displayed SPL"
        status, _ = cls.admin.request("POST", cls.SAVED, form={"name": cls.NAME, "search": body["spl"], "disabled": "0"})
        assert status in (200, 201), status
        cls.quote = quote

    @classmethod
    def tearDownClass(cls):
        from splunk_ucm.discovery.external import external_key
        cls.admin.request("DELETE", cls.SAVED + "/" + cls.quote(cls.NAME, safe=""))
        cls.kv.delete(C.EXTERNAL_MATCHES, external_key(cls.APP, cls.NAME))

    def test_hash_match_is_proposed_accepted_and_counted_without_changing_levels(self):
        from splunk_ucm.discovery.external import ExternalSettings, external_key, run_external
        from splunk_ucm.discovery.inventory import SplunkInventory
        summary = run_external(self.kv, SplunkInventory(self.admin), ExternalSettings(), "live")
        self.assertTrue(summary["available"] and summary["listed"] >= 1 and summary["matched"] >= 1, summary)
        key = external_key(self.APP, self.NAME)
        doc = self.kv.get(C.EXTERNAL_MATCHES, key)
        self.assertEqual(doc["state"], "proposed", doc)
        self.assertTrue(doc["enabled"], doc)
        self.assertIn(("spl_hash", self.row["_key"]), [(c["basis"], c["content_key"]) for c in doc["candidates"]])
        self.assertNotIn("search", doc)
        status, body = api(self.admin, "GET", "external", {"state": "proposed", "count": "200"})
        self.assertEqual(status, 200, body)
        self.assertIn(key, [i["_key"] for i in body["items"]])
        status, body = api(self.admin, "POST", "external", body={"id": key, "decision": "accept",
                                                                  "content_key": self.row["_key"]})
        self.assertEqual((status, body["match"]["state"]), (200, "accepted"), body)
        status, uc = api(self.admin, "GET", "usecase", {"id": self.row["content_id"]})
        self.assertEqual(uc["external"]["enabled"], 1, uc["external"])
        self.assertEqual([m["name"] for m in uc["external"]["matches"]], [self.NAME])
        status, matrix = api(self.admin, "GET", "frameworks/matrix")
        self.assertEqual(status, 200, matrix)
        self.assertGreaterEqual(matrix["totals"]["elsewhere"], 1)
        status, body = api(self.admin, "POST", "external", body={"id": key, "decision": "reset"})
        self.assertEqual(body["match"]["state"], "proposed")
        self.assertEqual(api(self.admin, "GET", "external", {"state": "bogus"})[0], 400)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveActionsTest(unittest.TestCase):
    """D-072: email and webhook actions are drafted, approved with an acknowledgment, written disabled and verified."""

    OPERATOR = "ucm_test_actions_" + uuid.uuid4().hex[:6]
    OPERATOR_PW = "T3st!" + uuid.uuid4().hex
    UC = "fenre:UC-9.1.2"
    SAVED = "/servicesNS/nobody/sunavigator/saved/searches/"
    KEYS = {"email_domains": "example.com", "webhook_hosts": "hooks.example.com"}

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.before = {k: conf_value(cls.admin, "actions", k) for k in cls.KEYS}
        for key, value in cls.KEYS.items():
            set_conf_value(cls.admin, "actions", key, value)
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
        from urllib.parse import quote
        doc = cls.kv.get(C.DEPLOYMENTS, "dep_fenre_UC-9.1.2")
        if doc:
            cls.admin.request("DELETE", cls.SAVED + quote(doc["saved_search"]["name"], safe=""))
            cls.kv.delete(C.DEPLOYMENTS, "dep_fenre_UC-9.1.2")
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.OPERATOR)
        for key, value in cls.before.items():
            set_conf_value(cls.admin, "actions", key, value)

    def act(self, who, action, **body):
        body["id"] = self.UC
        return api(who, "POST", "deployment/" + action, body=body)

    def saved(self, name):
        from urllib.parse import quote
        status, content = self.admin.request("GET", self.SAVED + quote(name, safe=""), {"output_mode": "json"})
        return json.loads(content)["entry"][0]["content"] if status == 200 else None

    def test_actions_round_trip_through_splunk(self):
        actions = {"email": {"to": "soc@example.com, lead@example.com", "subject": "Alert $name$", "message": "Check it"},
                   "webhook": {"url": "https://hooks.example.com/services/T1/B2/token"}}
        status, body = self.act(self.operator, "draft", suppress_period="1h", actions={"email": {"to": "x@evil.test"}})
        self.assertEqual(status, 400, body)
        status, body = self.act(self.operator, "draft", actions=actions)
        self.assertEqual(status, 400, body)
        status, body = self.act(self.operator, "draft", suppress_period="1h", actions=actions)
        self.assertEqual(status, 200, body)
        name = body["deployment"]["saved_search"]["name"]
        self.assertEqual(body["deployment"]["notify"], ["email", "webhook"])
        self.assertEqual(self.act(self.operator, "submit")[0], 200)
        status, body = self.act(self.admin, "approve")
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["details"]["code"], "actions_acknowledgment_required")
        status, body = self.act(self.admin, "approve", acknowledge_actions=True)
        self.assertEqual(status, 200, body)
        status, body = self.act(self.operator, "deploy")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["live"]["drift"], [])
        live = self.saved(name)
        self.assertTrue(live["disabled"])
        self.assertEqual([a.strip() for a in live["actions"].split(",")], ["email", "webhook"])
        self.assertEqual(live["action.email.to"], "soc@example.com,lead@example.com")
        self.assertEqual(live["action.webhook.param.url"], actions["webhook"]["url"])
        self.assertIn(str(live["action.email.sendresults"]).lower(), ("0", "false"))
        from urllib.parse import quote
        self.admin.request("POST", self.SAVED + quote(name, safe=""), form={"action.email.to": "someone@example.com"})
        status, body = self.act(self.operator, "verify")
        self.assertEqual([d["field"] for d in body["deployment"]["live"]["drift"]], ["action.email.to"])
        status, bundle = api(self.operator, "GET", "deployments/export")
        entry = [e for e in bundle["manifest"]["entries"] if e["saved_search"] == name][0]
        self.assertEqual(entry["actions"]["webhook"], {"host": "hooks.example.com"})
        self.assertNotIn("token", json.dumps(entry))
        self.act(self.operator, "draft", suppress_period="1h")
        self.act(self.operator, "submit")
        self.act(self.admin, "approve")
        status, body = self.act(self.operator, "deploy")
        self.assertEqual(status, 200, body)
        live = self.saved(name)
        self.assertEqual(live["actions"], "", live)
        self.assertEqual([str(live["action.email"]).lower(), str(live["action.webhook"]).lower()].count("true"), 0, live)
        self.assertEqual(body["deployment"]["live"]["drift"], [])
        self.act(self.operator, "retire")


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveLifecycleRefinementsTest(unittest.TestCase):
    """D-075: the audit chain verifies on the real KV Store; withdraw, outcome and revision diff round-trip."""

    OPERATOR = "ucm_test_life_" + uuid.uuid4().hex[:6]
    OPERATOR_PW = "T3st!" + uuid.uuid4().hex
    UC = "fenre:UC-9.1.2"
    KEY = "dep_fenre_UC-9.1.2"
    SAVED = "/servicesNS/nobody/sunavigator/saved/searches/"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.kv = KVStore(cls.admin)
        status, _ = cls.admin.request("POST", "/services/authentication/users",
                                      form={"name": cls.OPERATOR, "password": cls.OPERATOR_PW, "roles": "ucm_deployment_operator"})
        assert status in (200, 201), status
        cls.operator = transport(cls.OPERATOR, cls.OPERATOR_PW)
        status, body = api(cls.admin, "POST", "import", raw=json.dumps(helpers.fixture_bundle(record_ids=["9.1.2"])).encode("utf-8"))
        assert status == 200, body
        cls.kv.delete(C.DEPLOYMENTS, cls.KEY)

    @classmethod
    def tearDownClass(cls):
        from urllib.parse import quote
        doc = cls.kv.get(C.DEPLOYMENTS, cls.KEY)
        if doc:
            cls.admin.request("DELETE", cls.SAVED + quote(doc["saved_search"]["name"], safe=""))
            cls.kv.delete(C.DEPLOYMENTS, cls.KEY)
        cls.admin.request("DELETE", "/services/authentication/users/" + cls.OPERATOR)

    def act(self, who, action, **body):
        body["id"] = self.UC
        return api(who, "POST", "deployment/" + action, body=body)

    def test_audit_chain_survives_the_real_kv_store(self):
        status, before = api(self.admin, "POST", "audit/verify")
        self.assertEqual(status, 200, before)
        self.assertTrue(before["ok"], before)
        self.assertEqual(api(self.operator, "POST", "audit/verify")[0], 403)
        self.act(self.operator, "draft")
        status, after = api(self.admin, "POST", "audit/verify")
        self.assertTrue(after["ok"], after)
        self.assertEqual(after["modified_count"], 0, after)
        self.assertGreater(after["chained"], before["chained"], (before, after))
        self.assertTrue(after["head"] and after["head"] != before["head"])

    def test_withdraw_outcome_and_revision_diff(self):
        self.assertEqual(self.act(self.operator, "draft")[0], 200)
        self.assertEqual(self.act(self.operator, "submit")[0], 200)
        status, body = self.act(self.admin, "withdraw", note="x")
        self.assertEqual(status, 409, body)
        self.assertEqual(self.act(self.admin, "approve")[0], 200)
        status, body = self.act(self.admin, "withdraw", note="wrong cron, redo")
        self.assertEqual((status, body["deployment"]["state"]), (200, "pending_approval"), body)
        self.assertEqual(self.act(self.operator, "deploy")[0], 409)
        self.assertEqual(self.act(self.admin, "approve")[0], 200)
        status, body = self.act(self.operator, "deploy")
        self.assertEqual(status, 200, body)
        status, body = self.act(self.operator, "outcome", outcome="needs_tuning")
        self.assertEqual(status, 400, body)
        status, body = self.act(self.operator, "outcome", outcome="needs_tuning", note="fires on every admin login")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["deployment"]["outcome"]["value"], "needs_tuning")
        status, listed = api(self.admin, "GET", "deployments", {"outcome": "needs_tuning", "summary": "1"})
        self.assertIn(self.UC, [i["content_id"] for i in listed["items"]])
        self.assertGreaterEqual(listed["summary"]["pipeline"]["needs_tuning"], 1)
        status, body = self.act(self.operator, "draft", cron="17 * * * *")
        self.assertEqual(status, 200, body)
        revs = [r["rev"] for r in body["deployment"]["revisions"]]
        self.assertGreaterEqual(len(revs), 2, revs)
        status, diff = api(self.operator, "GET", "deployment/diff", {"id": self.UC, "from": str(revs[-2]), "to": str(revs[-1])})
        self.assertEqual(status, 200, diff)
        self.assertTrue(diff["available"], diff)
        self.assertIn("cron", [f["field"] for f in diff["fields"]])
        status, verify = api(self.admin, "POST", "audit/verify")
        self.assertTrue(verify["ok"], verify)
        self.act(self.operator, "retire")


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveControlCatalogueTest(unittest.TestCase):
    """D-076: bundled NIST catalogues are served from the installed app; an imported v2 definition round-trips the KV Store."""

    FW = "ucm-live-catalogue"

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.kv = KVStore(cls.admin)

    @classmethod
    def tearDownClass(cls):
        from splunk_ucm.frameworks.registry import definition_key
        from splunk_ucm.util import safe_key
        for version in ("98", "99"):
            cls.kv.delete(C.FRAMEWORKS, definition_key(cls.FW, version))
        cls.kv.delete(C.FRAMEWORKS, safe_key("active", cls.FW))

    def test_bundled_catalogues_are_installed_and_served(self):
        status, body = api(self.admin, "GET", "frameworks")
        self.assertEqual(status, 200, body)
        controls = {d["framework_id"]: d for d in body["definitions"] if d.get("kind") == "controls"}
        self.assertTrue({"nist-800-53", "nist-800-171", "nist-csf"} <= set(controls), list(controls))
        for fw, minimum in (("nist-800-53", 700), ("nist-800-171", 90), ("nist-csf", 100)):
            status, cat = api(self.admin, "GET", "frameworks/catalogue", {"framework_id": fw})
            self.assertEqual(status, 200, cat)
            self.assertGreaterEqual(cat["totals"]["controls"], minimum, cat["totals"])
            self.assertEqual(cat["totals"]["mapped"] + cat["totals"]["unmapped"], cat["totals"]["controls"])
            self.assertIn("NIST", cat["catalogue"]["attribution"])
        self.assertEqual(api(self.admin, "GET", "frameworks/matrix", {"framework_id": "nist-csf"})[0], 400)

    def test_imported_definition_round_trips_and_orders_by_sort_key(self):
        def definition(label, key):
            return {"format": "ucm.framework/2", "kind": "controls", "framework_id": self.FW, "framework": "Live", "name": "Live catalogue",
                    "regulation_ids": ["ucm-live"], "version_label": label, "sort_key": key, "match": "exact",
                    "controls": [{"id": "A", "title": "Family A", "parent": None, "kind": "family"},
                                 {"id": "A.1", "title": "First", "parent": "A", "kind": "control"}]}
        for label, key in (("Edition ten", [99]), ("Edition nine", [98])):
            status, body = api(self.admin, "POST", "frameworks/import", raw=json.dumps(definition(label, key)).encode("utf-8"))
            self.assertEqual(status, 200, body)
        status, body = api(self.admin, "GET", "frameworks/catalogue", {"framework_id": self.FW})
        self.assertEqual((status, body["catalogue"]["version_label"], body["active_version"]), (200, "Edition ten", "99"), body)
        self.assertEqual([v["label"] for v in body["versions"]], ["Edition nine", "Edition ten"])
        self.assertEqual(body["totals"]["unmapped"], 1)
        status, body = api(self.admin, "POST", "frameworks/activate", body={"framework_id": self.FW, "version": "98"})
        self.assertEqual(status, 200, body)
        status, body = api(self.admin, "GET", "frameworks/catalogue", {"framework_id": self.FW})
        self.assertEqual(body["catalogue"]["version_label"], "Edition nine")


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveAssessmentTest(unittest.TestCase):
    """D-077: assessments, POA&M and snapshots on the real KV Store, behind the ucm_assess capability."""

    USER = "ucm_test_assessor_" + uuid.uuid4().hex[:6]
    VIEWER = "ucm_test_viewer_" + uuid.uuid4().hex[:6]
    PW = "T3st!" + uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.kv = KVStore(cls.admin)
        cls.created = {C.ASSESSMENTS: [], C.POAM: [], C.SNAPSHOTS: []}
        for name, role in ((cls.USER, "ucm_compliance_assessor"), (cls.VIEWER, "ucm_viewer")):
            status, body = cls.admin.request("POST", "/services/authentication/users",
                                             form={"name": name, "password": cls.PW, "roles": role})
            assert status in (200, 201), (status, body[:300])
        cls.assessor = transport(cls.USER, cls.PW)
        cls.viewer = transport(cls.VIEWER, cls.PW)

    @classmethod
    def tearDownClass(cls):
        from splunk_ucm.frameworks.assessment import assessment_key
        for fw, control in getattr(cls, "assessed", []):
            cls.kv.delete(C.ASSESSMENTS, assessment_key(fw, control))
        for collection, keys in cls.created.items():
            for key in keys:
                cls.kv.delete(collection, key)
        for name in (cls.USER, cls.VIEWER):
            cls.admin.request("DELETE", "/services/authentication/users/" + name)

    assessed = []

    def objective_control(self):
        status, cat = api(self.admin, "GET", "frameworks/catalogue", {"framework_id": "nist-800-171"})
        self.assertEqual(status, 200, cat)
        return next(r for r in cat["controls"] if r.get("objective_count"))

    def test_capability_and_roles_are_installed(self):
        status, content = self.admin.request("GET", "/services/authorization/roles/ucm_compliance_assessor", {"output_mode": "json"})
        self.assertEqual(status, 200)
        self.assertIn("ucm_assess", json.loads(content)["entry"][0]["content"]["capabilities"])
        for t in (self.viewer,):
            for path in ("assessment", "poam", "assessment/snapshots"):
                self.assertEqual(api(t, "GET", path, {"framework_id": "cmmc-l2"})[0], 403, path)
            self.assertEqual(api(t, "POST", "assessment", body={"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.1"})[0], 403)
        self.assertEqual(api(self.assessor, "GET", "assessment", {"framework_id": "cmmc-l2"})[0], 200)

    def test_cmmc_score_starts_at_the_methodology_floor_and_rises(self):
        status, body = api(self.assessor, "GET", "assessment", {"framework_id": "cmmc-l2"})
        self.assertEqual(status, 200, body)
        score = body["score"]
        self.assertEqual((score["start"], score["points_lost"] + score["score"]), (110, 110), score)
        self.assertEqual(score["all_assessed"], score["complete"])
        self.assertIn("can_pass", score)
        before = score["score"]
        status, out = api(self.assessor, "POST", "assessment", body={"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.1",
                                                                  "status": "implemented", "note": "Live test: verified"})
        self.assertEqual(status, 200, out)
        LiveAssessmentTest.assessed.append(("cmmc-l2", "AC.L2-3.1.1"))
        self.assertGreater(out["score"]["score"], before)
        self.assertEqual(out["assessment"]["assessed_by"], self.USER)
        status, out = api(self.assessor, "POST", "assessment/clear", body={"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.1", "note": "Live test: done"})
        self.assertEqual(status, 200, out)
        self.assertEqual(out["score"]["score"], before)

    def test_objective_results_round_trip_with_dotted_ids_and_derive_the_status(self):
        row = self.objective_control()
        status, res = api(self.assessor, "GET", "assessment/control", {"framework_id": "nist-800-171", "control_id": row["id"]})
        self.assertEqual(status, 200, res)
        ids = [o["id"] for o in res["control"]["objectives"]]
        self.assertGreater(len(ids), 0)
        self.assertTrue(any("." in i for i in ids), ids)
        LiveAssessmentTest.assessed.append(("nist-800-171", row["id"]))
        status, out = api(self.assessor, "POST", "assessment", body={
            "framework_id": "nist-800-171", "control_id": row["id"], "note": "Live test: all met",
            "objectives": {i: {"result": "met", "note": ""} for i in ids}})
        self.assertEqual(status, 200, out)
        self.assertEqual((out["assessment"]["status"], out["assessment"]["complete"]), ("implemented", True))
        status, out = api(self.assessor, "POST", "assessment", body={
            "framework_id": "nist-800-171", "control_id": row["id"], "note": "Live test: one fails",
            "objectives": {ids[0]: {"result": "not_met", "note": ""}}})
        self.assertEqual((out["assessment"]["status"], out["assessment"]["complete"]), ("partially_implemented", True), out)
        self.assertEqual([h["status"] for h in out["assessment"]["history"]], ["implemented"])
        status, stored = api(self.assessor, "GET", "assessment/control", {"framework_id": "nist-800-171", "control_id": row["id"]})
        self.assertEqual(stored["assessment"]["objectives"][ids[0]]["result"], "not_met")
        self.assertEqual(stored["assessment"]["first_assessed_by"], self.USER)
        status, out = api(self.assessor, "POST", "assessment", body={
            "framework_id": "nist-800-171", "control_id": row["id"], "note": "ok", "objectives": {ids[0]: {"result": "not_applicable", "note": ""}}})
        self.assertEqual(status, 400, out)

    def test_poam_lifecycle_and_overdue(self):
        status, out = api(self.assessor, "POST", "poam", body={
            "framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.2", "title": "Live plan", "weakness": "Live test weakness", "owner": "bob",
            "due": "2020-01-01", "milestones": [{"text": "First step", "due": "2019-12-01"}]})
        self.assertEqual(status, 200, out)
        item = out["item"]
        self.created[C.POAM].append(item["id"])
        self.assertTrue(item["overdue"])
        status, listing = api(self.assessor, "GET", "poam", {"framework_id": "cmmc-l2", "overdue": "1"})
        self.assertIn(item["id"], [i["id"] for i in listing["items"]])
        self.assertFalse(item["eligibility"]["eligible"], item["eligibility"])
        self.assertEqual(item["eligibility"]["point_value"], 5)
        self.assertIn("not a CMMC status", item["eligibility"]["notice"])
        status, out = api(self.assessor, "POST", "poam", body={
            "framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.20", "title": "Excluded", "weakness": "Live test weakness",
            "owner": "bob", "due": "2031-01-01"})
        self.assertEqual(status, 200, out)
        self.created[C.POAM].append(out["item"]["id"])
        self.assertIn("excluded", " ".join(out["item"]["eligibility"]["reasons"]))
        self.assertEqual(api(self.assessor, "POST", "poam/update", body={"id": item["id"], "due": "2031-01-01"})[0], 400)
        status, out = api(self.assessor, "POST", "poam/update", body={"id": item["id"], "due": "2031-01-01", "note": "Vendor delay"})
        self.assertEqual((status, out["item"]["overdue"]), (200, False), out)
        self.assertEqual(api(self.assessor, "POST", "poam/close", body={"id": item["id"], "resolution": "risk_accepted", "note": "short"})[0], 400)
        status, out = api(self.assessor, "POST", "poam/close", body={"id": item["id"], "resolution": "closed", "note": "Done and tested"})
        self.assertEqual((status, out["item"]["state"]), (200, "closed"), out)
        status, out = api(self.assessor, "POST", "poam/reopen", body={"id": item["id"], "note": "Regression found"})
        self.assertEqual((status, out["item"]["state"]), (200, "open"), out)
        self.assertEqual([h["action"] for h in out["item"]["history"]], ["created", "updated", "closed", "reopened"])

    def refused_rows(self, prefix="refused."):
        _, audit = api(self.admin, "GET", "audit", {"prefix": prefix, "limit": "200"})
        return [e for e in audit["events"] if e["actor"] == self.VIEWER]

    def test_refusals_are_audited_once_and_capped(self):
        body = {"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.1", "status": "implemented", "note": "Live test: no right"}
        for _ in range(3):
            self.assertEqual(api(self.viewer, "POST", "assessment", body=body)[0], 403)
        rows = self.refused_rows()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual((rows[0]["outcome"], rows[0]["details"]["status"], rows[0]["object_id"]), ("refused", 403, "AC.L2-3.1.1"), rows[0])
        self.assertNotIn("Live test: no right", json.dumps(rows[0]))
        for n in range(30):
            api(self.viewer, "POST", "poam", body={"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.%d" % (n + 100)})
        rows = self.refused_rows()
        limited = [r for r in rows if r["action"] == "refused.rate_limited"]
        self.assertEqual(len(limited), 1, [r["action"] for r in rows])
        self.assertEqual(len(rows), 21, len(rows))
        self.assertEqual(limited[0]["details"]["scope"], "actor")
        status, out = api(self.admin, "POST", "audit/verify")
        self.assertTrue(out["ok"], out)

    def test_snapshot_is_stored_hashed_and_verifiable(self):
        status, out = api(self.assessor, "POST", "assessment/snapshot", body={"framework_id": "cmmc-l2", "label": "Live snapshot"})
        self.assertEqual(status, 200, out)
        snap = out["snapshot"]
        self.created[C.SNAPSHOTS].append(snap["id"])
        status, got = api(self.assessor, "GET", "assessment/snapshot", {"id": snap["id"]})
        self.assertEqual(status, 200, got)
        self.assertTrue(got["integrity"]["ok"], got["integrity"])
        self.assertEqual(hashlib.sha256(got["content"].encode("utf-8")).hexdigest(), snap["sha256"])
        content = json.loads(got["content"])
        self.assertEqual((content["format"], content["created_by"], content["label"]), ("ucm.assessment.snapshot/1", self.USER, "Live snapshot"))
        status, listing = api(self.assessor, "GET", "assessment/snapshots", {"framework_id": "cmmc-l2"})
        self.assertIn(snap["id"], [s["id"] for s in listing["items"]])

    def test_audit_chain_is_intact_after_all_assessment_writes(self):
        status, out = api(self.admin, "POST", "audit/verify")
        self.assertEqual(status, 200, out)
        self.assertTrue(out["ok"], out)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveCollectionAclTest(unittest.TestCase):
    """0.12.2: the collections that only the app writes are not readable through the KV Store REST by ordinary roles."""

    ANALYST = "ucm_acl_analyst_" + uuid.uuid4().hex[:6]
    ASSESSOR = "ucm_acl_assessor_" + uuid.uuid4().hex[:6]
    VIEWER = "ucm_acl_viewer_" + uuid.uuid4().hex[:6]
    PW = "T3st!" + uuid.uuid4().hex
    KV = "/servicesNS/nobody/sunavigator/storage/collections/data/"
    # Splunk answers 404 for an object the role may not see, 403 where it knows the object and refuses.

    @classmethod
    def setUpClass(cls):
        cls.admin = transport()
        cls.users = {}
        for name, role in ((cls.ANALYST, "ucm_analyst"), (cls.ASSESSOR, "ucm_compliance_assessor"), (cls.VIEWER, "ucm_viewer")):
            status, _ = cls.admin.request("POST", "/services/authentication/users",
                                          form={"name": name, "password": cls.PW, "roles": role})
            assert status in (200, 201), status
            cls.users[role] = transport(name, cls.PW)

    @classmethod
    def tearDownClass(cls):
        for name in (cls.ANALYST, cls.ASSESSOR, cls.VIEWER):
            cls.admin.request("DELETE", "/services/authentication/users/" + name)

    def kv_status(self, t, collection):
        status, _ = t.request("GET", self.KV + collection, {"output_mode": "json", "limit": "1"})
        return status

    def test_app_written_collections_are_closed_to_ordinary_roles(self):
        for collection in ("uc_field_profile", "uc_event_check", "uc_external_matches"):
            self.assertEqual(self.kv_status(self.admin, collection), 200, collection)
            for role, t in self.users.items():
                self.assertIn(self.kv_status(t, collection), (403, 404), "%s read by %s" % (collection, role))

    def test_assessment_collections_are_open_to_assessors_only(self):
        for collection in ("uc_assessments", "uc_poam", "uc_assessment_snapshots"):
            self.assertEqual(self.kv_status(self.admin, collection), 200, collection)
            self.assertEqual(self.kv_status(self.users["ucm_compliance_assessor"], collection), 200, collection)
            for role in ("ucm_viewer", "ucm_analyst"):
                self.assertIn(self.kv_status(self.users[role], collection), (403, 404), "%s read by %s" % (collection, role))

    def test_the_api_still_serves_what_the_collections_hold(self):
        status, body = api(self.users["ucm_analyst"], "GET", "external")
        self.assertEqual(status, 200, body)
        status, body = api(self.users["ucm_viewer"], "GET", "external")
        self.assertEqual(status, 403, body)
        status, body = api(self.users["ucm_compliance_assessor"], "GET", "assessment", {"framework_id": "cmmc-l2"})
        self.assertEqual(status, 200, body)


@unittest.skipUnless(LIVE, "set UCM_LIVE_SPLUNK=1 to run against a real Splunk instance")
class LiveBackgroundReindexTest(unittest.TestCase):
    """0.12.2 (#25): Reindex runs in the worker; the request returns at once and a second one is refused while it runs."""

    def test_reindex_runs_in_the_background(self):
        admin = transport()
        deadline = time.time() + 120
        while time.time() < deadline:
            _, cur = api(admin, "GET", "catalog/reindex")
            if not cur["job"] or cur["job"]["status"] in ("succeeded", "failed"):
                break
            time.sleep(3)
        started = time.time()
        status, body = api(admin, "POST", "catalog/reindex", body={}, query={"background": "1"})
        self.assertEqual(status, 200, body)
        self.assertLess(time.time() - started, 10, "the request must not wait for the reindex")
        self.assertIn(body["job"]["status"], ("queued", "running"))
        status, again = api(admin, "POST", "catalog/reindex", body={}, query={"background": "1"})
        self.assertEqual(status, 409, again)
        job = body["job"]
        deadline = time.time() + 240
        while time.time() < deadline:
            _, cur = api(admin, "GET", "catalog/reindex")
            job = cur["job"]
            if job["status"] in ("succeeded", "failed"):
                break
            time.sleep(5)
        self.assertEqual(job["status"], "succeeded", job)

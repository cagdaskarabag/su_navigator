import datetime
import os
import re
import unittest

import helpers  # noqa: F401

from splunk_ucm.api.app import CAP_RUN_DISCOVERY
from splunk_ucm.audit import AuditService
from splunk_ucm.config import AppConfig
from splunk_ucm.discovery.service import DiscoveryService, new_job as new_djob
from splunk_ucm.errors import ValidationError
from splunk_ucm.readiness.evaluators import (MET, NOT_MET, PARTIAL, STATUSES, UNKNOWN, UNVERIFIED,
                                             EvaluationSettings, evaluate)
from splunk_ucm.readiness.query import ReadinessFilter, ReadinessQueryService
from splunk_ucm.readiness.scoring import STATES, ScoringSettings, score
from splunk_ucm.readiness.service import ReadinessService, new_job
from splunk_ucm.readiness.snapshot import EnvironmentSnapshot
from splunk_ucm.readiness.worker import ReadinessWorker
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import APPS, INDEXES, MODELS, ROWS, FakeInventory, FakeSearch, loaded_catalog

SETTINGS = EvaluationSettings(stale_hours=24)


def snap(sources=(), mappings=(), state=None):
    return EnvironmentSnapshot(list(sources), list(mappings),
                               state or {"last_completed_at": "2026-11-20T09:00:00Z", "splunk_version": "10.2.9",
                                         "earliest": "-7d", "latest": "now"})


def pair(index, st, count=10, age=60, status="active"):
    return {"kind": "pair", "index": index, "sourcetype": st, "window_count": count,
            "age_seconds": age, "status": status}


def req(type_, value, level="required", confidence="high", **attrs):
    return {"req_id": "%s:%s" % (type_, value), "type": type_, "value": value, "level": level,
            "source": "provider_structured", "confidence": confidence, "attributes": attrs}


class EvaluatorTest(unittest.TestCase):
    def test_sourcetype_present_stale_missing_and_wildcard(self):
        s = snap([pair("win", "WinEventLog:Security", age=120),
                  pair("fw", "pan:traffic", age=3 * 86400),
                  pair("old", "cisco:asa", status="missing")])
        self.assertEqual(evaluate(req("sourcetype", "wineventlog:security"), s, SETTINGS)["status"], MET)
        self.assertEqual(evaluate(req("sourcetype", "pan:traffic"), s, SETTINGS)["code"], "stale")
        self.assertEqual(evaluate(req("sourcetype", "pan:traffic"), s, SETTINGS)["status"], PARTIAL)
        self.assertEqual(evaluate(req("sourcetype", "cisco:asa"), s, SETTINGS)["code"], "no_longer_seen")
        self.assertEqual(evaluate(req("sourcetype", "nope"), s, SETTINGS)["code"], "not_found")
        self.assertEqual(evaluate(req("sourcetype", "WinEventLog:*"), s, SETTINGS)["status"], MET)

    def test_sourcetype_via_local_mapping(self):
        s = snap([pair("win", "my:winsec")],
                 [{"kind": "sourcetype", "value": "my:winsec", "canonical_value": "WinEventLog:Security",
                   "origin": "local", "confidence": "high"}])
        out = evaluate(req("sourcetype", "WinEventLog:Security"), s, SETTINGS)
        self.assertEqual(out["status"], MET)
        self.assertEqual(out["via_mapping"]["origin"], "local")

    def test_datamodel_and_acceleration(self):
        s = snap([{"kind": "datamodel", "name": "Authentication", "status": "active", "accelerated": False}])
        self.assertEqual(evaluate(req("cim_model", "Authentication"), s, SETTINGS)["status"], MET)
        self.assertEqual(evaluate(req("datamodel_acceleration", "Authentication"), s, SETTINGS)["code"],
                         "not_accelerated")
        self.assertEqual(evaluate(req("cim_model", "Network_Traffic"), s, SETTINGS)["status"], NOT_MET)

    def test_addon_by_label_splunkbase_id_and_min_version(self):
        s = snap([{"kind": "app", "name": "Splunk_TA_nix", "label": "Splunk Add-on for Unix and Linux",
                   "version": "9.0.0", "status": "active"}])
        by_label = evaluate(req("addon", "Splunk Add-on for Unix and Linux"), s, SETTINGS)
        self.assertEqual(by_label["status"], MET)
        by_id = evaluate(req("addon", "Unix TA", splunkbase_id=833), s, SETTINGS)
        self.assertEqual(by_id["status"], MET)
        old = evaluate(req("addon", "Unix TA", splunkbase_id=833, min_version="10.2.0"), s, SETTINGS)
        self.assertEqual(old["code"], "version_below_minimum")
        self.assertEqual(evaluate(req("addon", "Other TA"), s, SETTINGS)["status"], NOT_MET)

    def test_addon_by_package_id_and_verified_splunkbase_map(self):
        s = snap([{"kind": "app", "name": "aws_renamed", "label": "AWS", "package_id": "Splunk_TA_aws",
                   "version": "7.0.0", "status": "active"},
                  {"kind": "app", "name": "docker_simple", "label": "Docker Simple", "status": "active"}])
        out = evaluate(req("addon", "Splunk Add-on for AWS", splunkbase_id=1876), s, SETTINGS)
        self.assertEqual((out["status"], out["observed"][0]["matched_by"]), (MET, "splunkbase_id"))
        self.assertEqual(evaluate(req("addon", "Splunk_TA_aws"), s, SETTINGS)["status"], MET)
        # Upstream records cite 4467 for Kubernetes; Splunkbase 4467 is Docker Simple.
        wrong = evaluate(req("addon", "Splunk Connect for Kubernetes", splunkbase_id=4467), s, SETTINGS)
        self.assertEqual(wrong["status"], NOT_MET)
        self.assertEqual(evaluate(req("addon", "x", splunkbase_id=True), s, SETTINGS)["status"], NOT_MET)

    def test_splunkbase_map_shape(self):
        from splunk_ucm.discovery.apps import SPLUNKBASE_APPS, package_id
        for sb, (pkg, title) in SPLUNKBASE_APPS.items():
            self.assertTrue(isinstance(sb, int) and pkg and title, sb)
            self.assertEqual(package_id("https://apps.splunk.com/apps/id/" + pkg), pkg)
        self.assertFalse({4413, 4467, 4800, 5018, 5680} & set(SPLUNKBASE_APPS))
        self.assertEqual(package_id("https://evil.example/apps/id/../x"), "")

    def test_product_alias(self):
        s = snap([{"kind": "app", "name": "SplunkEnterpriseSecuritySuite", "label": "Enterprise Security",
                   "status": "active"}])
        self.assertEqual(evaluate(req("product", "Splunk Enterprise Security"), s, SETTINGS)["status"], MET)

    def test_macro_and_lookup_sharing(self):
        s = snap([{"kind": "macro", "name": "sec_idx", "app": "TA", "sharing": "global", "status": "active"},
                  {"kind": "macro", "name": "local_only", "app": "search", "sharing": "app", "status": "active"},
                  {"kind": "lookup", "name": "assets.csv", "app": "x", "sharing": "global", "status": "active"}])
        self.assertEqual(evaluate(req("macro", "sec_idx"), s, SETTINGS)["status"], MET)
        self.assertEqual(evaluate(req("macro", "local_only"), s, SETTINGS)["code"], "app_scoped")
        self.assertEqual(evaluate(req("macro", "missing(2)"), s, SETTINGS)["status"], NOT_MET)
        self.assertEqual(evaluate(req("lookup", "assets"), s, SETTINGS)["status"], MET)

    def test_version(self):
        s = snap()
        self.assertEqual(evaluate(req("version", "9.2+,Cloud"), s, SETTINGS)["status"], MET)
        self.assertEqual(evaluate(req("version", "10.x"), s, SETTINGS)["status"], MET)
        self.assertEqual(evaluate(req("version", "9.1"), s, SETTINGS)["status"], NOT_MET)
        self.assertEqual(evaluate(req("version", "Cloud"), s, SETTINGS)["status"], UNKNOWN)

    def test_unverifiable_types_and_spl(self):
        s = snap()
        self.assertEqual(evaluate(req("field", "user"), s, SETTINGS)["status"], UNVERIFIED)
        self.assertEqual(evaluate(req("spl_validity", "missing", level="critical"), s, SETTINGS)["status"],
                         NOT_MET)


def scored(status, level="required", confidence="high", code="x"):
    return {"req_id": level + status, "type": "sourcetype", "value": "v", "level": level,
            "confidence": confidence, "status": status, "code": code}


class ScoringTest(unittest.TestCase):
    S = ScoringSettings(ready_threshold=90, partial_threshold=50, min_coverage=0.5)

    def test_critical_veto_overrides_score(self):
        results = [scored(MET)] * 10 + [scored(NOT_MET, level="critical")]
        out = score(results, self.S)
        self.assertEqual(out["state"], "blocked")
        self.assertEqual(len(out["blockers"]), 1)

    def test_ready_partial_not_ready(self):
        self.assertEqual(score([scored(MET), scored(MET)], self.S)["state"], "ready")
        self.assertEqual(score([scored(MET), scored(PARTIAL)], self.S)["state"], "partially_ready")
        self.assertEqual(score([scored(MET), scored(NOT_MET), scored(NOT_MET)], self.S)["state"], "not_ready")

    def test_required_gap_prevents_ready_even_with_high_score(self):
        results = [scored(MET)] * 30 + [scored(NOT_MET)]
        out = score(results, self.S)
        self.assertGreaterEqual(out["score"], 90)
        self.assertEqual(out["state"], "partially_ready")

    def test_unverified_excluded_and_unknown_lowers_coverage(self):
        out = score([scored(MET), scored(UNVERIFIED)], self.S)
        self.assertEqual((out["score"], out["unverified"]), (100, 1))
        out = score([scored(MET), scored(UNKNOWN), scored(UNKNOWN)], self.S)
        self.assertEqual(out["state"], "insufficient_evidence")
        out = score([scored(UNVERIFIED), scored(MET, level="informational")], self.S)
        self.assertIsNone(out["score"])
        self.assertEqual(out["state"], "insufficient_evidence")

    def test_confidence_weights(self):
        out = score([scored(MET, confidence="high"), scored(NOT_MET, level="recommended", confidence="low")], self.S)
        self.assertEqual(out["score"], 80)


class SourcetypeGroupTest(unittest.TestCase):
    S = ScoringTest.S
    ENV = snap([pair("itsm", "snow:incident")])

    def assess(self, spl):
        from splunk_ucm.readiness.service import ReadinessSettings, assess_use_case
        from unit.test_normalizer import FenreNormalizerTest
        FenreNormalizerTest.setUpClass()
        uc = FenreNormalizerTest("test_deterministic").normalize("9.1.1", lambda r: r.update(spl=spl, requiredFields=[], splunkbaseApps=[],
                                                        cimModels=[], premiumApps=[]))
        doc = assess_use_case(uc, self.ENV, ReadinessSettings())
        return doc, {r["value"]: r for r in doc["results"] if r["type"] == "sourcetype"}

    def test_or_and_in_with_one_present_are_met(self):
        for spl in ("index=itsm (sourcetype=snow:incident OR sourcetype=snow:sc_req_item) | stats count",
                    'index=itsm sourcetype IN ("snow:incident", "snow:sc_req_item") | stats count'):
            doc, st = self.assess(spl)
            self.assertEqual(st["snow:sc_req_item"]["any_of"], ["snow:incident", "snow:sc_req_item"], spl)
            self.assertTrue(st["snow:sc_req_item"]["collapsed"])
            self.assertEqual((st["snow:sc_req_item"]["status"], st["snow:incident"]["status"]), (NOT_MET, MET))
            self.assertEqual(doc["gaps"], [], spl)

    def test_join_append_multisearch_stay_all_of(self):
        for spl in ("index=itsm sourcetype=snow:incident | join n [search index=x sourcetype=snow:sc_req_item]",
                    "index=itsm sourcetype=snow:incident | append [search index=x sourcetype=snow:sc_req_item]",
                    "| multisearch [search sourcetype=snow:incident] [search sourcetype=snow:sc_req_item]"):
            doc, st = self.assess(spl)
            self.assertNotIn("any_of", st["snow:sc_req_item"], spl)
            self.assertEqual([g["value"] for g in doc["gaps"]], ["snow:sc_req_item"], spl)

    def test_group_with_no_member_present_is_one_gap(self):
        doc, st = self.assess("index=ot (sourcetype=modbus:traffic OR sourcetype=dnp3:traffic) | stats count")
        self.assertEqual([g["value"] for g in doc["gaps"]], ["any of modbus:traffic, dnp3:traffic"])

    def test_alternative_to_a_sole_sourcetype_is_recommended(self):
        doc, st = self.assess("index=a sourcetype=snow:incident OR sourcetype=x:y "
                              "| append [search sourcetype=snow:incident]")
        self.assertEqual((st["x:y"]["level"], st["snow:incident"]["level"]), ("recommended", "required"))
        self.assertNotIn("any_of", st["x:y"])

    def test_unverified_member_beats_missing_one(self):
        results = [dict(scored(NOT_MET), req_id="a", value="a", any_of=["a", "b"]),
                   dict(scored(UNVERIFIED), req_id="b", value="b", any_of=["a", "b"])]
        out = score(results, self.S)
        self.assertEqual(out["gaps"], [])
        self.assertTrue(results[0]["collapsed"])


def discovered_store():
    store = loaded_catalog()
    inv = FakeInventory(INDEXES, APPS, MODELS)
    inv.list_knowledge_objects = lambda: []
    inv.server_version = lambda: "10.2.9"
    DiscoveryService(store, AuditService(store), inv, FakeSearch(ROWS),
                     now_epoch=lambda: 1795163600).run(new_djob("alice"))
    return store


class ReadinessServiceTest(unittest.TestCase):
    def test_requires_discovery(self):
        svc = ReadinessService(loaded_catalog(), AuditService(InMemoryStore()))
        with self.assertRaises(ValidationError):
            svc.enqueue(new_job("a"))
        with self.assertRaises(ValidationError):
            svc.assess_one("fenre:UC-9.1.1", "a")

    def test_full_job_persists_and_queries(self):
        store = discovered_store()
        svc = ReadinessService(store, AuditService(store))
        job = svc.run(new_job("alice"))
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["totals"]["assessed"], store.count(C.CATALOG, {"provider_status": "active"}))
        doc = svc.get("fenre:UC-9.1.1")
        self.assertEqual(doc["state"], "ready")
        self.assertFalse(doc["stale"])
        self.assertTrue(all("status" in r and "code" in r for r in doc["results"]))
        page = ReadinessQueryService(store).search(ReadinessFilter(states=["ready"]))
        self.assertIn("fenre_UC-9.1.1", [i["_key"] for i in page["items"]])
        self.assertNotIn("results", page["items"][0])
        summary = ReadinessQueryService(store).summary()
        self.assertEqual(summary["total"], job["totals"]["assessed"])
        with self.assertRaises(ValidationError):
            ReadinessQueryService(store).search(ReadinessFilter(states=["bogus"]))

    def test_staleness_after_new_discovery(self):
        store = discovered_store()
        svc = ReadinessService(store, AuditService(store))
        svc.assess_one("fenre:UC-9.1.1", "alice")
        state = store.get(C.SYNC_STATE, "discovery::local")
        state["last_completed_at"] = "2099-01-01T00:00:00Z"
        store.upsert(C.SYNC_STATE, state)
        self.assertIn("newer_discovery", svc.get("fenre:UC-9.1.1")["stale_reasons"])

    def test_removed_use_cases_are_pruned(self):
        store = discovered_store()
        svc = ReadinessService(store, AuditService(store))
        svc.run(new_job("a"))
        cat = store.get(C.CATALOG, "fenre_UC-9.1.2")
        cat["provider_status"] = "withdrawn"
        store.upsert(C.CATALOG, cat)
        job = svc.run(new_job("a"))
        self.assertEqual(job["totals"]["removed"], 1)
        self.assertIsNone(store.get(C.READINESS, "fenre_UC-9.1.2"))


class ReadinessWorkerTest(unittest.TestCase):
    def test_auto_assess_once_per_discovery(self):
        store = discovered_store()
        worker = ReadinessWorker(store, AppConfig({}), lambda: True)
        self.assertEqual(worker.run_once()["action"], "ran")
        self.assertEqual(worker.run_once()["action"], "idle")
        state = store.get(C.SYNC_STATE, "discovery::local")
        state["last_completed_at"] = "2099-01-01T00:00:00Z"
        store.upsert(C.SYNC_STATE, state)
        self.assertEqual(worker.run_once()["action"], "ran")

    def test_disabled_and_no_discovery(self):
        self.assertEqual(ReadinessWorker(loaded_catalog(), AppConfig({}), lambda: True).run_once()["action"], "idle")
        cfg = AppConfig({"readiness": {"auto_assess": "false"}})
        self.assertEqual(ReadinessWorker(discovered_store(), cfg, lambda: True).run_once()["action"], "idle")
        self.assertEqual(ReadinessWorker(discovered_store(), AppConfig({}), lambda: False).run_once()["action"],
                         "skipped")

    def test_timeout_expiry(self):
        store = discovered_store()
        worker = ReadinessWorker(store, AppConfig({}), lambda: True,
                                 now=lambda: datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
        job = new_job("a")
        job.update({"status": "running", "started_at": "2026-01-01T00:00:00Z"})
        worker.service.save_job(job)
        self.assertEqual(worker.expire_stale(), 1)


class ReadinessApiTest(unittest.TestCase):
    def test_rbac_and_endpoints(self):
        store = discovered_store()
        viewer = make_ctx(store, [])
        self.assertEqual(call(viewer, "POST", "readiness")[0], 403)
        self.assertEqual(call(viewer, "POST", "readiness/assess", body={"id": "fenre:UC-9.1.1"})[0], 403)
        self.assertEqual(call(viewer, "GET", "readiness/usecase", {"id": "fenre:UC-9.1.1"})[0], 404)
        analyst = make_ctx(store, [CAP_RUN_DISCOVERY])
        status, body = call(analyst, "POST", "readiness/assess", body={"id": "fenre:UC-9.1.1"})
        self.assertEqual((status, body["state"]), (200, "ready"))
        status, body = call(viewer, "GET", "usecase", {"id": "fenre:UC-9.1.1"})
        self.assertEqual(body["readiness"]["state"], "ready")
        self.assertEqual(body["requirement_summary"]["assessment"], "ready")
        self.assertEqual(call(analyst, "POST", "readiness")[0], 202)
        self.assertEqual(call(analyst, "POST", "readiness")[0], 400)
        status, body = call(viewer, "GET", "readiness/summary")
        self.assertEqual(status, 200)
        self.assertIn("by_state", body)
        self.assertEqual(call(viewer, "GET", "readiness", {"state": "ready"})[0], 200)


class ReadinessGlossaryTest(unittest.TestCase):
    """The UI glossary in ucm_common.js names exactly the engine's states and statuses."""

    def setUp(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "appserver", "static", "ucm_common.js")
        with open(path, encoding="utf-8") as handle:
            self.js = handle.read()

    def keys(self, name):
        block = self.js.split("var %s = {" % name, 1)[1].split("};", 1)[0]
        return re.findall(r"^\s*(\w+):", block, re.M)

    def array(self, name):
        block = self.js.split("%s: [" % name, 1)[1].split("]", 1)[0]
        return re.findall(r'"(\w+)"', block)

    def test_glossary_matches_engine(self):
        self.assertEqual(self.keys("READINESS_HELP"), list(STATES))
        self.assertEqual(self.array("READINESS_STATES"), list(STATES))
        self.assertEqual(self.keys("STATUS_HELP"), list(STATUSES))
        self.assertEqual(self.array("STATUSES"), list(STATUSES))

    def test_glossary_never_equates_unchecked_with_absent(self):
        block = self.js.split("var STATUS_HELP = {", 1)[1].split("};", 1)[0]
        unverified = block.split("unverified:", 1)[1].split("not_applicable:", 1)[0]
        self.assertIn("does not mean the data is absent", unverified)
        self.assertIn("Left out of score and coverage", unverified)


if __name__ == "__main__":
    unittest.main()

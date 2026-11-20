import copy
import json
import unittest

import helpers  # noqa: F401  (sets sys.path)
from attack_builder import build
from splunk_ucm.audit import AuditService
from splunk_ucm.dashboards.service import DashboardService
from splunk_ucm.dashboards.templates import MARKER, render, view_name
from splunk_ucm.errors import ConflictError, NotFoundError, ValidationError
from splunk_ucm.frameworks.coverage import CoverageService
from splunk_ucm.frameworks.operations import OperationsService, classify
from splunk_ucm.frameworks.registry import FrameworkRegistry, validate_definition
from splunk_ucm.platform.search import SearchResult
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import UC, approved, service
from unit.test_discovery import loaded_catalog

TINY = {
    "format": "ucm.framework/1", "framework": "mitre_attack", "framework_id": "mitre_attack_enterprise",
    "domain": "enterprise", "name": "MITRE ATT&CK Enterprise", "version": "99.0",
    "tactics": [{"id": "TA0006", "name": "Credential Access"}, {"id": "TA0005", "name": "Defense Evasion"}],
    "techniques": [
        {"id": "T1110", "name": "Brute Force", "tactics": ["TA0006"]},
        {"id": "T1110.001", "name": "Password Guessing", "tactics": ["TA0006"], "parent": "T1110"},
        {"id": "T1685", "name": "Disable or Modify Tools", "tactics": ["TA0005"]},
    ],
    "revoked": {"T1562": "T1685"}, "deprecated": ["T1999"],
}


def stix_bundle():
    tac = lambda i, ext, short: {"type": "x-mitre-tactic", "id": i, "name": short.title(), "x_mitre_shortname": short,
                                 "external_references": [{"source_name": "mitre-attack", "external_id": ext}]}
    ap = lambda i, ext, phase, **kw: dict({"type": "attack-pattern", "id": i, "name": ext + " name",
                                           "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase}],
                                           "external_references": [{"source_name": "mitre-attack", "external_id": ext}]}, **kw)
    return {"type": "bundle", "objects": [
        {"type": "x-mitre-matrix", "id": "m1", "tactic_refs": ["t1", "t2"], "x_mitre_domains": ["enterprise-attack"],
         "modified": "2026-01-01"},
        tac("t1", "TA0006", "credential-access"), tac("t2", "TA0005", "defense-evasion"),
        ap("a1", "T1110", "credential-access"), ap("a2", "T1110.001", "credential-access", x_mitre_is_subtechnique=True),
        ap("a3", "T1562", "defense-evasion", revoked=True), ap("a4", "T1685", "defense-evasion"),
        ap("a5", "T1999", "defense-evasion", x_mitre_deprecated=True),
        {"type": "relationship", "id": "r1", "relationship_type": "revoked-by", "source_ref": "a3", "target_ref": "a4"},
    ]}


class BuilderAndRegistryTest(unittest.TestCase):
    def test_builder_reduces_stix(self):
        out = build(stix_bundle(), "99.0")
        self.assertEqual(out["framework_id"], "mitre_attack_enterprise")
        self.assertEqual([t["id"] for t in out["tactics"]], ["TA0006", "TA0005"])
        self.assertEqual([t["id"] for t in out["techniques"]], ["T1110", "T1110.001", "T1685"])
        self.assertEqual(out["techniques"][1]["parent"], "T1110")
        self.assertEqual(out["revoked"], {"T1562": "T1685"})
        self.assertEqual(out["deprecated"], ["T1999"])
        validate_definition(out)

    def test_bundled_attack_versions(self):
        reg = FrameworkRegistry(loaded_catalog())
        items = {(i["framework_id"], i["version"]): i for i in reg.list()}
        ent = items[("mitre_attack_enterprise", "20.1")]
        self.assertTrue(ent["active"])
        self.assertGreater(ent["techniques"], 500)
        self.assertIn(("mitre_attack_ics", "20.1"), items)
        self.assertIn("MITRE", ent["attribution"])

    def test_validation_rejects_malformed(self):
        for mutate in (lambda d: d.update(format="x"), lambda d: d.update(version="v20"),
                       lambda d: d["techniques"].append({"id": "T1110", "name": "dup", "tactics": []}),
                       lambda d: d["techniques"].append({"id": "T2", "name": "x", "tactics": ["TA9999"]}),
                       lambda d: d["techniques"].append({"id": "T3.001", "name": "x", "tactics": [], "parent": "T3"}),
                       lambda d: d["techniques"].append({"id": "<script>", "name": "x", "tactics": []}),
                       lambda d: d.update(revoked={"T1": "$bad"})):
            doc = copy.deepcopy(TINY)
            mutate(doc)
            with self.assertRaises(ValidationError):
                validate_definition(doc)

    def test_import_and_activate_versions(self):
        store = loaded_catalog()
        reg = FrameworkRegistry(store)
        reg.import_definition(json.dumps(TINY).encode(), "carol")
        self.assertEqual(reg.versions("mitre_attack_enterprise")[-1], "99.0")
        self.assertEqual(reg.active_versions()["mitre_attack_enterprise"], "99.0")
        reg.activate("mitre_attack_enterprise", "20.1", "carol")
        self.assertEqual(reg.active_versions()["mitre_attack_enterprise"], "20.1")
        self.assertEqual(reg.get("mitre_attack_enterprise", "99.0")["techniques"][0]["id"], "T1110")
        with self.assertRaises(NotFoundError):
            reg.activate("mitre_attack_enterprise", "1.0", "carol")
        with self.assertRaises(ValidationError):
            reg.import_definition(b"[1]", "carol")
        bundled = reg.get("mitre_attack_ics")
        with self.assertRaises(ValidationError):
            reg.import_definition(json.dumps(bundled).encode(), "carol")


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.cov = CoverageService(self.store)

    def test_levels_follow_readiness_and_deployment(self):
        svc, store, saved = service(store=self.store)
        approved(svc)
        svc.deploy("bob", UC)
        store.upsert(C.READINESS, {"_key": "fenre_UC-9.1.2", "state": "ready"})
        levels = self.cov.use_case_levels()
        self.assertEqual(levels["fenre_UC-9.1.1"]["level"], "deployed")
        self.assertEqual(levels["fenre_UC-9.1.2"]["level"], "ready")
        svc.enable("bob", UC)
        self.assertEqual(self.cov.use_case_levels()["fenre_UC-9.1.1"]["level"], "enabled")
        self.assertEqual(self.cov.use_case_levels({UC: "operational"})["fenre_UC-9.1.1"]["level"], "operational")
        self.assertEqual(set(self.cov.use_case_levels(domain="identity")), {"fenre_UC-9.1.1", "fenre_UC-9.1.2"})

    def test_matrix_rolls_up_and_reports_revoked_and_unresolved(self):
        self.store.upsert(C.READINESS, {"_key": "fenre_UC-9.1.2", "state": "ready"})
        cat = self.store.get(C.CATALOG, "fenre_UC-7.1.1")
        cat["mitre_ids"] = ["T1999", "T0800", "T4242"]
        self.store.upsert(C.CATALOG, cat)
        m = self.cov.attack_matrix(validate_definition(TINY), self.cov.use_case_levels())
        cred = next(t for t in m["tactics"] if t["id"] == "TA0006")
        brute = cred["techniques"][0]
        self.assertEqual(brute["id"], "T1110")
        self.assertEqual(brute["counts"]["catalogue"], 2)
        self.assertEqual(brute["counts"]["ready"], 1)
        self.assertEqual(brute["level"], "ready")
        self.assertEqual(brute["subs"][0]["counts"]["catalogue"], 1)
        evasion = next(t for t in m["tactics"] if t["id"] == "TA0005")
        self.assertEqual(evasion["techniques"][0]["counts"]["catalogue"], 1)
        self.assertEqual(m["remapped"], [{"from": "T1562", "to": "T1685", "use_cases": ["fenre:UC-10.4.24"], "count": 1}])
        unresolved = {u["id"]: u["reason"] for u in m["unresolved"]}
        self.assertEqual(unresolved, {"T1999": "deprecated", "T4242": "unknown"})
        self.assertEqual(m["totals"]["techniques"], 2)
        self.assertEqual(m["totals"]["covered"]["catalogue"], 2)
        uses = self.cov.technique_use_cases(validate_definition(TINY), "T1110", self.cov.use_case_levels())
        self.assertEqual([u["content_id"] for u in uses], ["fenre:UC-9.1.2", "fenre:UC-9.1.1"])

    def test_bundled_matrix_with_fixture_catalogue(self):
        reg = FrameworkRegistry(self.store)
        m = self.cov.attack_matrix(reg.get("mitre_attack_enterprise"), self.cov.use_case_levels())
        self.assertEqual(len(m["tactics"]), 15)
        self.assertEqual(m["remapped"][0]["from"], "T1562")
        ics = self.cov.attack_matrix(reg.get("mitre_attack_ics"), self.cov.use_case_levels())
        self.assertEqual(ics["totals"]["covered"]["catalogue"], 0)

    def test_generic_frameworks_and_controls(self):
        summary = {f["framework"]: f for f in self.cov.frameworks_summary(self.cov.use_case_levels())}
        self.assertEqual(summary["mitre_attack"]["counts"]["catalogue"], 3)
        self.assertEqual(summary["regulation:gdpr"]["kind"], "regulation")
        self.assertEqual(summary["regulation:gdpr"]["controls"], 1)
        controls = self.cov.framework_controls("regulation:hitrust", self.cov.use_case_levels())
        self.assertEqual(controls[0]["control"], "01.b")
        self.assertEqual(controls[0]["use_cases"], ["fenre:UC-9.1.1"])


class FakeHealthSearch:
    def __init__(self, rows=None, fail=None, internal_events=100):
        self.rows = rows or []
        self.fail = fail
        self.internal_events = internal_events
        self.calls = []

    def oneshot(self, spl, **kw):
        self.calls.append((spl, kw))
        if self.fail:
            raise self.fail
        if spl.startswith("| tstats"):
            return SearchResult([{"count": str(self.internal_events)}], [], False)
        return SearchResult(self.rows, [], False)


class OperationsTest(unittest.TestCase):
    def test_health_classification(self):
        self.assertEqual(classify(False, {}), "disabled")
        self.assertEqual(classify(True, {}), "no_runs")
        self.assertEqual(classify(True, {"runs": "3", "succeeded": "3", "last_status": "success"}), "operational")
        self.assertEqual(classify(True, {"runs": "3", "succeeded": "0", "last_status": "skipped"}), "unhealthy")

    def test_health_joins_scheduler_rows(self):
        svc, store, _ = service()
        approved(svc)
        doc = svc.deploy("bob", UC)
        svc.enable("bob", UC)
        rows = [{"savedsearch_name": doc["saved_search"]["name"], "runs": "4", "succeeded": "4", "skipped": "0",
                 "other": "0", "runs_with_results": "1", "last_run": "1795169820", "last_status": "success",
                 "last_result_count": "2"}]
        search = FakeHealthSearch(rows)
        out = OperationsService(store, search).health(24)
        self.assertTrue(out["available"])
        self.assertEqual(out["items"][0]["health"], "operational")
        self.assertEqual(out["counts"], {"operational": 1})
        spl, kw = search.calls[0]
        self.assertTrue(spl.startswith("| search index=_internal sourcetype=scheduler"))
        self.assertEqual(kw["earliest"], "-24h")
        from splunk_ucm.errors import UnsupportedOperation
        out = OperationsService(store, FakeHealthSearch(fail=UnsupportedOperation("no access"))).health(24)
        self.assertFalse(out["available"])
        self.assertEqual(out["items"][0]["health"], "unknown")
        with self.assertRaises(ValidationError):
            OperationsService(store, search).health(5)
        out = OperationsService(store, FakeHealthSearch()).health(24)
        self.assertEqual(out["items"][0]["health"], "no_runs")
        out = OperationsService(store, FakeHealthSearch(internal_events=0)).health(24)
        self.assertFalse(out["available"])
        self.assertIn("_internal", out["reason"])
        self.assertEqual(out["counts"], {"unknown": 1})


class FakeViews:
    def __init__(self):
        self.views = {}

    def get(self, name):
        return self.views.get(name)

    def save(self, name, xml, exists):
        assert exists == (name in self.views)
        self.views[name] = xml

    def delete(self, name):
        self.views.pop(name, None)


class DashboardTest(unittest.TestCase):
    def test_render_validates_and_escapes(self):
        out = render("domain_overview", {"domain": "security"}, {})
        self.assertIn(MARKER, out["xml"])
        self.assertIn('domains="security"', out["xml"])
        import xml.etree.ElementTree as ET
        ET.fromstring(out["xml"])
        with self.assertRaises(ValidationError):
            render("domain_overview", {"domain": "security\" | delete"}, {})
        with self.assertRaises(ValidationError):
            render("nope", {}, {})
        with self.assertRaises(ValidationError):
            render("deployed_searches", {}, {"deployed": []})
        deployed = [{"title": 'A <b>&"x"', "saved_search": 'UCM - 1 - "q" <x>', "live_status": "enabled",
                     "domains": ["security"]}]
        out = render("deployed_searches", {"domain": "security"}, {"deployed": deployed})
        root = ET.fromstring(out["xml"])
        refs = [s.get("ref") for s in root.iter("search") if s.get("ref")]
        self.assertEqual(refs, ['UCM - 1 - "q" <x>'])
        self.assertEqual(view_name("domain_overview", {"domain": "ot_ics"}), "ucm_gen_domain_overview_ot_ics")

    def test_create_update_delete_and_conflicts(self):
        store = loaded_catalog()
        views = FakeViews()
        svc = DashboardService(store, AuditService(store), views)
        doc = svc.create("bob", "domain_overview", {"domain": "security"})
        self.assertEqual(doc["name"], "ucm_gen_domain_overview_security")
        self.assertIn(MARKER, views.views[doc["name"]])
        svc.create("bob", "domain_overview", {"domain": "security"})
        self.assertEqual(len(svc.list()), 1)
        views.views["ucm_gen_domain_overview_network"] = "<dashboard>someone else</dashboard>"
        with self.assertRaises(ConflictError):
            svc.create("bob", "domain_overview", {"domain": "network"})
        svc.delete("bob", doc["name"])
        self.assertNotIn(doc["name"], views.views)
        with self.assertRaises(NotFoundError):
            svc.delete("bob", "ucm_gen_domain_overview_network")
        self.assertIn("ucm_gen_domain_overview_network", views.views)


class FrameworkApiTest(unittest.TestCase):
    def test_reads_and_capabilities(self):
        store = loaded_catalog()
        viewer = make_ctx(store, [])
        status, body = call(viewer, "GET", "frameworks")
        self.assertEqual(status, 200)
        self.assertTrue(any(d["framework_id"] == "mitre_attack_ics" for d in body["definitions"]))
        status, body = call(viewer, "GET", "frameworks/matrix", {"framework_id": "mitre_attack_enterprise"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["active_version"], "20.1")
        self.assertEqual(call(viewer, "GET", "frameworks/matrix", {"framework_id": "nope"})[0], 404)
        self.assertEqual(call(viewer, "GET", "frameworks/technique",
                              {"framework_id": "mitre_attack_enterprise", "id": "T1110"})[0], 200)
        self.assertEqual(call(viewer, "GET", "frameworks/controls", {"framework": "regulation:gdpr"})[0], 200)
        self.assertEqual(call(viewer, "GET", "frameworks", {"domain": "bogus"})[0], 400)
        self.assertEqual(call(viewer, "POST", "frameworks/import", body=TINY)[0], 403)
        self.assertEqual(call(viewer, "POST", "frameworks/activate", body={})[0], 403)
        self.assertEqual(call(viewer, "POST", "dashboards/create", body={"template": "domain_overview"})[0], 403)
        self.assertEqual(call(viewer, "POST", "dashboards/delete", body={"name": "ucm_gen_x"})[0], 403)
        status, body = call(viewer, "POST", "dashboards/preview",
                            body={"template": "domain_overview", "params": {"domain": "network"}})
        self.assertEqual(status, 200, body)
        self.assertEqual(call(viewer, "GET", "dashboards")[0], 200)
        manager = make_ctx(store, ["ucm_manage_content"])
        self.assertEqual(call(manager, "POST", "frameworks/import", body=TINY)[0], 200)
        self.assertEqual(call(manager, "POST", "frameworks/activate",
                              body={"framework_id": "mitre_attack_enterprise", "version": "20.1"})[0], 200)


if __name__ == "__main__":
    unittest.main()

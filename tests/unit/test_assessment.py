import json
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.errors import ConflictError, NotFoundError, ValidationError
from splunk_ucm.frameworks import assessment as A
from splunk_ucm.frameworks.assessment import AssessmentService, assessment_key, derive_status
from splunk_ucm.frameworks.controls import catalogue_coverage
from splunk_ucm.frameworks.registry import FrameworkRegistry
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog

REG = FrameworkRegistry(InMemoryStore())
R3 = REG.get("nist-800-171")
CMMC = REG.get("cmmc-l2")
CSF = REG.get("nist-csf")


def service():
    store = InMemoryStore()
    return AssessmentService(store, AuditService(store)), store


class StatusTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.store = service()

    def test_a_status_records_who_when_and_why(self):
        out = self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Mission is documented in the ISMS charter.", None)
        self.assertEqual((out["status"], out["assessed_by"], out["note"], out["version"]),
                         ("implemented", "alice", "Mission is documented in the ISMS charter.", "2.0"))
        self.assertTrue(out["assessed_at"].endswith("Z") and out["first_assessed_by"] == "alice")
        self.assertEqual(self.svc.docs("nist-csf")["GV.OC-01"]["status"], "implemented")

    def test_a_reason_is_required(self):
        for note in (None, "", "   ", "no"):
            with self.assertRaises(ValidationError):
                self.svc.set("alice", CSF, "GV.OC-01", "implemented", note, None)
        self.assertEqual(self.store.query(C.ASSESSMENTS, None), [])

    def test_not_applicable_needs_a_longer_reason(self):
        with self.assertRaises(ValidationError):
            self.svc.set("alice", CSF, "GV.OC-01", "not_applicable", "n/a here", None)
        out = self.svc.set("alice", CSF, "GV.OC-01", "not_applicable", "We do not operate this function.", None)
        self.assertEqual(out["status"], "not_applicable")

    def test_invalid_input_is_refused(self):
        with self.assertRaises(ValidationError):
            self.svc.set("alice", CSF, "GV.OC-01", "done", "because reasons", None)
        with self.assertRaises(ValidationError):
            self.svc.set("alice", CSF, "GV.OC-01", "", "because reasons", None)
        with self.assertRaises(ValidationError):
            self.svc.set("alice", CSF, "GV.OC-01", "implemented", "because reasons", {"x": "met"})
        with self.assertRaises(ValidationError):
            self.svc.set("alice", CSF, "GV", "implemented", "a function cannot be assessed", None)
        with self.assertRaises(ValidationError):
            self.svc.set("alice", CSF, "ID.BE-01", "implemented", "withdrawn in 2.0", None)
        with self.assertRaises(NotFoundError):
            self.svc.set("alice", CSF, "XX-1", "implemented", "no such control", None)

    def test_a_change_keeps_the_previous_decision_in_the_history(self):
        self.svc.set("alice", CSF, "GV.OC-01", "planned", "Charter is being written.", None)
        out = self.svc.set("bob", CSF, "GV.OC-01", "implemented", "Charter approved on 2026-11-01.", None)
        self.assertEqual((out["assessed_by"], out["first_assessed_by"]), ("bob", "alice"))
        self.assertEqual([(h["status"], h["by"], h["note"]) for h in out["history"]],
                         [("planned", "alice", "Charter is being written.")])

    def test_history_is_bounded(self):
        for i in range(A.HISTORY + 8):
            self.svc.set("alice", CSF, "GV.OC-01", "planned" if i % 2 else "implemented", "round %d" % i * 2, None)
        self.assertEqual(len(self.svc.docs("nist-csf")["GV.OC-01"]["history"]), A.HISTORY)

    def test_clear_removes_the_assessment_and_audits_who_and_why(self):
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        with self.assertRaises(ValidationError):
            self.svc.clear("bob", CSF, "GV.OC-01", "")
        self.assertTrue(self.svc.clear("bob", CSF, "GV.OC-01", "Entered on the wrong control.")["cleared"])
        self.assertEqual(self.svc.docs("nist-csf"), {})
        with self.assertRaises(NotFoundError):
            self.svc.clear("bob", CSF, "GV.OC-01", "Entered on the wrong control.")
        rows = [r for r in self.store.query(C.AUDIT, None) if r["action"] == "assessment.cleared"]
        self.assertEqual((rows[0]["actor"], rows[0]["details"]["previous"], rows[0]["details"]["by"]), ("bob", "implemented", "alice"))

    def test_audit_records_each_decision_and_the_chain_still_verifies(self):
        self.svc.set("alice", CSF, "GV.OC-01", "planned", "Charter is being written.", None)
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        actions = [r["action"] for r in sorted(self.store.query(C.AUDIT, None), key=lambda r: (r["time"], r["_key"]))]
        self.assertEqual(actions, ["assessment.set", "assessment.set"])
        self.assertTrue(self.svc.audit.verify_chain()["ok"])

    def test_an_assessment_against_an_older_version_is_marked_stale(self):
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        newer = dict(CSF, version="3.0")
        view = self.svc.view(newer)
        self.assertTrue(view["assessments"]["GV.OC-01"]["stale_version"])
        self.assertEqual(view["summary"]["stale_version"], 1)
        gone = dict(newer, controls=[c for c in CSF["controls"] if c["id"] != "GV.OC-01"])
        self.assertEqual([o["control_id"] for o in self.svc.view(gone)["orphaned"]], ["GV.OC-01"])

    def test_summary_counts_only_assessable_controls(self):
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        self.svc.set("alice", CSF, "GV.OC-02", "not_implemented", "No process yet.", None)
        s = self.svc.view(CSF)["summary"]
        self.assertEqual((s["controls"], s["assessed"], s["not_assessed"]), (106, 2, 104))
        self.assertEqual((s["by_status"]["implemented"], s["by_status"]["not_implemented"]), (1, 1))
        self.assertIsNone(self.svc.view(CSF)["score"])


class ObjectiveTest(unittest.TestCase):
    CONTROL = "03.01.01"

    def setUp(self):
        self.svc, self.store = service()
        self.objectives = [o["id"] for o in next(c for c in R3["controls"] if c["id"] == self.CONTROL)["objectives"]]

    def test_the_status_is_derived_from_the_objective_results(self):
        self.assertEqual(len(self.objectives), 22)
        out = self.svc.set("alice", R3, self.CONTROL, "", "Reviewed with the identity team.",
                           {self.objectives[0]: "met", self.objectives[1]: "met"})
        self.assertEqual((out["status"], out["complete"], out["derived"]), ("partially_implemented", False, True))
        out = self.svc.set("alice", R3, self.CONTROL, "", "Reviewed the rest.", {o: "met" for o in self.objectives})
        self.assertEqual((out["status"], out["complete"]), ("implemented", True))
        out = self.svc.set("bob", R3, self.CONTROL, "", "Found a gap in account removal.", {self.objectives[3]: {"result": "not_met", "note": "x"}})
        self.assertEqual((out["status"], out["complete"]), ("partially_implemented", True))
        self.assertEqual(out["objectives"][self.objectives[0]]["by"], "alice")
        self.assertEqual(out["objectives"][self.objectives[3]]["by"], "bob")

    def test_all_not_met_is_not_implemented_and_all_not_applicable_is_not_applicable(self):
        out = self.svc.set("alice", R3, self.CONTROL, "", "Nothing exists.", {o: "not_met" for o in self.objectives})
        self.assertEqual(out["status"], "not_implemented")
        out = self.svc.set("alice", R3, self.CONTROL, "", "System has no accounts.",
                           {o: {"result": "not_applicable", "note": "The system has no user accounts."} for o in self.objectives})
        self.assertEqual(out["status"], "not_applicable")

    def test_rules(self):
        with self.assertRaises(ValidationError):
            self.svc.set("alice", R3, self.CONTROL, "implemented", "claimed directly", {self.objectives[0]: "met"})
        with self.assertRaises(ValidationError):
            self.svc.set("alice", R3, self.CONTROL, "", "no objectives sent", None)
        with self.assertRaises(ValidationError):
            self.svc.set("alice", R3, self.CONTROL, "", "bad id", {"nope": "met"})
        with self.assertRaises(ValidationError):
            self.svc.set("alice", R3, self.CONTROL, "", "bad result", {self.objectives[0]: "maybe"})
        with self.assertRaises(ValidationError):
            self.svc.set("alice", R3, self.CONTROL, "", "needs a reason", {self.objectives[0]: "not_applicable"})
        with self.assertRaises(NotFoundError):
            self.svc.set("alice", R3, "03.01.99", "", "x" * 6, {self.objectives[0]: "met"})

    def test_an_objective_can_be_taken_back_and_the_last_one_cannot(self):
        self.svc.set("alice", R3, self.CONTROL, "", "two results", {self.objectives[0]: "met", self.objectives[1]: "not_met"})
        out = self.svc.set("alice", R3, self.CONTROL, "", "retract one", {self.objectives[1]: "not_assessed"})
        self.assertEqual(list(out["objectives"]), [self.objectives[0]])
        with self.assertRaises(ValidationError):
            self.svc.set("alice", R3, self.CONTROL, "", "retract the last", {self.objectives[0]: "not_assessed"})
        self.assertEqual(self.svc.docs("nist-800-171")[self.CONTROL]["status"], "partially_implemented")

    def test_objective_progress_in_the_summary(self):
        self.svc.set("alice", R3, self.CONTROL, "", "two results", {self.objectives[0]: "met", self.objectives[1]: "met"})
        s = self.svc.view(R3)["summary"]
        self.assertEqual((s["objectives"], s["objectives_assessed"], s["incomplete"]), (422, 2, 1))

    def test_derive_status_directly(self):
        objs = [{"id": "a"}, {"id": "b"}]
        res = lambda *r: {k: {"result": v} for k, v in zip("ab", r) if v}
        self.assertEqual(derive_status(objs, res(None, None)), ("", False))
        self.assertEqual(derive_status(objs, res("met", None)), ("partially_implemented", False))
        self.assertEqual(derive_status(objs, res("met", "not_applicable")), ("implemented", True))
        self.assertEqual(derive_status(objs, res("not_met", None)), ("not_implemented", False))


class ScoreTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.store = service()

    def score(self):
        return self.svc.view(CMMC)["score"]

    def test_the_method_starts_at_110_and_the_worst_case_is_minus_203(self):
        s = self.score()
        self.assertEqual((s["start"], s["requirements"], s["assessed"], s["score"], s["ceiling"], s["points_lost"]),
                         (110, 110, 0, -203, 110, 313))
        self.assertEqual(s["method"], "dod-800-171-1.2.1")
        self.assertEqual(s["lost_by_value"], {"5": 44, "3": 14, "1": 51})

    def test_implemented_requirements_recover_their_points(self):
        self.svc.set("alice", CMMC, "AC.L2-3.1.1", "implemented", "Directory enforces access.", None)
        self.svc.set("alice", CMMC, "AC.L2-3.1.3", "implemented", "CUI flow is controlled.", None)
        self.svc.set("alice", CMMC, "AC.L2-3.1.5", "implemented", "Least privilege reviewed.", None)
        s = self.score()
        self.assertEqual((s["score"], s["assessed"], s["unassessed"]), (-203 + 5 + 1 + 3, 3, 107))
        self.assertEqual(s["ceiling"], 110)
        self.assertFalse(s["complete"])

    def test_a_plan_does_not_reduce_the_deduction(self):
        self.svc.set("alice", CMMC, "AC.L2-3.1.1", "planned", "Rolling out in Q1.", None)
        self.assertEqual(self.score()["score"], -203)
        self.assertEqual(self.score()["ceiling"], 110 - 5)

    def test_partial_credit_exists_only_for_the_two_requirements_that_define_it(self):
        self.svc.set("alice", CMMC, "IA.L2-3.5.3", "partially_implemented", "MFA for admins only.", None)
        self.svc.set("alice", CMMC, "SC.L2-3.13.11", "partially_implemented", "Some encryption is not FIPS validated.", None)
        self.svc.set("alice", CMMC, "AC.L2-3.1.1", "partially_implemented", "Only some systems.", None)
        s = self.score()
        self.assertEqual(s["score"], -203 + 2 + 2)
        self.assertEqual(s["ceiling"], 110 - 3 - 3 - 5)

    def test_not_applicable_deducts_nothing(self):
        self.svc.set("alice", CMMC, "AC.L2-3.1.12", "not_applicable", "Remote access is not permitted.", None)
        self.assertEqual(self.score()["score"], -203 + 5)

    def test_the_system_security_plan_is_a_precondition_not_points(self):
        self.assertEqual(self.score()["blocked_by"], ["CA.L2-3.12.4"])
        self.svc.set("alice", CMMC, "CA.L2-3.12.4", "implemented", "SSP v3 approved.", None)
        s = self.score()
        self.assertEqual((s["blocked_by"], s["score"]), ([], -203))

    def test_all_implemented_scores_110_and_is_complete(self):
        for c in CMMC["controls"]:
            if c["kind"] == "requirement":
                self.svc.set("alice", CMMC, c["id"], "implemented", "Verified in the assessment.", None)
        s = self.score()
        self.assertEqual((s["score"], s["ceiling"], s["complete"], s["unassessed"], s["blocked_by"]), (110, 110, True, 0, []))


class PoamTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.store = service()

    def create(self, **kw):
        body = dict(control_id="GV.OC-01", title="Write the charter", weakness="No approved mission statement.",
                    owner="CISO", due="2099-01-31")
        body.update(kw)
        return self.svc.poam_create("alice", CSF, body)

    def test_create_validates_and_records_the_creator(self):
        item = self.create(milestones=[{"text": "Draft", "due": "2098-12-01"}, {"text": "Approve"}])
        self.assertEqual((item["state"], item["created_by"], item["overdue"], item["control_id"]), ("open", "alice", False, "GV.OC-01"))
        self.assertEqual([m["text"] for m in item["milestones"]], ["Draft", "Approve"])
        for bad in ({"due": "31/01/2099"}, {"due": "2099-02-30"}, {"due": ""}, {"owner": ""}, {"title": ""}, {"weakness": "x"},
                    {"control_id": "GV"}, {"milestones": [{"text": ""}]}, {"milestones": "x"}):
            with self.assertRaises(ValidationError, msg=str(bad)):
                self.create(**bad)
        with self.assertRaises(NotFoundError):
            self.create(control_id="NOPE-1")

    def test_overdue_is_computed_from_the_date_and_only_for_open_items(self):
        item = self.create(due="2020-01-01")
        self.assertTrue(item["overdue"])
        listed = self.svc.poam_list("nist-csf", [])
        self.assertEqual((listed["counts"]["overdue"], listed["counts"]["open"]), (1, 1))
        self.assertEqual(self.svc.poam_list("nist-csf", [], overdue=True)["total"], 1)
        closed = self.svc.poam_close("bob", item["id"], "closed", "Charter approved.")
        self.assertFalse(closed["overdue"])
        self.assertEqual(self.svc.poam_list("nist-csf", [], overdue=True)["total"], 0)

    def test_changing_the_due_date_needs_a_reason(self):
        item = self.create()
        with self.assertRaises(ValidationError):
            self.svc.poam_update("bob", item["id"], {"due": "2099-03-31"})
        out = self.svc.poam_update("bob", item["id"], {"due": "2099-03-31", "note": "Vendor delay."})
        self.assertEqual((out["due"], out["updated_by"], out["history"][-1]["note"]), ("2099-03-31", "bob", "Vendor delay."))
        out = self.svc.poam_update("bob", item["id"], {"state": "in_progress", "owner": "Head of IT"})
        self.assertEqual((out["state"], out["owner"]), ("in_progress", "Head of IT"))
        with self.assertRaises(ValidationError):
            self.svc.poam_update("bob", item["id"], {})
        with self.assertRaises(ValidationError):
            self.svc.poam_update("bob", item["id"], {"state": "closed"})

    def test_closing_records_who_and_why_and_risk_acceptance_needs_more(self):
        item = self.create()
        with self.assertRaises(ValidationError):
            self.svc.poam_close("bob", item["id"], "closed", "")
        with self.assertRaises(ValidationError):
            self.svc.poam_close("bob", item["id"], "risk_accepted", "ok")
        with self.assertRaises(ValidationError):
            self.svc.poam_close("bob", item["id"], "done", "finished the work")
        out = self.svc.poam_close("bob", item["id"], "risk_accepted", "Accepted by the risk committee, minute 14.")
        self.assertEqual((out["state"], out["closed_by"], out["close_note"]), ("risk_accepted", "bob", "Accepted by the risk committee, minute 14."))
        with self.assertRaises(ConflictError):
            self.svc.poam_close("bob", item["id"], "closed", "again, for good measure")
        with self.assertRaises(ConflictError):
            self.svc.poam_update("bob", item["id"], {"owner": "Someone"})
        back = self.svc.poam_reopen("carol", item["id"], "Risk acceptance withdrawn.")
        self.assertEqual((back["state"], back["closed_by"]), ("open", ""))
        self.assertEqual([h["action"] for h in back["history"]], ["created", "risk_accepted", "reopened"])

    def test_list_filters_and_shows_the_control_status(self):
        a = self.create()
        self.create(control_id="GV.OC-02", title="Second")
        self.svc.poam_close("bob", a["id"], "closed", "Charter approved.")
        self.svc.set("alice", CSF, "GV.OC-02", "not_implemented", "No process yet.", None)
        self.assertEqual(self.svc.poam_list("nist-csf", ["open"])["total"], 1)
        self.assertEqual(self.svc.poam_list("nist-csf", ["closed", "open"])["total"], 2)
        self.assertEqual(self.svc.poam_list("nist-csf", [], control_id="GV.OC-02")["items"][0]["control_status"], "not_implemented")
        with self.assertRaises(ValidationError):
            self.svc.poam_list("nist-csf", ["bogus"])
        self.assertEqual(self.svc.poam_list("other", [])["total"], 0)

    def test_unknown_ids_are_not_found(self):
        for bad in ("", "x", "pm_" + "0" * 32):
            with self.assertRaises(NotFoundError):
                self.svc.poam_close("bob", bad, "closed", "whatever it takes")


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.svc = AssessmentService(self.store, AuditService(self.store))

    def take(self, definition=None, label=""):
        from splunk_ucm.frameworks.coverage import CoverageService
        levels = CoverageService(self.store).use_case_levels()
        definition = definition or CSF
        cov = catalogue_coverage(definition, levels)
        return self.svc.snapshot("alice", definition, cov, {u["content_id"]: u for u in levels.values()}, label)

    def test_a_snapshot_freezes_the_state_with_a_hash_that_can_be_checked(self):
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        self.svc.poam_create("alice", CSF, dict(control_id="GV.OC-02", title="Process", weakness="No process yet.", owner="CISO",
                                                due="2099-01-01"))
        meta = self.take(label="Q4 review")
        self.assertEqual((meta["framework_id"], meta["label"], meta["created_by"], len(meta["sha256"])), ("nist-csf", "Q4 review", "alice", 64))
        got = self.svc.snapshot_get(meta["id"])
        self.assertTrue(got["integrity"]["ok"])
        content = json.loads(got["content"])
        self.assertEqual(content["format"], "ucm.assessment.snapshot/1")
        self.assertEqual({r["id"] for r in content["controls"]}, {"GV.OC-01", "GV.OC-02"})
        row = next(r for r in content["controls"] if r["id"] == "GV.OC-01")
        self.assertEqual((row["assessment"]["status"], row["assessment"]["assessed_by"]), ("implemented", "alice"))
        self.assertEqual(content["controls"][1]["poam"][0]["state"], "open")
        self.assertEqual(content["summary"]["assessed"], 1)
        self.assertIn("NIST", content["catalogue"]["attribution"])
        self.assertTrue(got["filename"].startswith("assessment-nist-csf-2.0-"))

    def test_a_later_change_does_not_alter_an_earlier_snapshot(self):
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        meta = self.take()
        self.svc.set("bob", CSF, "GV.OC-01", "not_implemented", "Charter was withdrawn.", None)
        got = self.svc.snapshot_get(meta["id"])
        self.assertEqual(json.loads(got["content"])["controls"][0]["assessment"]["status"], "implemented")
        self.assertEqual(got["sha256"], meta["sha256"])

    def test_tampering_with_a_stored_snapshot_is_detected(self):
        self.svc.set("alice", CSF, "GV.OC-01", "implemented", "Charter approved.", None)
        meta = self.take()
        doc = self.store.get(C.SNAPSHOTS, meta["id"])
        doc["content_json"] = doc["content_json"].replace('"implemented"', '"not_implemented"')
        self.store.upsert(C.SNAPSHOTS, doc)
        integrity = self.svc.snapshot_get(meta["id"])["integrity"]
        self.assertFalse(integrity["ok"])
        self.assertNotEqual(integrity["expected"], integrity["actual"])

    def test_objectives_and_score_are_in_the_snapshot(self):
        obj = [o["id"] for o in next(c for c in R3["controls"] if c["id"] == "03.01.01")["objectives"]]
        self.svc.set("alice", R3, "03.01.01", "", "Reviewed.", {obj[0]: "met", obj[1]: {"result": "not_met", "note": "gap"}})
        self.svc.set("alice", CMMC, "AC.L2-3.1.1", "implemented", "Verified.", None)
        content = json.loads(self.svc.snapshot_get(self.take(R3)["id"])["content"])
        self.assertEqual([o["result"] for o in content["controls"][0]["assessment"]["objectives"]], ["met", "not_met"])
        self.assertTrue(content["controls"][0]["assessment"]["objectives"][0]["text"])
        cmmc = json.loads(self.svc.snapshot_get(self.take(CMMC)["id"])["content"])
        self.assertEqual(cmmc["score"]["score"], -198)

    def test_the_list_has_no_content_and_newest_first(self):
        first = self.take(label="one")
        second = self.take(label="two")
        listed = self.svc.snapshots("nist-csf")
        self.assertEqual({s["id"] for s in listed}, {first["id"], second["id"]})
        self.assertTrue(all("content" not in s and "content_json" not in s for s in listed))

    def test_a_snapshot_limit_protects_the_store(self):
        old = A.MAX_SNAPSHOTS
        A.MAX_SNAPSHOTS = 2
        try:
            self.take()
            self.take()
            with self.assertRaises(ConflictError):
                self.take()
        finally:
            A.MAX_SNAPSHOTS = old

    def test_unknown_snapshot(self):
        for bad in ("", "sn_1", "sn_" + "0" * 32):
            with self.assertRaises(NotFoundError):
                self.svc.snapshot_get(bad)


class AssessmentApiTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.viewer = make_ctx(self.store, [])
        self.manager = make_ctx(self.store, ["ucm_manage_content", "ucm_deploy", "ucm_run_discovery", "ucm_admin"])
        self.assessor = make_ctx(self.store, ["ucm_assess"], user="carol")

    ROUTES = [("GET", "assessment", {"framework_id": "nist-csf"}), ("GET", "assessment/control", {"framework_id": "nist-csf", "control_id": "GV.OC-01"}),
              ("POST", "assessment", {}), ("POST", "assessment/clear", {}), ("POST", "assessment/snapshot", {}),
              ("GET", "assessment/snapshots", {"framework_id": "nist-csf"}), ("GET", "assessment/snapshot", {"id": "sn_x"}),
              ("GET", "poam", {"framework_id": "nist-csf"}), ("POST", "poam", {}), ("POST", "poam/update", {}),
              ("POST", "poam/close", {}), ("POST", "poam/reopen", {})]

    def test_every_route_needs_the_assessment_capability(self):
        for who in (self.viewer, self.manager):
            for method, path, query in self.ROUTES:
                body = {"framework_id": "nist-csf"} if method == "POST" else b""
                self.assertEqual(call(who, method, path, query if method == "GET" else None, body)[0], 403, (method, path))

    def test_an_assessor_records_and_reads_back(self):
        status, body = call(self.assessor, "POST", "assessment", body={
            "framework_id": "nist-csf", "control_id": "GV.OC-01", "status": "implemented", "note": "Charter approved."})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["assessment"]["assessed_by"], body["summary"]["assessed"]), ("carol", 1))
        status, body = call(self.assessor, "GET", "assessment", {"framework_id": "nist-csf"})
        self.assertEqual((status, body["assessments"]["GV.OC-01"]["status"]), (200, "implemented"))
        status, body = call(self.assessor, "GET", "assessment/control", {"framework_id": "nist-800-171", "control_id": "03.01.01"})
        self.assertEqual((status, len(body["control"]["objectives"]), body["assessment"]), (200, 22, None))
        self.assertEqual(call(self.assessor, "POST", "assessment", body={"framework_id": "nist-csf", "control_id": "GV.OC-01",
                                                                          "status": "implemented", "note": ""})[0], 400)
        status, body = call(self.assessor, "POST", "assessment/clear", body={"framework_id": "nist-csf", "control_id": "GV.OC-01",
                                                                              "note": "Entered in error."})
        self.assertEqual((status, body["summary"]["assessed"]), (200, 0))

    def test_score_is_in_the_response_only_for_a_scoring_catalogue(self):
        status, body = call(self.assessor, "GET", "assessment", {"framework_id": "cmmc-l2"})
        self.assertEqual((status, body["score"]["score"]), (200, -203))
        self.assertIsNone(call(self.assessor, "GET", "assessment", {"framework_id": "nist-csf"})[1]["score"])

    def test_attack_and_unknown_frameworks_are_refused(self):
        self.assertEqual(call(self.assessor, "GET", "assessment", {"framework_id": "mitre_attack_ics"})[0], 400)
        self.assertEqual(call(self.assessor, "GET", "assessment", {"framework_id": "nope"})[0], 404)
        self.assertEqual(call(self.assessor, "GET", "assessment")[0], 400)

    def test_poam_and_snapshot_through_the_api(self):
        status, body = call(self.assessor, "POST", "poam", body={
            "framework_id": "nist-csf", "control_id": "GV.OC-02", "title": "Write the process", "weakness": "No process.",
            "owner": "CISO", "due": "2020-01-01"})
        self.assertEqual((status, body["item"]["overdue"]), (200, True), body)
        item = body["item"]["id"]
        status, body = call(self.assessor, "GET", "poam", {"framework_id": "nist-csf", "overdue": "1"})
        self.assertEqual((status, body["total"], body["counts"]["overdue"]), (200, 1, 1))
        status, body = call(self.assessor, "POST", "poam/close", body={"id": item, "resolution": "closed", "note": "Process published."})
        self.assertEqual((status, body["item"]["state"]), (200, "closed"))
        status, body = call(self.assessor, "POST", "poam/reopen", body={"id": item, "note": "Reopened after review."})
        self.assertEqual(body["item"]["state"], "open")
        status, body = call(self.assessor, "POST", "poam/update", body={"id": item, "owner": "Head of IT"})
        self.assertEqual(body["item"]["owner"], "Head of IT")
        status, body = call(self.assessor, "POST", "assessment/snapshot", body={"framework_id": "nist-csf", "label": "api"})
        self.assertEqual(status, 200, body)
        snap = body["snapshot"]["id"]
        status, body = call(self.assessor, "GET", "assessment/snapshots", {"framework_id": "nist-csf"})
        self.assertEqual([s["id"] for s in body["items"]], [snap])
        status, body = call(self.assessor, "GET", "assessment/snapshot", {"id": snap})
        self.assertEqual((status, body["integrity"]["ok"]), (200, True))
        self.assertEqual(call(self.assessor, "GET", "assessment/snapshot", {"id": "sn_" + "0" * 32})[0], 404)

    def test_the_role_ships_the_capability(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "default", "authorize.conf")
        text = open(path, encoding="utf-8").read()
        self.assertIn("[capability::ucm_assess]", text)
        for role in ("role_ucm_compliance_assessor", "role_ucm_admin", "role_admin", "role_sc_admin"):
            block = text.split("[%s]" % role)[1].split("\n[")[0]
            self.assertIn("ucm_assess = enabled", block, role)
        viewer_block = text.split("[role_ucm_viewer]")[1].split("\n[")[0]
        self.assertNotIn("ucm_assess", viewer_block)
        self.assertEqual(assessment_key("a", "b"), assessment_key("a", "b"))
        self.assertNotEqual(assessment_key("a", "b"), assessment_key("a", "c"))


if __name__ == "__main__":
    unittest.main()

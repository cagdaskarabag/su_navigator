"""Informational POA&M eligibility for CMMC Level 2 (32 CFR 170.21, D-080)."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.frameworks import poam_rules as P
from splunk_ucm.frameworks.assessment import AssessmentService
from splunk_ucm.frameworks.registry import FrameworkRegistry
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx

REG = FrameworkRegistry(InMemoryStore())
CMMC = REG.get("cmmc-l2")
R3 = REG.get("nist-800-171")
TODAY = "2026-11-25"
NOTE = "Recorded for the test."


def flags(control, status="not_implemented", due="2026-12-31"):
    return P.item_flags(CMMC, control, status, due, TODAY)


class ItemRulesTest(unittest.TestCase):
    def test_a_one_point_requirement_is_eligible(self):
        out = flags("AC.L2-3.1.3")
        self.assertTrue(out["eligible"], out)
        self.assertEqual((out["point_value"], out["reasons"]), (1, []))
        self.assertIn("not a CMMC status determination", out["notice"])

    def test_a_five_point_requirement_is_not(self):
        out = flags("AC.L2-3.1.1")
        self.assertFalse(out["eligible"])
        self.assertEqual(out["point_value"], 5)
        self.assertIn("only requirements worth one point", out["reasons"][0])

    def test_partial_credit_is_not_one_point_either_except_for_encryption(self):
        self.assertFalse(flags("IA.L2-3.5.3", "partially_implemented")["eligible"])
        self.assertEqual(flags("IA.L2-3.5.3", "partially_implemented")["point_value"], 3)
        self.assertTrue(flags("SC.L2-3.13.11", "partially_implemented")["eligible"])
        out = flags("SC.L2-3.13.11", "not_implemented")
        self.assertFalse(out["eligible"])
        self.assertIn("3.13.11 is the exception", out["reasons"][0])

    def test_the_six_excluded_requirements_are_never_eligible(self):
        for control in P.EXCLUDED:
            with self.subTest(control=control):
                out = flags(control)
                self.assertFalse(out["eligible"])
                self.assertIn("six excluded requirements", out["reasons"][0])
        ids = {c["id"] for c in CMMC["controls"]}
        self.assertTrue(set(P.EXCLUDED) <= ids)

    def test_a_requirement_recorded_as_met_is_flagged(self):
        for status in ("implemented", "not_applicable"):
            out = flags("AC.L2-3.1.3", status)
            self.assertFalse(out["eligible"])
            self.assertIn("scored not met", out["reasons"][0])

    def test_a_due_date_beyond_180_days_is_flagged(self):
        self.assertEqual(flags("AC.L2-3.1.3")["closeout_deadline_if_awarded_today"], "2027-05-24")
        self.assertTrue(flags("AC.L2-3.1.3", due="2027-05-24")["eligible"])
        out = flags("AC.L2-3.1.3", due="2027-05-25")
        self.assertFalse(out["eligible"])
        self.assertIn("180 days", out["reasons"][0])

    def test_other_catalogues_have_no_such_rule(self):
        self.assertIsNone(P.item_flags(R3, "03.01.01", "not_implemented", "2026-12-01", TODAY))
        self.assertIsNone(P.item_flags(CMMC, "NOPE", "implemented", "2026-12-01", TODAY))
        self.assertIsNone(P.programme(R3, {"score": 1, "requirements": 2}))

    def test_the_weights_match_the_cited_rule(self):
        # 170.21(a)(2)(ii): only one-point requirements, so every other weight in the catalogue must exceed one
        by_id = {c["id"]: c for c in CMMC["controls"] if "weight" in c}
        counts = {w: sum(1 for c in by_id.values() if c["weight"] == w) for w in (0, 1, 3, 5)}
        self.assertEqual(counts, {0: 1, 1: 51, 3: 14, 5: 44})
        self.assertEqual(sum(c["weight"] for c in by_id.values()), 313)


class ProgrammeTest(unittest.TestCase):
    def test_the_threshold_is_point_eight_of_110(self):
        at = P.programme(CMMC, {"score": 88, "requirements": 110, "assessed": 110, "unassessed": 0})
        self.assertTrue(at["meets_threshold"])
        below = P.programme(CMMC, {"score": 87, "requirements": 110})
        self.assertFalse(below["meets_threshold"])
        self.assertEqual((below["threshold"], below["requirements"]), (0.8, 110))

    def test_no_score_no_programme(self):
        self.assertIsNone(P.programme(CMMC, None))
        self.assertIsNone(P.programme(CMMC, {"score": 0, "requirements": 0}))


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.svc = AssessmentService(self.store, AuditService(self.store))

    def plan(self, control, due="2026-12-31"):
        return self.svc.poam_create("alice", CMMC, {"control_id": control, "title": "Fix it", "weakness": "Gap in the control",
                                                    "owner": "bob", "due": due})

    def test_creating_an_ineligible_item_is_allowed_and_flagged_and_audited(self):
        item = self.plan("AC.L2-3.1.1")
        self.assertFalse(item["eligibility"]["eligible"])
        row = AuditService(self.store).recent(5, "poam.created")[0]
        self.assertIs(row["details"]["conditional_eligible"], False)
        self.assertIn("point value is 5", row["details"]["eligibility_reasons"][0])

    def test_the_list_carries_flags_and_the_programme(self):
        self.plan("AC.L2-3.1.3")
        self.plan("PE.L2-3.10.3")
        res = self.svc.poam_list("cmmc-l2", [], definition=CMMC)
        eligible = {i["control_id"]: i["eligibility"]["eligible"] for i in res["items"]}
        self.assertEqual(eligible, {"AC.L2-3.1.3": True, "PE.L2-3.10.3": False})
        self.assertEqual(res["programme"]["score"], -203)
        self.assertFalse(res["programme"]["meets_threshold"])

    def test_the_flag_follows_the_recorded_status_of_the_control(self):
        self.plan("AC.L2-3.1.3")
        self.svc.set("alice", CMMC, "AC.L2-3.1.3", "implemented", "Done and verified.", None)
        item = self.svc.poam_list("cmmc-l2", [], definition=CMMC)["items"][0]
        self.assertFalse(item["eligibility"]["eligible"])
        self.assertIn("recorded as implemented", item["eligibility"]["reasons"][0])

    def test_closed_items_carry_no_flag(self):
        item = self.plan("AC.L2-3.1.1")
        self.svc.poam_close("alice", item["id"], "closed", "Fixed and checked")
        self.assertIsNone(self.svc.poam_list("cmmc-l2", [], definition=CMMC)["items"][0]["eligibility"])

    def test_without_a_definition_nothing_is_added(self):
        self.plan("AC.L2-3.1.1")
        res = self.svc.poam_list("cmmc-l2", [])
        self.assertIsNone(res["programme"])
        self.assertIsNone(res["items"][0]["eligibility"])


class ApiTest(unittest.TestCase):
    def test_the_route_passes_the_catalogue_and_a_flagged_item_is_still_stored(self):
        store = InMemoryStore()
        ctx = make_ctx(store, ["ucm_assess", "ucm_read"])
        ctx.record_store = store
        status, body = call(ctx, "POST", "poam", body={"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.1", "title": "MFA",
                                                        "weakness": "No MFA yet", "owner": "bob", "due": "2026-12-31"})
        self.assertEqual(status, 200, body)
        self.assertFalse(body["item"]["eligibility"]["eligible"])
        status, body = call(ctx, "GET", "poam", {"framework_id": "cmmc-l2"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 1)
        self.assertIn("basis", body["programme"])
        self.assertEqual(len(store.query(C.POAM, None)), 1)


if __name__ == "__main__":
    unittest.main()


class ScoreFieldsTest(unittest.TestCase):
    def test_all_assessed_and_can_pass_are_separate_from_the_deprecated_complete(self):
        store = InMemoryStore()
        svc = AssessmentService(store, AuditService(store))
        score = svc.view(CMMC)["score"]
        self.assertEqual((score["all_assessed"], score["can_pass"], score["complete"]), (False, False, False))
        for control in CMMC["controls"]:
            if "weight" in control and not control.get("precondition"):
                svc.set("alice", CMMC, control["id"], "implemented", "Verified for the test.", None)
        score = svc.view(CMMC)["score"]
        self.assertEqual((score["all_assessed"], score["can_pass"], score["blocked_by"]), (False, False, ["CA.L2-3.12.4"]))
        svc.set("alice", CMMC, "CA.L2-3.12.4", "implemented", "The plan exists and is current.", None)
        score = svc.view(CMMC)["score"]
        self.assertEqual((score["all_assessed"], score["can_pass"], score["score"], score["complete"]), (True, True, 110, True))
        svc.set("alice", CMMC, "CA.L2-3.12.4", "not_implemented", "The plan was withdrawn.", None)
        score = svc.view(CMMC)["score"]
        self.assertEqual((score["all_assessed"], score["complete"], score["can_pass"]), (True, True, False))

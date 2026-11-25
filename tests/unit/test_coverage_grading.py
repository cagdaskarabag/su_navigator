import unittest

import helpers  # noqa: F401

from splunk_ucm.frameworks.coverage import CoverageService, LEVEL_WEIGHT, MATCH_WEIGHT
from splunk_ucm.storage.kvstore import InMemoryStore

DEFINITION = {
    "framework_id": "t", "version": "1", "name": "T", "domain": "enterprise", "revoked": {}, "deprecated": [],
    "tactics": [{"id": "TA1", "name": "Access"}, {"id": "TA2", "name": "Impact"}],
    "techniques": [
        {"id": "T1", "name": "Brute force", "tactics": ["TA1"]},
        {"id": "T1.001", "name": "Guessing", "tactics": ["TA1"], "parent": "T1"},
        {"id": "T1.002", "name": "Stuffing", "tactics": ["TA1"], "parent": "T1"},
        {"id": "T2", "name": "Wipe", "tactics": ["TA2"]},
        {"id": "T3", "name": "Exfil", "tactics": ["TA1", "TA2"]},
        {"id": "T4", "name": "Untouched", "tactics": ["TA2"]},
    ],
}


def uc(cid, mitre, level):
    return {"content_id": cid, "title": cid, "criticality": "high", "domains": [], "mitre_ids": mitre,
            "frameworks": [], "controls": [], "level": level}


def matrix(levels):
    return CoverageService(InMemoryStore()).attack_matrix(DEFINITION, {k: v for k, v in levels.items()})


def cells(m):
    out = {}
    for tac in m["tactics"]:
        for t in tac["techniques"]:
            out[t["id"]] = t
            for s in t["subs"]:
                out[s["id"]] = s
    return out


class GradeTest(unittest.TestCase):
    def test_direct_enabled_match_is_the_weighted_level(self):
        c = cells(matrix({"a": uc("a", ["T2"], "enabled")}))
        self.assertEqual((c["T2"]["grade"], c["T2"]["basis"]), (0.9, "direct"))

    def test_only_operational_reaches_one(self):
        self.assertEqual(cells(matrix({"a": uc("a", ["T2"], "operational")}))["T2"]["grade"], 1.0)
        self.assertLess(cells(matrix({"a": uc("a", ["T2"], "enabled")}))["T2"]["grade"], 1.0)

    def test_sub_technique_use_case_gives_its_parent_a_reduced_grade(self):
        c = cells(matrix({"a": uc("a", ["T1.001"], "enabled")}))
        self.assertEqual((c["T1.001"]["grade"], c["T1.001"]["basis"]), (0.9, "direct"))
        self.assertEqual((c["T1"]["grade"], c["T1"]["basis"]), (round(0.9 * MATCH_WEIGHT["sub"], 3), "sub"))
        self.assertEqual(c["T1.002"]["grade"], 0.0)

    def test_parent_use_case_gives_every_sub_technique_a_reduced_grade(self):
        c = cells(matrix({"a": uc("a", ["T1"], "deployed")}))
        self.assertEqual(c["T1"]["grade"], 0.5)
        for sub in ("T1.001", "T1.002"):
            self.assertEqual((c[sub]["grade"], c[sub]["basis"]), (round(0.5 * MATCH_WEIGHT["parent"], 3), "parent"))

    def test_best_single_use_case_wins_and_weak_ones_do_not_add_up(self):
        weak = {"w%d" % i: uc("w%d" % i, ["T2"], "ready") for i in range(10)}
        self.assertEqual(cells(matrix(weak))["T2"]["grade"], LEVEL_WEIGHT["ready"])
        strong = dict(weak, s=uc("s", ["T2"], "enabled"))
        self.assertEqual(cells(matrix(strong))["T2"]["grade"], 0.9)

    def test_catalogue_only_has_no_grade_and_counts_are_unchanged(self):
        m = matrix({"a": uc("a", ["T1.001"], "catalogue")})
        c = cells(m)
        self.assertEqual((c["T1.001"]["grade"], c["T1"]["grade"]), (0.0, 0.0))
        self.assertEqual((c["T1"]["counts"]["catalogue"], c["T1"]["via_sub"], c["T1"]["direct"]), (1, 1, 0))

    def test_average_grade_is_over_parent_techniques(self):
        m = matrix({"a": uc("a", ["T2"], "operational")})
        self.assertEqual(m["totals"]["techniques"], 4)
        self.assertEqual(m["totals"]["grade_avg"], 0.25)
        self.assertEqual(m["grading"]["match_weight"], MATCH_WEIGHT)


class GapTest(unittest.TestCase):
    def setUp(self):
        self.m = matrix({"r1": uc("r1", ["T2"], "ready"), "r2": uc("r2", ["T2"], "ready"),
                         "c": uc("c", ["T1.001"], "catalogue"), "e": uc("e", ["T3"], "enabled")})
        self.gaps = self.m["gaps"]

    def test_data_ready_but_not_deployed(self):
        self.assertEqual([g["id"] for g in self.gaps["data_ready"]], ["T2"])
        self.assertEqual((self.gaps["data_ready"][0]["ready"], self.gaps["data_ready"][0]["tactics"]), (2, ["Impact"]))

    def test_content_without_data_and_techniques_without_content(self):
        self.assertEqual([g["id"] for g in self.gaps["content_no_data"]], ["T1", "T1.001"])
        self.assertEqual([g["id"] for g in self.gaps["no_content"]], ["T1.002", "T4"])

    def test_a_technique_in_two_tactics_is_listed_once_with_both(self):
        m = matrix({"x": uc("x", ["T3"], "ready")})
        row = [g for g in m["gaps"]["data_ready"] if g["id"] == "T3"]
        self.assertEqual(len(row), 1)
        self.assertEqual(row[0]["tactics"], ["Access", "Impact"])

    def test_enabled_techniques_are_not_gaps(self):
        listed = {g["id"] for k in ("data_ready", "content_no_data", "no_content") for g in self.gaps[k]}
        self.assertNotIn("T3", listed)
        self.assertEqual(self.gaps["counts"], {"data_ready": 1, "content_no_data": 2, "no_content": 2})


if __name__ == "__main__":
    unittest.main()

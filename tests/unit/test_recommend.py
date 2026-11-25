import json
import random
import unittest

import helpers  # noqa: F401  (sets sys.path)

from splunk_ucm.errors import ValidationError
from splunk_ucm.frameworks.coverage import CoverageService
from splunk_ucm.readiness.recommend import (EMPTY_NO_ASSESSMENT, EMPTY_NO_CATALOGUE, EMPTY_NO_DISCOVERY,
                                            EMPTY_NONE_ELIGIBLE, MAX_ITEMS, WEIGHTS, RecommendationService,
                                            draft_score)
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx

RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
DISCOVERY = "2026-11-24T10:00:00Z"


def uc(store, n, state="ready", score=100, crit="high", mitre=(), coverage=1.0, status="active", assess=True,
       blockers=(), gaps=(), unverified=0, results=None, key=None):
    key = key or "fenre_UC-%d" % n
    cid = "fenre:UC-%d" % n
    store.upsert(C.CATALOG, {"_key": key, "content_id": cid, "title": "Use case %d" % n, "provider_status": status,
                             "criticality": crit, "domains": ["security"], "mitre_ids": list(mitre), "frameworks": [],
                             "framework_controls": []})
    if assess:
        store.upsert(C.READINESS, {
            "_key": key, "content_id": cid, "record_id": str(n), "title": "Use case %d" % n, "state": state,
            "score": score, "coverage": coverage, "blockers": list(blockers), "gaps": list(gaps),
            "counts": {"met": 3, "unverified": unverified}, "unverified": unverified, "requirement_count": 5,
            "criticality": crit, "criticality_rank": RANK[crit], "domains": ["security"], "results": results or []})
    return key, cid


def deploy(store, key, revision=1, live="enabled", state="deployed"):
    store.upsert(C.DEPLOYMENTS, {"_key": "dep_" + key, "catalog_key": key, "content_id": key, "state": state,
                                 "deployed_revision": revision, "live_status": live})


def select(store, user, key, intent):
    store.upsert(C.SELECTIONS, {"_key": "sel_%s_%s" % (user, key), "user": user, "catalog_key": key,
                                "content_id": key, "intent": intent})


def ids(out):
    return [i["content_id"] for i in out["items"]]


class FormulaTest(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(WEIGHTS.values()), 1.0)

    def test_documented_example(self):
        parts = draft_score(100, 3, 0.5, 1.0)
        self.assertEqual((parts["readiness"], parts["criticality"], parts["mitre_gain"], parts["coverage"]),
                         (40.0, 18.75, 10.0, 15.0))
        self.assertEqual(parts["total"], 83.75)

    def test_extremes_and_bad_input_stay_in_range(self):
        self.assertEqual(draft_score(100, 4, 1.0, 1.0)["total"], 100.0)
        self.assertEqual(draft_score(0, 0, 0.0, 0.0)["total"], 0.0)
        self.assertEqual(draft_score(None, None, 2.0, -1)["total"], 20.0)
        self.assertEqual(draft_score(500, 9, 0, 9)["total"], 40.0 + 25.0 + 15.0)


class EligibilityTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        uc(self.store, 1, "ready")
        uc(self.store, 2, "partially_ready", score=70)
        uc(self.store, 3, "not_ready", score=20)
        uc(self.store, 4, "blocked", score=None, blockers=[{"type": "index", "value": "x"}])
        uc(self.store, 5, "insufficient_evidence", score=None)
        uc(self.store, 6, "ready", status="withdrawn")
        uc(self.store, 7, "ready", assess=False)
        uc(self.store, 8, "partially_ready", score=60, blockers=[{"type": "sourcetype", "value": "x"}])
        self.svc = RecommendationService(self.store)

    def rec(self, user="alice", **kw):
        return self.svc.recommend(user, DISCOVERY, **kw)

    def test_only_ready_and_unblocked_partially_ready_active_assessed_entries(self):
        out = self.rec()
        self.assertEqual(sorted(ids(out)), ["fenre:UC-1", "fenre:UC-2"])
        self.assertEqual(out["eligible_total"], 2)
        self.assertEqual(out["excluded"], {"blocked": 1, "not_ready": 1, "insufficient_evidence": 1,
                                           "not_in_active_catalogue": 1, "has_blockers": 1})
        self.assertIsNone(out["empty"])

    def test_deployed_enabled_or_disabled_is_excluded_retired_is_not(self):
        for n, live in ((10, "enabled"), (11, "disabled"), (12, "missing"), (13, "unmanaged")):
            key, _ = uc(self.store, n)
            deploy(self.store, key, live=live)
        key, _ = uc(self.store, 14)
        deploy(self.store, key, revision=None, live="absent", state="retired")
        out = self.rec(limit=10)
        self.assertEqual(sorted(ids(out)), ["fenre:UC-1", "fenre:UC-14", "fenre:UC-2"])
        self.assertEqual(out["excluded"]["already_deployed"], 4)

    def test_same_deployed_logic_as_coverage(self):
        rnd = random.Random(7)
        for n in range(20, 40):
            key, _ = uc(self.store, n, crit=rnd.choice(list(RANK)), mitre=["T%d" % (1000 + n % 5)])
            if rnd.random() < 0.5:
                deploy(self.store, key, revision=rnd.choice([None, 1, 2]), live=rnd.choice(["enabled", "disabled", "absent"]))
        levels = CoverageService(self.store).use_case_levels()
        deployed = {k for k, v in levels.items() if v["level"] in ("deployed", "enabled", "operational")}
        out = self.svc.recommend("alice", DISCOVERY, limit=10)
        recommended = {i["content_id"] for i in out["items"]}
        self.assertFalse(recommended & {levels[k]["content_id"] for k in deployed})
        full = {levels[k]["content_id"] for k in levels
                if levels[k]["level"] not in ("deployed", "enabled", "operational")
                and self.store.get(C.READINESS, k) and self.store.get(C.READINESS, k)["state"] in ("ready", "partially_ready")
                and not self.store.get(C.READINESS, k)["blockers"]}
        self.assertEqual(out["eligible_total"], len(full))

    def test_deployment_in_progress_is_flagged_not_hidden(self):
        deploy(self.store, "fenre_UC-1", revision=None, live="absent", state="pending_approval")
        item = [i for i in self.rec()["items"] if i["content_id"] == "fenre:UC-1"][0]
        self.assertIn("deployment_in_progress", item["flags"])
        self.assertEqual(item["deployment_state"], "pending_approval")

    def test_rejected_by_the_caller_is_excluded(self):
        select(self.store, "alice", "fenre_UC-1", "reject")
        out = self.rec("alice")
        self.assertEqual(ids(out), ["fenre:UC-2"])
        self.assertEqual(out["excluded"]["rejected_by_you"], 1)

    def test_other_users_rejects_never_leak(self):
        select(self.store, "alice", "fenre_UC-1", "reject")
        select(self.store, "mallory", "fenre_UC-2", "reject")
        bob = self.rec("bob")
        self.assertEqual(sorted(ids(bob)), ["fenre:UC-1", "fenre:UC-2"])
        self.assertNotIn("rejected_by_you", bob["excluded"])
        text = json.dumps(bob)
        for name in ("alice", "mallory"):
            self.assertNotIn(name, text)
        alice = self.rec("alice")
        self.assertEqual(ids(alice), ["fenre:UC-2"])
        self.assertNotIn("mallory", json.dumps(alice))
        self.assertEqual(self.rec("")["eligible_total"], 2)

    def test_select_and_defer_stay_eligible_with_a_flag_and_no_boost(self):
        before = {i["content_id"]: i["draft_score"] for i in self.rec()["items"]}
        select(self.store, "alice", "fenre_UC-1", "select")
        select(self.store, "alice", "fenre_UC-2", "defer")
        after = self.rec("alice")
        flags = {i["content_id"]: i["flags"] for i in after["items"]}
        self.assertEqual(flags, {"fenre:UC-1": ["in_backlog"], "fenre:UC-2": ["deferred"]})
        self.assertEqual({i["content_id"]: i["draft_score"] for i in after["items"]}, before)
        select(self.store, "alice", "fenre_UC-1", "bookmark")
        self.assertEqual([i["flags"] for i in self.rec("alice")["items"] if i["content_id"] == "fenre:UC-1"], [["bookmarked"]])
        self.assertEqual(self.rec("bob")["items"][0]["flags"], [])


class OrderingTest(unittest.TestCase):
    def build(self, order=None):
        store = InMemoryStore()
        specs = [
            (1, dict(state="partially_ready", score=95, crit="critical", mitre=["T1", "T2"])),
            (2, dict(state="ready", score=90, crit="low")),
            (3, dict(state="ready", score=90, crit="low")),
            (4, dict(state="ready", score=100, crit="high")),
            (5, dict(state="ready", score=90, crit="medium")),
            (6, dict(state="ready", score=90, crit="low", mitre=["T9"])),
        ]
        for n, kw in (order and [specs[i] for i in order] or specs):
            uc(store, n, **kw)
        return store

    def test_ready_before_partially_ready_then_draft_score(self):
        out = RecommendationService(self.build()).recommend("u", DISCOVERY)
        self.assertEqual(ids(out)[-1], "fenre:UC-1", "partially ready comes after every ready use case")
        scores = [i["draft_score"] for i in out["items"][:-1]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(ids(out)[:2], ["fenre:UC-6", "fenre:UC-4"], "T9 is uncovered, so UC-6 scores 77.25 against 73.75")

    def test_ties_break_on_content_id_after_criticality_and_score(self):
        out = RecommendationService(self.build()).recommend("u", DISCOVERY)
        tied = [i for i in out["items"] if i["content_id"] in ("fenre:UC-2", "fenre:UC-3")]
        self.assertEqual(tied[0]["draft_score"], tied[1]["draft_score"])
        self.assertEqual([i["content_id"] for i in tied], ["fenre:UC-2", "fenre:UC-3"])

    def test_criticality_breaks_a_draft_score_tie(self):
        store = InMemoryStore()
        uc(store, 1, "ready", score=100, crit="medium", coverage=1.0)
        uc(store, 2, "ready", score=90, crit="high", coverage=0.85)
        out = RecommendationService(store).recommend("u", DISCOVERY)
        self.assertEqual([i["draft_score"] for i in out["items"]], [67.5, 67.5])
        self.assertEqual(ids(out), ["fenre:UC-2", "fenre:UC-1"], "high before medium")

    def test_deterministic_and_independent_of_insertion_order(self):
        first = RecommendationService(self.build()).recommend("u", DISCOVERY)
        again = RecommendationService(self.build()).recommend("u", DISCOVERY)
        shuffled = RecommendationService(self.build([5, 3, 0, 4, 1, 2])).recommend("u", DISCOVERY)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(again, sort_keys=True))
        self.assertEqual(ids(first), ids(shuffled))
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(shuffled, sort_keys=True))

    def test_at_most_ten_and_eligible_total_counts_all(self):
        store = InMemoryStore()
        for n in range(1, 26):
            uc(store, n)
        out = RecommendationService(store).recommend("u", DISCOVERY, limit=99)
        self.assertEqual((len(out["items"]), out["eligible_total"], MAX_ITEMS), (10, 25, 10))
        self.assertEqual(len(RecommendationService(store).recommend("u", DISCOVERY, limit=3)["items"]), 3)


class MitreGainTest(unittest.TestCase):
    def test_gain_is_the_share_of_techniques_no_deployed_use_case_covers(self):
        store = InMemoryStore()
        key, _ = uc(store, 1, mitre=["T1110", "T1078"])
        deploy(store, key)
        uc(store, 2, mitre=["T1110", "T1059", "T1003", "T1021"])
        uc(store, 3, mitre=["T1110", "T1078"])
        uc(store, 4, mitre=[])
        uc(store, 5, mitre=["T1555", "T1555"])
        # a ready but not deployed use case covers nothing
        out = {i["content_id"]: i for i in RecommendationService(store).recommend("u", DISCOVERY)["items"]}
        self.assertEqual(out["fenre:UC-2"]["mitre_new"], ["T1003", "T1021", "T1059"])
        self.assertEqual(out["fenre:UC-2"]["score_parts"]["mitre_gain"], 0.2 * 75)
        self.assertEqual(out["fenre:UC-3"]["mitre_new"], [])
        self.assertEqual(out["fenre:UC-3"]["score_parts"]["mitre_gain"], 0.0)
        self.assertEqual(out["fenre:UC-4"]["mitre_total"], 0)
        self.assertEqual(out["fenre:UC-4"]["score_parts"]["mitre_gain"], 0.0)
        self.assertEqual(out["fenre:UC-5"]["mitre_total"], 1)
        self.assertEqual(out["fenre:UC-5"]["score_parts"]["mitre_gain"], 20.0)

    def test_only_deployed_or_higher_cover(self):
        store = InMemoryStore()
        uc(store, 1, "ready", mitre=["T1"])
        uc(store, 2, "ready", mitre=["T1"])
        out = RecommendationService(store).recommend("u", DISCOVERY)
        self.assertTrue(all(i["mitre_new"] == ["T1"] for i in out["items"]), "ready is not deployed")


class ReasonsTest(unittest.TestCase):
    def test_reasons_come_from_stored_fields(self):
        store = InMemoryStore()
        uc(store, 1, "partially_ready", score=72, crit="critical", mitre=["T1", "T2"], coverage=0.8, unverified=2,
           gaps=[{"type": "sourcetype", "value": "wineventlog"}])
        out = RecommendationService(store).recommend("u", DISCOVERY)
        reasons = out["items"][0]["reasons"]
        self.assertIn("Readiness partially ready: score 72, 80% of the requirement weight decided.", reasons)
        self.assertIn("Criticality critical.", reasons)
        self.assertIn("2 of 2 mapped MITRE techniques are not covered by a deployed use case yet: T1, T2.", reasons)
        self.assertIn("3 of 5 requirements met.", reasons)
        self.assertTrue(any(r.startswith("2 requirements not verified yet") for r in reasons), reasons)
        self.assertIn("Unmet required: sourcetype wineventlog.", reasons)

    def test_unverified_count_is_always_stated(self):
        store = InMemoryStore()
        uc(store, 1, unverified=0)
        self.assertIn("No requirements are left unverified.", RecommendationService(store).recommend("u", DISCOVERY)["items"][0]["reasons"])

    def test_data_model_statement_only_when_the_stored_result_says_so(self):
        store = InMemoryStore()
        uc(store, 1)
        uc(store, 2, results=[{"type": "cim_model", "value": "Authentication", "status": "met", "code": "model_present"}])
        uc(store, 3, results=[{"type": "cim_model", "value": "Authentication", "status": "not_met", "code": "model_missing"}])
        out = {i["content_id"]: i["reasons"] for i in RecommendationService(store).recommend("u", DISCOVERY)["items"]}
        stmt = "Data model definition installed (populated data not verified)."
        self.assertIn(stmt, out["fenre:UC-2"])
        self.assertNotIn(stmt, out["fenre:UC-1"])
        self.assertNotIn(stmt, out["fenre:UC-3"])
        for reasons in out.values():
            text = " ".join(reasons).lower()
            self.assertNotIn("cim compliant", text)
            self.assertNotIn("data is populated", text)

    def test_mitre_wording_for_no_mapping_and_full_overlap(self):
        store = InMemoryStore()
        key, _ = uc(store, 1, mitre=["T1"])
        deploy(store, key)
        uc(store, 2, mitre=["T1"])
        uc(store, 3)
        out = {i["content_id"]: i["reasons"] for i in RecommendationService(store).recommend("u", DISCOVERY)["items"]}
        self.assertIn("All 1 mapped MITRE techniques are already covered by deployed use cases.", out["fenre:UC-2"])
        self.assertIn("No MITRE ATT&CK technique mapping is stored.", out["fenre:UC-3"])

    def test_many_techniques_are_truncated_with_a_count(self):
        store = InMemoryStore()
        uc(store, 1, mitre=["T10%02d" % n for n in range(8)])
        reason = [r for r in RecommendationService(store).recommend("u", DISCOVERY)["items"][0]["reasons"] if "MITRE" in r][0]
        self.assertIn("8 of 8", reason)
        self.assertTrue(reason.endswith("and 3 more."), reason)


class EmptyStateTest(unittest.TestCase):
    def test_four_distinct_states(self):
        store = InMemoryStore()
        svc = RecommendationService(store)
        self.assertEqual(svc.recommend("u", DISCOVERY)["empty"], EMPTY_NO_CATALOGUE)
        uc(store, 1, assess=False)
        self.assertEqual(svc.recommend("u", None)["empty"], EMPTY_NO_DISCOVERY)
        self.assertEqual(svc.recommend("u", DISCOVERY)["empty"], EMPTY_NO_ASSESSMENT)
        uc(store, 2, "not_ready", score=10)
        out = svc.recommend("u", DISCOVERY)
        self.assertEqual((out["empty"], out["items"], out["excluded"]), (EMPTY_NONE_ELIGIBLE, [], {"not_ready": 1}))
        uc(store, 3, "ready")
        self.assertIsNone(svc.recommend("u", DISCOVERY)["empty"])

    def test_all_rejected_is_none_eligible_with_the_reason_counted(self):
        store = InMemoryStore()
        uc(store, 1)
        select(store, "alice", "fenre_UC-1", "reject")
        out = RecommendationService(store).recommend("alice", DISCOVERY)
        self.assertEqual((out["empty"], out["excluded"]), (EMPTY_NONE_ELIGIBLE, {"rejected_by_you": 1}))

    def test_assessment_exists_but_discovery_missing_still_recommends(self):
        store = InMemoryStore()
        uc(store, 1)
        self.assertEqual(ids(RecommendationService(store).recommend("u", None)), ["fenre:UC-1"])


class ExcludeQualityTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.k1, _ = uc(self.store, 1)
        self.k2, _ = uc(self.store, 2, crit="low")
        self.k3, _ = uc(self.store, 3, crit="medium")
        self.store.upsert(C.CATALOG, dict(self.store.get(C.CATALOG, self.k1), quality_flags=["unreviewed"]))
        self.store.upsert(C.CATALOG, dict(self.store.get(C.CATALOG, self.k2), quality_flags=["ai_reviewed", "duplicate_spl"]))
        self.svc = RecommendationService(self.store)

    def test_default_is_unchanged_and_flags_do_not_matter(self):
        out = self.svc.recommend("alice", DISCOVERY)
        self.assertEqual(sorted(ids(out)), ["fenre:UC-1", "fenre:UC-2", "fenre:UC-3"])
        self.assertEqual(out["exclude_quality"], [])
        self.assertNotIn("quality_flagged", out["excluded"])
        self.assertEqual(out, self.svc.recommend("alice", DISCOVERY, exclude_quality=()))

    def test_excluding_leaves_out_flagged_use_cases_and_counts_them(self):
        out = self.svc.recommend("alice", DISCOVERY, exclude_quality=["ai_reviewed", "unreviewed"])
        self.assertEqual(ids(out), ["fenre:UC-3"])
        self.assertEqual(out["excluded"]["quality_flagged"], 2)
        self.assertEqual(out["eligible_total"], 1)
        self.assertEqual(out["exclude_quality"], ["ai_reviewed", "unreviewed"])

    def test_one_flag_only_removes_what_carries_it(self):
        out = self.svc.recommend("alice", DISCOVERY, exclude_quality=["unreviewed"])
        self.assertEqual(sorted(ids(out)), ["fenre:UC-2", "fenre:UC-3"])

    def test_everything_flagged_is_the_none_eligible_state(self):
        self.store.upsert(C.CATALOG, dict(self.store.get(C.CATALOG, self.k3), quality_flags=["unreviewed"]))
        out = self.svc.recommend("alice", DISCOVERY, exclude_quality=["unreviewed", "ai_reviewed"])
        self.assertEqual((out["items"], out["empty"]), ([], EMPTY_NONE_ELIGIBLE))

    def test_unknown_flag_is_refused(self):
        with self.assertRaises(ValidationError):
            self.svc.recommend("alice", DISCOVERY, exclude_quality=["nonsense"])

    def test_route_passes_the_option_and_rejects_bad_values(self):
        ctx = make_ctx(self.store, [], user="alice")
        status, body = call(ctx, "GET", "readiness/recommendations", query={"exclude_quality": "ai_reviewed,unreviewed"})
        self.assertEqual((status, ids(body)), (200, ["fenre:UC-3"]))
        status, _ = call(ctx, "GET", "readiness/recommendations", query={"exclude_quality": "bogus"})
        self.assertEqual(status, 400)
        status, body = call(ctx, "GET", "readiness/recommendations")
        self.assertEqual(len(ids(body)), 3)


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        uc(self.store, 1)
        uc(self.store, 2, crit="low")
        select(self.store, "alice", "fenre_UC-1", "reject")

    def test_route_uses_the_session_user_and_ignores_parameters(self):
        status, body = call(make_ctx(self.store, [], user="alice"), "GET", "readiness/recommendations")
        self.assertEqual(status, 200)
        self.assertEqual(ids(body), ["fenre:UC-2"])
        status, body = call(make_ctx(self.store, [], user="bob"), "GET", "readiness/recommendations", query={"user": "alice"})
        self.assertEqual(ids(body), ["fenre:UC-1", "fenre:UC-2"])
        self.assertEqual(body["formula"]["version"], "ucm.recommend/2")

    def test_count_is_bounded_and_validated(self):
        status, body = call(make_ctx(self.store, [], user="bob"), "GET", "readiness/recommendations", query={"count": "1"})
        self.assertEqual((status, len(body["items"]), body["eligible_total"]), (200, 1, 2))
        status, body = call(make_ctx(self.store, [], user="bob"), "GET", "readiness/recommendations", query={"count": "x"})
        self.assertEqual(status, 400)

    def test_does_not_write_anything(self):
        def snapshot():
            return json.dumps({k: v for k, v in self.store.collections.items() if v}, sort_keys=True)
        before = snapshot()
        call(make_ctx(self.store, [], user="bob"), "GET", "readiness/recommendations")
        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()

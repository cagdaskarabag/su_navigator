"""The hardening release: the eleven low-severity items of issue #51 (D-082)."""

import os
import re
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.config import AppConfig
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import UC, approved, service


def meta_stanza(name):
    with open(os.path.join(helpers.ROOT, "sunavigator", "metadata", "default.meta"), encoding="utf-8") as handle:
        text = handle.read()
    block = re.search(r"^\[%s\]\n((?:(?!\[).*\n?)*)" % re.escape(name), text, re.MULTILINE)
    return block.group(1)


def writers(name):
    access = re.search(r"write : \[ ([^\]]*) \]", meta_stanza(name)).group(1)
    return [w.strip() for w in access.split(",")]


class RolesAndAuditTest(unittest.TestCase):
    def test_item_1_ucm_admin_cannot_write_deployed_saved_searches(self):
        self.assertEqual(writers("savedsearches"), ["admin", "sc_admin"])

    def verified_rows(self, store):
        return [r for r in store.query("uc_audit", {}, limit=500) if r.get("action") == "deployment.verified"]

    def test_item_2_repeated_verify_writes_one_audit_row_per_window(self):
        svc, store, saved = service()
        approved(svc)
        svc.deploy("bob", UC)
        before = len(self.verified_rows(store))
        for _ in range(5):
            svc.verify("carol", UC)
        self.assertEqual(len(self.verified_rows(store)) - before, 1)

    def test_item_2_a_change_in_the_result_is_always_written(self):
        svc, store, saved = service()
        approved(svc)
        name = svc.deploy("bob", UC)["saved_search"]["name"]
        svc.verify("carol", UC)
        first = len(self.verified_rows(store))
        saved.items[name]["cron_schedule"] = "0 * * * *"
        svc.verify("carol", UC)
        svc.verify("carol", UC)
        self.assertEqual(len(self.verified_rows(store)) - first, 1)

    def test_item_2_window_zero_writes_every_time(self):
        svc, store, saved = service(verify_audit_window_seconds=0)
        approved(svc)
        svc.deploy("bob", UC)
        before = len(self.verified_rows(store))
        for _ in range(3):
            svc.verify("carol", UC)
        self.assertEqual(len(self.verified_rows(store)) - before, 3)

    def test_item_2_audit_verify_is_a_post_and_throttled(self):
        from splunk_ucm.storage.kvstore import InMemoryStore
        store = InMemoryStore()
        ctx = make_ctx(store, ["ucm_admin"], AppConfig({}))
        self.assertEqual(call(ctx, "GET", "audit/verify")[0], 405)
        for _ in range(4):
            status, body = call(ctx, "POST", "audit/verify")
            self.assertEqual(status, 200)
            self.assertTrue(body["ok"])
        rows = [r for r in store.query("uc_audit", {}, limit=50) if r.get("action") == "audit.verified"]
        self.assertEqual(len(rows), 1)

    def test_item_2_audit_verify_still_needs_a_capability(self):
        from splunk_ucm.storage.kvstore import InMemoryStore
        self.assertEqual(call(make_ctx(InMemoryStore(), []), "POST", "audit/verify")[0], 403)


class SaveTokenTest(unittest.TestCase):
    def test_item_3_two_saves_from_the_same_version_are_told_apart(self):
        from splunk_ucm.errors import ConflictError
        from splunk_ucm.storage import collections as C
        svc, store, _ = service()
        svc.save_draft("alice", UC, {})
        real = store.upsert
        rival_wrote = []

        def with_rival(collection, doc):
            real(collection, doc)
            if collection == C.DEPLOYMENTS and not rival_wrote:
                rival_wrote.append(True)
                other = dict(doc)
                other["save_token"] = "someone-else"
                real(collection, other)
        store.upsert = with_rival
        with self.assertRaises(ConflictError) as raised:
            svc.submit("alice", UC)
        self.assertEqual(raised.exception.details["code"], "concurrent_update_detected")

    def test_item_3_the_token_is_stored_but_not_returned(self):
        from splunk_ucm.deployment.service import deployment_key
        from splunk_ucm.storage import collections as C
        svc, store, _ = service()
        doc = svc.save_draft("alice", UC, {})
        self.assertNotIn("save_token", doc)
        stored = store.get(C.DEPLOYMENTS, deployment_key("fenre_UC-9.1.1"))
        self.assertTrue(stored["save_token"])
        first = stored["save_token"]
        svc.submit("alice", UC)
        self.assertNotEqual(store.get(C.DEPLOYMENTS, deployment_key("fenre_UC-9.1.1"))["save_token"], first)


class DraftAuditTest(unittest.TestCase):
    def draft_rows(self, store):
        return [r for r in store.query("uc_audit", {}, limit=500) if r.get("action") == "deployment.draft"]

    def test_item_4_the_draft_row_says_which_state_it_replaced(self):
        svc, store, _ = service()
        svc.save_draft("alice", UC, {})
        svc.save_draft("alice", UC, {"severity": "high"})
        svc.submit("alice", UC)
        svc.save_draft("mallory", UC, {"severity": "low"})
        rows = sorted(self.draft_rows(store), key=lambda r: r["time"])
        self.assertEqual([(r["details"]["from"], r["details"]["replaced_draft"]) for r in rows],
                         [("none", False), ("draft", True), ("pending_approval", False)])
        self.assertEqual(rows[-1]["actor"], "mallory")
        self.assertEqual(rows[-1]["details"]["revision"], 2)


class WildcardAndChainTest(unittest.TestCase):
    def check(self, allowed, pattern="fw_*", known=("fw_a", "fw_b", "fw_c")):
        from splunk_ucm.readiness.principal import PrincipalAccess, check_access
        principal = PrincipalAccess("svc", roles=["r"], allowed=allowed)
        scan = {"indexes": [pattern], "reads_indexes": True, "uses_default": False, "unverified": [], "sourcetypes": []}
        return check_access(principal, scan, [{"name": k} for k in known])

    def test_item_5_a_wildcard_the_account_only_partly_covers_is_partial(self):
        result = self.check(["fw_a"])
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["code"], "index_not_accessible")
        self.assertIn("fw_b", result["detail"])
        row = result["observed"][0]
        self.assertTrue(row["partial"] and row["searchable"])
        self.assertIn("matches 3 indexes", row["reason"])

    def test_item_5_a_wildcard_fully_covered_is_met_and_not_covered_is_not_met(self):
        self.assertEqual(self.check(["fw_*"])["status"], "met")
        self.assertEqual(self.check(["other"])["status"], "not_met")

    def test_item_5_the_verify_result_lists_the_rows_that_share_a_predecessor(self):
        from splunk_ucm.audit import AuditService, row_hash
        from splunk_ucm.storage import collections as C
        from splunk_ucm.storage.kvstore import InMemoryStore
        store = InMemoryStore()
        audit = AuditService(store)
        for i in range(3):
            audit.record("a", "deployment.draft", "deployment", "x%d" % i)
        rows = sorted(store.query(C.AUDIT, {}, limit=10), key=lambda r: r["time"])
        twin = {"_key": "zz", "time": rows[-1]["time"] + 0.5, "time_iso": "t", "actor": "b", "action": "deployment.twin",
                "object_type": "deployment", "object_id": "x", "outcome": "success", "details": {},
                "prev_hash": rows[-2]["hash"]}
        twin["hash"] = row_hash(twin)
        store.upsert(C.AUDIT, twin)
        result = audit.verify_chain()
        self.assertTrue(result["ok"])
        self.assertEqual(result["branches"], 1)
        self.assertEqual(sorted(r["action"] for r in result["branch_rows"]), ["deployment.draft", "deployment.twin"])
        clean = AuditService(InMemoryStore())
        clean.record("a", "x", "x", "x")
        self.assertEqual(clean.verify_chain()["branch_rows"], [])


class SplSplitTest(unittest.TestCase):
    def side_effects(self, spl):
        from splunk_ucm.spl.analysis import analyze
        return analyze(spl).side_effect_commands

    def test_item_6_a_backtick_inside_a_comment_does_not_hide_a_later_command(self):
        spl = "index=a [ ```a`b``` | makeresults | outputlookup x.csv ]"
        self.assertIn("outputlookup", self.side_effects(spl))

    def test_item_6_an_unpaired_backtick_hides_nothing(self):
        self.assertIn("outputlookup", self.side_effects("index=a ` | outputlookup x.csv"))
        self.assertIn("collect", self.side_effects("index=a | stats count ` | collect index=x"))
        self.assertIn("outputlookup", self.side_effects("index=a ```never closed | outputlookup x.csv"))

    def test_item_6_a_closed_comment_and_closed_macros_are_still_skipped(self):
        self.assertEqual(self.side_effects("index=a ```| outputlookup x``` | stats count"), [])
        self.assertEqual(self.side_effects("index=a `m` ``` note ``` `n(1)` | stats count"), [])
        self.assertIn("outputlookup", self.side_effects("index=a ```note``` | `m` | outputlookup x.csv"))

    def test_item_6_the_policy_refuses_the_case_from_the_review(self):
        from splunk_ucm.spl.policy import classify
        verdict = classify("index=a [ ```a`b``` | makeresults | outputlookup x.csv ]")
        self.assertIn("outputlookup", verdict.side_effects)


if __name__ == "__main__":
    unittest.main()

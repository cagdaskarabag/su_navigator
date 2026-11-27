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


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

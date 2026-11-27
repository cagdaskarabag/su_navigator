"""Sprint 21 (0.11.0, D-080): approval with an access gap, second person for overrides, audited refusals."""

import csv
import os
import unittest
from unittest import mock

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.config import AppConfig
from splunk_ucm.deployment.service import DeploymentService, DeploymentSettings
from splunk_ucm.errors import ConflictError, PermissionDenied, ValidationError
from splunk_ucm.readiness.principal import NOT_MET, SchedulerAccess
from splunk_ucm.refusals import MESSAGE_CHARS, RefusalAudit, clean_message, governed
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import FakeSavedSearches, UC
from unit.test_discovery import loaded_catalog
from unit.test_principal import FakeRoles, role
from unit.test_selection_validation import FakeParser

CUSTOM = {"spl_source": "custom", "custom_spl": "index=_internal sourcetype=scheduler | stats count by status",
          "cron": "*/5 * * * *"}
REASON = "Accepted: the role is being changed this week"


def build(**settings):
    store = loaded_catalog()
    store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "idx1", "kind": "index", "name": "_internal", "status": "active"})
    transport = FakeRoles({"ucm_scheduler": {"roles": ["r"]}}, {"r": role(imported={"allowed": ["*"]})})
    access = SchedulerAccess(store, transport, "ucm_scheduler")
    svc = DeploymentService(store, AuditService(store), FakeParser(), FakeSavedSearches(),
                            DeploymentSettings(**settings), access=access)
    return svc, store


def audit_rows(store, prefix=""):
    return [r for r in store.query(C.AUDIT, None, sort=[("time", 1)]) if r["action"].startswith(prefix)]


class ApprovalWithAnAccessGapTest(unittest.TestCase):
    def pending(self):
        svc, store = build()
        svc.save_draft("alice", UC, dict(CUSTOM))
        svc.submit("alice", UC)
        return svc, store

    def test_approving_a_revision_the_scheduler_cannot_read_needs_a_reason(self):
        svc, store = self.pending()
        with self.assertRaises(ConflictError) as ctx:
            svc.approve("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "access_gap_reason_required")
        self.assertIn("ucm_scheduler cannot search _internal", ctx.exception.message)
        with self.assertRaises(ConflictError):
            svc.approve("bob", UC, access_reason="short")
        self.assertEqual(svc.get(UC)["state"], "pending_approval")

    def test_the_reason_is_kept_on_the_revision_and_in_the_audit_row(self):
        svc, store = self.pending()
        doc = svc.approve("bob", UC, "ok", access_reason=REASON)
        gap = doc["revisions"][-1]["approved_with_access_gap"]
        self.assertEqual((gap["by"], gap["reason"], gap["code"]), ("bob", REASON, "index_not_accessible"))
        details = audit_rows(store, "deployment.approve")[0]["details"]
        self.assertEqual((details["scheduler_access"], details["access_gap_reason"]), (NOT_MET, REASON))

    def test_a_revision_the_scheduler_can_read_needs_no_reason(self):
        store = loaded_catalog()
        svc = DeploymentService(store, AuditService(store), FakeParser(), FakeSavedSearches(), DeploymentSettings())
        svc.save_draft("alice", UC, {"cron": "*/5 * * * *"})
        svc.submit("alice", UC)
        doc = svc.approve("bob", UC)
        self.assertNotIn("approved_with_access_gap", doc["revisions"][-1])


class OverrideNeedsASecondPersonTest(unittest.TestCase):
    def deployed(self, **settings):
        svc, store = build(**settings)
        svc.save_draft("alice", UC, dict(CUSTOM))
        svc.submit("alice", UC)
        svc.approve("bob", UC, access_reason=REASON)
        svc.deploy("bob", UC)
        return svc, store

    def test_the_default_is_on(self):
        self.assertTrue(DeploymentSettings().override_second_person)

    def test_one_person_cannot_override_and_enable_alone(self):
        svc, store = self.deployed()
        doc = svc.enable("bob", UC, REASON)
        self.assertEqual(doc["live"]["status"], "disabled")
        self.assertTrue(doc["enable_request_active"])
        with self.assertRaises(ConflictError) as ctx:
            svc.enable("bob", UC, REASON)
        self.assertEqual(ctx.exception.details["code"], "second_person_required")
        doc = svc.enable("carol", UC, "Reviewed the role change ticket")
        self.assertEqual(doc["live"]["status"], "enabled")
        self.assertEqual(doc["override"]["by"], "carol")
        details = audit_rows(store, "deployment.enable")[-1]["details"]
        self.assertEqual(details["requested_by"], "bob")
        self.assertEqual(audit_rows(store, "deployment.enable_requested")[0]["details"]["override_reason"], REASON)

    def test_the_confirmer_must_give_their_own_reason(self):
        svc, _ = self.deployed()
        svc.enable("bob", UC, REASON)
        with self.assertRaises(ConflictError):
            svc.enable("carol", UC)

    def test_self_approval_setting_lets_one_person_do_both(self):
        svc, _ = self.deployed(allow_self_approval=True)
        svc.enable("bob", UC, REASON)
        self.assertEqual(svc.enable("bob", UC, REASON)["live"]["status"], "enabled")

    def test_an_ungated_enable_stays_a_single_step(self):
        store = loaded_catalog()
        svc = DeploymentService(store, AuditService(store), FakeParser(), FakeSavedSearches(), DeploymentSettings())
        svc.save_draft("alice", UC, {"cron": "*/5 * * * *"})
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        svc.deploy("bob", UC)
        self.assertEqual(svc.enable("bob", UC)["live"]["status"], "enabled")

    def test_switching_it_off_restores_the_single_person_override(self):
        svc, _ = self.deployed(override_second_person=False)
        self.assertEqual(svc.enable("bob", UC, REASON)["live"]["status"], "enabled")


class FakeError(Exception):
    pass


def refused_ctx(store, caps=(), user="mallory", config=None):
    return make_ctx(store, list(caps), config=config, user=user)


class RefusedActionsAreAuditedTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()

    def rows(self):
        return audit_rows(self.store, "refused.")

    def test_a_refused_governance_request_leaves_a_row(self):
        ctx = refused_ctx(self.store)
        status, body = call(ctx, "POST", "deployment/approve", body={"id": UC, "note": "x" * 10})
        self.assertEqual(status, 403)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["action"], row["outcome"], row["actor"], row["object_id"], row["object_type"]),
                         ("refused.deployment.approve", "refused", "mallory", UC, "deployment"))
        self.assertEqual((row["details"]["code"], row["details"]["status"]), ("permission_denied", 403))
        self.assertTrue(row.get("hash"))

    def test_the_rows_stay_in_the_hash_chain(self):
        ctx = refused_ctx(self.store)
        call(ctx, "POST", "deployment/approve", body={"id": UC})
        call(ctx, "POST", "assessment", body={"framework_id": "cmmc-l2", "control_id": "AC.L2-3.1.1"})
        verdict = AuditService(self.store).verify_chain()
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict["chained"], 2)

    def test_assessment_poam_and_admin_routes_count(self):
        ctx = refused_ctx(self.store)
        for path in ("assessment", "assessment/clear", "poam", "poam/close", "frameworks/import", "import",
                     "catalog/reindex", "mappings", "sync", "dashboards/create"):
            self.assertEqual(call(ctx, "POST", path, body={"id": path})[0], 403, path)
        self.assertEqual(len(self.rows()), 10)

    def test_other_requests_are_not_audited(self):
        ctx = refused_ctx(self.store)
        call(ctx, "GET", "audit")
        call(ctx, "GET", "nope")
        call(ctx, "DELETE", "catalog")
        call(ctx, "POST", "selections", body={})
        call(ctx, "POST", "readiness", body={})
        self.assertEqual(self.rows(), [])

    def test_a_successful_request_is_not_a_refusal(self):
        ctx = refused_ctx(self.store, ["ucm_deploy"])
        status, _ = call(ctx, "POST", "deployment/draft", body={"id": "fenre:UC-none"})
        self.assertEqual(status, 404)
        self.assertEqual(self.rows(), [])

    def test_a_validation_refusal_is_recorded_with_its_code(self):
        ctx = refused_ctx(self.store, ["ucm_deploy"])
        status, _ = call(ctx, "POST", "deployment/approve", body=b"not json")
        self.assertEqual(status, 400)
        row = self.rows()[0]
        self.assertEqual((row["details"]["code"], row["object_id"]), ("validation_error", ""))

    def test_two_conflicts_with_different_reasons_are_two_refusals(self):
        audit = AuditService(self.store)
        refusals = RefusalAudit(audit, window=300)
        first = ConflictError("a", {"code": "readiness_gate"})
        second = ConflictError("b", {"code": "second_person_required"})
        self.assertTrue(refusals.record("op", "POST", "deployment/enable", first, {"id": UC}))
        self.assertTrue(refusals.record("op", "POST", "deployment/enable", second, {"id": UC}))
        self.assertIsNone(refusals.record("op", "POST", "deployment/enable", second, {"id": UC}))
        rows = sorted((r["details"]["code"], r["details"]["error"]) for r in self.rows())
        self.assertEqual(rows, [("readiness_gate", "conflict"), ("second_person_required", "conflict")])

    def clocked(self, clock):
        patcher = mock.patch("splunk_ucm.audit.epoch_now", lambda: clock[0])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_same_refusal_is_written_once_per_window(self):
        clock = [1000.0]
        self.clocked(clock)
        audit = AuditService(self.store)
        refusals = RefusalAudit(audit, window=300, now=lambda: clock[0])
        error = PermissionDenied("missing capability ucm_deploy")
        keys = [refusals.record("mallory", "POST", "deployment/approve", error, {"id": UC})]
        clock[0] += 10
        keys.append(refusals.record("mallory", "POST", "deployment/approve", error, {"id": UC}))
        self.assertEqual((bool(keys[0]), keys[1]), (True, None))
        clock[0] += 10
        self.assertTrue(refusals.record("mallory", "POST", "deployment/approve", error, {"id": "other"}))
        self.assertTrue(refusals.record("mallory", "POST", "deployment/reject", error, {"id": UC}))
        self.assertTrue(refusals.record("trudy", "POST", "deployment/approve", error, {"id": UC}))
        self.assertTrue(refusals.record("mallory", "POST", "deployment/approve", ConflictError("c"), {"id": UC}))
        clock[0] += 300
        self.assertTrue(refusals.record("mallory", "POST", "deployment/approve", error, {"id": UC}))
        self.assertEqual(len(self.rows()), 6)

    def test_one_user_is_capped_per_hour_and_the_cap_writes_one_marker(self):
        clock = [5000.0]
        self.clocked(clock)
        refusals = RefusalAudit(AuditService(self.store), window=0, per_actor=3, total=100, now=lambda: clock[0])
        error = PermissionDenied("denied")
        for i in range(10):
            refusals.record("mallory", "POST", "deployment/approve", error, {"id": "uc%d" % i})
            clock[0] += 1
        rows = self.rows()
        self.assertEqual([r["action"] for r in rows].count("refused.deployment.approve"), 3)
        markers = [r for r in rows if r["action"] == "refused.rate_limited"]
        self.assertEqual(len(markers), 1)
        self.assertEqual((markers[0]["actor"], markers[0]["details"]["scope"], markers[0]["details"]["limit"]),
                         ("mallory", "actor", 3))
        self.assertTrue(refusals.record("trudy", "POST", "deployment/approve", error, {"id": "x"}))

    def test_everyone_together_is_capped_and_the_window_reopens_after_an_hour(self):
        clock = [9000.0]
        self.clocked(clock)
        refusals = RefusalAudit(AuditService(self.store), window=0, per_actor=50, total=5, now=lambda: clock[0])
        error = PermissionDenied("denied")
        for i in range(30):
            refusals.record("user%d" % i, "POST", "deployment/approve", error, {"id": UC})
            clock[0] += 1
        rows = self.rows()
        self.assertEqual(len([r for r in rows if r["action"] != "refused.rate_limited"]), 5)
        markers = [r for r in rows if r["action"] == "refused.rate_limited"]
        self.assertEqual((len(markers), markers[0]["actor"], markers[0]["details"]["scope"]), (1, "system", "all"))
        clock[0] += 3700
        self.assertTrue(refusals.record("late", "POST", "deployment/approve", error, {"id": UC}))

    def test_total_rows_are_bounded_under_a_flood(self):
        ctx = refused_ctx(self.store, config=AppConfig({"audit": {"refusal_actor_per_hour": "5",
                                                                  "refusal_window_seconds": "0"}}))
        for i in range(60):
            call(ctx, "POST", "deployment/approve", body={"id": "uc%d" % i})
        self.assertLessEqual(len(self.rows()), 6)

    def test_the_setting_turns_it_off(self):
        ctx = refused_ctx(self.store, config=AppConfig({"audit": {"refusals": "false"}}))
        call(ctx, "POST", "deployment/approve", body={"id": UC})
        self.assertEqual(self.rows(), [])

    def test_a_failing_audit_store_never_changes_the_response(self):
        ctx = refused_ctx(self.store)

        def boom(*a, **kw):
            raise RuntimeError("kv down")
        ctx.audit.store.query = boom
        ctx.audit.store.upsert = boom
        status, body = call(ctx, "POST", "deployment/approve", body={"id": UC})
        self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))

    def test_messages_lose_query_strings_and_credentials(self):
        text = "webhook https://user:pw@evil.example/hook?token=SECRET&x=1 is not permitted " + "y" * 400
        out = clean_message(text)
        self.assertNotIn("SECRET", out)
        self.assertNotIn("pw@", out)
        self.assertLessEqual(len(out), MESSAGE_CHARS)

    def test_governed_matches_only_post_to_the_listed_routes(self):
        self.assertTrue(governed("POST", "deployment/enable"))
        self.assertTrue(governed("post", "assessment/snapshot"))
        self.assertTrue(governed("POST", "poam/update"))
        self.assertFalse(governed("GET", "deployment/enable"))
        self.assertFalse(governed("POST", "selections"))
        self.assertFalse(governed("POST", "validate"))


if __name__ == "__main__":
    unittest.main()


class FenreReportTest(unittest.TestCase):
    FINDINGS = [
        {"rule": "L002", "use_case": "2.6.58", "title": "A | title", "search": "primary", "command": "timechart",
         "call": "by a, b", "message": "m", "suggestion": "Use one field"},
        {"rule": "L001", "use_case": "2.6.9", "title": "T", "search": "cim", "command": "search",
         "call": 'match(_raw, "x|y")', "message": "m", "suggestion": "| where match(_raw, \"x|y\")"},
        {"rule": "L001", "use_case": "2.6.10", "title": "T2", "search": "primary", "command": "search",
         "call": "lower(f)", "message": "m", "suggestion": "s"},
    ]

    def setUp(self):
        import sys
        tools = os.path.join(os.path.dirname(__file__), "..", "..", "tools")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        import fenre_report
        self.mod = fenre_report

    def test_report_stands_alone_and_orders_use_cases_naturally(self):
        text = self.mod.report(self.FINDINGS, 10, 8, "abcd1234", "0.11.0", "### F-01 something\n")
        self.assertIn("`abcd1234`", text)
        self.assertIn("3 findings in 3 searches", text)
        self.assertLess(text.index("UC-2.6.9"), text.index("UC-2.6.10"))
        self.assertIn("### F-01 something", text)
        self.assertIn("A \\| title", text)
        self.assertNotIn("D-0", text)

    def test_csv_has_one_row_per_finding_and_keeps_pipes(self):
        import csv
        import io
        rows = list(csv.DictReader(io.StringIO(self.mod.csv_text(self.FINDINGS))))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]["construct"], 'match(_raw, "x|y")')
        self.assertEqual(rows[0]["use_case"], "UC-2.6.58")

    def test_shipped_report_matches_the_findings_file(self):
        base = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "upstream", "for-fenre-owner")
        with open(os.path.join(base, "fenre_content_findings.csv"), encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        with open(os.path.join(base, "FENRE_CONTENT_FINDINGS.md"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(len(rows), 155)
        self.assertIn("%d findings in" % len(rows), text)

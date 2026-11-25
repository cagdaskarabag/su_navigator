import unittest

import helpers  # noqa: F401

from splunk_ucm.audit import AuditService
from splunk_ucm.deployment import revisions as R
from splunk_ucm.errors import ConflictError, NotFoundError, ValidationError
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import UC, approved, service

BLOCKED = {"_key": "fenre_UC-9.1.1", "content_id": UC, "state": "blocked"}
READY = {"_key": "fenre_UC-9.1.1", "content_id": UC, "state": "ready"}


def deployed(**kw):
    svc, store, saved = service(**kw)
    approved(svc)
    svc.deploy("bob", UC)
    return svc, store, saved


def actions(svc, user="bob"):
    return svc.allowed_actions(svc.get(UC), user, ["ucm_deploy"])


class WithdrawTest(unittest.TestCase):
    def test_a_withdrawn_approval_cannot_be_deployed_and_needs_a_new_approval(self):
        svc, store, saved = service()
        approved(svc)
        self.assertIn("withdraw", actions(svc))
        doc = svc.withdraw("carol", UC, "the recipient list is wrong")
        self.assertEqual(doc["state"], "pending_approval")
        rev = doc["revisions"][-1]
        self.assertNotIn("approved_by", rev)
        self.assertEqual(rev["approval_withdrawn"][0]["approved_by"], "bob")
        with self.assertRaises(ConflictError):
            svc.deploy("bob", UC)
        self.assertEqual(saved.items, {})
        self.assertNotIn("deploy", actions(svc))
        with self.assertRaises(Exception):
            svc.approve("alice", UC)
        self.assertEqual(svc.approve("carol", UC)["state"], "approved")

    def test_it_needs_a_reason_and_an_approved_undeployed_revision(self):
        svc, _, _ = service()
        svc.save_draft("alice", UC, {})
        with self.assertRaises(ConflictError):
            svc.withdraw("bob", UC, "no approval yet")
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        with self.assertRaises(ValidationError):
            svc.withdraw("bob", UC, "x")
        svc.deploy("bob", UC)
        with self.assertRaises(ConflictError) as ctx:
            svc.withdraw("bob", UC, "too late for this")
        self.assertEqual(ctx.exception.details["code"], "invalid_transition")
        self.assertNotIn("withdraw", actions(svc))

    def test_without_required_approval_it_goes_back_to_draft(self):
        svc, _, _ = service(require_approval=False)
        svc.save_draft("alice", UC, {})
        svc.submit("alice", UC)
        doc = svc.withdraw("alice", UC, "not ready to go")
        self.assertEqual(doc["state"], "draft")
        self.assertNotIn("submitted_by", doc["revisions"][-1])

    def test_it_is_audited_with_who_had_approved(self):
        svc, store, _ = service()
        approved(svc)
        svc.withdraw("carol", UC, "the recipient list is wrong")
        event = AuditService(store).recent(1, "deployment.withdraw")[0]
        self.assertEqual((event["actor"], event["details"]["withdrawn_approval_of"]), ("carol", "bob"))


class SecondPersonTest(unittest.TestCase):
    def test_off_by_default_enabling_is_one_step(self):
        svc, _, _ = deployed()
        self.assertEqual(svc.enable("bob", UC)["live"]["status"], "enabled")

    def test_with_it_on_a_different_person_must_confirm(self):
        svc, store, saved = deployed(enable_second_person=True)
        doc = svc.enable("bob", UC)
        self.assertEqual(doc["live"]["status"], "disabled")
        self.assertTrue(doc["enable_request_active"])
        self.assertIn("cancel_enable", actions(svc))
        with self.assertRaises(ConflictError) as ctx:
            svc.enable("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "second_person_required")
        doc = svc.enable("carol", UC)
        self.assertEqual(doc["live"]["status"], "enabled")
        self.assertNotIn("enable_request", doc)
        event = AuditService(store).recent(1, "deployment.enable")[0]
        self.assertEqual((event["actor"], event["details"]["requested_by"]), ("carol", "bob"))
        self.assertTrue(AuditService(store).recent(5, "deployment.enable_requested"))

    def test_a_request_can_be_cancelled_and_expires(self):
        svc, store, _ = deployed(enable_second_person=True, enable_request_hours=1)
        svc.enable("bob", UC)
        svc.cancel_enable("bob", UC, "changed my mind")
        with self.assertRaises(ConflictError):
            svc.cancel_enable("bob", UC)
        svc.enable("bob", UC)
        doc = store.get(C.DEPLOYMENTS, "dep_fenre_UC-9.1.1")
        doc["enable_request"]["expires_at"] = "2020-01-01T00:00:00Z"
        store.upsert(C.DEPLOYMENTS, doc)
        self.assertFalse(svc.get(UC)["enable_request_active"])
        self.assertEqual(svc.enable("carol", UC)["live"]["status"], "disabled")

    def test_a_request_for_an_older_revision_does_not_count(self):
        svc, store, _ = deployed(enable_second_person=True)
        svc.enable("bob", UC)
        svc.save_draft("alice", UC, {"cron": "0 * * * *"})
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        svc.deploy("bob", UC)
        self.assertFalse(svc.get(UC)["enable_request_active"])
        self.assertEqual(svc.enable("carol", UC)["live"]["status"], "disabled")

    def test_the_gate_still_applies_to_both_people(self):
        svc, store, _ = deployed(enable_second_person=True)
        store.upsert(C.READINESS, BLOCKED)
        with self.assertRaises(ConflictError):
            svc.enable("bob", UC)
        svc.enable("bob", UC, "data arrives on Monday")
        with self.assertRaises(ConflictError):
            svc.enable("carol", UC)
        doc = svc.enable("carol", UC, "checked with the data owner")
        self.assertEqual(doc["override"]["by"], "carol")


class OverrideTest(unittest.TestCase):
    def test_an_override_is_recorded_with_an_expiry(self):
        svc, store, _ = deployed(override_days=7)
        store.upsert(C.READINESS, BLOCKED)
        doc = svc.enable("bob", UC, "data arrives on Monday")
        status = doc["override_status"]
        self.assertEqual((status["reason"], status["by"], status["expired"]), ("data arrives on Monday", "bob", False))
        self.assertTrue(status["expires_at"] > doc["override"]["at"])
        self.assertEqual(svc.pipeline()["override_active"], 1)

    def test_override_days_zero_never_expires(self):
        svc, store, _ = deployed(override_days=0)
        store.upsert(C.READINESS, BLOCKED)
        self.assertEqual(svc.enable("bob", UC, "data arrives on Monday")["override_status"]["expires_at"], "")

    def expire(self, svc, store):
        doc = store.get(C.DEPLOYMENTS, "dep_fenre_UC-9.1.1")
        doc["override"]["expires_at"] = "2020-01-01T00:00:00Z"
        store.upsert(C.DEPLOYMENTS, doc)

    def test_the_sweep_reminds_once_and_leaves_the_search_enabled(self):
        svc, store, saved = deployed()
        store.upsert(C.READINESS, BLOCKED)
        svc.enable("bob", UC, "data arrives on Monday")
        self.expire(svc, store)
        self.assertEqual(svc.sweep_overrides()["expired"], 1)
        self.assertEqual(svc.sweep_overrides()["expired"], 0)
        self.assertEqual(svc.get(UC)["live"]["status"], "enabled")
        self.assertTrue(svc.get(UC)["override_status"]["expired"])
        self.assertEqual(svc.pipeline()["override_expired"], 1)
        event = AuditService(store).recent(1, "deployment.override_expired")[0]
        self.assertEqual((event["actor"], event["outcome"], event["details"]["enabled_by"]),
                         ("system:override-expiry", "failure", "bob"))

    def test_the_sweep_can_disable_when_configured(self):
        svc, store, saved = deployed(override_expiry_action="disable")
        store.upsert(C.READINESS, BLOCKED)
        svc.enable("bob", UC, "data arrives on Monday")
        self.expire(svc, store)
        result = svc.sweep_overrides()
        self.assertEqual((result["expired"], result["disabled"]), (1, 1))
        doc = svc.get(UC)
        self.assertEqual(doc["live"]["status"], "disabled")
        self.assertIsNone(doc["override_status"])

    def test_an_override_is_dropped_when_its_reason_no_longer_holds(self):
        svc, store, _ = deployed()
        store.upsert(C.READINESS, BLOCKED)
        svc.enable("bob", UC, "data arrives on Monday")
        store.upsert(C.READINESS, READY)
        self.assertEqual(svc.sweep_overrides()["cleared"], 1)
        self.assertIsNone(svc.get(UC)["override_status"])
        self.assertEqual(svc.pipeline()["override_active"], 0)

    def test_disable_and_retire_clear_it(self):
        svc, store, _ = deployed()
        store.upsert(C.READINESS, BLOCKED)
        svc.enable("bob", UC, "data arrives on Monday")
        self.assertIsNone(svc.disable("bob", UC)["override_status"])
        svc.enable("bob", UC, "data arrives on Monday")
        self.assertIsNone(svc.retire("bob", UC)["override_status"])

    def test_verify_all_runs_the_sweep(self):
        svc, store, _ = deployed()
        store.upsert(C.READINESS, BLOCKED)
        svc.enable("bob", UC, "data arrives on Monday")
        self.expire(svc, store)
        self.assertEqual(svc.verify_all("system")["overrides_expired"], 1)


class OutcomeTest(unittest.TestCase):
    def test_set_clear_and_list(self):
        svc, store, _ = deployed()
        doc = svc.set_outcome("bob", UC, "needs_tuning", "fires on every admin login")
        self.assertEqual(doc["outcome"]["value"], "needs_tuning")
        self.assertEqual(svc.pipeline()["needs_tuning"], 1)
        self.assertEqual([i["content_id"] for i in svc.list(outcomes=["needs_tuning"])["items"]], [UC])
        self.assertEqual(svc.list(outcomes=["waiting_on_data"])["items"], [])
        svc.set_outcome("bob", UC, "waiting_on_data", "no sysmon yet")
        self.assertEqual((svc.pipeline()["needs_tuning"], svc.pipeline()["waiting_on_data"]), (0, 1))
        self.assertNotIn("outcome", svc.set_outcome("bob", UC, "none"))
        self.assertEqual(svc.pipeline()["waiting_on_data"], 0)

    def test_rules(self):
        svc, store, _ = service()
        approved(svc)
        with self.assertRaises(ConflictError):
            svc.set_outcome("bob", UC, "needs_tuning", "not deployed yet")
        svc.deploy("bob", UC)
        with self.assertRaises(ValidationError):
            svc.set_outcome("bob", UC, "needs_tuning", "x")
        with self.assertRaises(ValidationError):
            svc.set_outcome("bob", UC, "great", "all good here")
        with self.assertRaises(ValidationError):
            svc.list(outcomes=["bogus"])

    def test_retire_clears_it_and_it_is_audited(self):
        svc, store, _ = deployed()
        svc.set_outcome("bob", UC, "needs_tuning", "fires on every admin login")
        self.assertEqual(AuditService(store).recent(1, "deployment.outcome")[0]["details"]["outcome"], "needs_tuning")
        self.assertNotIn("outcome", svc.retire("bob", UC))
        self.assertEqual(svc.pipeline()["needs_tuning"], 0)


class PipelineTest(unittest.TestCase):
    def test_counts_follow_the_workflow(self):
        svc, store, _ = service()
        self.assertEqual(sum(svc.pipeline().values()), 0)
        svc.save_draft("alice", UC, {})
        self.assertEqual(svc.pipeline()["draft"], 1)
        svc.submit("alice", UC)
        self.assertEqual((svc.pipeline()["draft"], svc.pipeline()["pending_approval"]), (0, 1))
        svc.approve("bob", UC)
        self.assertEqual(svc.pipeline()["approved"], 1)
        svc.deploy("bob", UC)
        self.assertEqual((svc.pipeline()["deployed"], svc.pipeline()["enabled"]), (1, 0))
        svc.enable("bob", UC)
        self.assertEqual((svc.pipeline()["deployed"], svc.pipeline()["enabled"]), (0, 1))
        self.assertEqual(svc.summary()["pipeline"]["enabled"], 1)


class RevisionTest(unittest.TestCase):
    def revise(self, svc, cron):
        svc.save_draft("alice", UC, {"cron": cron})
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        svc.deploy("bob", UC)

    def test_trimmed_revisions_leave_a_stub_with_the_hash(self):
        svc, store, _ = service(max_revisions=2)
        for cron in ("*/5 * * * *", "*/10 * * * *", "*/15 * * * *", "*/20 * * * *", "*/30 * * * *"):
            self.revise(svc, cron)
        doc = svc.get(UC)
        kept = [r["rev"] for r in doc["revisions"]]
        stubs = [s["rev"] for s in doc["revision_log"]]
        self.assertEqual(sorted(kept + stubs), [1, 2, 3, 4, 5])
        self.assertTrue(stubs)
        stub = doc["revision_log"][0]
        self.assertTrue(stub["spl_hash"] and stub["approved_by"] == "bob" and stub["trimmed_at"])
        self.assertNotIn("spl", stub)

    def test_diff_shows_changed_settings_and_spl(self):
        svc, store, _ = service()
        self.revise(svc, "*/5 * * * *")
        svc.save_draft("alice", UC, {"cron": "0 * * * *", "severity": "critical", "spl_source": "custom",
                                     "custom_spl": "index=main sourcetype=x | head 5"})
        diff = svc.diff(UC, 2, 1)
        self.assertTrue(diff["available"])
        self.assertEqual((diff["from"]["rev"], diff["to"]["rev"]), (1, 2))
        fields = {f["field"]: (f["from"], f["to"]) for f in diff["fields"]}
        self.assertEqual(fields["cron"], ("*/5 * * * *", "0 * * * *"))
        self.assertEqual(fields["severity"][1], "critical")
        self.assertTrue(diff["spl"]["changed"])
        self.assertGreater(diff["spl"]["added"], 0)
        self.assertTrue(any(line.startswith("+index=main sourcetype=x") for line in diff["spl"]["lines"]))

    def test_diff_hides_webhook_paths(self):
        a = {"rev": 1, "spl": "x", "spl_hash": "h", "actions": {"webhook": {"url": "https://hooks.example.com/T1/secret"}}}
        b = {"rev": 2, "spl": "x", "spl_hash": "h", "actions": {"webhook": {"url": "https://hooks.example.com/T1/other"}}}
        out = R.diff_revisions(a, b)
        self.assertEqual(out["fields"][0]["field"], "actions")
        self.assertNotIn("secret", repr(out))
        self.assertNotIn("other", repr(out))

    def test_diff_of_a_trimmed_revision_says_what_remains(self):
        svc, store, _ = service(max_revisions=2)
        for cron in ("*/5 * * * *", "*/10 * * * *", "*/15 * * * *", "*/20 * * * *", "*/30 * * * *"):
            self.revise(svc, cron)
        doc = svc.get(UC)
        gone = doc["revision_log"][0]["rev"]
        latest = doc["revisions"][-1]["rev"]
        out = svc.diff(UC, gone, latest)
        self.assertFalse(out["available"])
        self.assertTrue(any(r.get("spl_hash") for r in out["revisions"]))
        with self.assertRaises(NotFoundError):
            svc.diff(UC, 99, latest)
        with self.assertRaises(ValidationError):
            svc.diff(UC, latest, latest)


class ConcurrencyTest(unittest.TestCase):
    def test_a_write_that_does_not_stick_is_reported(self):
        svc, store, _ = service()
        svc.save_draft("alice", UC, {})
        real = store.upsert
        calls = []

        def lose(collection, doc):
            calls.append(collection)
            if collection == C.DEPLOYMENTS:
                stored = dict(doc)
                stored["version"] = doc["version"] + 7
                return real(collection, stored)
            return real(collection, doc)
        store.upsert = lose
        with self.assertRaises(ConflictError) as ctx:
            svc.submit("alice", UC)
        self.assertEqual(ctx.exception.details["code"], "concurrent_update_detected")


class ApiTest(unittest.TestCase):
    def test_actions_are_capability_gated_and_the_diff_is_readable(self):
        svc, store, _ = deployed()
        viewer = make_ctx(store, [])
        for action, body in (("withdraw", {"id": UC, "note": "no reason needed"}),
                             ("cancel_enable", {"id": UC}), ("outcome", {"id": UC, "outcome": "none"})):
            self.assertEqual(call(viewer, "POST", "deployment/" + action, body=body)[0], 403, action)
        status, body = call(viewer, "GET", "deployment/diff", {"id": UC, "from": "1", "to": "2"})
        self.assertIn(status, (404, 200, 400))
        status, body = call(viewer, "GET", "deployments", {"summary": "1"})
        self.assertEqual(status, 200)
        self.assertIn("pipeline", body["summary"])
        self.assertEqual(call(viewer, "GET", "deployments", {"outcome": "bogus"})[0], 400)


if __name__ == "__main__":
    unittest.main()

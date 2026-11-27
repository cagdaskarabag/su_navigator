import unittest

import helpers  # noqa: F401
from splunk_ucm.deployment import actions as A
from splunk_ucm.deployment.actions import ActionPolicy, normalize_actions, parse_list
from splunk_ucm.deployment.spec import drift, settings_for, spl_hash
from splunk_ucm.errors import ConflictError, PermissionDenied, ValidationError
from unit.test_deployment import UC, FakeSavedSearches, service

POLICY = ActionPolicy(email_domains=("example.com", "*.corp.example"), webhook_hosts=("hooks.example.com", "*.chat.example"))
EMAIL = {"email": {"to": "SOC@Example.com, lead@team.corp.example", "subject": "Alert $name$", "message": "Check it"}}
HOOK = {"webhook": {"url": "https://hooks.example.com/services/T1/B2/secret"}}


def norm(raw, mode="track", suppress="1h", policy=POLICY):
    return normalize_actions(raw, policy, mode, suppress)


class ValidationTest(unittest.TestCase):
    def test_nothing_requested_is_empty(self):
        for raw in (None, {}, [], "", {"email": {"enabled": False, "to": "a@example.com"}}):
            self.assertEqual(norm(raw), {})

    def test_email_is_normalised_and_checked_against_the_domain_list(self):
        out = norm(EMAIL)
        self.assertEqual(out["email"]["to"], ["soc@example.com", "lead@team.corp.example"])
        self.assertTrue(out["email"]["include_link"])
        for bad in ("nobody@evil.test", "not-an-address", "a@b", "x@example.com.evil.test", "a b@example.com"):
            with self.assertRaises(ValidationError, msg=bad):
                norm({"email": {"to": bad}})
        with self.assertRaises(ValidationError):
            norm({"email": {"to": ""}})
        with self.assertRaises(ValidationError):
            norm({"email": {"to": ",".join("u%d@example.com" % i for i in range(11))}})

    def test_wildcard_domain_needs_a_subdomain(self):
        norm({"email": {"to": "a@x.corp.example"}})
        with self.assertRaises(ValidationError):
            norm({"email": {"to": "a@corp.example"}})

    def test_subject_and_message_are_single_line_and_bounded(self):
        for field, value in (("subject", "a\nBcc: x@evil.test"), ("subject", "s" * 201), ("message", "m" * 1001)):
            with self.assertRaises(ValidationError, msg=field):
                norm({"email": {"to": "a@example.com", field: value}})

    def test_webhook_url_rules(self):
        self.assertEqual(norm(HOOK)["webhook"]["url"], HOOK["webhook"]["url"])
        norm({"webhook": {"url": "https://a.chat.example/x"}})
        for bad in ("http://hooks.example.com/x", "https://evil.test/x", "https://user:pw@hooks.example.com/x",
                    "https://hooks.example.com.evil.test/x", "ftp://hooks.example.com/x", "https://hooks.example.com/x#f",
                    "https://hooks.example.com:99999/x", "https://hooks.example.com/ x", "", "https://chat.example/x"):
            with self.assertRaises(ValidationError, msg=bad):
                norm({"webhook": {"url": bad}})

    def test_http_only_when_the_administrator_allows_it(self):
        lenient = ActionPolicy(webhook_hosts=("hooks.example.com",), webhook_allow_http=True)
        self.assertTrue(norm({"webhook": {"url": "http://hooks.example.com/x"}}, policy=lenient))

    def test_empty_allowlists_deny_everything(self):
        closed = ActionPolicy()
        for raw in (EMAIL, HOOK):
            with self.assertRaises(ValidationError):
                norm(raw, policy=closed)

    def test_master_switch_mode_and_suppression(self):
        with self.assertRaises(ValidationError):
            norm(EMAIL, policy=ActionPolicy(enabled=False, email_domains=("example.com",)))
        with self.assertRaises(ValidationError):
            norm(EMAIL, mode="none")
        with self.assertRaises(ValidationError):
            norm(EMAIL, suppress="")
        relaxed = ActionPolicy(email_domains=("example.com", "*.corp.example"), require_suppression=False)
        self.assertTrue(norm(EMAIL, suppress="", policy=relaxed))

    def test_other_action_kinds_are_refused_not_ignored(self):
        for kind in ("script", "logevent", "summary_index", "lookup"):
            with self.assertRaises(ValidationError, msg=kind):
                norm({kind: {"x": "y"}})
        with self.assertRaises(ValidationError):
            norm("email")

    def test_list_parsing_drops_invalid_entries(self):
        self.assertEqual(parse_list("Example.com; *.corp.example , bad entry, ,x_y"), ("example.com", "*.corp.example"))
        self.assertEqual(parse_list(""), ())


class SettingsAndDriftTest(unittest.TestCase):
    REV = {"rev": 1, "spl": "index=main", "cron": "*/5 * * * *", "earliest": "-5m", "latest": "now",
           "alert_mode": "track", "threshold": 0, "severity": "high", "spl_hash": "x"}

    def settings(self, actions):
        return settings_for(dict(self.REV, actions=actions), UC)

    def test_email_and_webhook_keys_never_send_results(self):
        s = self.settings(norm(dict(EMAIL, **HOOK)))
        self.assertEqual(s["actions"], "email,webhook")
        self.assertEqual((s["action.email"], s["action.webhook"]), ("1", "1"))
        self.assertEqual(s["action.email.to"], "soc@example.com,lead@team.corp.example")
        self.assertEqual(s["action.webhook.param.url"], HOOK["webhook"]["url"])
        for key in ("sendresults", "sendcsv", "sendpdf", "inline"):
            self.assertEqual(s["action.email." + key], "0")
        self.assertEqual(s["action.email.include.results_link"], "1")

    def test_removing_actions_switches_them_off(self):
        s = self.settings({})
        self.assertEqual((s["actions"], s["action.email"], s["action.webhook"]), ("", "0", "0"))

    def test_a_revision_from_before_actions_existed_leaves_them_alone(self):
        self.assertFalse(any(k.startswith("action") for k in settings_for(self.REV, UC)))

    def live(self, acts, **over):
        base = {"search": "index=main", "cron_schedule": "*/5 * * * *", "dispatch.earliest_time": "-5m",
                "dispatch.latest_time": "now", "is_scheduled": True, "disabled": True}
        base.update({k: v for k, v in self.settings(acts).items() if k not in ("search", "description", "disabled")})
        base.update(over)
        return base

    def test_matching_live_search_has_no_drift(self):
        for actions in ({}, norm(EMAIL), norm(dict(EMAIL, **HOOK))):
            rev = dict(self.REV, actions=actions, spl_hash=spl_hash("index=main"))
            self.assertEqual(drift(rev, self.live(actions), True), [], actions)

    def test_drift_is_reported_for_each_change(self):
        actions = norm(dict(EMAIL, **HOOK))
        self.assertEqual(A.drift(actions, self.live(actions, **{"actions": "email"}))[0]["field"], "actions")
        self.assertEqual(A.drift(actions, self.live(actions, **{"action.email.to": "x@example.com"}))[0]["field"],
                         "action.email.to")
        self.assertEqual(A.drift(actions, self.live(actions, **{"action.email.subject": "other"}))[0]["field"],
                         "action.email.subject")
        self.assertEqual(A.drift(actions, self.live(actions, **{"action.webhook.param.url": "https://x.test/"}))[0]["field"],
                         "action.webhook.param.url")
        self.assertEqual(A.drift(actions, self.live(actions, **{"action.email.sendresults": "1"}))[0]["field"],
                         "action.email.sendresults")
        self.assertEqual(A.drift({}, {"actions": "email"})[0]["field"], "actions")

    def test_email_message_and_results_link_edits_are_reported(self):
        actions = norm(EMAIL)
        message = A.drift(actions, self.live(actions, **{"action.email.message.alert": "Ignore this alert"}))
        self.assertEqual([d["field"] for d in message], ["action.email.message.alert"])
        self.assertNotIn("Ignore", repr(message))
        link = A.drift(actions, self.live(actions, **{"action.email.include.results_link": "0"}))
        self.assertEqual([d["field"] for d in link], ["action.email.include.results_link"])
        for same in ("1", 1, True, "true", "True"):
            self.assertEqual(A.drift(actions, self.live(actions, **{"action.email.include.results_link": same})), [])
        off = norm({"email": dict(EMAIL["email"], include_link=False)})
        self.assertEqual(A.drift(off, self.live(off)), [])
        self.assertEqual([d["field"] for d in A.drift(off, self.live(off, **{"action.email.include.results_link": "1"}))],
                         ["action.email.include.results_link"])

    def test_audit_summary_has_no_webhook_path(self):
        out = A.summary(norm(dict(EMAIL, **HOOK)))
        self.assertEqual(out["webhook"], {"host": "hooks.example.com"})
        self.assertEqual(out["email"], {"recipients": 2, "domains": ["example.com", "team.corp.example"]})
        self.assertNotIn("secret", repr(out))


def with_actions(**over):
    return service(actions=POLICY, **over)


class WorkflowTest(unittest.TestCase):
    BODY = {"cron": "*/5 * * * *", "suppress_period": "1h", "actions": dict(EMAIL, **HOOK)}

    def drafted(self, svc):
        svc.save_draft("alice", UC, self.BODY)
        return svc.submit("alice", UC)

    def test_draft_stores_validated_actions_and_audits_only_their_summary(self):
        svc, store, saved = with_actions()
        doc = svc.save_draft("alice", UC, self.BODY)
        self.assertEqual(doc["revisions"][-1]["actions"]["email"]["to"][0], "soc@example.com")
        events = [e for e in store.query("uc_audit", {}) if e["action"] == "deployment.draft"]
        self.assertEqual(events[-1]["details"]["actions"]["webhook"], {"host": "hooks.example.com"})
        self.assertNotIn("secret", repr(events))

    def test_a_draft_with_a_disallowed_destination_is_refused(self):
        svc, _, _ = with_actions()
        with self.assertRaises(ValidationError):
            svc.save_draft("alice", UC, dict(self.BODY, actions={"email": {"to": "a@evil.test"}}))
        closed, _, _ = service()
        with self.assertRaises(ValidationError):
            closed.save_draft("alice", UC, self.BODY)

    def test_the_approver_must_acknowledge_the_actions(self):
        svc, _, _ = with_actions()
        self.drafted(svc)
        with self.assertRaises(ConflictError) as ctx:
            svc.approve("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "actions_acknowledgment_required")
        doc = svc.approve("bob", UC, acknowledge_actions=True)
        rev = doc["revisions"][-1]
        self.assertEqual(rev["actions_acknowledged_by"], "bob")
        self.assertEqual(rev["actions_acknowledged_digest"], A.digest(rev["actions"]))

    def test_submitter_still_cannot_approve_their_own_actions(self):
        svc, _, _ = with_actions()
        self.drafted(svc)
        with self.assertRaises(PermissionDenied):
            svc.approve("alice", UC, acknowledge_actions=True)

    def test_deploy_writes_actions_disabled_and_verifies_them(self):
        svc, _, saved = with_actions()
        self.drafted(svc)
        svc.approve("bob", UC, acknowledge_actions=True)
        doc = svc.deploy("bob", UC)
        self.assertEqual(doc["state"], "deployed")
        name = doc["saved_search"]["name"]
        live = saved.items[name]
        self.assertTrue(live["disabled"])
        self.assertEqual(live["actions"], "email,webhook")
        self.assertEqual(live["action.webhook.param.url"], HOOK["webhook"]["url"])
        self.assertEqual(doc["live"]["drift"], [])
        live["action.email.to"] = "attacker@example.com"
        self.assertIn("action.email.to", [d["field"] for d in svc.verify("bob", UC)["live"]["drift"]])

    def test_policy_tightening_after_approval_blocks_deploy_and_enable(self):
        svc, store, saved = with_actions()
        self.drafted(svc)
        svc.approve("bob", UC, acknowledge_actions=True)
        svc.settings.actions = ActionPolicy(email_domains=("other.example",), webhook_hosts=("hooks.example.com",))
        with self.assertRaises(ConflictError) as ctx:
            svc.deploy("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "actions_not_allowed")
        self.assertEqual([c for c in saved.calls if c[0] in ("create", "update")], [])

    def test_changed_actions_after_approval_are_not_deployed(self):
        svc, store, _ = with_actions()
        self.drafted(svc)
        svc.approve("bob", UC, acknowledge_actions=True)
        stored = svc._require(UC)
        stored["revisions"][-1]["actions"]["email"]["to"] = ["attacker@example.com"]
        svc._save(stored, "x")
        with self.assertRaises(ConflictError) as ctx:
            svc.deploy("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "unacknowledged_actions")

    def test_without_actions_nothing_extra_is_asked(self):
        svc, _, saved = with_actions()
        svc.save_draft("alice", UC, {"cron": "*/5 * * * *"})
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        doc = svc.deploy("bob", UC)
        live = saved.items[doc["saved_search"]["name"]]
        self.assertEqual((live["actions"], live["action.email"], live["action.webhook"]), ("", "0", "0"))
        self.assertEqual(doc["live"]["drift"], [])

    def test_without_four_eyes_the_submitter_acknowledges(self):
        svc, _, _ = with_actions(require_approval=False)
        svc.save_draft("alice", UC, self.BODY)
        with self.assertRaises(ConflictError):
            svc.submit("alice", UC)
        doc = svc.submit("alice", UC, acknowledge_actions=True)
        self.assertEqual(doc["revisions"][-1]["actions_acknowledged_by"], "alice")


if __name__ == "__main__":
    unittest.main()

import datetime
import unittest
from urllib.parse import unquote

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.config import AppConfig
from splunk_ucm.deployment.savedsearch import MANAGED_MARKER
from splunk_ucm.deployment.service import DeploymentService, DeploymentSettings, deployment_key
from splunk_ucm.deployment.spec import normalize_spec, saved_search_name, settings_for, spl_hash, validate_cron
from splunk_ucm.deployment.worker import DeploymentWorker, STATE_KEY
from splunk_ucm.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog
from unit.test_selection_validation import FakeParser

UC = "fenre:UC-9.1.1"


class FakeSavedSearches:
    """In-memory stand-in for /servicesNS/nobody/<app>/saved/searches with the fields we read."""

    app = "sunavigator"

    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail_next = None
        self.ignore_disabled = False

    def get(self, name):
        item = self.items.get(name)
        return None if item is None else dict(item)

    def create(self, name, settings):
        self.calls.append(("create", name))
        self._maybe_fail()
        if name in self.items:
            raise ConflictError("exists")
        item = {"name": name, "owner": "op", "sharing": "app", "app": self.app, "is_scheduled": False,
                "disabled": False}
        self._apply(item, settings)
        self.items[name] = item

    def update(self, name, settings):
        self.calls.append(("update", name, dict(settings)))
        self._maybe_fail()
        if name not in self.items:
            raise NotFoundError("missing")
        self._apply(self.items[name], settings)

    def delete(self, name):
        self.calls.append(("delete", name))
        return self.items.pop(name, None) is not None

    def _maybe_fail(self):
        if self.fail_next:
            exc, self.fail_next = self.fail_next, None
            raise exc

    def _apply(self, item, settings):
        for k, v in settings.items():
            if k == "disabled":
                if not self.ignore_disabled:
                    item["disabled"] = v == "1"
            elif k == "is_scheduled":
                item["is_scheduled"] = v == "1"
            else:
                item[k] = v


def service(store=None, saved=None, parser=None, **kw):
    store = store or loaded_catalog()
    saved = saved or FakeSavedSearches()
    svc = DeploymentService(store, AuditService(store), parser or FakeParser(), saved, DeploymentSettings(**kw))
    return svc, store, saved


def approved(svc, uc=UC):
    svc.save_draft("alice", uc, {"cron": "*/5 * * * *", "severity": "high"})
    svc.submit("alice", uc)
    return svc.approve("bob", uc)


class SpecTest(unittest.TestCase):
    def test_cron_and_times(self):
        self.assertEqual(validate_cron(" */5  * * * 1-5 "), "*/5 * * * 1-5")
        for bad in ("@daily", "* * * *", "*/5 * * * * *", "a b c d e", "*/5 * * * ;rm"):
            with self.assertRaises(ValidationError):
                validate_cron(bad)
        spec = normalize_spec({"earliest": "-1h@h", "latest": "@h"}, {})
        self.assertEqual((spec["earliest"], spec["latest"]), ("-1h@h", "@h"))
        for bad in ({"earliest": "rt-5m"}, {"latest": "now|delete"}, {"spl_source": "x"},
                    {"spl_source": "custom"}, {"severity": "urgent"}, {"threshold": "-1"},
                    {"alert_mode": "email"}):
            with self.assertRaises(ValidationError):
                normalize_spec(bad, {})

    def test_name_is_sanitized_and_bounded(self):
        name = saved_search_name("9.1.1", 'Brute force <script>/"x" ' + "y" * 200)
        self.assertTrue(name.startswith("SUN - 9.1.1 - Brute force script x"))
        self.assertLessEqual(len(name), 100)
        self.assertNotIn("/", name)

    def test_settings_have_no_external_actions(self):
        rev = {"rev": 2, "spl": "index=main", "cron": "*/5 * * * *", "earliest": "-5m", "latest": "now",
               "alert_mode": "track", "threshold": 3, "severity": "critical"}
        s = settings_for(rev, UC)
        self.assertEqual(s["disabled"], "1")
        self.assertNotIn("actions", s)
        self.assertEqual(s["alert_threshold"], "3")
        self.assertEqual(s["alert.severity"], "5")
        self.assertIn(MANAGED_MARKER, s["description"])
        self.assertIn("content_id=%s " % UC, s["description"])
        self.assertFalse(any(k.startswith("action.") for k in s))


class SchedulingTest(unittest.TestCase):
    def test_new_drafts_carry_scheduling_defaults(self):
        svc, store, saved = service()
        rev = svc.save_draft("alice", UC, {})["revisions"][-1]
        self.assertEqual((rev["earliest"], rev["latest"], rev["schedule_window"], rev["suppress_period"]),
                         ("-20m@m", "-5m@m", "auto", ""))
        self.assertFalse(rev["spl_time_bounds"])
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        doc = svc.deploy("bob", UC)
        live = saved.items[doc["saved_search"]["name"]]
        self.assertEqual((live["dispatch.earliest_time"], live["schedule_window"], live["alert.suppress"]),
                         ("-20m@m", "auto", "0"))
        self.assertEqual(doc["live"]["drift"], [])

    def test_suppression_and_window_are_written_and_checked(self):
        svc, store, saved = service()
        svc.save_draft("alice", UC, {"schedule_window": "10", "suppress_period": "1h",
                                     "suppress_fields": "user, src"})
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        name = svc.deploy("bob", UC)["saved_search"]["name"]
        live = saved.items[name]
        self.assertEqual((live["schedule_window"], live["alert.suppress"], live["alert.suppress.period"],
                          live["alert.suppress.fields"]), ("10", "1", "1h", "user,src"))
        live.update({"schedule_window": "0", "alert.suppress.period": "5m"})
        fields = [d["field"] for d in svc.verify("bob", UC)["live"]["drift"]]
        self.assertEqual(fields, ["schedule_window", "alert.suppress.period"])

    def test_revisions_frozen_before_the_keys_show_no_drift(self):
        from splunk_ucm.deployment.spec import drift
        old = {"rev": 1, "spl": "index=main", "spl_hash": spl_hash("index=main"), "cron": "*/15 * * * *",
               "earliest": "-15m", "latest": "now", "alert_mode": "track", "threshold": 0, "severity": "medium"}
        settings = settings_for(old, UC)
        self.assertNotIn("schedule_window", settings)
        self.assertNotIn("alert.suppress", settings)
        live = dict(settings, is_scheduled=True, disabled=True, schedule_window="5", **{"alert.suppress": True})
        self.assertEqual(drift(old, live, True), [])

    def test_embedded_time_bounds_are_flagged(self):
        svc, store, saved = service()
        rev = svc.save_draft("alice", UC, {"spl_source": "custom",
                                           "custom_spl": "index=main earliest=-24h | stats count"})
        self.assertTrue(rev["revisions"][-1]["spl_time_bounds"])

    def test_scheduling_validation(self):
        for bad in ({"schedule_window": "1441"}, {"schedule_window": "soon"}, {"suppress_period": "1 hour"},
                    {"suppress_period": "1h", "alert_mode": "none"}, {"suppress_fields": "user"},
                    {"suppress_period": "1h", "suppress_fields": "us er"},
                    {"suppress_period": "1h", "suppress_fields": ",".join("f%d" % i for i in range(11))}):
            with self.assertRaises(ValidationError, msg=bad):
                normalize_spec(bad, {})
        spec = normalize_spec({"schedule_window": "AUTO", "suppress_period": "30m"}, {})
        self.assertEqual((spec["schedule_window"], spec["suppress_period"], spec["suppress_fields"]),
                         ("auto", "30m", ""))


class OwnershipTest(unittest.TestCase):
    """D-051: writes go through the system token and every search is owned by scheduled_owner."""

    class FakeTransport:
        def __init__(self, owner_after_create="splunk-system-user"):
            self.calls = []
            self.items = {}
            self.owner_after_create = owner_after_create

        def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
            form = dict(form or {})
            self.calls.append((method, path, form))
            name = unquote(path.rsplit("/saved/searches/", 1)[-1].split("/")[0]) if "/saved/searches/" in path else form.get("name")
            if path.endswith("/acl"):
                self.items[name]["owner"] = form["owner"]
                return 200, b"{}"
            if method == "POST" and path.endswith("/saved/searches"):
                self.items[form["name"]] = {"owner": self.owner_after_create, "sharing": "app"}
                return 201, b"{}"
            if method == "POST":
                return (200, b"{}") if name in self.items else (404, b"{}")
            if method == "DELETE":
                return (200, b"{}") if self.items.pop(name, None) is not None else (404, b"{}")
            return 404, b"{}"

    def test_writes_refused_without_scheduled_owner(self):
        from splunk_ucm.deployment.savedsearch import SavedSearchClient
        client = SavedSearchClient(self.FakeTransport(), owner="")
        for action in (lambda: client.create("x", {}), lambda: client.update("x", {}), lambda: client.delete("x")):
            with self.assertRaises(ValidationError):
                action()
        self.assertEqual(client.t.calls, [])

    def test_create_and_update_reassign_owner(self):
        from splunk_ucm.deployment.savedsearch import SavedSearchClient
        t = self.FakeTransport()
        client = SavedSearchClient(t, owner="ucm_scheduler")
        client.create("SUN - x", {"search": "| makeresults"})
        self.assertEqual(t.items["SUN - x"]["owner"], "ucm_scheduler")
        t.items["SUN - x"]["owner"] = "alice"
        client.update("SUN - x", {"disabled": "0"})
        self.assertEqual(t.items["SUN - x"]["owner"], "ucm_scheduler")
        acl = [c for c in t.calls if c[1].endswith("/acl")]
        self.assertEqual([c[2] for c in acl], [{"owner": "ucm_scheduler", "sharing": "app"}] * 2)

    def test_owner_drift_is_reported(self):
        from splunk_ucm.deployment.spec import drift
        rev = {"spl_hash": spl_hash("| makeresults"), "cron": "*/5 * * * *", "earliest": "-20m@m",
               "latest": "-5m@m", "rev": 1}
        live = {"search": "| makeresults", "cron_schedule": "*/5 * * * *", "dispatch.earliest_time": "-20m@m",
                "dispatch.latest_time": "-5m@m", "is_scheduled": True, "disabled": True, "owner": "alice"}
        self.assertEqual(drift(rev, live, True), [])
        self.assertEqual([p["field"] for p in drift(rev, live, True, "ucm_scheduler")], ["owner"])
        live["owner"] = "ucm_scheduler"
        self.assertEqual(drift(rev, live, True, "ucm_scheduler"), [])


class WorkflowTest(unittest.TestCase):
    def test_full_lifecycle_disabled_first(self):
        svc, store, saved = service()
        doc = svc.save_draft("alice", UC, {"notes": "first"})
        self.assertEqual(doc["state"], "draft")
        self.assertEqual(doc["revision"], 1)
        self.assertTrue(doc["revisions"][0]["parse_ok"])
        self.assertEqual(set(svc.search.parse_apps), {"sunavigator"})
        doc = svc.submit("alice", UC)
        self.assertEqual(doc["state"], "pending_approval")
        with self.assertRaises(PermissionDenied):
            svc.approve("alice", UC)
        doc = svc.approve("bob", UC)
        self.assertEqual(doc["state"], "approved")
        self.assertEqual(saved.items, {})
        doc = svc.deploy("bob", UC)
        self.assertEqual(doc["state"], "deployed")
        self.assertEqual(doc["deployed_revision"], 1)
        self.assertEqual(doc["live"]["status"], "disabled")
        self.assertEqual(doc["live"]["drift"], [])
        name = doc["saved_search"]["name"]
        self.assertTrue(saved.items[name]["disabled"])
        doc = svc.enable("bob", UC)
        self.assertEqual(doc["live"]["status"], "enabled")
        self.assertFalse(saved.items[name]["disabled"])
        doc = svc.disable("bob", UC)
        self.assertEqual(doc["live"]["status"], "disabled")
        doc = svc.retire("bob", UC)
        self.assertEqual(doc["state"], "retired")
        self.assertNotIn(name, saved.items)
        actions = [h["action"] for h in doc["history"]]
        self.assertEqual(actions, ["draft", "submit", "approve", "deploy", "enable", "disable", "retire"])
        audited = [a["action"] for a in AuditService(store).recent(50, "deployment.")]
        for action in ("deployment.draft", "deployment.approve", "deployment.deploy", "deployment.enable",
                       "deployment.retire"):
            self.assertIn(action, audited)

    def test_invalid_transitions(self):
        svc, _, _ = service()
        with self.assertRaises(NotFoundError):
            svc.submit("alice", UC)
        svc.save_draft("alice", UC, {})
        for fn in (svc.approve, svc.deploy, svc.reject):
            with self.assertRaises(ConflictError):
                fn("bob", UC)
        with self.assertRaises(ConflictError):
            svc.enable("bob", UC)

    def test_reject_then_new_revision(self):
        svc, _, _ = service()
        svc.save_draft("alice", UC, {})
        svc.submit("alice", UC)
        doc = svc.reject("bob", UC, "use a shorter window")
        self.assertEqual(doc["state"], "rejected")
        doc = svc.save_draft("alice", UC, {"earliest": "-5m"})
        self.assertEqual(doc["revision"], 2)
        self.assertEqual(doc["state"], "draft")

    def test_unsubmitted_draft_is_replaced_not_stacked(self):
        svc, _, _ = service()
        svc.save_draft("alice", UC, {})
        doc = svc.save_draft("alice", UC, {"cron": "0 * * * *"})
        self.assertEqual(len(doc["revisions"]), 1)
        self.assertEqual(doc["revisions"][0]["cron"], "0 * * * *")

    def test_self_approval_and_no_approval_settings(self):
        svc, _, _ = service(allow_self_approval=True)
        svc.save_draft("alice", UC, {})
        svc.submit("alice", UC)
        self.assertEqual(svc.approve("alice", UC)["state"], "approved")
        svc2, _, _ = service(require_approval=False)
        svc2.save_draft("alice", UC, {})
        doc = svc2.submit("alice", UC)
        self.assertEqual(doc["state"], "approved")
        self.assertEqual(doc["revisions"][-1]["approval"], "not_required")

    def test_side_effects_and_parse_failures_block_submit_and_deploy(self):
        svc, _, _ = service(parser=FakeParser(commands=["search", "outputlookup"]))
        doc = svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": "index=main | outputlookup x.csv"})
        self.assertEqual(doc["revisions"][0]["side_effects"], ["outputlookup"])
        with self.assertRaises(ValidationError):
            svc.submit("alice", UC)
        svc2, _, _ = service(parser=FakeParser(ok=False, error="Unknown search command 'nope'"))
        svc2.save_draft("alice", UC, {})
        with self.assertRaises(ValidationError):
            svc2.submit("alice", UC)

    def test_review_commands_need_approver_acknowledgment(self):
        svc, store, saved = service(parser=FakeParser(commands=["search", "map"]))
        doc = svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": 'index=main | map search="x"'})
        self.assertEqual(doc["revisions"][0]["review_commands"], ["map"])
        svc.submit("alice", UC)
        with self.assertRaises(ConflictError) as cm:
            svc.approve("bob", UC)
        self.assertEqual(cm.exception.details["code"], "acknowledgment_required")
        self.assertEqual(cm.exception.details["indirect"], ["map"])
        doc = svc.approve("bob", UC, acknowledge_commands=True)
        rev = doc["revisions"][-1]
        self.assertEqual((rev["acknowledged_commands"], rev["acknowledged_by"]), (["map"], "bob"))
        audit = AuditService(store).recent(10, "deployment.approve")[0]
        self.assertEqual(audit["details"]["acknowledged_commands"], ["map"])
        self.assertEqual(svc.deploy("bob", UC)["state"], "deployed")

    def test_deploy_refuses_commands_added_after_approval(self):
        parser = FakeParser(commands=["search", "map"])
        svc, _, saved = service(parser=parser)
        svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": "index=main | `m`"})
        svc.submit("alice", UC)
        svc.approve("bob", UC, acknowledge_commands=True)
        parser.commands = ["search", "map", "rest"]
        with self.assertRaises(ConflictError) as cm:
            svc.deploy("bob", UC)
        self.assertEqual(cm.exception.details, {"code": "unacknowledged_commands", "commands": ["rest"]})
        self.assertEqual(saved.items, {})

    def test_unknown_commands_and_extra_safe(self):
        svc, _, _ = service(parser=FakeParser(commands=["search", "apply"]))
        doc = svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": "index=main | apply m"})
        self.assertEqual(doc["revisions"][0]["unknown_commands"], ["apply"])
        svc2, _, _ = service(parser=FakeParser(commands=["search", "apply"]), extra_safe_commands=["apply"])
        doc = svc2.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": "index=main | apply m"})
        self.assertEqual(doc["revisions"][0]["review_commands"], [])

    def test_no_approval_mode_acknowledges_at_submit(self):
        svc, _, _ = service(parser=FakeParser(commands=["search", "rest"]), require_approval=False)
        svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": "| rest /services/server/info"})
        with self.assertRaises(ConflictError):
            svc.submit("alice", UC)
        doc = svc.submit("alice", UC, acknowledge_commands=True)
        self.assertEqual(doc["state"], "approved")
        self.assertEqual(doc["revisions"][-1]["acknowledged_by"], "alice")

    def test_api_passes_acknowledgment(self):
        svc, store, _ = service(parser=FakeParser(commands=["search", "map"]))
        ctx = make_ctx(store, ["ucm_deploy"], user="bob")
        svc.save_draft("alice", UC, {"spl_source": "custom", "custom_spl": 'index=main | map search="x"'})
        svc.submit("alice", UC)
        ctx.deployment_service = lambda: svc
        status, body = call(ctx, "POST", "deployment/approve", body={"id": UC})
        self.assertEqual((status, body["error"]["details"]["code"]), (409, "acknowledgment_required"))
        status, body = call(ctx, "POST", "deployment/approve", body={"id": UC, "acknowledge_commands": "yes"})
        self.assertEqual(status, 409)
        status, body = call(ctx, "POST", "deployment/approve", body={"id": UC, "acknowledge_commands": True})
        self.assertEqual((status, body["deployment"]["state"]), (200, "approved"))

    def test_missing_cim_spl_is_refused(self):
        svc, store, _ = service()
        with self.assertRaises(ValidationError):
            svc.save_draft("alice", "fenre:UC-14.1.1", {"spl_source": "cim"})

    def test_existing_unmanaged_search_is_not_overwritten(self):
        svc, _, saved = service()
        doc = svc.save_draft("alice", UC, {})
        saved.items[doc["saved_search"]["name"]] = {"name": doc["saved_search"]["name"], "search": "index=x",
                                                    "description": "someone else's", "disabled": False}
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        with self.assertRaises(ConflictError):
            svc.deploy("bob", UC)
        doc = svc.get(UC)
        self.assertEqual(doc["state"], "failed")
        self.assertEqual(saved.items[doc["saved_search"]["name"]]["search"], "index=x")

    def test_verification_failure_marks_failed_and_disables(self):
        svc, _, saved = service()
        approved(svc)
        saved.ignore_disabled = True
        doc = svc.deploy("bob", UC)
        self.assertEqual(doc["state"], "failed")
        self.assertTrue(any(d["field"] == "disabled" for d in doc["live"]["drift"]))
        self.assertIn("verification failed", doc["last_error"])

    def test_write_error_marks_failed_and_reraises(self):
        svc, _, saved = service()
        approved(svc)
        saved.fail_next = PermissionDenied("Splunk refused")
        with self.assertRaises(PermissionDenied):
            svc.deploy("bob", UC)
        doc = svc.get(UC)
        self.assertEqual(doc["state"], "failed")
        self.assertEqual(doc["deployed_revision"], None)
        self.assertEqual(svc.deploy("bob", UC)["state"], "deployed")

    def test_redeploy_new_revision_disables_and_rollback_restores(self):
        svc, _, saved = service()
        approved(svc)
        svc.deploy("bob", UC)
        svc.enable("bob", UC)
        svc.save_draft("alice", UC, {"cron": "0 * * * *"})
        doc = svc.get(UC)
        self.assertEqual(doc["live"]["status"], "enabled")
        self.assertIn("disable", svc.allowed_actions(doc, "bob", ["ucm_deploy"]))
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        doc = svc.deploy("bob", UC)
        name = doc["saved_search"]["name"]
        self.assertEqual(doc["deployed_revision"], 2)
        self.assertEqual(saved.items[name]["cron_schedule"], "0 * * * *")
        self.assertTrue(saved.items[name]["disabled"])
        doc = svc.rollback("bob", UC, "too noisy")
        self.assertEqual(doc["deployed_revision"], 1)
        self.assertEqual(saved.items[name]["cron_schedule"], "*/5 * * * *")
        self.assertTrue(saved.items[name]["disabled"])
        self.assertEqual(doc["live"]["drift"], [])
        with self.assertRaises(ConflictError):
            svc.rollback("bob", UC)

    def test_readiness_gate_on_enable(self):
        svc, store, _ = service()
        approved(svc)
        svc.deploy("bob", UC)
        store.upsert(C.READINESS, {"_key": "fenre_UC-9.1.1", "content_id": UC, "state": "blocked"})
        with self.assertRaises(ConflictError) as ctx:
            svc.enable("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "readiness_gate")
        with self.assertRaises(ConflictError):
            svc.enable("bob", UC, "short")
        doc = svc.enable("bob", UC, "Accepted: data arrives next week")
        self.assertEqual(doc["live"]["status"], "enabled")
        events = AuditService(store).recent(5, "deployment.enable")
        self.assertEqual(events[0]["details"]["override_reason"], "Accepted: data arrives next week")

    def test_verify_detects_drift_missing_and_unmanaged(self):
        svc, _, saved = service()
        approved(svc)
        doc = svc.deploy("bob", UC)
        name = doc["saved_search"]["name"]
        saved.items[name]["search"] = "index=main | delete"
        saved.items[name]["actions"] = "email"
        doc = svc.verify("bob", UC)
        self.assertEqual([d["field"] for d in doc["live"]["drift"]], ["search", "actions"])
        saved.items[name]["description"] = "edited"
        self.assertEqual(svc.verify("bob", UC)["live"]["status"], "unmanaged")
        with self.assertRaises(ConflictError):
            svc.enable("bob", UC)
        del saved.items[name]
        self.assertEqual(svc.verify("bob", UC)["live"]["status"], "missing")
        self.assertEqual(svc.summary()["drifted"], 1)

    def test_approved_spl_is_frozen_against_upstream_changes(self):
        svc, store, saved = service()
        approved(svc)
        catalog = store.get(C.CATALOG, "fenre_UC-9.1.1")
        catalog["source_hash"] = "changed"
        store.upsert(C.CATALOG, catalog)
        doc = svc.deploy("bob", UC)
        self.assertTrue(doc["content_changed"])
        self.assertEqual(saved.items[doc["saved_search"]["name"]]["search"], doc["revisions"][0]["spl"])

    def test_revision_trim_keeps_deployed(self):
        svc, _, _ = service(max_revisions=3)
        approved(svc)
        svc.deploy("bob", UC)
        for i in range(5):
            svc.save_draft("alice", UC, {"cron": "%d * * * *" % i})
            svc.submit("alice", UC)
            svc.reject("bob", UC)
        doc = svc.get(UC)
        revs = [r["rev"] for r in doc["revisions"]]
        self.assertLessEqual(len(revs), 3)
        self.assertIn(1, revs)
        self.assertEqual(revs[-1], 6)

    def test_concurrent_update_detected(self):
        svc, store, _ = service()
        svc.save_draft("alice", UC, {})
        stale = store.get(C.DEPLOYMENTS, deployment_key("fenre_UC-9.1.1"))
        svc.submit("alice", UC)
        with self.assertRaises(ConflictError):
            svc._save(stale, "mallory")

    def test_allowed_actions(self):
        svc, _, _ = service()
        self.assertEqual(svc.allowed_actions(None, "alice", []), [])
        self.assertEqual(svc.allowed_actions(None, "alice", ["ucm_run_discovery"]), ["draft"])
        svc.save_draft("alice", UC, {})
        doc = svc.submit("alice", UC)
        self.assertNotIn("approve", svc.allowed_actions(doc, "alice", ["ucm_deploy"]))
        self.assertIn("approve", svc.allowed_actions(doc, "bob", ["ucm_deploy"]))
        self.assertEqual(svc.allowed_actions(doc, "carol", ["ucm_run_discovery"]), ["draft"])


class ApiTest(unittest.TestCase):
    def test_capabilities(self):
        store = loaded_catalog()
        viewer = make_ctx(store, [])
        for action in ("draft", "submit", "approve", "deploy", "enable", "rollback", "retire", "verify"):
            self.assertEqual(call(viewer, "POST", "deployment/" + action, body={"id": UC})[0], 403, action)
        analyst = make_ctx(store, ["ucm_run_discovery"])
        for action in ("approve", "deploy", "enable", "disable", "rollback", "retire"):
            self.assertEqual(call(analyst, "POST", "deployment/" + action, body={"id": UC})[0], 403, action)
        status, body = call(viewer, "GET", "deployment", {"id": UC})
        self.assertEqual(status, 200)
        self.assertIsNone(body["deployment"])
        self.assertEqual(body["allowed_actions"], [])
        self.assertEqual(call(viewer, "GET", "deployments", {"summary": "1"})[0], 200)
        self.assertEqual(call(viewer, "GET", "deployments", {"state": "bogus"})[0], 400)

    def test_usecase_detail_embeds_deployment(self):
        store = loaded_catalog()
        status, body = call(make_ctx(store, ["ucm_deploy"]), "GET", "usecase", {"id": UC})
        self.assertEqual(status, 200)
        self.assertEqual(body["deployment"]["allowed_actions"], ["draft"])


class WorkerTest(unittest.TestCase):
    def test_interval_and_leader_gate(self):
        store = loaded_catalog()
        now = [datetime.datetime(2026, 11, 20, 10, 0, tzinfo=datetime.timezone.utc)]
        worker = DeploymentWorker(store, AppConfig({}), None, lambda: True, now=lambda: now[0])
        saved = FakeSavedSearches()
        worker.service.saved = saved
        worker.service.search = FakeParser()
        self.assertEqual(worker.run_once()["action"], "idle")
        approved(worker.service)
        worker.service.deploy("bob", UC)
        self.assertEqual(worker.run_once()["action"], "idle")
        now[0] += datetime.timedelta(minutes=61)
        result = worker.run_once()
        self.assertEqual(result["action"], "ran")
        self.assertEqual(result["totals"]["checked"], 1)
        self.assertEqual(store.get(C.SYNC_STATE, STATE_KEY)["totals"]["drifted"], 0)
        follower = DeploymentWorker(store, AppConfig({}), None, lambda: False)
        self.assertEqual(follower.run_once()["action"], "skipped")


if __name__ == "__main__":
    unittest.main()

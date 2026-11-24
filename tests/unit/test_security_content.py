import json
import unittest
from urllib.parse import quote

import helpers  # noqa: F401
from splunk_ucm.api.app import CAP_DEPLOY, Context, Request, build_router
from splunk_ucm.config import AppConfig
from splunk_ucm.errors import StorageError
from splunk_ucm.platform import security_content as SC
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.transport import SplunkdTransport
from unit.test_escu import DEFENDER, LOGONS
from unit.test_provider_navigation import two_provider_store

ES = "SplunkEnterpriseSecuritySuite"
STANZA = "ESCU - Disable Windows Defender Real-time Protection - Rule"


def app_entry(version="6.11.1", disabled=False, label="ES Content Updates"):
    return {"entry": [{"name": "x", "content": {"version": version, "disabled": disabled, "label": label}}]}


def stanza_entry(disabled=True, cron="0 * * * *", actions="notable", scheduled=True, **extra):
    content = {"disabled": disabled, "cron_schedule": cron, "is_scheduled": scheduled, "actions": actions,
               "dispatch.earliest_time": "-70m@m", "dispatch.latest_time": "-10m@m"}
    if "notable" in actions:
        content["action.notable"] = "1"
    content.update(extra)
    return {"entry": [{"name": "s", "content": content}]}


class FakeSystem(SplunkdTransport):
    """Answers app and saved-search reads; anything else is a test failure (the card is read-only)."""

    def __init__(self, apps=None, stanzas=None, fail=None):
        self.apps = apps or {}
        self.stanzas = stanzas or {}
        self.fail = fail or {}
        self.calls = []

    def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        self.calls.append((method, path))
        assert method == "GET", "the hand-off must never write: %s %s" % (method, path)
        if path in self.fail:
            exc = self.fail[path]
            if isinstance(exc, Exception):
                raise exc
            return exc, b"{}"
        prefix = "/services/apps/local/"
        if path.startswith(prefix):
            name = path[len(prefix):]
            if name in self.apps:
                return 200, json.dumps(self.apps[name]).encode()
            return 404, b"{}"
        ns = "/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/"
        if path.startswith(ns):
            for name, body in self.stanzas.items():
                if path == ns + quote(name, safe=""):
                    return 200, json.dumps(body).encode()
            return 404, b"{}"
        raise AssertionError("unexpected read " + path)


class Tick:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def reader(system, tick=None):
    return SC.SecurityContentReader(system, tick or Tick())


def card(apps, stanzas, name=STANZA):
    SC.clear_cache()
    r = reader(FakeSystem(apps, stanzas))
    return SC.handoff_for(r, "escu", "id", "Disable Windows Defender Real-time Protection", {"stanza": name})


class AppDetectionTest(unittest.TestCase):
    def setUp(self):
        SC.clear_cache()

    def test_reports_versions_and_absence(self):
        r = reader(FakeSystem({ES: app_entry("8.8.0", label="Splunk Enterprise Security"),
                               "DA-ESS-ContentUpdate": app_entry("6.11.1")}))
        o = r.overview()
        self.assertEqual((o["es"]["state"], o["es"]["version"]), ("installed", "8.8.0"))
        self.assertEqual((o["escu"]["state"], o["escu"]["version"]), ("installed", "6.11.1"))
        SC.clear_cache()
        o = reader(FakeSystem({"DA-ESS-ContentUpdate": app_entry()})).overview()
        self.assertEqual(o["es"]["state"], "not_installed")
        self.assertEqual(o["es"]["app_id"], ES)
        SC.clear_cache()
        o = reader(FakeSystem()).overview()
        self.assertEqual((o["es"]["state"], o["escu"]["state"]), ("not_installed", "not_installed"))

    def test_disabled_app_is_not_treated_as_installed(self):
        o = reader(FakeSystem({ES: app_entry("8.8.0", disabled=True)})).overview()
        self.assertEqual(o["es"]["state"], "disabled")
        self.assertIsNone(SC.es_link(o["es"]))

    def test_unreadable_app_is_unverified_not_absent(self):
        for fail in (403, StorageError("boom"), RuntimeError("x")):
            SC.clear_cache()
            r = reader(FakeSystem(fail={"/services/apps/local/" + ES: fail}))
            o = r.overview()
            self.assertEqual(o["es"]["state"], "unverified", fail)
            self.assertTrue(o["es"]["reason"])

    def test_no_system_session_is_unverified(self):
        o = SC.SecurityContentReader(None).overview()
        self.assertEqual((o["es"]["state"], o["escu"]["state"]), ("unverified", "unverified"))
        self.assertEqual(SC.SecurityContentReader(None).stanza("x")["state"], "unverified")

    def test_reads_are_cached_briefly_and_expire(self):
        tick = Tick()
        system = FakeSystem({ES: app_entry("8.8.0")})
        r = reader(system, tick)
        r.app(ES)
        r.app(ES)
        self.assertEqual(len(system.calls), 1)
        tick.t += SC.CACHE_SECONDS + 1
        r.app(ES)
        self.assertEqual(len(system.calls), 2)

    def test_unverified_answers_are_not_cached(self):
        system = FakeSystem(fail={"/services/apps/local/" + ES: 500})
        r = reader(system)
        r.app(ES)
        r.app(ES)
        self.assertEqual(len(system.calls), 2)


class StanzaReadTest(unittest.TestCase):
    def setUp(self):
        SC.clear_cache()

    def read(self, body=None, fail=None):
        stanzas = {STANZA: body} if body is not None else {}
        return reader(FakeSystem(stanzas=stanzas, fail=fail or {})).stanza(STANZA)

    def test_disabled_shipped_stanza_with_notable_action(self):
        s = self.read(stanza_entry(disabled=True))
        self.assertEqual((s["state"], s["scheduled"], s["cron"]), ("disabled", True, "0 * * * *"))
        self.assertEqual((s["notable"], s["risk"]), (True, False))
        self.assertEqual(s["actions"], ["notable"])

    def test_enabled_stanza_with_risk_and_notable(self):
        s = self.read(stanza_entry(disabled="0", actions="notable, risk", **{"action.risk": "1"}))
        self.assertEqual(s["state"], "enabled")
        self.assertEqual((s["notable"], s["risk"]), (True, True))

    def test_stringly_typed_disabled_values(self):
        for value, state in (("1", "disabled"), ("0", "enabled"), (True, "disabled"), (False, "enabled"), ("true", "disabled")):
            SC.clear_cache()
            self.assertEqual(self.read(stanza_entry(disabled=value))["state"], state, value)

    def test_missing_stanza_is_not_found_not_unverified(self):
        s = self.read(None)
        self.assertEqual(s["state"], "not_found")

    def test_unreadable_is_unverified_with_a_reason(self):
        for fail in (403, 500, StorageError("down")):
            SC.clear_cache()
            s = self.read(None, {"/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/" + quote(STANZA, safe=""): fail})
            self.assertEqual(s["state"], "unverified", fail)
            self.assertTrue(s["reason"])

    def test_uninterpretable_body_is_unverified(self):
        self.assertEqual(self.read({"entry": []})["state"], "unverified")
        SC.clear_cache()
        self.assertEqual(self.read({"entry": [{"content": {"cron_schedule": "x"}}]})["state"], "unverified")

    def test_unusable_names_are_refused_without_a_request(self):
        system = FakeSystem()
        r = reader(system)
        for name in ("", "a/b", "x\ny", "n" * 400):
            self.assertEqual(r.stanza(name)["state"], "unverified", name)
        self.assertEqual(system.calls, [])


class NameMappingTest(unittest.TestCase):
    def test_stored_stanza_wins_then_title_pattern(self):
        self.assertEqual(SC.stanza_name_for("escu", "id", "T", {"stanza": "ESCU - Real - Rule"}), "ESCU - Real - Rule")
        self.assertEqual(SC.stanza_name_for("escu", "id", "Windows Event Log Cleared", {}),
                         "ESCU - Windows Event Log Cleared - Rule")
        self.assertEqual(SC.stanza_name_for("escu", "id", "", {}), "")

    def test_only_escu_records_have_a_card(self):
        self.assertEqual(SC.stanza_name_for("fenre", "UC-1", "T", {"stanza": "ESCU - x - Rule"}), "")
        self.assertIsNone(SC.handoff_for(reader(FakeSystem()), "fenre", "UC-1", "T", {}))

    def test_imported_record_stores_the_shipped_stanza_name(self):
        store = two_provider_store()
        from splunk_ucm.catalog.detail import UseCaseDetailService
        from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
        d = UseCaseDetailService(ContentRepository(store), CategoryRepository(store)).get(DEFENDER)
        self.assertEqual(d["provider_extras"]["stanza"], STANZA)
        self.assertEqual(SC.stanza_name_for(d["provenance"]["provider"], "x", d["title"], d["provider_extras"]), STANZA)


class CardTest(unittest.TestCase):
    APPS_ESCU = {"DA-ESS-ContentUpdate": app_entry()}
    APPS_BOTH = {"DA-ESS-ContentUpdate": app_entry(), ES: app_entry("8.8.0")}

    def test_escu_without_es_disabled_stanza(self):
        c = card(self.APPS_ESCU, {STANZA: stanza_entry(disabled=True)})
        self.assertEqual(c["code"], "escu_without_es")
        self.assertIn("independent copy", c["text"])
        self.assertIsNone(c["es_link"])
        self.assertFalse(c["parallel_copy"]["warn"])
        self.assertEqual(c["stanza"]["state"], "disabled")
        self.assertIn("does not count as enabled in SUN coverage", c["coverage_note"])

    def test_escu_without_es_but_enabled_stanza_warns(self):
        c = card(self.APPS_ESCU, {STANZA: stanza_entry(disabled=False)})
        self.assertEqual(c["code"], "escu_without_es")
        self.assertTrue(c["parallel_copy"]["warn"])
        self.assertTrue(c["parallel_copy"]["escu_enabled"])
        self.assertIn("enabled and nothing manages it", c["text"])

    def test_es_present_points_to_content_management_and_warns(self):
        c = card(self.APPS_BOTH, {STANZA: stanza_entry(disabled=True)})
        self.assertEqual(c["code"], "enable_in_es")
        self.assertIn("ES Content Management", c["text"])
        self.assertTrue(c["parallel_copy"]["warn"])
        self.assertEqual((c["es_link"]["app_id"], c["es_link"]["content_management_view"]),
                         ("SplunkEnterpriseSecuritySuite", "ess_content_management"))
        self.assertIs(c["es_link"]["verified"], False)
        self.assertIn("varies by ES version", c["es_link"]["note"])
        self.assertIn("unvalidated", c["validated"])

    def test_es_enabled_in_es_never_counts_as_sun_coverage(self):
        c = card(self.APPS_BOTH, {STANZA: stanza_entry(disabled=False)})
        self.assertEqual(c["stanza"]["state"], "enabled")
        self.assertIn("does not count as enabled in SUN coverage", c["coverage_note"])

    def test_escu_not_installed(self):
        c = card({}, {})
        self.assertEqual(c["code"], "escu_not_installed")
        self.assertIsNone(c["stanza"])
        self.assertFalse(c["parallel_copy"]["warn"])

    def test_es_installed_without_escu_still_offers_the_link(self):
        c = card({ES: app_entry("8.8.0")}, {})
        self.assertEqual(c["code"], "escu_not_installed")
        self.assertIsNotNone(c["es_link"])
        self.assertFalse(c["parallel_copy"]["warn"])

    def test_stanza_not_found_in_installed_escu(self):
        c = card(self.APPS_ESCU, {})
        self.assertEqual(c["code"], "stanza_not_found")
        self.assertEqual(c["stanza"]["state"], "not_found")

    def test_unreadable_stanza_is_unverified_and_never_called_disabled(self):
        SC.clear_cache()
        system = FakeSystem(self.APPS_ESCU, fail={"/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/"
                                                  + quote(STANZA, safe=""): 403})
        c = SC.handoff_for(reader(system), "escu", "id", "t", {"stanza": STANZA})
        self.assertEqual(c["code"], "unverified")
        self.assertEqual(c["stanza"]["state"], "unverified")
        self.assertNotIn("search is disabled", c["text"])
        self.assertFalse(c["parallel_copy"]["warn"])

    def test_es_unreadable_with_escu_present(self):
        SC.clear_cache()
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry()}, {STANZA: stanza_entry()},
                            fail={"/services/apps/local/" + ES: 500})
        c = SC.handoff_for(reader(system), "escu", "id", "t", {"stanza": STANZA})
        self.assertEqual(c["code"], "es_unverified")
        self.assertIsNone(c["es_link"])

    def test_deploy_record_only_when_the_warning_applies(self):
        warn = card(self.APPS_BOTH, {STANZA: stanza_entry(disabled=True)})
        rec = SC.deploy_record(warn)
        self.assertTrue(rec["warned"] and rec["es_installed"] and not rec["escu_enabled"])
        self.assertEqual(rec["stanza"], STANZA)
        self.assertIsNone(SC.deploy_record(card(self.APPS_ESCU, {STANZA: stanza_entry(disabled=True)})))
        self.assertIsNone(SC.deploy_record(None))

    def test_a_failing_reader_still_yields_a_card(self):
        class Boom:
            def overview(self):
                raise RuntimeError("x")
        c = SC.handoff_for(Boom(), "escu", "id", "t", {"stanza": STANZA})
        self.assertEqual(c["code"], "unverified")
        self.assertFalse(c["parallel_copy"]["warn"])


def ctx_with(store, system, caps=()):
    ctx = Context(FakeUser(), system, "viewer", store=store, audit_store=store, config=AppConfig({}), record_store=store)
    ctx._caps = list(caps)
    return ctx


class FakeUser(SplunkdTransport):
    def request(self, *a, **kw):
        raise AssertionError("the user session must not read other apps' saved searches")


def get(ctx, path, query):
    resp = build_router().dispatch(ctx, Request("GET", path, {k: [v] for k, v in query.items()}, b"", ctx.user))
    return resp.status, resp.body


class ApiTest(unittest.TestCase):
    def setUp(self):
        SC.clear_cache()
        self.store = two_provider_store()

    def test_escu_use_case_carries_the_card_for_a_viewer(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry()}, {STANZA: stanza_entry(disabled=True)})
        status, body = get(ctx_with(self.store, system), "usecase", {"id": DEFENDER})
        self.assertEqual(status, 200)
        self.assertEqual(body["escu_handoff"]["code"], "escu_without_es")
        self.assertEqual(body["escu_handoff"]["stanza"]["name"], STANZA)
        self.assertTrue(all(m == "GET" for m, _ in system.calls))

    def test_non_escu_use_case_has_no_card_and_no_reads(self):
        system = FakeSystem()
        status, body = get(ctx_with(self.store, system), "usecase", {"id": "fenre:UC-9.1.1"})
        self.assertEqual(status, 200)
        self.assertIsNone(body["escu_handoff"])
        self.assertEqual(system.calls, [])

    def test_without_a_system_session_the_page_still_loads_with_unverified(self):
        status, body = get(ctx_with(self.store, None), "usecase", {"id": DEFENDER})
        self.assertEqual(status, 200)
        self.assertEqual(body["escu_handoff"]["code"], "unverified")

    def test_unknown_stanza_name_for_a_record(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry()}, {})
        body = get(ctx_with(self.store, system), "usecase", {"id": LOGONS})[1]
        self.assertEqual(body["escu_handoff"]["code"], "stanza_not_found")

    def test_platform_reports_security_content_apps(self):
        class Platform(FakeUser):
            def request(self, method, path, query=None, *a, **kw):
                if path == "/services/server/info":
                    return 200, json.dumps({"entry": [{"content": {"version": "10.2.9"}}]}).encode()
                if path == "/services/authentication/current-context":
                    return 200, json.dumps({"entry": [{"content": {"username": "viewer", "capabilities": []}}]}).encode()
                return 200, json.dumps({"entry": [{"content": {"current": {"status": "ready"}}}]}).encode()
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry("6.11.1")})
        ctx = Context(Platform(), system, "viewer", store=self.store, audit_store=self.store, config=AppConfig({}), record_store=self.store)
        status, body = get(ctx, "platform", {})
        self.assertEqual(status, 200)
        sc = body["security_content"]
        self.assertEqual((sc["es"]["state"], sc["escu"]["state"], sc["escu"]["version"]),
                         ("not_installed", "installed", "6.11.1"))


class DeploymentRecordTest(unittest.TestCase):
    """The warning is recorded in the draft revision and the audit event; it blocks nothing."""

    def setUp(self):
        SC.clear_cache()
        self.store = two_provider_store(twin=False)

    def service(self, system):
        from splunk_ucm.audit import AuditService
        from splunk_ucm.deployment.service import DeploymentService, DeploymentSettings
        from unit.test_deployment import FakeSavedSearches
        from unit.test_selection_validation import FakeParser
        r = reader(system)
        return DeploymentService(
            self.store, AuditService(self.store), FakeParser(), FakeSavedSearches(), DeploymentSettings(),
            handoff=lambda uc: SC.deploy_record(SC.handoff_for(
                r, uc.provenance.provider, uc.provenance.provider_record_id, uc.title, uc.provider_extras)))

    def test_draft_records_the_parallel_copy_when_es_is_present(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry(), ES: app_entry("8.8.0")},
                            {STANZA: stanza_entry(disabled=True)})
        doc = self.service(system).save_draft("alice", DEFENDER, {})
        rev = doc["revisions"][-1]
        self.assertTrue(rev["parallel_copy"]["warned"])
        self.assertTrue(rev["parallel_copy"]["es_installed"])
        self.assertEqual(doc["state"], "draft")
        events = [e for e in self.store.query(C.AUDIT, None) if e.get("action") == "deployment.draft"]
        self.assertTrue(events[-1]["details"]["parallel_copy"]["warned"])

    def test_draft_with_an_enabled_escu_copy_records_it(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry()}, {STANZA: stanza_entry(disabled=False)})
        rev = self.service(system).save_draft("alice", DEFENDER, {})["revisions"][-1]
        self.assertTrue(rev["parallel_copy"]["escu_enabled"])
        self.assertFalse(rev["parallel_copy"]["es_installed"])

    def test_draft_without_a_warning_records_nothing_extra(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry()}, {STANZA: stanza_entry(disabled=True)})
        doc = self.service(system).save_draft("alice", DEFENDER, {})
        self.assertNotIn("parallel_copy", doc["revisions"][-1])
        events = [e for e in self.store.query(C.AUDIT, None) if e.get("action") == "deployment.draft"]
        self.assertNotIn("parallel_copy", events[-1]["details"])

    def test_an_unreadable_state_never_blocks_the_draft(self):
        system = FakeSystem(fail={"/services/apps/local/" + ES: 500, "/services/apps/local/DA-ESS-ContentUpdate": 500})
        doc = self.service(system).save_draft("alice", DEFENDER, {})
        self.assertEqual(doc["state"], "draft")
        self.assertNotIn("parallel_copy", doc["revisions"][-1])

    def test_the_full_workflow_is_unchanged_with_the_warning_present(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry(), ES: app_entry("8.8.0")},
                            {STANZA: stanza_entry(disabled=True)})
        svc = self.service(system)
        svc.save_draft("alice", DEFENDER, {})
        svc.submit("alice", DEFENDER)
        self.assertEqual(svc.approve("bob", DEFENDER)["state"], "approved")
        from splunk_ucm.errors import PermissionDenied
        svc.save_draft("alice", DEFENDER, {})
        svc.submit("alice", DEFENDER)
        with self.assertRaises(PermissionDenied):
            svc.approve("alice", DEFENDER)

    def test_context_wires_the_handoff_for_escu_records_only(self):
        system = FakeSystem({"DA-ESS-ContentUpdate": app_entry(), ES: app_entry("8.8.0")},
                            {STANZA: stanza_entry(disabled=True)})
        svc = ctx_with(self.store, system, [CAP_DEPLOY]).deployment_service()
        self.assertIsNotNone(svc.handoff)
        from splunk_ucm.content.reindex import StoredNormalizer
        from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
        from splunk_ucm.catalog.detail import key_from_id
        norm = StoredNormalizer(CategoryRepository(self.store))
        escu = norm.normalize(ContentRepository(self.store).get_content(key_from_id(DEFENDER)))
        fenre = norm.normalize(ContentRepository(self.store).get_content(key_from_id("fenre:UC-9.1.1")))
        self.assertTrue(svc.handoff(escu)["warned"])
        self.assertIsNone(svc.handoff(fenre))


if __name__ == "__main__":
    unittest.main()

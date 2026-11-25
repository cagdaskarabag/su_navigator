import unittest

import helpers  # noqa: F401

from splunk_ucm.audit import AuditService
from splunk_ucm.api.app import CAP_RUN_DISCOVERY
from splunk_ucm.catalog.quality import spl_hash
from splunk_ucm.discovery import external as X
from splunk_ucm.discovery.external import ExternalMatchService, ExternalSettings, run_external
from splunk_ucm.errors import NotFoundError, ValidationError
from splunk_ucm.frameworks.coverage import CoverageService
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx

SPL = "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest"


def search(name, app="SplunkEnterpriseSecuritySuite", spl=SPL, enabled=True, annotations=""):
    return {"name": name, "app": app, "owner": "nobody", "sharing": "app", "enabled": enabled, "scheduled": True,
            "search": spl, "annotations": annotations}


class Inventory:
    def __init__(self, searches=None, fail=None):
        self.searches, self.fail = searches or [], fail

    def list_saved_searches(self, limit=20000):
        if self.fail:
            raise self.fail
        return self.searches[:limit]


class Store(InMemoryStore):
    pass


def seed(store):
    rows = [
        ("k1", "uc-1", "Windows Cmd Exec", SPL, ["T1059.003"]),
        ("k2", "uc-2", "Windows Cmd Exec", "| tstats other", ["T1059"]),
        ("k3", "uc-3", "Different Title", SPL, ["T1059"]),
        ("k4", "uc-4", "Unrelated", "| tstats nothing", ["T1000"]),
    ]
    for key, cid, title, spl, mitre in rows:
        store.upsert(C.CATALOG, {"_key": key, "content_id": cid, "title": title, "spl_hash": spl_hash(spl),
                                 "mitre_ids": mitre, "provider_status": "active", "provider": "p",
                                 "criticality": "high", "domains": [], "frameworks": [], "framework_controls": []})


class HelpersTest(unittest.TestCase):
    def test_title_normalisation_drops_escu_decoration(self):
        self.assertEqual(X.normalize_title("ESCU - Windows Cmd Exec - Rule"), "windows cmd exec")
        self.assertEqual(X.normalize_title("  Windows  cmd exec "), "windows cmd exec")

    def test_mitre_ids_come_from_annotations_only(self):
        raw = '{"mitre_attack": ["T1059.003", "T1059"], "nist": ["DE.CM"], "note": "see T9999x"}'
        self.assertEqual(X.mitre_ids(raw), ["T1059", "T1059.003"])
        self.assertEqual(X.mitre_ids(""), [])

    def test_key_is_stable_per_app_and_name(self):
        self.assertEqual(X.external_key("a", "n"), X.external_key("a", "n"))
        self.assertNotEqual(X.external_key("a", "n"), X.external_key("b", "n"))


class FakeTransport:
    def __init__(self):
        self.calls = []

    def json(self, method, path, query=None, **kw):
        self.calls.append((method, path, query))
        return {"entry": [
            {"name": "ESCU - A - Rule", "acl": {"app": "SplunkEnterpriseSecuritySuite", "owner": "nobody", "sharing": "app"},
             "content": {"search": SPL, "disabled": "0", "is_scheduled": "1",
                         "action.correlationsearch.annotations": '{"mitre_attack": ["T1059"]}'}},
            {"name": "Off", "acl": {"app": "search", "owner": "bob", "sharing": "user"},
             "content": {"search": "| x", "disabled": "1", "is_scheduled": "0"}},
            {"name": "", "content": {}}]}


class InventoryTest(unittest.TestCase):
    def test_listing_reads_names_flags_and_text_and_asks_for_everything(self):
        from splunk_ucm.discovery.inventory import SplunkInventory
        transport = FakeTransport()
        rows = SplunkInventory(transport).list_saved_searches()
        self.assertEqual(transport.calls, [("GET", "/servicesNS/-/-/saved/searches", {"count": "0"})])
        self.assertEqual([(r["name"], r["app"], r["enabled"], r["scheduled"]) for r in rows],
                         [("ESCU - A - Rule", "SplunkEnterpriseSecuritySuite", True, True), ("Off", "search", False, False)])
        self.assertEqual(rows[0]["search"], SPL)
        self.assertEqual(X.mitre_ids(rows[0]["annotations"]), ["T1059"])


class RunTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        seed(self.store)
        self.settings = ExternalSettings()

    def run_it(self, searches, **kw):
        return run_external(self.store, Inventory(searches, **kw), self.settings, "j1")

    def rows(self):
        return {r["name"]: r for r in self.store.query(C.EXTERNAL_MATCHES, {})}

    def test_hash_match_ranks_before_title_matches_and_spl_is_not_stored(self):
        summary = self.run_it([search("ESCU - Windows Cmd Exec - Rule", annotations='{"mitre_attack":["T1059"]}')])
        self.assertEqual((summary["listed"], summary["matched"], summary["proposed"]), (1, 1, 1))
        row = self.rows()["ESCU - Windows Cmd Exec - Rule"]
        self.assertEqual([(c["content_id"], c["basis"]) for c in row["candidates"]],
                         [("uc-1", "spl_hash"), ("uc-3", "spl_hash"), ("uc-2", "title_mitre")])
        self.assertEqual(row["state"], "proposed")
        self.assertNotIn(SPL, repr(row))
        self.assertNotIn("search", row)

    def test_no_candidate_is_counted_not_stored_and_own_app_is_skipped(self):
        summary = self.run_it([search("Nothing alike", spl="| tstats zzz"), search("Windows Cmd Exec", app="sunavigator")])
        self.assertEqual((summary["listed"], summary["matched"], summary["unmatched"]), (1, 0, 1))
        self.assertEqual(self.rows(), {})

    def test_title_only_basis_without_matching_mitre(self):
        self.run_it([search("Windows Cmd Exec", spl="| tstats changed")])
        row = self.rows()["Windows Cmd Exec"]
        self.assertEqual([(c["content_id"], c["basis"]) for c in row["candidates"]],
                         [("uc-1", "title"), ("uc-2", "title")])

    def test_decisions_survive_a_rerun_and_reset_when_the_search_changes(self):
        self.run_it([search("Windows Cmd Exec")])
        key = X.external_key("SplunkEnterpriseSecuritySuite", "Windows Cmd Exec")
        svc = ExternalMatchService(self.store, AuditService(self.store))
        svc.decide("bob", key, "accept", "k1")
        self.run_it([search("Windows Cmd Exec")])
        self.assertEqual(self.rows()["Windows Cmd Exec"]["state"], "accepted")
        summary = self.run_it([search("Windows Cmd Exec", spl=SPL + " | head 5")])
        row = self.rows()["Windows Cmd Exec"]
        self.assertEqual((row["state"], row["previous_state"], row["content_key"]), ("proposed", "accepted", ""))
        self.assertEqual(summary["reset"], 1)

    def test_disappeared_search_is_marked_missing_and_stops_counting(self):
        self.run_it([search("Windows Cmd Exec")])
        key = X.external_key("SplunkEnterpriseSecuritySuite", "Windows Cmd Exec")
        svc = ExternalMatchService(self.store, AuditService(self.store))
        svc.decide("bob", key, "accept", "k1")
        summary = self.run_it([])
        self.assertEqual(summary["missing"], 1)
        self.assertEqual(self.rows()["Windows Cmd Exec"]["status"], "missing")
        self.assertEqual(svc.elsewhere(), {})

    def test_truncated_listing_never_marks_anything_missing(self):
        self.run_it([search("Windows Cmd Exec")])
        self.settings.max_searches = 1
        summary = self.run_it([search("Other", spl="| tstats zzz"), search("Third", spl="| tstats yyy")])
        self.assertTrue(summary["truncated"])
        self.assertEqual(self.rows()["Windows Cmd Exec"]["status"], "active")

    def test_unreadable_listing_and_disabled_setting_change_nothing(self):
        self.run_it([search("Windows Cmd Exec")])
        before = self.rows()
        summary = self.run_it([], fail=RuntimeError("403"))
        self.assertFalse(summary["available"])
        self.assertEqual(self.rows(), before)
        self.settings.enabled = False
        self.assertEqual(self.run_it([search("x")])["listed"], 0)

    def test_inventory_without_the_listing_is_tolerated(self):
        summary = run_external(self.store, object(), self.settings, "j1")
        self.assertFalse(summary["available"])


class DecisionTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        seed(self.store)
        run_external(self.store, Inventory([search("Windows Cmd Exec", enabled=True),
                                            search("Windows Cmd Exec", app="other", enabled=False)]),
                     ExternalSettings(), "j1")
        self.svc = ExternalMatchService(self.store, AuditService(self.store))
        self.a = X.external_key("SplunkEnterpriseSecuritySuite", "Windows Cmd Exec")
        self.b = X.external_key("other", "Windows Cmd Exec")

    def test_accept_requires_a_listed_candidate(self):
        with self.assertRaises(ValidationError):
            self.svc.decide("bob", self.a, "accept", "k4")
        with self.assertRaises(NotFoundError):
            self.svc.decide("bob", "xm_" + "0" * 40, "reject")
        with self.assertRaises(NotFoundError):
            self.svc.decide("bob", "bad", "reject")
        with self.assertRaises(ValidationError):
            self.svc.decide("bob", self.a, "maybe")

    def test_accept_reject_reset_are_audited_by_name_only(self):
        self.svc.decide("bob", self.a, "accept", "k1")
        self.svc.decide("bob", self.b, "reject")
        self.svc.decide("bob", self.b, "reset")
        actions = [r["action"] for r in self.store.query(C.AUDIT, {})]
        self.assertEqual(sorted(actions), ["external.accepted", "external.rejected", "external.reset"])
        detail = [r for r in self.store.query(C.AUDIT, {}) if r["action"] == "external.accepted"][0]["details"]
        self.assertEqual(detail["name"], "Windows Cmd Exec")
        self.assertNotIn(SPL, repr(detail))

    def test_elsewhere_counts_only_accepted_matches_and_flags_enabled(self):
        self.svc.decide("bob", self.a, "accept", "k1")
        self.svc.decide("bob", self.b, "accept", "k1")
        found = self.svc.elsewhere()["k1"]
        self.assertEqual(sorted((m["app"], m["enabled"]) for m in found),
                         [("SplunkEnterpriseSecuritySuite", True), ("other", False)])
        self.assertEqual(self.svc.proposals_for("k1"), 0)
        self.assertEqual(self.svc.proposals_for("k3"), 0)

    def test_list_filters_by_state_and_counts(self):
        self.svc.decide("bob", self.a, "accept", "k1")
        listing = self.svc.list("proposed")
        self.assertEqual([i["app"] for i in listing["items"]], ["other"])
        self.assertEqual(listing["counts"], {"proposed": 1, "accepted": 1, "rejected": 0})
        with self.assertRaises(ValidationError):
            self.svc.list("nope")
        self.assertNotIn("search", listing["items"][0])


class CoverageTest(unittest.TestCase):
    def test_elsewhere_marks_cells_without_changing_levels_or_grade(self):
        store = Store()
        seed(store)
        cov = CoverageService(store)
        plain = cov.use_case_levels()
        accepted = {"k1": [{"app": "es", "name": "n", "enabled": True}, {"app": "x", "name": "m", "enabled": False}]}
        levels = cov.use_case_levels(elsewhere=accepted)
        self.assertEqual(levels["k1"]["elsewhere"], 1)
        self.assertEqual(levels["k2"]["elsewhere"], 0)
        self.assertEqual({k: v["level"] for k, v in levels.items()}, {k: v["level"] for k, v in plain.items()})
        definition = {"framework_id": "f", "version": "1", "name": "F", "domain": "enterprise",
                      "tactics": [{"id": "TA1", "name": "Exec"}],
                      "techniques": [{"id": "T1059", "name": "Cmd", "tactics": ["TA1"]},
                                     {"id": "T1059.003", "name": "Win", "tactics": ["TA1"], "parent": "T1059"}]}
        matrix = cov.attack_matrix(definition, levels)
        parent = matrix["tactics"][0]["techniques"][0]
        self.assertEqual(parent["elsewhere"], 1)
        self.assertEqual(parent["subs"][0]["elsewhere"], 1)
        self.assertEqual(parent["level"], "catalogue")
        self.assertEqual(matrix["totals"]["elsewhere"], 1)
        self.assertEqual(matrix["totals"]["covered"]["enabled"], 0)
        self.assertEqual(matrix["totals"]["grade_avg"], 0.0)


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        seed(self.store)
        run_external(self.store, Inventory([search("Windows Cmd Exec")]), ExternalSettings(), "j1")
        self.key = X.external_key("SplunkEnterpriseSecuritySuite", "Windows Cmd Exec")

    def test_listing_and_deciding_need_the_discovery_capability(self):
        viewer = make_ctx(self.store, [])
        self.assertEqual(call(viewer, "GET", "external")[0], 403)
        self.assertEqual(call(viewer, "POST", "external", body={"id": self.key, "decision": "reject"})[0], 403)
        operator = make_ctx(self.store, [CAP_RUN_DISCOVERY])
        status, body = call(operator, "GET", "external", {"state": "proposed"})
        self.assertEqual(status, 200)
        self.assertEqual(body["counts"]["proposed"], 1)
        status, body = call(operator, "POST", "external", body={"id": self.key, "decision": "accept",
                                                                "content_key": "k1"})
        self.assertEqual((status, body["match"]["state"]), (200, "accepted"))
        self.assertEqual(call(operator, "POST", "external", body={"id": self.key, "decision": "accept",
                                                                  "content_key": "k4"})[0], 400)

    def test_coverage_endpoints_carry_the_flag(self):
        operator = make_ctx(self.store, [CAP_RUN_DISCOVERY])
        call(operator, "POST", "external", body={"id": self.key, "decision": "accept", "content_key": "k1"})
        viewer = make_ctx(self.store, [])
        status, body = call(viewer, "GET", "frameworks")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()

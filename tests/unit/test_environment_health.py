import unittest

import helpers  # noqa: F401

from splunk_ucm.discovery import populated as P
from splunk_ucm.discovery.health import (SUMMARY_BUILT, SUMMARY_NO_DATA, SUMMARY_NOT_ACCELERATED, SUMMARY_NOT_BUILT,
                                         SUMMARY_PARTIAL, SUMMARY_UNVERIFIED, environment_health, model_summary_state)
from splunk_ucm.discovery.inventory import SplunkInventory
from splunk_ucm.platform.search import SearchResult
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_freshness import PassSearch, run
from unit.test_populated import Clock, ModelSearch, model


class SummaryCheckTest(unittest.TestCase):
    def test_accelerated_populated_models_get_a_summariesonly_count(self):
        s = ModelSearch({"Authentication": 42, "Web": 5, "Empty": 0})
        models = [model("Authentication", accelerated=True), model("Web"), model("Empty", accelerated=True)]
        out = P.check_models(s, models, ["Authentication", "Web", "Empty"], P.PopulatedSettings(), Clock())
        self.assertEqual(out["Authentication"]["summary_count"], 42)
        self.assertNotIn("summary_count", out["Web"])
        self.assertNotIn("summary_count", out["Empty"])
        self.assertIn("| tstats summariesonly=t count from datamodel=Authentication where earliest=-24h",
                      s.model_calls)
        self.assertEqual(len(s.model_calls), 4)

    def test_a_failed_summary_search_leaves_the_count_unset(self):
        class Failing(ModelSearch):
            def oneshot(self, search, **kw):
                if "summariesonly" in search:
                    raise RuntimeError("boom")
                return super().oneshot(search, **kw)
        out = P.check_models(Failing({"A": 3}), [model("A", accelerated=True)], ["A"], P.PopulatedSettings(), Clock())
        self.assertEqual((out["A"]["populated"], out["A"]["summary_count"]), ("yes", None))


class SummaryStateTest(unittest.TestCase):
    def test_states(self):
        self.assertEqual(model_summary_state({"accelerated": False}), SUMMARY_NOT_ACCELERATED)
        self.assertEqual(model_summary_state({"accelerated": True, "populated": "no"}), SUMMARY_NO_DATA)
        self.assertEqual(model_summary_state({"accelerated": True, "populated": "yes"}), SUMMARY_UNVERIFIED)
        self.assertEqual(model_summary_state({"accelerated": True, "populated": "yes", "populated_count": 10,
                                              "summary_count": 0}), SUMMARY_NOT_BUILT)
        self.assertEqual(model_summary_state({"accelerated": True, "populated": "yes", "populated_count": 10,
                                              "summary_count": 5}), SUMMARY_PARTIAL)
        self.assertEqual(model_summary_state({"accelerated": True, "populated": "yes", "populated_count": 10,
                                              "summary_count": 10}), SUMMARY_BUILT)


class MacroDefinitionTest(unittest.TestCase):
    def test_only_cim_index_macros_keep_their_definition(self):
        class T:
            def json(self, method, path, query=None, **kw):
                if path.endswith("admin/macros"):
                    return {"entry": [
                        {"name": "cim_Authentication_indexes", "acl": {"app": "Splunk_SA_CIM", "sharing": "global"},
                         "content": {"definition": "(index=wineventlog OR index=linux)"}},
                        {"name": "my_macro", "acl": {"app": "search"}, "content": {"definition": "secret stuff"}}]}
                return {"entry": []}
        inv = SplunkInventory.__new__(SplunkInventory)
        inv.t = T()
        rows = {r["name"]: r for r in inv.list_knowledge_objects() if r["kind"] == "macro"}
        self.assertEqual(rows["cim_Authentication_indexes"]["definition"], "(index=wineventlog OR index=linux)")
        self.assertNotIn("definition", rows["my_macro"])


class HealthPanelTest(unittest.TestCase):
    def test_not_discovered(self):
        self.assertEqual(environment_health(InMemoryStore()), {"discovered": False})

    def test_panel_from_stored_discovery(self):
        store, _ = run(PassSearch())
        store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "macro:x", "kind": "macro", "status": "active",
                                             "name": "cim_Authentication_indexes", "app": "Splunk_SA_CIM",
                                             "definition": "()"})
        store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "macro:y", "kind": "macro", "status": "active",
                                             "name": "cim_Web_indexes", "app": "Splunk_SA_CIM",
                                             "definition": "(index=proxy)"})
        h = environment_health(store)
        self.assertTrue(h["discovered"])
        self.assertEqual([m["constrained"] for m in h["cim_index_macros"]["items"]], [False, True])
        self.assertIn("main", [i["name"] for i in h["indexes_without_data"]["items"]])
        self.assertNotIn("_internal", [i["name"] for i in h["indexes_without_data"]["items"]])
        self.assertEqual([p["sourcetype"] for p in h["freshness"]["stale_from_start"]["items"]], ["WinEventLog:Old"])
        self.assertEqual([p["sourcetype"] for p in h["freshness"]["future_dated"]["items"]], ["WinEventLog:System"])
        self.assertEqual(h["freshness"]["future_only"][0]["sourcetype"], "clock_skew")
        self.assertIn("WinEventLog:Old", h["unmapped_sourcetypes"]["items"])
        self.assertNotIn("WinEventLog:Security", h["unmapped_sourcetypes"]["items"])
        self.assertTrue(all("summary_state" in m for m in h["datamodels"]["items"]))
        self.assertIn("installed", h["cim"])

    def test_route_is_readable_by_any_app_user(self):
        ctx = make_ctx(store=run(PassSearch())[0], caps=())
        status, body = call(ctx, "GET", "environment/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["discovered"])


if __name__ == "__main__":
    unittest.main()

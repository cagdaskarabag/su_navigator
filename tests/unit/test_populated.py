import configparser
import os
import unittest

import helpers  # noqa: F401
from splunk_ucm.audit import AuditService
from splunk_ucm.config import DEFAULTS, AppConfig
from splunk_ucm.discovery import populated as P
from splunk_ucm.discovery.service import DiscoveryService, DiscoverySettings, new_job as new_djob
from splunk_ucm.discovery.worker import settings_from_config
from splunk_ucm.errors import StorageError, UnsupportedOperation, ValidationError
from splunk_ucm.platform.search import SearchClient, SearchResult
from splunk_ucm.readiness.evaluators import MET, EvaluationSettings, evaluate
from splunk_ucm.readiness.recommend import RecommendationService
from splunk_ucm.readiness.scoring import ScoringSettings, score
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_discovery import APPS, INDEXES, ROWS, FakeInventory, loaded_catalog
from unit.test_platform_search import SplunkdOneshot
from unit.test_readiness import req, snap
from unit.test_recommend import DISCOVERY, uc

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def model(name, app="Splunk_SA_CIM", accelerated=True, disabled=False):
    return {"name": name, "app": app, "disabled": disabled, "display_name": name, "objects": [name],
            "accelerated": accelerated}


class ModelSearch:
    """Answers the populated check; every other search is the pair scan."""

    def __init__(self, counts=None, errors=None, messages=None, rows=None):
        self.counts = counts or {}
        self.errors = errors or {}
        self.messages = messages or {}
        self.rows = rows
        self.model_calls = []
        self.kwargs = []
        self.apps = []

    def oneshot(self, search, timeout=120.0, max_count=5000, earliest="", latest="", max_time=0, app=""):
        if "from datamodel=" not in search:
            return SearchResult([dict(r) for r in ROWS], [], False)
        name = search.split("datamodel=")[1].split(" ")[0]
        self.model_calls.append(search)
        self.kwargs.append({"timeout": timeout, "max_count": max_count, "max_time": max_time})
        self.apps.append(app)
        if name in self.errors:
            raise self.errors[name]
        if self.rows is not None:
            return SearchResult(self.rows, self.messages.get(name, []), False)
        return SearchResult([{"count": str(self.counts.get(name, 0))}], self.messages.get(name, []), False)


class Clock:
    def __init__(self, step=0.0):
        self.t = 0.0
        self.step = step

    def __call__(self):
        self.t += self.step
        return self.t


class SearchConstructionTest(unittest.TestCase):
    def test_exact_search_text(self):
        self.assertEqual(P.populated_search("Authentication"),
                         "| tstats count from datamodel=Authentication where earliest=-24h")

    def test_names_are_validated_before_a_search_is_built(self):
        for bad in ("", "a b", "x; | delete", "a|b", "../x", "A" * 81, None):
            with self.assertRaises(ValidationError):
                P.populated_search(bad)

    def test_search_runs_in_the_apps_namespace_of_the_model(self):
        s = ModelSearch({"Authentication": 1, "Mine": 1})
        P.check_models(s, [model("Authentication"), model("Mine", app="other_app")], ["Mine"], P.PopulatedSettings(), Clock())
        self.assertEqual(s.apps, ["other_app", "Splunk_SA_CIM"])

    def test_namespace_is_sent_to_splunkd(self):
        t = SplunkdOneshot([{"count": "1"}])
        SearchClient(t).oneshot("| tstats count from datamodel=A where earliest=-24h", app="my app")
        self.assertEqual(t.paths[0], "/servicesNS/nobody/my%20app/search/jobs")

    def test_max_time_reaches_splunkd(self):
        t = SplunkdOneshot([{"count": "1"}])
        SearchClient(t).oneshot("| tstats count from datamodel=A where earliest=-24h", timeout=30, max_count=1, max_time=30)
        self.assertEqual(t.forms[0]["max_time"], "30")
        self.assertEqual(t.forms[0]["timeout"], "30")
        SearchClient(t).oneshot("| tstats count", timeout=30)
        self.assertNotIn("max_time", t.forms[1])


class SelectionTest(unittest.TestCase):
    def test_referenced_first_then_cim_and_disabled_or_custom_left_out(self):
        models = [model("Web"), model("Authentication"), model("Mine", app="other"), model("Zed", app="other"),
                  model("Off", disabled=True)]
        self.assertEqual(P.select_models(models, ["zed", "Mine"]), ["Mine", "Zed", "Authentication", "Web"])
        self.assertEqual(P.select_models(models, []), ["Authentication", "Web"])


class CheckTest(unittest.TestCase):
    def run_check(self, search, models=None, referenced=("Authentication",), clock=None, **settings):
        models = models if models is not None else [model("Authentication")]
        return P.check_models(search, models, referenced, P.PopulatedSettings(**settings), clock or Clock())

    def test_yes_with_count(self):
        out = self.run_check(ModelSearch({"Authentication": 42}))
        self.assertEqual(out["Authentication"], {"populated": "yes", "reason": "", "count": 42})

    def test_no_when_the_search_completes_with_zero(self):
        out = self.run_check(ModelSearch({"Authentication": 0}))
        self.assertEqual(out["Authentication"]["populated"], "no")
        self.assertEqual(out["Authentication"]["count"], 0)

    def test_one_bounded_search_per_model(self):
        s = ModelSearch({"Authentication": 1})
        self.run_check(s, timeout_seconds=17)
        self.assertEqual(s.model_calls, ["| tstats count from datamodel=Authentication where earliest=-24h"])
        self.assertEqual(s.kwargs, [{"timeout": 17.0, "max_count": 1, "max_time": 17}])

    def test_timeout_is_unverified_with_reason(self):
        for exc in (StorageError("splunkd connection failed: timed out"), TimeoutError("read timeout")):
            out = self.run_check(ModelSearch(errors={"Authentication": exc}))
            self.assertEqual(out["Authentication"]["populated"], "unverified", exc)
            self.assertEqual(out["Authentication"]["reason"], "timeout")

    def test_finalized_zero_is_not_reported_as_no(self):
        msgs = {"Authentication": [{"type": "INFO", "text": "Search auto-finalized after time limit (30 seconds) reached."}]}
        out = self.run_check(ModelSearch({"Authentication": 0}, messages=msgs))
        self.assertEqual((out["Authentication"]["populated"], out["Authentication"]["reason"]), ("unverified", "timeout"))

    def test_finalized_with_events_is_still_yes(self):
        msgs = {"Authentication": [{"type": "INFO", "text": "Search auto-finalized after time limit (30 seconds) reached."}]}
        out = self.run_check(ModelSearch({"Authentication": 7}, messages=msgs))
        self.assertEqual(out["Authentication"]["populated"], "yes")

    def test_failure_is_unverified_and_never_raises(self):
        for exc in (RuntimeError("x"), StorageError("HTTP 500"), ValueError("v")):
            out = self.run_check(ModelSearch(errors={"Authentication": exc}))
            self.assertEqual((out["Authentication"]["populated"], out["Authentication"]["reason"]),
                             ("unverified", "search_failed"), exc)

    def test_search_not_available(self):
        out = self.run_check(ModelSearch(errors={"Authentication": UnsupportedOperation("no search")}))
        self.assertEqual(out["Authentication"]["reason"], "search_unavailable")

    def test_empty_result_is_unverified(self):
        for rows in ([], [{"count": "n/a"}]):
            out = self.run_check(ModelSearch(rows=rows))
            self.assertEqual((out["Authentication"]["populated"], out["Authentication"]["reason"]),
                             ("unverified", "no_result"))

    def test_cap_marks_the_rest_unverified(self):
        models = [model("A"), model("B"), model("C")]
        s = ModelSearch({"A": 1, "B": 1, "C": 1})
        out = self.run_check(s, models, referenced=("A", "B", "C"), max_models=2)
        self.assertEqual([out[n]["populated"] for n in "ABC"], ["yes", "yes", "unverified"])
        self.assertEqual(out["C"]["reason"], "model_cap")
        self.assertEqual(len(s.model_calls), 2)

    def test_not_accelerated_model_beyond_the_cap_is_skipped_with_a_reason(self):
        models = [model("A"), model("Slow", accelerated=False)]
        out = self.run_check(ModelSearch({"A": 1}), models, referenced=("A", "Slow"), max_models=1)
        self.assertEqual(out["Slow"], {"populated": "unverified", "reason": "model_cap", "count": None})

    def test_total_budget_stops_further_searches(self):
        models = [model("A"), model("B"), model("C")]
        s = ModelSearch({"A": 1, "B": 1, "C": 1})
        out = self.run_check(s, models, referenced=("A", "B", "C"), clock=Clock(step=100.0), budget_seconds=250)
        reasons = [out[n]["reason"] for n in "ABC"]
        self.assertIn("time_budget", reasons)
        self.assertLess(len(s.model_calls), 3)

    def test_repeated_failures_stop_the_check(self):
        names = ["M%d" % i for i in range(6)]
        s = ModelSearch(errors={n: RuntimeError("down") for n in names})
        out = self.run_check(s, [model(n) for n in names], referenced=names)
        self.assertEqual(len(s.model_calls), P.MAX_CONSECUTIVE_FAILURES)
        self.assertEqual(out["M5"]["reason"], "stopped_after_failures")

    def test_a_success_resets_the_failure_streak(self):
        names = ["M0", "M1", "M2", "M3", "M4"]
        s = ModelSearch({"M2": 5}, errors={"M0": RuntimeError("x"), "M1": RuntimeError("x"),
                                          "M3": RuntimeError("x"), "M4": RuntimeError("x")})
        self.run_check(s, [model(n) for n in names], referenced=names)
        self.assertEqual(len(s.model_calls), 5)

    def test_setting_off_runs_no_search_and_says_why(self):
        s = ModelSearch({"Authentication": 9})
        out = self.run_check(s, enabled=False)
        self.assertEqual(s.model_calls, [])
        self.assertEqual(out["Authentication"], {"populated": "unverified", "reason": "check_disabled", "count": None})

    def test_custom_unreferenced_model_is_not_searched(self):
        s = ModelSearch({"Mine": 3})
        out = self.run_check(s, [model("Mine", app="other")], referenced=())
        self.assertEqual(s.model_calls, [])
        self.assertEqual(out["Mine"]["reason"], "not_referenced")

    def test_invalid_model_name_is_unverified(self):
        out = self.run_check(ModelSearch(), [model("bad name", app="x")], referenced=("bad name",))
        self.assertEqual(out["bad name"]["reason"], "invalid_name")


class DiscoveryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.models = [model("Authentication"), model("Web", accelerated=False), model("Mine", app="other")]
        self.inv = FakeInventory(INDEXES, APPS, self.models)

    def run_job(self, search, **settings):
        svc = DiscoveryService(self.store, AuditService(self.store), self.inv, search,
                               DiscoverySettings(**settings), now_epoch=lambda: 1795163600)
        return svc.run(new_djob("alice"))

    def doc(self, name):
        return next(d for d in self.store.query(C.ENVIRONMENT_SOURCES, {"kind": "datamodel"}) if d["name"] == name)

    def test_populated_is_stored_next_to_each_model(self):
        job = self.run_job(ModelSearch({"Authentication": 12, "Web": 0}))
        self.assertEqual(job["status"], "succeeded")
        a, w, m = self.doc("Authentication"), self.doc("Web"), self.doc("Mine")
        self.assertEqual((a["populated"], a["populated_count"], a["populated_window"]), ("yes", 12, "-24h"))
        self.assertEqual((w["populated"], w["populated_count"]), ("no", 0))
        self.assertEqual((m["populated"], m["populated_reason"]), ("unverified", "not_referenced"))
        self.assertTrue(a["populated_at"])
        self.assertEqual(job["totals"]["populated"], {"enabled": True, "window": "-24h", "models": 3,
                                                      "yes": 1, "no": 1, "unverified": 1})

    def test_search_text_is_not_polluted(self):
        self.run_job(ModelSearch({"Authentication": 12}))
        self.assertNotIn("yes", self.doc("Authentication")["search_text"].split())

    def test_a_failing_check_never_fails_or_downgrades_the_job(self):
        job = self.run_job(ModelSearch(errors={n: RuntimeError("boom") for n in ("Authentication", "Web")}))
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["errors"], [])
        self.assertEqual(self.doc("Authentication")["populated"], "unverified")

    def test_setting_off(self):
        s = ModelSearch({"Authentication": 12})
        job = self.run_job(s, populated=P.PopulatedSettings(enabled=False))
        self.assertEqual(s.model_calls, [])
        self.assertEqual(self.doc("Authentication")["populated_reason"], "check_disabled")
        self.assertFalse(job["totals"]["populated"]["enabled"])

    def test_catalogue_references_are_checked_first_under_a_cap(self):
        self.store = InMemoryStore()
        self.store.upsert(C.CATALOG, {"_key": "x", "provider_status": "active", "datamodels": ["Web"]})
        s = ModelSearch({"Authentication": 1, "Web": 1})
        self.run_job(s, populated=P.PopulatedSettings(max_models=1))
        self.assertEqual(self.doc("Web")["populated"], "yes")
        self.assertEqual(self.doc("Authentication")["populated_reason"], "model_cap")

    def test_mapped_local_name_counts_as_referenced(self):
        self.store = InMemoryStore()
        self.store.upsert(C.CATALOG, {"_key": "x", "provider_status": "active", "datamodels": ["Network_Traffic"]})
        self.store.upsert(C.SOURCE_MAPPINGS, {"_key": "m1", "kind": "datamodel", "value": "Mine",
                                              "canonical_value": "Network_Traffic", "origin": "local"})
        s = ModelSearch({"Mine": 4})
        self.run_job(s, populated=P.PopulatedSettings(max_models=1))
        self.assertEqual(self.doc("Mine")["populated"], "yes")


class EvaluatorTest(unittest.TestCase):
    def doc(self, **extra):
        d = {"kind": "datamodel", "status": "active", "name": "Authentication", "app": "Splunk_SA_CIM",
             "accelerated": True}
        d.update(extra)
        return d

    def evaluate(self, **extra):
        return evaluate(req("cim_model", "Authentication"), snap([self.doc(**extra)]), EvaluationSettings())

    def test_status_is_met_for_every_populated_value(self):
        for extra in ({"populated": "yes", "populated_count": 5, "populated_window": "-24h"},
                      {"populated": "no", "populated_count": 0, "populated_window": "-24h"},
                      {"populated": "unverified", "populated_reason": "timeout"}, {}):
            r = self.evaluate(**extra)
            self.assertEqual((r["status"], r["code"]), (MET, "model_present"), extra)

    def test_yes_no_unverified_are_stated_separately(self):
        yes = self.evaluate(populated="yes", populated_count=5, populated_window="-24h")
        self.assertEqual(yes["populated"], "yes")
        self.assertIn("populated: yes (5 events in the last 24 h at discovery)", yes["detail"])
        self.assertEqual(yes["observed"][0]["populated_count"], 5)
        no = self.evaluate(populated="no", populated_count=0, populated_window="-24h")
        self.assertEqual(no["populated"], "no")
        self.assertIn("populated: no (the discovery check found no events in the last 24 h)", no["detail"])
        un = self.evaluate(populated="unverified", populated_reason="model_cap")
        self.assertEqual((un["populated"], un["populated_reason"]), ("unverified", "model_cap"))
        self.assertIn("populated: unverified (the cap on checked models", un["detail"])

    def test_old_discovery_data_without_the_field_is_unverified(self):
        r = self.evaluate()
        self.assertEqual((r["populated"], r["populated_reason"]), ("unverified", "predates_check"))
        self.assertIn("run discovery again", r["detail"])

    def test_scores_and_state_do_not_depend_on_populated(self):
        results = []
        for extra in ({"populated": "yes", "populated_count": 5}, {"populated": "no", "populated_count": 0}, {}):
            r = self.evaluate(**extra)
            results.append(score([dict(r, req_id="a", type="cim_model", level="required", confidence="high",
                                       source="provider_structured")], ScoringSettings()))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1], results[2])

    def test_missing_model_has_no_populated_field(self):
        r = evaluate(req("cim_model", "Web"), snap([self.doc()]), EvaluationSettings())
        self.assertEqual(r["code"], "model_missing")
        self.assertNotIn("populated", r)

    def test_aliased_model_carries_its_own_populated_value(self):
        s = snap([self.doc(name="Mine", populated="no", populated_count=0)],
                 [{"kind": "datamodel", "value": "Mine", "canonical_value": "Authentication", "origin": "local",
                   "confidence": "high"}])
        r = evaluate(req("cim_model", "Authentication"), s, EvaluationSettings())
        self.assertEqual((r["status"], r["populated"]), (MET, "no"))


class RecommendationTest(unittest.TestCase):
    def reasons(self, result):
        store = InMemoryStore()
        uc(store, 1, results=[result])
        return RecommendationService(store).recommend("u", DISCOVERY)["items"][0]["reasons"]

    def base(self, **extra):
        r = {"type": "cim_model", "value": "Authentication", "status": "met", "code": "model_present",
             "observed": [{"populated_count": 12}]}
        r.update(extra)
        return r

    def test_yes_no_and_unverified_wording(self):
        yes = " ".join(self.reasons(self.base(populated="yes")))
        self.assertIn("Data model Authentication: installed and populated in the last 24 h at discovery (12 events).", yes)
        no = " ".join(self.reasons(self.base(populated="no")))
        self.assertIn("found no events in the last 24 h (populated: no). The requirement still counts as met.", no)
        un = " ".join(self.reasons(self.base(populated="unverified", populated_reason="timeout")))
        self.assertIn("populated data not verified: the search hit its time limit", un)

    def test_stored_result_without_the_field_keeps_the_old_sentence(self):
        self.assertIn("Data model definition installed (populated data not verified).", self.reasons(self.base()))

    def test_state_and_order_do_not_depend_on_populated(self):
        store = InMemoryStore()
        uc(store, 1, results=[self.base(populated="no")], score=80)
        uc(store, 2, results=[self.base(populated="yes")], score=80)
        out = RecommendationService(store).recommend("u", DISCOVERY)
        self.assertEqual([i["state"] for i in out["items"]], ["ready", "ready"])
        self.assertEqual(out["items"][0]["draft_score"], out["items"][1]["draft_score"])


class SettingsTest(unittest.TestCase):
    def test_defaults_are_enabled_and_bounded(self):
        s = settings_from_config(AppConfig({})).populated
        self.assertEqual((s.enabled, s.max_models, s.timeout_seconds, s.budget_seconds), (True, 30, 30, 300))

    def test_overrides_are_clamped(self):
        s = settings_from_config(AppConfig({"discovery": {
            "populated_check": "false", "populated_max_models": "9999", "populated_timeout_seconds": "1",
            "job_timeout_seconds": "900"}})).populated
        self.assertEqual((s.enabled, s.max_models, s.timeout_seconds, s.budget_seconds), (False, 100, 5, 450))

    def test_default_conf_spec_and_config_agree(self):
        parser = configparser.RawConfigParser()
        parser.optionxform = str
        parser.read(os.path.join(ROOT, "sunavigator", "default", "ucm.conf"))
        with open(os.path.join(ROOT, "sunavigator", "README", "ucm.conf.spec"), encoding="utf-8") as handle:
            spec = handle.read()
        for key in ("populated_check", "populated_max_models", "populated_timeout_seconds"):
            self.assertEqual(parser.get("discovery", key), DEFAULTS["discovery"][key], key)
            self.assertIn("\n%s = <" % key, spec, key)


if __name__ == "__main__":
    unittest.main()

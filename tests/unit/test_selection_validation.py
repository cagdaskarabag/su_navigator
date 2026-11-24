import unittest
import json

from splunk_ucm.api.app import CAP_RUN_DISCOVERY
from splunk_ucm.audit import AuditService
from splunk_ucm.errors import ValidationError
from splunk_ucm.platform.search import ParseResult, SearchResult
from splunk_ucm.readiness.evaluators import MET, NOT_MET, PARTIAL, UNVERIFIED, EvaluationSettings, evaluate
from splunk_ucm.readiness.service import assess_use_case, ReadinessSettings
from splunk_ucm.readiness.snapshot import EnvironmentSnapshot
from splunk_ucm.selection.service import SelectionService
from splunk_ucm.spl.parser import for_parser, parser_candidates
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import encode_raw
from splunk_ucm.validation.service import ValidationService
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import APPS, INDEXES, MODELS, ROWS, FakeInventory, FakeSearch, loaded_catalog
from splunk_ucm.discovery.service import DiscoveryService, new_job as new_djob
from splunk_ucm.content.reindex import StoredNormalizer
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository


class FakeParser:
    def __init__(self, ok=True, commands=None, error="", field_rows=None, preview_rows=None):
        self.ok = ok
        self.commands = commands or ["search", "stats"]
        self.error = error
        self.field_rows = field_rows if field_rows is not None else [
            {"field": "sun_sample_marker", "count": "12", "values": "[]"},
            {"field": "host", "count": "12", "values": '[{"value":"idx","count":12}]'},
        ]
        self.preview_rows = preview_rows or [{"host": "h1", "count": "1"}]
        self.preview_calls = []
        self.oneshot_calls = []
        self.parse_calls = []

    def parse(self, q, app=""):
        self.parse_calls.append(q)
        self.parse_apps = getattr(self, "parse_apps", []) + [app]
        if not self.ok:
            return ParseResult(False, [], [{"type": "FATAL", "text": self.error}])
        return ParseResult(True, list(self.commands), [])

    def preview(self, search, timeout=30, max_count=50, earliest="-15m", latest="now", app=""):
        self.preview_calls.append(search)
        self.preview_apps = getattr(self, "preview_apps", []) + [app]
        return SearchResult(list(self.preview_rows), [], False)

    field_truncated = False
    field_error = None

    def oneshot(self, search, timeout=30, max_count=50, earliest="", latest=""):
        self.oneshot_calls.append(search)
        self.oneshot_windows = getattr(self, "oneshot_windows", []) + [(earliest, latest)]
        if not search.startswith("|"):
            raise ValidationError("only generating searches are permitted")
        if self.field_error:
            raise self.field_error
        return SearchResult(list(self.field_rows), [], self.field_truncated)


def discovered():
    store = loaded_catalog()
    inv = FakeInventory(INDEXES, APPS, MODELS)
    DiscoveryService(store, AuditService(store), inv, FakeSearch(ROWS),
                     now_epoch=lambda: 1795163600).run(new_djob("alice"))
    return store


class ParserPrepTest(unittest.TestCase):
    def test_prefixes_index_equals(self):
        cands = parser_candidates("index=_internal | stats count")
        self.assertEqual(cands[0], "index=_internal | stats count")
        self.assertIn("search index=_internal | stats count", cands)
        self.assertEqual(parser_candidates("| tstats count where index=_internal"),
                         ["| tstats count where index=_internal"])
        self.assertTrue(for_parser("search index=main").startswith("search "))
        with self.assertRaises(ValidationError):
            for_parser("  ")


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.svc = SelectionService(self.store, AuditService(self.store))

    def test_upsert_list_delete(self):
        doc = self.svc.upsert("alice", "fenre:UC-9.1.1", "select", "try this", 80)
        self.assertEqual(doc["intent"], "select")
        self.assertEqual(doc["title"], self.store.get(C.CATALOG, "fenre_UC-9.1.1")["title"])
        listed = self.svc.list_for("alice", "backlog")
        self.assertEqual(len(listed["items"]), 1)
        self.svc.upsert("alice", "fenre:UC-9.1.1", "bookmark")
        self.assertEqual(self.svc.list_for("alice", "backlog")["items"], [])
        self.assertEqual(self.svc.list_for("bob", None)["items"], [])
        self.svc.delete("alice", "fenre:UC-9.1.1")
        self.assertIsNone(self.svc.for_use_case("alice", "fenre:UC-9.1.1"))

    def test_rejects_unknown_use_case(self):
        with self.assertRaises(Exception):
            self.svc.upsert("alice", "fenre:UC-99.99.99", "select")


class ValidationServiceTest(unittest.TestCase):
    def setUp(self):
        self.store = discovered()
        self.search = FakeParser()
        self.svc = ValidationService(self.store, AuditService(self.store), self.search)

    def test_parse_and_refuse_side_effects(self):
        self.search.commands = ["search", "outputlookup"]
        with self.assertRaises(ValidationError) as ctx:
            self.svc.preview("fenre:UC-9.1.1", "alice")
        self.assertIn("side-effect", str(ctx.exception).lower())
        self.assertEqual(self.search.preview_calls, [])

    def test_review_commands_refuse_preview(self):
        self.search.commands = ["search", "map"]
        with self.assertRaises(ValidationError) as ctx:
            self.svc.preview("fenre:UC-9.1.1", "alice")
        self.assertEqual(ctx.exception.details["code"], "review_commands")
        self.assertEqual(ctx.exception.details["indirect"], ["map"])
        self.assertEqual(self.search.preview_calls, [])
        doc = self.svc.parse_only("fenre:UC-9.1.1", "alice")
        self.assertEqual(doc["review_commands"], ["map"])
        self.assertIn("commands needing review: map", doc["warnings"])

    def test_extra_safe_command_allows_preview(self):
        self.search.commands = ["search", "apply"]
        with self.assertRaises(ValidationError):
            self.svc.preview("fenre:UC-9.1.1", "alice")
        self.svc.settings.extra_safe_commands = ("apply",)
        self.assertTrue(self.svc.preview("fenre:UC-9.1.1", "alice")["preview"]["ok"])

    def test_parse_and_preview_use_the_deploy_namespace(self):
        self.svc.preview("fenre:UC-9.1.1", "alice")
        self.assertEqual(set(self.search.parse_apps), {"sunavigator"})
        self.assertEqual(self.search.preview_apps, ["sunavigator"])

    def test_parse_failure_refuses_preview(self):
        self.search.ok = False
        self.search.error = "Error in stats"
        with self.assertRaises(ValidationError):
            self.svc.preview("fenre:UC-9.1.1", "alice")

    def test_preview_and_field_sample(self):
        doc = self.svc.preview("fenre:UC-9.1.1", "alice")
        self.assertTrue(doc["parse_ok"])
        self.assertTrue(doc["preview"]["ok"])
        self.assertTrue(any(c.startswith("search ") or c.startswith("index=") or c.startswith("`")
                            for c in self.search.parse_calls))
        from splunk_ucm.discovery.keys import source_key
        self.store.upsert(C.ENVIRONMENT_SOURCES, {
            "_key": source_key("pair", "_internal", "splunkd"), "kind": "pair", "status": "active",
            "index": "_internal", "sourcetype": "splunkd", "window_count": 10})
        sampled = self.svc.sample_and_assess("fenre:UC-13.1.1", "alice")
        self.assertTrue(self.search.oneshot_calls)
        self.assertTrue(self.search.oneshot_calls[0].startswith("| search "))
        self.assertIn("fieldsummary", self.search.oneshot_calls[0])
        self.assertNotIn("outputlookup", self.search.oneshot_calls[0])
        names = {r["field"]: r["present"] for r in sampled["field_samples"]}
        self.assertTrue(names.get("host") or names.get("_time") or sampled["field_samples"])


class FieldSampleCompletenessTest(unittest.TestCase):
    def setUp(self):
        from splunk_ucm.discovery.keys import source_key
        self.store = discovered()
        self.search = FakeParser()
        self.svc = ValidationService(self.store, AuditService(self.store), self.search)
        self.store.upsert(C.ENVIRONMENT_SOURCES, {
            "_key": source_key("pair", "wineventlog", "st_a"), "kind": "pair", "status": "active",
            "index": "wineventlog", "sourcetype": "st_a", "window_count": 10})

    def sample(self):
        return {r["field"]: r for r in self.svc._sample(["host", "user"], ["st_a"])}

    def test_complete_sample_can_show_absence(self):
        out = self.sample()
        self.assertTrue(out["host"]["present"])
        self.assertTrue(out["user"]["sampled"])
        self.assertFalse(out["user"]["present"])

    def test_truncated_sample_is_not_absence(self):
        self.search.field_truncated = True
        out = self.sample()
        self.assertTrue(out["host"]["present"])
        self.assertEqual((out["user"]["sampled"], out["user"]["reason"]), (False, "sample_truncated"))
        snap = EnvironmentSnapshot([], [], {"last_completed_at": "t"}, [{
            "_key": "k", "content_id": "c", "field_samples": [out["user"]]}])
        res = evaluate({"type": "field", "value": "user"}, snap, EvaluationSettings(), "c", "k")
        self.assertEqual((res["status"], res["code"]), (UNVERIFIED, "sample_truncated"))
        self.assertIn("truncated", res["detail"])

    def test_empty_sample_is_not_absence(self):
        self.search.field_rows = []
        out = self.sample()
        self.assertEqual((out["user"]["sampled"], out["user"]["reason"]), (False, "sample_empty"))
        self.assertEqual(out["host"]["reason"], "sample_empty")
        snap = EnvironmentSnapshot([], [], {"last_completed_at": "t"}, [{
            "_key": "k", "content_id": "c", "field_samples": [out["user"]]}])
        res = evaluate({"type": "field", "value": "user"}, snap, EvaluationSettings(), "c", "k")
        self.assertEqual((res["status"], res["code"]), (UNVERIFIED, "sample_empty"))

    def test_events_without_requested_fields_show_absence(self):
        self.search.field_rows = [{"field": "sun_sample_marker", "count": "40", "values": "[]"}]
        out = self.sample()
        self.assertEqual((out["user"]["sampled"], out["user"]["present"]), (True, False))

    def test_window_ends_at_the_pairs_newest_event(self):
        from splunk_ucm.discovery.keys import source_key
        self.store.upsert(C.ENVIRONMENT_SOURCES, {
            "_key": source_key("pair", "wineventlog", "st_a"), "kind": "pair", "status": "active",
            "index": "wineventlog", "sourcetype": "st_a", "window_count": 10, "last_time": 1795000000})
        self.sample()
        self.assertEqual(self.search.oneshot_windows[-1], (str(1795000000 - 3600), "1795000001"))

    def test_window_falls_back_without_last_time(self):
        self.sample()
        self.assertEqual(self.search.oneshot_windows[-1], ("-15m", "now"))

    def test_summary_is_restricted_to_requested_fields(self):
        self.svc._sample(["host", "Authentication.user", "bad field", "sun_sample_marker"], ["st_a"])
        spl = self.search.oneshot_calls[-1]
        self.assertIn('| eval sun_sample_marker=1 | fields sun_sample_marker "host" "Authentication.user" '
                      '| fieldsummary', spl)
        self.assertNotIn("bad field", spl)

    def test_failed_sample_is_not_absence(self):
        from splunk_ucm.errors import UnsupportedOperation
        self.search.field_error = UnsupportedOperation("search failed")
        out = self.sample()
        self.assertEqual((out["user"]["sampled"], out["user"]["reason"]), (False, "sample_failed"))
        self.assertEqual(out["host"]["reason"], "sample_failed")


class DerivedFieldTest(unittest.TestCase):
    def test_derived_field_is_not_applicable_and_not_sampled(self):
        res = evaluate({"type": "field", "value": "age_days", "attributes": {"derived_in_spl": "eval"}},
                       EnvironmentSnapshot([], [], {"last_completed_at": "t"}, []), EvaluationSettings())
        self.assertEqual((res["status"], res["code"]), ("not_applicable", "derived_in_spl"))
        store = discovered()
        doc = store.get(C.CONTENT, "fenre_UC-9.1.1")
        raw = json.loads(doc["raw_json"])
        raw["spl"] = raw["spl"] + " | eval sun_derived=1"
        raw["requiredFields"] = ["user", "sun_derived"]
        doc["raw_json"] = encode_raw(raw)
        store.upsert(C.CONTENT, doc)
        search = FakeParser()
        out = ValidationService(store, AuditService(store), search).sample_and_assess("fenre:UC-9.1.1", "alice")
        self.assertEqual([f["field"] for f in out["field_samples"]], ["user"])
        self.assertNotIn("sun_derived", search.oneshot_calls[-1])


class EvaluatorValidationTest(unittest.TestCase):
    def test_field_and_spl_from_validation_doc(self):
        snap = EnvironmentSnapshot([], [], {"last_completed_at": "t", "splunk_version": "10.2.9"}, [{
            "_key": "fenre_UC-x", "content_id": "fenre:UC-x", "parse_ok": True, "commands": ["search"],
            "side_effects": [], "field_samples": [
                {"field": "user", "present": True, "sampled": True, "count": 4, "sourcetype": "st", "index": "main"},
                {"field": "missing_f", "present": False, "sampled": True, "count": 0},
            ]}])
        settings = EvaluationSettings()
        self.assertEqual(evaluate({"type": "spl_validity", "value": "primary"}, snap, settings,
                                  "fenre:UC-x", "fenre_UC-x")["status"], MET)
        self.assertEqual(evaluate({"type": "field", "value": "user"}, snap, settings,
                                  "fenre:UC-x", "fenre_UC-x")["status"], MET)
        self.assertEqual(evaluate({"type": "field", "value": "missing_f"}, snap, settings,
                                  "fenre:UC-x", "fenre_UC-x")["status"], NOT_MET)
        self.assertEqual(evaluate({"type": "field", "value": "user"}, snap, settings, "other", "other")["status"],
                         UNVERIFIED)

    def test_side_effect_parse_is_partial(self):
        snap = EnvironmentSnapshot([], [], {"last_completed_at": "t"}, [{
            "content_id": "fenre:UC-x", "_key": "k", "parse_ok": True, "side_effects": ["delete"],
            "commands": ["search", "delete"]}])
        out = evaluate({"type": "spl_validity", "value": "primary"}, snap, EvaluationSettings(), "fenre:UC-x", "k")
        self.assertEqual(out["status"], PARTIAL)

    def test_review_commands_parse_is_partial(self):
        snap = EnvironmentSnapshot([], [], {"last_completed_at": "t"}, [{
            "content_id": "fenre:UC-x", "_key": "k", "parse_ok": True, "side_effects": [],
            "review_commands": ["map"], "commands": ["search", "map"]}])
        out = evaluate({"type": "spl_validity", "value": "primary"}, snap, EvaluationSettings(), "fenre:UC-x", "k")
        self.assertEqual((out["status"], out["code"]), (PARTIAL, "review_commands"))

    def test_synthetic_spl_requirement_scored(self):
        store = loaded_catalog()
        stored = ContentRepository(store).get_content("fenre_UC-9.1.1")
        uc = StoredNormalizer(CategoryRepository(store)).normalize(stored)
        snap = EnvironmentSnapshot([], [], {"last_completed_at": "t", "splunk_version": "10.2.9"}, [{
            "content_id": uc.content_id, "_key": uc.key, "parse_ok": True, "side_effects": [],
            "commands": ["search"]}])
        doc = assess_use_case(uc, snap, ReadinessSettings())
        spl = [r for r in doc["results"] if r["type"] == "spl_validity"]
        self.assertEqual(spl[0]["status"], MET)


class SelectionValidationApiTest(unittest.TestCase):
    def test_viewer_can_select_not_validate(self):
        store = loaded_catalog()
        viewer = make_ctx(store, [])
        status, body = call(viewer, "POST", "selections", body={"id": "fenre:UC-9.1.1", "intent": "select"})
        self.assertEqual(status, 200, body)
        self.assertEqual(call(viewer, "GET", "selections", {"intent": "backlog"})[0], 200)
        self.assertEqual(call(viewer, "POST", "validate", body={"id": "fenre:UC-9.1.1"})[0], 403)
        self.assertEqual(call(viewer, "POST", "preview", body={"id": "fenre:UC-9.1.1"})[0], 403)
        analyst = make_ctx(store, [CAP_RUN_DISCOVERY])
        # no search client that parses — expect 500/error from NoSplunkd; capability is the point
        self.assertNotEqual(call(analyst, "POST", "validate", body={"id": "fenre:UC-9.1.1"})[0], 403)


if __name__ == "__main__":
    unittest.main()

import os
import re
import unittest

import helpers  # noqa: F401

from splunk_ucm.audit import AuditService
from splunk_ucm.config import AppConfig
from splunk_ucm.errors import ValidationError
from splunk_ucm.readiness import ENGINE_VERSION
from splunk_ucm.readiness.evidence import (DATA_NONE, DATA_NOT_APPLICABLE, DATA_PARTIAL, DATA_SEEN, DATA_STATES,
                                           DATA_UNVERIFIED, data_evidence, requirement_evidence, summary_line)
from splunk_ucm.readiness.query import ReadinessFilter, ReadinessQueryService
from splunk_ucm.readiness.recommend import RecommendationService
from splunk_ucm.readiness.service import ReadinessService, new_job
from splunk_ucm.readiness.worker import ReadinessWorker
from splunk_ucm.storage import collections as C
from unit.test_readiness import discovered_store


def r(type_, status, level="required", **extra):
    return dict({"type": type_, "value": type_ + "_x", "status": status, "code": "c", "level": level}, **extra)


class RequirementEvidenceTest(unittest.TestCase):
    def test_each_type(self):
        self.assertEqual(requirement_evidence(r("sourcetype", "met")), "seen")
        self.assertEqual(requirement_evidence(r("sourcetype", "partial")), "stale")
        self.assertEqual(requirement_evidence(r("sourcetype", "not_met")), "missing")
        self.assertEqual(requirement_evidence(r("index", "partial")), "missing")
        self.assertEqual(requirement_evidence(r("index", "unverified")), "unverified")
        self.assertEqual(requirement_evidence(r("cim_model", "met", populated="yes")), "seen")
        self.assertEqual(requirement_evidence(r("cim_model", "met", populated="no")), "missing")
        self.assertEqual(requirement_evidence(r("cim_model", "met", populated="unverified")), "unverified")
        self.assertEqual(requirement_evidence(r("cim_model", "met")), "unverified")
        self.assertEqual(requirement_evidence(r("cim_model", "not_met")), "missing")
        self.assertEqual(requirement_evidence(r("field", "met")), "seen")
        self.assertEqual(requirement_evidence(r("field", "not_met")), "missing")
        self.assertEqual(requirement_evidence(r("field", "unverified")), "unverified")

    def test_ignored(self):
        self.assertIsNone(requirement_evidence(r("field", "not_applicable")))
        self.assertIsNone(requirement_evidence(r("addon", "not_met")))
        self.assertIsNone(requirement_evidence(r("datamodel_acceleration", "not_met")))
        self.assertIsNone(requirement_evidence(r("sourcetype", "not_met", level="informational")))
        self.assertIsNone(requirement_evidence(r("sourcetype", "not_met", collapsed=True)))


class DataEvidenceTest(unittest.TestCase):
    def state(self, *rows):
        return data_evidence(rows)["state"]

    def test_states(self):
        self.assertEqual(self.state(), DATA_NOT_APPLICABLE)
        self.assertEqual(self.state(r("addon", "met")), DATA_NOT_APPLICABLE)
        self.assertEqual(self.state(r("sourcetype", "met"), r("field", "unverified")), DATA_SEEN)
        self.assertEqual(self.state(r("sourcetype", "met"), r("field", "not_met")), DATA_PARTIAL)
        self.assertEqual(self.state(r("sourcetype", "partial")), DATA_NONE)
        self.assertEqual(self.state(r("cim_model", "met", populated="no"), r("field", "unverified")), DATA_NONE)
        self.assertEqual(self.state(r("cim_model", "met", populated="unverified")), DATA_UNVERIFIED)

    def test_installed_but_empty_data_model_is_not_data_seen(self):
        ev = data_evidence([r("cim_model", "met", value="Endpoint", populated="no"), r("addon", "met")])
        self.assertEqual(ev["state"], DATA_NONE)
        self.assertEqual(ev["missing"], [{"type": "cim_model", "value": "Endpoint", "code": "c", "level": "required"}])
        self.assertIn("cim_model Endpoint", summary_line(ev))

    def test_any_of_groups_name_all_members(self):
        ev = data_evidence([r("sourcetype", "not_met", any_of=["a", "b"])])
        self.assertEqual(ev["missing"][0]["value"], "any of a, b")

    def test_summary_lines(self):
        self.assertTrue(summary_line(data_evidence([r("index", "met")])).startswith("Data seen"))
        self.assertTrue(summary_line(data_evidence([r("index", "met"), r("index", "not_met")])).startswith("Data partly"))
        self.assertTrue(summary_line(data_evidence([r("field", "unverified")])).startswith("Data not verified"))
        self.assertTrue(summary_line(data_evidence([])).startswith("The use case names no data"))


class StoredEvidenceTest(unittest.TestCase):
    def test_assessment_stores_data_state_and_summary_counts_it(self):
        self.assertEqual(ENGINE_VERSION, "ucm.readiness/6")
        store = discovered_store()
        ReadinessService(store, AuditService(store)).run(new_job("alice"))
        doc = store.get(C.READINESS, "fenre_UC-9.1.1")
        self.assertIn(doc["data_state"], DATA_STATES)
        self.assertEqual(doc["data_evidence"]["state"], doc["data_state"])
        summary = ReadinessQueryService(store).summary()
        self.assertEqual(sum(summary["by_data_state"].values()), summary["total"])
        page = ReadinessQueryService(store).search(ReadinessFilter(data_states=[doc["data_state"]]))
        self.assertIn("fenre_UC-9.1.1", [i["_key"] for i in page["items"]])
        self.assertIn("data_evidence", page["items"][0])
        with self.assertRaises(ValidationError):
            ReadinessQueryService(store).search(ReadinessFilter(data_states=["maybe"]))

    def test_engine_upgrade_queues_one_reassessment(self):
        store = discovered_store()
        worker = ReadinessWorker(store, AppConfig({}), lambda: True)
        self.assertEqual(worker.run_once()["action"], "ran")
        self.assertEqual(worker.run_once()["action"], "idle")
        state = store.get(C.SYNC_STATE, "readiness::local")
        state["engine_version"] = "ucm.readiness/4"
        store.upsert(C.SYNC_STATE, state)
        self.assertEqual(worker.run_once()["action"], "ran")
        self.assertEqual(worker.run_once()["action"], "idle")

    def test_recommender_leaves_out_use_cases_with_no_data_seen(self):
        store = discovered_store()
        ReadinessService(store, AuditService(store)).run(new_job("alice"))
        before = RecommendationService(store).recommend("alice", "2026-01-01T00:00:00Z")
        self.assertTrue(before["items"])
        first = before["items"][0]
        self.assertTrue(any(line.startswith(("Data", "No data", "The use case names")) for line in first["reasons"]))
        key = first["content_id"].replace(":", "_")
        doc = store.get(C.READINESS, key)
        doc["data_state"] = DATA_NONE
        doc["data_evidence"] = data_evidence([r("cim_model", "met", value="Endpoint", populated="no")])
        store.upsert(C.READINESS, doc)
        after = RecommendationService(store).recommend("alice", "2026-01-01T00:00:00Z")
        self.assertNotIn(first["content_id"], [i["content_id"] for i in after["items"]])
        self.assertEqual(after["excluded"]["no_data_seen"], 1)
        self.assertEqual(after["formula"]["version"], "ucm.recommend/2")


class DataGlossaryTest(unittest.TestCase):
    def test_js_names_the_engine_data_states(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "appserver", "static", "ucm_common.js")
        with open(path, encoding="utf-8") as handle:
            js = handle.read()
        array = js.split("var DATA_STATES = [", 1)[1].split("]", 1)[0]
        self.assertEqual(re.findall(r'"(\w+)"', array), list(DATA_STATES))
        labels = js.split("var DATA_LABELS = {", 1)[1].split("};", 1)[0]
        self.assertEqual(re.findall(r"(\w+): \[", labels), list(DATA_STATES))
        helptext = js.split("var DATA_HELP = {", 1)[1].split("};", 1)[0]
        self.assertEqual(re.findall(r"^\s*(\w+):", helptext, re.M), list(DATA_STATES))


if __name__ == "__main__":
    unittest.main()

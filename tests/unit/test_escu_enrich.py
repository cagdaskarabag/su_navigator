import copy
import json
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.catalog.detail import UseCaseDetailService
from splunk_ucm.content.escu.enrich import enrich, macro_names, macro_sourcetype
from splunk_ucm.content.escu.package import build_bundle
from splunk_ucm.content.importer import BundleImportService
from splunk_ucm.content.sync import SyncService
from splunk_ucm.discovery.events import targets
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
from unit.test_escu import FIXTURE, LOGONS, SCANNING

DETECTION = {
    "id": "x", "status": "experimental",
    "data_source": ["AWS CloudTrail DescribeImageScanFindings", "Missing Source"],
    "how_to_implement": "Install the   add-on.\nThen enable it.",
    "known_false_positives": "Admins.",
    "drilldown_searches": [{"name": "View $user$", "search": "| from datamodel:Risk"}, "junk"],
    "rba": {"entities": [{"field": "user", "type": "user", "score": 20, "message": "m"},
                         {"field": "bad field", "type": "user", "score": 20},
                         {"field": "dest", "type": "system", "score": 1000}]},
    "tests": [{"name": "t", "test_type": "unit", "attack_data": [
        {"data": "https://media.githubusercontent.com/x.log", "sourcetype": "aws:cloudtrail", "source": "s"},
        {"data": "http://insecure.example/x.log", "sourcetype": "a", "source": "b"},
        {"data": "javascript:alert(1)", "sourcetype": "a", "source": "b"}]}],
}
SOURCES = {"AWS CloudTrail DescribeImageScanFindings": {
    "name": "AWS CloudTrail DescribeImageScanFindings", "sourcetype": "aws:cloudtrail", "source": "aws_cloudtrail",
    "separator": "eventName", "separator_value": "DescribeImageScanFindings",
    "supported_TA": [{"name": "Splunk Add-on for AWS", "url": "https://splunkbase.splunk.com/app/1876", "version": "7.0"},
                     {"name": "Bad", "url": "javascript:x"}]}}
MACROS = {"cloudtrail": {"name": "cloudtrail", "definition": "sourcetype=aws:cloudtrail"},
          "complex": {"name": "complex", "definition": "index=x sourcetype=y"}}


class EnrichTest(unittest.TestCase):
    def test_unmatched_record_is_left_alone(self):
        raw = {"id": "x", "search": "`cloudtrail`"}
        self.assertEqual(enrich(raw, None, SOURCES, MACROS), raw)

    def test_input_is_not_modified(self):
        raw = {"id": "x", "search": "`cloudtrail` | stats count"}
        before = copy.deepcopy(raw)
        enrich(raw, DETECTION, SOURCES, MACROS)
        self.assertEqual(raw, before)

    def test_fields_are_added_and_bounded(self):
        out = enrich({"id": "x", "search": "`cloudtrail` | `complex` | `cloudtrail`"}, DETECTION, SOURCES, MACROS)
        self.assertEqual(out["status"], "experimental")
        self.assertEqual(len(out["dataSourceDetails"]), 1)
        detail = out["dataSourceDetails"][0]
        self.assertEqual((detail["sourcetype"], detail["separator"], detail["separatorValue"]),
                         ("aws:cloudtrail", "eventName", "DescribeImageScanFindings"))
        self.assertEqual([t["name"] for t in out["supportedTA"]], ["Splunk Add-on for AWS", "Bad"])
        self.assertEqual(out["supportedTA"][1]["url"], "")
        self.assertEqual([d["name"] for d in out["drilldowns"]], ["View $user$"])
        self.assertEqual([e["field"] for e in out["riskEntities"]], ["user", "dest"])
        self.assertIsNone(out["riskEntities"][1]["score"])
        self.assertEqual(out["howToImplement"], "Install the add-on. Then enable it.")
        self.assertEqual(sorted(out["macroDefinitions"]), ["cloudtrail", "complex"])

    def test_only_https_attack_data_links_are_kept(self):
        out = enrich({"id": "x", "search": ""}, DETECTION, SOURCES, MACROS)
        self.assertEqual([d["url"] for d in out["tests"][0]["attackData"]], ["https://media.githubusercontent.com/x.log"])

    def test_unsafe_separator_is_dropped(self):
        sources = {"s": {"name": "s", "sourcetype": "a:b", "separator": "event Name", "separator_value": "x"}}
        out = enrich({"id": "x", "search": ""}, {"data_source": ["s"]}, sources, {})
        self.assertNotIn("separator", out["dataSourceDetails"][0])

    def test_macro_helpers(self):
        self.assertEqual(macro_names("`a` | `b(1,2)` | `a`"), ["a", "b"])
        self.assertEqual(macro_sourcetype("sourcetype=aws:cloudtrail"), "aws:cloudtrail")
        self.assertEqual(macro_sourcetype('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'),
                         "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(macro_sourcetype("index=x sourcetype=y"), "")
        self.assertEqual(macro_sourcetype("source=foo"), "")
        self.assertEqual(macro_sourcetype("sourcetype=a OR sourcetype=b"), "")


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.service = BundleImportService(SyncService(self.store, AuditService(self.store)), 5 * 1024 * 1024)

    def enricher(self, raw):
        if raw["id"] == "11111111-2222-4333-8444-555555555502":
            return enrich(raw, DETECTION, SOURCES, MACROS)
        return raw

    def detail(self, content_id):
        return UseCaseDetailService(ContentRepository(self.store), CategoryRepository(self.store)).get(content_id)

    def test_without_the_enricher_the_bundle_is_unchanged(self):
        plain, _ = build_bundle(FIXTURE)
        same, _ = build_bundle(FIXTURE, None, "")
        self.assertEqual(json.dumps(plain, sort_keys=True), json.dumps(same, sort_keys=True))

    def test_source_ref_names_the_extra_source(self):
        bundle, _ = build_bundle(FIXTURE, self.enricher, "security_content@abc123")
        self.assertTrue(bundle["source_ref"].endswith("+security_content@abc123"))

    def test_enriched_bundle_imports_and_adds_data_requirements(self):
        bundle, _ = build_bundle(FIXTURE, self.enricher, "security_content@abc123")
        job = self.service.import_bundle(copy.deepcopy(bundle), "admin")
        self.assertEqual(job["status"], "succeeded", job)
        uc = self.detail(SCANNING)
        requirements = {(r["type"], r["value"]): r for r in uc["requirements"]}
        self.assertIn(("sourcetype", "aws:cloudtrail"), requirements)
        event = requirements[("event_condition", "eventName=DescribeImageScanFindings")]
        self.assertEqual(event["level"], "recommended")
        self.assertEqual(event["attributes"]["sourcetype"], "aws:cloudtrail")
        extras = uc["provider_extras"]
        self.assertEqual(extras["status"], "experimental")
        self.assertEqual(uc["instructions"], "Install the add-on. Then enable it.")
        self.assertEqual(uc["known_false_positives"], "Admins.")
        self.assertEqual(extras["supportedTA"][0]["name"], "Splunk Add-on for AWS")

    def test_unenriched_records_gain_no_requirements(self):
        bundle, _ = build_bundle(FIXTURE, self.enricher, "x")
        self.service.import_bundle(copy.deepcopy(bundle), "admin")
        self.assertFalse([r for r in self.detail(LOGONS)["requirements"] if r["type"] == "event_condition"])

    def test_upstream_deprecated_status_raises_the_flag(self):
        def deprecate(raw):
            return enrich(raw, {"status": "deprecated"}, {}, {}) if raw["id"].endswith("502") else raw

        bundle, _ = build_bundle(FIXTURE, deprecate, "x")
        self.service.import_bundle(copy.deepcopy(bundle), "admin")
        self.assertIn("deprecated_upstream", self.detail(SCANNING)["quality_flags"])
        self.assertNotIn("deprecated_upstream", self.detail(LOGONS)["quality_flags"])

    def test_event_check_targets_come_from_the_active_catalogue(self):
        bundle, _ = build_bundle(FIXTURE, self.enricher, "x")
        self.service.import_bundle(copy.deepcopy(bundle), "admin")
        found = targets(self.store, CategoryRepository(self.store), 10)
        self.assertEqual(found, [(("aws:cloudtrail", "eventName", "DescribeImageScanFindings"), 1)])
        self.assertEqual(targets(self.store, CategoryRepository(self.store), 0), [])

    def test_absent_sourcetypes_do_not_use_up_the_limit(self):
        bundle, _ = build_bundle(FIXTURE, self.enricher, "x")
        self.service.import_bundle(copy.deepcopy(bundle), "admin")
        cats = CategoryRepository(self.store)
        self.assertEqual(targets(self.store, cats, 1, {"other"}), [])
        self.assertEqual(len(targets(self.store, cats, 1, {"aws:cloudtrail"})), 1)


if __name__ == "__main__":
    unittest.main()

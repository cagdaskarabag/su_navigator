import copy
import json
import os
import unittest

import helpers  # noqa: F401  (sets sys.path)
from control_catalogue_builder import build as build_catalogue
from splunk_ucm.errors import ValidationError
from splunk_ucm.frameworks.controls import ASSESSED, canonical, catalogue_coverage, validate_controls_definition
from splunk_ucm.frameworks.registry import DATA_DIR, FrameworkRegistry, version_key
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog

SMALL = {
    "format": "ucm.framework/2", "kind": "controls", "framework_id": "nist-test", "framework": "Test", "name": "Test catalogue",
    "regulation_ids": ["nist-test"], "version_label": "Rev. 5.2", "sort_key": [5, 2], "match": "nist-800-53",
    "controls": [
        {"id": "AC", "title": "Access Control", "parent": None, "kind": "family"},
        {"id": "AC-1", "title": "Policy", "parent": "AC", "kind": "control"},
        {"id": "AC-2", "title": "Account Management", "parent": "AC", "kind": "control"},
        {"id": "AC-2(1)", "title": "Automated", "parent": "AC-2", "kind": "enhancement"},
        {"id": "AC-13", "title": "Withdrawn", "parent": "AC", "kind": "control", "withdrawn": True},
        {"id": "AU", "title": "Audit", "parent": None, "kind": "family"},
        {"id": "AU-6", "title": "Review", "parent": "AU", "kind": "control"},
    ],
}


def uc(content_id, level, *refs):
    return {"content_id": content_id, "level": level, "controls": list(refs), "frameworks": [], "title": content_id,
            "criticality": "", "domains": [], "mitre_ids": []}


def small():
    return validate_controls_definition(copy.deepcopy(SMALL))


class CanonicalTest(unittest.TestCase):
    def test_nist_spellings_are_one_control(self):
        for text in ("AC-2(1)", "ac-2.1", "AC-02(01)", " AC-2 (1) ", "AC-02.01"):
            self.assertEqual(canonical(text, "nist-800-53"), "AC-2(1)", text)
        self.assertEqual(canonical("ac-02", "nist-800-53"), "AC-2")
        self.assertEqual(canonical("AC", "nist-800-53"), "AC")

    def test_exact_rule_only_normalises_case_and_space(self):
        self.assertEqual(canonical("gv.oc-01", "exact"), "GV.OC-01")
        self.assertEqual(canonical("03.01.01", "exact"), "03.01.01")
        self.assertNotEqual(canonical("3.1.1", "exact"), canonical("03.01.01", "exact"))


class ValidationTest(unittest.TestCase):
    def mutate(self, fn):
        doc = copy.deepcopy(SMALL)
        fn(doc)
        with self.assertRaises(ValidationError):
            validate_controls_definition(doc)

    def test_a_valid_definition_gets_a_dotted_version_from_the_sort_key(self):
        out = small()
        self.assertEqual((out["version"], out["version_label"], out["kind"]), ("5.2", "Rev. 5.2", "controls"))

    def test_rejects_malformed_definitions(self):
        self.mutate(lambda d: d.update(sort_key=["5"]))
        self.mutate(lambda d: d.update(sort_key=[]))
        self.mutate(lambda d: d.update(sort_key=[1, 2, 3, 4, 5]))
        self.mutate(lambda d: d.update(sort_key=[True]))
        self.mutate(lambda d: d.update(version_label=""))
        self.mutate(lambda d: d.update(match="regex"))
        self.mutate(lambda d: d.update(regulation_ids=["Bad Id"]))
        self.mutate(lambda d: d.update(controls=[]))
        self.mutate(lambda d: d["controls"].append(dict(d["controls"][1])))
        self.mutate(lambda d: d["controls"].append({"id": "ac-2.1", "title": "same as AC-2(1)", "parent": "AC-2", "kind": "enhancement"}))
        self.mutate(lambda d: d["controls"].append({"id": "X-1", "title": "t", "parent": "NOPE", "kind": "control"}))
        self.mutate(lambda d: d["controls"].insert(0, {"id": "Z", "title": "t", "parent": "AC", "kind": "control"}))
        self.mutate(lambda d: d["controls"].append({"id": "X-1", "title": "t", "parent": None, "kind": "chapter"}))
        self.mutate(lambda d: d["controls"].append({"id": "<b>", "title": "t", "parent": None, "kind": "control"}))

    def test_version_label_is_text_and_sort_key_orders_versions(self):
        store = InMemoryStore()
        reg = FrameworkRegistry(store)
        for label, key in (("Rev. 4", [4]), ("Rev. 5", [5]), ("Rev. 10", [10]), ("Rev. 5.2", [5, 2])):
            doc = copy.deepcopy(SMALL)
            doc.update(version_label=label, sort_key=key)
            reg.import_definition(json.dumps(doc).encode(), "alice")
        self.assertEqual(reg.versions("nist-test"), ["4", "5", "5.2", "10"])
        self.assertEqual(reg.get("nist-test")["version_label"], "Rev. 10")
        reg.activate("nist-test", "5.2", "alice")
        self.assertEqual(reg.get("nist-test")["version_label"], "Rev. 5.2")
        listed = [d for d in reg.list() if d["framework_id"] == "nist-test"]
        self.assertEqual([d["version_label"] for d in listed], ["Rev. 4", "Rev. 5", "Rev. 5.2", "Rev. 10"])
        self.assertTrue(all(d["kind"] == "controls" and d["controls"] == 7 for d in listed))
        self.assertEqual(sum(1 for d in listed if d["active"]), 1)
        self.assertEqual(version_key("5.2"), (5, 2))


class BundledCatalogueTest(unittest.TestCase):
    def setUp(self):
        self.reg = FrameworkRegistry(InMemoryStore())

    def test_the_public_catalogues_are_bundled_and_valid(self):
        listed = {d["framework_id"]: d for d in self.reg.list() if d.get("kind") == "controls"}
        self.assertEqual(set(listed), {"nist-800-53", "nist-800-171", "nist-csf", "cmmc-l2"})
        self.assertEqual((listed["nist-800-53"]["version_label"], listed["nist-800-171"]["version_label"],
                          listed["nist-csf"]["version_label"]), ("Rev. 5.2.0", "Rev. 3", "2.0"))
        for d in listed.values():
            self.assertIn("NIST", d["attribution"])
            self.assertTrue(d["origin"] == "bundled" and d["controls"] > 100)

    def test_attack_definitions_are_still_attack(self):
        kinds = {d["framework_id"]: d.get("kind") for d in self.reg.list()}
        self.assertEqual(kinds["mitre_attack_enterprise"], "attack")
        self.assertEqual(kinds["mitre_attack_ics"], "attack")

    def test_contents_are_what_the_standard_says(self):
        for fw, count in (("nist-800-53", 20), ("nist-800-171", 17), ("nist-csf", 6), ("cmmc-l2", 14)):
            roots = [c for c in self.reg.get(fw)["controls"] if c["parent"] is None]
            self.assertEqual(len(roots), count, fw)
        ids = {c["id"] for c in self.reg.get("nist-800-53")["controls"]}
        self.assertTrue({"AC-2", "AC-2(1)", "SI-4", "SI-4(4)", "AU-9(3)", "SR-12"} <= ids)
        csf = {c["id"]: c for c in self.reg.get("nist-csf")["controls"]}
        self.assertEqual(csf["GV.OC-01"]["parent"], "GV.OC")
        self.assertEqual(csf["GV.OC"]["parent"], "GV")
        self.assertFalse(csf["GV.OC-01"].get("withdrawn"))
        self.assertTrue(csf["ID.BE-01"].get("withdrawn"))
        self.assertEqual(sum(1 for c in csf.values() if c["kind"] == "subcategory" and not c.get("withdrawn")), 106)
        r3 = {c["id"]: c for c in self.reg.get("nist-800-171")["controls"]}
        self.assertEqual((r3["03.01.01"]["title"], r3["03.01.01"]["parent"]), ("Account Management", "03.01"))
        self.assertEqual(sum(len(c.get("objectives", [])) for c in r3.values()), 422)
        self.assertIn("[organization-defined value]", json.dumps(r3["03.01.01"]["objectives"]))
        self.assertNotIn("{{", json.dumps(list(r3.values())))

    def test_shipped_files_carry_identifiers_and_titles_only(self):
        for name in os.listdir(os.path.join(DATA_DIR, "controls")):
            with open(os.path.join(DATA_DIR, "controls", name), encoding="utf-8") as handle:
                doc = json.load(handle)
            self.assertLess(os.path.getsize(os.path.join(DATA_DIR, "controls", name)), 200000, name)
            for c in doc["controls"]:
                self.assertLessEqual(set(c), {"id", "title", "parent", "kind", "withdrawn", "objectives", "weight", "partial_weight",
                                              "precondition"}, c)
                if "objectives" in c:
                    self.assertEqual(doc["framework_id"], "nist-800-171")
            self.assertTrue(doc["source"].startswith(("https://raw.githubusercontent.com/usnistgov/oscal-content/",
                                                      "https://web.archive.org/web/2023/https://www.acq.osd.mil/")), doc["source"])
            self.assertEqual(len(doc["source_sha256"]), 64)


class CoverageTest(unittest.TestCase):
    def levels(self):
        return {
            "k1": uc("UC-1", "enabled", "regulation:nist-test#AC-2", "regulation:other#X"),
            "k2": uc("UC-2", "catalogue", "regulation:nist-test#ac-02.01"),
            "k3": uc("UC-3", "ready", "regulation:nist-test#AC-2"),
            "k4": uc("UC-4", "deployed", "regulation:nist-test#ZZ-9", "regulation:nist-test#AC-13"),
        }

    def rows(self, out):
        return {r["id"]: r for r in out["controls"]}

    def test_unmapped_controls_are_listed_and_counted(self):
        out = catalogue_coverage(small(), self.levels())
        rows = self.rows(out)
        self.assertEqual(len(rows), 7)
        self.assertFalse(rows["AC-1"]["mapped"])
        self.assertTrue(rows["AC-1"]["gap"] and rows["AU-6"]["gap"] and rows["AC-1"]["level"] is None)
        self.assertEqual(out["totals"]["unmapped"], 2)
        self.assertEqual(out["totals"]["controls"], 4)

    def test_best_level_use_cases_and_spellings(self):
        rows = self.rows(catalogue_coverage(small(), self.levels()))
        self.assertEqual((rows["AC-2"]["level"], rows["AC-2"]["counts"]["catalogue"]), ("enabled", 2))
        self.assertEqual(rows["AC-2"]["use_cases"], ["UC-1", "UC-3"])
        self.assertFalse(rows["AC-2"]["gap"])
        self.assertEqual((rows["AC-2(1)"]["level"], rows["AC-2(1)"]["clauses"]), ("catalogue", ["ac-02.01"]))
        self.assertTrue(rows["AC-2(1)"]["gap"] and rows["AC-2(1)"]["mapped"])

    def test_roll_up_counts_every_level_of_the_tree(self):
        rows = self.rows(catalogue_coverage(small(), self.levels()))
        self.assertEqual(rows["AC"]["below"], {"controls": 3, "mapped": 2, "ready": 1, "enabled": 1})
        self.assertEqual(rows["AC-2"]["below"], {"controls": 1, "mapped": 1, "ready": 0, "enabled": 0})
        self.assertEqual(rows["AU"]["below"], {"controls": 1, "mapped": 0, "ready": 0, "enabled": 0})

    def test_withdrawn_controls_do_not_count_but_their_mappings_show(self):
        out = catalogue_coverage(small(), self.levels())
        row = self.rows(out)["AC-13"]
        self.assertTrue(row["withdrawn"] and row["mapped"])
        rows = self.rows(catalogue_coverage(small(), {}))
        self.assertFalse(rows["AC-13"]["gap"])
        self.assertEqual((out["totals"]["withdrawn"], out["totals"]["mapped_to_withdrawn"]), (1, 1))
        self.assertNotIn("AC-13", [r["id"] for r in out["controls"] if r["kind"] in ASSESSED and not r["withdrawn"]])

    def test_clauses_that_match_nothing_are_reported_not_dropped(self):
        out = catalogue_coverage(small(), self.levels())
        self.assertEqual([u["clause"] for u in out["unmatched"]], ["ZZ-9"])
        self.assertEqual(out["unmatched_count"], 1)
        self.assertEqual(out["unmatched"][0]["use_cases"], ["UC-4"])

    def test_other_regulations_are_ignored(self):
        out = catalogue_coverage(small(), {"k": uc("UC-9", "enabled", "regulation:other#AC-2")})
        self.assertEqual((out["totals"]["mapped"], out["unmatched_count"]), (0, 0))

    def test_group_rows_are_never_gaps(self):
        rows = self.rows(catalogue_coverage(small(), {}))
        self.assertFalse(rows["AC"]["gap"] or rows["AU"]["gap"])
        self.assertTrue(all(r["gap"] for r in rows.values() if r["kind"] in ASSESSED and not r["withdrawn"]))

    def test_exact_rule_does_not_merge_spellings(self):
        doc = small()
        doc["match"] = "exact"
        out = catalogue_coverage(doc, {"k": uc("UC", "ready", "regulation:nist-test#AC-02")})
        self.assertEqual(out["unmatched_count"], 1)


class BuilderTest(unittest.TestCase):
    OSCAL = {"catalog": {"metadata": {"version": "9.9", "last-modified": "2026-01-01"}, "groups": [
        {"id": "ac", "title": "Access Control", "controls": [
            {"id": "ac-1", "title": "Policy", "props": [{"name": "label", "value": "AC-01", "class": "zero-padded"},
                                                       {"name": "label", "value": "AC-1"}, {"name": "sort-id", "value": "ac-01"}]},
            {"id": "ac-2", "title": "Accounts", "props": [{"name": "label", "value": "AC-2"}, {"name": "sort-id", "value": "ac-02"}],
             "parts": [{"name": "statement", "prose": "must not be copied"}], "controls": [
                 {"id": "ac-2.1", "title": "Automated", "props": [{"name": "label", "value": "AC-2(1)"},
                                                                  {"name": "sort-id", "value": "ac-02.01"}]}]},
            {"id": "ac-3", "title": "Gone", "props": [{"name": "label", "value": "AC-3"}, {"name": "status", "value": "withdrawn"},
                                                     {"name": "sort-id", "value": "ac-03"}]}]}]}}

    def test_builder_output_validates_and_keeps_only_ids_and_titles(self):
        out = build_catalogue("nist-800-53", self.OSCAL, "https://example.test/x.json", "a" * 64)
        self.assertEqual(out["format"], "ucm.framework/2")
        self.assertEqual([(c["id"], c["kind"], c["parent"]) for c in out["controls"]],
                         [("AC", "family", None), ("AC-1", "control", "AC"), ("AC-2", "control", "AC"),
                          ("AC-2(1)", "enhancement", "AC-2"), ("AC-3", "control", "AC")])
        self.assertTrue(out["controls"][-1]["withdrawn"])
        self.assertNotIn("must not be copied", json.dumps(out))
        self.assertEqual(validate_controls_definition(out)["version"], "5.2.0")


class CatalogueApiTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.viewer = make_ctx(self.store, [])
        self.manager = make_ctx(self.store, ["ucm_manage_content"])

    def test_bundled_catalogue_reads_for_everyone_and_lists_unmapped_controls(self):
        status, body = call(self.viewer, "GET", "frameworks/catalogue", {"framework_id": "nist-800-53"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["catalogue"]["version_label"], "Rev. 5.2.0")
        self.assertGreater(body["totals"]["controls"], 700)
        self.assertEqual(body["totals"]["unmapped"] + body["totals"]["mapped"], body["totals"]["controls"])
        self.assertIn("SI-4", {r["id"] for r in body["controls"]})
        self.assertEqual(body["unmatched_count"], 0)
        self.assertEqual([v["label"] for v in body["versions"]], ["Rev. 5.2.0"])

    def test_imported_catalogue_matches_fixture_mappings(self):
        doc = copy.deepcopy(SMALL)
        doc.update(framework_id="hitrust-test", regulation_ids=["hitrust"], match="exact", sort_key=[1])
        doc["controls"] = [{"id": "01", "title": "Access", "parent": None, "kind": "family"},
                           {"id": "01.B", "title": "User registration", "parent": "01", "kind": "control"},
                           {"id": "01.c", "title": "Privilege management", "parent": "01", "kind": "control"}]
        self.assertEqual(call(self.viewer, "POST", "frameworks/import", body=doc)[0], 403)
        self.assertEqual(call(self.manager, "POST", "frameworks/import", body=doc)[0], 200)
        status, body = call(self.viewer, "GET", "frameworks/catalogue", {"framework_id": "hitrust-test"})
        self.assertEqual(status, 200, body)
        rows = {r["id"]: r for r in body["controls"]}
        self.assertTrue(rows["01.B"]["mapped"])
        self.assertFalse(rows["01.c"]["mapped"])
        self.assertEqual(body["totals"]["unmapped"], 1)

    def test_errors(self):
        self.assertEqual(call(self.viewer, "GET", "frameworks/catalogue")[0], 400)
        self.assertEqual(call(self.viewer, "GET", "frameworks/catalogue", {"framework_id": "nope"})[0], 404)
        self.assertEqual(call(self.viewer, "GET", "frameworks/catalogue", {"framework_id": "mitre_attack_ics"})[0], 400)
        self.assertEqual(call(self.viewer, "GET", "frameworks/matrix", {"framework_id": "nist-csf"})[0], 400)
        self.assertEqual(call(self.viewer, "GET", "frameworks/technique", {"framework_id": "nist-csf", "id": "T1"})[0], 400)
        self.assertEqual(call(self.viewer, "GET", "frameworks/navigator", {"framework_id": "nist-csf"})[0], 400)

    def test_listing_shows_catalogues_beside_attack(self):
        status, body = call(self.viewer, "GET", "frameworks")
        self.assertEqual(status, 200)
        self.assertEqual({d["framework_id"] for d in body["definitions"] if d["kind"] == "controls"},
                         {"nist-800-53", "nist-800-171", "nist-csf", "cmmc-l2"})


if __name__ == "__main__":
    unittest.main()

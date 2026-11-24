import csv
import io
import json
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.frameworks.coverage import CoverageService, clause_sort_key
from splunk_ucm.frameworks.evidence import COLUMNS, EvidenceService, _cell
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import UC, approved, service
from unit.test_discovery import loaded_catalog


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.svc, self.store, _ = service()
        approved(self.svc)
        self.svc.deploy("bob", UC)
        self.store.upsert(C.READINESS, {"_key": "fenre_UC-9.1.1", "state": "ready", "score": 92,
                                        "evaluated_at": "2026-11-20T10:00:00Z", "engine_version": "old",
                                        "discovery_at": "2026-11-20T09:00:00Z", "source_hash": ""})
        self.levels = CoverageService(self.store).use_case_levels()
        self.ev = EvidenceService(self.store)

    def test_rows_join_mapping_readiness_deployment_and_provenance(self):
        rows = self.ev.rows("regulation:cjis", self.levels)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["clause"], r["content_id"], r["level"], r["gap"]), ("5.5.1", UC, "deployed", False))
        self.assertEqual((r["readiness_state"], r["readiness_score"], r["readiness_stale"]), ("ready", 92, True))
        self.assertEqual((r["deployment_state"], r["deployed_revision"], r["live_status"]), ("deployed", 1, "disabled"))
        self.assertTrue(r["saved_search"].startswith("SUN - 9.1.1"), r["saved_search"])
        self.assertEqual((r["mode"], r["assurance"]), ("detects-violation-of", "partial"))
        self.assertTrue(r["control_objective"] and r["evidence_artifact"])
        stored = self.store.get(C.CONTENT, "fenre_UC-9.1.1")
        self.assertEqual(r["source_blob_sha"], stored["provenance"]["source_blob_sha"])
        self.assertEqual(set(r), set(COLUMNS))

    def test_gaps_are_reproducible_from_kv(self):
        pack = json.loads(self.ev.pack("regulation:gdpr", self.levels)["content"])
        self.assertEqual([(c["clause"], c["gap"], c["level"]) for c in pack["clauses"]], [("Art.7", True, "catalogue")])
        self.assertEqual(pack["meta"]["gaps"], 1)
        # Independent recomputation from the collections the pack reads.
        for fw in ("regulation:gdpr", "regulation:hitrust", "regulation:cjis"):
            ready = {d["_key"] for d in self.store.query(C.READINESS, {"state": "ready"})}
            deployed = {d["catalog_key"] for d in self.store.query(C.DEPLOYMENTS, {"deployed_revision": {"$gte": 1}})}
            covered, clauses = set(), set()
            for doc in self.store.query(C.CATALOG, {"provider_status": "active", "frameworks": fw}):
                for ref in doc["framework_controls"]:
                    if ref.startswith(fw + "#"):
                        clauses.add(ref[len(fw) + 1:])
                        if doc["_key"] in ready | deployed:
                            covered.add(ref[len(fw) + 1:])
            got = json.loads(self.ev.pack(fw, self.levels)["content"])["clauses"]
            self.assertEqual({c["clause"] for c in got if c["gap"]}, clauses - covered, fw)
            controls = CoverageService(self.store).framework_controls(fw, self.levels)
            self.assertEqual({c["control"] for c in controls if c["gap"]}, clauses - covered, fw)

    def test_pack_is_deterministic_and_csv_is_well_formed(self):
        first = self.ev.pack("regulation:uk-cyber-essentials", self.levels, "csv")
        doc = self.store.get(C.CATALOG, "fenre_UC-9.1.1")
        self.store.upsert(C.CATALOG, doc)
        again = self.ev.pack("regulation:uk-cyber-essentials", CoverageService(self.store).use_case_levels(), "csv")
        self.assertEqual((first["content"], first["sha256"]), (again["content"], again["sha256"]))
        self.assertEqual(first["filename"], "evidence-uk-cyber-essentials.csv")
        table = list(csv.reader(io.StringIO(first["content"])))
        self.assertEqual(tuple(table[0]), COLUMNS)
        self.assertEqual(len(table) - 1, first["meta"]["rows"])
        self.assertGreaterEqual(first["meta"]["rows"], 1)
        j1 = self.ev.pack("regulation:uk-cyber-essentials", self.levels, "json")
        j2 = self.ev.pack("regulation:uk-cyber-essentials", self.levels, "json")
        self.assertEqual(j1["sha256"], j2["sha256"])
        self.assertNotIn("generated_at", j1["meta"])

    def test_cells_and_clause_order(self):
        self.assertEqual(_cell("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual((_cell(True), _cell(None), _cell(7)), ("true", "", "7"))
        self.assertEqual(sorted(["A.5.10", "A.5.9", "A.5.1", "a.4"], key=clause_sort_key),
                         ["a.4", "A.5.1", "A.5.9", "A.5.10"])


class EvidenceApiTest(unittest.TestCase):
    def test_viewer_reads_clause_and_export(self):
        viewer = make_ctx(loaded_catalog(), [])
        status, body = call(viewer, "GET", "frameworks/clause", {"framework": "regulation:hitrust", "clause": "01.b"})
        self.assertEqual(status, 200, body)
        self.assertEqual([u["content_id"] for u in body["use_cases"]], [UC])
        status, body = call(viewer, "GET", "frameworks/evidence", {"framework": "regulation:hitrust", "format": "csv"})
        self.assertEqual((status, body["format"]), (200, "csv"))
        for args in ({"framework": "mitre_attack"}, {"framework": "regulation:hitrust", "format": "xml"}):
            self.assertEqual(call(viewer, "GET", "frameworks/evidence", args)[0], 400, args)
        self.assertEqual(call(viewer, "GET", "frameworks/clause", {"framework": "regulation:hitrust"})[0], 400)


if __name__ == "__main__":
    unittest.main()

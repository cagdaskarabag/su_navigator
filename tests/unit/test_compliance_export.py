"""The export keeps the retired module's records and checks each snapshot the way the app used to (D-086)."""

import importlib.util
import json
import os
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.util import sha256_text

spec = importlib.util.spec_from_file_location("compliance_export", os.path.join(helpers.ROOT, "tools", "compliance_export.py"))
export_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export_mod)


def snapshot(key, content):
    return {"_key": key, "framework_id": "cmmc-l2", "sha256": sha256_text(content), "content_json": content}


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.store.upsert(C.ASSESSMENTS, {"_key": "as_1", "framework_id": "cmmc-l2", "control_id": "3.1.1", "status": "planned"})
        self.store.upsert(C.POAM, {"_key": "pm_1", "framework_id": "cmmc-l2", "control_id": "3.1.1", "state": "open"})
        self.store.upsert(C.SNAPSHOTS, snapshot("sn_good", '{"controls": []}'))
        self.store.upsert(C.SNAPSHOTS, snapshot("sn_bad", '{"controls": [1]}'))
        self.store.upsert(C.SNAPSHOTS, dict(snapshot("sn_edited", '{"a": 1}'), content_json='{"a": 2}'))

    def test_every_record_is_exported_and_counted(self):
        out = export_mod.export(self.store, now="2026-11-28T10:00:00Z")
        self.assertEqual(out["format"], export_mod.FORMAT)
        self.assertEqual(out["counts"]["assessments"], 1)
        self.assertEqual(out["counts"]["poam"], 1)
        self.assertEqual(out["counts"]["snapshots"], 3)
        self.assertEqual(out["records"]["poam"][0]["state"], "open")

    def test_snapshots_are_kept_byte_for_byte_and_checked(self):
        out = export_mod.export(self.store)
        stored = {d["_key"]: d for d in out["records"]["snapshots"]}
        self.assertEqual(stored["sn_good"]["content_json"], '{"controls": []}')
        checks = {c["id"]: c["ok"] for c in out["snapshot_integrity"]}
        self.assertEqual(checks, {"sn_good": True, "sn_bad": True, "sn_edited": False})
        self.assertEqual(out["counts"]["snapshots_failing_check"], 1)

    def test_the_output_is_json_serialisable(self):
        json.dumps(export_mod.export(self.store))

    def test_an_empty_install_exports_empty_lists(self):
        out = export_mod.export(InMemoryStore())
        self.assertEqual(out["counts"], {"assessments": 0, "poam": 0, "snapshots": 0, "snapshots_failing_check": 0})


if __name__ == "__main__":
    unittest.main()

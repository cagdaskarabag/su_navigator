import copy
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm import conf
from splunk_ucm.audit import AuditService
from splunk_ucm.deployment.export import build_bundle, conf_search
from splunk_ucm.storage import collections as C
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import UC, approved, service
from unit.test_discovery import loaded_catalog


def deployed_service(**kw):
    svc, store, saved = service(**kw)
    approved(svc)
    svc.deploy("bob", UC)
    return svc, store, saved


class ConfTest(unittest.TestCase):
    def test_round_trip_multiline_and_plain_values(self):
        search = "index=_internal\n| stats count by host\n\n| where count > 1"
        text = conf.write([("SUN - a", {"search": search, "disabled": "1"}),
                           ("SUN - b", {"search": "| makeresults", "disabled": "0"})], header=["gen"])
        parsed = dict(conf.parse(text))
        self.assertEqual(parsed["SUN - a"]["search"], search)
        self.assertEqual(parsed["SUN - b"], {"search": "| makeresults", "disabled": "0"})

    def test_values_that_would_not_read_back_are_refused(self):
        for bad in ("| eval x=\"a\\\\\n| table x", "x \\", "a\r\nb", " lead", "trail "):
            with self.assertRaises(conf.ConfError, msg=repr(bad)):
                conf.write_stanza("S", {"search": bad})
        with self.assertRaises(conf.ConfError):
            conf.write_stanza("bad]name", {"a": "1"})

    def test_parser_skips_comments_and_reads_splunk_style_continuations(self):
        text = ("# comment\n; other\n[default]\nx = 1\n\n[SUN - q]\n"
                "search = index=a \\\n    | stats count \\\n    | head 5\ndisabled = 0\n")
        parsed = dict(conf.parse(text))
        self.assertEqual(parsed["default"], {"x": "1"})
        self.assertEqual(parsed["SUN - q"], {"search": "index=a\n| stats count\n| head 5", "disabled": "0"})


class ExportTest(unittest.TestCase):
    def test_export_contains_deployed_revision_only(self):
        svc, store, saved = service()
        self.assertEqual(build_bundle(store.query(C.DEPLOYMENTS, None))["count"], 0)
        svc.save_draft("alice", UC, {"cron": "*/5 * * * *"})
        svc.submit("alice", UC)
        self.assertEqual(build_bundle(store.query(C.DEPLOYMENTS, None))["count"], 0)
        svc.approve("bob", UC)
        self.assertEqual(build_bundle(store.query(C.DEPLOYMENTS, None))["count"], 0)
        svc.deploy("bob", UC)
        bundle = svc.export("carol")
        self.assertEqual(bundle["count"], 1)
        doc = svc.get(UC)
        name = doc["saved_search"]["name"]
        settings = dict(conf.parse(bundle["content"]))[name]
        self.assertEqual(settings["disabled"], "1")
        self.assertEqual(settings["search"], conf_search(doc["revisions"][0]["spl"]))
        self.assertEqual(settings["cron_schedule"], "*/5 * * * *")
        entry = bundle["manifest"]["entries"][0]
        self.assertEqual(entry["revision"], 1)
        self.assertEqual(entry["approved_by"], "bob")
        self.assertEqual(entry["saved_search"], name)
        self.assertEqual(bundle["manifest"]["file"]["sha256"], bundle["sha256"])

    def test_export_is_deterministic_and_ignores_live_state(self):
        svc, store, saved = deployed_service()
        first = svc.export("carol")
        second = svc.export("carol")
        self.assertEqual(first["content"], second["content"])
        self.assertEqual(first["manifest"], second["manifest"])
        svc.enable("bob", UC)
        self.assertEqual(svc.export("carol")["sha256"], first["sha256"])
        docs = store.query(C.DEPLOYMENTS, None)
        self.assertEqual(build_bundle(list(reversed(docs)))["content"], build_bundle(docs)["content"])
        self.assertNotIn("updated_at", first["content"])

    def test_retired_and_unapproved_records_are_not_exported(self):
        svc, store, saved = deployed_service()
        svc.retire("bob", UC)
        self.assertEqual(svc.export("carol")["count"], 0)
        doc = copy.deepcopy(svc.get(UC))
        doc["deployed_revision"] = 1
        doc["state"] = "deployed"
        doc["revisions"][0].pop("approved_by", None)
        bundle = build_bundle([doc])
        self.assertEqual(bundle["count"], 0)
        self.assertEqual(bundle["manifest"]["skipped"], [{"content_id": UC, "reason": "deployed revision has no approver"}])

    def test_unwritable_spl_is_skipped_with_a_reason(self):
        svc, store, saved = deployed_service()
        doc = copy.deepcopy(svc.get(UC))
        doc["revisions"][0]["spl"] = "| makeresults \\\n| eval x=1"
        bundle = build_bundle([doc])
        self.assertEqual(bundle["count"], 0)
        self.assertIn("backslash", bundle["manifest"]["skipped"][0]["reason"])

    def test_whitespace_normalisation_is_recorded(self):
        svc, store, saved = deployed_service()
        doc = copy.deepcopy(svc.get(UC))
        doc["revisions"][0]["spl"] = "  | makeresults\n    | eval x=1  \n"
        entry = build_bundle([doc])["manifest"]["entries"][0]
        self.assertTrue(entry["whitespace_normalized"])
        self.assertNotEqual(entry["spl_sha256"], entry["conf_search_sha256"])
        self.assertEqual(dict(conf.parse(build_bundle([doc])["content"]))[entry["saved_search"]]["search"],
                         "| makeresults\n| eval x=1")

    def test_duplicate_names_are_refused(self):
        from splunk_ucm.errors import ConflictError
        svc, store, saved = deployed_service()
        doc = copy.deepcopy(svc.get(UC))
        other = copy.deepcopy(doc)
        other["content_id"] = UC + "-copy"
        with self.assertRaises(ConflictError):
            build_bundle([doc, other])

    def test_export_is_audited_and_readable_by_viewers(self):
        svc, store, saved = deployed_service()
        svc.export("carol")
        audited = AuditService(store).recent(20, "deployment.export")
        self.assertTrue(audited)
        store = loaded_catalog()
        viewer = make_ctx(store, [])
        self.assertEqual(call(viewer, "GET", "deployments/export")[0], 200)


if __name__ == "__main__":
    unittest.main()

import os
import shutil
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.deployment import controltest as ct
from splunk_ucm.deployment.service import DeploymentService, DeploymentSettings, deployment_key
from splunk_ucm.errors import ConflictError, UnsupportedOperation, ValidationError
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import FakeSavedSearches, UC, approved, service
from unit.test_discovery import loaded_catalog
from unit.test_selection_validation import FakeParser

DEP_KEY = deployment_key("fenre_UC-9.1.1")

MANIFEST = """uc_id: "9.1.1"
sourcetype: "snort:alert"
index: "ids"
source: "/var/log/snort.log"
host: "sensor-1"
timerange: "-24h"
expected:
  min_count: 2
  fields:
    - name: host
      values: ["sensor-1"]
origin: "vendor-doc"
notes: |
  Two alerts simulate a scan.
"""


class FakeSplunk:
    """Stores each ingested event by source marker. An event containing 'hit' matches the SPL.

    ``keep`` stores only the first N events per marker, to model events lost in indexing.
    """

    def __init__(self, fail_ingest=False, index_lag=0, indexed=True, keep=None, row_fields=None, error=None):
        self.events = {}
        self.ingests = []
        self.searches = []
        self.fail_ingest = fail_ingest
        self.index_lag = index_lag
        self.indexed = indexed
        self.keep = keep
        self.counts = {}
        self.windows = []
        self.row_fields = row_fields
        self.error = error

    def ingest(self, event, index, sourcetype, source, host):
        self.ingests.append((index, sourcetype, source, host))
        if self.fail_ingest:
            raise ct.StorageError("event receiver returned HTTP 400")
        if self.indexed:
            stored = self.events.setdefault(source, [])
            if self.keep is None or len(stored) < self.keep:
                stored.append(event)

    def count(self, index, marker):
        seen = self.counts.get(marker, 0)
        self.counts[marker] = seen + 1
        if seen < self.index_lag:
            return 0
        return len(self.events.get(marker, []))

    def search(self, spl, marker, earliest, latest):
        self.searches.append(spl)
        self.windows.append((earliest, latest))
        if self.error is not None:
            raise self.error
        rows = []
        for event in self.events.get(marker, []):
            if "hit" in event:
                rows.append(self.row_fields(event) if self.row_fields else {"_raw": event})
        return rows


CLOCK = 1790000000.0


def runner(splunk=None, **kw):
    splunk = splunk or FakeSplunk()
    kw.setdefault("clock", lambda: CLOCK)
    return ct.ControlTestRunner(splunk.ingest, splunk.count, splunk.search, sleep=lambda s: None, settle=5.0, **kw), splunk


def fixture(positive="hit\nhit\nhit\n", negative="miss\n", min_count=2):
    return {"sourcetype": "snort:alert", "host": "sensor-1", "min_count": min_count,
            "positive": positive, "negative": negative}


class ManifestTest(unittest.TestCase):
    def test_reads_scalars_and_nested_min_count_and_skips_block_scalars(self):
        m = ct.parse_manifest(MANIFEST)
        self.assertEqual(m["uc_id"], "9.1.1")
        self.assertEqual(m["sourcetype"], "snort:alert")
        self.assertEqual(m["expected"]["min_count"], 2)


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        for name, manifest, pos, neg in (
                ("UC-9.1.1", MANIFEST, "hit one\nhit two\n", "miss\n"),
                ("UC-9.1.2", MANIFEST.replace("9.1.1", "9.1.2"), "hit\n", None),
                ("UC-9.1.3", MANIFEST.replace("9.1.1", "9.1.3"), "", None),
                ("UC-9.1.4", MANIFEST.replace("9.1.1", "9.1.4"), None, None)):
            path = os.path.join(self.dir, name)
            os.makedirs(path)
            with open(os.path.join(path, "manifest.yaml"), "w") as fh:
                fh.write(manifest)
            if pos is not None:
                with open(os.path.join(path, "positive.log"), "w") as fh:
                    fh.write(pos)
            if neg is not None:
                with open(os.path.join(path, "negative.log"), "w") as fh:
                    fh.write(neg)
        os.makedirs(os.path.join(self.dir, "_schema"))

    def test_bundle_keeps_raw_text_and_reports_skipped_fixtures(self):
        bundle, report = ct.build_fixture_bundle(self.dir)
        self.assertEqual(report["fixtures"], 2)
        by_id = {f["uc_id"]: f for f in bundle["fixtures"]}
        self.assertEqual(by_id["9.1.1"]["positive"], "hit one\nhit two\n")
        self.assertEqual(by_id["9.1.1"]["negative"], "miss\n")
        self.assertEqual(by_id["9.1.2"]["negative"], "")
        reasons = {s["uc_id"]: s["reason"] for s in report["skipped"]}
        self.assertEqual(reasons["9.1.3"], "positive.log is empty")
        self.assertEqual(reasons["9.1.4"], "no positive.log")
        self.assertEqual(report["sha256"], ct.bundle_hash(bundle))

    def test_bundle_is_deterministic(self):
        self.assertEqual(ct.build_fixture_bundle(self.dir)[1]["sha256"], ct.build_fixture_bundle(self.dir)[1]["sha256"])

    def test_manifest_uc_id_must_match_directory(self):
        path = os.path.join(self.dir, "UC-9.1.1")
        with open(os.path.join(path, "manifest.yaml"), "w") as fh:
            fh.write(MANIFEST.replace("9.1.1", "9.9.9"))
        reasons = {s["uc_id"]: s["reason"] for s in ct.build_fixture_bundle(self.dir)[1]["skipped"]}
        self.assertEqual(reasons["9.1.1"], "manifest uc_id does not match its directory")

    def test_validate_bundle_accepts_built_bundle_and_refuses_malformed(self):
        bundle, _ = ct.build_fixture_bundle(self.dir)
        provider, fixtures = ct.validate_bundle(bundle)
        self.assertEqual((provider, len(fixtures)), ("fenre", 2))
        bad_cases = [
            {}, dict(bundle, format="other"), dict(bundle, provider="Bad Name"),
            dict(bundle, fixtures=[dict(bundle["fixtures"][0], uc_id="../x")]),
            dict(bundle, fixtures=[dict(bundle["fixtures"][0], positive="")]),
            dict(bundle, fixtures=[dict(bundle["fixtures"][0], min_count=0)]),
            dict(bundle, fixtures=[dict(bundle["fixtures"][0], positive="x" * (ct.MAX_FIXTURE_BYTES + 1))]),
            dict(bundle, fixtures=[dict(bundle["fixtures"][0], sourcetype=" ")]),
        ]
        for bad in bad_cases:
            with self.assertRaises(ValidationError, msg=str(bad)[:80]):
                ct.validate_bundle(bad)


class ScopeTest(unittest.TestCase):
    def test_index_filters_are_rewritten_to_test_index_and_marker(self):
        out = ct.scope_to_test_index('index=ids sourcetype=snort:alert | stats count by src', "ucm_controltest", "m1")
        self.assertEqual(out, 'index=ucm_controltest source="m1" sourcetype=snort:alert | stats count by src')
        multi = ct.scope_to_test_index('(index=a OR index=b) x', "t", "m")
        self.assertEqual(multi, '(index=t source="m" OR index=t source="m") x')

    def test_searches_that_cannot_be_scoped_are_refused(self):
        refused = [
            "| tstats count where index=ids by host",
            "index=ids | datamodel Network search",
            "index!=ids x",
            "index IN (a,b) x",
            "index=ids source=/var/log/a x",
            "| makeresults",
            "index=ids | map search=\"search index=x\"",
            "index=ids | savedsearch foo",
        ]
        for spl in refused:
            with self.assertRaises(ct.NotRunnable, msg=spl):
                ct.scope_to_test_index(spl, "t", "m")

    def test_every_clause_that_starts_a_pipeline_needs_an_index(self):
        """Issue #50: a subsearch without an index would run on the caller's default indexes."""
        refused = [
            "index=ids [ search sourcetype=auth user=admin ]",
            "index=ids | append [ search sourcetype=auth ] | stats count",
            "index=ids | join host [ search sourcetype=auth | fields host ]",
            "| makeresults | join [ search host=x ]",
            "index=ids [ search index=other | fields host ] [ search sourcetype=auth ]",
        ]
        for spl in refused:
            with self.assertRaises(ct.NotRunnable, msg=spl) as ctx:
                ct.scope_to_test_index(spl, "t", "m")
            self.assertIn("names no index", str(ctx.exception), spl)

    def test_subsearches_with_an_index_and_later_search_clauses_stay_runnable(self):
        self.assertEqual(
            ct.scope_to_test_index("index=ids | append [ search index=other sourcetype=x ] | stats count", "t", "m"),
            'index=t source="m" | append [ search index=t source="m" sourcetype=x ] | stats count')
        self.assertEqual(ct.scope_to_test_index("index=ids | search error | where x>1 | search foo=bar", "t", "m"),
                         'index=t source="m" | search error | where x>1 | search foo=bar')
        self.assertEqual(ct.scope_to_test_index("| search index=ids user=a", "t", "m"),
                         '| search index=t source="m" user=a')
        self.assertEqual(ct.scope_to_test_index("| makeresults | append [ search index=ids ]", "t", "m"),
                         '| makeresults | append [ search index=t source="m" ]')

    def test_a_generating_command_written_first_without_a_pipe_is_refused(self):
        for spl in ("metadata type=hosts index=ids", "tstats count where index=ids", "dbinspect index=ids",
                    "index=ids [ metadata type=hosts index=ids ]"):
            with self.assertRaises(ct.NotRunnable, msg=spl) as ctx:
                ct.scope_to_test_index(spl, "t", "m")
            self.assertIn("cannot be redirected", str(ctx.exception), spl)

    def test_a_breaker_name_used_as_a_search_term_is_not_a_command(self):
        for spl, want in (("index=ids from=a", 'index=t source="m" from=a'),
                          ("index=ids history failed", 'index=t source="m" history failed')):
            self.assertEqual(ct.scope_to_test_index(spl, "t", "m"), want)


class RunnerTest(unittest.TestCase):
    SPL = 'index=ids sourcetype=snort:alert | search "hit" | stats count'

    def test_passes_when_positive_meets_min_count_and_negative_is_empty(self):
        run, splunk = runner()
        result = run.run(self.SPL, fixture(positive="hit a\nhit b\nhit c\n", negative="nothing\n", min_count=2))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["positive"]["rows"], 3)
        self.assertEqual(result["negative"]["rows"], 0)
        self.assertEqual(result["reason"], "")
        for spl in splunk.searches:
            self.assertIn('index=ucm_controltest source="ucm-ct-', spl)

    def test_positive_below_min_count_fails(self):
        run, _ = runner()
        result = run.run(self.SPL, fixture(positive="hit\n", min_count=2))
        self.assertEqual(result["status"], "failed")
        self.assertIn("positive run returned 1 rows, expected at least 2", result["reason"])

    def test_negative_matches_fail(self):
        run, _ = runner()
        result = run.run(self.SPL, fixture(positive="hit\nhit\n", negative="hit noise\n", min_count=1))
        self.assertEqual(result["status"], "failed")
        self.assertIn("negative run returned 1 rows, expected none", result["reason"])

    def test_no_negative_fixture_skips_the_negative_run(self):
        run, splunk = runner()
        result = run.run(self.SPL, fixture(negative="", min_count=1))
        self.assertEqual(result["status"], "passed")
        self.assertIsNone(result["negative"])
        self.assertEqual(len(splunk.searches), 1)

    def test_events_that_never_index_are_inconclusive_not_passed(self):
        run, _ = runner(splunk=FakeSplunk(indexed=False))
        result = run.run(self.SPL, fixture())
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("no events", result["reason"])

    def test_receiver_errors_are_inconclusive(self):
        run, _ = runner(splunk=FakeSplunk(fail_ingest=True))
        result = run.run(self.SPL, fixture())
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("HTTP 400", result["reason"])

    def test_unscopable_spl_is_not_run_at_all(self):
        run, splunk = runner()
        result = run.run("| tstats count where index=ids", fixture())
        self.assertEqual(result["status"], "not_runnable")
        self.assertEqual(splunk.ingests, [])
        self.assertEqual(splunk.searches, [])

    def test_the_search_own_time_terms_are_replaced_by_the_test_window(self):
        run, splunk = runner()
        result = run.run('index=ids earliest=-75m@m latest=-15m@m sourcetype=snort:alert | search "hit"',
                         fixture(negative="", min_count=1))
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("earliest", splunk.searches[0])
        self.assertNotIn("latest", splunk.searches[0])
        self.assertIn('index=ucm_controltest source="ucm-ct-', splunk.searches[0])

    def test_time_terms_are_stripped_only_as_search_terms(self):
        self.assertEqual(ct.strip_time_terms("index=a _index_earliest=-1h | where x>1").strip(),
                         "index=a _index_earliest=-1h | where x>1")

    def test_settle_waits_until_every_event_is_searchable(self):
        splunk = FakeSplunk(index_lag=2)
        run, _ = runner(splunk=splunk)
        result = run.run(self.SPL, fixture(negative="", min_count=1))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["positive"]["indexed"], 3)

    def test_partial_indexing_is_inconclusive_not_a_failure(self):
        run, _ = runner(splunk=FakeSplunk(keep=1))
        result = run.run(self.SPL, fixture(positive="hit a\nhit b\nhit c\n", negative="", min_count=2))
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("only 1 of 3 fixture events", result["reason"])

    def test_each_event_is_sent_on_its_own(self):
        run, splunk = runner()
        run.run(self.SPL, fixture(positive="hit a\nhit b\nhit c\n", negative="", min_count=1))
        self.assertEqual(len(splunk.ingests), 3)

    def test_split_events_uses_blank_lines_when_present_and_lines_otherwise(self):
        self.assertEqual(ct.split_events("a\nb\n"), ["a", "b"])
        self.assertEqual(ct.split_events("x1\nx2\n\n  \ny1\ny2\n"), ["x1\nx2", "y1\ny2"])
        self.assertEqual(ct.split_events("\n\n"), [])

    def test_verdict_table(self):
        self.assertEqual(ct.verdict(None, None), "inconclusive")
        self.assertEqual(ct.verdict({"pass": True}, None), "passed")
        self.assertEqual(ct.verdict({"pass": True}, {"pass": False}), "failed")
        self.assertEqual(ct.verdict({"pass": False}, None), "failed")


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.store = loaded_catalog()
        self.saved = FakeSavedSearches()
        self.splunk = FakeSplunk()
        self.run, _ = runner(splunk=self.splunk)
        self.svc = DeploymentService(self.store, AuditService(self.store), FakeParser(), self.saved,
                                     DeploymentSettings(), control_runner=self.run)
        approved(self.svc)
        self.svc.deploy("bob", UC)
        self.bundle = {"format": ct.FIXTURE_FORMAT, "format_version": ct.FIXTURE_VERSION, "provider": "fenre",
                       "fixtures": [{"uc_id": "9.1.1", "sourcetype": "snort:alert", "host": "sensor-1",
                                     "min_count": 1, "positive": "hit\n", "negative": "miss\n"}]}

    def test_import_stores_fixtures_and_replaces_stale_batch(self):
        out = self.svc.import_fixtures("carol", self.bundle)
        self.assertEqual(out["count"], 1)
        doc = self.store.get(C.CONTROL_FIXTURES, "cf_fenre_UC-9.1.1")
        self.assertEqual(doc["positive"], "hit\n")
        other = dict(self.bundle, fixtures=[dict(self.bundle["fixtures"][0], uc_id="9.1.2")])
        self.svc.import_fixtures("carol", other)
        self.assertIsNone(self.store.get(C.CONTROL_FIXTURES, "cf_fenre_UC-9.1.1"))
        self.assertIsNotNone(self.store.get(C.CONTROL_FIXTURES, "cf_fenre_UC-9.1.2"))

    def test_control_test_records_verdict_on_deployment(self):
        self.svc.import_fixtures("carol", self.bundle)
        doc = self.svc.control_test("dave", UC)
        self.assertEqual(doc["control_test"]["status"], "passed")
        self.assertEqual(doc["control_test"]["revision"], 1)
        self.assertEqual(doc["control_test"]["ran_by"], "dave")
        self.assertEqual(self.svc.get(UC)["control_test"]["status"], "passed")
        self.assertIn("controltest", self.svc.allowed_actions(self.store.get(C.DEPLOYMENTS, DEP_KEY),
                                                             "dave", ["ucm_deploy"]))

    def test_missing_fixture_is_reported_not_run(self):
        doc = self.svc.control_test("dave", UC)
        self.assertEqual(doc["control_test"]["status"], "no_fixture")
        self.assertEqual(self.splunk.ingests, [])

    def test_side_effect_search_is_not_run(self):
        self.svc.import_fixtures("carol", self.bundle)
        doc = self.store.get(C.DEPLOYMENTS, DEP_KEY)
        doc["revisions"][-1]["side_effects"] = ["outputlookup"]
        self.store.upsert(C.DEPLOYMENTS, doc)
        out = self.svc.control_test("dave", UC)
        self.assertEqual(out["control_test"]["status"], "not_runnable")
        self.assertEqual(self.splunk.ingests, [])

    def test_undeployed_use_case_is_refused(self):
        svc, _, _ = service()
        svc.control_runner = self.run
        svc.save_draft("alice", UC, {})
        with self.assertRaises(ConflictError):
            svc.control_test("dave", UC)

    def test_without_runner_the_action_is_not_offered(self):
        svc = DeploymentService(self.store, AuditService(self.store), FakeParser(), self.saved, DeploymentSettings())
        doc = self.store.get(C.DEPLOYMENTS, DEP_KEY)
        self.assertNotIn("controltest", svc.allowed_actions(doc, "dave", ["ucm_deploy"]))
        with self.assertRaises(UnsupportedOperation):
            svc.control_test("dave", UC)


class ApiTest(unittest.TestCase):
    def test_import_requires_content_capability_and_validates_body(self):
        store = InMemoryStore()
        bundle = {"format": ct.FIXTURE_FORMAT, "format_version": 1, "provider": "fenre", "fixtures": []}
        status, _ = call(make_ctx(store, []), "POST", "controltest/import", body=bundle)
        self.assertEqual(status, 403)
        status, body = call(make_ctx(store, ["ucm_manage_content"]), "POST", "controltest/import", body=bundle)
        self.assertEqual(status, 200, body)
        status, _ = call(make_ctx(store, ["ucm_manage_content"]), "POST", "controltest/import", body={"x": 1})
        self.assertEqual(status, 400)

    def test_controltest_action_needs_deploy_capability(self):
        status, _ = call(make_ctx(InMemoryStore(), []), "POST", "deployment/controltest", body={"id": UC})
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()

"""Readiness regression corpus (T-08).

Runs every record in ``tests/fixtures/readiness/corpus.json`` through the real
pipeline (bundle import, discovery, validation with field sampling, readiness)
against a synthetic environment, then compares each requirement with its
ground truth. The resulting counts must equal ``baseline.json``; a change that
moves them updates the baseline in the same commit, so the delta is reviewed.

    python3 tests/unit/test_readiness_corpus.py          # print metrics and per-case report
    python3 tests/unit/test_readiness_corpus.py --write  # rewrite baseline.json
"""

import configparser
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helpers  # noqa: E402,F401  (sets sys.path)
import splunk_ucm.api.app as app_module  # noqa: E402
from splunk_ucm.api.app import Context  # noqa: E402
from splunk_ucm.audit import AuditService  # noqa: E402
from splunk_ucm.config import AppConfig  # noqa: E402
from splunk_ucm.content.registry import bundle_provider  # noqa: E402
from splunk_ucm.content.sync import SyncService, new_job  # noqa: E402
from splunk_ucm.discovery.service import DiscoveryService, new_job as new_djob  # noqa: E402
from splunk_ucm.platform.search import ParseResult, SearchResult  # noqa: E402
from splunk_ucm.spl.analysis import analyze  # noqa: E402
from splunk_ucm.storage import collections as C  # noqa: E402
from splunk_ucm.storage.kvstore import InMemoryStore  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS_DIR = os.path.join(ROOT, "tests", "fixtures", "readiness")
CORPUS = os.path.join(CORPUS_DIR, "corpus.json")
BASELINE = os.path.join(CORPUS_DIR, "baseline.json")
DEFAULT_CONF = os.path.join(ROOT, "sunavigator", "default", "ucm.conf")
EVENT_SPAN = 7 * 86400
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_PAIR = re.compile(r'index=(\S+) sourcetype="([^"]+)"')
_FIELDS = re.compile(r"\| fields sun_sample_marker ([^|]*)\| fieldsummary")


def load_corpus():
    with open(CORPUS, "r", encoding="utf-8") as handle:
        return json.load(handle)


def default_config() -> AppConfig:
    parser = configparser.RawConfigParser()
    parser.optionxform = str
    parser.read(DEFAULT_CONF)
    return AppConfig({s: dict(parser.items(s)) for s in parser.sections()})


class CorpusInventory:
    def __init__(self, env):
        self.env = env

    def list_indexes(self):
        names = sorted({p["index"] for p in self.env["pairs"]})
        return [{"name": n, "disabled": False, "is_internal": False, "is_ready": True, "datatype": "event",
                 "total_event_count": 1, "min_time": "", "max_time": ""} for n in names]

    def list_apps(self):
        return []

    def list_datamodels(self):
        return []

    def list_knowledge_objects(self):
        return [{"kind": "lookup", "name": n, "app": "search", "sharing": "global", "disabled": False,
                 "lookup_type": "file"} for n in self.env.get("lookups", [])]

    def server_version(self):
        return "10.2.9"


class CorpusSearch:
    """tstats for discovery; parser; fieldsummary over the events each pair holds."""

    def __init__(self, env, now):
        self.env = env
        self.now = now
        self.pairs = {(p["index"], p["sourcetype"]): p for p in env["pairs"]}

    def tstats_rows(self):
        return [{"index": p["index"], "sourcetype": p["sourcetype"], "count": str(p["count"]),
                 "first_time": str(self.now - p["last_age"] - EVENT_SPAN),
                 "last_time": str(self.now - p["last_age"])} for p in self.env["pairs"]]

    def _time(self, value):
        value = str(value or "now")
        if value == "now":
            return float(self.now)
        rel = re.match(r"^-(\d+)([smhdw])$", value)
        if rel:
            return float(self.now - int(rel.group(1)) * _UNITS[rel.group(2)])
        return float(value)

    def parse(self, q, app=""):
        return ParseResult(True, analyze(q).commands, [])

    def preview(self, *a, **kw):
        raise AssertionError("the corpus does not preview")

    def oneshot(self, search, timeout=30.0, max_count=100, earliest="", latest=""):
        if search.lstrip().startswith("| tstats"):
            return SearchResult(self.tstats_rows(), [], False)
        m = _PAIR.search(search)
        pair = self.pairs.get((m.group(1), m.group(2))) if m else None
        if pair is None:
            return SearchResult([], [], False)
        last = self.now - pair["last_age"]
        if self._time(earliest) > last or self._time(latest) < last - EVENT_SPAN:
            return SearchResult([], [], False)
        held = set(pair["fields"]) | {"host", "source", "sourcetype"}
        wanted = _FIELDS.search(search)
        names = re.findall(r'"([^"]+)"', wanted.group(1)) if wanted else sorted(held)
        rows = [{"field": "sun_sample_marker", "count": "50", "values": "[]"}] if wanted else []
        rows += [{"field": f, "count": "50", "values": '[{"value":"v","count":50}]'} for f in names if f in held]
        return SearchResult(rows[:max_count], [], len(rows) > max_count)


def materialise(corpus, target):
    cat = os.path.join(target, "content", "cat-90-readiness-corpus")
    os.makedirs(cat)
    with open(os.path.join(cat, "_category.json"), "w", encoding="utf-8") as handle:
        json.dump({"id": 90, "name": "Readiness corpus", "slug": "cat-90-readiness-corpus"}, handle)
    for case in corpus["cases"]:
        record = {"id": case["id"], "title": "Corpus %s: %s" % (case["id"], case["pattern"]),
                  "criticality": "high", "spl": case["spl"], "requiredFields": case["requiredFields"]}
        with open(os.path.join(cat, "UC-%s.json" % case["id"]), "w", encoding="utf-8") as handle:
            json.dump(record, handle)
    shutil.copytree(os.path.join(helpers.FIXTURE_REPO, "schemas"), os.path.join(target, "schemas"))
    shutil.copy(os.path.join(helpers.FIXTURE_REPO, "VERSION"), os.path.join(target, "VERSION"))


def run_corpus():
    from ucm_bundle_builder import build_bundle_from_directory
    corpus = load_corpus()
    now = corpus["now"]
    env = corpus["environment"]
    search = CorpusSearch(env, now)
    store = InMemoryStore()
    tmp = tempfile.mkdtemp(prefix="sun-corpus-")
    try:
        materialise(corpus, tmp)
        bundle = build_bundle_from_directory(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    SyncService(store, AuditService(store)).run(new_job("corpus", "fenre", ["90"]), bundle_provider(bundle))
    DiscoveryService(store, AuditService(store), CorpusInventory(env), search,
                     now_epoch=lambda: now).run(new_djob("corpus"))
    ctx = Context(None, None, "corpus", store=store, audit_store=store, config=default_config(),
                  record_store=store)
    original = app_module.SearchClient
    app_module.SearchClient = lambda transport: search
    try:
        validation = ctx.validation_service()
        outcomes = []
        for case in corpus["cases"]:
            content_id = "fenre:UC-" + case["id"]
            validation.sample_and_assess(content_id, "corpus")
            outcomes.append((case, store.get(C.READINESS, "fenre_UC-" + case["id"])))
        return outcomes
    finally:
        app_module.SearchClient = original


COUNTED_LEVELS = ("required", "critical")


def metrics(outcomes):
    out = {
        "cases": len(outcomes), "requirements": 0,
        "false_not_met": {"derived": 0, "alternative": 0, "present": 0},
        "true_not_met": 0, "missing_not_flagged": 0,
        "unverified": {"present": 0, "derived": 0, "alternative": 0, "missing": 0},
        "false_not_ready": [], "false_ready": [],
    }
    report = []
    for case, doc in outcomes:
        results = {("%s:%s" % (r["type"], r["value"])).lower(): r for r in doc["results"]}
        lines = []
        for key, truth in sorted(case["truth"].items()):
            out["requirements"] += 1
            r = results.get(key.lower())
            status = r["status"] if r else "absent"
            counted = bool(r) and r["level"] in COUNTED_LEVELS
            if status == "not_met" and counted:
                if truth == "missing":
                    out["true_not_met"] += 1
                else:
                    out["false_not_met"][truth] += 1
            elif status == "unverified" and counted:
                out["unverified"][truth] += 1
            elif truth == "missing":
                out["missing_not_flagged"] += 1
            lines.append("    %-34s truth=%-11s status=%-12s level=%s" % (
                key, truth, status, r["level"] if r else "-"))
        ready = doc["state"] == "ready"
        if case["ready"] and not ready:
            out["false_not_ready"].append(case["id"])
        if not case["ready"] and ready:
            out["false_ready"].append(case["id"])
        report.append("%s %s: state=%s score=%s (expected %s)\n%s" % (
            case["id"], case["pattern"], doc["state"], doc["score"],
            "ready" if case["ready"] else "not ready", "\n".join(lines)))
    return out, "\n".join(report)


class ReadinessCorpusTest(unittest.TestCase):
    def test_metrics_match_baseline(self):
        measured, report = metrics(run_corpus())
        with open(BASELINE, "r", encoding="utf-8") as handle:
            baseline = json.load(handle)["metrics"]
        self.assertEqual(measured, baseline, "corpus metrics moved; review and update baseline.json\n" + report)

    def test_truth_covers_every_generated_requirement_that_counts(self):
        for case, doc in run_corpus():
            truth = {k.lower() for k in case["truth"]}
            for r in doc["results"]:
                if r["level"] in COUNTED_LEVELS and r["type"] in ("field", "sourcetype", "lookup"):
                    self.assertIn(("%s:%s" % (r["type"], r["value"])).lower(), truth, case["id"])


if __name__ == "__main__":
    measured, text = metrics(run_corpus())
    print(text)
    print(json.dumps(measured, indent=2))
    if "--write" in sys.argv:
        with open(BASELINE, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        doc["metrics"] = measured
        with open(BASELINE, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2)
            handle.write("\n")

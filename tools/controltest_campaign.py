#!/usr/bin/env python3
"""Control-test campaign over a Fenre ``samples/`` tree against a Splunk lab (B-06, issues #5 and #6).

For every fixture it runs the app's own control-test code (``splunk_ucm.deployment.controltest``) against
the use case's SPL from the Fenre checkout, exactly as ``POST ucm/deployment/controltest`` would for a
deployed revision: the events go to the ``[controltest] index`` test index with a per-run source marker,
and the SPL is scoped to that index and marker. Nothing is deployed: no saved search, KV row or role is
created or changed.

Before running a fixture the script applies the deployment gate (Splunk must parse the SPL in the app's
namespace and it must not contain side-effect commands), so a use case the app would refuse to deploy is
reported ``not_runnable`` instead of being tested.

  python3 tools/controltest_campaign.py --fenre /tmp/fenre_0e21 --output results.json
  python3 tools/controltest_campaign.py --fenre /tmp/fenre_0e21 --uc 1.1.1 --uc 9.1.2 --rows 5
  python3 tools/controltest_campaign.py --fenre /tmp/fenre_0e21 --static     # no Splunk: scoping and windows only
  python3 tools/controltest_campaign.py --report results.json --classification classes.json > report.md

Connection: ``UCM_SPLUNK_URL`` (default https://127.0.0.1:8089), ``UCM_SPLUNK_USER`` (default admin),
``UCM_SPLUNK_PASSWORD`` (environment only, never an argument), ``UCM_SPLUNK_VERIFY_TLS=0`` for a
self-signed lab. The account needs the ``search`` capability and index access to the test index.

Cleanup: ``--delete`` removes the events this run indexed (``| delete`` on the run's markers, indexed since
the start of the run). It needs the ``delete_by_keyword`` capability (the ``can_delete`` role); without it the
events stay until the index's retention removes them, and the script says so.
"""

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sunavigator", "lib"))
sys.path.insert(0, HERE)

from splunk_ucm.config import DEFAULTS  # noqa: E402
from splunk_ucm.content.registry import bundle_provider  # noqa: E402
from splunk_ucm.deployment import controltest as ct  # noqa: E402
from splunk_ucm.deployment.service import DeploymentSettings  # noqa: E402
from splunk_ucm.errors import UcmError  # noqa: E402
from splunk_ucm.platform.search import SearchClient  # noqa: E402
from splunk_ucm.spl.parser import parse  # noqa: E402
from splunk_ucm.spl.policy import classify, command_exists  # noqa: E402
from ucm_bundle_builder import build_bundle_from_directory  # noqa: E402

APP = "sunavigator"
VERDICTS = ("passed", "failed", "content_error", "inconclusive", "not_runnable")
CLASSES = ["SUN defect", "missing add-on or KV_MODE", "upstream content defect", "fixture defect", "not runnable", "passed"]
REASON_CLASSES = ("SUN defect", "missing add-on or KV_MODE", "upstream content defect", "fixture defect",
                  "not runnable")


def load_use_cases(fenre: str, uc_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """``{uc_id: {"title", "spl"}}`` through the app's own bundle provider and Fenre normalizer."""
    bundle = build_bundle_from_directory(fenre, record_ids=uc_ids or None)
    provider = bundle_provider(bundle)
    manifest = provider.get_manifest()
    normalizer = provider.normalizer()
    out: Dict[str, Dict[str, Any]] = {}
    categories = {c.category_id: normalizer.normalize_category(c) for c in manifest.categories}
    for pcat in manifest.categories:
        for listing in provider.list_records(manifest, pcat):
            record = provider.fetch_record(manifest, pcat, listing)
            uc = normalizer.normalize(record, categories[pcat.category_id], manifest, "")
            out[listing.record_id] = {"title": uc.title, "spl": uc.spl, "addons": uc.addons_text}
    return out


def deploy_gate(search: SearchClient, spl: str) -> Optional[str]:
    """The reason the app would refuse to deploy this SPL, or None."""
    parsed = parse(search, spl, app=APP)
    if not parsed.ok:
        return "Splunk could not parse the search: %s" % ((parsed.errors[0] if parsed.errors else "parse failed")[:300])
    policy = classify(spl, parsed, DeploymentSettings().extra_safe_commands,
                      exists=lambda name: command_exists(search, name, APP))
    if policy.side_effects:
        return "search contains side-effect commands (%s)" % ", ".join(policy.side_effects)
    return None


class RowRecorder:
    """Keeps the first rows of each search the runner issues, as evidence."""

    def __init__(self, runner: ct.ControlTestRunner, limit: int):
        self.limit = limit
        self.rows: List[Dict[str, Any]] = []
        self.scoped: List[str] = []
        inner = runner.run_search

        def recording(spl, marker, earliest, latest):
            self.scoped.append(spl)
            rows = inner(spl, marker, earliest, latest)
            if not self.rows:
                self.rows = [{k: v for k, v in row.items() if not k.startswith("_") or k in ("_time",)}
                             for row in rows[:self.limit]]
            return rows

        runner.run_search = recording


def run_fixture(runner: ct.ControlTestRunner, search: Optional[SearchClient], uc_id: str,
                case: Optional[Dict[str, Any]], fixture: Dict[str, Any], rows: int) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"uc_id": uc_id, "title": (case or {}).get("title", ""), "fixture_events": {
        "positive": len(ct.split_events(fixture["positive"])), "negative": len(ct.split_events(fixture["negative"]))}}
    if case is None or not case["spl"]:
        return dict(entry, status="not_runnable", reason="the use case has no SPL in the Fenre checkout")
    started = time.time()
    if search is not None:
        refusal = deploy_gate(search, case["spl"])
        if refusal:
            return dict(entry, status="not_runnable", reason="the app would not deploy this search: " + refusal,
                        gate="refused")
    recorder = RowRecorder(runner, rows)
    result = runner.run(case["spl"], fixture)
    entry.update(result)
    entry["duration_s"] = round(time.time() - started, 1)
    if rows:
        entry["sample_rows"] = recorder.rows
    return entry


def bisect(runner: ct.ControlTestRunner, search: SearchClient, spl: str, fixture: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Re-run the positive fixture and count the rows after every top-level pipeline stage (diagnosis, not a verdict)."""
    scoped_source = ct.strip_time_terms(spl)
    events = ct.split_events(fixture["positive"])
    window = ct.derive_window(events)
    marker = "ucm-ct-bisect-" + uuid.uuid4().hex
    for event in events:
        runner.ingest(event, runner.test_index, fixture["sourcetype"], marker, fixture["host"])
    runner._indexed(marker, len(events))
    scoped = ct.scope_to_test_index(scoped_source, runner.test_index, marker)
    stages = ct.pipeline_stages(scoped)
    out = []
    for upto in range(1, len(stages) + 1):
        query = " | ".join(stages[:upto])
        query = query if query.lstrip().startswith("|") else "search " + query
        entry: Dict[str, Any] = {"stage": upto, "command": stages[upto - 1][:160]}
        try:
            result = search.preview(query, app=APP, earliest=window["earliest"], latest=window["latest"],
                                    max_count=ct.MAX_RESULT_ROWS, timeout=120.0, level="smart")
            entry["rows"] = len(result.rows)
            fields = sorted(k for k in (result.rows[0] if result.rows else {}) if not k.startswith("_"))
            entry["fields"] = fields[:25]
            if result.rows:
                entry["sample"] = {k: str(v)[:80] for k, v in result.rows[0].items()
                                   if not k.startswith("_") and k in fields[:25]}
        except UcmError as exc:
            entry["error"] = getattr(exc, "message", str(exc))[:300]
            out.append(entry)
            break
        out.append(entry)
    return out


def static_result(uc_id: str, case: Optional[Dict[str, Any]], fixture: Dict[str, Any], test_index: str) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"uc_id": uc_id, "title": (case or {}).get("title", "")}
    if case is None or not case["spl"]:
        return dict(entry, status="not_runnable", reason="the use case has no SPL in the Fenre checkout")
    try:
        spl = ct.strip_time_terms(case["spl"])
        ct.scope_to_test_index(spl, test_index, "static")
    except ct.NotRunnable as exc:
        return dict(entry, status="not_runnable", reason=str(exc))
    window = ct.derive_window(ct.split_events(fixture["positive"]))
    return dict(entry, status="scopable", reason="", window=window)


def delete_events(search: SearchClient, test_index: str, since: float) -> Dict[str, Any]:
    query = ('search index=%s source="ucm-ct-*" _indextime>=%d | delete' % (test_index, int(since)))
    try:
        result = search.preview(query, app=APP, earliest="0", latest="+1d", max_count=10, timeout=300.0)
    except UcmError as exc:
        return {"deleted": False, "reason": getattr(exc, "message", str(exc))[:300]}
    row = result.rows[0] if result.rows else {}
    return {"deleted": True, "rows": row}


def summarize(results: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {name: 0 for name in VERDICTS}
    for item in results:
        out[item["status"]] = out.get(item["status"], 0) + 1
    out["total"] = len(results)
    return out


def _cell(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def render_report(data: Dict[str, Any], classes: Dict[str, Dict[str, str]]) -> str:
    results = data["results"]
    lines = ["## Summary", "", "| Verdict | Fixtures |", "|---|---|"]
    counts = summarize(results)
    for name in VERDICTS:
        lines.append("| %s | %d |" % (name, counts.get(name, 0)))
    lines += ["| **total** | **%d** |" % counts["total"], "", "| Reason class | Fixtures |", "|---|---|"]
    by_class: Dict[str, int] = {}
    for item in results:
        info = classes.get(item["uc_id"], {})
        label = info.get("class") or ("passed" if item["status"] == "passed" else "unclassified")
        by_class[label] = by_class.get(label, 0) + 1
    for label in CLASSES + sorted(set(by_class) - set(CLASSES)):
        if label in by_class or label in CLASSES:
            lines.append("| %s | %d |" % (label, by_class.get(label, 0)))
    lines += ["", "## Per fixture", "", "| UC | Verdict | Reason class | Evidence |", "|---|---|---|---|"]

    def order(item: Dict[str, Any]):
        return [int(part) for part in item["uc_id"].split(".")]

    for item in sorted(results, key=order):
        info = classes.get(item["uc_id"], {})
        evidence = info.get("evidence") or item.get("reason") or ""
        label = info.get("class") or ("passed" if item["status"] == "passed" else "unclassified")
        lines.append("| UC-%s | %s | %s | %s |" % (item["uc_id"], item["status"], label, _cell(evidence)))
    return "\n".join(lines) + "\n"


def connect(verify: bool):
    from splunkd_http import HttpTransport
    transport = HttpTransport(os.environ.get("UCM_SPLUNK_URL", "https://127.0.0.1:8089"),
                              username=os.environ.get("UCM_SPLUNK_USER", "admin"),
                              password=os.environ.get("UCM_SPLUNK_PASSWORD", ""), verify_tls=verify)
    return transport, SearchClient(transport)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fenre", help="Fenre checkout (content/ and samples/)")
    parser.add_argument("--samples", help="samples directory (default <fenre>/samples)")
    parser.add_argument("--uc", action="append", default=[], help="only this use case id, e.g. 1.1.1 (repeatable)")
    parser.add_argument("--test-index", default=DEFAULTS.get("controltest", {}).get("index", ct.DEFAULT_TEST_INDEX))
    parser.add_argument("--settle", type=float, default=ct.SETTLE_SECONDS, help="seconds to wait for indexing")
    parser.add_argument("--rows", type=int, default=3, help="sample result rows kept per fixture as evidence")
    parser.add_argument("--output", help="write the results JSON here")
    parser.add_argument("--bisect", action="store_true",
                        help="for fixtures that did not pass, count rows after each pipeline stage (diagnosis)")
    parser.add_argument("--static", action="store_true", help="no Splunk: only scoping and window derivation")
    parser.add_argument("--delete", action="store_true", help="delete this run's events afterwards (needs can_delete)")
    parser.add_argument("--report", help="render a Markdown report from a results JSON instead of running")
    parser.add_argument("--classification", help="JSON {uc_id: {class, evidence}} used with --report")
    args = parser.parse_args(argv)

    if args.report:
        with open(args.report, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        classes: Dict[str, Dict[str, str]] = {}
        if args.classification:
            with open(args.classification, "r", encoding="utf-8") as handle:
                classes = json.load(handle)
        sys.stdout.write(render_report(data, classes))
        return 0
    if not args.fenre:
        parser.error("--fenre is required")
    samples = args.samples or os.path.join(args.fenre, "samples")
    wanted = {u[3:] if u.startswith("UC-") else u for u in args.uc}
    bundle, report = ct.build_fixture_bundle(samples)
    _, fixtures = ct.validate_bundle(bundle)
    fixtures = [dict(fx, **ct.expectations(fx)) for fx in fixtures if not wanted or fx["uc_id"] in wanted]
    cases = load_use_cases(args.fenre, sorted(fx["uc_id"] for fx in fixtures))
    started = time.time()
    results: List[Dict[str, Any]] = []
    search: Optional[SearchClient] = None
    runner: Optional[ct.ControlTestRunner] = None
    if not args.static:
        transport, search = connect(os.environ.get("UCM_SPLUNK_VERIFY_TLS", "1") != "0")
        runner = ct.splunk_runner(transport, search, APP, args.test_index, settle=args.settle)
    for fx in fixtures:
        uc_id = fx["uc_id"]
        try:
            if runner is None:
                entry = static_result(uc_id, cases.get(uc_id), fx, args.test_index)
            else:
                entry = run_fixture(runner, search, uc_id, cases.get(uc_id), fx, args.rows)
        except UcmError as exc:
            entry = {"uc_id": uc_id, "title": cases.get(uc_id, {}).get("title", ""), "status": "inconclusive",
                     "reason": "campaign error: %s" % getattr(exc, "message", str(exc))[:300]}
        if args.bisect and runner is not None and entry["status"] in ("failed", "content_error"):
            try:
                entry["stages"] = bisect(runner, search, cases[uc_id]["spl"], fx)
            except (UcmError, ct.NotRunnable) as exc:
                entry["stages"] = [{"error": getattr(exc, "message", str(exc))[:300]}]
        results.append(entry)
        print("UC-%-9s %-13s %s" % (uc_id, entry["status"], (entry.get("reason") or "")[:110]), flush=True)
    output: Dict[str, Any] = {"run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                              "test_index": args.test_index, "fixtures_skipped": report["skipped"],
                              "summary": summarize(results), "results": results}
    if args.delete and search is not None:
        output["cleanup"] = delete_events(search, args.test_index, started)
        print("cleanup:", json.dumps(output["cleanup"]))
    print(json.dumps(output["summary"]))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=1, sort_keys=True)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

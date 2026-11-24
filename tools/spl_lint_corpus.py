#!/usr/bin/env python3
"""Run the advisory SPL lint (``splunk_ucm.spl.lint``, D-065) over a whole content corpus. No Splunk needed.

  python3 tools/spl_lint_corpus.py --fenre /tmp/fenre_0e21 --escu /tmp/escu/DA-ESS-ContentUpdate
  python3 tools/spl_lint_corpus.py --bundle bundle.json --output findings.json --examples 3

Sources (any combination): ``--fenre`` a Fenre-layout checkout, ``--escu`` an extracted ESCU package or
.tar.gz, ``--bundle`` an offline bundle written by ``tools/ucm_cli.py``. Every use case is normalized by
the app's own provider code, and both its primary and its CIM SPL are linted.

The report counts, per source and per rule, the searches with at least one finding (a search counts once
per rule, however many times the rule fires in it) and the findings themselves. ``--output`` writes every
finding with its use case id as JSON; ``--examples N`` prints N example use case ids per rule (``--ids``: all of them).
"""

import argparse
import collections
import json
import os
import sys
from typing import Any, Dict, Iterator, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sunavigator", "lib"))
sys.path.insert(0, HERE)

from splunk_ucm.content.escu.package import build_bundle as build_escu_bundle  # noqa: E402
from splunk_ucm.content.registry import bundle_provider  # noqa: E402
from splunk_ucm.spl.lint import RULES, lint  # noqa: E402
from ucm_bundle_builder import build_bundle_from_directory  # noqa: E402


def use_cases(bundle: Dict[str, Any]) -> Iterator[Tuple[str, str, str]]:
    """``(use case id, kind, spl)`` for every primary and CIM search of a bundle."""
    provider = bundle_provider(bundle)
    manifest = provider.get_manifest()
    normalizer = provider.normalizer()
    categories = {c.category_id: normalizer.normalize_category(c) for c in manifest.categories}
    for pcat in manifest.categories:
        for listing in provider.list_records(manifest, pcat):
            record = provider.fetch_record(manifest, pcat, listing)
            uc = normalizer.normalize(record, categories[pcat.category_id], manifest, "")
            for kind, spl in (("primary", uc.spl), ("cim", uc.cim_spl)):
                if spl:
                    yield listing.record_id, kind, spl


def measure(label: str, bundle: Dict[str, Any], examples: int) -> Dict[str, Any]:
    searches = 0
    records = set()
    by_rule: Dict[str, set] = {rule: set() for rule in RULES}
    findings_per_rule: Dict[str, int] = collections.Counter()
    by_function: Dict[str, set] = collections.defaultdict(set)
    flagged = set()
    findings: List[Dict[str, Any]] = []
    for uc_id, kind, spl in use_cases(bundle):
        searches += 1
        records.add(uc_id)
        for finding in lint(spl):
            key = "%s/%s" % (uc_id, kind)
            by_rule[finding["rule"]].add(key)
            findings_per_rule[finding["rule"]] += 1
            flagged.add(key)
            if finding["rule"] == "L001":
                by_function[finding["call"].split("(")[0]].add(key)
            findings.append(dict(finding, use_case=uc_id, search=kind))
    return {
        "source": label, "records": len(records), "searches": searches, "searches_with_findings": len(flagged),
        "searches_per_rule": {r: len(v) for r, v in by_rule.items()},
        "findings_per_rule": {r: findings_per_rule[r] for r in RULES},
        "l001_by_function": {f: len(v) for f, v in sorted(by_function.items())},
        "examples": {r: sorted(v)[:examples] for r, v in by_rule.items()},
        "findings": findings,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--fenre", help="Fenre-layout checkout")
    p.add_argument("--escu", help="extracted ESCU package directory or .tar.gz")
    p.add_argument("--bundle", action="append", default=[], help="offline bundle JSON (repeatable)")
    p.add_argument("--output", help="write the full findings as JSON")
    p.add_argument("--examples", type=int, default=3)
    p.add_argument("--ids", action="store_true", help="list every flagged use case id per rule")
    args = p.parse_args(argv)
    if not (args.fenre or args.escu or args.bundle):
        p.error("give at least one of --fenre, --escu, --bundle")
    shown = 10 ** 9 if args.ids else args.examples
    reports = []
    if args.fenre:
        reports.append(measure("fenre", build_bundle_from_directory(args.fenre), shown))
    if args.escu:
        bundle, _ = build_escu_bundle(args.escu)
        reports.append(measure("escu", bundle, shown))
    for path in args.bundle:
        with open(path, "r", encoding="utf-8") as handle:
            reports.append(measure(os.path.basename(path), json.load(handle), shown))
    for r in reports:
        print("%s: %d records, %d searches, %d with findings" % (
            r["source"], r["records"], r["searches"], r["searches_with_findings"]))
        for rule, name in RULES.items():
            print("  %s %-34s %5d searches  %5d findings" % (
                rule, name, r["searches_per_rule"][rule], r["findings_per_rule"][rule]))
            if r["examples"][rule]:
                print("       %s " % ("ids:" if args.ids else "e.g.") + ", ".join(r["examples"][rule]))
        if r["l001_by_function"]:
            print("  L001 by function: " + ", ".join("%s %d" % kv for kv in r["l001_by_function"].items()))
    if len(reports) > 1:
        print("all sources: %d searches, %s" % (
            sum(r["searches"] for r in reports),
            ", ".join("%s %d" % (rule, sum(r["searches_per_rule"][rule] for r in reports)) for rule in RULES)))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(reports, handle, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

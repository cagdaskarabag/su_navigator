#!/usr/bin/env python3
"""Write the findings about a Fenre checkout as one file the project owner can hand to the Fenre maintainer.

  python3 tools/fenre_report.py --fenre /tmp/fenre_0e21 --output docs/upstream/for-fenre-owner

Writes ``FENRE_CONTENT_FINDINGS.md`` (readable on its own) and ``fenre_content_findings.csv`` (one row per
finding, for a spreadsheet or for scripting the fixes) into the output directory. The SPL findings come from the
app's own lint (``splunk_ucm.spl.lint``, D-065) run over every use case; the control-test findings are the
hand-verified list in ``docs/upstream/FENRE_FINDINGS.md`` (D-064). Nothing is sent anywhere: sending it is
the project owner's decision (D-072, D-080).
"""

import argparse
import collections
import csv
import io
import os
import re
import sys
from typing import Any, Dict, Iterator, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "sunavigator", "lib"))
sys.path.insert(0, HERE)

from splunk_ucm.content.registry import bundle_provider  # noqa: E402
from splunk_ucm.frameworks.evidence import _cell as csv_cell  # noqa: E402
from splunk_ucm.spl.lint import RULES, lint  # noqa: E402
from ucm_bundle_builder import build_bundle_from_directory  # noqa: E402

RULE_TEXT: Dict[str, Tuple[str, str, str]] = {
    "L001": (
        "An eval function used as a search term",
        "`search` (and the implicit search at the start of a query) does not evaluate eval functions. `match(...)`, "
        "`like(...)` and the others are read as plain words, so the clause matches nothing, and under `NOT` it matches "
        "everything. Splunk reports no error.",
        "Move the condition into `| where` or `| eval` after the base search, for example "
        "`index=x sourcetype=y | where match(_raw, \"pattern\")`.",
    ),
    "L002": (
        "`timechart` with more than one split-by field",
        "`timechart` takes a single `by` field. A comma or a space separated list makes Splunk reject the search.",
        "Use one field, or aggregate with `bin _time span=...` and `stats ... by _time, a, b`.",
    ),
    "L003": (
        "`match`, `like` or `cidrmatch` with the wrong number of arguments",
        "These functions take exactly two arguments. A third argument (for example the flags string `\"i\"`) makes "
        "Splunk reject the search.",
        "Put the flags inside the pattern: `match(field, \"(?i)pattern\")`.",
    ),
    "L004": (
        "Regex ending in a single backslash inside an eval string",
        "An eval string is unescaped once before the regex sees it, so a regex backslash needs four backslashes "
        "in the SPL. `\"^.*\\\\\"` leaves one backslash, which is an incomplete escape; Splunk rejects the search.",
        "Write the end of the string as `\"...\\\\\\\\\"` (four backslashes).",
    ),
    "L005": (
        "Time modifier that snaps to a number of units",
        "`-6h@5m` is not valid. `@` snaps to one unit. `tstats` rejects the search and a plain search silently selects "
        "no events.",
        "Snap to one unit, for example `-6h@m`, and use `span=5m` in `bin`, `tstats` or `timechart` for 5-minute buckets.",
    ),
    "L006": (
        "Regex with an escape PCRE2 does not support",
        "After the eval string is unescaped, `\\u`, `\\U`, `\\l`, `\\L` and `\\F` remain in the regex, usually a Windows "
        "path written `\"^.:\\\\users\\\\\"`. PCRE2 does not support them and Splunk rejects the search.",
        "Write four backslashes for each literal backslash: `\"^.:\\\\\\\\users\\\\\\\\\"`.",
    ),
}


def findings_for(bundle: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    provider = bundle_provider(bundle)
    manifest = provider.get_manifest()
    normalizer = provider.normalizer()
    categories = {c.category_id: normalizer.normalize_category(c) for c in manifest.categories}
    for pcat in manifest.categories:
        for listing in provider.list_records(manifest, pcat):
            record = provider.fetch_record(manifest, pcat, listing)
            uc = normalizer.normalize(record, categories[pcat.category_id], manifest, "")
            for kind, spl in (("primary", uc.spl), ("cim", uc.cim_spl)):
                for finding in (lint(spl) if spl else []):
                    yield {
                        "rule": finding["rule"], "use_case": listing.record_id, "title": uc.title or "",
                        "search": kind, "command": finding["command"], "call": finding["call"],
                        "message": finding["message"], "suggestion": finding["suggestion"],
                    }


def _natural(value: str) -> List[Any]:
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", value)]


def _cell(text: str, limit: int = 110) -> str:
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.replace("|", "\\|").replace("`", "'")


def csv_text(findings: List[Dict[str, Any]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["rule", "use_case", "title", "search", "command", "construct", "suggested_fix"])
    for f in findings:
        writer.writerow([csv_cell(v) for v in (f["rule"], "UC-" + f["use_case"], f["title"], f["search"], f["command"],
                                               f["call"], f["suggestion"])])
    return out.getvalue()


def campaign_section(path: str) -> str:
    """The hand-verified control-test findings (F-01 to F-11), from the project's working file."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    start = text.index("| ID | Use cases |")
    body = text[start:]
    end = body.index("## SPL lint over the whole corpus")
    body = body[:end].rstrip() + "\n"
    body = re.sub(r"\s*\(issue #\d+\)", "", body)
    body = re.sub(r"\s*\(D-\d+\)", "", body)
    return body.replace("## ", "### ")


def report(findings: List[Dict[str, Any]], searches: int, records: int, commit: str, version: str,
           campaign: str) -> str:
    by_rule: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for f in findings:
        by_rule[f["rule"]].append(f)
    flagged = {(f["use_case"], f["search"]) for f in findings}
    lines = [
        "# Findings in the Fenre content catalogue, found while building SUNavigator",
        "",
        "This is a courtesy report. It is written to be read on its own and nothing in it has been filed as an issue.",
        "Use as much or as little of it as is useful; every item says how to reproduce it and what would fix it.",
        "",
        "* Catalogue checked: Fenre `main` at commit `%s` (%s use cases, %s searches counting the CIM variants)."
        % (commit, format(records, ","), format(searches, ",")),
        "* Tool: SUNavigator %s (https://github.com/cagdaskarabag/su_navigator, Apache-2.0), `tools/fenre_report.py` (SPL lint, `sunavigator/lib/splunk_ucm/spl/lint.py`) and the "
        "control-test campaign (`tools/controltest_campaign.py`)." % version,
        "* Environment: Splunk Enterprise 10.2.9, no add-ons installed. Every rule below fires only for a construct that "
        "was shown to be wrong on that version. For rules `L002` to `L005` the flagged searches were also sent to "
        "Splunk's own parser (`/services/search/parser`) and all of them were rejected. `L001` is silent in the parser "
        "(Splunk accepts the search and returns nothing), so it is shown by the one-line check in its section.",
        "* Counting: %d findings in %d searches. A search counts once per rule however often the rule fires in it."
        % (len(findings), len(flagged)),
        "",
        "## Part A. SPL that Splunk rejects or that cannot match",
        "",
        "| Rule | Problem | Searches | Findings |",
        "|---|---|---|---|",
    ]
    for rule in RULES:
        items = by_rule.get(rule, [])
        lines.append("| %s | %s | %d | %d |" % (
            rule, RULE_TEXT[rule][0], len({(f["use_case"], f["search"]) for f in items}), len(items)))
    lines += ["", "The same rows, one per finding, are in `fenre_content_findings.csv`.", ""]
    for rule in RULES:
        items = sorted(by_rule.get(rule, []), key=lambda f: (_natural(f["use_case"]), f["search"]))
        title, why, fix = RULE_TEXT[rule]
        lines += ["### %s %s" % (rule, title), "", "* Why it is wrong: " + why, "* Suggested fix: " + fix, ""]
        if rule == "L001":
            lines += [
                "* Check it yourself: run `index=_internal | head 5 | search match(_raw, \"nothing_like_this\")` and then "
                "`index=_internal | head 5 | search NOT match(_raw, \"nothing_like_this\")`. The first returns no events "
                "and the second returns all five, because the call is searched for as text and never evaluated.",
                "",
            ]
            counts = collections.Counter(f["call"].split("(")[0] for f in items)
            lines += ["By function (findings): " + ", ".join("`%s` %d" % kv for kv in sorted(counts.items(), key=lambda kv: -kv[1])), ""]
        if not items:
            lines += ["No findings.", ""]
            continue
        lines += ["| Use case | Title | Search | Command | Construct |", "|---|---|---|---|---|"]
        for f in items:
            lines.append("| UC-%s | %s | %s | `%s` | `%s` |" % (
                f["use_case"], _cell(f["title"], 70), f["search"], f["command"], _cell(f["call"])))
        lines.append("")
    lines += [
        "## Part B. Findings from running the fixtures",
        "",
        "SUNavigator ran the events of 94 fixtures through each use case's own SPL on a lab with no add-ons and compared "
        "the result with the fixture's manifest. A defect is listed only when it holds without any add-on, or when it "
        "was shown to hold with the add-on's fields emulated. Fixture and manifest names refer to the files in "
        "`samples/` and `content/`.",
        "",
        campaign,
    ]
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--fenre", required=True, help="Fenre-layout checkout")
    p.add_argument("--output", required=True, help="directory to write the report and the CSV into")
    args = p.parse_args(argv)
    bundle = build_bundle_from_directory(args.fenre)
    findings = sorted(findings_for(bundle), key=lambda f: (f["rule"], _natural(f["use_case"]), f["search"]))
    provider = bundle_provider(bundle)
    manifest = provider.get_manifest()
    records = searches = 0
    normalizer = provider.normalizer()
    categories = {c.category_id: normalizer.normalize_category(c) for c in manifest.categories}
    for pcat in manifest.categories:
        for listing in provider.list_records(manifest, pcat):
            uc = normalizer.normalize(provider.fetch_record(manifest, pcat, listing), categories[pcat.category_id], manifest, "")
            records += 1
            searches += bool(uc.spl) + bool(uc.cim_spl)
    commit = ""
    try:
        import subprocess
        commit = subprocess.check_output(["git", "-C", args.fenre, "rev-parse", "--short=8", "HEAD"], text=True).strip()
    except Exception:
        commit = "unknown"
    with open(os.path.join(ROOT, "sunavigator", "default", "app.conf"), "r", encoding="utf-8") as handle:
        version = re.search(r"^version\s*=\s*(\S+)", handle.read(), re.M).group(1)
    campaign = campaign_section(os.path.join(ROOT, "docs", "upstream", "FENRE_FINDINGS.md"))
    os.makedirs(args.output, exist_ok=True)
    with open(os.path.join(args.output, "FENRE_CONTENT_FINDINGS.md"), "w", encoding="utf-8") as handle:
        handle.write(report(findings, searches, records, commit, version, campaign))
    with open(os.path.join(args.output, "fenre_content_findings.csv"), "w", encoding="utf-8", newline="") as handle:
        handle.write(csv_text(findings))
    print("%d findings, %d searches, %d records -> %s" % (len(findings), searches, records, args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())

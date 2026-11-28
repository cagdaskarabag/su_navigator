#!/usr/bin/env python3
"""Count how much each part of SUNavigator is used, from the app's own audit log.

Prints counts only: audit rows per module, the distinct number of people behind them and the last use. It never
prints a user name, an object id or any record content, so the output is safe to paste into a feedback issue.

The audit log records changes (a sync, an assessment, a deployment, a POA&M item), not page views. A module with no
rows may still be read; a module with rows is used.

    UCM_SPLUNK_PASSWORD=... python3 tools/usage_census.py --url https://localhost:8089 --user admin --days 90

The password is read from the environment, never from the command line. Use ``--insecure`` for a self-signed
certificate. Needs a role that may read the app's audit collection (admin, sc_admin or ucm_admin).
"""

import argparse
import base64
import collections
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

COLLECTION = "/servicesNS/nobody/sunavigator/storage/collections/data/uc_audit"
PAGE = 1000
MAX_PAGES = 200

MODULES = (
    ("compliance", ("assessment.", "poam.", "framework.")),
    ("dashboards", ("dashboard.",)),
    ("content", ("content.", "controltest.import")),
    ("discovery", ("discovery.",)),
    ("readiness", ("readiness.",)),
    ("selection", ("selection.",)),
    ("validation", ("validation.",)),
    ("control_tests", ("deployment.controltest",)),
    ("deployment", ("deployment.",)),
    ("audit", ("audit.",)),
    ("external", ("external.",)),
    ("refused", ("refused.",)),
    ("platform", ("app.", "retention.")),
)
CORE = ("content", "discovery", "readiness", "selection", "validation", "control_tests", "deployment")


def module_of(action):
    for name, prefixes in MODULES:
        if any(action.startswith(p) for p in prefixes):
            return name
    return "other"


def census(rows, now, days):
    since = now - days * 86400
    stats = collections.OrderedDict((name, {"rows": 0, "people": set(), "last": 0.0}) for name, _ in MODULES)
    stats["other"] = {"rows": 0, "people": set(), "last": 0.0}
    for row in rows:
        when = float(row.get("time") or 0)
        if when < since:
            continue
        entry = stats[module_of(str(row.get("action") or ""))]
        entry["rows"] += 1
        actor = str(row.get("actor") or "")
        if actor and actor not in ("system", "unknown"):
            entry["people"].add(actor)
        entry["last"] = max(entry["last"], when)
    out = {"days": days, "modules": {}}
    for name, entry in stats.items():
        out["modules"][name] = {"rows": entry["rows"], "people": len(entry["people"]),
                                "last_days_ago": round((now - entry["last"]) / 86400, 1) if entry["last"] else None}
    core = sum(out["modules"][m]["rows"] for m in CORE)
    comp = out["modules"]["compliance"]["rows"] + out["modules"]["dashboards"]["rows"]
    out["summary"] = {"core_rows": core, "compliance_and_dashboard_rows": comp,
                      "compliance_share": round(comp / (core + comp), 3) if core + comp else None}
    return out


def fetch(url, user, password, verify, days, now):
    ctx = None if verify else ssl._create_unverified_context()  # nosec - opt-in for lab certificates
    token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
    rows = []
    since = now - days * 86400
    for page in range(MAX_PAGES):
        query = urllib.parse.urlencode({
            "output_mode": "json", "fields": "action,actor,time", "limit": PAGE, "skip": page * PAGE,
            "query": json.dumps({"time": {"$gte": since}})})
        req = urllib.request.Request(url.rstrip("/") + COLLECTION + "?" + query, headers={"Authorization": "Basic " + token})
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:  # nosec - operator-supplied URL
            batch = json.loads(resp.read().decode("utf-8"))
        rows.extend(batch)
        if len(batch) < PAGE:
            return rows
    raise SystemExit("more than %d audit rows in the window; use a shorter --days" % (MAX_PAGES * PAGE))


def render(result):
    lines = ["SUNavigator usage census, last %d days (audit rows only; page views are not recorded)" % result["days"], "",
             "%-14s %8s %8s %s" % ("module", "rows", "people", "last use")]
    for name, m in result["modules"].items():
        if m["rows"] or name in CORE or name in ("compliance", "dashboards"):
            last = "never" if m["last_days_ago"] is None else "%s days ago" % m["last_days_ago"]
            lines.append("%-14s %8d %8d %s" % (name, m["rows"], m["people"], last))
    s = result["summary"]
    share = "n/a" if s["compliance_share"] is None else "%.0f%%" % (100 * s["compliance_share"])
    lines += ["", "core rows %d, compliance and dashboards rows %d, compliance share %s" % (
        s["core_rows"], s["compliance_and_dashboard_rows"], share)]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default="https://localhost:8089")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args(argv)
    password = os.environ.get("UCM_SPLUNK_PASSWORD", "")
    if not password:
        parser.error("set UCM_SPLUNK_PASSWORD in the environment")
    now = time.time()
    result = census(fetch(args.url, args.user, password, not args.insecure, args.days, now), now, args.days)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())

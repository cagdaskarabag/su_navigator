#!/usr/bin/env python3
"""Export the records of the retired compliance module: assessments, plan-of-action items and evidence snapshots.

0.14.0 removed the assessment, POA&M and snapshot features (D-086). Their three collections keep every record, and
this tool writes them to one JSON file so an administrator can keep or move them. A snapshot is written exactly as it
was stored, and its SHA-256 is checked the same way the app checked it, so an exported snapshot can still be verified.

    UCM_SPLUNK_PASSWORD=... python3 tools/compliance_export.py --url https://localhost:8089 --user admin --insecure --out export.json

The password is read from the environment, never from the command line. Use ``--insecure`` for a self-signed
certificate. Needs a role that reads the collections: admin, sc_admin or ucm_admin.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunkd_http import HttpTransport  # noqa: E402  (also puts sunavigator/lib on the path)
from splunk_ucm.storage import collections as C  # noqa: E402
from splunk_ucm.storage.kvstore import KVStore  # noqa: E402
from splunk_ucm.util import sha256_text, utc_now_iso  # noqa: E402

FORMAT = "sunavigator.compliance-export/1"
COLLECTIONS = (("assessments", C.ASSESSMENTS), ("poam", C.POAM), ("snapshots", C.SNAPSHOTS))


def _snapshot_check(doc):
    actual = sha256_text(doc.get("content_json") or "")
    return {"id": doc.get("_key"), "framework_id": doc.get("framework_id"), "ok": actual == doc.get("sha256"),
            "expected": doc.get("sha256"), "actual": actual}


def export(store, now=None):
    out = {"format": FORMAT, "exported_at": now or utc_now_iso(), "records": {}, "counts": {}, "snapshot_integrity": []}
    for label, collection in COLLECTIONS:
        docs = store.query(collection, None, sort=[("_key", 1)], limit=0)
        out["records"][label] = docs
        out["counts"][label] = len(docs)
    out["snapshot_integrity"] = [_snapshot_check(d) for d in out["records"]["snapshots"]]
    out["counts"]["snapshots_failing_check"] = sum(1 for c in out["snapshot_integrity"] if not c["ok"])
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default="https://localhost:8089")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    parser.add_argument("--out", default="-", help="file to write, or - for standard output")
    args = parser.parse_args(argv)
    password = os.environ.get("UCM_SPLUNK_PASSWORD", "")
    if not password:
        parser.error("set UCM_SPLUNK_PASSWORD in the environment")
    transport = HttpTransport(args.url, username=args.user, password=password, verify_tls=not args.insecure)
    result = export(KVStore(transport))
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        sys.stderr.write("wrote %s: %s\n" % (args.out, json.dumps(result["counts"], sort_keys=True)))
    return 1 if result["counts"]["snapshots_failing_check"] else 0


if __name__ == "__main__":
    sys.exit(main())

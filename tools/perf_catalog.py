#!/usr/bin/env python3
"""Catalogue query performance check against a real KV Store.

Normalizes a local Fenre-layout checkout, writes the catalogue summaries to
``uc_catalog`` under a separate ``perf`` provider (keys ``perf_*``), times the
queries the catalogue UI issues, then deletes the documents again.

  UCM_SPLUNK_PASSWORD=... python3 tools/perf_catalog.py --repo /path/to/checkout \
      [--url https://localhost:8089] [--user admin] [--target 20000] [--insecure]
"""

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunkd_http import HttpTransport  # noqa: E402
from splunk_ucm.catalog.query import CatalogFilter, CatalogQueryService  # noqa: E402
from splunk_ucm.catalog.summary import catalog_summary  # noqa: E402
from splunk_ucm.content.registry import bundle_provider  # noqa: E402
from splunk_ucm.storage import collections as C  # noqa: E402
from splunk_ucm.storage.kvstore import KVStore  # noqa: E402
from ucm_bundle_builder import build_bundle_from_directory  # noqa: E402

QUERIES = {
    "first page (id sort, with total)": CatalogFilter(provider_status="any"),
    "free text 'failed login'": CatalogFilter(q="failed login", provider_status="any"),
    "domain=security, sort criticality": CatalogFilter(domains=["security"], sort="criticality",
                                                       provider_status="any"),
    "mitre=T1110": CatalogFilter(mitre="T1110", provider_status="any"),
    "sourcetype=WinEventLog:Security": CatalogFilter(sourcetype="WinEventLog:Security", provider_status="any"),
    "deep page offset=15000": CatalogFilter(offset=15000, provider_status="any"),
    "page without total": CatalogFilter(with_total=False, provider_status="any"),
}


def summaries(repo, target):
    bundle = build_bundle_from_directory(repo)
    provider = bundle_provider(bundle)
    manifest = provider.get_manifest()
    normalizer = provider.normalizer()
    docs = []
    for pcat in manifest.categories:
        cat = normalizer.normalize_category(pcat)
        for listing in provider.list_records(manifest, pcat):
            uc = normalizer.normalize(provider.fetch_record(manifest, pcat, listing), cat, manifest,
                                      "2026-01-01T00:00:00Z")
            docs.append(catalog_summary(uc))
    out = []
    copy_no = 0
    while len(out) < target:
        for doc in docs:
            if len(out) >= target:
                break
            d = dict(doc)
            d["_key"] = "perf_%d_%s" % (copy_no, doc["_key"])
            d["provider"] = "perf"
            out.append(d)
        copy_no += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--url", default="https://localhost:8089")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--target", type=int, default=20000)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (dev only)")
    ap.add_argument("--repeat", type=int, default=5)
    args = ap.parse_args()
    kv = KVStore(HttpTransport(args.url, username=args.user, password=os.environ.get("UCM_SPLUNK_PASSWORD", ""),
                               verify_tls=not args.insecure))
    docs = summaries(args.repo, args.target)
    report = {"documents": len(docs), "avg_doc_bytes": int(statistics.mean(len(json.dumps(d)) for d in docs))}
    t0 = time.time()
    try:
        kv.batch_save(C.CATALOG, docs)
        report["write_seconds"] = round(time.time() - t0, 1)
        report["collection_count"] = kv.count(C.CATALOG)
        svc = CatalogQueryService(kv)
        report["queries_ms"] = {}
        for name, f in QUERIES.items():
            times, result = [], None
            for _ in range(args.repeat):
                start = time.time()
                result = svc.search(f)
                times.append((time.time() - start) * 1000)
            report["queries_ms"][name] = {"median": round(statistics.median(times)), "max": round(max(times)),
                                          "total": result["total"], "returned": len(result["items"])}
    finally:
        kv.delete_query(C.CATALOG, {"provider": "perf"})
        report["cleanup_remaining"] = kv.count(C.CATALOG, {"provider": "perf"})
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

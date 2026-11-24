#!/usr/bin/env python3
"""Catalogue query performance check against a real KV Store.

Normalizes a local Fenre-layout checkout, writes the catalogue summaries to
``uc_catalog`` (keys ``perf_*``, marked ``perf_run``), times the queries the catalogue UI issues,
then deletes the documents again. Hashes are salted so no perf document pairs with a real one; the
post-pass timing also rewrites the stored facets document, so run Reindex on a lab afterwards.

  UCM_SPLUNK_PASSWORD=... python3 tools/perf_catalog.py --repo /path/to/checkout \
      [--escu /path/to/DA-ESS-ContentUpdate] [--url https://localhost:8089] [--user admin] \
      [--target 20000] [--insecure]

With ``--escu`` the ESCU detections are part of the corpus, so the provider, story and data source
filters have something to match. Facet timings: ``get_facets`` (stored document), ``recompute`` (the scan
a stale facets document costs on request) and ``post-pass`` (what runs after sync, import and reindex).
"""

import argparse
import dataclasses
import hashlib
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunkd_http import HttpTransport  # noqa: E402
from splunk_ucm.catalog import derived  # noqa: E402
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


NEW_QUERIES = {
    "provider=escu": {"providers": ["escu"]},
    "provider=fenre, domain=security": {"providers": ["fenre"], "domains": ["security"]},
    "wave=crawl": {"waves": ["crawl"]},
    "story=Brute Force": {"stories": ["Brute Force"]},
    "data_source=Sysmon EventID 1": {"data_sources": ["Sysmon EventID 1"]},
    "exclude_quality=unreviewed,ai_reviewed": {"exclude_quality": ["unreviewed", "ai_reviewed"]},
    "provider=escu + availability=ready": {"providers": ["escu"], "availability": ["ready"]},
}


def one_bundle_docs(bundle):
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
    return docs


def summaries(repo, target, escu=None):
    docs = one_bundle_docs(build_bundle_from_directory(repo))
    if escu:
        from splunk_ucm.content.escu.package import build_bundle
        docs.extend(one_bundle_docs(build_bundle(escu)[0]))
    out = []
    copy_no = 0
    while len(out) < target:
        for doc in docs:
            if len(out) >= target:
                break
            d = dict(doc)
            d["_key"] = "perf_%d_%s" % (copy_no, doc["_key"])
            d["perf_run"] = True
            if d.get("spl_hash"):
                d["spl_hash"] = hashlib.sha256(("perf%d:%s" % (copy_no, d["spl_hash"])).encode()).hexdigest()
            out.append(d)
        copy_no += 1
    return out


def facet_timings(kv, repeat):
    scan = getattr(derived, "scan_catalog", None) or derived._scan
    out = {}

    def timed(name, fn, times):
        samples = []
        for _ in range(times):
            start = time.time()
            fn()
            samples.append((time.time() - start) * 1000)
        out[name] = {"median": round(statistics.median(samples)), "max": round(max(samples))}

    timed("recompute (scan + compute)", lambda: derived.compute_facets(scan(kv)), min(repeat, 3))
    timed("post-pass (refresh_derived)", lambda: derived.refresh_derived(kv), 2)
    timed("get_facets (stored)", lambda: derived.get_facets(kv), repeat)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--url", default="https://localhost:8089")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--target", type=int, default=20000)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (dev only)")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--escu", default="", help="ESCU package directory or archive to include in the corpus")
    args = ap.parse_args()
    kv = KVStore(HttpTransport(args.url, username=args.user, password=os.environ.get("UCM_SPLUNK_PASSWORD", ""),
                               verify_tls=not args.insecure))
    docs = summaries(args.repo, args.target, args.escu or None)
    report = {"documents": len(docs), "avg_doc_bytes": int(statistics.mean(len(json.dumps(d)) for d in docs))}
    t0 = time.time()
    try:
        kv.batch_save(C.CATALOG, docs)
        report["write_seconds"] = round(time.time() - t0, 1)
        report["collection_count"] = kv.count(C.CATALOG)
        svc = CatalogQueryService(kv)
        report["queries_ms"] = {}
        available = {f.name for f in dataclasses.fields(CatalogFilter)}
        queries = dict(QUERIES)
        for name, kw in NEW_QUERIES.items():
            if set(kw) <= available:
                queries[name] = CatalogFilter(provider_status="any", **kw)
        for name, f in queries.items():
            times, result = [], None
            for _ in range(args.repeat):
                start = time.time()
                result = svc.search(f)
                times.append((time.time() - start) * 1000)
            report["queries_ms"][name] = {"median": round(statistics.median(times)), "max": round(max(times)),
                                          "total": result["total"], "returned": len(result["items"])}
        report["facets_ms"] = facet_timings(kv, args.repeat)
    finally:
        kv.delete_query(C.CATALOG, {"perf_run": True})
        report["cleanup_remaining"] = kv.count(C.CATALOG, {"perf_run": True})
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

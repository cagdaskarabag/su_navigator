"""Catalogue-wide values recomputed after every sync, offline import and reindex.

One scan of ``uc_catalog`` sets ``duplicate_spl`` (D-046) and ``provider_twin`` (D-066) and stores
the filter facets the catalogue view offers (D-047). Facet counts are computed here, never by the
list query.
"""

from typing import Any, Dict, List

from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso
from .quality import DERIVED_FLAGS, FLAG_ORDER, ordered
from .summary import SUMMARY_VERSION

FACETS_KEY = "catalog::facets"
# 2 adds global counts per domain, category, criticality and difficulty (D-059). 3 adds providers,
# waves, analytic stories, data sources and the number of summaries older than SUMMARY_VERSION (D-066).
# 4 adds data maturity (D-074).
FACETS_VERSION = 4
# Longest value list stored per facet (analytic stories and data sources): most frequent first.
MAX_FACET_VALUES = 600
_PAGE = 5000
_FIELDS = ["_key", "spl_hash", "quality_flags", "provider_status", "review_status", "frameworks",
           "regulation_labels", "domains", "category_key", "criticality", "difficulty", "provider", "wave",
           "data_maturity", "analytic_stories", "data_sources", "summary_version",
           "provider_version", "imported_at"]


def scan_catalog(store: DocumentStore) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    skip = 0
    while True:
        page = store.query(C.CATALOG, None, sort=[("_key", 1)], skip=skip, limit=_PAGE, fields=_FIELDS)
        rows.extend(page)
        if len(page) < _PAGE:
            return rows
        skip += _PAGE


def _active(row: Dict[str, Any]) -> bool:
    return row.get("provider_status") != "withdrawn"


def _refresh_duplicates(store: DocumentStore, rows: List[Dict[str, Any]]) -> Dict[str, int]:
    seen: Dict[str, int] = {}
    providers: Dict[str, set] = {}
    for row in rows:
        if row.get("spl_hash") and _active(row):
            seen[row["spl_hash"]] = seen.get(row["spl_hash"], 0) + 1
            providers.setdefault(row["spl_hash"], set()).add(row.get("provider") or "")

    def wanted(row: Dict[str, Any]) -> List[str]:
        digest = row.get("spl_hash") or ""
        if not digest or not _active(row):
            return []
        out = []
        if seen.get(digest, 0) > 1:
            out.append("duplicate_spl")
        if len(providers.get(digest, ())) > 1:
            out.append("provider_twin")
        return out

    def current(row: Dict[str, Any]) -> List[str]:
        return [f for f in DERIVED_FLAGS if f in (row.get("quality_flags") or [])]

    changed = [r["_key"] for r in rows if wanted(r) != current(r)]
    for start in range(0, len(changed), 500):
        docs = store.query(C.CATALOG, {"_key": {"$in": changed[start:start + 500]}})
        for doc in docs:
            flags = [f for f in doc.get("quality_flags") or [] if f not in DERIVED_FLAGS]
            doc["quality_flags"] = ordered(flags + wanted(doc))
        store.batch_save(C.CATALOG, docs)
    moved = set(changed)
    for row in rows:
        if row["_key"] in moved:
            flags = [f for f in row.get("quality_flags") or [] if f not in DERIVED_FLAGS]
            row["quality_flags"] = ordered(flags + wanted(row))
    return {"duplicate_groups": sum(1 for n in seen.values() if n > 1),
            "twin_groups": sum(1 for v in providers.values() if len(v) > 1), "updated": len(changed)}


def _top(counts: Dict[str, int]) -> List[Dict[str, Any]]:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower(), kv[0]))
    return [{"id": k, "count": n} for k, n in ranked[:MAX_FACET_VALUES]]


def compute_facets(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    review: Dict[str, int] = {}
    regulations: Dict[str, Dict[str, Any]] = {}
    quality = {f: 0 for f in FLAG_ORDER}
    domains: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    criticality: Dict[str, int] = {}
    difficulty: Dict[str, int] = {}
    providers: Dict[str, int] = {}
    waves: Dict[str, int] = {}
    maturities: Dict[str, int] = {}
    stories: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    info: Dict[str, Dict[str, Any]] = {}
    active = 0
    outdated = 0
    for row in rows:
        if not _active(row):
            continue
        active += 1
        if (row.get("summary_version") or 0) < SUMMARY_VERSION:
            outdated += 1
        if row.get("provider"):
            entry = info.setdefault(row["provider"], {"count": 0, "version": "", "updated": ""})
            entry["count"] += 1
            if (row.get("imported_at") or "") >= entry["updated"]:
                entry["updated"], entry["version"] = row.get("imported_at") or "", row.get("provider_version") or ""
        for field, counts in (("provider", providers), ("wave", waves), ("data_maturity", maturities)):
            if row.get(field):
                counts[row[field]] = counts.get(row[field], 0) + 1
        for field, counts in (("analytic_stories", stories), ("data_sources", sources)):
            for value in row.get(field) or []:
                counts[value] = counts.get(value, 0) + 1
        for d in row.get("domains") or []:
            domains[d] = domains.get(d, 0) + 1
        for field, counts in (("category_key", categories), ("criticality", criticality),
                              ("difficulty", difficulty)):
            if row.get(field):
                counts[row[field]] = counts.get(row[field], 0) + 1
        status = row.get("review_status") or "unknown"
        review[status] = review.get(status, 0) + 1
        labels = row.get("regulation_labels") or {}
        for fw in row.get("frameworks") or []:
            if fw.startswith("regulation:"):
                reg = fw[len("regulation:"):]
                entry = regulations.setdefault(reg, {"id": reg, "label": labels.get(reg) or reg, "count": 0})
                entry["count"] += 1
        for flag in row.get("quality_flags") or []:
            if flag in quality:
                quality[flag] += 1
    return {
        "facets_version": FACETS_VERSION,
        "active": active,
        "domains": domains,
        "categories": categories,
        "criticality": criticality,
        "difficulty": difficulty,
        "providers": providers,
        "waves": waves,
        "maturities": maturities,
        "provider_info": info,
        "analytic_stories": _top(stories),
        "data_sources": _top(sources),
        "analytic_stories_total": len(stories),
        "data_sources_total": len(sources),
        "summary": {"version": SUMMARY_VERSION, "outdated": outdated},
        "review_statuses": [{"id": k, "count": review[k]} for k in sorted(review)],
        "regulations": sorted(regulations.values(), key=lambda r: (r["label"].lower(), r["id"])),
        "quality_flags": [{"id": f, "count": quality[f]} for f in FLAG_ORDER],
    }


def refresh_derived(store: DocumentStore) -> Dict[str, int]:
    rows = scan_catalog(store)
    result = _refresh_duplicates(store, rows)
    facets = compute_facets(rows)
    facets.update({"_key": FACETS_KEY, "doc_type": "catalog_facets", "computed_at": utc_now_iso()})
    store.upsert(C.SYNC_STATE, facets)
    return result


def get_facets(store: DocumentStore) -> Dict[str, Any]:
    doc = store.get(C.SYNC_STATE, FACETS_KEY)
    if doc is None or (doc.get("facets_version") or 0) < FACETS_VERSION:
        doc = dict(compute_facets(scan_catalog(store)), computed_at=None)
    return {k: doc.get(k) for k in ("review_statuses", "regulations", "quality_flags", "domains", "categories",
                                    "criticality", "difficulty", "providers", "waves", "maturities", "provider_info", "analytic_stories",
                                    "data_sources", "analytic_stories_total", "data_sources_total", "summary",
                                    "active", "computed_at")}


def facets_outdated(store: DocumentStore) -> bool:
    doc = store.get(C.SYNC_STATE, FACETS_KEY)
    return doc is None or (doc.get("facets_version") or 0) < FACETS_VERSION

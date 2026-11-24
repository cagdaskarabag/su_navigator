"""Catalogue-wide values recomputed after every sync, offline import and reindex.

One scan of ``uc_catalog`` sets ``duplicate_spl`` (D-046) and stores the
filter facets the catalogue view offers (D-047).
"""

from typing import Any, Dict, List

from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso
from .quality import FLAG_ORDER, ordered

FACETS_KEY = "catalog::facets"
# 2 adds global counts per domain, category, criticality and difficulty (D-059).
FACETS_VERSION = 2
_PAGE = 5000
_FIELDS = ["_key", "spl_hash", "quality_flags", "provider_status", "review_status", "frameworks",
           "regulation_labels", "domains", "category_key", "criticality", "difficulty"]


def _scan(store: DocumentStore) -> List[Dict[str, Any]]:
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
    for row in rows:
        if row.get("spl_hash") and _active(row):
            seen[row["spl_hash"]] = seen.get(row["spl_hash"], 0) + 1

    def is_dup(row: Dict[str, Any]) -> bool:
        return seen.get(row.get("spl_hash") or "", 0) > 1 and _active(row)

    changed = [r["_key"] for r in rows if is_dup(r) != ("duplicate_spl" in (r.get("quality_flags") or []))]
    for start in range(0, len(changed), 500):
        docs = store.query(C.CATALOG, {"_key": {"$in": changed[start:start + 500]}})
        for doc in docs:
            flags = [f for f in doc.get("quality_flags") or [] if f != "duplicate_spl"]
            doc["quality_flags"] = ordered(flags + (["duplicate_spl"] if is_dup(doc) else []))
        store.batch_save(C.CATALOG, docs)
    for row in rows:
        if row["_key"] in changed:
            flags = [f for f in row.get("quality_flags") or [] if f != "duplicate_spl"]
            row["quality_flags"] = flags + (["duplicate_spl"] if is_dup(row) else [])
    return {"duplicate_groups": sum(1 for n in seen.values() if n > 1), "updated": len(changed)}


def compute_facets(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    review: Dict[str, int] = {}
    regulations: Dict[str, Dict[str, Any]] = {}
    quality = {f: 0 for f in FLAG_ORDER}
    domains: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    criticality: Dict[str, int] = {}
    difficulty: Dict[str, int] = {}
    active = 0
    for row in rows:
        if not _active(row):
            continue
        active += 1
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
        "review_statuses": [{"id": k, "count": review[k]} for k in sorted(review)],
        "regulations": sorted(regulations.values(), key=lambda r: (r["label"].lower(), r["id"])),
        "quality_flags": [{"id": f, "count": quality[f]} for f in FLAG_ORDER],
    }


def refresh_derived(store: DocumentStore) -> Dict[str, int]:
    rows = _scan(store)
    result = _refresh_duplicates(store, rows)
    facets = compute_facets(rows)
    facets.update({"_key": FACETS_KEY, "doc_type": "catalog_facets", "computed_at": utc_now_iso()})
    store.upsert(C.SYNC_STATE, facets)
    return result


def get_facets(store: DocumentStore) -> Dict[str, Any]:
    doc = store.get(C.SYNC_STATE, FACETS_KEY)
    if doc is None or (doc.get("facets_version") or 0) < FACETS_VERSION:
        doc = dict(compute_facets(_scan(store)), computed_at=None)
    return {k: doc.get(k) for k in ("review_statuses", "regulations", "quality_flags", "domains", "categories",
                                    "criticality", "difficulty", "active", "computed_at")}


def facets_outdated(store: DocumentStore) -> bool:
    doc = store.get(C.SYNC_STATE, FACETS_KEY)
    return doc is None or (doc.get("facets_version") or 0) < FACETS_VERSION

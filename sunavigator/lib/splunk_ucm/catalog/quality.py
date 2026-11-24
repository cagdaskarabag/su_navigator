"""Content quality signals shown as badges and usable as catalogue filters (D-046).

Per-record flags are derived by the normalizer. ``duplicate_spl`` needs the
whole catalogue, so :func:`refresh_duplicate_flags` recomputes it after every
sync and reindex.
"""

import hashlib
import re
from typing import Any, Dict, List

from ..storage import collections as C
from ..storage.kvstore import DocumentStore

QUALITY_FLAGS = {
    "unreviewed": "No review status, or draft",
    "reviewer_na": "Reviewer recorded as N/A",
    "ai_reviewed": "Reviewer is an automated or AI agent",
    "sme_review_pending": "Compliance mapping awaits SME review",
    "unbounded_index": "Primary SPL searches index=* or no index",
    "es_required": "Requires Splunk Enterprise Security",
    "duplicate_spl": "Primary SPL is identical to another use case",
}
FLAG_ORDER = tuple(QUALITY_FLAGS)
_PAGE = 5000


def spl_hash(spl: str) -> str:
    text = re.sub(r"\s+", " ", spl or "").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def ordered(flags) -> List[str]:
    present = set(flags)
    return [f for f in FLAG_ORDER if f in present]


def refresh_duplicate_flags(store: DocumentStore) -> Dict[str, int]:
    """Set ``duplicate_spl`` on active summaries whose ``spl_hash`` is shared."""
    rows: List[Dict[str, Any]] = []
    skip = 0
    while True:
        page = store.query(C.CATALOG, None, sort=[("_key", 1)], skip=skip, limit=_PAGE,
                           fields=["_key", "spl_hash", "quality_flags", "provider_status"])
        rows.extend(page)
        if len(page) < _PAGE:
            break
        skip += _PAGE
    seen: Dict[str, int] = {}
    for row in rows:
        if row.get("spl_hash") and row.get("provider_status") != "withdrawn":
            seen[row["spl_hash"]] = seen.get(row["spl_hash"], 0) + 1
    changed = []
    for row in rows:
        dup = seen.get(row.get("spl_hash") or "", 0) > 1 and row.get("provider_status") != "withdrawn"
        if dup != ("duplicate_spl" in (row.get("quality_flags") or [])):
            changed.append(row["_key"])
    for start in range(0, len(changed), 500):
        keys = changed[start:start + 500]
        docs = store.query(C.CATALOG, {"_key": {"$in": keys}})
        for doc in docs:
            flags = [f for f in doc.get("quality_flags") or [] if f != "duplicate_spl"]
            if seen.get(doc.get("spl_hash") or "", 0) > 1 and doc.get("provider_status") != "withdrawn":
                flags.append("duplicate_spl")
            doc["quality_flags"] = ordered(flags)
        store.batch_save(C.CATALOG, docs)
    return {"duplicate_groups": sum(1 for n in seen.values() if n > 1), "updated": len(changed)}

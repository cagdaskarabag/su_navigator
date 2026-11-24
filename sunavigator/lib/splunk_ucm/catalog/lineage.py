"""Cross-provider lineage: which other providers carry the same primary SPL (D-066).

A twin is an active use case of another provider whose whitespace-normalised primary SPL hashes to
the same value (``spl_hash``). The hash proves the search text is identical. It says nothing about
whether metadata, schedule, severity or compliance mappings agree, so the labels below describe the
role each provider plays in the catalogue, not a comparison of the two records.
"""

from typing import Any, Dict, List

from ..storage import collections as C
from ..storage.kvstore import DocumentStore

# Role of a provider's content when the same search exists in more than one provider. This is a
# product rule kept as data: add a provider here to give it a role.
AUTHORITY: Dict[str, Dict[str, str]] = {
    "escu": {"role": "detection", "label": "Detection content source",
             "note": "ESCU is the source for detection content (search, schedule, severity)."},
    "fenre": {"role": "compliance", "label": "Compliance and mapping context",
              "note": "Fenre is used for compliance, regulation and implementation context."},
}
NO_AUTHORITY = {"role": "", "label": "", "note": ""}
MAX_TWINS = 20
_TWIN_FIELDS = ["_key", "content_id", "provider", "record_id", "title", "category_name", "criticality",
                "review_status"]


def authority(provider: str) -> Dict[str, str]:
    return dict(AUTHORITY.get(provider, NO_AUTHORITY))


def find_twins(store: DocumentStore, spl_hash: str, provider: str, content_id: str) -> List[Dict[str, Any]]:
    """Active use cases of other providers with the same SPL hash, ordered by provider and id."""
    if not spl_hash:
        return []
    rows = store.query(C.CATALOG, {"$and": [{"spl_hash": spl_hash}, {"provider_status": "active"},
                                            {"provider": {"$ne": provider}}]},
                       sort=[("provider", 1), ("sort_key", 1)], limit=MAX_TWINS, fields=_TWIN_FIELDS)
    return [dict(_public(r), authority=authority(r.get("provider", "")))
            for r in rows if r.get("content_id") != content_id]


def _public(row: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: row.get(k) for k in _TWIN_FIELDS if k != "_key"}
    out["key"] = row.get("_key")
    return out

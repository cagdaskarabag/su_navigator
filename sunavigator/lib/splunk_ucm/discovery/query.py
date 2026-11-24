"""Server-side inventory listing over ``uc_environment_sources``."""

import dataclasses
import re
from typing import Any, Dict, List, Optional, Sequence

from ..errors import ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from .apps import app_candidates

KINDS = ("index", "pair", "app", "datamodel", "macro", "lookup", "eventtype")
STATUSES = ("active", "missing")
SORTS = {
    "name": [("sort_key", 1)],
    "count": [("window_count", -1), ("sort_key", 1)],
    "age": [("age_seconds", -1), ("sort_key", 1)],
    "index": [("index", 1), ("sort_key", 1)],
}
_TOKEN = re.compile(r"^[^\x00-\x1f]{1,200}$")
_INDEX = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$")


@dataclasses.dataclass
class InventoryFilter:
    kind: str = "pair"
    status: str = "active"
    q: str = ""
    index: str = ""
    sourcetype: str = ""
    stale_hours: int = 0
    sort: str = "count"
    offset: int = 0
    count: int = 25
    with_total: bool = True


def build_query(f: InventoryFilter) -> Dict[str, Any]:
    clauses: List[Dict[str, Any]] = []
    if f.kind:
        if f.kind not in KINDS:
            raise ValidationError("invalid kind", {"allowed": list(KINDS)})
        clauses.append({"kind": f.kind})
    if f.status and f.status != "any":
        if f.status not in STATUSES:
            raise ValidationError("invalid status")
        clauses.append({"status": f.status})
    if f.index:
        if not _INDEX.match(f.index):
            raise ValidationError("invalid index")
        clauses.append({"index": f.index})
    if f.sourcetype:
        if not _TOKEN.match(f.sourcetype) or len(f.sourcetype) > 100:
            raise ValidationError("invalid sourcetype")
        clauses.append({"sourcetype": f.sourcetype})
    if f.stale_hours:
        if not 1 <= f.stale_hours <= 24 * 365:
            raise ValidationError("stale_hours out of range")
        clauses.append({"age_seconds": {"$gte": f.stale_hours * 3600}})
    if f.q:
        if not _TOKEN.match(f.q):
            raise ValidationError("invalid search text")
        for term in [t for t in f.q.lower().split() if t][:6]:
            clauses.append({"search_text": {"$regex": re.escape(term)}})
    if not clauses:
        return {}
    return clauses[0] if len(clauses) == 1 else {"$and": clauses}


class InventoryQueryService:
    def __init__(self, store: DocumentStore, max_page_size: int = 100, max_offset: int = 50000):
        self.store = store
        self.max_page_size = max_page_size
        self.max_offset = max_offset

    def search(self, f: InventoryFilter) -> Dict[str, Any]:
        if f.sort not in SORTS:
            raise ValidationError("invalid sort", {"allowed": sorted(SORTS)})
        if not 0 <= f.offset <= self.max_offset:
            raise ValidationError("offset out of range")
        count = max(1, min(self.max_page_size, f.count))
        query = build_query(f)
        rows = self.store.query(C.ENVIRONMENT_SOURCES, query or None, sort=SORTS[f.sort],
                                skip=f.offset, limit=count + 1)
        has_more = len(rows) > count
        total: Optional[int] = None
        if f.with_total:
            total = self.store.count(C.ENVIRONMENT_SOURCES, query or None)
        return {"items": rows[:count], "offset": f.offset, "count": count, "has_more": has_more,
                "total": total, "sort": f.sort}


def coverage(store: DocumentStore) -> Dict[str, Any]:
    """Compare catalogue requirement values against discovered environment sources."""
    catalog = store.query(C.CATALOG, {"provider_status": "active"},
                          fields=["sourcetypes", "indexes", "datamodels", "addons", "addon_ids"])
    wanted = {"sourcetype": set(), "index": set(), "datamodel": set(), "addon": set()}
    addon_ids: Dict[str, int] = {}
    for row in catalog:
        wanted["sourcetype"].update(row.get("sourcetypes") or [])
        wanted["index"].update(row.get("indexes") or [])
        wanted["datamodel"].update(row.get("datamodels") or [])
        wanted["addon"].update(row.get("addons") or [])
        for name, sb in row.get("addon_ids") or []:
            addon_ids.setdefault(name, sb)
    present = {
        "sourcetype": {r.get("sourcetype") for r in store.query(
            C.ENVIRONMENT_SOURCES, {"kind": "pair", "status": "active"}, fields=["sourcetype"])
            if r.get("sourcetype")},
        "index": {r.get("name") for r in store.query(
            C.ENVIRONMENT_SOURCES, {"kind": "index", "status": "active"}, fields=["name"])
            if r.get("name")},
        "datamodel": {r.get("name") for r in store.query(
            C.ENVIRONMENT_SOURCES, {"kind": "datamodel", "status": "active"}, fields=["name"])
            if r.get("name")},
        "addon": set(),
    }
    installed = set()
    for r in store.query(C.ENVIRONMENT_SOURCES, {"kind": "app", "status": "active"},
                         fields=["name", "label", "package_id"]):
        installed.update(str(r.get(f) or "").lower() for f in ("name", "label", "package_id"))
    installed.discard("")
    for name in wanted["addon"]:
        req = {"value": name, "attributes": {"splunkbase_id": addon_ids.get(name)}}
        if any(candidate.lower() in installed for candidate, _ in app_candidates(req)):
            present["addon"].add(name)
    out: Dict[str, Any] = {}
    for kind, values in wanted.items():
        found = sorted(v for v in values if v in present[kind])
        missing = sorted(v for v in values if v not in present[kind])
        out[kind] = {"wanted": len(values), "found": len(found), "missing": len(missing),
                     "missing_values": missing[:50]}
    return out

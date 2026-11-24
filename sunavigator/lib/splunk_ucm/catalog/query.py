"""Server-side catalogue filtering and paging over ``uc_catalog``.

All user input is validated against allowlists or escaped before it becomes a
KV Store query. The browser never receives more than one page.
"""

import dataclasses
import re
from typing import Any, Dict, List, Optional, Sequence

from ..errors import ValidationError
from ..model.canonical import CRITICALITY_RANK, DIFFICULTIES, DOMAINS
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from .quality import QUALITY_FLAGS
from .summary import STATUS_ACTIVE, STATUS_WITHDRAWN

LIST_FIELDS = (
    "_key", "content_id", "record_id", "title", "summary", "domains", "category_key", "category_name",
    "subcategory", "criticality", "difficulty", "monitoring_types", "sourcetypes", "datamodels",
    "mitre_ids", "provider", "provider_status", "provider_version", "review_status", "has_spl",
    "imported_at", "quality_flags",
)
SORTS = {
    "id": [("sort_key", 1)],
    "title": [("title", 1), ("sort_key", 1)],
    "criticality": [("criticality_rank", -1), ("sort_key", 1)],
    "imported": [("imported_at", -1), ("sort_key", 1)],
}
_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_TOKEN_RE = re.compile(r"^[^\x00-\x1f]{1,200}$")
_MITRE_RE = re.compile(r"^(T\d{4}(\.\d{3})?|TA\d{4})$")
MAX_TERMS = 6


@dataclasses.dataclass
class CatalogFilter:
    q: str = ""
    domains: Sequence[str] = ()
    category_keys: Sequence[str] = ()
    criticality: Sequence[str] = ()
    difficulty: Sequence[str] = ()
    sourcetype: str = ""
    mitre: str = ""
    quality: Sequence[str] = ()
    provider_status: str = STATUS_ACTIVE
    sort: str = "id"
    offset: int = 0
    count: int = 25
    with_total: bool = True


def _check_all(values: Sequence[str], allowed: Sequence[str], name: str) -> List[str]:
    out = []
    for v in values:
        if v not in allowed:
            raise ValidationError("invalid %s" % name, {"value": v[:50]})
        out.append(v)
    return out


def build_query(f: CatalogFilter) -> Dict[str, Any]:
    clauses: List[Dict[str, Any]] = []
    if f.provider_status not in ("", "any"):
        _check_all([f.provider_status], (STATUS_ACTIVE, STATUS_WITHDRAWN), "provider_status")
        clauses.append({"provider_status": f.provider_status})
    if f.domains:
        clauses.append({"domains": {"$in": _check_all(f.domains, DOMAINS, "domain")}})
    if f.category_keys:
        for key in f.category_keys:
            if not _KEY_RE.match(key):
                raise ValidationError("invalid category")
        clauses.append({"category_key": {"$in": list(f.category_keys)}})
    if f.criticality:
        clauses.append({"criticality": {"$in": _check_all(f.criticality, list(CRITICALITY_RANK), "criticality")}})
    if f.difficulty:
        clauses.append({"difficulty": {"$in": _check_all(f.difficulty, DIFFICULTIES, "difficulty")}})
    if f.sourcetype:
        if not _TOKEN_RE.match(f.sourcetype):
            raise ValidationError("invalid sourcetype")
        clauses.append({"sourcetypes": f.sourcetype})
    if f.mitre:
        if not _MITRE_RE.match(f.mitre):
            raise ValidationError("invalid MITRE id")
        clauses.append({"mitre_ids": f.mitre})
    if f.quality:
        clauses.append({"quality_flags": {"$in": _check_all(f.quality, list(QUALITY_FLAGS), "quality flag")}})
    if f.q:
        if not _TOKEN_RE.match(f.q):
            raise ValidationError("invalid search text")
        terms = [t for t in f.q.lower().split() if t][:MAX_TERMS]
        for term in terms:
            clauses.append({"search_text": {"$regex": re.escape(term)}})
    if not clauses:
        return {}
    return clauses[0] if len(clauses) == 1 else {"$and": clauses}


class CatalogQueryService:
    def __init__(self, store: DocumentStore, max_page_size: int = 100, max_offset: int = 50000):
        self.store = store
        self.max_page_size = max_page_size
        self.max_offset = max_offset

    def search(self, f: CatalogFilter) -> Dict[str, Any]:
        if f.sort not in SORTS:
            raise ValidationError("invalid sort", {"allowed": sorted(SORTS)})
        if not 0 <= f.offset <= self.max_offset:
            raise ValidationError("offset out of range")
        count = max(1, min(self.max_page_size, f.count))
        query = build_query(f)
        rows = self.store.query(C.CATALOG, query or None, sort=SORTS[f.sort], skip=f.offset,
                                limit=count + 1, fields=LIST_FIELDS)
        has_more = len(rows) > count
        total: Optional[int] = None
        if f.with_total:
            total = self.store.count(C.CATALOG, query or None)
        return {"items": rows[:count], "offset": f.offset, "count": count, "has_more": has_more,
                "total": total, "sort": f.sort}

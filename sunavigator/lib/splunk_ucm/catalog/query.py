"""Server-side catalogue filtering and paging over ``uc_catalog``.

All user input is validated against allowlists or escaped before it becomes a
KV Store query. The browser never receives more than one page.
"""

import dataclasses
import re
from typing import Any, Dict, List, Optional, Sequence, Set

from ..errors import ValidationError
from ..model.canonical import CRITICALITY_RANK, DIFFICULTIES, DOMAINS
from ..readiness.scoring import STATES as READINESS_STATES
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
_FACET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
MAX_TERMS = 6
MAX_FACET_VALUES = 50
WAVES = ("crawl", "walk", "run")
NOT_ASSESSED = "not_assessed"
AVAILABILITY = tuple(READINESS_STATES) + (NOT_ASSESSED,)
# Largest key list sent to the KV Store as ``_key $in``. Measured on Splunk 10.2.9: 8000 keys of 44
# characters (a 432 KB request line) still work and 10000 are refused with HTTP 414, so 2000 keeps
# a 4x margin. Larger key sets use the scan path below.
DEFAULT_MAX_JOIN_KEYS = 2000
# Most catalogue keys the scan path reads. One below the KV Store ``max_rows_per_query`` default of
# 50000, because the scan asks for one extra row to notice that the limit was exceeded.
DEFAULT_MAX_SCAN = 49999
# ``limits.conf [kvstore] max_rows_per_query``. A count or scan that returns this many rows may have been cut off.
DEFAULT_KV_ROW_LIMIT = 50000


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
    review: Sequence[str] = ()
    regulation: Any = ()
    providers: Sequence[str] = ()
    waves: Sequence[str] = ()
    stories: Sequence[str] = ()
    data_sources: Sequence[str] = ()
    exclude_quality: Sequence[str] = ()
    availability: Sequence[str] = ()
    bookmarked: bool = False
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
    if f.review:
        for value in f.review:
            if not _FACET_RE.match(value):
                raise ValidationError("invalid review status", {"value": value[:50]})
        clauses.append({"review_status": {"$in": list(f.review)}})
    regulations = [f.regulation] if isinstance(f.regulation, str) and f.regulation else list(f.regulation or ())
    if regulations:
        for value in regulations:
            if not _FACET_RE.match(value):
                raise ValidationError("invalid regulation")
        clauses.append({"frameworks": {"$in": ["regulation:" + v for v in regulations]}})
    if f.quality:
        clauses.append({"quality_flags": {"$in": _check_all(f.quality, list(QUALITY_FLAGS), "quality flag")}})
    for flag in _check_all(f.exclude_quality, list(QUALITY_FLAGS), "quality flag"):
        clauses.append({"quality_flags": {"$ne": flag}})
    if f.providers:
        for value in f.providers:
            if not _FACET_RE.match(value):
                raise ValidationError("invalid provider", {"value": value[:50]})
        clauses.append({"provider": {"$in": list(f.providers)}})
    if f.waves:
        clauses.append({"wave": {"$in": _check_all(f.waves, WAVES, "wave")}})
    for field, values, name in (("analytic_stories", f.stories, "analytic story"),
                                ("data_sources", f.data_sources, "data source")):
        if values:
            if len(values) > MAX_FACET_VALUES:
                raise ValidationError("too many %s values" % name, {"limit": MAX_FACET_VALUES})
            for value in values:
                if not _TOKEN_RE.match(value):
                    raise ValidationError("invalid %s" % name)
            clauses.append({field: {"$in": list(values)}})
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
    def __init__(self, store: DocumentStore, max_page_size: int = 100, max_offset: int = 50000,
                 max_join_keys: int = DEFAULT_MAX_JOIN_KEYS, max_scan: int = DEFAULT_MAX_SCAN,
                 kv_row_limit: int = DEFAULT_KV_ROW_LIMIT):
        self.store = store
        self.max_page_size = max_page_size
        self.max_offset = max_offset
        self.max_join_keys = max_join_keys
        self.max_scan = max_scan
        self.kv_row_limit = kv_row_limit

    def search(self, f: CatalogFilter, user: str = "") -> Dict[str, Any]:
        if f.sort not in SORTS:
            raise ValidationError("invalid sort", {"allowed": sorted(SORTS)})
        if not 0 <= f.offset <= self.max_offset:
            raise ValidationError("offset out of range")
        count = max(1, min(self.max_page_size, f.count))
        query = build_query(f)
        allowed = self._allowed_keys(f, user, query)
        if allowed is not None and not allowed:
            return self._page([], f, count, 0)
        if allowed is not None and len(allowed) > self.max_join_keys:
            return self._scan_page(query, f, count, allowed)
        if allowed is not None:
            key_clause = {"_key": {"$in": sorted(allowed)}}
            query = {"$and": [query, key_clause]} if query else key_clause
        rows = self.store.query(C.CATALOG, query or None, sort=SORTS[f.sort], skip=f.offset,
                                limit=count + 1, fields=LIST_FIELDS)
        total: Optional[int] = None
        if f.with_total:
            total = self.store.count(C.CATALOG, query or None)
        return self._page(rows, f, count, total, total is not None and total >= self.kv_row_limit)

    @staticmethod
    def _page(rows: List[Dict[str, Any]], f: CatalogFilter, count: int, total: Optional[int],
              capped: bool = False) -> Dict[str, Any]:
        """``total_capped``: the KV Store returns at most ``max_rows_per_query`` rows, so a total at that
        number is a lower bound, not a count."""
        return {"items": rows[:count], "offset": f.offset, "count": count, "has_more": len(rows) > count,
                "next_offset": f.offset + count if len(rows) > count else None,
                "total": total if f.with_total else None, "total_capped": bool(capped and f.with_total),
                "sort": f.sort}

    def _allowed_keys(self, f: CatalogFilter, user: str, base_query: Dict[str, Any]) -> Optional[Set[str]]:
        """Catalogue keys the readiness and bookmark filters allow, or None when neither is set.

        Both sets come from other collections (``uc_readiness``, the caller's own rows in
        ``uc_selections``), so they are joined here by key rather than stored in ``uc_catalog``.
        """
        allowed: Optional[Set[str]] = None
        if f.availability:
            allowed = self._availability_keys(_check_all(f.availability, AVAILABILITY, "availability"), base_query)
        if f.bookmarked:
            if not user:
                raise ValidationError("bookmarks need a signed-in user")
            rows = self._bounded(C.SELECTIONS, {"$and": [{"user": user}, {"intent": "bookmark"}]}, ["catalog_key"])
            marked = {r["catalog_key"] for r in rows if r.get("catalog_key")}
            allowed = marked if allowed is None else allowed & marked
        return allowed

    def _bounded(self, collection: str, query: Optional[Dict[str, Any]], fields: Sequence[str]) -> List[Dict[str, Any]]:
        rows = self.store.query(collection, query, fields=list(fields), limit=self.max_scan + 1)
        if len(rows) > self.max_scan:
            raise ValidationError("too many rows for this filter; narrow the other filters first",
                                  {"limit": self.max_scan})
        return rows

    def _availability_keys(self, values: Sequence[str], base_query: Dict[str, Any]) -> Set[str]:
        states = [v for v in values if v != NOT_ASSESSED]
        keys: Set[str] = set()
        if states:
            keys.update(r["_key"] for r in self._bounded(C.READINESS, {"state": {"$in": states}}, ["_key"]))
        if NOT_ASSESSED in values:
            assessed = {r["_key"] for r in self._bounded(C.READINESS, None, ["_key"])}
            # Only the use cases the other filters already select (by default the active ones): withdrawn
            # entries have no readiness result and would otherwise all count as not assessed.
            every = self.store.query(C.CATALOG, base_query or None, fields=["_key"], limit=self.max_scan + 1)
            if len(every) > self.max_scan:
                raise ValidationError("too many use cases for this filter; narrow the other filters first",
                                      {"limit": self.max_scan})
            keys.update(r["_key"] for r in every if r["_key"] not in assessed)
        return keys

    def _scan_page(self, query: Dict[str, Any], f: CatalogFilter, count: int, allowed: Set[str]) -> Dict[str, Any]:
        """Key set too long for one request: order and filter keys here, then fetch only the page."""
        ordered = self.store.query(C.CATALOG, query or None, sort=SORTS[f.sort], fields=["_key"],
                                   limit=self.max_scan + 1)
        if len(ordered) > self.max_scan:
            raise ValidationError("too many use cases for this filter; narrow the other filters first",
                                  {"limit": self.max_scan})
        matching = [r["_key"] for r in ordered if r["_key"] in allowed]
        page_keys = matching[f.offset:f.offset + count + 1]
        by_key = {r["_key"]: r for r in self.store.query(C.CATALOG, {"_key": {"$in": page_keys}},
                                                         fields=LIST_FIELDS)} if page_keys else {}
        rows = [by_key[k] for k in page_keys if k in by_key]
        return self._page(rows, f, count, len(matching))

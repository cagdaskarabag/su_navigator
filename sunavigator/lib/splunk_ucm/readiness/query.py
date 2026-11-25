"""Server-side readiness listing and summary over ``uc_readiness``."""

import dataclasses
import re
from typing import Any, Dict, List, Optional, Sequence

from ..errors import ValidationError
from ..model.canonical import CRITICALITY_RANK, DOMAINS
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from .scoring import STATES

LIST_FIELDS = ("_key", "content_id", "record_id", "title", "category_key", "category_name", "domains",
               "criticality", "state", "score", "coverage", "blockers", "gaps", "counts", "unverified",
               "requirement_count", "evaluated_at", "discovery_at", "engine_version", "source_hash")
SORTS = {
    "score": [("score_sort", -1), ("criticality_rank", -1), ("_key", 1)],
    "score_asc": [("score_sort", 1), ("criticality_rank", -1), ("_key", 1)],
    "criticality": [("criticality_rank", -1), ("score_sort", -1), ("_key", 1)],
    "title": [("title", 1), ("_key", 1)],
}
_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_TOKEN_RE = re.compile(r"^[^\x00-\x1f]{1,200}$")


@dataclasses.dataclass
class ReadinessFilter:
    states: Sequence[str] = ()
    domains: Sequence[str] = ()
    criticality: Sequence[str] = ()
    category_keys: Sequence[str] = ()
    q: str = ""
    sort: str = "score"
    offset: int = 0
    count: int = 25
    with_total: bool = True


def _in(field: str, values: Sequence[str]) -> Dict[str, Any]:
    if len(values) == 1:
        return {field: values[0]}
    return {"$or": [{field: v} for v in values]}


def build_query(f: ReadinessFilter) -> Dict[str, Any]:
    clauses: List[Dict[str, Any]] = []
    for value in f.states:
        if value not in STATES:
            raise ValidationError("invalid state", {"allowed": list(STATES)})
    if f.states:
        clauses.append(_in("state", list(f.states)))
    for value in f.domains:
        if value not in DOMAINS:
            raise ValidationError("invalid domain")
    if f.domains:
        clauses.append(_in("domains", list(f.domains)))
    for value in f.criticality:
        if value not in CRITICALITY_RANK:
            raise ValidationError("invalid criticality")
    if f.criticality:
        clauses.append(_in("criticality", list(f.criticality)))
    for value in f.category_keys:
        if not _KEY_RE.match(value):
            raise ValidationError("invalid category")
    if f.category_keys:
        clauses.append(_in("category_key", list(f.category_keys)))
    if f.q:
        if not _TOKEN_RE.match(f.q):
            raise ValidationError("invalid search text")
        for term in [t for t in f.q.lower().split() if t][:6]:
            clauses.append({"search_text": {"$regex": re.escape(term)}})
    if not clauses:
        return {}
    return clauses[0] if len(clauses) == 1 else {"$and": clauses}


class ReadinessQueryService:
    def __init__(self, store: DocumentStore, max_page_size: int = 100, max_offset: int = 50000):
        self.store = store
        self.max_page_size = max_page_size
        self.max_offset = max_offset

    def search(self, f: ReadinessFilter) -> Dict[str, Any]:
        if f.sort not in SORTS:
            raise ValidationError("invalid sort", {"allowed": sorted(SORTS)})
        if not 0 <= f.offset <= self.max_offset:
            raise ValidationError("offset out of range")
        count = max(1, min(self.max_page_size, f.count))
        query = build_query(f)
        rows = self.store.query(C.READINESS, query or None, sort=SORTS[f.sort], skip=f.offset,
                                limit=count + 1, fields=list(LIST_FIELDS))
        total: Optional[int] = self.store.count(C.READINESS, query or None) if f.with_total else None
        return {"items": rows[:count], "offset": f.offset, "count": count, "has_more": len(rows) > count,
                "next_offset": f.offset + count if len(rows) > count else None,
                "total": total, "sort": f.sort}

    def summary(self) -> Dict[str, Any]:
        by_state = {s: self.store.count(C.READINESS, {"state": s}) for s in STATES}
        blockers: Dict[str, int] = {}
        gaps: Dict[str, int] = {}
        for row in self.store.query(C.READINESS, {"$or": [{"state": "blocked"}, {"state": "not_ready"},
                                                          {"state": "partially_ready"}]},
                                    fields=["blockers", "gaps"]):
            for b in row.get("blockers") or []:
                k = "%s:%s" % (b.get("type"), b.get("value"))
                blockers[k] = blockers.get(k, 0) + 1
            for g in row.get("gaps") or []:
                k = "%s:%s" % (g.get("type"), g.get("value"))
                gaps[k] = gaps.get(k, 0) + 1
        top_gaps = sorted(gaps.items(), key=lambda kv: (-kv[1], kv[0]))[:15]
        top_blockers = sorted(blockers.items(), key=lambda kv: (-kv[1], kv[0]))[:15]
        return {"by_state": by_state, "total": sum(by_state.values()),
                "top_gaps": [{"requirement": k, "use_cases": v} for k, v in top_gaps],
                "top_blockers": [{"requirement": k, "use_cases": v} for k, v in top_blockers]}

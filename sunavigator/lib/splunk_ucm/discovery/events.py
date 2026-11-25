"""Event-level data checks: does this sourcetype carry events of the type a detection reads? (D-073, F-10)

Some data sources are one sourcetype with many event types, told apart by one field (AWS CloudTrail's
``eventName``, Windows' ``EventCode``). A detection for ``DescribeImageScanFindings`` is not ready because
``aws:cloudtrail`` exists if that event type never occurs. For each distinct (sourcetype, field, value) the
active catalogue names, discovery runs one bounded search against the busiest index of that sourcetype:

    search index=I sourcetype="S" "VALUE" FIELD="VALUE" earliest=-30d latest=now | head 100 | stats count

The quoted free-text term lets Splunk's index narrow the events before the field is evaluated, so an event
type that never occurs is answered quickly. Only the count (0 to 100) is stored; no event value is read.
A missing event type is not an error: rare events are normal, and readiness says so.
"""

import dataclasses
import hashlib
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..errors import UcmError, ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso
from .spl import validate_index_name

FIELD = re.compile(r"^[A-Za-z_][\w.\-]{0,99}$")
VALUE = re.compile(r"^[A-Za-z0-9_.:\-/ ]{1,100}$")
SOURCETYPE = re.compile(r"^[A-Za-z0-9_:.\-/]{1,200}$")
MAX_HITS = 100


@dataclasses.dataclass
class EventCheckSettings:
    enabled: bool = True
    max_checks: int = 100
    timeout_seconds: int = 30
    budget_seconds: int = 300


def event_key(sourcetype: str, field: str, value: str) -> str:
    return "ev_" + hashlib.sha256(("%s|%s|%s" % (sourcetype.lower(), field.lower(), value.lower())).encode("utf-8")).hexdigest()[:40]


def event_spl(index: str, sourcetype: str, field: str, value: str, days: int) -> str:
    validate_index_name(index)
    if not SOURCETYPE.match(sourcetype or ""):
        raise ValidationError("invalid sourcetype", {"value": str(sourcetype)[:80]})
    if not FIELD.match(field or ""):
        raise ValidationError("invalid field name", {"value": str(field)[:80]})
    if not VALUE.match(value or ""):
        raise ValidationError("invalid event value", {"value": str(value)[:80]})
    days = max(1, min(365, int(days)))
    return ('| search index=%s sourcetype="%s" "%s" %s="%s" earliest=-%dd latest=now | head %d | stats count as sun_hits'
            % (index, sourcetype, value, field, value, days, MAX_HITS))


def targets(store: DocumentStore, categories: Any, limit: int,
            present: Optional[Set[str]] = None) -> List[Tuple[Tuple[str, str, str], int]]:
    """Distinct (sourcetype, field, value) the active catalogue reads, most used first.

    ``present`` (lower-case sourcetypes seen by discovery) is applied before ``limit``: an event type of a sourcetype
    that is not in this environment cannot be checked and must not use up the limit."""
    from ..content.reindex import StoredNormalizer
    from ..storage.repositories import ContentRepository

    active = {r["_key"] for r in store.query(C.CATALOG, {"provider_status": "active"}, fields=["_key"], limit=50000)}
    normalizer = StoredNormalizer(categories)
    uses: Dict[Tuple[str, str, str], int] = {}
    for stored in ContentRepository(store).iter_content():
        if stored.get("_key") not in active:
            continue
        uc = normalizer.normalize(stored)
        if uc is None:
            continue
        for r in uc.requirements:
            if r.type != "event_condition":
                continue
            a = r.attributes or {}
            triple = (str(a.get("sourcetype") or ""), str(a.get("field") or ""), str(a.get("value") or ""))
            if SOURCETYPE.match(triple[0]) and FIELD.match(triple[1]) and VALUE.match(triple[2]):
                if present is not None and triple[0].lower() not in present:
                    continue
                uses[triple] = uses.get(triple, 0) + 1
    ordered = sorted(uses.items(), key=lambda kv: (-kv[1], kv[0]))
    return ordered[: max(0, limit)]


def run_event_checks(store: DocumentStore, search: Any, categories: Any, settings: EventCheckSettings, job_id: str,
                     days: int, clock: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
    """Run the bounded checks and store counts. Never raises for a bounded failure."""
    summary: Dict[str, Any] = {"enabled": settings.enabled, "checked": 0, "seen": 0, "not_seen": 0, "skipped": 0,
                               "errors": 0, "budget_exhausted": False, "window_days": days}
    if not settings.enabled:
        return summary
    started = clock()
    stored: List[Dict[str, Any]] = []
    busiest: Dict[str, Dict[str, Any]] = {}
    for pair in store.query(C.ENVIRONMENT_SOURCES, {"kind": "pair", "status": "active"},
                            fields=["index", "sourcetype", "window_count"], limit=50000):
        key = str(pair.get("sourcetype") or "").lower()
        if key and int(pair.get("window_count") or 0) >= int((busiest.get(key) or {}).get("window_count") or -1):
            busiest[key] = pair
    for (sourcetype, field, value), _uses in targets(store, categories, settings.max_checks, set(busiest)):
        if clock() - started > settings.budget_seconds:
            summary["budget_exhausted"] = True
            summary["skipped"] += 1
            continue
        index = (busiest.get(sourcetype.lower()) or {}).get("index") or ""
        if not index:
            summary["skipped"] += 1
            continue
        try:
            result = search.oneshot(event_spl(index, sourcetype, field, value, days),
                                    timeout=float(settings.timeout_seconds), max_count=1)
        except (UcmError, ValidationError):
            summary["errors"] += 1
            continue
        if not result.rows:
            summary["errors"] += 1
            continue
        try:
            hits = max(0, min(MAX_HITS, int(float(result.rows[0].get("sun_hits") or 0))))
        except (TypeError, ValueError):
            summary["errors"] += 1
            continue
        stored.append({"_key": event_key(sourcetype, field, value), "doc_schema": C.DOC_SCHEMA, "index": index,
                       "sourcetype": sourcetype, "field": field, "value": value, "count": hits,
                       "window_days": days, "evaluated_at": utc_now_iso(), "job_id": job_id})
        summary["checked"] += 1
        summary["seen" if hits else "not_seen"] += 1
    if stored:
        store.batch_save(C.EVENT_CHECK, stored)
    return summary

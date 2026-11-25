"""Field fill and placeholder rates for the fields active use cases read (D-070, research finding F-07).

Discovery picks one index per sourcetype (the one with the most events in the discovery window),
takes the newest ``sample_events`` events in the last 24 hours and counts, per field, the events
where the field is present and non-blank, and the events where it holds a placeholder value
(``-``, ``N/A``, ``0.0.0.0``, ... as configured). Only rates and the sample size are stored; no
raw value leaves the search.

Bounds: sourcetypes (most used first), fields per search, sample events, time per search and a
total time budget. Anything beyond a bound is not profiled and says so in the totals.
"""

import dataclasses
import hashlib
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..errors import UcmError, ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso
from .spl import validate_index_name

FIELD = re.compile(r"^[A-Za-z_][\w.\-]{0,99}$")
SOURCETYPE = re.compile(r"^[A-Za-z0-9_:.\-/]{1,200}$")
PLACEHOLDER = re.compile(r"^[^\"\\\x00-\x1f]{1,40}$")
DEFAULT_PLACEHOLDERS = ("-", "N/A", "n/a", "null", "NULL", "unknown", "none", "0.0.0.0")
WINDOW = "-24h"
# Requirement fields the search itself produces, or that raw events never carry (the sampler skips them too).
INTRINSIC = {"_time", "_raw", "host", "source", "sourcetype", "index", "linecount", "splunk_server"}


@dataclasses.dataclass
class ProfileSettings:
    enabled: bool = True
    max_sourcetypes: int = 20
    max_fields: int = 60
    sample_events: int = 1000
    timeout_seconds: int = 60
    budget_seconds: int = 300
    placeholders: Tuple[str, ...] = DEFAULT_PLACEHOLDERS


def parse_placeholders(text: str) -> Tuple[str, ...]:
    values = tuple(v.strip() for v in str(text or "").split(",") if v.strip())
    if not values:
        return DEFAULT_PLACEHOLDERS
    for value in values:
        if not PLACEHOLDER.match(value):
            raise ValidationError("invalid placeholder value", {"value": value[:40]})
    return values


def profile_key(index: str, sourcetype: str, field: str) -> str:
    return "fp_" + hashlib.sha256(("%s|%s|%s" % (index, sourcetype, field)).encode("utf-8")).hexdigest()[:40]


def _quote_free(value: str) -> str:
    return value.replace('"', "").replace("\\", "")


def profile_spl(index: str, sourcetype: str, fields: Sequence[str], placeholders: Sequence[str],
                sample_events: int) -> str:
    """One bounded search that counts filled and placeholder events per field. Every name is validated."""
    validate_index_name(index)
    if not SOURCETYPE.match(sourcetype or ""):
        raise ValidationError("invalid sourcetype", {"value": str(sourcetype)[:80]})
    if not fields:
        raise ValidationError("no fields to profile")
    for name in fields:
        if not FIELD.match(name):
            raise ValidationError("invalid field name", {"value": str(name)[:80]})
    for value in placeholders:
        if not PLACEHOLDER.match(value):
            raise ValidationError("invalid placeholder value", {"value": value[:40]})
    sample = max(1, min(10000, int(sample_events)))
    stats = ["count as sun_events"]
    for i, name in enumerate(fields):
        ref = "'%s'" % name
        filled = "isnotnull(%s) AND trim(%s)!=\"\"" % (ref, ref)
        placeholder = " OR ".join('trim(%s)="%s"' % (ref, p) for p in placeholders)
        stats.append("sum(eval(if(%s,1,0))) as f%d_filled" % (filled, i))
        stats.append("sum(eval(if(%s,1,0))) as f%d_placeholder" % (placeholder, i))
    return ('| search index=%s sourcetype="%s" earliest=%s latest=now | head %d | stats %s'
            % (index, _quote_free(sourcetype), WINDOW, sample, " ".join(stats)))


def parse_profile(row: Dict[str, Any], fields: Sequence[str]) -> List[Dict[str, Any]]:
    events = int(float(row.get("sun_events") or 0))
    out = []
    for i, name in enumerate(fields):
        if events <= 0:
            continue
        filled = int(float(row.get("f%d_filled" % i) or 0))
        placeholder = int(float(row.get("f%d_placeholder" % i) or 0))
        out.append({"field": name, "sample_size": events,
                    "fill_rate": round(filled / events, 4), "placeholder_rate": round(placeholder / events, 4)})
    return out


def targets(store: DocumentStore, categories: Any, settings: ProfileSettings) -> Dict[str, Dict[str, Set[str]]]:
    """sourcetype -> fields, from the active catalogue, most used sourcetypes first (capped)."""
    from ..content.reindex import StoredNormalizer
    from ..storage.repositories import ContentRepository

    active = {r["_key"] for r in store.query(C.CATALOG, {"provider_status": "active"}, fields=["_key"],
                                              limit=50000)}
    normalizer = StoredNormalizer(categories)
    uses: Dict[str, int] = {}
    fields_for: Dict[str, Set[str]] = {}
    for stored in ContentRepository(store).iter_content():
        if stored.get("_key") not in active:
            continue
        uc = normalizer.normalize(stored)
        if uc is None:
            continue
        sts = {r.value.lower() for r in uc.requirements if r.type == "sourcetype" and SOURCETYPE.match(r.value or "")}
        names = {r.value for r in uc.requirements if r.type == "field" and FIELD.match(r.value or "")
                 and r.value not in INTRINSIC and not r.attributes.get("derived_in_spl")}
        for st in sts:
            uses[st] = uses.get(st, 0) + 1
            fields_for.setdefault(st, set()).update(names)
    ordered = sorted(uses, key=lambda s: (-uses[s], s))[: max(0, settings.max_sourcetypes)]
    return {st: {"fields": fields_for[st]} for st in ordered if fields_for.get(st)}


def run_profile(store: DocumentStore, search: Any, categories: Any, settings: ProfileSettings, job_id: str,
                clock: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
    """Profile the targets, store the rates and return a summary. Never raises for a bounded failure."""
    summary: Dict[str, Any] = {"enabled": settings.enabled, "sourcetypes": 0, "fields": 0, "skipped": 0,
                               "errors": 0, "budget_exhausted": False, "window": WINDOW}
    if not settings.enabled:
        return summary
    wanted = targets(store, categories, settings)
    started = clock()
    stored: List[Dict[str, Any]] = []
    for st, spec in sorted(wanted.items()):
        if clock() - started > settings.budget_seconds:
            summary["budget_exhausted"] = True
            summary["skipped"] += 1
            continue
        pairs = store.query(C.ENVIRONMENT_SOURCES, {"kind": "pair", "status": "active", "sourcetype": st},
                            sort=[("window_count", -1)], limit=1, fields=["index", "window_count"])
        if not pairs:
            summary["skipped"] += 1
            continue
        index = pairs[0].get("index") or ""
        names = sorted(spec["fields"])[: max(1, settings.max_fields)]
        try:
            spl = profile_spl(index, st, names, settings.placeholders, settings.sample_events)
            result = search.oneshot(spl, timeout=float(settings.timeout_seconds), max_count=1)
        except (UcmError, ValidationError):
            summary["errors"] += 1
            continue
        rows = result.rows[:1]
        if not rows:
            summary["errors"] += 1
            continue
        profiled = parse_profile(rows[0], names)
        if not profiled:
            summary["skipped"] += 1
            continue
        for row in profiled:
            row.update({"_key": profile_key(index, st, row["field"]), "doc_schema": C.DOC_SCHEMA,
                        "index": index, "sourcetype": st, "window": WINDOW, "evaluated_at": utc_now_iso(),
                        "job_id": job_id})
            stored.append(row)
        summary["sourcetypes"] += 1
        summary["fields"] += len(profiled)
    if stored:
        for st in {r["sourcetype"] for r in stored}:
            for old in store.query(C.FIELD_PROFILE, {"sourcetype": st}, fields=["_key"], limit=50000):
                store.delete(C.FIELD_PROFILE, old["_key"])
        store.batch_save(C.FIELD_PROFILE, stored)
    return summary

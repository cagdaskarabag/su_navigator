"""Environment health panel (D-070, research finding F-06).

Read-only, built from what the last discovery stored: the CIM add-on, each data model's
acceleration and summary state, the CIM index macros, indexes without data, sources that stopped
before the discovery window or carry future time stamps, and active sourcetypes that no
catalogue requirement or mapping names. No search runs here. Every list is capped and says so.
"""

import re
from typing import Any, Dict, List

from ..storage import collections as C
from ..storage.kvstore import DocumentStore

CIM_APP = "Splunk_SA_CIM"
CIM_INDEX_MACRO = re.compile(r"^cim_.+_indexes$", re.I)
MAX_LISTED = 50

SUMMARY_NOT_ACCELERATED = "not_accelerated"
SUMMARY_UNVERIFIED = "summary_unverified"
SUMMARY_NO_DATA = "no_data"
SUMMARY_NOT_BUILT = "summary_not_built"
SUMMARY_PARTIAL = "summary_partial"
SUMMARY_BUILT = "summary_built"


def model_summary_state(doc: Dict[str, Any]) -> str:
    """What a ``summariesonly=t`` search on this model would see over the populated window."""
    if not doc.get("accelerated"):
        return SUMMARY_NOT_ACCELERATED
    if doc.get("populated") == "no":
        return SUMMARY_NO_DATA
    summary = doc.get("summary_count")
    if doc.get("populated") != "yes" or summary is None:
        return SUMMARY_UNVERIFIED
    if not summary:
        return SUMMARY_NOT_BUILT
    total = doc.get("populated_count") or 0
    return SUMMARY_BUILT if total and summary >= 0.9 * total else SUMMARY_PARTIAL


def _capped(rows: List[Any]) -> Dict[str, Any]:
    return {"total": len(rows), "items": rows[:MAX_LISTED], "truncated": len(rows) > MAX_LISTED}


def environment_health(store: DocumentStore) -> Dict[str, Any]:
    state = store.get(C.SYNC_STATE, "discovery::local") or {}
    if not state.get("last_completed_at"):
        return {"discovered": False}
    include_internal = bool(state.get("include_internal"))
    apps = store.query(C.ENVIRONMENT_SOURCES, {"kind": "app", "status": "active"}, fields=["name", "version"])
    cim = next((a for a in apps if str(a.get("name") or "").lower() == CIM_APP.lower()), None)

    models = []
    for d in store.query(C.ENVIRONMENT_SOURCES, {"kind": "datamodel", "status": "active"},
                         sort=[("sort_key", 1)], limit=1000):
        models.append({
            "name": d.get("name"), "app": d.get("app"), "accelerated": bool(d.get("accelerated")),
            "acceleration_earliest": d.get("acceleration_earliest") or "",
            "populated": d.get("populated") or "unverified", "populated_count": d.get("populated_count"),
            "summary_state": model_summary_state(d), "summary_count": d.get("summary_count")})
    cim_models = [m for m in models if m["app"] == CIM_APP]

    macros = []
    for d in store.query(C.ENVIRONMENT_SOURCES, {"kind": "macro", "status": "active"},
                         fields=["name", "app", "definition"], limit=20000):
        if CIM_INDEX_MACRO.match(str(d.get("name") or "")):
            definition = str(d.get("definition") or "").strip()
            macros.append({"name": d.get("name"), "app": d.get("app"), "definition": definition,
                           "constrained": "index" in definition.lower()})
    macros.sort(key=lambda m: str(m["name"]).lower())

    empty = []
    for d in store.query(C.ENVIRONMENT_SOURCES, {"kind": "index", "status": "active"}, limit=5000):
        if d.get("disabled") or d.get("datatype") == "metric":
            continue
        if (d.get("is_internal") or str(d.get("name", "")).startswith("_")) and not include_internal:
            continue
        if not d.get("window_count") and not d.get("volume_30d"):
            empty.append({"name": d.get("name"), "total_event_count": d.get("total_event_count"),
                          "max_time": d.get("max_time") or ""})
    empty.sort(key=lambda r: str(r["name"]))

    stale, future, active_sourcetypes = [], [], set()
    for d in store.query(C.ENVIRONMENT_SOURCES, {"kind": "pair", "status": "active"},
                         fields=["index", "sourcetype", "window_count", "volume_30d", "last_time", "age_seconds",
                                 "stale_from_start", "future_count", "future_last_time"], limit=20000):
        active_sourcetypes.add(str(d.get("sourcetype") or ""))
        if d.get("stale_from_start"):
            stale.append({"index": d.get("index"), "sourcetype": d.get("sourcetype"),
                          "volume_30d": d.get("volume_30d"), "age_seconds": d.get("age_seconds")})
        if d.get("future_count"):
            future.append({"index": d.get("index"), "sourcetype": d.get("sourcetype"),
                           "future_count": d.get("future_count"), "future_last_time": d.get("future_last_time")})
    stale.sort(key=lambda r: -(r["volume_30d"] or 0))
    future.sort(key=lambda r: -(r["future_count"] or 0))
    freshness = (state.get("totals") or {}).get("freshness") or {}

    wanted = set()
    for row in store.query(C.CATALOG, {"provider_status": "active"}, fields=["sourcetypes"], limit=50000):
        wanted.update(str(s).lower() for s in row.get("sourcetypes") or [])
    mapped = {str(m.get("value") or "").lower()
              for m in store.query(C.SOURCE_MAPPINGS, {"kind": "sourcetype"}, fields=["value"])}
    unmapped = sorted(st for st in active_sourcetypes
                      if st and st.lower() not in wanted and st.lower() not in mapped)

    return {
        "discovered": True, "discovery_at": state.get("last_completed_at"), "include_internal": include_internal,
        "cim": {"installed": cim is not None, "version": (cim or {}).get("version") or "",
                "models": len(cim_models), "accelerated": sum(1 for m in cim_models if m["accelerated"])},
        "datamodels": _capped(models),
        "cim_index_macros": _capped(macros),
        "indexes_without_data": _capped(empty),
        "freshness": {"enabled": bool(freshness.get("enabled")), "days": freshness.get("days"),
                      "errors": freshness.get("errors", 0), "stale_from_start": _capped(stale),
                      "future_dated": _capped(future), "future_only": freshness.get("future_only") or []},
        "unmapped_sourcetypes": _capped(unmapped),
    }

"""Attach environment evidence to a canonical use-case detail (read-only)."""

from typing import Any, Dict, List

from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from .apps import app_candidates
from .mapping import MappingService

_REQ_TO_MAP = {
    "sourcetype": "sourcetype", "index": "index", "cim_model": "datamodel", "addon": "addon",
}


def attach_environment(detail: Dict[str, Any], store: DocumentStore) -> Dict[str, Any]:
    mappings = MappingService(store)
    reqs = detail.get("requirements") or []
    present = 0
    for req in reqs:
        kind = _REQ_TO_MAP.get(req.get("type"))
        if not kind:
            req["environment"] = {"applicable": False}
            continue
        mapping = mappings.get(kind, req.get("value") or "")
        sources = _sources(store, kind, req.get("value") or "", mapping, req)
        req["environment"] = {
            "applicable": True,
            "mapping": None if mapping is None else {
                "origin": mapping.get("origin"), "confidence": mapping.get("confidence"),
                "canonical_value": mapping.get("canonical_value"),
            },
            "sources": sources[:10],
            "present": bool(sources),
        }
        if sources:
            present += 1
    applicable = sum(1 for r in reqs if (r.get("environment") or {}).get("applicable"))
    detail["environment_summary"] = {
        "requirements_applicable": applicable,
        "requirements_present": present,
        "note": "Presence is an inventory match, not a readiness assessment.",
    }
    return detail


def _sources(store: DocumentStore, kind: str, value: str, mapping: Dict[str, Any] = None,
             req: Dict[str, Any] = None) -> List[Dict]:
    lookup = (mapping or {}).get("canonical_value") or value
    if kind == "sourcetype":
        query = {"kind": "pair", "status": "active", "sourcetype": lookup}
        fields = ["index", "sourcetype", "window_count", "age_seconds", "last_time", "status"]
    elif kind == "index":
        query = {"kind": "index", "status": "active", "name": lookup}
        fields = ["name", "datatype", "window_count", "age_seconds", "last_time", "status",
                  "total_event_count"]
    elif kind == "datamodel":
        query = {"kind": "datamodel", "status": "active", "name": lookup}
        fields = ["name", "app", "accelerated", "status"]
    else:
        names = [lookup] + [name for name, _ in app_candidates(req or {})]
        query = {"kind": "app", "status": "active",
                 "$or": [{f: {"$in": names}} for f in ("name", "package_id", "label")]}
        fields = ["name", "label", "version", "package_id", "status"]
    rows = store.query(C.ENVIRONMENT_SOURCES, query, sort=[("window_count", -1)], limit=10,
                       fields=fields)
    return rows

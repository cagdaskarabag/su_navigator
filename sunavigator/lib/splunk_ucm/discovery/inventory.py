"""Read-only inventory of indexes, apps and data models via management REST.

These are the same endpoints ``| rest /services/data/indexes`` (and friends)
wrap. Calling them over the management port avoids dispatching a search for
metadata (docs/DECISIONS.md D-020).
"""

import json
from typing import Any, Dict, List

from ..errors import StorageError, UnsupportedOperation
from ..storage.transport import SplunkdTransport
from .apps import package_id


def _entries(data: Any) -> List[Dict[str, Any]]:
    return [e for e in (data or {}).get("entry") or [] if isinstance(e, dict)]


def _content(entry: Dict[str, Any]) -> Dict[str, Any]:
    content = entry.get("content")
    return content if isinstance(content, dict) else {}


class SplunkInventory:
    def __init__(self, transport: SplunkdTransport):
        self.t = transport

    def _get(self, path: str, capability: str) -> List[Dict[str, Any]]:
        try:
            data = self.t.json("GET", path, {"count": "0"})
        except StorageError as exc:
            if exc.status in (403, 404, 402):
                raise UnsupportedOperation("%s is not available" % capability,
                                          {"path": path, "status": exc.status}) from exc
            raise
        return _entries(data)

    def list_indexes(self) -> List[Dict[str, Any]]:
        out = []
        for entry in self._get("/services/data/indexes", "index listing"):
            content = _content(entry)
            name = str(entry.get("name") or content.get("name") or "")
            if not name:
                continue
            out.append({
                "name": name,
                "disabled": bool(content.get("disabled")),
                "is_internal": bool(content.get("isInternal")),
                "is_ready": content.get("isReady") in (True, "1", 1, "True"),
                "datatype": str(content.get("datatype") or "event"),
                "total_event_count": _int(content.get("totalEventCount")),
                "min_time": str(content.get("minTime") or ""),
                "max_time": str(content.get("maxTime") or ""),
            })
        return out

    def list_apps(self) -> List[Dict[str, Any]]:
        out = []
        for entry in self._get("/services/apps/local", "app listing"):
            content = _content(entry)
            name = str(entry.get("name") or "")
            if not name:
                continue
            out.append({
                "name": name,
                "label": str(content.get("label") or name),
                "version": str(content.get("version") or ""),
                "package_id": package_id(content.get("details")),
                "disabled": bool(content.get("disabled")),
                "visible": bool(content.get("visible")),
            })
        return out

    def server_version(self) -> str:
        try:
            data = self.t.json("GET", "/services/server/info")
        except StorageError:
            return ""
        entries = _entries(data)
        return str(_content(entries[0]).get("version") or "") if entries else ""

    def list_knowledge_objects(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Macros, lookup definitions, lookup table files and eventtypes visible to the caller."""
        out: List[Dict[str, Any]] = []
        for kind, path in (("macro", "/servicesNS/-/-/admin/macros"),
                           ("lookup", "/servicesNS/-/-/data/transforms/lookups"),
                           ("lookup", "/servicesNS/-/-/data/lookup-table-files"),
                           ("eventtype", "/servicesNS/-/-/saved/eventtypes")):
            try:
                entries = self._get(path, kind + " listing")
            except UnsupportedOperation:
                continue
            for entry in entries[:limit]:
                name = str(entry.get("name") or "")
                if not name:
                    continue
                content = _content(entry)
                acl = entry.get("acl") if isinstance(entry.get("acl"), dict) else {}
                out.append({
                    "kind": kind, "name": name,
                    "app": str(acl.get("app") or content.get("eai:appName") or ""),
                    "sharing": str(acl.get("sharing") or ""),
                    "disabled": bool(content.get("disabled")),
                    "lookup_type": str(content.get("type") or ("file" if path.endswith("files") else "")),
                })
        return out

    def list_datamodels(self) -> List[Dict[str, Any]]:
        out = []
        for entry in self._get("/services/data/models", "data model listing"):
            content = _content(entry)
            name = str(entry.get("name") or "")
            if not name:
                continue
            parsed = _parse_model(content.get("eai:data"))
            acl = entry.get("acl") if isinstance(entry.get("acl"), dict) else {}
            acceleration = content.get("acceleration")
            if acceleration is None:
                acceleration = parsed.get("acceleration")
            out.append({
                "name": name,
                "app": str(acl.get("app") or content.get("eai:appName") or ""),
                "disabled": bool(content.get("disabled")),
                "display_name": parsed.get("displayName") or name,
                "objects": list(parsed.get("objectNameList") or []),
                "accelerated": _is_accelerated(acceleration),
                "acceleration_earliest": str(content.get("acceleration.earliest_time") or "")
                if _is_accelerated(acceleration) else "",
            })
        return out


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_model(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}
    return {}


_TRUE = (True, 1, "1", "true", "True")


def _is_accelerated(value: Any) -> bool:
    """``/services/data/models`` (10.2.9) reports a top-level boolean; ``datamodel/model`` a JSON
    string with ``enabled``; older payloads a dict inside ``eai:data``."""
    if isinstance(value, str) and value.lstrip().startswith("{"):
        value = _parse_model(value)
    if isinstance(value, dict):
        return value.get("enabled") in _TRUE
    return value in _TRUE

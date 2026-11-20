"""Read-only inventory of indexes, apps and data models via management REST.

These are the same endpoints ``| rest /services/data/indexes`` (and friends)
wrap. Calling them over the management port avoids dispatching a search for
metadata (docs/DECISIONS.md D-020).
"""

import json
from typing import Any, Dict, List

from ..errors import StorageError, UnsupportedOperation
from ..storage.transport import SplunkdTransport


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
                "disabled": bool(content.get("disabled")),
                "visible": bool(content.get("visible")),
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
            out.append({
                "name": name,
                "app": str(content.get("eai:appName") or ""),
                "disabled": bool(content.get("disabled")),
                "display_name": parsed.get("displayName") or name,
                "objects": list(parsed.get("objectNameList") or []),
                "accelerated": _is_accelerated(parsed.get("acceleration")),
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


def _is_accelerated(value: Any) -> bool:
    if isinstance(value, dict):
        enabled = value.get("enabled")
        return enabled in (True, "1", 1, "true", "True")
    return False

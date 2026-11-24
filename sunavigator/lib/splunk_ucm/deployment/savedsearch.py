"""Saved-search adapter over ``/servicesNS/nobody/<app>/saved/searches``.

Always called with the caller's session (D-011, D-028): Splunk enforces the
app ACL (``metadata/default.meta [savedsearches]``) and the created search is
owned by the deploying user, so it never runs with more privilege than they have.
"""

import json
from typing import Any, Dict, Optional
from urllib.parse import quote

from .. import APP_NAME
from ..errors import ConflictError, PermissionDenied, StorageError, ValidationError
from ..storage.transport import SplunkdTransport

MANAGED_MARKER = "Managed by SUNavigator"

READ_KEYS = ("search", "disabled", "is_scheduled", "cron_schedule", "dispatch.earliest_time",
             "dispatch.latest_time", "description", "alert_type", "alert_comparator", "alert_threshold",
             "alert.track", "alert.severity", "next_scheduled_time", "actions", "schedule_window",
             "alert.suppress", "alert.suppress.period", "alert.suppress.fields")


def _messages(body: bytes) -> str:
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError):
        return ""
    msgs = data.get("messages") if isinstance(data, dict) else None
    if isinstance(msgs, list) and msgs and isinstance(msgs[0], dict):
        return str(msgs[0].get("text") or "")[:300]
    return ""


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class SavedSearchClient:
    def __init__(self, transport: SplunkdTransport, app: str = APP_NAME):
        self.t = transport
        self.app = app
        self.base = "/servicesNS/nobody/%s/saved/searches" % quote(app, safe="")

    def _path(self, name: str) -> str:
        return "%s/%s" % (self.base, quote(name, safe=""))

    def _raise(self, status: int, body: bytes, action: str) -> None:
        text = _messages(body)
        if status == 403:
            raise PermissionDenied("Splunk refused to %s the saved search: %s" % (action, text or "forbidden"))
        if status == 409:
            raise ConflictError("a saved search with this name already exists", {"splunk": text})
        if status == 400:
            raise ValidationError("Splunk rejected the saved search: %s" % (text or "bad request"))
        raise StorageError("saved search %s failed" % action, status, {"splunk": text})

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        status, body = self.t.request("GET", self._path(name), {"output_mode": "json"})
        if status == 404:
            return None
        if status != 200:
            self._raise(status, body, "read")
        data = json.loads(body.decode("utf-8") or "{}")
        entries = data.get("entry") or []
        if not entries:
            return None
        entry = entries[0]
        acl = entry.get("acl") or {}
        if acl.get("app") and acl.get("app") != self.app:
            return None
        content = entry.get("content") or {}
        out = {k: content.get(k) for k in READ_KEYS}
        out["disabled"] = _bool(out.get("disabled"))
        out["is_scheduled"] = _bool(out.get("is_scheduled"))
        out["name"] = entry.get("name") or name
        out["owner"] = acl.get("owner") or ""
        out["sharing"] = acl.get("sharing") or ""
        out["app"] = acl.get("app") or self.app
        return out

    def create(self, name: str, settings: Dict[str, str]) -> None:
        form = dict(settings)
        form["name"] = name
        status, body = self.t.request("POST", self.base, {"output_mode": "json"}, form=form)
        if status not in (200, 201):
            self._raise(status, body, "create")

    def update(self, name: str, settings: Dict[str, str]) -> None:
        status, body = self.t.request("POST", self._path(name), {"output_mode": "json"}, form=dict(settings))
        if status != 200:
            self._raise(status, body, "update")

    def delete(self, name: str) -> bool:
        status, body = self.t.request("DELETE", self._path(name), {"output_mode": "json"})
        if status == 404:
            return False
        if status != 200:
            self._raise(status, body, "delete")
        return True

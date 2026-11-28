"""Audit rows for governance requests the app refused (D-080).

A refused request (missing capability, failed validation, conflict with the workflow) changes nothing, but a run of
them is what an attempted bypass looks like. They are written to the same hash-chained audit trail, as
``refused.<route>`` with ``outcome=refused``, under limits so that nobody can use refusals to flood the chain:

* a request that repeats (same user, route, object and reason code) inside ``refusal_window_seconds`` is not written again;
* one user writes at most ``refusal_actor_per_hour`` rows per hour, everyone together at most ``refusal_total_per_hour``;
* the first request over a limit writes one ``refused.rate_limited`` row for that hour, then nothing more;
* only POST requests to the governance routes below count, only client errors (400, 403, 409), and only an error
  code, a route and a shortened message are kept: no request body, no query string, no credentials.
"""

import re
from typing import Any, Callable, Dict, Optional

from .errors import UcmError
from .log import get_logger
from .storage import collections as C
from .util import epoch_now

log = get_logger(__name__)

GOVERNED_PREFIXES = ("deployment/", "frameworks/import", "frameworks/activate",
                     "dashboards/create", "dashboards/delete", "controltest/import", "sync", "import", "mappings",
                     "catalog/reindex")
REFUSED_STATUSES = (400, 403, 409)
HOUR = 3600
MESSAGE_CHARS = 200

DEFAULT_WINDOW = 300
DEFAULT_PER_ACTOR = 20
DEFAULT_TOTAL = 200

_URL_QUERY = re.compile(r"\?[^\s\"']*")
_USERINFO = re.compile(r"://[^\s/@]*@")
_PREFIX = "refused."
_LIMITED = "refused.rate_limited"


def governed(method: str, path: str) -> bool:
    return method.upper() == "POST" and any(path == p.rstrip("/") or path.startswith(p) for p in GOVERNED_PREFIXES)


def clean_message(text: str) -> str:
    """The error message without a URL query string or credentials, shortened."""
    text = _USERINFO.sub("://", str(text or ""))
    return _URL_QUERY.sub("", text)[:MESSAGE_CHARS]


def _object_id(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    for key in ("id", "control_id", "framework_id", "item_id", "snapshot_id"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value[:200]
    return ""


def _code(error: UcmError) -> str:
    """The specific reason when the error names one (a ``conflict`` can be five different refusals)."""
    return str((error.details or {}).get("code") or error.code)[:80]


class RefusalAudit:
    def __init__(self, audit: Any, enabled: bool = True, window: int = DEFAULT_WINDOW, per_actor: int = DEFAULT_PER_ACTOR,
                 total: int = DEFAULT_TOTAL, now: Callable[[], float] = epoch_now):
        self.audit = audit
        self.enabled = enabled
        self.window = max(0, window)
        self.per_actor = max(1, per_actor)
        self.total = max(1, total)
        self.now = now

    @classmethod
    def from_config(cls, audit: Any, config: Any) -> "RefusalAudit":
        return cls(audit, enabled=config.get_bool("audit", "refusals", True),
                   window=config.get_int("audit", "refusal_window_seconds", DEFAULT_WINDOW, 0, HOUR),
                   per_actor=config.get_int("audit", "refusal_actor_per_hour", DEFAULT_PER_ACTOR, 1, 1000),
                   total=config.get_int("audit", "refusal_total_per_hour", DEFAULT_TOTAL, 1, 100000))

    def record(self, actor: str, method: str, path: str, error: UcmError, body: Any = None) -> Optional[str]:
        """Write a refusal row unless a limit applies; returns the row key, or None. Never raises."""
        try:
            if not self.enabled or error.http_status not in REFUSED_STATUSES or not governed(method, path):
                return None
            actor = actor or "unknown"
            action = _PREFIX + path.replace("/", ".")
            code = _code(error)
            object_id = _object_id(body)
            store = self.audit.store
            now = self.now()
            hour = store.query(C.AUDIT, {"$and": [{"action": {"$regex": "^refused\\."}}, {"time": {"$gte": now - HOUR}}]},
                               sort=[("time", -1)], limit=self.total + 2, fields=["actor", "action", "time", "object_id",
                                                                                  "details"])
            if self.window and any(
                    r.get("actor") == actor and r.get("action") == action and r.get("object_id") == object_id
                    and (r.get("details") or {}).get("code") == code and float(r.get("time") or 0) >= now - self.window
                    for r in hour):
                return None
            limited = [r for r in hour if r.get("action") == _LIMITED]
            written = [r for r in hour if r.get("action") != _LIMITED]
            mine = [r for r in written if r.get("actor") == actor]
            scope = ""
            if len(mine) >= self.per_actor:
                scope = "actor"
            elif len(written) >= self.total:
                scope = "all"
            if scope:
                if not any(r.get("actor") == (actor if scope == "actor" else "system") for r in limited):
                    self.audit.record(actor if scope == "actor" else "system", _LIMITED, "audit", "",
                                      outcome="refused",
                                      details={"scope": scope, "limit": self.per_actor if scope == "actor" else self.total,
                                               "per": "hour", "first_dropped_route": path})
                return None
            return self.audit.record(actor, action, path.split("/")[0], object_id, outcome="refused",
                                     details={"code": code, "error": error.code, "status": error.http_status, "route": path,
                                              "message": clean_message(error.message)})
        except Exception:
            log.exception("refusal audit failed", extra={"path": path})
            return None

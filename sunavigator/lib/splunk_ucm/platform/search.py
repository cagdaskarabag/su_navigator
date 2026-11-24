"""Ad-hoc search client over splunkd's search/jobs and search/parser endpoints.

Discovery uses ``oneshot`` only for constructed generating searches (``| tstats``).
Imported SPL is parsed with ``parse`` and is dispatched only by ``preview`` after
a side-effect gate (WP4).
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from ..errors import StorageError, UnsupportedOperation, ValidationError
from ..storage.transport import SplunkdTransport

# limits.conf [restapi] maxresultrows default. splunkd never returns more rows than
# this from one request, so a limit must stay below it for the sentinel row to fit.
ONESHOT_ROW_CEILING = 50000


class SearchResult:
    def __init__(self, rows: List[Dict[str, Any]], messages: List[Dict[str, str]], truncated: bool):
        self.rows = rows
        self.messages = messages
        self.truncated = truncated
        self.errors = [m.get("text", "") for m in messages if m.get("type") in ("ERROR", "FATAL")]


class ParseResult:
    def __init__(self, ok: bool, commands: List[str], messages: List[Dict[str, str]],
                 remote_search: str = "", normalized: str = "", raw: Optional[Dict[str, Any]] = None):
        self.ok = ok
        self.commands = commands
        self.messages = messages
        self.remote_search = remote_search
        self.normalized = normalized
        self.raw = raw or {}
        self.errors = [m.get("text", "") for m in messages if m.get("type") in ("ERROR", "FATAL")]


class SearchClient:
    def __init__(self, transport: SplunkdTransport):
        self.t = transport

    def oneshot(self, search: str, timeout: float = 120.0, max_count: int = 5000,
                earliest: str = "", latest: str = "") -> SearchResult:
        if not search.startswith("|"):
            raise ValidationError("only generating searches are permitted")
        return self._oneshot(search, timeout, max_count, earliest, latest)

    def preview(self, search: str, timeout: float = 30.0, max_count: int = 100,
                earliest: str = "-15m", latest: str = "now") -> SearchResult:
        """Dispatch a *user-approved* bounded search. Caller must have gated side effects."""
        text = (search or "").strip()
        if not text:
            raise ValidationError("empty search")
        return self._oneshot(text, timeout, max_count, earliest, latest)

    def parse(self, q: str, app: str = "") -> ParseResult:
        """POST search/parser with parse_only. 400 is a parse failure, not a transport error.

        With ``app`` the parser resolves macros and lookups in that app's namespace,
        as a saved search in that app would.
        """
        path = "/servicesNS/-/%s/search/parser" % quote(app, safe="") if app else "/services/search/parser"
        status, body = self.t.request(
            "POST", path,
            query={"output_mode": "json", "parse_only": "true"},
            form={"q": q}, timeout=30.0)
        if status not in (200, 400):
            if status in (403, 402):
                raise UnsupportedOperation("search parser is not available", {"status": status})
            raise StorageError("splunkd returned HTTP %d" % status, status, {"path": path})
        try:
            data = json.loads(body.decode("utf-8") if body else "{}")
        except ValueError as exc:
            raise StorageError("invalid JSON from search/parser") from exc
        if not isinstance(data, dict):
            data = {}
        messages = [m for m in (data.get("messages") or []) if isinstance(m, dict)]
        commands = []
        for cmd in data.get("commands") or []:
            if isinstance(cmd, dict) and cmd.get("command"):
                commands.append(str(cmd["command"]).lower())
        ok = status == 200 and not any(m.get("type") in ("ERROR", "FATAL") for m in messages)
        parsed = ParseResult(ok, commands, messages, str(data.get("remoteSearch") or ""),
                             str(data.get("normalizedSearch") or ""), data)
        return parsed

    def _oneshot(self, search: str, timeout: float, max_count: int,
                 earliest: str, latest: str) -> SearchResult:
        """Return at most ``max_count`` rows; ``truncated`` is True only if more existed.

        A oneshot returns ``count`` rows (splunkd default 100) whatever ``max_count``
        says; ``max_count`` bounds only the events a search may retain. Both are set to
        one row past the limit so the extra row proves truncation.
        """
        limit = max(1, min(int(max_count), ONESHOT_ROW_CEILING - 1))
        form: Dict[str, Any] = {
            "search": search,
            "exec_mode": "oneshot",
            "count": str(limit + 1),
            "max_count": str(limit + 1),
            "timeout": str(max(1, int(timeout))),
            "adhoc_search_level": "fast",
        }
        if earliest:
            form["earliest_time"] = earliest
        if latest:
            form["latest_time"] = latest
        try:
            data = self.t.json("POST", "/services/search/jobs", form=form, timeout=timeout + 15.0)
        except StorageError as exc:
            if exc.status in (403, 402, 409):
                raise UnsupportedOperation("ad-hoc search is not available",
                                          {"status": exc.status}) from exc
            raise
        if not isinstance(data, dict):
            raise StorageError("unexpected search response")
        rows = data.get("results") if isinstance(data.get("results"), list) else []
        messages = [m for m in (data.get("messages") or []) if isinstance(m, dict)]
        truncated = len(rows) > limit
        result = SearchResult(rows[:limit], messages, truncated)
        if result.errors:
            raise UnsupportedOperation("search failed: %s" % result.errors[0][:300],
                                       {"messages": result.errors[:5]})
        return result

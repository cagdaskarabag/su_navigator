"""Ad-hoc search client over splunkd's search/jobs endpoint.

Discovery jobs use this to run a *constructed* ``tstats`` template. Imported
SPL is never passed here.
"""

from typing import Any, Dict, List, Optional

from ..errors import StorageError, UnsupportedOperation, ValidationError
from ..storage.transport import SplunkdTransport


class SearchResult:
    def __init__(self, rows: List[Dict[str, Any]], messages: List[Dict[str, str]], truncated: bool):
        self.rows = rows
        self.messages = messages
        self.truncated = truncated
        self.errors = [m.get("text", "") for m in messages if m.get("type") == "ERROR"]


class SearchClient:
    def __init__(self, transport: SplunkdTransport):
        self.t = transport

    def oneshot(self, search: str, timeout: float = 120.0, max_count: int = 5000) -> SearchResult:
        if not search.startswith("|"):
            raise ValidationError("only generating searches are permitted")
        try:
            data = self.t.json(
                "POST", "/services/search/jobs",
                form={
                    "search": search,
                    "exec_mode": "oneshot",
                    "max_count": str(int(max_count)),
                    "timeout": str(max(1, int(timeout))),
                    "adhoc_search_level": "fast",
                },
                timeout=timeout + 15.0)
        except StorageError as exc:
            if exc.status in (403, 402, 409):
                raise UnsupportedOperation("ad-hoc search is not available",
                                          {"status": exc.status}) from exc
            raise
        if not isinstance(data, dict):
            raise StorageError("unexpected search response")
        rows = data.get("results") if isinstance(data.get("results"), list) else []
        messages = [m for m in (data.get("messages") or []) if isinstance(m, dict)]
        truncated = len(rows) >= int(max_count)
        result = SearchResult(rows, messages, truncated)
        if result.errors:
            raise UnsupportedOperation("search failed: %s" % result.errors[0][:300],
                                       {"messages": result.errors[:5]})
        return result

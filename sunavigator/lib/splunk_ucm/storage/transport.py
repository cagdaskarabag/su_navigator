"""Transports to splunkd's management REST API.

This is the only module that imports ``splunk.*``. Services receive a
``SplunkdTransport`` and therefore run unchanged in unit tests and tools
(``tools/splunkd_http.py`` provides an HTTP transport outside Splunk).
"""

import abc
import json
from typing import Any, Dict, Optional, Tuple

from ..errors import StorageError

Query = Optional[Dict[str, Any]]


class SplunkdTransport(abc.ABC):
    @abc.abstractmethod
    def request(self, method: str, path: str, query: Query = None, json_body: Any = None,
                form: Optional[Dict[str, Any]] = None, timeout: float = 60.0) -> Tuple[int, bytes]:
        """Perform a request; ``path`` starts with ``/services`` or ``/servicesNS``."""

    def json(self, method: str, path: str, query: Query = None, json_body: Any = None,
             form: Optional[Dict[str, Any]] = None, ok=(200, 201), timeout: float = 60.0) -> Any:
        q = dict(query or {})
        q.setdefault("output_mode", "json")
        status, body = self.request(method, path, q, json_body, form, timeout)
        if status not in ok:
            raise StorageError("splunkd returned HTTP %d" % status, status,
                               {"path": path, "body": body[:500].decode("utf-8", "replace")})
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise StorageError("invalid JSON from splunkd", status, {"path": path}) from exc


class SimpleRequestTransport(SplunkdTransport):
    """In-Splunk transport using ``splunk.rest.simpleRequest`` and a session key."""

    def __init__(self, session_key: str):
        self.session_key = session_key

    def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        import splunk.rest  # type: ignore  # provided by Splunk at runtime

        kwargs: Dict[str, Any] = {
            "sessionKey": self.session_key, "method": method, "getargs": query or None,
            "raiseAllErrors": False, "rawResult": True, "timeout": timeout,
        }
        if json_body is not None:
            kwargs["jsonargs"] = json.dumps(json_body)
        elif form is not None:
            kwargs["postargs"] = form
        try:
            response, content = splunk.rest.simpleRequest(path, **kwargs)
        except Exception as exc:  # splunk.SplunkdConnectionException and friends
            raise StorageError("splunkd connection failed: %s" % exc) from exc
        if isinstance(content, str):
            content = content.encode("utf-8")
        return int(response.status), content or b""

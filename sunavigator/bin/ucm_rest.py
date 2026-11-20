"""Persistent REST handler for /services/ucm/* (see default/restmap.conf)."""

import json
import os
import sys

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from splunk_ucm.api.app import Context, Request, build_router  # noqa: E402
from splunk_ucm.log import get_logger  # noqa: E402
from splunk_ucm.storage.transport import SimpleRequestTransport  # noqa: E402

log = get_logger("splunk_ucm.rest")
_ROUTER = build_router()
_PREFIX = "/ucm"


def _query(pairs):
    out = {}
    for item in pairs or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out.setdefault(str(item[0]), []).append(str(item[1]))
    return out


class UcmRestHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        PersistentServerConnectionApplication.__init__(self)

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
        except ValueError:
            return self._respond(400, {"error": {"code": "bad_request", "message": "invalid request"}})
        session = request.get("session") or {}
        user_token = session.get("authtoken")
        if not user_token:
            return self._respond(401, {"error": {"code": "unauthenticated", "message": "no session"}})
        rest_path = request.get("rest_path") or ""
        path = rest_path[len(_PREFIX):] if rest_path.startswith(_PREFIX) else rest_path
        payload = request.get("payload") or ""
        body = payload.encode("utf-8") if isinstance(payload, str) else (payload or b"")
        req = Request(method=str(request.get("method", "GET")).upper(), path=path,
                      query=_query(request.get("query")), body=body, user=str(session.get("user", "")))
        system_token = request.get("system_authtoken")
        ctx = Context(SimpleRequestTransport(user_token),
                      SimpleRequestTransport(system_token) if system_token else None, req.user)
        response = _ROUTER.dispatch(ctx, req)
        return self._respond(response.status, response.body)

    @staticmethod
    def _respond(status, body):
        return {"status": status, "payload": json.dumps(body),
                "headers": {"Content-Type": "application/json", "Cache-Control": "no-store",
                            "X-Content-Type-Options": "nosniff"}}

    def handleStream(self, handle, in_string):
        raise NotImplementedError("streaming not supported")

    def done(self):
        pass

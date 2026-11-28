"""Request, response, router and capability names shared by the route modules."""

import dataclasses
import json
from typing import Any, Callable, Dict, List, TYPE_CHECKING, Tuple

from ..log import get_logger
from ..errors import UcmError, ValidationError
from ..refusals import REFUSED_STATUSES, RefusalAudit, governed

if TYPE_CHECKING:
    from .app import Context

log = get_logger(__name__)


CAP_MANAGE_CONTENT = "ucm_manage_content"
CAP_ADMIN = "ucm_admin"
CAP_RUN_DISCOVERY = "ucm_run_discovery"
CAP_DEPLOY = "ucm_deploy"
CAP_ASSESS = "ucm_assess"


@dataclasses.dataclass
class Request:
    method: str
    path: str  # relative to /ucm, e.g. "catalog"
    query: Dict[str, List[str]]
    body: bytes
    user: str

    def arg(self, name: str, default: str = "") -> str:
        values = self.query.get(name)
        return values[-1] if values else default

    def args(self, name: str) -> List[str]:
        out: List[str] = []
        for v in self.query.get(name, []):
            out.extend(p for p in v.split(",") if p)
        return out

    def json(self) -> Dict[str, Any]:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ValidationError("request body is not valid JSON")
        if not isinstance(data, dict):
            raise ValidationError("request body must be a JSON object")
        return data


@dataclasses.dataclass
class Response:
    status: int
    body: Any


def _int(value: str, default: int, name: str) -> int:
    if value == "":
        return default
    try:
        return int(value)
    except ValueError:
        raise ValidationError("%s must be an integer" % name)


def _bool(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


Handler = Callable[["Context", Request], Response]


class Router:
    def __init__(self) -> None:
        self.routes: Dict[Tuple[str, str], Handler] = {}

    def add(self, method: str, path: str, handler: Handler) -> None:
        self.routes[(method, path)] = handler

    def dispatch(self, ctx: "Context", req: Request) -> Response:
        path = req.path.strip("/")
        handler = self.routes.get((req.method.upper(), path))
        if handler is None:
            if any(p == path for (_, p) in self.routes):
                return Response(405, {"error": {"code": "method_not_allowed", "message": "method not allowed"}})
            return Response(404, {"error": {"code": "not_found", "message": "unknown endpoint"}})
        try:
            return handler(ctx, req)
        except UcmError as exc:
            if exc.http_status >= 500:
                log.warning("request failed", extra={"path": path, "code": exc.code, "error": exc.message})
            elif exc.http_status in REFUSED_STATUSES and governed(req.method, path):
                _audit_refusal(ctx, req, path, exc)
            return Response(exc.http_status, {"error": exc.to_dict()})
        except Exception:
            log.exception("unhandled error", extra={"path": path})
            return Response(500, {"error": {"code": "internal_error", "message": "internal error"}})


def _audit_refusal(ctx: "Context", req: Request, path: str, exc: UcmError) -> None:
    """Record a refused governance request in the audit trail, within the limits of D-080."""
    try:
        try:
            body: Any = req.json()
        except UcmError:
            body = None
        try:
            refusals = RefusalAudit.from_config(ctx.audit, ctx.config)
        except Exception:
            refusals = RefusalAudit(ctx.audit)
        refusals.record(ctx.user, req.method, path, exc, body)
    except Exception:
        log.exception("refusal audit failed", extra={"path": path})


# -- handlers ---------------------------------------------------------------

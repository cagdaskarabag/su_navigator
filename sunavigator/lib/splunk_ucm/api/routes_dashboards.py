"""Dashboard routes."""

from typing import TYPE_CHECKING

from ..errors import ValidationError
from .base import CAP_DEPLOY, Request, Response

if TYPE_CHECKING:
    from .app import Context


def get_dashboards(ctx: "Context", req: Request) -> Response:
    svc = ctx.dashboard_service()
    return Response(200, {"templates": svc.templates(), "dashboards": svc.list()})


def post_dashboard_preview(ctx: "Context", req: Request) -> Response:
    body = req.json()
    return Response(200, ctx.dashboard_service().preview(str(body.get("template") or ""), body.get("params") or {}))


def post_dashboard_create(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_DEPLOY)
    body = req.json()
    return Response(200, {"dashboard": ctx.dashboard_service().create(
        ctx.user, str(body.get("template") or ""), body.get("params") or {})})


def post_dashboard_delete(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_DEPLOY)
    body = req.json()
    name = str(body.get("name") or "")
    if not name.startswith("ucm_gen_") or len(name) > 100:
        raise ValidationError("not a generated dashboard name")
    ctx.dashboard_service().delete(ctx.user, name)
    return Response(200, {"deleted": True})

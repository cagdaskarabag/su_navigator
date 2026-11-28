"""Validation, preview, control-test and deployment routes."""

from typing import Any, Dict, Optional, TYPE_CHECKING, Tuple

from ..deployment.controltest import DEFAULT_TEST_INDEX
from ..deployment.service import DeploymentService
from ..errors import ConflictError, PermissionDenied, ValidationError
from ..frameworks.operations import OperationsService
from ..platform.search import SearchClient
from ..readiness.principal import pattern_matches, read_principal
from .base import CAP_MANAGE_CONTENT, CAP_RUN_DISCOVERY, CAP_DEPLOY, Request, Response, Handler, _int

if TYPE_CHECKING:
    from .app import Context


def _require_any(ctx: "Context", *caps: str) -> None:
    have = ctx.capabilities()
    if not any(c in have for c in caps):
        raise PermissionDenied("missing capability %s" % " or ".join(caps))


def _deployment_view(ctx: "Context", svc: DeploymentService, doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"deployment": doc, "allowed_actions": svc.allowed_actions(doc, ctx.user, ctx.capabilities()),
            "scheduler_access": svc.scheduler_access_for(doc),
            "settings": {"require_approval": svc.settings.require_approval,
                         "allow_self_approval": svc.settings.allow_self_approval,
                         "enable_second_person": svc.settings.enable_second_person,
                         "override_second_person": svc.settings.override_second_person,
                         "enable_request_hours": svc.settings.enable_request_hours,
                         "override_days": svc.settings.override_days,
                         "override_expiry_action": svc.settings.override_expiry_action,
                         "block_enable_states": list(svc.settings.block_enable_states),
                         "defaults": svc.settings.defaults(), "actions": svc.settings.actions.public()}}


def get_deployments(ctx: "Context", req: Request) -> Response:
    svc = ctx.deployment_service()
    out = svc.list(req.args("state"), req.args("live"), _int(req.arg("offset"), 0, "offset"),
                   _int(req.arg("count"), 50, "count"), drifted=req.arg("drift") == "1",
                   outcomes=req.args("outcome"), override_active=req.arg("override") == "1")
    if req.arg("summary") == "1":
        out["summary"] = svc.summary()
    return Response(200, out)


def post_controltest_import(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    max_mb = ctx.config.get_int("import", "max_bundle_mb", 50, 1, 500)
    if len(req.body or b"") > max_mb * 1024 * 1024:
        raise ValidationError("fixture bundle is larger than max_bundle_mb")
    return Response(200, ctx.deployment_service().import_fixtures(ctx.user, req.json()))


def get_deployments_export(ctx: "Context", req: Request) -> Response:
    return Response(200, ctx.deployment_service().export(ctx.user))


def get_deployment_diff(ctx: "Context", req: Request) -> Response:
    use_case_id = req.arg("id")
    if not use_case_id:
        raise ValidationError("id is required")
    return Response(200, ctx.deployment_service().diff(use_case_id, _int(req.arg("from"), 0, "from"),
                                                       _int(req.arg("to"), 0, "to")))


def get_deployment(ctx: "Context", req: Request) -> Response:
    svc = ctx.deployment_service()
    return Response(200, _deployment_view(ctx, svc, svc.get(req.arg("id"))))


ALWAYS_DEFAULT_INDEXES = ("main", "defaultdb")


def _refuse_default_test_index(ctx: "Context") -> None:
    """Control-test events must not land in an index that searches without ``index=`` read (issue #51, item 9)."""
    index = (ctx.config.get("controltest", "index", DEFAULT_TEST_INDEX).strip() or DEFAULT_TEST_INDEX).lower()
    as_default = index in ALWAYS_DEFAULT_INDEXES
    if not as_default and ctx.system_transport is not None:
        principal = read_principal(ctx.system_transport, ctx.user)
        as_default = principal.readable and any(pattern_matches(p, index) for p in principal.default)
    if as_default:
        raise ConflictError("the control-test index %r is a default search index, so the test events would show up in "
                            "searches that name no index; set [controltest] index in ucm.conf to a dedicated index"
                            % index, {"code": "test_index_is_default"})


def _deployment_action(action: str) -> Handler:
    propose = action in ("draft", "submit")
    observe = action == "verify"

    def handler(ctx: "Context", req: Request) -> Response:
        if propose or observe:
            _require_any(ctx, CAP_DEPLOY, CAP_RUN_DISCOVERY)
        else:
            ctx.require(CAP_DEPLOY)
        body = req.json()
        use_case_id = str(body.get("id") or req.arg("id") or "")
        if not use_case_id:
            raise ValidationError("id is required")
        svc = ctx.deployment_service()
        note = str(body.get("note") or "")
        if len(note) > 500:
            raise ValidationError("note too long")
        if action == "draft":
            doc = svc.save_draft(ctx.user, use_case_id, body)
        elif action == "enable":
            doc = svc.enable(ctx.user, use_case_id, str(body.get("override_reason") or ""))
        elif action == "outcome":
            doc = svc.set_outcome(ctx.user, use_case_id, str(body.get("outcome") or ""), note)
        elif action == "verify":
            doc = svc.verify(ctx.user, use_case_id)
        elif action == "controltest":
            _refuse_default_test_index(ctx)
            doc = svc.control_test(ctx.user, use_case_id)
        elif action == "approve":
            doc = svc.approve(ctx.user, use_case_id, note,
                              acknowledge_commands=body.get("acknowledge_commands") is True,
                              acknowledge_actions=body.get("acknowledge_actions") is True,
                              access_reason=str(body.get("access_reason") or "")[:500])
        elif action == "submit":
            doc = svc.submit(ctx.user, use_case_id, note,
                             acknowledge_commands=body.get("acknowledge_commands") is True,
                             acknowledge_actions=body.get("acknowledge_actions") is True)
        else:
            doc = getattr(svc, action)(ctx.user, use_case_id, note)
        return Response(200, _deployment_view(ctx, svc, doc))

    return handler


def _operational_map(ctx: "Context", hours: int) -> Tuple[Optional[Dict[str, str]], Dict[str, Any]]:
    health = OperationsService(ctx.store, SearchClient(ctx.user_transport)).health(hours)
    if not health["available"]:
        return None, health
    return {i["content_id"]: i["health"] for i in health["items"]}, health


DEPLOYMENT_ACTIONS = ("draft", "submit", "approve", "reject", "withdraw", "deploy", "enable", "cancel_enable", "disable",
                      "rollback", "retire", "verify", "controltest", "outcome")

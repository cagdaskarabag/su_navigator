"""Frameworks, control catalogues, ATT&CK, assessment and POA&M routes."""

import json
from typing import Any, Dict, Optional, TYPE_CHECKING, Tuple

from ..discovery.external import ExternalMatchService
from ..discovery.query import coverage
from ..dashboards.templates import DOMAINS as DASHBOARD_DOMAINS
from ..errors import NotFoundError, ValidationError
from ..frameworks.coverage import CoverageService
from ..frameworks.evidence import EvidenceService
from ..frameworks.operations import OperationsService
from ..frameworks.assessment import AssessmentService
from ..frameworks.controls import catalogue_coverage
from ..frameworks.registry import FrameworkRegistry
from ..platform.search import SearchClient
from .base import CAP_MANAGE_CONTENT, CAP_ASSESS, Request, Response, Handler, _int
from .routes_deployment import _operational_map

if TYPE_CHECKING:
    from .app import Context


def _levels(ctx: "Context", req: Request) -> Tuple[Dict[str, Dict[str, Any]], Optional[Dict[str, Any]]]:
    operational, health = None, None
    if req.arg("operational") == "1":
        operational, health = _operational_map(ctx, _int(req.arg("hours"), 24, "hours"))
    domain = req.arg("domain")
    if domain and domain not in DASHBOARD_DOMAINS:
        raise ValidationError("invalid domain")
    elsewhere = ExternalMatchService(ctx.records(), ctx.audit).elsewhere()
    return CoverageService(ctx.store).use_case_levels(operational, domain, elsewhere), health


def get_frameworks(ctx: "Context", req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    levels, _ = _levels(ctx, req)
    return Response(200, {"definitions": registry.list(),
                          "coverage": CoverageService(ctx.store).frameworks_summary(levels),
                          "use_cases": len(levels),
                          "features": {"compliance": ctx.config.get_bool("features", "compliance", False)}})


def _attack_definition(registry: FrameworkRegistry, req: Request) -> Dict[str, Any]:
    definition = registry.get(req.arg("framework_id", "mitre_attack_enterprise"), req.arg("version"))
    if definition.get("kind") == "controls":
        raise ValidationError("this is a control catalogue, not an ATT&CK matrix; use frameworks/catalogue")
    return definition


def get_framework_catalogue(ctx: "Context", req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    framework_id = req.arg("framework_id")
    if not framework_id:
        raise ValidationError("framework_id is required")
    definition = registry.get(framework_id, req.arg("version"))
    if definition.get("kind") != "controls":
        raise ValidationError("this framework has no control catalogue")
    levels, _ = _levels(ctx, req)
    out = catalogue_coverage(definition, levels)
    out["versions"] = [{"version": v, "label": registry.get(framework_id, v).get("version_label", v)}
                       for v in registry.versions(framework_id)]
    out["active_version"] = registry.active_versions().get(framework_id)
    return Response(200, out)


def _compliance_module(handler: Handler) -> Handler:
    """The assessment, POA&M and snapshot routes exist only while ``[features] compliance`` is on (D-085)."""
    def guarded(ctx: "Context", req: Request) -> Response:
        ctx.require_feature("compliance")
        return handler(ctx, req)
    return guarded


def _assessment_scope(ctx: "Context", framework_id: Any, version: Any) -> Tuple[AssessmentService, Dict[str, Any]]:
    ctx.require(CAP_ASSESS)
    framework_id = str(framework_id or "")
    if not framework_id:
        raise ValidationError("framework_id is required")
    definition = FrameworkRegistry(ctx.records()).get(framework_id, str(version or ""))
    if definition.get("kind") != "controls":
        raise ValidationError("this framework has no control catalogue")
    return AssessmentService(ctx.records(), ctx.audit), definition


def get_assessment(ctx: "Context", req: Request) -> Response:
    svc, definition = _assessment_scope(ctx, req.arg("framework_id"), req.arg("version"))
    out = svc.view(definition)
    out["catalogue"] = {k: definition.get(k, "") for k in ("framework_id", "name", "version", "version_label")}
    return Response(200, out)


def get_assessment_control(ctx: "Context", req: Request) -> Response:
    svc, definition = _assessment_scope(ctx, req.arg("framework_id"), req.arg("version"))
    control_id = req.arg("control_id")
    control = next((c for c in definition["controls"] if c["id"] == control_id), None)
    if control is None:
        raise NotFoundError("no such control in this catalogue version")
    doc = svc.docs(definition["framework_id"]).get(control_id)
    return Response(200, {"control": control, "assessment": svc.public(doc, definition["version"]) if doc else None})


def post_assessment(ctx: "Context", req: Request) -> Response:
    body = req.json()
    svc, definition = _assessment_scope(ctx, body.get("framework_id"), body.get("version"))
    saved = svc.set(ctx.user, definition, str(body.get("control_id") or ""), str(body.get("status") or ""),
                    body.get("note"), body.get("objectives"))
    docs = svc.docs(definition["framework_id"])
    return Response(200, {"assessment": saved, "summary": svc.summary(definition, docs), "score": svc.score(definition, docs)})


def post_assessment_clear(ctx: "Context", req: Request) -> Response:
    body = req.json()
    svc, definition = _assessment_scope(ctx, body.get("framework_id"), body.get("version"))
    out = svc.clear(ctx.user, definition, str(body.get("control_id") or ""), body.get("note"))
    docs = svc.docs(definition["framework_id"])
    return Response(200, dict(out, summary=svc.summary(definition, docs), score=svc.score(definition, docs)))


def get_poam(ctx: "Context", req: Request) -> Response:
    svc, definition = _assessment_scope(ctx, req.arg("framework_id"), req.arg("version"))
    return Response(200, svc.poam_list(definition["framework_id"], req.args("state"), req.arg("control_id"),
                                       req.arg("overdue") == "1", _int(req.arg("offset"), 0, "offset"),
                                       _int(req.arg("count"), 100, "count"), definition))


def post_poam(ctx: "Context", req: Request) -> Response:
    body = req.json()
    svc, definition = _assessment_scope(ctx, body.get("framework_id"), body.get("version"))
    return Response(200, {"item": svc.poam_create(ctx.user, definition, body)})


def _poam_action(action: str) -> Handler:
    def handler(ctx: "Context", req: Request) -> Response:
        ctx.require(CAP_ASSESS)
        body = req.json()
        svc = AssessmentService(ctx.records(), ctx.audit)
        item_id = str(body.get("id") or "")
        if action == "update":
            return Response(200, {"item": svc.poam_update(ctx.user, item_id, body)})
        if action == "close":
            return Response(200, {"item": svc.poam_close(ctx.user, item_id, str(body.get("resolution") or "closed"), body.get("note"))})
        return Response(200, {"item": svc.poam_reopen(ctx.user, item_id, body.get("note"))})
    return handler


def post_assessment_snapshot(ctx: "Context", req: Request) -> Response:
    body = req.json()
    svc, definition = _assessment_scope(ctx, body.get("framework_id"), body.get("version"))
    levels, _ = _levels(ctx, req)
    coverage = catalogue_coverage(definition, levels)
    use_cases = {u["content_id"]: u for u in levels.values()}
    return Response(200, {"snapshot": svc.snapshot(ctx.user, definition, coverage, use_cases, str(body.get("label") or ""))})


def get_assessment_snapshots(ctx: "Context", req: Request) -> Response:
    svc, definition = _assessment_scope(ctx, req.arg("framework_id"), req.arg("version"))
    return Response(200, {"items": svc.snapshots(definition["framework_id"])})


def get_assessment_snapshot(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_ASSESS)
    return Response(200, AssessmentService(ctx.records(), ctx.audit).snapshot_get(req.arg("id")))


def get_framework_matrix(ctx: "Context", req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    definition = _attack_definition(registry, req)
    levels, health = _levels(ctx, req)
    out = CoverageService(ctx.store).attack_matrix(definition, levels)
    out["versions"] = registry.versions(definition["framework_id"])
    out["active_version"] = registry.active_versions().get(definition["framework_id"])
    out["operational"] = None if health is None else {"available": health["available"], "reason": health["reason"],
                                                      "hours": health["hours"], "counts": health["counts"]}
    return Response(200, out)


def get_framework_navigator(ctx: "Context", req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    definition = _attack_definition(registry, req)
    levels, health = _levels(ctx, req)
    cov = CoverageService(ctx.store)
    layer = cov.navigator_layer(cov.attack_matrix(definition, levels), bool(health and health["available"]))
    return Response(200, {"layer": layer, "filename": "attack-layer-%s-%s.json" % (
        definition["framework_id"], definition["version"])})


def get_framework_technique(ctx: "Context", req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    definition = _attack_definition(registry, req)
    tid = req.arg("id")
    if not any(t["id"] == tid for t in definition["techniques"]):
        raise ValidationError("unknown technique for this framework version")
    levels, _ = _levels(ctx, req)
    return Response(200, {"id": tid, "use_cases": CoverageService(ctx.store).technique_use_cases(
        definition, tid, levels)})


def get_framework_controls(ctx: "Context", req: Request) -> Response:
    framework = req.arg("framework")
    if not framework or len(framework) > 200:
        raise ValidationError("framework is required")
    levels, _ = _levels(ctx, req)
    return Response(200, {"framework": framework,
                          "controls": CoverageService(ctx.store).framework_controls(framework, levels)})


def _regulation(req: Request) -> str:
    framework = req.arg("framework")
    if not framework.startswith("regulation:") or len(framework) > 200:
        raise ValidationError("framework must be a regulation:<id> framework")
    return framework


def get_framework_clause(ctx: "Context", req: Request) -> Response:
    framework, clause = _regulation(req), req.arg("clause")
    if not clause or len(clause) > 200:
        raise ValidationError("clause is required")
    levels, _ = _levels(ctx, req)
    rows = EvidenceService(ctx.store).rows(framework, levels, clause)
    return Response(200, {"framework": framework, "clause": clause, "use_cases": rows})


def get_framework_evidence(ctx: "Context", req: Request) -> Response:
    framework, clause = _regulation(req), req.arg("clause")
    if len(clause) > 200:
        raise ValidationError("clause is too long")
    levels, _ = _levels(ctx, req)
    return Response(200, EvidenceService(ctx.store).pack(framework, levels, req.arg("format", "json"), clause))


def post_framework_import(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    summary = FrameworkRegistry(ctx.records()).import_definition(req.body, ctx.user)
    ctx.audit.record(ctx.user, "framework.imported", "framework", summary["framework_id"],
                     details={"version": summary["version"], "techniques": summary["techniques"],
                                "controls": summary.get("controls", 0)})
    return Response(200, {"definition": summary})


def post_framework_activate(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    body = req.json()
    out = FrameworkRegistry(ctx.records()).activate(str(body.get("framework_id") or ""),
                                                    str(body.get("version") or ""), ctx.user)
    ctx.audit.record(ctx.user, "framework.activated", "framework", out["framework_id"],
                     details={"version": out["version"]})
    return Response(200, out)


def get_operations(ctx: "Context", req: Request) -> Response:
    return Response(200, OperationsService(ctx.store, SearchClient(ctx.user_transport)).health(
        _int(req.arg("hours"), 24, "hours")))

"""Frameworks, control catalogues, ATT&CK matrix and regulation evidence routes."""

import json
from typing import Any, Dict, Optional, TYPE_CHECKING, Tuple

from ..discovery.external import ExternalMatchService
from ..discovery.query import coverage
from ..dashboards.templates import DOMAINS as DASHBOARD_DOMAINS
from ..errors import NotFoundError, ValidationError
from ..frameworks.coverage import CoverageService
from ..frameworks.evidence import EvidenceService
from ..frameworks.operations import OperationsService
from ..frameworks.controls import catalogue_coverage
from ..frameworks.registry import FrameworkRegistry
from ..platform.search import SearchClient
from .base import CAP_MANAGE_CONTENT, Request, Response, _int
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
                          "use_cases": len(levels)})


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

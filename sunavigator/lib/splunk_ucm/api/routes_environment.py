"""Inventory, discovery, mapping, readiness and selection routes."""

import dataclasses
from typing import TYPE_CHECKING

from ..discovery.health import environment_health
from ..discovery.mapping import MappingService
from ..discovery.query import InventoryFilter, InventoryQueryService, coverage
from ..discovery.service import new_job as new_discovery_job
from ..errors import ValidationError
from ..readiness.principal import read_principal
from ..readiness.query import ReadinessFilter, ReadinessQueryService
from ..readiness.recommend import MAX_ITEMS as MAX_RECOMMENDATIONS, RecommendationService
from ..readiness.service import new_job as new_readiness_job
from .base import CAP_RUN_DISCOVERY, Request, Response, _int, _bool

if TYPE_CHECKING:
    from .app import Context


def get_inventory(ctx: "Context", req: Request) -> Response:
    f = InventoryFilter(
        kind=req.arg("kind", "pair"), status=req.arg("status", "active"), q=req.arg("q").strip(),
        index=req.arg("index").strip(), sourcetype=req.arg("sourcetype").strip(),
        stale_hours=_int(req.arg("stale_hours"), 0, "stale_hours"),
        sort=req.arg("sort", "count"), offset=_int(req.arg("offset"), 0, "offset"),
        count=_int(req.arg("count"), 25, "count"), with_total=req.arg("total", "1") != "0")
    max_page = ctx.config.get_int("catalog", "max_page_size", 100, 10, 500)
    return Response(200, InventoryQueryService(ctx.store, max_page).search(f))


def get_inventory_coverage(ctx: "Context", req: Request) -> Response:
    return Response(200, coverage(ctx.store))


def get_environment_health(ctx: "Context", req: Request) -> Response:
    return Response(200, environment_health(ctx.store))


def get_discovery(ctx: "Context", req: Request) -> Response:
    svc = ctx.discovery_service()
    return Response(200, {
        "state": svc.state.state(),
        "jobs": svc.state.jobs(limit=_int(req.arg("limit"), 20, "limit")),
        "settings": {
            "earliest": ctx.config.get("discovery", "earliest", "-7d"),
            "latest": ctx.config.get("discovery", "latest", "now"),
            "include_internal": ctx.config.get_bool("discovery", "include_internal", False),
            "max_pairs": ctx.config.get_int("discovery", "max_pairs", 5000, 100, 20000),
        },
    })


def post_discovery(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    include = body.get("include_internal")
    if include is not None:
        include = _bool(include)
    earliest = str(body.get("earliest") or "")
    latest = str(body.get("latest") or "")
    job = new_discovery_job(ctx.user, include_internal=include, earliest=earliest, latest=latest)
    ctx.discovery_service().enqueue(job)
    return Response(202, {"job": job})


def get_mappings(ctx: "Context", req: Request) -> Response:
    kind = req.arg("kind")
    origin = req.arg("origin")
    offset = _int(req.arg("offset"), 0, "offset")
    count = max(1, min(200, _int(req.arg("count"), 50, "count")))
    rows = MappingService(ctx.store).repo.list(kind or None, origin or None, offset, count + 1)
    return Response(200, {"items": rows[:count], "offset": offset, "count": min(count, len(rows[:count])),
                          "has_more": len(rows) > count})


def post_mappings(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    doc = ctx.mapping_service().upsert_local(
        str(body.get("kind") or ""), str(body.get("value") or ""),
        str(body.get("canonical_value") or body.get("value") or ""), ctx.user,
        str(body.get("notes") or ""), str(body.get("confidence") or "high"))
    ctx.audit.record(ctx.user, "discovery.mapping.upsert", "mapping", doc["_key"],
                     details={"kind": doc["kind"], "value": doc["value"]})
    return Response(200, {"mapping": doc})


def post_mappings_delete(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    ctx.mapping_service().delete_local(str(body.get("kind") or ""), str(body.get("value") or ""),
                                           ctx.user)
    ctx.audit.record(ctx.user, "discovery.mapping.delete", "mapping",
                     "%s:%s" % (body.get("kind"), body.get("value")))
    return Response(200, {"deleted": True})


def get_readiness(ctx: "Context", req: Request) -> Response:
    f = ReadinessFilter(
        states=req.args("state"), data_states=req.args("data_state"), domains=req.args("domain"), criticality=req.args("criticality"),
        category_keys=req.args("category"), q=req.arg("q").strip(), sort=req.arg("sort", "score"),
        offset=_int(req.arg("offset"), 0, "offset"), count=_int(req.arg("count"), 25, "count"),
        with_total=req.arg("total", "1") != "0")
    max_page = ctx.config.get_int("catalog", "max_page_size", 100, 10, 500)
    return Response(200, ReadinessQueryService(ctx.store, max_page).search(f))


def get_readiness_summary(ctx: "Context", req: Request) -> Response:
    svc = ctx.readiness_service()
    out = ReadinessQueryService(ctx.store).summary()
    out["state"] = svc.state()
    out["jobs"] = svc.jobs(limit=10)
    discovery = ctx.discovery_service().state.state()
    out["discovery_completed_at"] = discovery.get("last_completed_at")
    out["settings"] = dataclasses.asdict(svc.settings)
    owner = ctx.config.get("deployment", "scheduled_owner", "").strip()
    scheduler = read_principal(ctx.system_transport, owner).summary()
    scheduler["discovery_include_internal"] = bool(discovery.get("include_internal")) \
        if discovery.get("last_completed_at") else None
    out["scheduler"] = scheduler
    return Response(200, out)


def get_readiness_recommendations(ctx: "Context", req: Request) -> Response:
    completed = ctx.discovery_service().state.state().get("last_completed_at")
    return Response(200, RecommendationService(ctx.store).recommend(
        ctx.user, completed, _int(req.arg("count"), MAX_RECOMMENDATIONS, "count"),
        req.args("exclude_quality")))


def get_readiness_usecase(ctx: "Context", req: Request) -> Response:
    doc = ctx.readiness_service().get(req.arg("id"))
    if doc is None:
        return Response(404, {"error": {"code": "not_assessed", "message": "use case has not been assessed"}})
    return Response(200, doc)


def post_readiness(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    job = ctx.readiness_service().enqueue(new_readiness_job(ctx.user))
    return Response(202, {"job": job})


def get_selections(ctx: "Context", req: Request) -> Response:
    return Response(200, ctx.selection_service().list_for(
        ctx.user, req.arg("intent") or None, _int(req.arg("offset"), 0, "offset"),
        _int(req.arg("count"), 50, "count")))


def post_selections(ctx: "Context", req: Request) -> Response:
    body = req.json()
    doc = ctx.selection_service().upsert(
        ctx.user, str(body.get("id") or body.get("content_id") or ""),
        str(body.get("intent") or ""), str(body.get("notes") or ""),
        _int(str(body.get("priority") if body.get("priority") is not None else "50"), 50, "priority"))
    return Response(200, {"selection": doc})


def post_selections_delete(ctx: "Context", req: Request) -> Response:
    body = req.json()
    ctx.selection_service().delete(ctx.user, str(body.get("id") or body.get("content_id") or ""))
    return Response(200, {"deleted": True})


def get_validation(ctx: "Context", req: Request) -> Response:
    doc = ctx.validation_service().get(req.arg("id"))
    if doc is None:
        return Response(404, {"error": {"code": "not_validated", "message": "use case has not been validated"}})
    return Response(200, doc)


def post_validate(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    use_case_id = str(body.get("id") or req.arg("id") or "")
    if not use_case_id:
        raise ValidationError("id is required")
    sample = body.get("sample", True)
    if sample is True or str(sample).lower() in ("1", "true"):
        return Response(200, ctx.validation_service().sample_and_assess(use_case_id, ctx.user))
    return Response(200, ctx.validation_service().parse_only(use_case_id, ctx.user))


def post_preview(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    use_case_id = str(body.get("id") or req.arg("id") or "")
    if not use_case_id:
        raise ValidationError("id is required")
    return Response(200, ctx.validation_service().preview(
        use_case_id, ctx.user, str(body.get("earliest") or ""), str(body.get("latest") or "")))


def post_readiness_assess(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    use_case_id = str(body.get("id") or req.arg("id") or "")
    if not use_case_id:
        raise ValidationError("id is required")
    return Response(200, ctx.readiness_service().assess_one(use_case_id, ctx.user))

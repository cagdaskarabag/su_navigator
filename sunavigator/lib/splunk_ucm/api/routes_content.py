"""Catalogue, use-case, content-source and audit routes."""

from typing import Any, Dict, TYPE_CHECKING

from ..catalog.derived import get_facets
from ..catalog.detail import UseCaseDetailService, key_from_id
from ..catalog.query import DEFAULT_KV_ROW_LIMIT, DEFAULT_MAX_JOIN_KEYS, CatalogFilter, CatalogQueryService
from ..content.importer import BundleImportService
from ..content.fenre.provider import check_ref_name, parse_allowed_refs
from ..content.reindex import ReindexService
from ..content.reindex_job import ReindexJobs
from ..content.sync import new_job
from ..discovery.external import ExternalMatchService
from ..discovery.overlay import attach_environment
from ..errors import PermissionDenied, UnsupportedOperation, ValidationError
from ..platform.capabilities import PlatformProbe
from ..platform.security_content import handoff_for
from ..secrets import get_secret
from ..storage.repositories import CategoryRepository, ContentRepository, SyncStateRepository
from .base import CAP_MANAGE_CONTENT, CAP_ADMIN, CAP_RUN_DISCOVERY, Request, Response, _int, _bool
from .routes_deployment import _deployment_view

if TYPE_CHECKING:
    from .app import Context


def get_catalog(ctx: "Context", req: Request) -> Response:
    f = CatalogFilter(
        q=req.arg("q").strip(), domains=req.args("domain"), category_keys=req.args("category"),
        criticality=req.args("criticality"), difficulty=req.args("difficulty"),
        sourcetype=req.arg("sourcetype").strip(), mitre=req.arg("mitre").strip().upper(),
        quality=req.args("quality"), review=req.args("review"), regulation=req.args("regulation"),
        providers=req.args("provider"), waves=req.args("wave"), maturities=req.args("maturity"), stories=req.args("story"),
        data_sources=req.args("data_source"), exclude_quality=req.args("exclude_quality"),
        availability=req.args("availability"), bookmarked=req.arg("bookmarked") == "1",
        provider_status=req.arg("status", "active"), sort=req.arg("sort", "id"),
        offset=_int(req.arg("offset"), 0, "offset"), count=_int(req.arg("count"), 25, "count"),
        with_total=req.arg("total", "1") != "0")
    max_page = ctx.config.get_int("catalog", "max_page_size", 100, 10, 500)
    join_keys = ctx.config.get_int("catalog", "max_join_keys", DEFAULT_MAX_JOIN_KEYS, 1, 5000)
    row_limit = _kv_row_limit(ctx)
    return Response(200, CatalogQueryService(ctx.store, max_page, max_join_keys=join_keys, max_scan=row_limit - 1,
                                             kv_row_limit=row_limit).search(f, ctx.user))


def _kv_row_limit(ctx: "Context") -> int:
    return ctx.config.get_int("catalog", "kv_row_limit", DEFAULT_KV_ROW_LIMIT, 1000, 10000000)


def get_catalog_facets(ctx: "Context", req: Request) -> Response:
    return Response(200, get_facets(ctx.store))


def get_usecase(ctx: "Context", req: Request) -> Response:
    service = UseCaseDetailService(ContentRepository(ctx.store), CategoryRepository(ctx.store))
    detail = attach_environment(service.get(req.arg("id")), ctx.store)
    readiness = ctx.readiness_service().get(req.arg("id"))
    detail["readiness"] = readiness
    detail["requirement_summary"]["assessment"] = readiness["state"] if readiness else "not_assessed"
    detail["selection"] = ctx.selection_service().for_use_case(ctx.user, req.arg("id"))
    detail["validation"] = ctx.validation_service().get(req.arg("id"))
    detail["interactive_search"] = {"enabled": ctx.config.get_bool("interactive_search", "enabled", True)}
    detail["escu_handoff"] = handoff_for(ctx.security_content(), detail["provenance"]["provider"],
                                         detail["provenance"]["provider_record_id"], detail["title"],
                                         detail.get("provider_extras") or {})
    svc = ctx.deployment_service()
    detail["deployment"] = _deployment_view(ctx, svc, svc.get(req.arg("id")))
    detail["external"] = _external_for(ctx, req.arg("id"))
    return Response(200, detail)


def _external_for(ctx: "Context", use_case_id: str) -> Dict[str, Any]:
    """Accepted and proposed matches for one use case; search names only for people who may manage discovery."""
    key = key_from_id(use_case_id)
    service = ExternalMatchService(ctx.records(), ctx.audit)
    accepted = service.for_content(key) if key else []
    out: Dict[str, Any] = {"enabled": sum(1 for m in accepted if m["enabled"]), "accepted": len(accepted),
                           "proposed": service.proposals_for(key) if key else 0, "matches": None}
    if CAP_RUN_DISCOVERY in ctx.capabilities() or CAP_ADMIN in ctx.capabilities():
        out["matches"] = accepted
    return out


def get_external(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    return Response(200, ExternalMatchService(ctx.records(), ctx.audit).list(
        req.arg("state"), _int(req.arg("offset"), 0, "offset"), _int(req.arg("count"), 50, "count")))


def post_external(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    row = ExternalMatchService(ctx.records(), ctx.audit).decide(
        ctx.user, str(body.get("id") or ""), str(body.get("decision") or ""), str(body.get("content_key") or ""))
    return Response(200, {"match": row})


def get_categories(ctx: "Context", req: Request) -> Response:
    return Response(200, {"categories": CategoryRepository(ctx.store).list()})


def get_sync(ctx: "Context", req: Request) -> Response:
    repo = SyncStateRepository(ctx.store)
    provider = req.arg("provider", "fenre")
    return Response(200, {
        "provider_state": repo.provider_state(provider),
        "jobs": repo.jobs(limit=_int(req.arg("limit"), 20, "limit")),
        "remote_sync_enabled": ctx.config.get_bool("provider:" + provider, "remote_sync_enabled", True),
        "configured_ref": ctx.config.get("provider:" + provider, "ref", "main"),
        "allowed_refs": list(_allowed_refs(ctx)),
        "kv_row_limit": _kv_row_limit(ctx),
    })


def _allowed_refs(ctx: "Context"):
    return parse_allowed_refs(ctx.config.get("provider:fenre", "allowed_refs", "main"),
                              ctx.config.get("provider:fenre", "ref", "main"))


def _provider_token(ctx: "Context") -> str:
    if ctx.system_transport is None:
        return ""
    return get_secret(ctx.system_transport, "github_token") or ""


def post_sync(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    body = req.json()
    provider = body.get("provider", "fenre")
    if provider != "fenre":
        raise ValidationError("unsupported provider")
    if not ctx.config.get_bool("provider:fenre", "remote_sync_enabled", True):
        raise UnsupportedOperation("remote synchronization is disabled; use offline import")
    cats = body.get("categories") or []
    if not isinstance(cats, list) or not all(isinstance(c, (str, int)) for c in cats) or len(cats) > 100:
        raise ValidationError("categories must be a list of category ids")
    ref = str(body.get("ref") or "")
    if ref and (len(ref) > 200 or not all(ch.isalnum() or ch in "._/-" for ch in ref)):
        raise ValidationError("invalid ref")
    if ref:
        check_ref_name(ref, _allowed_refs(ctx))
    job = new_job(ctx.user, provider, [str(c) for c in cats], ref=ref, source="manual",
                  allow_schema_change=_bool(body.get("allow_schema_change")), force=_bool(body.get("force")))
    ctx.sync_service().enqueue(job)
    return Response(202, {"job": job})


def get_manifest(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    if not ctx.config.get_bool("provider:fenre", "remote_sync_enabled", True):
        raise UnsupportedOperation("remote synchronization is disabled; use offline import")
    if req.arg("ref"):
        check_ref_name(req.arg("ref"), _allowed_refs(ctx))
    provider = ctx.provider_factory("fenre", ctx.config.provider_settings("fenre"), _provider_token(ctx),
                                    req.arg("ref"))
    manifest = provider.get_manifest()
    ctx.audit.record(ctx.user, "content.provider.manifest_viewed", "provider", "fenre",
                     details={"source_ref": manifest.source_ref, "version": manifest.provider_version})
    return Response(200, manifest.summary())


def post_import(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    max_mb = ctx.config.get_int("import", "max_bundle_mb", 50, 1, 500)
    cats = req.args("categories")
    service = BundleImportService(ctx.sync_service(), max_mb * 1024 * 1024)
    job = service.import_bytes(req.body, ctx.user, _bool(req.arg("allow_schema_change")), cats or None)
    return Response(200, {"job": job})


def post_reindex(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    if req.arg("background") == "1":
        job = ReindexJobs(ctx.records()).enqueue(ctx.user, req.arg("category") or "")
        ctx.audit.record(ctx.user, "content.reindex.queued", "catalog", req.arg("category") or "*")
        return Response(200, {"job": job})
    result = ReindexService(ctx.store).reindex(req.arg("category") or None)
    ctx.audit.record(ctx.user, "content.reindex", "catalog", req.arg("category") or "*", details=result)
    return Response(200, result)


def get_reindex(ctx: "Context", req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    return Response(200, {"job": ReindexJobs(ctx.records()).current()})


def get_platform(ctx: "Context", req: Request) -> Response:
    report = PlatformProbe(ctx.user_transport).report(
        ctx.config.get_bool("provider:fenre", "remote_sync_enabled", True))
    out = report.to_dict()
    overview = ctx.security_content().overview()
    out["security_content"] = {"es": overview["es"], "escu": overview["escu"], "read_at": overview["read_at"],
                               "note": "Read-only presence check with the app's system session. Behaviour with ES "
                                       "installed is unvalidated (no ES lab)."}
    return Response(200, out)


def get_audit(ctx: "Context", req: Request) -> Response:
    caps = ctx.capabilities()
    if CAP_ADMIN not in caps and CAP_MANAGE_CONTENT not in caps:
        raise PermissionDenied("missing capability %s" % CAP_ADMIN)
    limit = max(1, min(200, _int(req.arg("limit"), 50, "limit")))
    return Response(200, {"events": ctx.audit.recent(limit, req.arg("prefix"))})


def post_audit_verify(ctx: "Context", req: Request) -> Response:
    caps = ctx.capabilities()
    if CAP_ADMIN not in caps and CAP_MANAGE_CONTENT not in caps:
        raise PermissionDenied("missing capability %s" % CAP_ADMIN)
    result = ctx.audit.verify_chain()
    window = ctx.config.get_int("audit", "verify_window_seconds", 300, 0, 3600)
    if not result["ok"] or not ctx.audit.written_within("audit.verified", "*", window):
        ctx.audit.record(ctx.user, "audit.verified", "audit", "*", outcome="success" if result["ok"] else "failure",
                         details={"rows": result["rows"], "modified": result["modified_count"],
                                  "missing": result["missing_count"], "restarts": result["restart_count"],
                                  "head": result["head"]})
    return Response(200, result)

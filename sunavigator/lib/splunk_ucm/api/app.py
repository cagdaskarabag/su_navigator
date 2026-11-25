"""REST API routing and handlers (transport-independent).

Authorization model (docs/DECISIONS.md D-011):
* All reads/writes use the **caller's** token, so KV Store ACLs apply.
* Write endpoints additionally require an app capability.
* The system token is used only to append audit records and to read the
  provider secret for capability-gated operations.
"""

import dataclasses
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import APP_NAME
from ..audit import AuditService
from ..catalog.derived import get_facets
from ..catalog.detail import UseCaseDetailService
from ..catalog.query import DEFAULT_KV_ROW_LIMIT, DEFAULT_MAX_JOIN_KEYS, CatalogFilter, CatalogQueryService
from ..config import AppConfig, load_config
from ..content.importer import BundleImportService
from ..content.fenre.provider import check_ref_name, parse_allowed_refs
from ..content.registry import remote_provider
from ..content.reindex import ReindexService
from ..content.sync import SyncService, SyncSettings, new_job
from ..discovery.health import environment_health
from ..discovery.inventory import SplunkInventory
from ..discovery.mapping import MappingService
from ..discovery.overlay import attach_environment
from ..discovery.query import InventoryFilter, InventoryQueryService, coverage
from ..discovery.service import DiscoveryService, new_job as new_discovery_job
from ..discovery.worker import settings_from_config
from ..dashboards.service import DashboardService, ViewClient
from ..dashboards.templates import DOMAINS as DASHBOARD_DOMAINS
from ..deployment.controltest import DEFAULT_TEST_INDEX, splunk_runner
from ..deployment.savedsearch import SavedSearchClient
from ..deployment.service import DeploymentService
from ..deployment.worker import settings_from_config as deployment_settings
from ..errors import PermissionDenied, UcmError, UnsupportedOperation, ValidationError
from ..frameworks.coverage import CoverageService
from ..frameworks.evidence import EvidenceService
from ..frameworks.operations import OperationsService
from ..frameworks.registry import FrameworkRegistry
from ..platform.search import SearchClient
from ..readiness.principal import SchedulerAccess, read_principal
from ..readiness.query import ReadinessFilter, ReadinessQueryService
from ..readiness.recommend import MAX_ITEMS as MAX_RECOMMENDATIONS, RecommendationService
from ..readiness.service import ReadinessService, new_job as new_readiness_job
from ..readiness.worker import settings_from_config as readiness_settings
from ..selection.service import SelectionService
from ..spl.policy import parse_extra_safe
from ..validation.service import ValidationService, ValidationSettings
from ..log import get_logger
from ..platform.capabilities import PlatformProbe
from ..platform.security_content import SecurityContentReader, deploy_record, handoff_for
from ..secrets import get_secret
from ..storage.kvstore import DocumentStore, KVStore
from ..storage.repositories import CategoryRepository, ContentRepository, SyncStateRepository
from ..storage.transport import SplunkdTransport

log = get_logger(__name__)

CAP_MANAGE_CONTENT = "ucm_manage_content"
CAP_ADMIN = "ucm_admin"
CAP_RUN_DISCOVERY = "ucm_run_discovery"
CAP_DEPLOY = "ucm_deploy"


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


class Context:
    """Per-request service wiring."""

    def __init__(self, user_transport: SplunkdTransport, system_transport: Optional[SplunkdTransport],
                 user: str, store: Optional[DocumentStore] = None, audit_store: Optional[DocumentStore] = None,
                 config: Optional[AppConfig] = None,
                 provider_factory: Optional[Callable[..., Any]] = None,
                 record_store: Optional[DocumentStore] = None, view_client: Optional[Any] = None):
        self.user = user
        self.record_store = record_store
        self.view_client = view_client
        self.user_transport = user_transport
        self.system_transport = system_transport
        self.store = store or KVStore(user_transport)
        audit_backend = audit_store or (KVStore(system_transport) if system_transport else self.store)
        self.audit = AuditService(audit_backend)
        self._config = config
        self._caps: Optional[List[str]] = None
        self.provider_factory = provider_factory or remote_provider

    @property
    def config(self) -> AppConfig:
        if self._config is None:
            self._config = load_config(self.user_transport)
        return self._config

    def capabilities(self) -> List[str]:
        if self._caps is None:
            self._caps = PlatformProbe(self.user_transport).user_capabilities()
        return self._caps

    def require(self, capability: str) -> None:
        if capability not in self.capabilities():
            raise PermissionDenied("missing capability %s" % capability)

    def sync_service(self) -> SyncService:
        cfg = self.config
        settings = SyncSettings(
            fetch_concurrency=cfg.get_int("provider:fenre", "fetch_concurrency", 4, 1, 16),
            max_invalid_ratio=cfg.get_float("sync", "max_invalid_ratio", 0.2, 0.0, 1.0),
            job_timeout_seconds=cfg.get_int("sync", "job_timeout_seconds", 3600, 60, 86400))
        return SyncService(self.records(), self.audit, settings)

    def discovery_service(self) -> DiscoveryService:
        return DiscoveryService(
            self.records(), self.audit, SplunkInventory(self.user_transport),
            SearchClient(self.user_transport), settings_from_config(self.config))

    def readiness_service(self) -> ReadinessService:
        return ReadinessService(self.records(), self.audit, readiness_settings(self.config),
                                principal_reader=lambda owner: read_principal(self.system_transport, owner))

    def security_content(self) -> SecurityContentReader:
        return SecurityContentReader(self.system_transport)

    def mapping_service(self) -> MappingService:
        return MappingService(self.records())

    def selection_service(self) -> SelectionService:
        # Selections are written only through this handler path, with the system token (D-062);
        # the service takes the user from the session and touches only that user's rows.
        return SelectionService(self.records(), self.audit)

    def validation_service(self) -> ValidationService:
        cfg = self.config
        settings = ValidationSettings(
            earliest=cfg.get("validation", "earliest", "-15m") or "-15m",
            latest=cfg.get("validation", "latest", "now") or "now",
            preview_max=cfg.get_int("validation", "preview_max_events", 50, 1, 200),
            preview_timeout=cfg.get_int("validation", "preview_timeout_seconds", 30, 5, 120),
            sample_events=cfg.get_int("validation", "sample_events", 200, 10, 1000),
            sample_timeout=cfg.get_int("validation", "sample_timeout_seconds", 30, 5, 120),
            sample_window_minutes=cfg.get_int("validation", "sample_window_minutes", 60, 1, 10080),
            extra_safe_commands=parse_extra_safe(cfg.get("spl", "extra_safe_commands", "")))
        return ValidationService(self.records(), self.audit, SearchClient(self.user_transport),
                                 settings, self.readiness_service())

    def records(self) -> DocumentStore:
        """Store for admin-write-only collections (D-039). Handlers write through it only after
        their capability check; searches still run with the caller's session."""
        return self.record_store or (KVStore(self.system_transport) if self.system_transport else self.store)

    def deployment_service(self) -> DeploymentService:
        # Workflow records go through the system token (uc_deployments is admin-write only);
        # saved searches are written with the caller's session (D-028, D-029).
        owner = self.config.get("deployment", "scheduled_owner", "").strip()
        writer = self.system_transport or self.user_transport
        test_index = self.config.get("controltest", "index", DEFAULT_TEST_INDEX).strip() or DEFAULT_TEST_INDEX
        runner = splunk_runner(writer, SearchClient(self.user_transport), APP_NAME, test_index)
        reader = self.security_content()
        return DeploymentService(self.records(), self.audit, SearchClient(self.user_transport),
                                 SavedSearchClient(writer, owner=owner), deployment_settings(self.config),
                                 control_runner=runner,
                                 access=SchedulerAccess(self.records(), self.system_transport, owner),
                                 handoff=lambda uc: deploy_record(handoff_for(
                                     reader, uc.provenance.provider, uc.provenance.provider_record_id, uc.title,
                                     uc.provider_extras)))

    def dashboard_service(self) -> DashboardService:
        views = ViewClient(self.system_transport) if self.system_transport else self.view_client
        return DashboardService(self.records(), self.audit, views)


Handler = Callable[[Context, Request], Response]


class Router:
    def __init__(self) -> None:
        self.routes: Dict[Tuple[str, str], Handler] = {}

    def add(self, method: str, path: str, handler: Handler) -> None:
        self.routes[(method, path)] = handler

    def dispatch(self, ctx: Context, req: Request) -> Response:
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
            return Response(exc.http_status, {"error": exc.to_dict()})
        except Exception:
            log.exception("unhandled error", extra={"path": path})
            return Response(500, {"error": {"code": "internal_error", "message": "internal error"}})


# -- handlers ---------------------------------------------------------------

def get_catalog(ctx: Context, req: Request) -> Response:
    f = CatalogFilter(
        q=req.arg("q").strip(), domains=req.args("domain"), category_keys=req.args("category"),
        criticality=req.args("criticality"), difficulty=req.args("difficulty"),
        sourcetype=req.arg("sourcetype").strip(), mitre=req.arg("mitre").strip().upper(),
        quality=req.args("quality"), review=req.args("review"), regulation=req.args("regulation"),
        providers=req.args("provider"), waves=req.args("wave"), stories=req.args("story"),
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


def _kv_row_limit(ctx: Context) -> int:
    return ctx.config.get_int("catalog", "kv_row_limit", DEFAULT_KV_ROW_LIMIT, 1000, 10000000)


def get_catalog_facets(ctx: Context, req: Request) -> Response:
    return Response(200, get_facets(ctx.store))


def get_usecase(ctx: Context, req: Request) -> Response:
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
    return Response(200, detail)


def get_categories(ctx: Context, req: Request) -> Response:
    return Response(200, {"categories": CategoryRepository(ctx.store).list()})


def get_sync(ctx: Context, req: Request) -> Response:
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


def _allowed_refs(ctx: Context):
    return parse_allowed_refs(ctx.config.get("provider:fenre", "allowed_refs", "main"),
                              ctx.config.get("provider:fenre", "ref", "main"))


def _provider_token(ctx: Context) -> str:
    if ctx.system_transport is None:
        return ""
    return get_secret(ctx.system_transport, "github_token") or ""


def post_sync(ctx: Context, req: Request) -> Response:
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


def get_manifest(ctx: Context, req: Request) -> Response:
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


def post_import(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    max_mb = ctx.config.get_int("import", "max_bundle_mb", 50, 1, 500)
    cats = req.args("categories")
    service = BundleImportService(ctx.sync_service(), max_mb * 1024 * 1024)
    job = service.import_bytes(req.body, ctx.user, _bool(req.arg("allow_schema_change")), cats or None)
    return Response(200, {"job": job})


def post_reindex(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    result = ReindexService(ctx.store).reindex(req.arg("category") or None)
    ctx.audit.record(ctx.user, "content.reindex", "catalog", req.arg("category") or "*", details=result)
    return Response(200, result)


def get_platform(ctx: Context, req: Request) -> Response:
    report = PlatformProbe(ctx.user_transport).report(
        ctx.config.get_bool("provider:fenre", "remote_sync_enabled", True))
    out = report.to_dict()
    overview = ctx.security_content().overview()
    out["security_content"] = {"es": overview["es"], "escu": overview["escu"], "read_at": overview["read_at"],
                               "note": "Read-only presence check with the app's system session. Behaviour with ES "
                                       "installed is unvalidated (no ES lab)."}
    return Response(200, out)


def get_audit(ctx: Context, req: Request) -> Response:
    caps = ctx.capabilities()
    if CAP_ADMIN not in caps and CAP_MANAGE_CONTENT not in caps:
        raise PermissionDenied("missing capability %s" % CAP_ADMIN)
    limit = max(1, min(200, _int(req.arg("limit"), 50, "limit")))
    return Response(200, {"events": ctx.audit.recent(limit, req.arg("prefix"))})


def get_inventory(ctx: Context, req: Request) -> Response:
    f = InventoryFilter(
        kind=req.arg("kind", "pair"), status=req.arg("status", "active"), q=req.arg("q").strip(),
        index=req.arg("index").strip(), sourcetype=req.arg("sourcetype").strip(),
        stale_hours=_int(req.arg("stale_hours"), 0, "stale_hours"),
        sort=req.arg("sort", "count"), offset=_int(req.arg("offset"), 0, "offset"),
        count=_int(req.arg("count"), 25, "count"), with_total=req.arg("total", "1") != "0")
    max_page = ctx.config.get_int("catalog", "max_page_size", 100, 10, 500)
    return Response(200, InventoryQueryService(ctx.store, max_page).search(f))


def get_inventory_coverage(ctx: Context, req: Request) -> Response:
    return Response(200, coverage(ctx.store))


def get_environment_health(ctx: Context, req: Request) -> Response:
    return Response(200, environment_health(ctx.store))


def get_discovery(ctx: Context, req: Request) -> Response:
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


def post_discovery(ctx: Context, req: Request) -> Response:
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


def get_mappings(ctx: Context, req: Request) -> Response:
    kind = req.arg("kind")
    origin = req.arg("origin")
    offset = _int(req.arg("offset"), 0, "offset")
    count = max(1, min(200, _int(req.arg("count"), 50, "count")))
    rows = MappingService(ctx.store).repo.list(kind or None, origin or None, offset, count + 1)
    return Response(200, {"items": rows[:count], "offset": offset, "count": min(count, len(rows[:count])),
                          "has_more": len(rows) > count})


def post_mappings(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    doc = ctx.mapping_service().upsert_local(
        str(body.get("kind") or ""), str(body.get("value") or ""),
        str(body.get("canonical_value") or body.get("value") or ""), ctx.user,
        str(body.get("notes") or ""), str(body.get("confidence") or "high"))
    ctx.audit.record(ctx.user, "discovery.mapping.upsert", "mapping", doc["_key"],
                     details={"kind": doc["kind"], "value": doc["value"]})
    return Response(200, {"mapping": doc})


def post_mappings_delete(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    ctx.mapping_service().delete_local(str(body.get("kind") or ""), str(body.get("value") or ""),
                                           ctx.user)
    ctx.audit.record(ctx.user, "discovery.mapping.delete", "mapping",
                     "%s:%s" % (body.get("kind"), body.get("value")))
    return Response(200, {"deleted": True})


def get_readiness(ctx: Context, req: Request) -> Response:
    f = ReadinessFilter(
        states=req.args("state"), data_states=req.args("data_state"), domains=req.args("domain"), criticality=req.args("criticality"),
        category_keys=req.args("category"), q=req.arg("q").strip(), sort=req.arg("sort", "score"),
        offset=_int(req.arg("offset"), 0, "offset"), count=_int(req.arg("count"), 25, "count"),
        with_total=req.arg("total", "1") != "0")
    max_page = ctx.config.get_int("catalog", "max_page_size", 100, 10, 500)
    return Response(200, ReadinessQueryService(ctx.store, max_page).search(f))


def get_readiness_summary(ctx: Context, req: Request) -> Response:
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


def get_readiness_recommendations(ctx: Context, req: Request) -> Response:
    completed = ctx.discovery_service().state.state().get("last_completed_at")
    return Response(200, RecommendationService(ctx.store).recommend(
        ctx.user, completed, _int(req.arg("count"), MAX_RECOMMENDATIONS, "count"),
        req.args("exclude_quality")))


def get_readiness_usecase(ctx: Context, req: Request) -> Response:
    doc = ctx.readiness_service().get(req.arg("id"))
    if doc is None:
        return Response(404, {"error": {"code": "not_assessed", "message": "use case has not been assessed"}})
    return Response(200, doc)


def post_readiness(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    job = ctx.readiness_service().enqueue(new_readiness_job(ctx.user))
    return Response(202, {"job": job})


def get_selections(ctx: Context, req: Request) -> Response:
    return Response(200, ctx.selection_service().list_for(
        ctx.user, req.arg("intent") or None, _int(req.arg("offset"), 0, "offset"),
        _int(req.arg("count"), 50, "count")))


def post_selections(ctx: Context, req: Request) -> Response:
    body = req.json()
    doc = ctx.selection_service().upsert(
        ctx.user, str(body.get("id") or body.get("content_id") or ""),
        str(body.get("intent") or ""), str(body.get("notes") or ""),
        _int(str(body.get("priority") if body.get("priority") is not None else "50"), 50, "priority"))
    return Response(200, {"selection": doc})


def post_selections_delete(ctx: Context, req: Request) -> Response:
    body = req.json()
    ctx.selection_service().delete(ctx.user, str(body.get("id") or body.get("content_id") or ""))
    return Response(200, {"deleted": True})


def get_validation(ctx: Context, req: Request) -> Response:
    doc = ctx.validation_service().get(req.arg("id"))
    if doc is None:
        return Response(404, {"error": {"code": "not_validated", "message": "use case has not been validated"}})
    return Response(200, doc)


def post_validate(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    use_case_id = str(body.get("id") or req.arg("id") or "")
    if not use_case_id:
        raise ValidationError("id is required")
    sample = body.get("sample", True)
    if sample is True or str(sample).lower() in ("1", "true"):
        return Response(200, ctx.validation_service().sample_and_assess(use_case_id, ctx.user))
    return Response(200, ctx.validation_service().parse_only(use_case_id, ctx.user))


def post_preview(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    use_case_id = str(body.get("id") or req.arg("id") or "")
    if not use_case_id:
        raise ValidationError("id is required")
    return Response(200, ctx.validation_service().preview(
        use_case_id, ctx.user, str(body.get("earliest") or ""), str(body.get("latest") or "")))


def post_readiness_assess(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    use_case_id = str(body.get("id") or req.arg("id") or "")
    if not use_case_id:
        raise ValidationError("id is required")
    return Response(200, ctx.readiness_service().assess_one(use_case_id, ctx.user))


def _require_any(ctx: Context, *caps: str) -> None:
    have = ctx.capabilities()
    if not any(c in have for c in caps):
        raise PermissionDenied("missing capability %s" % " or ".join(caps))


def _deployment_view(ctx: Context, svc: DeploymentService, doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"deployment": doc, "allowed_actions": svc.allowed_actions(doc, ctx.user, ctx.capabilities()),
            "scheduler_access": svc.scheduler_access_for(doc),
            "settings": {"require_approval": svc.settings.require_approval,
                         "allow_self_approval": svc.settings.allow_self_approval,
                         "block_enable_states": list(svc.settings.block_enable_states),
                         "defaults": svc.settings.defaults()}}


def get_deployments(ctx: Context, req: Request) -> Response:
    svc = ctx.deployment_service()
    out = svc.list(req.args("state"), req.args("live"), _int(req.arg("offset"), 0, "offset"),
                   _int(req.arg("count"), 50, "count"), drifted=req.arg("drift") == "1")
    if req.arg("summary") == "1":
        out["summary"] = svc.summary()
    return Response(200, out)


def post_controltest_import(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    max_mb = ctx.config.get_int("import", "max_bundle_mb", 50, 1, 500)
    if len(req.body or b"") > max_mb * 1024 * 1024:
        raise ValidationError("fixture bundle is larger than max_bundle_mb")
    return Response(200, ctx.deployment_service().import_fixtures(ctx.user, req.json()))


def get_deployments_export(ctx: Context, req: Request) -> Response:
    return Response(200, ctx.deployment_service().export(ctx.user))


def get_deployment(ctx: Context, req: Request) -> Response:
    svc = ctx.deployment_service()
    return Response(200, _deployment_view(ctx, svc, svc.get(req.arg("id"))))


def _deployment_action(action: str) -> Handler:
    propose = action in ("draft", "submit")
    observe = action == "verify"

    def handler(ctx: Context, req: Request) -> Response:
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
        elif action == "verify":
            doc = svc.verify(ctx.user, use_case_id)
        elif action == "controltest":
            doc = svc.control_test(ctx.user, use_case_id)
        elif action in ("submit", "approve"):
            doc = getattr(svc, action)(ctx.user, use_case_id, note,
                                       acknowledge_commands=body.get("acknowledge_commands") is True)
        else:
            doc = getattr(svc, action)(ctx.user, use_case_id, note)
        return Response(200, _deployment_view(ctx, svc, doc))

    return handler


def _operational_map(ctx: Context, hours: int) -> Tuple[Optional[Dict[str, str]], Dict[str, Any]]:
    health = OperationsService(ctx.store, SearchClient(ctx.user_transport)).health(hours)
    if not health["available"]:
        return None, health
    return {i["content_id"]: i["health"] for i in health["items"]}, health


def _levels(ctx: Context, req: Request) -> Tuple[Dict[str, Dict[str, Any]], Optional[Dict[str, Any]]]:
    operational, health = None, None
    if req.arg("operational") == "1":
        operational, health = _operational_map(ctx, _int(req.arg("hours"), 24, "hours"))
    domain = req.arg("domain")
    if domain and domain not in DASHBOARD_DOMAINS:
        raise ValidationError("invalid domain")
    return CoverageService(ctx.store).use_case_levels(operational, domain), health


def get_frameworks(ctx: Context, req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    levels, _ = _levels(ctx, req)
    return Response(200, {"definitions": registry.list(),
                          "coverage": CoverageService(ctx.store).frameworks_summary(levels),
                          "use_cases": len(levels)})


def get_framework_matrix(ctx: Context, req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    definition = registry.get(req.arg("framework_id", "mitre_attack_enterprise"), req.arg("version"))
    levels, health = _levels(ctx, req)
    out = CoverageService(ctx.store).attack_matrix(definition, levels)
    out["versions"] = registry.versions(definition["framework_id"])
    out["active_version"] = registry.active_versions().get(definition["framework_id"])
    out["operational"] = None if health is None else {"available": health["available"], "reason": health["reason"],
                                                      "hours": health["hours"], "counts": health["counts"]}
    return Response(200, out)


def get_framework_navigator(ctx: Context, req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    definition = registry.get(req.arg("framework_id", "mitre_attack_enterprise"), req.arg("version"))
    levels, health = _levels(ctx, req)
    cov = CoverageService(ctx.store)
    layer = cov.navigator_layer(cov.attack_matrix(definition, levels), bool(health and health["available"]))
    return Response(200, {"layer": layer, "filename": "attack-layer-%s-%s.json" % (
        definition["framework_id"], definition["version"])})


def get_framework_technique(ctx: Context, req: Request) -> Response:
    registry = FrameworkRegistry(ctx.records())
    definition = registry.get(req.arg("framework_id", "mitre_attack_enterprise"), req.arg("version"))
    tid = req.arg("id")
    if not any(t["id"] == tid for t in definition["techniques"]):
        raise ValidationError("unknown technique for this framework version")
    levels, _ = _levels(ctx, req)
    return Response(200, {"id": tid, "use_cases": CoverageService(ctx.store).technique_use_cases(
        definition, tid, levels)})


def get_framework_controls(ctx: Context, req: Request) -> Response:
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


def get_framework_clause(ctx: Context, req: Request) -> Response:
    framework, clause = _regulation(req), req.arg("clause")
    if not clause or len(clause) > 200:
        raise ValidationError("clause is required")
    levels, _ = _levels(ctx, req)
    rows = EvidenceService(ctx.store).rows(framework, levels, clause)
    return Response(200, {"framework": framework, "clause": clause, "use_cases": rows})


def get_framework_evidence(ctx: Context, req: Request) -> Response:
    framework, clause = _regulation(req), req.arg("clause")
    if len(clause) > 200:
        raise ValidationError("clause is too long")
    levels, _ = _levels(ctx, req)
    return Response(200, EvidenceService(ctx.store).pack(framework, levels, req.arg("format", "json"), clause))


def post_framework_import(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    summary = FrameworkRegistry(ctx.records()).import_definition(req.body, ctx.user)
    ctx.audit.record(ctx.user, "framework.imported", "framework", summary["framework_id"],
                     details={"version": summary["version"], "techniques": summary["techniques"]})
    return Response(200, {"definition": summary})


def post_framework_activate(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    body = req.json()
    out = FrameworkRegistry(ctx.records()).activate(str(body.get("framework_id") or ""),
                                                    str(body.get("version") or ""), ctx.user)
    ctx.audit.record(ctx.user, "framework.activated", "framework", out["framework_id"],
                     details={"version": out["version"]})
    return Response(200, out)


def get_operations(ctx: Context, req: Request) -> Response:
    return Response(200, OperationsService(ctx.store, SearchClient(ctx.user_transport)).health(
        _int(req.arg("hours"), 24, "hours")))


def get_dashboards(ctx: Context, req: Request) -> Response:
    svc = ctx.dashboard_service()
    return Response(200, {"templates": svc.templates(), "dashboards": svc.list()})


def post_dashboard_preview(ctx: Context, req: Request) -> Response:
    body = req.json()
    return Response(200, ctx.dashboard_service().preview(str(body.get("template") or ""), body.get("params") or {}))


def post_dashboard_create(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_DEPLOY)
    body = req.json()
    return Response(200, {"dashboard": ctx.dashboard_service().create(
        ctx.user, str(body.get("template") or ""), body.get("params") or {})})


def post_dashboard_delete(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_DEPLOY)
    body = req.json()
    name = str(body.get("name") or "")
    if not name.startswith("ucm_gen_") or len(name) > 100:
        raise ValidationError("not a generated dashboard name")
    ctx.dashboard_service().delete(ctx.user, name)
    return Response(200, {"deleted": True})


DEPLOYMENT_ACTIONS = ("draft", "submit", "approve", "reject", "deploy", "enable", "disable", "rollback",
                      "retire", "verify", "controltest")


def build_router() -> Router:
    router = Router()
    router.add("GET", "catalog", get_catalog)
    router.add("GET", "catalog/facets", get_catalog_facets)
    router.add("GET", "usecase", get_usecase)
    router.add("GET", "categories", get_categories)
    router.add("GET", "sync", get_sync)
    router.add("POST", "sync", post_sync)
    router.add("GET", "provider/manifest", get_manifest)
    router.add("POST", "import", post_import)
    router.add("POST", "catalog/reindex", post_reindex)
    router.add("GET", "platform", get_platform)
    router.add("GET", "audit", get_audit)
    router.add("GET", "inventory", get_inventory)
    router.add("GET", "inventory/coverage", get_inventory_coverage)
    router.add("GET", "environment/health", get_environment_health)
    router.add("GET", "discovery", get_discovery)
    router.add("POST", "discovery", post_discovery)
    router.add("GET", "mappings", get_mappings)
    router.add("POST", "mappings", post_mappings)
    router.add("POST", "mappings/delete", post_mappings_delete)
    router.add("GET", "readiness", get_readiness)
    router.add("POST", "readiness", post_readiness)
    router.add("GET", "readiness/summary", get_readiness_summary)
    router.add("GET", "readiness/usecase", get_readiness_usecase)
    router.add("GET", "readiness/recommendations", get_readiness_recommendations)
    router.add("POST", "readiness/assess", post_readiness_assess)
    router.add("GET", "selections", get_selections)
    router.add("POST", "selections", post_selections)
    router.add("POST", "selections/delete", post_selections_delete)
    router.add("GET", "validation", get_validation)
    router.add("POST", "validate", post_validate)
    router.add("POST", "preview", post_preview)
    router.add("GET", "deployments", get_deployments)
    router.add("GET", "deployments/export", get_deployments_export)
    router.add("POST", "controltest/import", post_controltest_import)
    router.add("GET", "deployment", get_deployment)
    for action in DEPLOYMENT_ACTIONS:
        router.add("POST", "deployment/" + action, _deployment_action(action))
    router.add("GET", "frameworks", get_frameworks)
    router.add("GET", "frameworks/matrix", get_framework_matrix)
    router.add("GET", "frameworks/technique", get_framework_technique)
    router.add("GET", "frameworks/navigator", get_framework_navigator)
    router.add("GET", "frameworks/controls", get_framework_controls)
    router.add("GET", "frameworks/clause", get_framework_clause)
    router.add("GET", "frameworks/evidence", get_framework_evidence)
    router.add("POST", "frameworks/import", post_framework_import)
    router.add("POST", "frameworks/activate", post_framework_activate)
    router.add("GET", "operations", get_operations)
    router.add("GET", "dashboards", get_dashboards)
    router.add("POST", "dashboards/preview", post_dashboard_preview)
    router.add("POST", "dashboards/create", post_dashboard_create)
    router.add("POST", "dashboards/delete", post_dashboard_delete)
    return router

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

from ..audit import AuditService
from ..catalog.detail import UseCaseDetailService
from ..catalog.query import CatalogFilter, CatalogQueryService
from ..config import AppConfig, load_config
from ..content.importer import BundleImportService
from ..content.registry import remote_provider
from ..content.reindex import ReindexService
from ..content.sync import SyncService, SyncSettings, new_job
from ..discovery.inventory import SplunkInventory
from ..discovery.mapping import MappingService
from ..discovery.overlay import attach_environment
from ..discovery.query import InventoryFilter, InventoryQueryService, coverage
from ..discovery.service import DiscoveryService, new_job as new_discovery_job
from ..discovery.worker import settings_from_config
from ..errors import PermissionDenied, UcmError, UnsupportedOperation, ValidationError
from ..platform.search import SearchClient
from ..log import get_logger
from ..platform.capabilities import PlatformProbe
from ..secrets import get_secret
from ..storage.kvstore import DocumentStore, KVStore
from ..storage.repositories import CategoryRepository, ContentRepository, SyncStateRepository
from ..storage.transport import SplunkdTransport

log = get_logger(__name__)

CAP_MANAGE_CONTENT = "ucm_manage_content"
CAP_ADMIN = "ucm_admin"
CAP_RUN_DISCOVERY = "ucm_run_discovery"


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
                 provider_factory: Optional[Callable[..., Any]] = None):
        self.user = user
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
        return SyncService(self.store, self.audit, settings)

    def discovery_service(self) -> DiscoveryService:
        return DiscoveryService(
            self.store, self.audit, SplunkInventory(self.user_transport),
            SearchClient(self.user_transport), settings_from_config(self.config))


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
        provider_status=req.arg("status", "active"), sort=req.arg("sort", "id"),
        offset=_int(req.arg("offset"), 0, "offset"), count=_int(req.arg("count"), 25, "count"),
        with_total=req.arg("total", "1") != "0")
    max_page = ctx.config.get_int("catalog", "max_page_size", 100, 10, 500)
    return Response(200, CatalogQueryService(ctx.store, max_page).search(f))


def get_usecase(ctx: Context, req: Request) -> Response:
    service = UseCaseDetailService(ContentRepository(ctx.store), CategoryRepository(ctx.store))
    detail = service.get(req.arg("id"))
    return Response(200, attach_environment(detail, ctx.store))


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
    })


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
    job = new_job(ctx.user, provider, [str(c) for c in cats], ref=ref, source="manual",
                  allow_schema_change=_bool(body.get("allow_schema_change")), force=_bool(body.get("force")))
    ctx.sync_service().enqueue(job)
    return Response(202, {"job": job})


def get_manifest(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_MANAGE_CONTENT)
    if not ctx.config.get_bool("provider:fenre", "remote_sync_enabled", True):
        raise UnsupportedOperation("remote synchronization is disabled; use offline import")
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
    return Response(200, report.to_dict())


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
    doc = MappingService(ctx.store).upsert_local(
        str(body.get("kind") or ""), str(body.get("value") or ""),
        str(body.get("canonical_value") or body.get("value") or ""), ctx.user,
        str(body.get("notes") or ""), str(body.get("confidence") or "high"))
    ctx.audit.record(ctx.user, "discovery.mapping.upsert", "mapping", doc["_key"],
                     details={"kind": doc["kind"], "value": doc["value"]})
    return Response(200, {"mapping": doc})


def post_mappings_delete(ctx: Context, req: Request) -> Response:
    ctx.require(CAP_RUN_DISCOVERY)
    body = req.json()
    MappingService(ctx.store).delete_local(str(body.get("kind") or ""), str(body.get("value") or ""),
                                           ctx.user)
    ctx.audit.record(ctx.user, "discovery.mapping.delete", "mapping",
                     "%s:%s" % (body.get("kind"), body.get("value")))
    return Response(200, {"deleted": True})


def build_router() -> Router:
    router = Router()
    router.add("GET", "catalog", get_catalog)
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
    router.add("GET", "discovery", get_discovery)
    router.add("POST", "discovery", post_discovery)
    router.add("GET", "mappings", get_mappings)
    router.add("POST", "mappings", post_mappings)
    router.add("POST", "mappings/delete", post_mappings_delete)
    return router

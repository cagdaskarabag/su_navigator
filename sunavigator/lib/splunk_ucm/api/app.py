"""REST API: request context, the route table and, for compatibility, the names the handlers share.

The handlers live in ``routes_<domain>.py``; this module wires a request (``Context``) and lists every route
(``build_router``), so the route table stays in one place (docs/STRATEGY_ROADMAP.md, phase 3).

Authorization model (docs/DECISIONS.md D-011):
* All reads/writes use the **caller's** token, so KV Store ACLs apply.
* Write endpoints additionally require an app capability.
* The system token is used only to append audit records and to read the
  provider secret for capability-gated operations.
"""

from typing import Any, Callable, List, Optional

from .. import APP_NAME
from ..audit import AuditService
from ..config import AppConfig, load_config
from ..content.registry import remote_provider
from ..content.sync import SyncService, SyncSettings
from ..discovery.inventory import SplunkInventory
from ..discovery.mapping import MappingService
from ..discovery.query import coverage
from ..discovery.service import DiscoveryService
from ..discovery.worker import settings_from_config
from ..dashboards.service import DashboardService, ViewClient
from ..deployment.controltest import DEFAULT_TEST_INDEX, splunk_runner
from ..deployment.savedsearch import SavedSearchClient
from ..deployment.service import DeploymentService
from ..deployment.worker import settings_from_config as deployment_settings
from ..errors import PermissionDenied
from ..platform.search import SearchClient
from ..readiness.principal import SchedulerAccess, read_principal
from ..readiness.service import ReadinessService
from ..readiness.worker import settings_from_config as readiness_settings
from ..selection.service import SelectionService
from ..spl.policy import parse_extra_safe
from ..validation.service import ValidationService, ValidationSettings
from ..platform.capabilities import PlatformProbe
from ..platform.security_content import SecurityContentReader, deploy_record, handoff_for
from ..storage.kvstore import DocumentStore, KVStore
from ..storage.transport import SplunkdTransport
# Re-exported: callers import the capability names, Request and Response from here.
from .base import (
    CAP_ADMIN, CAP_DEPLOY, CAP_MANAGE_CONTENT, CAP_RUN_DISCOVERY, Request, Response, Router)  # noqa: F401
from .routes_content import (
    get_catalog, get_catalog_facets, get_usecase, get_external, post_external, get_categories, get_sync,
    post_sync, get_manifest, post_import, post_reindex, get_reindex, get_platform, get_audit,
    post_audit_verify)
from .routes_environment import (
    get_inventory, get_inventory_coverage, get_environment_health, get_discovery, post_discovery,
    get_mappings, post_mappings, post_mappings_delete, get_readiness, get_readiness_summary,
    get_readiness_recommendations, get_readiness_usecase, post_readiness, get_selections,
    post_selections, post_selections_delete, get_validation, post_validate, post_preview,
    post_readiness_assess)
from .routes_deployment import (
    get_deployments, post_controltest_import, get_deployments_export, get_deployment_diff,
    get_deployment, _deployment_action, DEPLOYMENT_ACTIONS)
from .routes_frameworks import (
    get_frameworks, get_framework_catalogue, get_framework_matrix, get_framework_navigator,
    get_framework_technique, get_framework_controls, get_framework_clause, get_framework_evidence,
    post_framework_import, post_framework_activate, get_operations)
from .routes_dashboards import (
    get_dashboards, post_dashboard_preview, post_dashboard_create, post_dashboard_delete)

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
    router.add("GET", "catalog/reindex", get_reindex)
    router.add("GET", "platform", get_platform)
    router.add("GET", "audit", get_audit)
    router.add("POST", "audit/verify", post_audit_verify)
    router.add("GET", "inventory", get_inventory)
    router.add("GET", "inventory/coverage", get_inventory_coverage)
    router.add("GET", "environment/health", get_environment_health)
    router.add("GET", "discovery", get_discovery)
    router.add("POST", "discovery", post_discovery)
    router.add("GET", "external", get_external)
    router.add("POST", "external", post_external)
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
    router.add("GET", "deployment/diff", get_deployment_diff)
    for action in DEPLOYMENT_ACTIONS:
        router.add("POST", "deployment/" + action, _deployment_action(action))
    router.add("GET", "frameworks", get_frameworks)
    router.add("GET", "frameworks/matrix", get_framework_matrix)
    router.add("GET", "frameworks/technique", get_framework_technique)
    router.add("GET", "frameworks/navigator", get_framework_navigator)
    router.add("GET", "frameworks/controls", get_framework_controls)
    router.add("GET", "frameworks/catalogue", get_framework_catalogue)
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

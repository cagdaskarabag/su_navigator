"""Periodic drift verification of deployed saved searches (runs in ucm_sync_worker)."""

import datetime
from typing import Any, Callable, Dict, Optional

from ..audit import AuditService
from ..config import AppConfig
from ..platform.search import SearchClient
from ..spl.policy import parse_extra_safe
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..storage.transport import SplunkdTransport
from ..util import utc_now
from .savedsearch import SavedSearchClient
from .actions import ActionPolicy, parse_list
from .service import DeploymentService, DeploymentSettings

STATE_KEY = "deployment::verify"


def settings_from_config(config: AppConfig) -> DeploymentSettings:
    blocked = [s.strip() for s in config.get("deployment", "block_enable_states", "blocked").split(",") if s.strip()]
    return DeploymentSettings(
        require_approval=config.get_bool("deployment", "require_approval", True),
        allow_self_approval=config.get_bool("deployment", "allow_self_approval", False),
        block_enable_states=blocked,
        cron=config.get("deployment", "default_cron", "*/15 * * * *") or "*/15 * * * *",
        earliest=config.get("deployment", "default_earliest", "-20m@m") or "-20m@m",
        latest=config.get("deployment", "default_latest", "-5m@m") or "-5m@m",
        schedule_window=config.get("deployment", "default_schedule_window", "auto") or "auto",
        scheduled_owner=config.get("deployment", "scheduled_owner", "").strip(),
        cron_jitter=config.get_bool("deployment", "cron_jitter", True),
        actions=ActionPolicy(
            enabled=config.get_bool("actions", "enabled", True),
            email_domains=parse_list(config.get("actions", "email_domains", "")),
            webhook_hosts=parse_list(config.get("actions", "webhook_hosts", "")),
            webhook_allow_http=config.get_bool("actions", "webhook_allow_http", False),
            max_recipients=config.get_int("actions", "max_recipients", 10, 1, 50),
            require_suppression=config.get_bool("actions", "require_suppression", True)),
        alert_mode=config.get("deployment", "default_alert_mode", "track") or "track",
        max_revisions=config.get_int("deployment", "max_revisions", 20, 2, 100),
        verify_interval_minutes=config.get_int("deployment", "verify_interval_minutes", 60, 0, 10080),
        extra_safe_commands=parse_extra_safe(config.get("spl", "extra_safe_commands", "")))


def _parse_iso(value: str) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


class DeploymentWorker:
    def __init__(self, store: DocumentStore, config: AppConfig, transport: SplunkdTransport,
                 is_leader: Callable[[], Optional[bool]], now: Callable[[], datetime.datetime] = utc_now):
        self.store = store
        self.is_leader = is_leader
        self.now = now
        self.service = DeploymentService(store, AuditService(store), SearchClient(transport),
                                         SavedSearchClient(transport), settings_from_config(config))

    def due(self) -> bool:
        interval = self.service.settings.verify_interval_minutes
        if interval <= 0:
            return False
        last = _parse_iso((self.store.get(C.SYNC_STATE, STATE_KEY) or {}).get("last_run_at", ""))
        return last is None or (self.now() - last).total_seconds() >= interval * 60

    def run_once(self) -> Dict[str, Any]:
        if self.is_leader() is False:
            return {"action": "skipped", "reason": "not_shc_captain"}
        if not self.due():
            return {"action": "idle"}
        if not self.store.query(C.DEPLOYMENTS, {"deployed_revision": {"$gte": 1}}, fields=["_key"], limit=1):
            self._record({"checked": 0, "drifted": 0, "missing": 0, "errors": 0})
            return {"action": "idle"}
        totals = self.service.verify_all("system")
        self._record(totals)
        return {"action": "ran", "job": "deployment_verify", "totals": totals}

    def _record(self, totals: Dict[str, int]) -> None:
        self.store.upsert(C.SYNC_STATE, {"_key": STATE_KEY, "doc_type": "deployment_verify",
                                         "last_run_at": self.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                                         "totals": totals})

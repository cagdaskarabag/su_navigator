"""Maintenance step of the background worker: migrations first, then retention."""

import datetime
from typing import Any, Callable, Dict, Optional

from ..audit import AuditService
from ..config import AppConfig
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import epoch_now, utc_now
from .migrations import MigrationRunner
from .retention import RetentionService, settings_from_config

STATE_KEY = "maintenance::retention"


class MaintenanceWorker:
    def __init__(self, store: DocumentStore, config: AppConfig, is_leader: Callable[[], Optional[bool]],
                 now: Callable[[], datetime.datetime] = utc_now, epoch: Callable[[], float] = epoch_now):
        self.store = store
        self.is_leader = is_leader
        self.now = now
        self.migrations = MigrationRunner(store, lambda: self._iso())
        self.retention = RetentionService(store, settings_from_config(config), epoch)
        self.audit = AuditService(store)

    def _iso(self) -> str:
        return self.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def retention_due(self) -> bool:
        interval = self.retention.settings.interval_hours
        if interval <= 0:
            return False
        last = (self.store.get(C.SYNC_STATE, STATE_KEY) or {}).get("last_run_at", "")
        try:
            then = datetime.datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return True
        return (self.now() - then).total_seconds() >= interval * 3600

    def run_once(self) -> Dict[str, Any]:
        if self.is_leader() is False:
            return {"action": "skipped", "reason": "not_shc_captain"}
        if self.migrations.outdated():
            results = self.migrations.run()
            for r in results:
                self.audit.record("system", "app.migration", "app", r["id"], details=r["details"])
            return {"action": "ran", "job": "migrations", "applied": [r["id"] for r in results]}
        if not self.retention_due():
            return {"action": "idle"}
        totals = self.retention.purge()
        self.store.upsert(C.SYNC_STATE, {"_key": STATE_KEY, "doc_type": "retention_state",
                                         "last_run_at": self._iso(), "totals": totals})
        if totals["audit"] or totals["jobs"]:
            self.audit.record("system", "retention.purged", "app", "retention", details=totals)
            return {"action": "ran", "job": "retention", "totals": totals}
        return {"action": "idle"}

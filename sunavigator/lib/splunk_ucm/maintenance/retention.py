"""Retention purges for the audit trail and job history (D-034)."""

from dataclasses import dataclass
from typing import Callable, Dict

from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import epoch_now

JOB_TYPES = ("job", "discovery_job", "readiness_job")


@dataclass
class RetentionSettings:
    audit_days: int = 365
    job_history: int = 50
    interval_hours: int = 24


def settings_from_config(config) -> RetentionSettings:
    return RetentionSettings(
        audit_days=config.get_int("retention", "audit_days", 365, 0, 3650),
        job_history=config.get_int("retention", "job_history", 50, 10, 200),
        interval_hours=config.get_int("retention", "interval_hours", 24, 0, 720),
    )


class RetentionService:
    def __init__(self, store: DocumentStore, settings: RetentionSettings, now: Callable[[], float] = epoch_now):
        self.store = store
        self.settings = settings
        self.now = now

    def purge(self) -> Dict[str, int]:
        out = {"audit": 0, "jobs": 0}
        if self.settings.audit_days > 0:
            cutoff = self.now() - self.settings.audit_days * 86400
            query = {"time": {"$lt": cutoff}}
            out["audit"] = self.store.count(C.AUDIT, query)
            if out["audit"]:
                self.store.delete_query(C.AUDIT, query)
        for doc_type in JOB_TYPES:
            rows = self.store.query(C.SYNC_STATE, {"doc_type": doc_type}, sort=[("requested_at", -1)],
                                    skip=self.settings.job_history, fields=["_key", "status"])
            for row in rows:
                if row.get("status") in ("queued", "running"):
                    continue
                self.store.delete(C.SYNC_STATE, row["_key"])
                out["jobs"] += 1
        return out

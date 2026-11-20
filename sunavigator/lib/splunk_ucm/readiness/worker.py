"""Background execution of readiness jobs, including re-assessment after discovery or sync."""

import datetime
from typing import Any, Callable, Dict, Optional

from ..audit import AuditService
from ..config import AppConfig
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now
from .evaluators import EvaluationSettings
from .scoring import ScoringSettings
from .service import JOB_FAILED, JOB_RUNNING, ReadinessService, ReadinessSettings, new_job


def _parse_iso(value: str) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def settings_from_config(config: AppConfig) -> ReadinessSettings:
    return ReadinessSettings(
        evaluation=EvaluationSettings(stale_hours=config.get_int("readiness", "stale_hours", 24, 1, 24 * 90)),
        scoring=ScoringSettings(
            ready_threshold=config.get_int("readiness", "ready_threshold", 90, 1, 100),
            partial_threshold=config.get_int("readiness", "partial_threshold", 50, 0, 100),
            min_coverage=config.get_float("readiness", "min_coverage", 0.5, 0.0, 1.0)),
        job_timeout_seconds=config.get_int("readiness", "job_timeout_seconds", 3600, 60, 86400))


class ReadinessWorker:
    def __init__(self, store: DocumentStore, config: AppConfig, is_leader: Callable[[], Optional[bool]],
                 now: Callable[[], datetime.datetime] = utc_now):
        self.store = store
        self.config = config
        self.is_leader = is_leader
        self.now = now
        self.service = ReadinessService(store, AuditService(store), settings_from_config(config))

    def expire_stale(self) -> int:
        expired = 0
        for job in self.service.jobs(JOB_RUNNING, 20):
            started = _parse_iso(job.get("started_at", ""))
            if started and (self.now() - started).total_seconds() > self.service.settings.job_timeout_seconds:
                job["status"] = JOB_FAILED
                job.setdefault("errors", []).append({"code": "timeout", "message": "job exceeded timeout"})
                self.service.save_job(job)
                expired += 1
        return expired

    def maybe_schedule(self) -> Optional[Dict[str, Any]]:
        """Queue a re-assessment when discovery or content is newer than the last assessment."""
        if not self.config.get_bool("readiness", "auto_assess", True):
            return None
        disc = self.store.get(C.SYNC_STATE, "discovery::local") or {}
        if not disc.get("last_completed_at"):
            return None
        provider = self.store.get(C.SYNC_STATE, "provider::fenre") or {}
        content_at = provider.get("last_success_at") or ""
        state = self.service.state()
        if state.get("last_attempt_status") == JOB_FAILED and state.get("last_attempt_at", "") >= max(
                disc.get("last_completed_at", ""), content_at):
            return None
        if state.get("discovery_at") == disc.get("last_completed_at") and state.get("content_at", "") >= content_at:
            return None
        if self.service.next_queued() or self.service.jobs(JOB_RUNNING, 1):
            return None
        job = new_job("system", source="auto")
        self.service.enqueue(job)
        return job

    def run_once(self) -> Dict[str, Any]:
        if self.is_leader() is False:
            return {"action": "skipped", "reason": "not_shc_captain"}
        expired = self.expire_stale()
        self.maybe_schedule()
        job = self.service.next_queued()
        if job is None:
            return {"action": "idle", "expired": expired}
        result = self.service.run(job)
        return {"action": "ran", "job_id": result["job_id"], "status": result["status"],
                "totals": result.get("totals")}

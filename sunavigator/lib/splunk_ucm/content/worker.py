"""Background sync worker logic, invoked by the ``ucm_sync_worker`` modular input.

One invocation performs at most one job. On a search head cluster only the
captain executes jobs, so members do not race (validation pending, see
docs/PROJECT_DISCOVERY.md §6).
"""

import datetime
from typing import Any, Callable, Dict, Optional

from ..audit import AuditService
from ..config import AppConfig
from ..errors import UcmError
from ..log import get_logger
from ..storage.kvstore import DocumentStore
from ..storage.repositories import SyncStateRepository
from ..util import utc_now
from .provider import ContentProvider
from .sync import JOB_FAILED, JOB_RUNNING, SyncService, SyncSettings, new_job

log = get_logger(__name__)

ProviderFactory = Callable[[str, Dict[str, str], str, str], ContentProvider]


def _parse_iso(value: str) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


class SyncWorker:
    def __init__(self, store: DocumentStore, config: AppConfig, provider_factory: ProviderFactory,
                 token_getter: Callable[[], str], is_leader: Callable[[], Optional[bool]],
                 now: Callable[[], datetime.datetime] = utc_now):
        self.store = store
        self.config = config
        self.provider_factory = provider_factory
        self.token_getter = token_getter
        self.is_leader = is_leader
        self.now = now
        self.state = SyncStateRepository(store)
        self.audit = AuditService(store)

    def _service(self) -> SyncService:
        cfg = self.config
        return SyncService(self.store, self.audit, SyncSettings(
            fetch_concurrency=cfg.get_int("provider:fenre", "fetch_concurrency", 4, 1, 16),
            max_invalid_ratio=cfg.get_float("sync", "max_invalid_ratio", 0.2, 0.0, 1.0),
            job_timeout_seconds=cfg.get_int("sync", "job_timeout_seconds", 3600, 60, 86400)))

    def expire_stale(self) -> int:
        timeout = self.config.get_int("sync", "job_timeout_seconds", 3600, 60, 86400)
        expired = 0
        for job in self.state.jobs(JOB_RUNNING, limit=20):
            started = _parse_iso(job.get("started_at", ""))
            if started and (self.now() - started).total_seconds() > timeout:
                job["status"] = JOB_FAILED
                job.setdefault("errors", []).append({"code": "timeout", "message": "job exceeded timeout"})
                self.state.save_job(job)
                self.audit.record("system", "content.sync.timeout", "sync_job", job.get("job_id", ""),
                                  outcome="failed")
                expired += 1
        return expired

    def maybe_schedule(self) -> Optional[Dict[str, Any]]:
        hours = self.config.get_int("sync", "schedule_interval_hours", 0, 0, 24 * 30)
        if hours <= 0 or not self.config.get_bool("provider:fenre", "remote_sync_enabled", True):
            return None
        state = self.state.provider_state("fenre")
        if not state.get("selected_categories"):
            return None
        last = _parse_iso(state.get("last_attempt_at", ""))
        if last and (self.now() - last).total_seconds() < hours * 3600:
            return None
        if self.state.next_queued() or self.state.jobs(JOB_RUNNING, limit=1):
            return None
        job = new_job("scheduler", "fenre", None, source="schedule")
        self._service().enqueue(job)
        return job

    def run_once(self) -> Dict[str, Any]:
        leader = self.is_leader()
        if leader is False:
            return {"action": "skipped", "reason": "not_shc_captain"}
        expired = self.expire_stale()
        self.maybe_schedule()
        job = self.state.next_queued()
        if job is None:
            return {"action": "idle", "expired": expired}
        provider_id = job.get("provider", "fenre")
        try:
            if not self.config.get_bool("provider:" + provider_id, "remote_sync_enabled", True):
                raise UcmError("remote synchronization is disabled")
            provider = self.provider_factory(provider_id, self.config.provider_settings(provider_id),
                                             self.token_getter(), job.get("ref", ""))
        except UcmError as exc:
            job["status"] = JOB_FAILED
            job.setdefault("errors", []).append(exc.to_dict())
            self.state.save_job(job)
            self.audit.record(job.get("requested_by", ""), "content.sync.completed", "sync_job",
                              job.get("job_id", ""), outcome=JOB_FAILED, details={"errors": job["errors"]})
            return {"action": "failed", "job_id": job.get("job_id")}
        result = self._service().run(job, provider)
        return {"action": "ran", "job_id": result.get("job_id"), "status": result.get("status"),
                "totals": result.get("totals")}

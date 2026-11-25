"""Background execution of queued and scheduled discovery jobs."""

import datetime
from typing import Any, Callable, Dict, Optional

from ..audit import AuditService
from ..config import AppConfig
from ..errors import UcmError
from ..log import get_logger
from ..platform.search import SearchClient
from ..storage.jobs import job_problem, reject
from ..storage.kvstore import DocumentStore
from ..storage.transport import SplunkdTransport
from ..util import utc_now
from .inventory import SplunkInventory
from .populated import PopulatedSettings
from .profile import ProfileSettings, parse_placeholders
from .service import (JOB_FAILED, JOB_RUNNING, DiscoveryService, DiscoverySettings,
                      new_job)

log = get_logger(__name__)


def _parse_iso(value: str) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def settings_from_config(config: AppConfig) -> DiscoverySettings:
    job_timeout = config.get_int("discovery", "job_timeout_seconds", 600, 60, 3600)
    return DiscoverySettings(
        earliest=config.get("discovery", "earliest", "-7d") or "-7d",
        latest=config.get("discovery", "latest", "now") or "now",
        include_internal=config.get_bool("discovery", "include_internal", False),
        max_pairs=config.get_int("discovery", "max_pairs", 5000, 100, 20000),
        search_timeout=config.get_int("discovery", "search_timeout_seconds", 120, 15, 600),
        freshness_days=config.get_int("discovery", "freshness_days", 30, 0, 365),
        profile=ProfileSettings(
            enabled=config.get_bool("discovery", "field_profile", True),
            max_sourcetypes=config.get_int("discovery", "profile_max_sourcetypes", 20, 0, 200),
            max_fields=config.get_int("discovery", "profile_max_fields", 60, 1, 200),
            sample_events=config.get_int("discovery", "profile_sample_events", 1000, 100, 10000),
            timeout_seconds=config.get_int("discovery", "profile_timeout_seconds", 60, 10, 600),
            budget_seconds=config.get_int("discovery", "profile_budget_seconds", 300, 30, 3600),
            placeholders=parse_placeholders(config.get("discovery", "profile_placeholders", ""))),
        job_timeout_seconds=job_timeout,
        populated=PopulatedSettings(
            enabled=config.get_bool("discovery", "populated_check", True),
            max_models=config.get_int("discovery", "populated_max_models", 30, 1, 100),
            timeout_seconds=config.get_int("discovery", "populated_timeout_seconds", 30, 5, 300),
            budget_seconds=job_timeout // 2))


class DiscoveryWorker:
    def __init__(self, store: DocumentStore, config: AppConfig, transport: SplunkdTransport,
                 is_leader: Callable[[], Optional[bool]],
                 now: Callable[[], datetime.datetime] = utc_now,
                 inventory: Optional[SplunkInventory] = None, search: Optional[SearchClient] = None):
        self.store = store
        self.config = config
        self.transport = transport
        self.is_leader = is_leader
        self.now = now
        self.audit = AuditService(store)
        self.inventory = inventory
        self.search = search

    def _service(self) -> DiscoveryService:
        return DiscoveryService(
            self.store, self.audit, self.inventory or SplunkInventory(self.transport),
            self.search or SearchClient(self.transport), settings_from_config(self.config))

    def expire_stale(self) -> int:
        timeout = settings_from_config(self.config).job_timeout_seconds
        expired = 0
        svc = self._service()
        for job in svc.state.jobs(JOB_RUNNING, limit=20):
            started = _parse_iso(job.get("started_at", ""))
            if started and (self.now() - started).total_seconds() > timeout:
                job["status"] = JOB_FAILED
                job.setdefault("errors", []).append({"code": "timeout", "message": "job exceeded timeout"})
                svc.state.save_job(job)
                self.audit.record("system", "discovery.timeout", "discovery_job", job.get("job_id", ""),
                                  outcome="failed")
                expired += 1
        return expired

    def maybe_schedule(self) -> Optional[Dict[str, Any]]:
        hours = self.config.get_int("discovery", "schedule_interval_hours", 0, 0, 24 * 30)
        if hours <= 0:
            return None
        svc = self._service()
        last = _parse_iso(svc.state.state().get("last_attempt_at", ""))
        if last and (self.now() - last).total_seconds() < hours * 3600:
            return None
        if svc.state.next_queued() or svc.state.jobs(JOB_RUNNING, limit=1):
            return None
        job = new_job("scheduler", source="schedule")
        svc.enqueue(job)
        return job

    def run_once(self) -> Dict[str, Any]:
        leader = self.is_leader()
        if leader is False:
            return {"action": "skipped", "reason": "not_shc_captain"}
        expired = self.expire_stale()
        self.maybe_schedule()
        svc = self._service()
        job = svc.state.next_queued()
        if job is None:
            return {"action": "idle", "expired": expired}
        problem = job_problem(job)
        if problem:
            svc.state.save_job(reject(job, problem))
            self.audit.record("system", "discovery.rejected", "discovery_job", str(job.get("job_id", "")),
                              outcome="failed", details={"problem": problem})
            return {"action": "rejected", "job_id": job.get("job_id"), "problem": problem}
        try:
            result = svc.run(job)
        except UcmError as exc:
            job["status"] = JOB_FAILED
            job.setdefault("errors", []).append(exc.to_dict())
            svc.state.save_job(job)
            return {"action": "failed", "job_id": job.get("job_id")}
        return {"action": "ran", "job_id": result.get("job_id"), "status": result.get("status"),
                "totals": result.get("totals")}

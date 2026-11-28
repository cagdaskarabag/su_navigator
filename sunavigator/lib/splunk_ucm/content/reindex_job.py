"""Reindex as a background job (issue #25).

A reindex re-derives every catalogue summary and takes about 5 seconds per 1,000 use cases, which is too long for one
request behind a proxy. The handler records one job document and the maintenance worker runs it. There is one slot:
a second request while a job is queued or running is refused, and a job that has been running longer than
``STALE_SECONDS`` is treated as lost so a crashed worker cannot block the next one.
"""

import datetime
import re
from typing import Any, Callable, Dict, Optional

from ..audit import AuditService
from ..errors import ConflictError, ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now
from .reindex import ReindexService

KEY = "reindex::current"
DOC_TYPE = "reindex_job"
STALE_SECONDS = 1800
_CATEGORY = re.compile(r"^[\w.\-]{1,100}$")
ACTIVE = ("queued", "running")


def _iso(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime(value or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


class ReindexJobs:
    def __init__(self, store: DocumentStore, now: Callable[[], datetime.datetime] = utc_now):
        self.store = store
        self.now = now

    def current(self) -> Optional[Dict[str, Any]]:
        job = self.store.get(C.SYNC_STATE, KEY)
        if job and job.get("status") == "running":
            started = _parse(job.get("started_at", ""))
            if started is None or (self.now() - started).total_seconds() > STALE_SECONDS:
                job = dict(job, status="failed", finished_at=_iso(self.now()),
                           error="the worker stopped before the reindex finished; start it again")
        return job

    def enqueue(self, user: str, category: str = "") -> Dict[str, Any]:
        if category and not _CATEGORY.match(category):
            raise ValidationError("invalid category")
        existing = self.current()
        if existing and existing.get("status") in ACTIVE:
            raise ConflictError("a reindex is already %s" % existing["status"], {"code": "reindex_active"})
        job = {"_key": KEY, "doc_type": DOC_TYPE, "status": "queued", "requested_by": user, "category": category,
               "queued_at": _iso(self.now()), "started_at": "", "finished_at": "", "result": None, "error": ""}
        self.store.upsert(C.SYNC_STATE, job)
        return job

    def run_queued(self, audit: AuditService) -> Optional[Dict[str, Any]]:
        job = self.store.get(C.SYNC_STATE, KEY)
        if not job or job.get("status") != "queued":
            return None
        job = dict(job, status="running", started_at=_iso(self.now()))
        self.store.upsert(C.SYNC_STATE, job)
        try:
            result = ReindexService(self.store).reindex(job.get("category") or None)
        except Exception as exc:  # the job records the failure; the worker keeps running
            job = dict(job, status="failed", finished_at=_iso(self.now()), error=str(exc)[:500])
            self.store.upsert(C.SYNC_STATE, job)
            audit.record(job["requested_by"], "content.reindex", "catalog", job.get("category") or "*",
                         outcome="failed", details={"error": job["error"], "background": True})
            return job
        job = dict(job, status="succeeded", finished_at=_iso(self.now()), result=result)
        self.store.upsert(C.SYNC_STATE, job)
        audit.record(job["requested_by"], "content.reindex", "catalog", job.get("category") or "*",
                     details=dict(result, background=True))
        return job

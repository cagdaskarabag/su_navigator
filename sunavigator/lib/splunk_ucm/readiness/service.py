"""Assess use cases against the environment snapshot and persist ``uc_readiness``."""

import dataclasses
from typing import Any, Callable, Dict, List, Optional

from ..audit import AuditService
from ..catalog.detail import key_from_id
from ..catalog.summary import STATUS_ACTIVE
from ..content.reindex import StoredNormalizer
from ..errors import NotFoundError, UcmError, ValidationError
from ..log import get_logger
from ..model.canonical import CRITICALITY_RANK, Requirement, UseCase
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..storage.repositories import CategoryRepository, ContentRepository
from ..util import new_id, utc_now_iso
from . import ENGINE_VERSION
from .evaluators import EvaluationSettings, evaluate
from .scoring import ScoringSettings, score
from .snapshot import EnvironmentSnapshot

log = get_logger(__name__)

JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_FAILED = "queued", "running", "succeeded", "failed"
STATE_KEY = "readiness::local"


@dataclasses.dataclass
class ReadinessSettings:
    evaluation: EvaluationSettings = dataclasses.field(default_factory=EvaluationSettings)
    scoring: ScoringSettings = dataclasses.field(default_factory=ScoringSettings)
    batch: int = 200
    job_timeout_seconds: int = 3600


def new_job(requested_by: str, source: str = "manual") -> Dict[str, Any]:
    job_id = new_id()
    return {"_key": "rjob::" + job_id, "doc_type": "readiness_job", "doc_schema": DOC_SCHEMA,
            "job_id": job_id, "source": source, "status": JOB_QUEUED, "requested_by": requested_by,
            "requested_at": utc_now_iso(), "errors": [], "totals": {}}


def _requirements(uc: UseCase) -> List[Requirement]:
    reqs = list(uc.requirements)
    if uc.spl and not any(r.type == "spl_validity" for r in reqs):
        reqs.append(Requirement(
            "spl_validity:primary", "spl_validity", "primary", "required", "derived_spl", "medium",
            "primary SPL parsed with Splunk search/parser"))
    return reqs


def assess_use_case(uc: UseCase, snap: EnvironmentSnapshot, settings: ReadinessSettings) -> Dict[str, Any]:
    results = []
    for req in _requirements(uc):
        r = dataclasses.asdict(req)
        ev = evaluate(r, snap, settings.evaluation, uc.content_id, uc.key)
        row = {
            "req_id": req.req_id, "type": req.type, "value": req.value, "level": req.level,
            "source": req.source, "confidence": req.confidence, **ev,
        }
        if req.attributes.get("any_of"):
            row["any_of"] = list(req.attributes["any_of"])
        results.append(row)
    summary = score(results, settings.scoring)
    return {
        "_key": uc.key, "doc_schema": DOC_SCHEMA, "content_id": uc.content_id,
        "record_id": uc.provenance.provider_record_id, "title": uc.title,
        "category_key": uc.category_key, "category_name": uc.category_name, "domains": uc.domains,
        "criticality": uc.criticality, "criticality_rank": CRITICALITY_RANK.get(uc.criticality, 0),
        "state": summary["state"], "score": summary["score"],
        "score_sort": -1 if summary["score"] is None else summary["score"],
        "coverage": summary["coverage"], "blockers": summary["blockers"], "gaps": summary["gaps"],
        "counts": summary["counts"], "unverified": summary["unverified"],
        "requirement_count": len(results), "results": results,
        "engine_version": ENGINE_VERSION, "evaluated_at": utc_now_iso(),
        "discovery_at": snap.discovered_at, "discovery_job_id": snap.discovery.get("last_completed_job_id"),
        "source_hash": uc.provenance.source_hash,
        "search_text": " ".join([uc.provenance.provider_record_id, uc.content_id, uc.title]).lower(),
    }


class ReadinessService:
    def __init__(self, store: DocumentStore, audit: AuditService, settings: Optional[ReadinessSettings] = None,
                 clock: Callable[[], str] = utc_now_iso):
        self.store = store
        self.audit = audit
        self.settings = settings or ReadinessSettings()
        self.clock = clock
        self.content = ContentRepository(store)
        self.categories = CategoryRepository(store)

    # -- state and jobs -------------------------------------------------------

    def state(self) -> Dict[str, Any]:
        return self.store.get(C.SYNC_STATE, STATE_KEY) or {"_key": STATE_KEY, "doc_type": "readiness_state"}

    def _save_state(self, state: Dict[str, Any]) -> None:
        state.update({"_key": STATE_KEY, "doc_type": "readiness_state", "updated_at": self.clock()})
        self.store.upsert(C.SYNC_STATE, state)

    def jobs(self, status: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"doc_type": "readiness_job"}
        if status:
            query["status"] = status
        return self.store.query(C.SYNC_STATE, query, sort=[("requested_at", -1)], limit=limit)

    def next_queued(self) -> Optional[Dict[str, Any]]:
        rows = self.store.query(C.SYNC_STATE, {"doc_type": "readiness_job", "status": JOB_QUEUED},
                                sort=[("requested_at", 1)], limit=1)
        return rows[0] if rows else None

    def save_job(self, job: Dict[str, Any]) -> None:
        job["updated_at"] = self.clock()
        self.store.upsert(C.SYNC_STATE, job)

    def enqueue(self, job: Dict[str, Any]) -> Dict[str, Any]:
        snap_state = self.store.get(C.SYNC_STATE, "discovery::local") or {}
        if not snap_state.get("last_completed_at"):
            raise ValidationError("run environment discovery before assessing readiness")
        active = self.jobs(JOB_QUEUED, 5) + self.jobs(JOB_RUNNING, 5)
        if active:
            raise ValidationError("a readiness job is already queued or running",
                                  {"job_id": active[0].get("job_id")})
        self.save_job(job)
        self.audit.record(job["requested_by"], "readiness.requested", "readiness_job", job["job_id"],
                          details={"source": job["source"]})
        return job

    def _prune_jobs(self, keep: int = 50) -> None:
        rows = self.store.query(C.SYNC_STATE, {"doc_type": "readiness_job"}, sort=[("requested_at", -1)],
                                skip=keep, fields=["_key"])
        for row in rows:
            self.store.delete(C.SYNC_STATE, row["_key"])

    # -- assessment -----------------------------------------------------------

    def assess_one(self, use_case_id: str, actor: str) -> Dict[str, Any]:
        key = key_from_id(use_case_id)
        snap = EnvironmentSnapshot.load(self.store)
        if not snap.discovered:
            raise ValidationError("run environment discovery before assessing readiness")
        stored = self.content.get_content(key)
        catalog = self.content.get_catalog(key)
        if not stored or not catalog:
            raise NotFoundError("use case not found", {"id": use_case_id})
        uc = StoredNormalizer(self.categories).normalize(stored)
        if uc is None:
            raise NotFoundError("stored content for this use case is unreadable", {"key": key})
        doc = assess_use_case(uc, snap, self.settings)
        doc["job_id"] = None
        self.store.upsert(C.READINESS, doc)
        self.audit.record(actor, "readiness.assessed", "use_case", uc.content_id,
                          details={"state": doc["state"], "score": doc["score"]})
        return doc

    def run(self, job: Dict[str, Any]) -> Dict[str, Any]:
        job["status"] = JOB_RUNNING
        job["started_at"] = self.clock()
        self.save_job(job)
        try:
            self._run(job)
            job["status"] = JOB_SUCCEEDED
        except UcmError as exc:
            job["status"] = JOB_FAILED
            job["errors"].append(exc.to_dict())
        except Exception as exc:
            job["status"] = JOB_FAILED
            job["errors"].append({"code": "internal_error", "message": str(exc)})
            log.exception("readiness job crashed", extra={"job_id": job["job_id"]})
        job["finished_at"] = self.clock()
        self.save_job(job)
        self._prune_jobs()
        state = self.state()
        state.update({"last_attempt_at": job["finished_at"], "last_attempt_status": job["status"],
                      "totals": job.get("totals")})
        if job["status"] == JOB_SUCCEEDED:
            state.update({"last_success_at": job["finished_at"],
                          "discovery_at": job.get("discovery_at"),
                          "content_at": job.get("content_at")})
        self._save_state(state)
        self.audit.record(job["requested_by"], "readiness.completed", "readiness_job", job["job_id"],
                          outcome=job["status"], details={"totals": job.get("totals"),
                                                          "errors": job["errors"][:5]})
        return job

    def _run(self, job: Dict[str, Any]) -> None:
        snap = EnvironmentSnapshot.load(self.store)
        if not snap.discovered:
            raise ValidationError("run environment discovery before assessing readiness")
        active = {r["_key"] for r in self.store.query(C.CATALOG, {"provider_status": STATUS_ACTIVE},
                                                      fields=["_key"])}
        normalizer = StoredNormalizer(self.categories)
        by_state: Dict[str, int] = {}
        pending: List[Dict[str, Any]] = []
        assessed = skipped = 0
        for stored in self.content.iter_content():
            if stored.get("_key") not in active:
                continue
            uc = normalizer.normalize(stored)
            if uc is None:
                skipped += 1
                continue
            doc = assess_use_case(uc, snap, self.settings)
            doc["job_id"] = job["job_id"]
            by_state[doc["state"]] = by_state.get(doc["state"], 0) + 1
            pending.append(doc)
            if len(pending) >= self.settings.batch:
                self.store.batch_save(C.READINESS, pending)
                assessed += len(pending)
                pending = []
        if pending:
            self.store.batch_save(C.READINESS, pending)
            assessed += len(pending)
        removed = 0
        for row in self.store.query(C.READINESS, None, fields=["_key"]):
            if row["_key"] not in active:
                self.store.delete(C.READINESS, row["_key"])
                removed += 1
        provider = self.store.get(C.SYNC_STATE, "provider::fenre") or {}
        job["discovery_at"] = snap.discovered_at
        job["content_at"] = provider.get("last_success_at") or ""
        job["totals"] = {"assessed": assessed, "skipped": skipped, "removed": removed, "by_state": by_state}

    # -- read -----------------------------------------------------------------

    def get(self, use_case_id: str) -> Optional[Dict[str, Any]]:
        doc = self.store.get(C.READINESS, key_from_id(use_case_id))
        if doc is None:
            return None
        return self.with_staleness(doc)

    def with_staleness(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        disc = self.store.get(C.SYNC_STATE, "discovery::local") or {}
        catalog = self.store.get(C.CATALOG, doc["_key"]) or {}
        reasons = []
        if disc.get("last_completed_at") and disc.get("last_completed_at") != doc.get("discovery_at"):
            reasons.append("newer_discovery")
        if catalog.get("source_hash") and catalog.get("source_hash") != doc.get("source_hash"):
            reasons.append("content_changed")
        if doc.get("engine_version") != ENGINE_VERSION:
            reasons.append("engine_upgraded")
        doc["stale"] = bool(reasons)
        doc["stale_reasons"] = reasons
        return doc

"""Guided, disabled-first deployment of use cases as saved searches (D-003, D-028, D-029).

Workflow state (``state``) belongs to the latest revision:

    draft ──submit──▶ pending_approval ──approve──▶ approved ──deploy──▶ deployed
      ▲                     │ reject                    │ deploy fails       │
      └──── edit ◀── rejected                          ▼                    │
                                                      failed ◀──────────────┘
    any state ──retire──▶ retired         (edit from any state starts a new draft)

The saved search itself is tracked separately in ``live`` (absent, disabled,
enabled, missing, unmanaged). Every deploy and rollback writes the search
**disabled**; enabling is a separate, audited step gated on readiness.
Approved SPL is copied into the revision, so later upstream changes never
alter what was approved.
"""

import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..audit import AuditService
from ..catalog.detail import key_from_id
from ..content.reindex import StoredNormalizer
from ..errors import ConflictError, NotFoundError, PermissionDenied, UcmError, UnsupportedOperation, ValidationError
from ..model.canonical import UseCase
from ..platform.search import SearchClient
from ..readiness.principal import NOT_MET, SchedulerAccess, check_access, scan_spl
from ..spl.analysis import analyze
from ..spl.lint import lint_search
from ..spl.parser import high_cost, parse
from ..spl.policy import classify, command_exists, expanded_pipeline
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..storage.repositories import CategoryRepository, ContentRepository
from ..util import new_id, safe_key, utc_now, utc_now_iso
from . import actions as action_rules
from . import revisions as revision_tools
from .actions import ActionPolicy
from .controltest import ControlTestRunner, bundle_hash, expectations, validate_bundle
from .savedsearch import SavedSearchClient
from .export import build_bundle
from .schedule import advisories as schedule_advisories, jittered_cron
from .spec import drift, is_managed_by_us, normalize_spec, saved_search_name, settings_for, spl_hash

DRAFT, PENDING, APPROVED, REJECTED, DEPLOYED, FAILED, RETIRED = (
    "draft", "pending_approval", "approved", "rejected", "deployed", "failed", "retired")
STATES = (DRAFT, PENDING, APPROVED, REJECTED, DEPLOYED, FAILED, RETIRED)
LIVE_ABSENT, LIVE_DISABLED, LIVE_ENABLED, LIVE_MISSING, LIVE_UNMANAGED = (
    "absent", "disabled", "enabled", "missing", "unmanaged")

MAX_HISTORY = 100
MIN_OVERRIDE_REASON = 10
MIN_NOTE = 5
OUTCOMES = ("needs_tuning", "waiting_on_data", "none")
OVERRIDE_ACTIONS = ("remind", "disable")
SYSTEM_ACTOR = "system:override-expiry"


class DeploymentSettings:
    def __init__(self, require_approval: bool = True, allow_self_approval: bool = False,
                 block_enable_states: Sequence[str] = ("blocked",), cron: str = "*/15 * * * *",
                 earliest: str = "-20m@m", latest: str = "-5m@m", alert_mode: str = "track",
                 max_revisions: int = 20, verify_interval_minutes: int = 60,
                 extra_safe_commands: Sequence[str] = (), schedule_window: str = "auto",
                 scheduled_owner: str = "", cron_jitter: bool = False, actions: Optional[ActionPolicy] = None,
                 enable_second_person: bool = False, enable_request_hours: int = 24, override_days: int = 14,
                 override_expiry_action: str = "remind", override_second_person: bool = True,
                 verify_audit_window_seconds: int = 300):
        self.verify_audit_window_seconds = max(0, verify_audit_window_seconds)
        self.enable_second_person = enable_second_person
        self.override_second_person = override_second_person
        self.enable_request_hours = enable_request_hours
        self.override_days = override_days
        self.override_expiry_action = override_expiry_action if override_expiry_action in OVERRIDE_ACTIONS else "remind"
        self.actions = actions or ActionPolicy()
        self.scheduled_owner = scheduled_owner
        self.cron_jitter = cron_jitter
        self.extra_safe_commands = tuple(extra_safe_commands)
        self.schedule_window = schedule_window
        self.require_approval = require_approval
        self.allow_self_approval = allow_self_approval
        self.block_enable_states = tuple(block_enable_states)
        self.cron = cron
        self.earliest = earliest
        self.latest = latest
        self.alert_mode = alert_mode
        self.max_revisions = max_revisions
        self.verify_interval_minutes = verify_interval_minutes

    def defaults(self) -> Dict[str, str]:
        return {"cron": self.cron, "earliest": self.earliest, "latest": self.latest,
                "alert_mode": self.alert_mode, "schedule_window": self.schedule_window}


def deployment_key(catalog_key: str) -> str:
    return safe_key("dep", catalog_key)


class DeploymentService:
    def __init__(self, store: DocumentStore, audit: AuditService, search: SearchClient,
                 saved: SavedSearchClient, settings: Optional[DeploymentSettings] = None,
                 control_runner: Optional[ControlTestRunner] = None,
                 access: Optional[SchedulerAccess] = None,
                 handoff: Optional[Callable[[UseCase], Optional[Dict[str, Any]]]] = None):
        self.access = access
        self.handoff = handoff
        self.store = store
        self.audit = audit
        self.search = search
        self.saved = saved
        self.settings = settings or DeploymentSettings()
        self.control_runner = control_runner
        self.content = ContentRepository(store)
        self.categories = CategoryRepository(store)

    # -- reads ---------------------------------------------------------------

    def get(self, content_id: str) -> Optional[Dict[str, Any]]:
        doc = self.store.get(C.DEPLOYMENTS, deployment_key(key_from_id(content_id)))
        return self._decorate(doc) if doc else None

    def list(self, states: Sequence[str] = (), live: Sequence[str] = (), offset: int = 0,
             count: int = 50, drifted: bool = False, outcomes: Sequence[str] = (),
             override_active: bool = False) -> Dict[str, Any]:
        count = max(1, min(200, count))
        clauses: List[Dict[str, Any]] = []
        if states:
            bad = [s for s in states if s not in STATES]
            if bad:
                raise ValidationError("invalid state", {"allowed": list(STATES)})
            clauses.append({"$or": [{"state": s} for s in states]})
        if live:
            clauses.append({"$or": [{"live_status": s} for s in live]})
        if drifted:
            clauses.append({"live_drift": True})
        if outcomes:
            bad = [o for o in outcomes if o not in OUTCOMES[:2]]
            if bad:
                raise ValidationError("invalid outcome", {"allowed": list(OUTCOMES[:2])})
            clauses.append({"$or": [{"outcome_value": o} for o in outcomes]})
        if override_active:
            clauses.append({"override_active": True})
        query = {"$and": clauses} if len(clauses) > 1 else (clauses[0] if clauses else None)
        rows = self.store.query(C.DEPLOYMENTS, query, sort=[("updated_at", -1)], skip=offset, limit=count + 1,
                                fields=["content_id", "catalog_key", "title", "record_id", "state", "revision",
                                        "deployed_revision", "live", "live_status", "saved_search", "updated_at",
                                        "updated_by", "last_error", "criticality", "notify", "outcome", "override",
                                        "enable_request"])
        items = [self._decorate(r, summary=True) for r in rows[:count]]
        return {"items": items, "offset": offset, "count": len(items), "has_more": len(rows) > count}

    def summary(self) -> Dict[str, Any]:
        rows = self.store.query(C.DEPLOYMENTS, None, fields=["state", "live_status"])
        by_state: Dict[str, int] = {s: 0 for s in STATES}
        by_live: Dict[str, int] = {}
        drifted = 0
        for r in rows:
            by_state[r.get("state", DRAFT)] = by_state.get(r.get("state", DRAFT), 0) + 1
            by_live[r.get("live_status") or LIVE_ABSENT] = by_live.get(r.get("live_status") or LIVE_ABSENT, 0) + 1
        for r in self.store.query(C.DEPLOYMENTS, {"live_drift": True}, fields=["_key"]):
            drifted += 1
        return {"total": len(rows), "by_state": by_state, "by_live": by_live, "drifted": drifted,
                "pipeline": self.pipeline()}

    def pipeline(self) -> Dict[str, int]:
        """Where deployments stand, in the order work flows, and the ones that need a person's attention."""
        rows = self.store.query(C.DEPLOYMENTS, None, fields=["state", "live_status", "live_drift", "outcome_value",
                                                              "override", "enable_request", "deployed_revision"])
        out = {"draft": 0, "pending_approval": 0, "approved": 0, "deployed": 0, "enabled": 0, "needs_tuning": 0,
               "waiting_on_data": 0, "override_expired": 0, "override_active": 0, "enable_requested": 0, "failed": 0,
               "rejected": 0, "drifted": 0}
        now = utc_now_iso()
        for r in rows:
            state = r.get("state")
            if state in ("draft", "pending_approval", "approved", "failed", "rejected"):
                out[state] += 1
            if state != RETIRED and r.get("deployed_revision"):
                out["enabled" if r.get("live_status") == LIVE_ENABLED else "deployed"] += 1
            if r.get("outcome_value") in ("needs_tuning", "waiting_on_data"):
                out[r["outcome_value"]] += 1
            override = r.get("override") or {}
            if override:
                out["override_active"] += 1
                if override.get("expires_at") and override["expires_at"] <= now:
                    out["override_expired"] += 1
            if self._request_active(r, now):
                out["enable_requested"] += 1
            if r.get("live_drift"):
                out["drifted"] += 1
        return out

    def export(self, actor: str) -> Dict[str, Any]:
        bundle = build_bundle(self.store.query(C.DEPLOYMENTS, None))
        self.audit.record(actor, "deployment.export", "deployment", "*",
                          details={"count": bundle["count"], "skipped": bundle["skipped"],
                                   "sha256": bundle["sha256"]})
        return bundle

    def allowed_actions(self, doc: Optional[Dict[str, Any]], user: str, caps: Sequence[str]) -> List[str]:
        can_deploy = "ucm_deploy" in caps
        can_propose = can_deploy or "ucm_run_discovery" in caps
        out: List[str] = []
        if doc is None:
            return ["draft"] if can_propose else []
        state = doc.get("state")
        live = (doc.get("live") or {}).get("status", LIVE_ABSENT)
        if can_propose:
            out.append("draft")
            if state == DRAFT:
                out.append("submit")
        if can_deploy:
            latest = self._latest(doc) or {}
            if state == PENDING and (self.settings.allow_self_approval or latest.get("submitted_by") != user):
                out.extend(["approve", "reject"])
            elif state == PENDING:
                out.append("reject")
            if state in (APPROVED, FAILED) and latest.get("approved_by"):
                out.append("deploy")
                if doc.get("deployed_revision") != latest.get("rev"):
                    out.append("withdraw")
            if doc.get("deployed_revision") and live in (LIVE_DISABLED, LIVE_ENABLED):
                out.append("enable" if live == LIVE_DISABLED else "disable")
                if live == LIVE_DISABLED and self._request_active(doc, utc_now_iso()):
                    out.append("cancel_enable")
                if self._previous_deployed(doc):
                    out.append("rollback")
            if state != RETIRED:
                out.append("retire")
            if doc.get("deployed_revision"):
                out.append("verify")
                out.append("outcome")
                if self.control_runner is not None:
                    out.append("controltest")
        elif can_propose and doc.get("deployed_revision"):
            out.append("verify")
        return out

    # -- workflow ------------------------------------------------------------

    def save_draft(self, actor: str, content_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        uc = self._load(content_id)
        spec = normalize_spec(body, self.settings.defaults())
        actions = action_rules.normalize_actions(body.get("actions"), self.settings.actions, spec["alert_mode"],
                                                 spec["suppress_period"])
        if self.settings.cron_jitter and not str(body.get("cron") or "").strip():
            spec["cron"] = jittered_cron(spec["cron"], uc.key)
        spl = {"primary": uc.spl, "cim": uc.cim_spl, "custom": spec["custom_spl"]}[spec["spl_source"]]
        if not spl:
            raise ValidationError("this use case has no %s SPL; choose another source or a custom search"
                                  % spec["spl_source"])
        check = self._check_spl(spl)
        key = deployment_key(uc.key)
        doc = self.store.get(C.DEPLOYMENTS, key)
        existed = doc is not None
        doc = doc or self._new(uc, actor)
        prev_state = doc.get("state")
        revisions = doc.setdefault("revisions", [])
        latest = revisions[-1] if revisions else None
        replaced_draft = latest is not None and prev_state == DRAFT and not latest.get("submitted_at")
        if replaced_draft:
            rev_no = latest["rev"]
            revisions.pop()
        else:
            rev_no = (latest["rev"] + 1) if latest else 1
        readiness = self.store.get(C.READINESS, uc.key) or {}
        revision = {
            "rev": rev_no, "spl": spl, "spl_hash": spl_hash(spl), "spl_source": spec["spl_source"],
            "cron": spec["cron"], "earliest": spec["earliest"], "latest": spec["latest"],
            "schedule_window": spec["schedule_window"], "suppress_period": spec["suppress_period"],
            "suppress_fields": spec["suppress_fields"], "spl_time_bounds": analyze(spl).has_time_bounds,
            "alert_mode": spec["alert_mode"], "severity": spec["severity"], "threshold": spec["threshold"],
            "actions": actions, "notes": spec["notes"], "content_source_hash": uc.provenance.source_hash,
            "readiness_state": readiness.get("state"), "readiness_score": readiness.get("score"),
            "created_by": actor, "created_at": utc_now_iso(),
        }
        revision.update(check)
        revision["schedule_advisories"] = schedule_advisories(spec["cron"], spec["earliest"], spec["latest"],
                                                              spec["suppress_period"])
        parallel = self._parallel_copy(uc)
        if parallel:
            revision["parallel_copy"] = parallel
        revisions.append(revision)
        doc["revision"] = rev_no
        doc["notify"] = action_rules.kinds(actions)
        doc["state"] = DRAFT
        doc["title"] = uc.title
        doc["criticality"] = uc.criticality
        self._trim_revisions(doc)
        self._history(doc, actor, "draft", prev_state, DRAFT, rev_no, spec["notes"][:200])
        self._save(doc, actor)
        details = {"revision": rev_no, "from": prev_state if existed else "none", "replaced_draft": replaced_draft,
                   "spl_source": spec["spl_source"], "parse_ok": check["parse_ok"], "side_effects": check["side_effects"],
                   "review_commands": check["review_commands"], "actions": action_rules.summary(actions)}
        if parallel:
            details["parallel_copy"] = parallel
        self.audit.record(actor, "deployment.draft", "deployment", uc.content_id, details=details)
        return self._decorate(doc)

    def _parallel_copy(self, uc: UseCase) -> Optional[Dict[str, Any]]:
        """Informational record that ESCU's own copy was enabled or ES present at draft time (D-067)."""
        if self.handoff is None:
            return None
        try:
            return self.handoff(uc)
        except Exception:
            return None

    def submit(self, actor: str, content_id: str, note: str = "", acknowledge_commands: bool = False,
               acknowledge_actions: bool = False) -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (DRAFT,), "submit")
        rev = self._latest(doc)
        self._require_clean_spl(rev)
        if not self.settings.require_approval:
            self._acknowledge(rev, actor, acknowledge_commands)
            self._acknowledge_actions(rev, actor, acknowledge_actions)
        rev["submitted_by"] = actor
        rev["submitted_at"] = utc_now_iso()
        access = self.scheduler_access(rev)
        rev["scheduler_access"] = {"status": access["status"], "code": access["code"],
                                   "detail": access["detail"][:500], "checked_at": utc_now_iso()}
        target = PENDING
        if not self.settings.require_approval:
            rev["approved_by"] = actor
            rev["approved_at"] = rev["submitted_at"]
            rev["approval"] = "not_required"
            target = APPROVED
        self._transition(doc, actor, "submit", target, note,
                         {"scheduler_access": access["status"], "scheduler_access_code": access["code"]})
        return self._decorate(doc)

    def approve(self, actor: str, content_id: str, note: str = "", acknowledge_commands: bool = False,
                acknowledge_actions: bool = False, access_reason: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (PENDING,), "approve")
        rev = self._latest(doc)
        if rev.get("submitted_by") == actor and not self.settings.allow_self_approval:
            raise PermissionDenied("the submitter cannot approve their own deployment "
                                   "(ucm.conf [deployment] allow_self_approval)")
        self._require_clean_spl(rev)
        access = self.scheduler_access(rev)
        reason = (access_reason or "").strip()
        if access["status"] == NOT_MET and len(reason) < MIN_OVERRIDE_REASON:
            raise ConflictError("%s Approving a revision that cannot see its data needs a reason (at least %d characters)."
                                % (access["detail"].split(" A scheduled run")[0], MIN_OVERRIDE_REASON),
                                {"code": "access_gap_reason_required", "scheduler_access": access["status"],
                                 "scheduler_access_code": access["code"]})
        self._acknowledge(rev, actor, acknowledge_commands)
        self._acknowledge_actions(rev, actor, acknowledge_actions)
        rev["approved_by"] = actor
        rev["approved_at"] = utc_now_iso()
        rev["approval"] = "approved"
        details = {"acknowledged_commands": rev.get("acknowledged_commands") or [],
                   "actions": action_rules.summary(rev.get("actions") or {}),
                   "scheduler_access": access["status"], "scheduler_access_code": access["code"]}
        if access["status"] == NOT_MET:
            rev["approved_with_access_gap"] = {"reason": reason[:500], "by": actor, "at": rev["approved_at"],
                                               "code": access["code"], "detail": access["detail"][:500]}
            details["access_gap_reason"] = reason[:500]
        self._transition(doc, actor, "approve", APPROVED, note, details)
        return self._decorate(doc)

    def reject(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (PENDING,), "reject")
        rev = self._latest(doc)
        rev["rejected_by"] = actor
        rev["rejected_at"] = utc_now_iso()
        self._transition(doc, actor, "reject", REJECTED, note)
        return self._decorate(doc)

    def withdraw(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        """Take back an approval before the revision is deployed. A withdrawn approval cannot be deployed (D-075)."""
        doc = self._require(content_id)
        self._expect(doc, (APPROVED, FAILED), "withdraw the approval of")
        rev = self._latest(doc)
        if not rev.get("approved_by"):
            raise ConflictError("revision %d is not approved" % rev["rev"], {"code": "not_approved"})
        if doc.get("deployed_revision") == rev["rev"]:
            raise ConflictError("revision %d is already deployed; roll back or retire instead" % rev["rev"],
                                {"code": "already_deployed"})
        if len((note or "").strip()) < MIN_NOTE:
            raise ValidationError("withdrawing an approval needs a reason (at least %d characters)" % MIN_NOTE)
        was = rev.get("approval")
        log = rev.setdefault("approval_withdrawn", [])
        log.append({"by": actor, "at": utc_now_iso(), "approved_by": rev.get("approved_by"), "note": note.strip()[:500]})
        del log[:-10]
        for key in ("approved_by", "approved_at", "approval", "acknowledged_commands", "acknowledged_by",
                    "actions_acknowledged_by", "actions_acknowledged_at", "actions_acknowledged_digest"):
            rev.pop(key, None)
        target = DRAFT if was == "not_required" else PENDING
        if target == DRAFT:
            for key in ("submitted_by", "submitted_at"):
                rev.pop(key, None)
        doc["last_error"] = ""
        self._transition(doc, actor, "withdraw", target, note.strip(), {"withdrawn_approval_of": log[-1]["approved_by"]})
        return self._decorate(doc)

    def deploy(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (APPROVED, FAILED), "deploy")
        rev = self._latest(doc)
        if not rev.get("approved_by"):
            raise ConflictError("revision %d is not approved" % rev["rev"], {"code": "not_approved"})
        recheck = self._check_spl(rev["spl"])
        rev.update(recheck)
        self._require_clean_spl(rev)
        self._require_acknowledged(rev)
        self._require_actions_ready(rev)
        name = doc["saved_search"]["name"]
        settings = settings_for(rev, doc["content_id"], disabled=True)
        try:
            live = self.saved.get(name)
            if live is None:
                self.saved.create(name, settings)
            elif is_managed_by_us(live, doc["content_id"]):
                self.saved.update(name, settings)
            else:
                raise ConflictError("a saved search named %r exists and is not managed by this app" % name,
                                    {"code": "name_conflict"})
        except UcmError as exc:
            self._fail(doc, actor, "deploy", exc.message)
            raise
        observed = self.saved.get(name)
        problems = drift(rev, observed, True, self.settings.scheduled_owner) if observed else [{"field": "*", "detail": "not found after write"}]
        if problems:
            if observed:
                self._safe_disable(name)
            self._set_live(doc, observed, True, rev, problems)
            self._fail(doc, actor, "deploy", "verification failed after write", problems)
            return self._decorate(doc)
        rev["deployed_by"] = actor
        rev["deployed_at"] = utc_now_iso()
        doc["deployed_revision"] = rev["rev"]
        doc["last_error"] = ""
        self._set_live(doc, observed, True, rev, [])
        self._transition(doc, actor, "deploy", DEPLOYED, note, {"saved_search": name, "disabled": True})
        return self._decorate(doc)

    def enable(self, actor: str, content_id: str, override_reason: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        rev = self._deployed(doc)
        self._check_actions_policy(rev)
        readiness = self.store.get(C.READINESS, doc["catalog_key"]) or {}
        state = readiness.get("state") or "not_assessed"
        access = self.scheduler_access(rev)
        blocked_by: List[str] = []
        if state in self.settings.block_enable_states:
            blocked_by.append("readiness is %s" % state)
        if access["status"] == NOT_MET:
            blocked_by.append(access["detail"].split(" A scheduled run")[0])
        override = ""
        if blocked_by:
            if len((override_reason or "").strip()) < MIN_OVERRIDE_REASON:
                code = "readiness_gate" if state in self.settings.block_enable_states else "scheduler_access_gate"
                raise ConflictError("%s; enabling needs an override reason (at least %d characters)"
                                    % ("; ".join(blocked_by), MIN_OVERRIDE_REASON),
                                    {"code": code, "readiness": state, "scheduler_access": access["status"]})
            override = override_reason.strip()[:500]
        request = None
        if self.settings.enable_second_person or (blocked_by and self.settings.override_second_person):
            request = doc.get("enable_request") if self._request_active(doc, utc_now_iso()) else None
            if request is None:
                doc["enable_request"] = {"by": actor, "at": utc_now_iso(), "revision": rev["rev"],
                                         "expires_at": self._later_iso(self.settings.enable_request_hours),
                                         "override_reason": override}
                self._history(doc, actor, "enable_requested", doc["state"], doc["state"], rev["rev"], override)
                self._save(doc, actor)
                self.audit.record(actor, "deployment.enable_requested", "deployment", doc["content_id"],
                                  details={"revision": rev["rev"], "blocked_by": blocked_by,
                                           "override_reason": override,
                                           "expires_at": doc["enable_request"]["expires_at"]})
                return self._decorate(doc)
            if request["by"] == actor and not self.settings.allow_self_approval:
                raise ConflictError("a different person must confirm enabling this search; %s asked for it"
                                    % request["by"], {"code": "second_person_required", "requested_by": request["by"]})
            doc.pop("enable_request", None)
        catalog = self.store.get(C.CATALOG, doc["catalog_key"]) or {}
        details = {"readiness_state": state, "override_reason": override,
                   "scheduler_access": access["status"], "scheduler_access_code": access["code"],
                   "provider_status": catalog.get("provider_status")}
        if request:
            details["requested_by"] = request["by"]
        if override:
            expires = self._later_iso(self.settings.override_days * 24) if self.settings.override_days else ""
            doc["override"] = {"reason": override, "by": actor, "at": utc_now_iso(), "expires_at": expires,
                               "blocked_by": blocked_by, "reminded_at": ""}
            doc["override_active"] = True
            details["override_expires_at"] = expires
        return self._set_enabled(doc, actor, rev, True, "enable", details)

    def cancel_enable(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        request = doc.get("enable_request")
        if not request:
            raise ConflictError("no request to enable this search is open", {"code": "no_enable_request"})
        doc.pop("enable_request", None)
        self._history(doc, actor, "enable_request_cancelled", doc["state"], doc["state"], request.get("revision"), note)
        self._save(doc, actor)
        self.audit.record(actor, "deployment.enable_request_cancelled", "deployment", doc["content_id"],
                          details={"requested_by": request.get("by"), "note": (note or "")[:200]})
        return self._decorate(doc)

    def set_outcome(self, actor: str, content_id: str, outcome: str, note: str = "") -> Dict[str, Any]:
        """Record what happened after deployment: needs tuning, waiting on data, or neither (D-075)."""
        if outcome not in OUTCOMES:
            raise ValidationError("invalid outcome", {"allowed": list(OUTCOMES)})
        doc = self._require(content_id)
        rev = self._deployed(doc)
        if outcome == "none":
            doc.pop("outcome", None)
            doc["outcome_value"] = ""
        else:
            if len((note or "").strip()) < MIN_NOTE:
                raise ValidationError("an outcome needs a note saying why (at least %d characters)" % MIN_NOTE)
            doc["outcome"] = {"value": outcome, "note": note.strip()[:500], "set_by": actor, "set_at": utc_now_iso(),
                              "revision": rev["rev"]}
            doc["outcome_value"] = outcome
        self._history(doc, actor, "outcome", doc["state"], doc["state"], rev["rev"], "%s: %s" % (outcome, note or ""))
        self._save(doc, actor)
        self.audit.record(actor, "deployment.outcome", "deployment", doc["content_id"],
                          details={"outcome": outcome, "revision": rev["rev"], "note": (note or "")[:200]})
        return self._decorate(doc)

    def diff(self, content_id: str, from_rev: int, to_rev: int) -> Dict[str, Any]:
        doc = self._require(content_id)
        if from_rev == to_rev:
            raise ValidationError("choose two different revisions")
        missing = revision_tools.unavailable(doc, (from_rev, to_rev))
        if missing is not None:
            if any(part.get("missing") for part in missing["revisions"]):
                raise NotFoundError("revision not found", {"from": from_rev, "to": to_rev})
            return missing
        older, newer = sorted((revision_tools.find(doc, from_rev)["full"], revision_tools.find(doc, to_rev)["full"]),
                              key=lambda r: r["rev"])
        return revision_tools.diff_revisions(older, newer)

    # -- time-limited override and enable request -------------------------------

    @staticmethod
    def _later_iso(hours: float) -> str:
        return (utc_now() + datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _request_active(doc: Dict[str, Any], now: str) -> bool:
        request = doc.get("enable_request") or {}
        return bool(request) and str(request.get("expires_at") or "") > now \
            and request.get("revision") == doc.get("deployed_revision")

    def sweep_overrides(self, now: Optional[str] = None) -> Dict[str, int]:
        """Remind (or disable) when an override has run out, and drop an override whose reason no longer holds."""
        now = now or utc_now_iso()
        totals = {"checked": 0, "cleared": 0, "expired": 0, "disabled": 0, "errors": 0}
        for row in self.store.query(C.DEPLOYMENTS, {"override_active": True}, fields=["content_id"], limit=500):
            try:
                doc = self._require(row["content_id"])
                override = doc.get("override")
                if not override:
                    doc["override_active"] = False
                    self._save(doc, SYSTEM_ACTOR)
                    continue
                totals["checked"] += 1
                rev = self._deployed(doc)
                readiness = (self.store.get(C.READINESS, doc["catalog_key"]) or {}).get("state") or "not_assessed"
                still = readiness in self.settings.block_enable_states or self.scheduler_access(rev)["status"] == NOT_MET
                if not still:
                    self._drop_override(doc)
                    self._history(doc, SYSTEM_ACTOR, "override_cleared", doc["state"], doc["state"], rev["rev"],
                                  "the reason for the override no longer applies")
                    self._save(doc, SYSTEM_ACTOR)
                    self.audit.record(SYSTEM_ACTOR, "deployment.override_cleared", "deployment", doc["content_id"],
                                      details={"revision": rev["rev"], "reason": override.get("reason")})
                    totals["cleared"] += 1
                    continue
                if override.get("expires_at") and override["expires_at"] <= now and not override.get("reminded_at"):
                    override["reminded_at"] = now
                    self._history(doc, SYSTEM_ACTOR, "override_expired", doc["state"], doc["state"], rev["rev"],
                                  override.get("reason") or "")
                    self._save(doc, SYSTEM_ACTOR)
                    self.audit.record(SYSTEM_ACTOR, "deployment.override_expired", "deployment", doc["content_id"],
                                      outcome="failure",
                                      details={"revision": rev["rev"], "reason": override.get("reason"),
                                               "enabled_by": override.get("by"), "expired_at": override["expires_at"],
                                               "action": self.settings.override_expiry_action})
                    totals["expired"] += 1
                    if self.settings.override_expiry_action == "disable" and \
                            (doc.get("live") or {}).get("status") == LIVE_ENABLED:
                        self._set_enabled(doc, SYSTEM_ACTOR, rev, False, "disable",
                                          {"note": "the override of %s expired" % override.get("by")})
                        totals["disabled"] += 1
            except UcmError:
                totals["errors"] += 1
        return totals

    @staticmethod
    def _drop_override(doc: Dict[str, Any]) -> None:
        doc.pop("override", None)
        doc["override_active"] = False

    @staticmethod
    def _override_status(doc: Dict[str, Any], now: str) -> Optional[Dict[str, Any]]:
        override = doc.get("override")
        if not override:
            return None
        expires = override.get("expires_at") or ""
        return {"reason": override.get("reason"), "by": override.get("by"), "at": override.get("at"),
                "expires_at": expires, "expired": bool(expires) and expires <= now,
                "blocked_by": override.get("blocked_by") or []}

    def scheduler_access_for(self, doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """The check for the deployed revision, or the latest one before anything is deployed."""
        if not doc:
            return None
        revs = doc.get("revisions") or []
        number = doc.get("deployed_revision")
        rev = next((r for r in revs if r.get("rev") == number), None) if number else (revs[-1] if revs else None)
        if rev is None:
            return None
        out = self.scheduler_access(rev)
        out["revision"] = rev.get("rev")
        return out

    def scheduler_access(self, rev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Index access of the scheduled owner for a revision's SPL, read live."""
        if not rev:
            return check_access(None, None)
        scan = rev.get("access_scan") or scan_spl(rev.get("spl") or "")
        if self.access is None:
            return check_access(None, scan)
        return self.access.check(scan)

    def disable(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        rev = self._deployed(doc)
        return self._set_enabled(doc, actor, rev, False, "disable", {"note": note[:200]})

    def rollback(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        current = self._deployed(doc)
        prev = self._previous_deployed(doc)
        if prev is None:
            raise ConflictError("no earlier deployed revision to roll back to", {"code": "no_previous_revision"})
        name = doc["saved_search"]["name"]
        self._require_managed(doc, name)
        self._check_actions_policy(prev)
        try:
            self.saved.update(name, settings_for(prev, doc["content_id"], disabled=True))
        except UcmError as exc:
            self._fail(doc, actor, "rollback", exc.message, keep_state=True)
            raise
        observed = self.saved.get(name)
        problems = drift(prev, observed, True, self.settings.scheduled_owner) if observed else [{"field": "*", "detail": "not found after write"}]
        self._set_live(doc, observed, True, prev, problems)
        self._drop_override(doc)
        doc.pop("enable_request", None)
        doc["deployed_revision"] = prev["rev"]
        prev["rolled_back_at"] = utc_now_iso()
        target = DEPLOYED if doc["state"] in (DEPLOYED, FAILED) else doc["state"]
        self._transition(doc, actor, "rollback", target, note,
                         {"from_revision": current["rev"], "to_revision": prev["rev"], "drift": len(problems)})
        return self._decorate(doc)

    def retire(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        if doc.get("state") == RETIRED:
            raise ConflictError("deployment is already retired", {"code": "invalid_transition"})
        name = doc["saved_search"]["name"]
        removed = False
        if doc.get("deployed_revision"):
            live = self.saved.get(name)
            if live is not None:
                if not is_managed_by_us(live, doc["content_id"]):
                    raise ConflictError("saved search %r is not managed by this app; it was left in place" % name,
                                        {"code": "unmanaged"})
                removed = self.saved.delete(name)
        doc["deployed_revision"] = None
        self._drop_override(doc)
        for key in ("enable_request", "outcome"):
            doc.pop(key, None)
        doc["outcome_value"] = ""
        doc["live"] = {"status": LIVE_ABSENT, "verified_at": utc_now_iso(), "drift": []}
        self._transition(doc, actor, "retire", RETIRED, note, {"saved_search_removed": removed})
        return self._decorate(doc)

    def verify(self, actor: str, content_id: str, audit_always: bool = True) -> Dict[str, Any]:
        doc = self._require(content_id)
        before = (doc.get("live") or {}).get("status")
        before_drift = bool((doc.get("live") or {}).get("drift"))
        self._refresh_live(doc)
        self._save(doc, actor)
        live = doc["live"]
        changed = live["status"] != before or bool(live.get("drift")) != before_drift
        if changed or (audit_always and not self.audit.written_within(
                "deployment.verified", doc["content_id"], self.settings.verify_audit_window_seconds)):
            self.audit.record(actor, "deployment.verified", "deployment", doc["content_id"],
                              outcome="success" if not live.get("drift") and live["status"] not in (
                                  LIVE_MISSING, LIVE_UNMANAGED) else "failure",
                              details={"live": live["status"], "drift": live.get("drift")})
        return self._decorate(doc)

    def verify_all(self, actor: str, limit: int = 500) -> Dict[str, int]:
        totals = {"checked": 0, "drifted": 0, "missing": 0, "errors": 0}
        rows = self.store.query(C.DEPLOYMENTS, {"deployed_revision": {"$gte": 1}}, fields=["content_id"],
                                limit=limit)
        for row in rows:
            try:
                doc = self.verify(actor, row["content_id"], audit_always=False)
            except UcmError:
                totals["errors"] += 1
                continue
            totals["checked"] += 1
            if doc["live"].get("drift"):
                totals["drifted"] += 1
            if doc["live"]["status"] in (LIVE_MISSING, LIVE_UNMANAGED):
                totals["missing"] += 1
        swept = self.sweep_overrides()
        totals["overrides_expired"] = swept["expired"]
        totals["overrides_cleared"] = swept["cleared"]
        return totals

    # -- control tests (D-054) -------------------------------------------------

    def import_fixtures(self, actor: str, bundle: Any) -> Dict[str, Any]:
        provider, fixtures = validate_bundle(bundle)
        batch = bundle_hash(bundle)
        now = utc_now_iso()
        docs = []
        for fx in fixtures:
            content_id = "%s:UC-%s" % (provider, fx["uc_id"])
            docs.append({"_key": safe_key("cf", key_from_id(content_id)), "content_id": content_id,
                         "provider": provider, "batch": batch, "sourcetype": fx["sourcetype"],
                         "host": fx["host"], "min_count": fx["min_count"], "positive": fx["positive"],
                         "negative": fx.get("negative", ""), "imported_at": now, "imported_by": actor,
                         **expectations(fx)})
        if docs:
            self.store.batch_save(C.CONTROL_FIXTURES, docs)
        self.store.delete_query(C.CONTROL_FIXTURES, {"provider": provider, "batch": {"$ne": batch}})
        self.audit.record(actor, "controltest.import", "controltest", provider,
                          details={"count": len(docs), "batch": batch})
        return {"provider": provider, "count": len(docs), "batch": batch}

    def control_test(self, actor: str, content_id: str) -> Dict[str, Any]:
        doc = self._require(content_id)
        rev = self._deployed(doc)
        if self.control_runner is None:
            raise UnsupportedOperation("control tests are not configured")
        if rev.get("side_effects"):
            result = {"status": "not_runnable",
                      "reason": "the deployed search has side effects: " + ", ".join(rev["side_effects"])}
        else:
            fixture = self.store.get(C.CONTROL_FIXTURES, safe_key("cf", key_from_id(content_id)))
            if fixture is None:
                result = {"status": "no_fixture", "reason": "no control fixture is imported for this use case",
                          "test_index": self.control_runner.test_index}
            else:
                result = self.control_runner.run(rev.get("spl") or "", fixture)
        result = dict(result, revision=rev["rev"], ran_at=utc_now_iso(), ran_by=actor)
        doc["control_test"] = result
        self._save(doc, actor)
        self.audit.record(actor, "deployment.controltest", "deployment", doc["content_id"],
                          outcome="success" if result["status"] == "passed" else "failure",
                          details={"status": result["status"], "revision": rev["rev"],
                                   "reason": result.get("reason", "")[:500]})
        return self._decorate(doc)

    # -- internals -----------------------------------------------------------

    def _set_enabled(self, doc: Dict[str, Any], actor: str, rev: Dict[str, Any], enabled: bool,
                     action: str, details: Dict[str, Any]) -> Dict[str, Any]:
        name = doc["saved_search"]["name"]
        self._require_managed(doc, name)
        try:
            self.saved.update(name, {"disabled": "0" if enabled else "1"})
        except UcmError as exc:
            self._fail(doc, actor, action, exc.message, keep_state=True)
            raise
        observed = self.saved.get(name)
        problems = drift(rev, observed, not enabled, self.settings.scheduled_owner) if observed else [{"field": "*", "detail": "not found"}]
        self._set_live(doc, observed, not enabled, rev, problems)
        if not enabled:
            self._drop_override(doc)
            doc.pop("enable_request", None)
        details = dict(details)
        details["drift"] = len(problems)
        self._history(doc, actor, action, doc["state"], doc["state"], rev["rev"],
                      details.get("override_reason") or details.get("note") or "")
        self._save(doc, actor)
        self.audit.record(actor, "deployment." + action, "deployment", doc["content_id"],
                          outcome="success" if not problems else "failure",
                          details=dict(details, saved_search=name, revision=rev["rev"]))
        return self._decorate(doc)

    def _refresh_live(self, doc: Dict[str, Any]) -> None:
        name = doc["saved_search"]["name"]
        observed = self.saved.get(name)
        now = utc_now_iso()
        if not doc.get("deployed_revision"):
            status = LIVE_ABSENT if observed is None else LIVE_UNMANAGED
            doc["live"] = {"status": status, "verified_at": now, "drift": []}
            doc["live_status"] = status
            doc["live_drift"] = False
            return
        rev = self._rev(doc, doc["deployed_revision"])
        expected_disabled = bool((doc.get("live") or {}).get("expected_disabled", True))
        if observed is None:
            doc["live"] = {"status": LIVE_MISSING, "verified_at": now, "expected_disabled": expected_disabled,
                           "drift": [{"field": "*", "detail": "saved search not found"}]}
            doc["live_status"] = LIVE_MISSING
            doc["live_drift"] = True
            return
        if not is_managed_by_us(observed, doc["content_id"]):
            doc["live"] = {"status": LIVE_UNMANAGED, "verified_at": now, "expected_disabled": expected_disabled,
                           "drift": [{"field": "description", "detail": "management marker removed"}]}
            doc["live_status"] = LIVE_UNMANAGED
            doc["live_drift"] = True
            return
        self._set_live(doc, observed, expected_disabled, rev, drift(rev, observed, expected_disabled, self.settings.scheduled_owner))

    def _set_live(self, doc: Dict[str, Any], observed: Optional[Dict[str, Any]], expected_disabled: bool,
                  rev: Dict[str, Any], problems: List[Dict[str, Any]]) -> None:
        if observed is None:
            status = LIVE_MISSING
        else:
            status = LIVE_DISABLED if observed.get("disabled") else LIVE_ENABLED
        doc["live"] = {
            "status": status, "expected_disabled": expected_disabled, "verified_at": utc_now_iso(),
            "revision": rev["rev"], "drift": problems,
            "owner": (observed or {}).get("owner"), "sharing": (observed or {}).get("sharing"),
            "next_scheduled_time": (observed or {}).get("next_scheduled_time") or "",
            "search_hash": spl_hash((observed or {}).get("search") or "") if observed else "",
        }
        doc["live_status"] = status
        doc["live_drift"] = bool(problems)

    def _safe_disable(self, name: str) -> None:
        try:
            self.saved.update(name, {"disabled": "1"})
        except UcmError:
            pass

    def _require_managed(self, doc: Dict[str, Any], name: str) -> None:
        live = self.saved.get(name)
        if live is None:
            doc["live"] = {"status": LIVE_MISSING, "verified_at": utc_now_iso(), "drift": [
                {"field": "*", "detail": "saved search not found"}]}
            doc["live_status"] = LIVE_MISSING
            doc["live_drift"] = True
            self.store.upsert(C.DEPLOYMENTS, doc)
            raise ConflictError("saved search %r was not found; deploy again to recreate it" % name,
                                {"code": "missing"})
        if not is_managed_by_us(live, doc["content_id"]):
            raise ConflictError("saved search %r is not managed by this app" % name, {"code": "unmanaged"})

    def _check_spl(self, spl: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"parse_ok": False, "parse_error": "", "side_effects": [], "high_cost": [],
                               "lint": lint_search(spl)}
        try:
            parsed = parse(self.search, spl, app=self.saved.app)
        except (UnsupportedOperation, ValidationError) as exc:
            out["parse_error"] = exc.message[:500]
            out.update(self._policy(spl, None))
            out["access_scan"] = scan_spl(spl)
            return out
        out.update(self._policy(spl, parsed))
        out["access_scan"] = scan_spl(spl, expanded_pipeline(parsed) if parsed.ok else "")
        out["high_cost"] = high_cost(parsed.commands)
        out["commands"] = parsed.commands[:50]
        out["parse_ok"] = bool(parsed.ok)
        if not parsed.ok:
            out["parse_error"] = (parsed.errors[0] if parsed.errors else "parse failed")[:500]
        return out

    def _policy(self, spl: str, parsed) -> Dict[str, Any]:
        policy = classify(spl, parsed, self.settings.extra_safe_commands,
                          exists=lambda name: command_exists(self.search, name, self.saved.app))
        return {"side_effects": policy.side_effects, "indirect_commands": policy.indirect,
                "unknown_commands": policy.unknown, "review_commands": policy.review}

    @staticmethod
    def _acknowledge(rev: Dict[str, Any], actor: str, acknowledged: bool) -> None:
        review = rev.get("review_commands") or []
        if not review:
            return
        if not acknowledged:
            raise ConflictError("this search runs commands SUN cannot verify as read-only (%s); approving it "
                                "needs an explicit acknowledgment" % ", ".join(review),
                                {"code": "acknowledgment_required", "commands": review,
                                 "indirect": rev.get("indirect_commands") or [],
                                 "unknown": rev.get("unknown_commands") or []})
        rev["acknowledged_commands"] = list(review)
        rev["acknowledged_by"] = actor

    @staticmethod
    def _require_acknowledged(rev: Dict[str, Any]) -> None:
        missing = [c for c in rev.get("review_commands") or [] if c not in (rev.get("acknowledged_commands") or [])]
        if missing:
            raise ConflictError("the search now runs commands the approver did not acknowledge (%s), for example "
                                "after a macro changed; start a new revision" % ", ".join(missing),
                                {"code": "unacknowledged_commands", "commands": missing})

    @staticmethod
    def _acknowledge_actions(rev: Dict[str, Any], actor: str, acknowledged: bool) -> None:
        actions = rev.get("actions") or {}
        if not actions:
            return
        if not acknowledged:
            raise ConflictError("this revision sends %s when the alert fires; approving it needs an explicit "
                                "acknowledgment of the recipients" % " and ".join(action_rules.kinds(actions)),
                                {"code": "actions_acknowledgment_required", "actions": action_rules.kinds(actions)})
        rev["actions_acknowledged_by"] = actor
        rev["actions_acknowledged_at"] = utc_now_iso()
        rev["actions_acknowledged_digest"] = action_rules.digest(actions)

    def _check_actions_policy(self, rev: Dict[str, Any]) -> None:
        """Today's allowlists apply to what is deployed, not only to what was drafted."""
        try:
            action_rules.validate_current(rev.get("actions") or {}, self.settings.actions,
                                          rev.get("alert_mode") or "none", rev.get("suppress_period") or "")
        except ValidationError as exc:
            raise ConflictError("the alert actions of revision %d are no longer allowed: %s" % (rev["rev"], exc.message),
                                {"code": "actions_not_allowed"})

    def _require_actions_ready(self, rev: Dict[str, Any]) -> None:
        actions = rev.get("actions") or {}
        if not actions:
            return
        if rev.get("actions_acknowledged_digest") != action_rules.digest(actions):
            raise ConflictError("the alert actions of revision %d were not acknowledged by the approver" % rev["rev"],
                                {"code": "unacknowledged_actions"})
        self._check_actions_policy(rev)

    @staticmethod
    def _require_clean_spl(rev: Dict[str, Any]) -> None:
        if rev.get("side_effects"):
            raise ValidationError("search contains side-effect commands (%s) and cannot be deployed"
                                  % ", ".join(rev["side_effects"]), {"commands": rev["side_effects"]})
        if not rev.get("parse_ok"):
            raise ValidationError("Splunk could not parse the search: %s" % (rev.get("parse_error") or "unknown"))

    def _new(self, uc: UseCase, actor: str) -> Dict[str, Any]:
        return {
            "_key": deployment_key(uc.key), "doc_schema": DOC_SCHEMA, "content_id": uc.content_id,
            "catalog_key": uc.key, "record_id": uc.provenance.provider_record_id, "title": uc.title,
            "state": DRAFT, "revision": 0, "deployed_revision": None, "revisions": [], "history": [],
            "saved_search": {"name": saved_search_name(uc.provenance.provider_record_id, uc.title),
                             "app": self.saved.app},
            "live": {"status": LIVE_ABSENT, "drift": []}, "live_status": LIVE_ABSENT, "live_drift": False,
            "override_active": False, "outcome_value": "", "created_by": actor, "created_at": utc_now_iso(), "version": 0, "last_error": "",
        }

    def _load(self, content_id: str) -> UseCase:
        key = key_from_id(content_id)
        stored = self.content.get_content(key)
        if not stored:
            raise NotFoundError("use case not found", {"id": content_id})
        uc = StoredNormalizer(self.categories).normalize(stored)
        if uc is None:
            raise NotFoundError("stored content for this use case is unreadable")
        return uc

    def _require(self, content_id: str) -> Dict[str, Any]:
        doc = self.store.get(C.DEPLOYMENTS, deployment_key(key_from_id(content_id)))
        if not doc:
            raise NotFoundError("no deployment for this use case", {"id": content_id})
        return doc

    @staticmethod
    def _expect(doc: Dict[str, Any], states: Sequence[str], action: str) -> None:
        if doc.get("state") not in states:
            raise ConflictError("cannot %s a deployment in state %s" % (action, doc.get("state")),
                                {"code": "invalid_transition", "state": doc.get("state"),
                                 "allowed_from": list(states)})

    @staticmethod
    def _latest(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        revs = doc.get("revisions") or []
        return revs[-1] if revs else None

    @staticmethod
    def _rev(doc: Dict[str, Any], number: int) -> Dict[str, Any]:
        for rev in doc.get("revisions") or []:
            if rev["rev"] == number:
                return rev
        raise NotFoundError("revision %s not found" % number)

    def _deployed(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        if not doc.get("deployed_revision"):
            raise ConflictError("nothing is deployed for this use case", {"code": "not_deployed"})
        return self._rev(doc, doc["deployed_revision"])

    @staticmethod
    def _previous_deployed(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        current = doc.get("deployed_revision")
        if not current:
            return None
        candidates = [r for r in doc.get("revisions") or [] if r["rev"] < current and r.get("deployed_at")]
        return candidates[-1] if candidates else None

    def _trim_revisions(self, doc: Dict[str, Any]) -> None:
        revs = doc.get("revisions") or []
        keep = {doc.get("deployed_revision"), revs[-1]["rev"] if revs else None}
        prev = self._previous_deployed(doc)
        if prev:
            keep.add(prev["rev"])
        while len(revs) > self.settings.max_revisions:
            for i, rev in enumerate(revs):
                if rev["rev"] not in keep:
                    log = doc.setdefault("revision_log", [])
                    log.append(revision_tools.stub(revs.pop(i), utc_now_iso()))
                    del log[:-revision_tools.MAX_STUBS]
                    break
            else:
                break

    @staticmethod
    def _history(doc: Dict[str, Any], actor: str, action: str, from_state: Optional[str], to_state: str,
                 rev: Optional[int], note: str = "") -> None:
        hist = doc.setdefault("history", [])
        hist.append({"at": utc_now_iso(), "actor": actor, "action": action, "from": from_state,
                     "to": to_state, "revision": rev, "note": (note or "")[:500]})
        del hist[:-MAX_HISTORY]

    def _transition(self, doc: Dict[str, Any], actor: str, action: str, target: str, note: str = "",
                    details: Optional[Dict[str, Any]] = None) -> None:
        prev = doc.get("state")
        rev = self._latest(doc)
        doc["state"] = target
        self._history(doc, actor, action, prev, target, rev["rev"] if rev else None, note)
        self._save(doc, actor)
        info = {"from": prev, "to": target, "revision": rev["rev"] if rev else None}
        info.update(details or {})
        self.audit.record(actor, "deployment." + action, "deployment", doc["content_id"], details=info)

    def _fail(self, doc: Dict[str, Any], actor: str, action: str, message: str,
              problems: Optional[List[Dict[str, Any]]] = None, keep_state: bool = False) -> None:
        prev = doc.get("state")
        doc["last_error"] = message[:500]
        if not keep_state:
            doc["state"] = FAILED
        rev = self._latest(doc)
        self._history(doc, actor, action + "_failed", prev, doc["state"], rev["rev"] if rev else None, message)
        self._save(doc, actor)
        self.audit.record(actor, "deployment." + action, "deployment", doc["content_id"], outcome="failure",
                          details={"error": message[:500], "drift": problems or []})

    def _save(self, doc: Dict[str, Any], actor: str) -> None:
        current = self.store.get(C.DEPLOYMENTS, doc["_key"])
        if current is not None and current.get("version", 0) != doc.get("version", 0):
            raise ConflictError("the deployment was changed by someone else; reload and retry",
                                {"code": "concurrent_update"})
        doc["version"] = int(doc.get("version", 0)) + 1
        doc["updated_at"] = utc_now_iso()
        doc["updated_by"] = actor
        doc["save_token"] = new_id()
        self.store.upsert(C.DEPLOYMENTS, doc)
        stored = self.store.get(C.DEPLOYMENTS, doc["_key"])
        if stored is None or stored.get("version") != doc["version"] or stored.get("save_token") != doc["save_token"]:
            raise ConflictError("the deployment was changed by someone else while it was being saved; reload and "
                                "check what it now says before retrying", {"code": "concurrent_update_detected"})

    def _decorate(self, doc: Dict[str, Any], summary: bool = False) -> Dict[str, Any]:
        out = dict(doc)
        out.pop("live_drift", None)
        out.pop("save_token", None)
        out.pop("override_active", None)
        out.pop("outcome_value", None)
        now = utc_now_iso()
        out["override_status"] = self._override_status(doc, now)
        out["enable_request_active"] = self._request_active(doc, now)
        if summary:
            return out
        latest = self._latest(doc)
        catalog = self.store.get(C.CATALOG, doc.get("catalog_key") or "") or {}
        out["content_changed"] = bool(latest and catalog.get("source_hash")
                                      and catalog.get("source_hash") != latest.get("content_source_hash"))
        out["provider_status"] = catalog.get("provider_status")
        return out

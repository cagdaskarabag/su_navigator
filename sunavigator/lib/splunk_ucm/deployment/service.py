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

from typing import Any, Dict, List, Optional, Sequence

from ..audit import AuditService
from ..catalog.detail import key_from_id
from ..content.reindex import StoredNormalizer
from ..errors import ConflictError, NotFoundError, PermissionDenied, UcmError, UnsupportedOperation, ValidationError
from ..model.canonical import UseCase
from ..platform.search import SearchClient
from ..spl.parser import high_cost, parse
from ..spl.policy import classify, command_exists
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..storage.repositories import CategoryRepository, ContentRepository
from ..util import safe_key, utc_now_iso
from .savedsearch import SavedSearchClient
from .spec import drift, is_managed_by_us, normalize_spec, saved_search_name, settings_for, spl_hash

DRAFT, PENDING, APPROVED, REJECTED, DEPLOYED, FAILED, RETIRED = (
    "draft", "pending_approval", "approved", "rejected", "deployed", "failed", "retired")
STATES = (DRAFT, PENDING, APPROVED, REJECTED, DEPLOYED, FAILED, RETIRED)
LIVE_ABSENT, LIVE_DISABLED, LIVE_ENABLED, LIVE_MISSING, LIVE_UNMANAGED = (
    "absent", "disabled", "enabled", "missing", "unmanaged")

MAX_HISTORY = 100
MIN_OVERRIDE_REASON = 10


class DeploymentSettings:
    def __init__(self, require_approval: bool = True, allow_self_approval: bool = False,
                 block_enable_states: Sequence[str] = ("blocked",), cron: str = "*/15 * * * *",
                 earliest: str = "-15m", latest: str = "now", alert_mode: str = "track",
                 max_revisions: int = 20, verify_interval_minutes: int = 60,
                 extra_safe_commands: Sequence[str] = ()):
        self.extra_safe_commands = tuple(extra_safe_commands)
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
                "alert_mode": self.alert_mode}


def deployment_key(catalog_key: str) -> str:
    return safe_key("dep", catalog_key)


class DeploymentService:
    def __init__(self, store: DocumentStore, audit: AuditService, search: SearchClient,
                 saved: SavedSearchClient, settings: Optional[DeploymentSettings] = None):
        self.store = store
        self.audit = audit
        self.search = search
        self.saved = saved
        self.settings = settings or DeploymentSettings()
        self.content = ContentRepository(store)
        self.categories = CategoryRepository(store)

    # -- reads ---------------------------------------------------------------

    def get(self, content_id: str) -> Optional[Dict[str, Any]]:
        doc = self.store.get(C.DEPLOYMENTS, deployment_key(key_from_id(content_id)))
        return self._decorate(doc) if doc else None

    def list(self, states: Sequence[str] = (), live: Sequence[str] = (), offset: int = 0,
             count: int = 50, drifted: bool = False) -> Dict[str, Any]:
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
        query = {"$and": clauses} if len(clauses) > 1 else (clauses[0] if clauses else None)
        rows = self.store.query(C.DEPLOYMENTS, query, sort=[("updated_at", -1)], skip=offset, limit=count + 1,
                                fields=["content_id", "catalog_key", "title", "record_id", "state", "revision",
                                        "deployed_revision", "live", "live_status", "saved_search", "updated_at",
                                        "updated_by", "last_error", "criticality"])
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
        return {"total": len(rows), "by_state": by_state, "by_live": by_live, "drifted": drifted}

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
            if doc.get("deployed_revision") and live in (LIVE_DISABLED, LIVE_ENABLED):
                out.append("enable" if live == LIVE_DISABLED else "disable")
                if self._previous_deployed(doc):
                    out.append("rollback")
            if state != RETIRED:
                out.append("retire")
            if doc.get("deployed_revision"):
                out.append("verify")
        elif can_propose and doc.get("deployed_revision"):
            out.append("verify")
        return out

    # -- workflow ------------------------------------------------------------

    def save_draft(self, actor: str, content_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        uc = self._load(content_id)
        spec = normalize_spec(body, self.settings.defaults())
        spl = {"primary": uc.spl, "cim": uc.cim_spl, "custom": spec["custom_spl"]}[spec["spl_source"]]
        if not spl:
            raise ValidationError("this use case has no %s SPL; choose another source or a custom search"
                                  % spec["spl_source"])
        check = self._check_spl(spl)
        key = deployment_key(uc.key)
        doc = self.store.get(C.DEPLOYMENTS, key) or self._new(uc, actor)
        prev_state = doc.get("state")
        revisions = doc.setdefault("revisions", [])
        latest = revisions[-1] if revisions else None
        if latest is not None and prev_state == DRAFT and not latest.get("submitted_at"):
            rev_no = latest["rev"]
            revisions.pop()
        else:
            rev_no = (latest["rev"] + 1) if latest else 1
        readiness = self.store.get(C.READINESS, uc.key) or {}
        revision = {
            "rev": rev_no, "spl": spl, "spl_hash": spl_hash(spl), "spl_source": spec["spl_source"],
            "cron": spec["cron"], "earliest": spec["earliest"], "latest": spec["latest"],
            "alert_mode": spec["alert_mode"], "severity": spec["severity"], "threshold": spec["threshold"],
            "notes": spec["notes"], "content_source_hash": uc.provenance.source_hash,
            "readiness_state": readiness.get("state"), "readiness_score": readiness.get("score"),
            "created_by": actor, "created_at": utc_now_iso(),
        }
        revision.update(check)
        revisions.append(revision)
        doc["revision"] = rev_no
        doc["state"] = DRAFT
        doc["title"] = uc.title
        doc["criticality"] = uc.criticality
        self._trim_revisions(doc)
        self._history(doc, actor, "draft", prev_state, DRAFT, rev_no, spec["notes"][:200])
        self._save(doc, actor)
        self.audit.record(actor, "deployment.draft", "deployment", uc.content_id,
                          details={"revision": rev_no, "spl_source": spec["spl_source"],
                                   "parse_ok": check["parse_ok"], "side_effects": check["side_effects"],
                                   "review_commands": check["review_commands"]})
        return self._decorate(doc)

    def submit(self, actor: str, content_id: str, note: str = "", acknowledge_commands: bool = False) -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (DRAFT,), "submit")
        rev = self._latest(doc)
        self._require_clean_spl(rev)
        if not self.settings.require_approval:
            self._acknowledge(rev, actor, acknowledge_commands)
        rev["submitted_by"] = actor
        rev["submitted_at"] = utc_now_iso()
        target = PENDING
        if not self.settings.require_approval:
            rev["approved_by"] = actor
            rev["approved_at"] = rev["submitted_at"]
            rev["approval"] = "not_required"
            target = APPROVED
        self._transition(doc, actor, "submit", target, note)
        return self._decorate(doc)

    def approve(self, actor: str, content_id: str, note: str = "", acknowledge_commands: bool = False) -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (PENDING,), "approve")
        rev = self._latest(doc)
        if rev.get("submitted_by") == actor and not self.settings.allow_self_approval:
            raise PermissionDenied("the submitter cannot approve their own deployment "
                                   "(ucm.conf [deployment] allow_self_approval)")
        self._require_clean_spl(rev)
        self._acknowledge(rev, actor, acknowledge_commands)
        rev["approved_by"] = actor
        rev["approved_at"] = utc_now_iso()
        rev["approval"] = "approved"
        self._transition(doc, actor, "approve", APPROVED, note,
                         {"acknowledged_commands": rev.get("acknowledged_commands") or []})
        return self._decorate(doc)

    def reject(self, actor: str, content_id: str, note: str = "") -> Dict[str, Any]:
        doc = self._require(content_id)
        self._expect(doc, (PENDING,), "reject")
        rev = self._latest(doc)
        rev["rejected_by"] = actor
        rev["rejected_at"] = utc_now_iso()
        self._transition(doc, actor, "reject", REJECTED, note)
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
        problems = drift(rev, observed, True) if observed else [{"field": "*", "detail": "not found after write"}]
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
        readiness = self.store.get(C.READINESS, doc["catalog_key"]) or {}
        state = readiness.get("state") or "not_assessed"
        override = ""
        if state in self.settings.block_enable_states:
            if len((override_reason or "").strip()) < MIN_OVERRIDE_REASON:
                raise ConflictError("readiness is %s; enabling needs an override reason (at least %d characters)"
                                    % (state, MIN_OVERRIDE_REASON), {"code": "readiness_gate", "readiness": state})
            override = override_reason.strip()[:500]
        catalog = self.store.get(C.CATALOG, doc["catalog_key"]) or {}
        return self._set_enabled(doc, actor, rev, True, "enable", {
            "readiness_state": state, "override_reason": override,
            "provider_status": catalog.get("provider_status")})

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
        try:
            self.saved.update(name, settings_for(prev, doc["content_id"], disabled=True))
        except UcmError as exc:
            self._fail(doc, actor, "rollback", exc.message, keep_state=True)
            raise
        observed = self.saved.get(name)
        problems = drift(prev, observed, True) if observed else [{"field": "*", "detail": "not found after write"}]
        self._set_live(doc, observed, True, prev, problems)
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
        if audit_always or live["status"] != before or bool(live.get("drift")) != before_drift:
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
        return totals

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
        problems = drift(rev, observed, not enabled) if observed else [{"field": "*", "detail": "not found"}]
        self._set_live(doc, observed, not enabled, rev, problems)
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
        self._set_live(doc, observed, expected_disabled, rev, drift(rev, observed, expected_disabled))

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
        out: Dict[str, Any] = {"parse_ok": False, "parse_error": "", "side_effects": [], "high_cost": []}
        try:
            parsed = parse(self.search, spl, app=self.saved.app)
        except (UnsupportedOperation, ValidationError) as exc:
            out["parse_error"] = exc.message[:500]
            out.update(self._policy(spl, None))
            return out
        out.update(self._policy(spl, parsed))
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
            "created_by": actor, "created_at": utc_now_iso(), "version": 0, "last_error": "",
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
                    revs.pop(i)
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
        self.store.upsert(C.DEPLOYMENTS, doc)

    def _decorate(self, doc: Dict[str, Any], summary: bool = False) -> Dict[str, Any]:
        out = dict(doc)
        out.pop("live_drift", None)
        if summary:
            return out
        latest = self._latest(doc)
        catalog = self.store.get(C.CATALOG, doc.get("catalog_key") or "") or {}
        out["content_changed"] = bool(latest and catalog.get("source_hash")
                                      and catalog.get("source_hash") != latest.get("content_source_hash"))
        out["provider_status"] = catalog.get("provider_status")
        return out

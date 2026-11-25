"""Assessed state of a control catalogue: who decided, when and why (D-077).

Coverage (D-076) says which controls have a use case mapped to them. This module records what a person decided about
each control: implemented or not, with a reason, and, where the catalogue lists assessment objectives, a result per
objective. A plan of action and milestones (POA&M) tracks what is not yet implemented. A snapshot freezes the whole
state with a hash so it can be handed to an assessor and checked later. All of it is checked and stored server-side; the
interface only displays it.
"""

import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..audit import AuditService
from ..errors import ConflictError, NotFoundError, ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import canonical_json, new_id, sha256_text, utc_now_iso
from . import poam_rules
from .controls import ASSESSED, assessable

STATUSES = ("implemented", "partially_implemented", "planned", "not_implemented", "not_applicable")
OBJECTIVE_RESULTS = ("met", "not_met", "not_applicable")
POAM_STATES = ("open", "in_progress", "closed", "risk_accepted")
POAM_OPEN = ("open", "in_progress")
MIN_NOTE = 5
MIN_NA_NOTE = 10
HISTORY = 20
MAX_MILESTONES = 20
MAX_SNAPSHOTS = 200
MAX_SNAPSHOT_BYTES = 6 * 1024 * 1024
SNAPSHOT_FORMAT = "ucm.assessment.snapshot/1"
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_POAM_ID = re.compile(r"^pm_[0-9a-f]{32}$")
_SNAPSHOT_ID = re.compile(r"^sn_[0-9a-f]{32}$")


def assessment_key(framework_id: str, control_id: str) -> str:
    return "as_" + hashlib.sha256(("%s\0%s" % (framework_id, control_id)).encode("utf-8")).hexdigest()[:40]


def _note(value: Any, minimum: int = MIN_NOTE, name: str = "note", limit: int = 2000) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if len(text) < minimum:
        raise ValidationError("%s is required (at least %d characters): say why" % (name, minimum))
    if len(text) > limit:
        raise ValidationError("%s is longer than %d characters" % (name, limit))
    return text


def _date(value: Any, name: str, required: bool = True) -> str:
    text = str(value or "").strip()
    if not text and not required:
        return ""
    try:
        if not _DATE.match(text):
            raise ValueError(text)
        datetime.date.fromisoformat(text)
    except ValueError:
        raise ValidationError("%s must be a date as YYYY-MM-DD" % name)
    return text


def today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def derive_status(objectives: List[Dict[str, str]], results: Dict[str, Dict[str, Any]]) -> Tuple[str, bool]:
    """Status of a requirement from its objective results, and whether every objective has a result."""
    given = [results[o["id"]]["result"] for o in objectives if o["id"] in results]
    complete = len(given) == len(objectives)
    if not given:
        return "", False
    if any(r == "not_met" for r in given):
        return ("partially_implemented" if any(r == "met" for r in given) else "not_implemented"), complete
    if complete and all(r == "not_applicable" for r in given):
        return "not_applicable", True
    return ("implemented" if complete else "partially_implemented"), complete


def results_of(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Objective results by objective id. Stored as a list: the KV Store refuses a field name that contains a dot."""
    return {r["id"]: r for r in (doc.get("objectives") or [])}


def deduction(control: Dict[str, Any], status: str) -> int:
    weight = control.get("weight", 0)
    if status in ("implemented", "not_applicable"):
        return 0
    if status == "partially_implemented" and control.get("partial_weight") is not None:
        return control["partial_weight"]
    return weight


class AssessmentService:
    def __init__(self, store: DocumentStore, audit: AuditService):
        self.store = store
        self.audit = audit

    @staticmethod
    def _controls(definition: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        return {c["id"]: c for c in definition["controls"]}

    def _assessable(self, definition: Dict[str, Any], control_id: str) -> Dict[str, Any]:
        control = self._controls(definition).get(control_id)
        if control is None:
            raise NotFoundError("no such control in this catalogue version", {"control_id": str(control_id)[:60]})
        if not assessable(control):
            raise ValidationError("a family or withdrawn control cannot be assessed")
        return control

    def docs(self, framework_id: str) -> Dict[str, Dict[str, Any]]:
        rows = self.store.query(C.ASSESSMENTS, {"framework_id": framework_id}, sort=[("control_id", 1)], limit=50000)
        return {r["control_id"]: r for r in rows}

    @staticmethod
    def public(doc: Dict[str, Any], version: str = "") -> Dict[str, Any]:
        keys = ("framework_id", "control_id", "version", "status", "derived", "complete", "note", "objectives",
                "assessed_by", "assessed_at", "first_assessed_by", "first_assessed_at", "history")
        out = {k: doc.get(k) for k in keys}
        out["objectives"] = results_of(doc)
        out["stale_version"] = bool(version and doc.get("version") != version)
        return out

    def view(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        fw = definition["framework_id"]
        docs = self.docs(fw)
        controls = self._controls(definition)
        items = {cid: self.public(d, definition["version"]) for cid, d in docs.items() if cid in controls}
        orphaned = [self.public(d, definition["version"]) for cid, d in docs.items() if cid not in controls]
        return {"framework_id": fw, "version": definition["version"], "assessments": items, "orphaned": orphaned,
                "summary": self.summary(definition, docs), "score": self.score(definition, docs)}

    def summary(self, definition: Dict[str, Any], docs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        counts = {s: 0 for s in STATUSES}
        total = assessed = incomplete = stale = objectives_total = objectives_done = 0
        for c in definition["controls"]:
            if not assessable(c):
                continue
            total += 1
            objectives_total += len(c.get("objectives") or [])
            doc = docs.get(c["id"])
            if not doc or not doc.get("status"):
                continue
            assessed += 1
            counts[doc["status"]] = counts.get(doc["status"], 0) + 1
            incomplete += 1 if doc.get("complete") is False else 0
            stale += 1 if doc.get("version") != definition["version"] else 0
            objectives_done += sum(1 for o in c.get("objectives") or [] if o["id"] in results_of(doc))
        return {"controls": total, "assessed": assessed, "not_assessed": total - assessed, "by_status": counts,
                "incomplete": incomplete, "stale_version": stale, "objectives": objectives_total,
                "objectives_assessed": objectives_done}

    def score(self, definition: Dict[str, Any], docs: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        scoring = definition.get("scoring")
        if not scoring:
            return None
        lost = ceiling_lost = assessed = 0
        total = 0
        blocked: List[str] = []
        by_value: Dict[str, int] = {}
        for c in definition["controls"]:
            if not assessable(c) or "weight" not in c:
                continue
            total += 1
            doc = docs.get(c["id"])
            status = (doc or {}).get("status") or ""
            lost_here = deduction(c, status or "not_implemented")
            if status:
                assessed += 1
                ceiling_lost += deduction(c, status)
            lost += lost_here
            if lost_here:
                by_value[str(lost_here)] = by_value.get(str(lost_here), 0) + 1
            if c.get("precondition") and status not in ("implemented", "not_applicable"):
                blocked.append(c["id"])
        return {"method": scoring["method"], "start": scoring["start"], "note": scoring.get("note", ""),
                "score": scoring["start"] - lost, "ceiling": scoring["start"] - ceiling_lost, "points_lost": lost,
                "requirements": total, "assessed": assessed, "unassessed": total - assessed,
                "lost_by_value": by_value, "all_assessed": assessed == total, "can_pass": not blocked,
                "complete": assessed == total,  # deprecated alias of all_assessed: it never meant "can pass"
                "blocked_by": blocked}

    def set(self, user: str, definition: Dict[str, Any], control_id: str, status: str, note: Any,
            objectives: Any) -> Dict[str, Any]:
        control = self._assessable(definition, control_id)
        fw = definition["framework_id"]
        text = _note(note)
        key = assessment_key(fw, control_id)
        doc = self.store.get(C.ASSESSMENTS, key) or {}
        defined = control.get("objectives") or []
        results: Dict[str, Dict[str, Any]] = results_of(doc)
        changed = 0
        if defined:
            if status:
                raise ValidationError("the status of this requirement comes from its objective results; send objectives")
            if not isinstance(objectives, dict) or not objectives:
                raise ValidationError("objectives must be an object of objective id to result")
            known = {o["id"] for o in defined}
            for oid, value in objectives.items():
                if oid not in known:
                    raise ValidationError("unknown objective", {"objective": str(oid)[:60]})
                result = value.get("result") if isinstance(value, dict) else value
                obj_note = str(value.get("note") or "").strip()[:500] if isinstance(value, dict) else ""
                if result == "not_assessed":
                    changed += 1 if results.pop(oid, None) is not None else 0
                    continue
                if result not in OBJECTIVE_RESULTS:
                    raise ValidationError("invalid objective result", {"allowed": list(OBJECTIVE_RESULTS) + ["not_assessed"]})
                if result == "not_applicable" and len(obj_note) < MIN_NA_NOTE:
                    raise ValidationError("an objective that does not apply needs a reason of at least %d characters"
                                          % MIN_NA_NOTE)
                if results.get(oid, {}).get("result") != result:
                    changed += 1
                results[oid] = {"id": oid, "result": result, "note": obj_note, "by": user, "at": utc_now_iso()}
            derived, complete = derive_status(defined, results)
            if not derived:
                raise ValidationError("no objective has a result; use clear to remove the assessment")
            new_status = derived
        else:
            if objectives:
                raise ValidationError("this control has no objectives; send a status")
            if status not in STATUSES:
                raise ValidationError("invalid status", {"allowed": list(STATUSES)})
            new_status, complete, derived = status, True, False
            results = {}
        if new_status == "not_applicable" and len(text) < MIN_NA_NOTE:
            raise ValidationError("'not applicable' needs a reason of at least %d characters" % MIN_NA_NOTE)
        now = utc_now_iso()
        history = list(doc.get("history") or [])
        if doc.get("status"):
            history.append({"status": doc["status"], "note": doc.get("note", ""), "by": doc.get("assessed_by", ""),
                            "at": doc.get("assessed_at", ""), "version": doc.get("version", "")})
        new = {"_key": key, "doc_schema": C.DOC_SCHEMA, "framework_id": fw, "control_id": control_id,
               "version": definition["version"], "status": new_status, "derived": bool(defined), "complete": complete,
               "note": text, "objectives": [results[k] for k in sorted(results)], "assessed_by": user, "assessed_at": now,
               "first_assessed_by": doc.get("first_assessed_by") or user, "first_assessed_at": doc.get("first_assessed_at") or now,
               "history": history[-HISTORY:]}
        self.store.upsert(C.ASSESSMENTS, new)
        self.audit.record(user, "assessment.set", "assessment", "%s#%s" % (fw, control_id),
                          details={"status": new_status, "previous": doc.get("status", ""), "version": definition["version"],
                                   "objectives_changed": changed})
        return self.public(new, definition["version"])

    def clear(self, user: str, definition: Dict[str, Any], control_id: str, note: Any) -> Dict[str, Any]:
        self._assessable(definition, control_id)
        text = _note(note)
        fw = definition["framework_id"]
        doc = self.store.get(C.ASSESSMENTS, assessment_key(fw, control_id))
        if not doc:
            raise NotFoundError("this control has no assessment")
        self.store.delete(C.ASSESSMENTS, doc["_key"])
        self.audit.record(user, "assessment.cleared", "assessment", "%s#%s" % (fw, control_id),
                          details={"previous": doc.get("status", ""), "by": doc.get("assessed_by", ""), "reason": text[:200]})
        return {"framework_id": fw, "control_id": control_id, "cleared": True}

    # --- plan of action and milestones -------------------------------------------------------------------------

    @staticmethod
    def _milestones(raw: Any) -> List[Dict[str, Any]]:
        if raw is None:
            return []
        if not isinstance(raw, list) or len(raw) > MAX_MILESTONES:
            raise ValidationError("milestones must be a list of at most %d" % MAX_MILESTONES)
        out = []
        for m in raw:
            if not isinstance(m, dict):
                raise ValidationError("invalid milestone")
            out.append({"text": _note(m.get("text"), 3, "milestone text", 300), "due": _date(m.get("due"), "milestone due", False),
                        "done": bool(m.get("done"))})
        return out

    def poam_public(self, doc: Dict[str, Any], statuses: Optional[Dict[str, str]] = None,
                    definition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        keys = ("framework_id", "control_id", "title", "weakness", "owner", "due", "state", "milestones", "created_by",
                "created_at", "updated_by", "updated_at", "closed_by", "closed_at", "close_note", "history")
        out = {k: doc.get(k) for k in keys}
        out["id"] = doc["_key"]
        out["overdue"] = doc.get("state") in POAM_OPEN and bool(doc.get("due")) and doc["due"] < today()
        if statuses is not None:
            out["control_status"] = statuses.get(doc.get("control_id"), "")
        out["eligibility"] = None
        if definition is not None and doc.get("state") in POAM_OPEN:
            out["eligibility"] = poam_rules.item_flags(definition, doc.get("control_id") or "",
                                                       (statuses or {}).get(doc.get("control_id"), ""),
                                                       doc.get("due") or "", today())
        return out

    def poam_list(self, framework_id: str, states: List[str], control_id: str = "", overdue: bool = False,
                  offset: int = 0, count: int = 100, definition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        for s in states:
            if s not in POAM_STATES:
                raise ValidationError("invalid state", {"allowed": list(POAM_STATES)})
        query: Dict[str, Any] = {"framework_id": framework_id}
        if control_id:
            query["control_id"] = control_id
        rows = self.store.query(C.POAM, query, sort=[("due", 1), ("_key", 1)], limit=50000)
        docs = self.docs(framework_id)
        statuses = {cid: d.get("status", "") for cid, d in docs.items()}
        items = [self.poam_public(r, statuses, definition) for r in rows]
        counts = {s: sum(1 for i in items if i["state"] == s) for s in POAM_STATES}
        counts["overdue"] = sum(1 for i in items if i["overdue"])
        if states:
            items = [i for i in items if i["state"] in states]
        if overdue:
            items = [i for i in items if i["overdue"]]
        count = max(1, min(200, count))
        page = items[max(0, offset):max(0, offset) + count]
        return {"items": page, "offset": offset, "count": count, "has_more": len(items) > max(0, offset) + count,
                "total": len(items), "counts": counts, "today": today(),
                "programme": poam_rules.programme(definition, self.score(definition, docs)) if definition else None}

    def poam_create(self, user: str, definition: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
        control_id = str(body.get("control_id") or "")
        self._assessable(definition, control_id)
        now = utc_now_iso()
        doc = {"_key": "pm_" + new_id(), "doc_schema": C.DOC_SCHEMA, "framework_id": definition["framework_id"],
               "control_id": control_id, "title": _note(body.get("title"), 3, "title", 200),
               "weakness": _note(body.get("weakness"), MIN_NOTE, "weakness", 2000),
               "owner": _note(body.get("owner"), 2, "owner", 100), "due": _date(body.get("due"), "due"),
               "state": "open", "milestones": self._milestones(body.get("milestones")), "created_by": user, "created_at": now,
               "updated_by": user, "updated_at": now, "history": [{"action": "created", "by": user, "at": now, "note": ""}]}
        self.store.upsert(C.POAM, doc)
        status = (self.docs(definition["framework_id"]).get(control_id) or {}).get("status", "")
        public = self.poam_public(doc, {control_id: status}, definition)
        details = {"framework_id": doc["framework_id"], "control_id": control_id, "due": doc["due"]}
        if public["eligibility"] is not None:
            details["conditional_eligible"] = public["eligibility"]["eligible"]
            details["eligibility_reasons"] = public["eligibility"]["reasons"]
        self.audit.record(user, "poam.created", "poam", doc["_key"], details=details)
        return public

    def _poam(self, item_id: str) -> Dict[str, Any]:
        doc = self.store.get(C.POAM, item_id) if _POAM_ID.match(item_id or "") else None
        if not doc:
            raise NotFoundError("no such plan item")
        return doc

    def poam_update(self, user: str, item_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        doc = self._poam(item_id)
        if doc["state"] not in POAM_OPEN:
            raise ConflictError("a closed plan item cannot be changed; reopen it first")
        changed = []
        if "title" in body:
            doc["title"] = _note(body["title"], 3, "title", 200)
            changed.append("title")
        if "weakness" in body:
            doc["weakness"] = _note(body["weakness"], MIN_NOTE, "weakness", 2000)
            changed.append("weakness")
        if "owner" in body:
            doc["owner"] = _note(body["owner"], 2, "owner", 100)
            changed.append("owner")
        if "due" in body:
            new_due = _date(body["due"], "due")
            if new_due != doc["due"] and len(str(body.get("note") or "").strip()) < MIN_NOTE:
                raise ValidationError("changing the due date needs a note that says why")
            doc["due"] = new_due
            changed.append("due")
        if "milestones" in body:
            doc["milestones"] = self._milestones(body["milestones"])
            changed.append("milestones")
        if "state" in body:
            if body["state"] not in POAM_OPEN:
                raise ValidationError("use close to close a plan item", {"allowed": list(POAM_OPEN)})
            doc["state"] = body["state"]
            changed.append("state")
        if not changed:
            raise ValidationError("nothing to change")
        return self._save_poam(user, doc, "updated", str(body.get("note") or "").strip()[:500], {"fields": changed})

    def poam_close(self, user: str, item_id: str, resolution: str, note: Any) -> Dict[str, Any]:
        doc = self._poam(item_id)
        if doc["state"] not in POAM_OPEN:
            raise ConflictError("this plan item is already closed")
        if resolution not in ("closed", "risk_accepted"):
            raise ValidationError("resolution must be closed or risk_accepted")
        text = _note(note, MIN_NA_NOTE if resolution == "risk_accepted" else MIN_NOTE, "note")
        doc.update({"state": resolution, "closed_by": user, "closed_at": utc_now_iso(), "close_note": text})
        return self._save_poam(user, doc, resolution, text[:500], {"resolution": resolution})

    def poam_reopen(self, user: str, item_id: str, note: Any) -> Dict[str, Any]:
        doc = self._poam(item_id)
        if doc["state"] in POAM_OPEN:
            raise ConflictError("this plan item is open")
        text = _note(note)
        doc.update({"state": "open", "closed_by": "", "closed_at": "", "close_note": ""})
        return self._save_poam(user, doc, "reopened", text[:500], {})

    def _save_poam(self, user: str, doc: Dict[str, Any], action: str, note: str, details: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now_iso()
        doc["updated_by"], doc["updated_at"] = user, now
        doc["history"] = (list(doc.get("history") or []) + [{"action": action, "by": user, "at": now, "note": note}])[-HISTORY:]
        self.store.upsert(C.POAM, doc)
        self.audit.record(user, "poam." + action, "poam", doc["_key"],
                          details=dict(details, framework_id=doc["framework_id"], control_id=doc["control_id"]))
        return self.poam_public(doc)

    # --- snapshots -----------------------------------------------------------------------------------------------

    def snapshot(self, user: str, definition: Dict[str, Any], coverage: Dict[str, Any], use_cases: Dict[str, Dict[str, Any]],
                 label: str = "") -> Dict[str, Any]:
        fw = definition["framework_id"]
        if self.store.count(C.SNAPSHOTS, {"framework_id": fw}) >= MAX_SNAPSHOTS:
            raise ConflictError("this framework already has %d snapshots; export and remove old ones first" % MAX_SNAPSHOTS)
        label = str(label or "").strip()[:100]
        docs = self.docs(fw)
        plan = self.poam_list(fw, [], count=200)
        plan_rows = self.store.query(C.POAM, {"framework_id": fw}, sort=[("due", 1), ("_key", 1)], limit=50000)
        by_control: Dict[str, List[Dict[str, Any]]] = {}
        for item in plan_rows:
            by_control.setdefault(item["control_id"], []).append(
                {"id": item["_key"], "title": item["title"], "state": item["state"], "due": item["due"], "owner": item["owner"]})
        defined = self._controls(definition)
        rows = []
        for c in coverage["controls"]:
            doc = docs.get(c["id"])
            if not (doc or c["mapped"] or by_control.get(c["id"])):
                continue
            row: Dict[str, Any] = {"id": c["id"], "title": c["title"], "kind": c["kind"], "withdrawn": c["withdrawn"],
                                   "mapped_level": c["level"],
                                   "use_cases": [{"content_id": u, "title": (use_cases.get(u) or {}).get("title", ""),
                                                  "level": (use_cases.get(u) or {}).get("level", "")} for u in c["use_cases"]]}
            if doc:
                row["assessment"] = {"status": doc.get("status"), "complete": doc.get("complete"), "note": doc.get("note"),
                                     "assessed_by": doc.get("assessed_by"), "assessed_at": doc.get("assessed_at"),
                                     "version": doc.get("version"), "history": doc.get("history") or []}
                if doc.get("objectives"):
                    texts = {o["id"]: o["text"] for o in defined[c["id"]].get("objectives") or []}
                    row["assessment"]["objectives"] = [dict(id=oid, text=texts.get(oid, ""), **{k: v.get(k, "") for k in ("result", "note", "by", "at")})
                                                       for oid, v in sorted(results_of(doc).items())]
            if by_control.get(c["id"]):
                row["poam"] = by_control[c["id"]]
            rows.append(row)
        now = utc_now_iso()
        content = {
            "format": SNAPSHOT_FORMAT, "created_at": now, "created_by": user, "label": label,
            "catalogue": {k: coverage["catalogue"].get(k, "") for k in ("framework_id", "name", "version", "version_label", "source",
                                                                          "attribution", "modified")},
            "summary": self.summary(definition, docs), "score": self.score(definition, docs), "coverage": coverage["totals"],
            "controls": rows, "unmatched_clauses": [u["clause"] for u in coverage["unmatched"]],
            "poam": {"counts": plan["counts"], "as_of": today()},
            "omitted": "Controls with no assessment, no mapped use case and no plan item are not listed.",
        }
        text = canonical_json(content)
        if len(text.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            raise ValidationError("the snapshot would be larger than %d MB" % (MAX_SNAPSHOT_BYTES // (1024 * 1024)))
        doc = {"_key": "sn_" + new_id(), "doc_schema": C.DOC_SCHEMA, "framework_id": fw, "version": definition["version"],
               "version_label": definition.get("version_label", ""), "label": label, "created_by": user, "created_at": now,
               "sha256": sha256_text(text), "size": len(text), "content_json": text}
        self.store.upsert(C.SNAPSHOTS, doc)
        self.audit.record(user, "assessment.snapshot", "snapshot", doc["_key"],
                          details={"framework_id": fw, "version": definition["version"], "sha256": doc["sha256"],
                                   "controls": len(rows), "label": label})
        return self._snapshot_meta(doc)

    @staticmethod
    def _snapshot_meta(doc: Dict[str, Any]) -> Dict[str, Any]:
        return {"id": doc["_key"], "framework_id": doc["framework_id"], "version": doc["version"],
                "version_label": doc.get("version_label", ""), "label": doc.get("label", ""),
                "created_by": doc["created_by"], "created_at": doc["created_at"], "sha256": doc["sha256"], "size": doc["size"]}

    def snapshots(self, framework_id: str) -> List[Dict[str, Any]]:
        rows = self.store.query(C.SNAPSHOTS, {"framework_id": framework_id}, sort=[("created_at", -1)], limit=MAX_SNAPSHOTS,
                                fields=["_key", "framework_id", "version", "version_label", "label", "created_by", "created_at",
                                        "sha256", "size"])
        return [self._snapshot_meta(r) for r in rows]

    def snapshot_get(self, snapshot_id: str) -> Dict[str, Any]:
        doc = self.store.get(C.SNAPSHOTS, snapshot_id) if _SNAPSHOT_ID.match(snapshot_id or "") else None
        if not doc:
            raise NotFoundError("no such snapshot")
        actual = sha256_text(doc["content_json"])
        meta = self._snapshot_meta(doc)
        meta.update({"content": doc["content_json"], "integrity": {"ok": actual == doc["sha256"], "expected": doc["sha256"],
                                                                   "actual": actual},
                     "filename": "assessment-%s-%s-%s.json" % (doc["framework_id"], doc["version"], doc["created_at"][:10])})
        return meta

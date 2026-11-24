"""Recommended next use cases (D-060).

A short, deterministic list of use cases worth looking at next, built only from stored
records: the readiness result, the catalogue entry, the deployments and the calling user's
own selections. Nothing is estimated, nothing is learned and nothing is written.

Eligible: an active catalogue entry with a ``uc_readiness`` row whose state is ``ready`` or
``partially_ready`` without blockers, that the calling user has not rejected and that is not
already deployed. "Deployed" is decided by ``CoverageService.use_case_levels`` (a
``uc_deployments`` row with ``deployed_revision >= 1``, enabled or not), so this list and the
coverage matrix cannot disagree.

Order: ``ready`` before ``partially_ready``; within a state by draft score, then criticality
rank, readiness score and content id. The draft score weights are product defaults, not
measured, and are returned with every response.
"""

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from ..frameworks.coverage import CoverageService
from ..model.canonical import CRITICALITY_RANK
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from .scoring import STATE_BLOCKED, STATE_INSUFFICIENT, STATE_NOT_READY, STATE_PARTIAL, STATE_READY

FORMULA_VERSION = "ucm.recommend/1"
WEIGHTS = {"readiness": 0.40, "criticality": 0.25, "mitre_gain": 0.20, "coverage": 0.15}
MAX_ITEMS = 10
DEPLOYED_LEVELS = ("deployed", "enabled", "operational")
IN_PROGRESS = ("draft", "pending_approval", "approved")
MAX_MITRE_LISTED = 5
_PAGE = 5000
_READINESS_FIELDS = ["_key", "content_id", "record_id", "title", "state", "score", "coverage", "blockers", "gaps",
                     "counts", "unverified", "requirement_count", "criticality", "criticality_rank", "domains"]

EMPTY_NO_CATALOGUE = "no_catalogue"
EMPTY_NO_DISCOVERY = "no_discovery"
EMPTY_NO_ASSESSMENT = "no_assessment"
EMPTY_NONE_ELIGIBLE = "none_eligible"


def _paged(store: DocumentStore, collection: str, query: Optional[Dict[str, Any]],
           fields: Sequence[str]) -> Iterable[Dict[str, Any]]:
    skip = 0
    while True:
        rows = store.query(collection, query, sort=[("_key", 1)], skip=skip, limit=_PAGE, fields=list(fields))
        for row in rows:
            yield row
        if len(rows) < _PAGE:
            return
        skip += _PAGE


def draft_score(readiness_score: float, criticality_rank: int, mitre_gain: float, coverage: float) -> Dict[str, float]:
    """The four weighted parts and their sum, each part on a 0 to 100 scale before weighting."""
    parts = {
        "readiness": WEIGHTS["readiness"] * max(0.0, min(100.0, float(readiness_score or 0))),
        "criticality": WEIGHTS["criticality"] * (max(0, min(4, int(criticality_rank or 0))) / 4.0 * 100.0),
        "mitre_gain": WEIGHTS["mitre_gain"] * (max(0.0, min(1.0, mitre_gain)) * 100.0),
        "coverage": WEIGHTS["coverage"] * (max(0.0, min(1.0, float(coverage or 0))) * 100.0),
    }
    parts = {k: round(v, 4) for k, v in parts.items()}
    parts["total"] = round(sum(parts.values()), 2)
    return parts


class RecommendationService:
    def __init__(self, store: DocumentStore):
        self.store = store

    def recommend(self, user: str, discovery_completed_at: Optional[str] = None,
                  limit: int = MAX_ITEMS) -> Dict[str, Any]:
        limit = max(1, min(MAX_ITEMS, int(limit)))
        levels = CoverageService(self.store).use_case_levels()
        assessed = {r["_key"]: r.get("state") for r in _paged(self.store, C.READINESS, None, ["_key", "state"])}
        base = {"items": [], "formula": {"version": FORMULA_VERSION, "weights": dict(WEIGHTS)},
                "basis": {"active_use_cases": len(levels), "assessed": len(assessed),
                          "discovery_completed_at": discovery_completed_at or None},
                "empty": None, "eligible_total": 0, "excluded": {}}
        if not levels:
            base["empty"] = EMPTY_NO_CATALOGUE
            return base
        if not assessed:
            base["empty"] = EMPTY_NO_ASSESSMENT if discovery_completed_at else EMPTY_NO_DISCOVERY
            return base

        mine = self._own_selections(user)
        deployments = self._deployment_states()
        covered = self._covered_techniques(levels)
        excluded = {"not_in_active_catalogue": 0, "already_deployed": 0, "rejected_by_you": 0,
                    "blocked": 0, "not_ready": 0, "insufficient_evidence": 0, "has_blockers": 0}
        candidates: List[Dict[str, Any]] = []
        for key, state in assessed.items():
            if key not in levels:
                excluded["not_in_active_catalogue"] += 1
            elif state == STATE_BLOCKED:
                excluded["blocked"] += 1
            elif state == STATE_NOT_READY:
                excluded["not_ready"] += 1
            elif state == STATE_INSUFFICIENT:
                excluded["insufficient_evidence"] += 1
        rows = _paged(self.store, C.READINESS, {"state": {"$in": [STATE_READY, STATE_PARTIAL]}}, _READINESS_FIELDS)
        for row in rows:
            key = row["_key"]
            level = levels.get(key)
            if level is None:
                continue
            if level["level"] in DEPLOYED_LEVELS:
                excluded["already_deployed"] += 1
                continue
            if mine.get(key) == "reject":
                excluded["rejected_by_you"] += 1
                continue
            if row.get("blockers"):
                excluded["has_blockers"] += 1
                continue
            candidates.append(self._candidate(row, level, mine.get(key), deployments.get(key), covered))
        candidates.sort(key=lambda c: (0 if c["state"] == STATE_READY else 1, -c["draft_score"],
                                       -c["criticality_rank"], -(c["score"] or 0), c["content_id"]))
        base["eligible_total"] = len(candidates)
        base["excluded"] = {k: v for k, v in excluded.items() if v}
        base["items"] = [self._with_reasons(c) for c in candidates[:limit]]
        if not candidates:
            base["empty"] = EMPTY_NONE_ELIGIBLE
        return base

    def _own_selections(self, user: str) -> Dict[str, str]:
        """catalog key -> intent for the calling user only; other users' rows are never read."""
        if not user:
            return {}
        rows = self.store.query(C.SELECTIONS, {"user": user}, fields=["catalog_key", "intent"], limit=50000)
        return {r["catalog_key"]: r.get("intent") for r in rows if r.get("catalog_key")}

    def _deployment_states(self) -> Dict[str, str]:
        rows = _paged(self.store, C.DEPLOYMENTS, None, ["_key", "catalog_key", "state"])
        return {r["catalog_key"]: r.get("state") for r in rows if r.get("catalog_key")}

    @staticmethod
    def _covered_techniques(levels: Dict[str, Dict[str, Any]]) -> Set[str]:
        covered: Set[str] = set()
        for item in levels.values():
            if item["level"] in DEPLOYED_LEVELS:
                covered.update(item.get("mitre_ids") or [])
        return covered

    @staticmethod
    def _candidate(row: Dict[str, Any], level: Dict[str, Any], intent: Optional[str],
                   deployment_state: Optional[str], covered: Set[str]) -> Dict[str, Any]:
        ids = sorted(set(level.get("mitre_ids") or []))
        new_ids = [t for t in ids if t not in covered]
        gain = (len(new_ids) / len(ids)) if ids else 0.0
        criticality = row.get("criticality") or level.get("criticality") or "unknown"
        rank = row.get("criticality_rank")
        if rank is None:
            rank = CRITICALITY_RANK.get(criticality, 0)
        parts = draft_score(row.get("score") or 0, rank, gain, row.get("coverage") or 0)
        flags = []
        if intent == "select":
            flags.append("in_backlog")
        elif intent == "defer":
            flags.append("deferred")
        elif intent == "bookmark":
            flags.append("bookmarked")
        if deployment_state in IN_PROGRESS:
            flags.append("deployment_in_progress")
        return {
            "content_id": row.get("content_id"), "record_id": row.get("record_id"), "title": row.get("title") or "",
            "state": row.get("state"), "score": row.get("score"), "coverage": row.get("coverage"),
            "criticality": criticality, "criticality_rank": int(rank or 0), "domains": row.get("domains") or [],
            "draft_score": parts["total"], "score_parts": {k: v for k, v in parts.items() if k != "total"},
            "mitre_total": len(ids), "mitre_new": new_ids, "unverified": row.get("unverified") or 0,
            "requirements": row.get("requirement_count") or 0, "met": (row.get("counts") or {}).get("met", 0),
            "gaps": [{"type": g.get("type"), "value": g.get("value")} for g in (row.get("gaps") or [])[:3]],
            "flags": flags, "deployment_state": deployment_state, "_key": row["_key"],
        }

    def _with_reasons(self, c: Dict[str, Any]) -> Dict[str, Any]:
        doc = self.store.get(C.READINESS, c.pop("_key")) or {}
        reasons: List[str] = []
        pct = int(round(100 * float(c["coverage"] or 0)))
        reasons.append("Readiness %s: score %s, %d%% of the requirement weight decided."
                       % (c["state"].replace("_", " "), c["score"], pct))
        reasons.append("Criticality %s." % c["criticality"] if c["criticality"] != "unknown"
                       else "Criticality is not set for this use case.")
        if not c["mitre_total"]:
            reasons.append("No MITRE ATT&CK technique mapping is stored.")
        elif not c["mitre_new"]:
            reasons.append("All %d mapped MITRE techniques are already covered by deployed use cases." % c["mitre_total"])
        else:
            shown = ", ".join(c["mitre_new"][:MAX_MITRE_LISTED])
            more = len(c["mitre_new"]) - MAX_MITRE_LISTED
            reasons.append("%d of %d mapped MITRE techniques are not covered by a deployed use case yet: %s%s."
                           % (len(c["mitre_new"]), c["mitre_total"], shown, " and %d more" % more if more > 0 else ""))
        reasons.append("%d of %d requirements met." % (c["met"], c["requirements"]))
        if c["unverified"]:
            reasons.append("%d requirement%s not verified yet (not checked, which is different from missing)."
                           % (c["unverified"], "" if c["unverified"] == 1 else "s"))
        else:
            reasons.append("No requirements are left unverified.")
        if c["gaps"]:
            reasons.append("Unmet required: %s." % ", ".join("%s %s" % (g["type"], g["value"]) for g in c["gaps"]))
        if any(r.get("type") == "cim_model" and r.get("code") == "model_present" for r in doc.get("results") or []):
            reasons.append("Data model definition installed (populated data not verified).")
        c["reasons"] = reasons
        return c

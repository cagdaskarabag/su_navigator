"""Weighted readiness score with a critical-requirement veto (docs/DECISIONS.md D-024).

weight = level weight x confidence factor. Score is computed over requirements
with a decided status (met / partial / not_met / unknown counts as 0 but is in
the denominator). ``unverified`` and ``not_applicable`` are excluded and
reported separately. Any critical requirement that is ``not_met`` vetoes the
score: the use case is ``blocked`` whatever its numeric score.
"""

import dataclasses
from typing import Any, Dict, List

from .evaluators import MET, NOT_APPLICABLE, NOT_MET, PARTIAL, STATUSES, UNKNOWN, UNVERIFIED

LEVEL_WEIGHT = {"critical": 3.0, "required": 2.0, "recommended": 1.0, "informational": 0.0}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.75, "low": 0.5}
STATUS_VALUE = {MET: 1.0, PARTIAL: 0.5, NOT_MET: 0.0, UNKNOWN: 0.0}

STATE_BLOCKED = "blocked"
STATE_READY = "ready"
STATE_PARTIAL = "partially_ready"
STATE_NOT_READY = "not_ready"
STATE_INSUFFICIENT = "insufficient_evidence"
STATES = (STATE_READY, STATE_PARTIAL, STATE_NOT_READY, STATE_BLOCKED, STATE_INSUFFICIENT)


@dataclasses.dataclass
class ScoringSettings:
    ready_threshold: int = 90
    partial_threshold: int = 50
    min_coverage: float = 0.5


def weight(req: Dict[str, Any]) -> float:
    return LEVEL_WEIGHT.get(req.get("level", ""), 0.0) * CONFIDENCE_FACTOR.get(req.get("confidence", ""), 0.5)


# Best first. An unverified alternative is better than a missing one: the group is not shown to fail.
_GROUP_RANK = {MET: 0, PARTIAL: 1, UNVERIFIED: 2, UNKNOWN: 3, NOT_APPLICABLE: 4, NOT_MET: 5}


def collapse_groups(results: List[Dict[str, Any]]) -> None:
    """Mark all but the best member of each any-of group ``collapsed`` (D-041)."""
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for r in results:
        r.pop("collapsed", None)
        if r.get("any_of"):
            groups.setdefault((r["type"], tuple(r["any_of"])), []).append(r)
    for members in groups.values():
        best = min(members, key=lambda r: _GROUP_RANK.get(r["status"], 9))
        for r in members:
            if r is not best:
                r["collapsed"] = True


def score(results: List[Dict[str, Any]], settings: ScoringSettings) -> Dict[str, Any]:
    collapse_groups(results)
    counts = {s: 0 for s in STATUSES}
    earned = scored = decided = 0.0
    blockers: List[Dict[str, Any]] = []
    gaps: List[Dict[str, Any]] = []
    for r in results:
        if r.get("collapsed"):
            continue
        status = r["status"]
        counts[status] = counts.get(status, 0) + 1
        w = weight(r)
        if status == NOT_MET and r["level"] in ("critical", "required"):
            ref = {"req_id": r["req_id"], "type": r["type"], "value": r["value"], "code": r["code"],
                   "level": r["level"]}
            if r.get("any_of"):
                ref["value"] = "any of " + ", ".join(r["any_of"])
            (blockers if r["level"] == "critical" else gaps).append(ref)
        if status in (UNVERIFIED, NOT_APPLICABLE) or w <= 0:
            continue
        scored += w
        earned += w * STATUS_VALUE.get(status, 0.0)
        if status != UNKNOWN:
            decided += w
    value = int(round(100.0 * earned / scored)) if scored else None
    coverage = round(decided / scored, 3) if scored else 0.0

    if blockers:
        state = STATE_BLOCKED
    elif value is None or coverage < settings.min_coverage:
        state = STATE_INSUFFICIENT
    elif value >= settings.ready_threshold and not gaps:
        state = STATE_READY
    elif value >= settings.partial_threshold:
        state = STATE_PARTIAL
    else:
        state = STATE_NOT_READY
    return {"state": state, "score": value, "coverage": coverage, "blockers": blockers,
            "gaps": gaps[:20], "counts": counts, "unverified": counts.get(UNVERIFIED, 0)}

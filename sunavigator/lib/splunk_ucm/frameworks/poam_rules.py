"""Informational POA&M eligibility for CMMC Level 2 (32 CFR 170.21, D-080).

32 CFR 170.21(a)(2) lets an organisation reach Conditional Level 2 status with a plan of action and milestones only if the
score divided by 110 is at least 0.8, no requirement on the plan is worth more than one point (except 3.13.11 at three points
when encryption is used but is not FIPS-validated), and none of six named requirements is on the plan; 170.21(b) requires
the closeout assessment within 180 days of the Conditional status date.

SUNavigator records coverage and assessments. It does not decide a CMMC status, and a flag here is advice for the person
who keeps the plan: it never blocks a plan item and never changes a score.
"""

import datetime
from typing import Any, Dict, List, Optional

METHOD = "dod-800-171-1.2.1"
THRESHOLD = 0.8
CLOSEOUT_DAYS = 180
EXCLUDED = ("AC.L2-3.1.20", "AC.L2-3.1.22", "CA.L2-3.12.4", "PE.L2-3.10.3", "PE.L2-3.10.4", "PE.L2-3.10.5")
FIPS_EXCEPTION = "SC.L2-3.13.11"
MET_STATUSES = ("implemented", "not_applicable")
BASIS = "32 CFR 170.21(a)(2) and (b)"
NOTICE = "Information only: this is not a CMMC status determination."


def applies(definition: Dict[str, Any]) -> bool:
    return ((definition or {}).get("scoring") or {}).get("method") == METHOD


def _value(control: Dict[str, Any], status: str) -> int:
    if status in MET_STATUSES:
        return 0
    if status == "partially_implemented" and control.get("partial_weight") is not None:
        return int(control["partial_weight"])
    return int(control.get("weight", 0))


def item_flags(definition: Dict[str, Any], control_id: str, status: str, due: str, today: str) -> Optional[Dict[str, Any]]:
    """Why a plan item may not count toward Conditional status; None when the framework has no such rule."""
    if not applies(definition):
        return None
    control = next((c for c in definition.get("controls", []) if c.get("id") == control_id), None)
    if control is None:
        return None
    reasons: List[str] = []
    value = _value(control, status or "not_implemented")
    if control_id in EXCLUDED:
        reasons.append("%s may not be on a plan of action (it is one of the six excluded requirements)." % control_id)
    elif status in MET_STATUSES:
        reasons.append("The requirement is recorded as %s; a plan of action covers only requirements scored not met."
                       % status.replace("_", " "))
    elif value > 1 and not (control_id == FIPS_EXCEPTION and value == 3):
        reasons.append("Its point value is %d; only requirements worth one point may be on a plan%s."
                       % (value, " (3.13.11 is the exception, and only at three points: encryption used but not FIPS-validated)"
                          if control_id == FIPS_EXCEPTION else ""))
    deadline = _later(today, CLOSEOUT_DAYS)
    late = bool(due) and bool(deadline) and due > deadline
    if late:
        reasons.append("Closeout is due within %d days of the Conditional status date; a due date after %s cannot meet that "
                       "if the status were awarded today." % (CLOSEOUT_DAYS, deadline))
    return {"basis": BASIS, "notice": NOTICE, "point_value": value, "eligible": not reasons, "reasons": reasons,
            "closeout_deadline_if_awarded_today": deadline}


def programme(definition: Dict[str, Any], score: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The 0.8 threshold on the score as it stands now."""
    if not applies(definition) or not score or not score.get("requirements"):
        return None
    ratio = score["score"] / float(score["requirements"])
    return {"basis": BASIS, "notice": NOTICE, "score": score["score"], "requirements": score["requirements"],
            "ratio": round(ratio, 4), "threshold": THRESHOLD, "meets_threshold": ratio >= THRESHOLD,
            "assessed": score.get("assessed"), "unassessed": score.get("unassessed"),
            "can_pass": score.get("can_pass", True), "blocked_by": list(score.get("blocked_by") or [])}


def _later(day: str, days: int) -> str:
    try:
        return (datetime.date.fromisoformat(day) + datetime.timedelta(days=days)).isoformat()
    except ValueError:
        return ""

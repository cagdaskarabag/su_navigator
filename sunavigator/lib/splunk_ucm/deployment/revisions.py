"""What changed between two revisions of a deployment, and what is kept of a revision that was trimmed (D-075).

A revision holds the approved SPL and the settings it was deployed with. When a deployment has more revisions than
``max_revisions`` the oldest unused ones are dropped; a short record (a stub) stays so that the hash of what was approved
and who approved it can still be shown. A diff needs both revisions in full.
"""

import difflib
from typing import Any, Dict, List, Optional, Sequence

from . import actions as action_rules

STUB_FIELDS = ("rev", "spl_hash", "spl_source", "cron", "created_by", "created_at", "submitted_by", "submitted_at",
               "approved_by", "approved_at", "deployed_by", "deployed_at")
MAX_STUBS = 500
MAX_DIFF_LINES = 400
SPEC_FIELDS = ("spl_source", "cron", "earliest", "latest", "schedule_window", "alert_mode", "severity", "threshold",
               "suppress_period", "suppress_fields", "notes")


def stub(rev: Dict[str, Any], trimmed_at: str) -> Dict[str, Any]:
    out = {k: rev.get(k) for k in STUB_FIELDS}
    out["trimmed_at"] = trimmed_at
    return out


def describe(rev: Dict[str, Any]) -> Dict[str, Any]:
    return {k: rev.get(k) for k in STUB_FIELDS}


def find(doc: Dict[str, Any], number: int) -> Dict[str, Any]:
    """``{"full": rev}`` when the revision is kept, ``{"stub": ...}`` when only its record is, else ``{}``."""
    for rev in doc.get("revisions") or []:
        if rev.get("rev") == number:
            return {"full": rev}
    for item in doc.get("revision_log") or []:
        if item.get("rev") == number:
            return {"stub": item}
    return {}


def _actions_view(rev: Dict[str, Any]) -> Dict[str, Any]:
    return action_rules.summary(rev.get("actions") or {})


def diff_revisions(older: Dict[str, Any], newer: Dict[str, Any]) -> Dict[str, Any]:
    fields: List[Dict[str, Any]] = []
    for name in SPEC_FIELDS:
        if older.get(name) != newer.get(name):
            fields.append({"field": name, "from": older.get(name), "to": newer.get(name)})
    if _actions_view(older) != _actions_view(newer) or \
            action_rules.digest(older.get("actions") or {}) != action_rules.digest(newer.get("actions") or {}):
        fields.append({"field": "actions", "from": _actions_view(older), "to": _actions_view(newer)})
    a = (older.get("spl") or "").splitlines()
    b = (newer.get("spl") or "").splitlines()
    unified = list(difflib.unified_diff(a, b, "revision %s" % older.get("rev"), "revision %s" % newer.get("rev"),
                                        lineterm="", n=2))
    added = sum(1 for line in unified if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in unified if line.startswith("-") and not line.startswith("---"))
    return {"available": True, "from": describe(older), "to": describe(newer), "fields": fields,
            "spl": {"changed": older.get("spl_hash") != newer.get("spl_hash") or bool(unified), "added": added,
                    "removed": removed, "lines": unified[:MAX_DIFF_LINES], "truncated": len(unified) > MAX_DIFF_LINES}}


def unavailable(doc: Dict[str, Any], numbers: Sequence[int]) -> Optional[Dict[str, Any]]:
    """The response for a pair where a revision was trimmed: what is still known about it."""
    known = [find(doc, n) for n in numbers]
    if all("full" in k for k in known):
        return None
    return {"available": False,
            "revisions": [k.get("full") and describe(k["full"]) or k.get("stub") or {"rev": n, "missing": True}
                          for k, n in zip(known, numbers)],
            "reason": "A revision was trimmed after max_revisions was reached; only its hash and record remain."}

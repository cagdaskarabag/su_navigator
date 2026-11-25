"""One record shape for advisory findings: SPL lint, schedule checks and run health (D-069).

``code`` is stable (``L001`` lint, ``S001`` schedule, ``H001`` health); ``category`` groups them;
``severity`` is ``info`` or ``warning`` (advisories never block); ``message`` is the sentence the
UI shows; ``evidence`` holds the values the message was computed from.
"""

from typing import Any, Dict, Iterable, List, Optional

SEVERITIES = ("info", "warning")
CATEGORIES = ("lint", "schedule", "health")


def finding(code: str, category: str, severity: str, message: str,
            evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if category not in CATEGORIES:
        raise ValueError("unknown finding category %r" % category)
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity %r" % severity)
    return {"code": code, "category": category, "severity": severity, "message": message,
            "evidence": dict(evidence or {})}


def from_lint(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Lint findings (``spl.lint``) in the common shape; the lint record itself is unchanged."""
    out = []
    for item in items or []:
        evidence = {k: item[k] for k in ("name", "segment", "command", "call", "in_map") if k in item}
        out.append(finding(str(item.get("rule") or ""), "lint", "warning", str(item.get("message") or ""), evidence))
    return out

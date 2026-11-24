"""Bounded "does this data model hold events" check run by discovery (docs/DECISIONS.md D-067, issue #13).

For each selected data model discovery runs one ``| tstats count from datamodel=<model> where
earliest=-24h`` through the same system-token search path as the pair scan. The outcome is an
informational ``populated`` value stored next to the data model in the discovery data:

* ``yes``: the search returned a non-zero count;
* ``no``: it ran to completion and returned zero;
* ``unverified``: it did not run or did not finish, with a reason code (never a guess).

The check never raises, never changes a readiness status or score, and is bounded four ways: a
cap on models, a time limit per search, a total time budget, and a stop after repeated failures.
"""

import dataclasses
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from ..errors import UnsupportedOperation, ValidationError
from ..log import get_logger

log = get_logger(__name__)

YES, NO, UNVERIFIED = "yes", "no", "unverified"
WINDOW = "-24h"
CIM_APP = "Splunk_SA_CIM"
_APP = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
MODEL_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$")
MAX_CONSECUTIVE_FAILURES = 3

REASON_DISABLED = "check_disabled"
REASON_NOT_SELECTED = "not_referenced"
REASON_CAP = "model_cap"
REASON_BUDGET = "time_budget"
REASON_TIMEOUT = "timeout"
REASON_FAILED = "search_failed"
REASON_UNAVAILABLE = "search_unavailable"
REASON_STOPPED = "stopped_after_failures"
REASON_NO_RESULT = "no_result"
REASON_BAD_NAME = "invalid_name"

REASON_TEXT = {
    REASON_DISABLED: "the check is switched off ([discovery] populated_check = false)",
    REASON_NOT_SELECTED: "no catalogue requirement references this model and it is not a CIM model",
    REASON_CAP: "the cap on checked models was reached ([discovery] populated_max_models)",
    REASON_BUDGET: "the total time budget for the check was used up",
    REASON_TIMEOUT: "the search hit its time limit ([discovery] populated_timeout_seconds)",
    REASON_FAILED: "the search failed",
    REASON_UNAVAILABLE: "ad-hoc search is not available to the discovery account",
    REASON_STOPPED: "earlier checks failed repeatedly, so the rest were skipped",
    REASON_NO_RESULT: "the search returned no count row",
    REASON_BAD_NAME: "the model name is not a plain identifier, so no search was built from it",
    "predates_check": "this discovery data was written before the populated check existed; run discovery again",
}


@dataclasses.dataclass
class PopulatedSettings:
    enabled: bool = True
    max_models: int = 30
    timeout_seconds: int = 30
    budget_seconds: int = 300


def populated_search(model: str) -> str:
    if not isinstance(model, str) or not MODEL_NAME.match(model):
        raise ValidationError("invalid data model name", {"value": str(model)[:80]})
    return "| tstats count from datamodel=%s where earliest=%s" % (model, WINDOW)


def _outcome(populated: str, reason: str = "", count: Optional[int] = None) -> Dict[str, Any]:
    return {"populated": populated, "reason": reason, "count": count}


def select_models(models: Sequence[Dict[str, Any]], referenced: Iterable[str]) -> List[str]:
    """Names to check, referenced models first, then CIM models; stable by name inside each group."""
    wanted = {str(n).lower() for n in referenced}
    live = [m for m in models if not m.get("disabled") and m.get("name")]
    first = sorted(m["name"] for m in live if m["name"].lower() in wanted)
    rest = sorted(m["name"] for m in live if m["name"].lower() not in wanted and m.get("app") == CIM_APP)
    return first + rest


def _is_timeout(exc: BaseException) -> bool:
    text = ("%s %s" % (type(exc).__name__, exc)).lower()
    return "timed out" in text or "timeout" in text


def _count(rows: Sequence[Dict[str, Any]]) -> Optional[int]:
    if not rows:
        return None
    try:
        return int(float(rows[0].get("count")))
    except (TypeError, ValueError):
        return None


def _finalized(messages: Sequence[Dict[str, Any]]) -> bool:
    for m in messages or []:
        text = str(m.get("text") or "").lower()
        if "finaliz" in text or "time limit" in text or "max_time" in text or "timed out" in text:
            return True
    return False


def check_models(search: Any, models: Sequence[Dict[str, Any]], referenced: Iterable[str],
                 settings: PopulatedSettings,
                 clock: Callable[[], float] = time.monotonic) -> Dict[str, Dict[str, Any]]:
    """Outcome per data model name for every enabled model; never raises."""
    out: Dict[str, Dict[str, Any]] = {}
    live = [m["name"] for m in models if not m.get("disabled") and m.get("name")]
    if not settings.enabled:
        return {name: _outcome(UNVERIFIED, REASON_DISABLED) for name in live}
    chosen = select_models(models, referenced)
    chosen_set: Set[str] = set(chosen)
    for name in live:
        if name not in chosen_set:
            out[name] = _outcome(UNVERIFIED, REASON_NOT_SELECTED)
    apps = {m["name"]: str(m.get("app") or "") for m in models if m.get("name")}
    started = clock()
    failures = 0
    for position, name in enumerate(chosen):
        if position >= max(0, settings.max_models):
            out[name] = _outcome(UNVERIFIED, REASON_CAP)
        elif failures >= MAX_CONSECUTIVE_FAILURES:
            out[name] = _outcome(UNVERIFIED, REASON_STOPPED)
        elif clock() - started > settings.budget_seconds:
            out[name] = _outcome(UNVERIFIED, REASON_BUDGET)
        else:
            out[name] = _check_one(search, name, apps.get(name, ""), settings)
            failures = failures + 1 if out[name]["reason"] in (REASON_FAILED, REASON_TIMEOUT,
                                                                REASON_UNAVAILABLE) else 0
    return out


def _check_one(search: Any, name: str, app: str, settings: PopulatedSettings) -> Dict[str, Any]:
    try:
        spl = populated_search(name)
    except ValidationError:
        return _outcome(UNVERIFIED, REASON_BAD_NAME)
    try:
        result = search.oneshot(spl, timeout=float(settings.timeout_seconds), max_count=1,
                                max_time=int(settings.timeout_seconds), app=app if _APP.match(app) else "")
    except UnsupportedOperation:
        return _outcome(UNVERIFIED, REASON_UNAVAILABLE)
    except Exception as exc:
        log.info("data model populated check failed", extra={"model": name, "error": str(exc)[:200]})
        return _outcome(UNVERIFIED, REASON_TIMEOUT if _is_timeout(exc) else REASON_FAILED)
    count = _count(result.rows)
    if count is None:
        return _outcome(UNVERIFIED, REASON_TIMEOUT if _finalized(result.messages) else REASON_NO_RESULT)
    if count > 0:
        return _outcome(YES, "", count)
    if _finalized(result.messages):
        return _outcome(UNVERIFIED, REASON_TIMEOUT, 0)
    return _outcome(NO, "", 0)


def summarize(outcomes: Dict[str, Dict[str, Any]], enabled: bool) -> Dict[str, Any]:
    tally = {YES: 0, NO: 0, UNVERIFIED: 0}
    for o in outcomes.values():
        tally[o["populated"]] += 1
    return {"enabled": enabled, "window": WINDOW, "models": len(outcomes), "yes": tally[YES],
            "no": tally[NO], "unverified": tally[UNVERIFIED]}


def reason_text(code: str) -> str:
    return REASON_TEXT.get(code or "", "")

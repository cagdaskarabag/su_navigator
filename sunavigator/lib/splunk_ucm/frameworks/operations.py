"""Operational health of deployed searches from the scheduler log (D-031, D-069).

A constructed search over ``index=_internal sourcetype=scheduler`` for this
app's managed searches; imported SPL is not involved. Callers without access
to ``_internal`` get ``available: false`` rather than an error.

Two kinds of scheduler line are read. A run line carries ``savedsearch_name``
and ``status`` (success, skipped, ...), ``run_time`` and ``result_count``. A
search that fails before it is dispatched (unknown command, missing
capability, permission denied) writes only ``savedsearch_id="owner;app;name"``
and ``message``, with no ``status``; Splunk 10.2.9, measured. Those are counted
as dispatch errors, never as runs.
"""

from typing import Any, Dict, List, Optional

from .. import APP_NAME
from ..deployment.schedule import cadence_seconds
from ..errors import UnsupportedOperation, ValidationError
from ..platform.search import SearchClient
from ..spl.findings import finding
from ..storage import collections as C
from ..storage.kvstore import DocumentStore

_HOURS = (1, 4, 24, 72, 168)

HEALTH_SPL = (
    '| search index=_internal sourcetype=scheduler '
    '((app="{app}" savedsearch_name="SUN - *") OR savedsearch_id="*;{app};SUN - *") '
    '| eval sun_name=coalesce(savedsearch_name, mvindex(split(savedsearch_id, ";"), 2)) '
    '| eval sun_error=if(isnull(status), 1, 0), sun_error_message=if(isnull(status), message, null()) '
    '| eval sun_error_time=if(isnull(status), _time, null()), sun_run_time=if(isnotnull(status), _time, null()) '
    '| eval sun_skip_reason=if(status="skipped", reason, null()) '
    '| fillnull value=0 result_count '
    '| stats count(status) as runs sum(eval(if(status="success",1,0))) as succeeded '
    'sum(eval(if(status="skipped",1,0))) as skipped '
    'sum(eval(if(isnotnull(status) AND status!="success" AND status!="skipped",1,0))) as other '
    'sum(eval(if(result_count>0,1,0))) as runs_with_results '
    'sum(sun_error) as dispatch_errors latest(sun_error_message) as last_error max(sun_error_time) as last_error_time '
    'latest(sun_skip_reason) as last_skip_reason '
    'max(sun_run_time) as last_run latest(status) as last_status latest(result_count) as last_result_count '
    'perc90(run_time) as p90_run_time max(run_time) as max_run_time '
    'by sun_name | rename sun_name as savedsearch_name'.format(app=APP_NAME))

# splunkd writes to _internal continuously, so zero events means the caller cannot read it.
VISIBILITY_SPL = "| tstats count where index=_internal"
NO_ACCESS = "Your role cannot read index=_internal, which holds the scheduler logs."

SKIP_WARN_RATIO = 0.2


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _opt(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def classify(enabled: bool, row: Dict[str, Any]) -> str:
    """``operational`` means the last run finished with status success and no dispatch error came after it;
    it says nothing about data. ``failing_dispatch``: the newest scheduler line for the search is a dispatch error."""
    if not enabled:
        return "disabled"
    last_error = _opt(row.get("last_error_time")) if row else None
    last_run = _opt(row.get("last_run")) if row else None
    if last_error is not None and (last_run is None or last_error >= last_run):
        return "failing_dispatch"
    if not row or not _num(row.get("runs")):
        return "no_runs"
    if row.get("last_status") == "success" and _num(row.get("succeeded")):
        return "operational"
    return "unhealthy"


def advisories(row: Dict[str, Any], cron: str) -> List[Dict[str, Any]]:
    """Health findings for one search: dispatch errors, skip ratio, run time against the cadence."""
    out: List[Dict[str, Any]] = []
    if not row:
        return out
    errors = int(_num(row.get("dispatch_errors")))
    if errors:
        out.append(finding("H001", "health", "warning",
                           "%d scheduled run%s failed before dispatch: %s" % (
                               errors, "" if errors == 1 else "s", str(row.get("last_error") or "no message")[:300]),
                           {"dispatch_errors": errors, "last_error_time": _opt(row.get("last_error_time"))}))
    runs, skipped = _num(row.get("runs")), _num(row.get("skipped"))
    if runs and skipped / runs >= SKIP_WARN_RATIO:
        out.append(finding("H002", "health", "warning",
                           "%d of %d scheduled runs were skipped (%d%%)%s." % (
                               skipped, runs, round(100 * skipped / runs),
                               ", last reason: %s" % str(row.get("last_skip_reason"))[:200]
                               if row.get("last_skip_reason") else ""),
                           {"runs": int(runs), "skipped": int(skipped), "ratio": round(skipped / runs, 3)}))
    cadence = cadence_seconds(cron)
    p90, longest = _opt(row.get("p90_run_time")), _opt(row.get("max_run_time"))
    if cadence and p90 is not None and p90 > cadence:
        out.append(finding("H003", "health", "warning",
                           "Nine in ten runs take up to %.0f s, longer than the %d s between runs: runs will be skipped "
                           "or queue." % (p90, cadence), {"p90_run_time": p90, "cadence_seconds": cadence}))
    elif cadence and longest is not None and longest > cadence:
        out.append(finding("H004", "health", "info",
                           "The longest run took %.0f s, longer than the %d s between runs." % (longest, cadence),
                           {"max_run_time": longest, "cadence_seconds": cadence}))
    return out


class OperationsService:
    def __init__(self, store: DocumentStore, search: SearchClient):
        self.store = store
        self.search = search

    def health(self, hours: int = 24) -> Dict[str, Any]:
        if hours not in _HOURS:
            raise ValidationError("hours must be one of %s" % ", ".join(str(h) for h in _HOURS))
        deployments = self.store.query(C.DEPLOYMENTS, {"deployed_revision": {"$gte": 1}},
                                       fields=["content_id", "catalog_key", "title", "saved_search",
                                               "live_status", "deployed_revision", "revisions"], limit=2000)
        rows: Dict[str, Dict[str, Any]] = {}
        available, reason, truncated = True, "", False
        if deployments:
            try:
                result = self.search.oneshot(HEALTH_SPL, timeout=60.0, max_count=5000,
                                             earliest="-%dh" % hours, latest="now")
                rows = {str(r.get("savedsearch_name") or ""): r for r in result.rows}
                truncated = result.truncated
                if not rows and not self._can_read_internal():
                    available, reason = False, NO_ACCESS
            except (UnsupportedOperation, ValidationError) as exc:
                available, reason = False, exc.message[:300]
        items = []
        counts: Dict[str, int] = {}
        for d in deployments:
            name = (d.get("saved_search") or {}).get("name", "")
            row = rows.get(name, {})
            enabled = d.get("live_status") == "enabled"
            if not available or (truncated and not row):
                # A row cut from a truncated result is not evidence that the search never ran.
                status = "disabled" if not enabled else "unknown"
            else:
                status = classify(enabled, row)
            counts[status] = counts.get(status, 0) + 1
            cron = _deployed_cron(d)
            items.append({
                "content_id": d.get("content_id"), "catalog_key": d.get("catalog_key"), "title": d.get("title"),
                "saved_search": name, "live_status": d.get("live_status"), "health": status,
                "runs": int(_num(row.get("runs"))), "succeeded": int(_num(row.get("succeeded"))),
                "skipped": int(_num(row.get("skipped"))), "other": int(_num(row.get("other"))),
                "runs_with_results": int(_num(row.get("runs_with_results"))),
                "last_run": _num(row.get("last_run")) or None, "last_status": row.get("last_status"),
                "last_result_count": int(_num(row.get("last_result_count"))) if row else None,
                "dispatch_errors": int(_num(row.get("dispatch_errors"))),
                "last_error": str(row.get("last_error") or "")[:300] or None,
                "last_error_time": _opt(row.get("last_error_time")),
                "last_skip_reason": str(row.get("last_skip_reason") or "")[:200] or None,
                "p90_run_time": _opt(row.get("p90_run_time")), "max_run_time": _opt(row.get("max_run_time")),
                "cadence_seconds": cadence_seconds(cron) if cron else None,
                "advisories": advisories(row, cron) if available else [],
            })
        return {"available": available, "reason": reason, "truncated": truncated, "hours": hours,
                "items": items, "counts": counts}

    def _can_read_internal(self) -> bool:
        result = self.search.oneshot(VISIBILITY_SPL, timeout=30.0, max_count=1, earliest="-1h", latest="now")
        return bool(result.rows) and _num(result.rows[0].get("count")) > 0


def _deployed_cron(doc: Dict[str, Any]) -> str:
    rev = doc.get("deployed_revision")
    for revision in doc.get("revisions") or []:
        if isinstance(revision, dict) and revision.get("rev") == rev:
            return str(revision.get("cron") or "")
    return ""

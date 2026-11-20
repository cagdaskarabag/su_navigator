"""Operational health of deployed searches from the scheduler log (D-031).

A constructed search over ``index=_internal sourcetype=scheduler`` for this
app's managed searches; imported SPL is not involved. Callers without access
to ``_internal`` get ``available: false`` rather than an error.
"""

from typing import Any, Dict

from .. import APP_NAME
from ..errors import UnsupportedOperation, ValidationError
from ..platform.search import SearchClient
from ..storage import collections as C
from ..storage.kvstore import DocumentStore

_HOURS = (1, 4, 24, 72, 168)

HEALTH_SPL = (
    '| search index=_internal sourcetype=scheduler app="%s" savedsearch_name="SUN - *" '
    '| stats count as runs sum(eval(if(status="success",1,0))) as succeeded '
    'sum(eval(if(status="skipped",1,0))) as skipped '
    'sum(eval(if(status!="success" AND status!="skipped",1,0))) as other '
    'sum(eval(if(result_count>0,1,0))) as runs_with_results '
    'max(_time) as last_run latest(status) as last_status latest(result_count) as last_result_count '
    'by savedsearch_name' % APP_NAME)

# splunkd writes to _internal continuously, so zero events means the caller cannot read it.
VISIBILITY_SPL = "| tstats count where index=_internal"
NO_ACCESS = "Your role cannot read index=_internal, which holds the scheduler logs."


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def classify(enabled: bool, row: Dict[str, Any]) -> str:
    if not enabled:
        return "disabled"
    if not row or not _num(row.get("runs")):
        return "no_runs"
    if row.get("last_status") == "success" and _num(row.get("succeeded")):
        return "operational"
    return "unhealthy"


class OperationsService:
    def __init__(self, store: DocumentStore, search: SearchClient):
        self.store = store
        self.search = search

    def health(self, hours: int = 24) -> Dict[str, Any]:
        if hours not in _HOURS:
            raise ValidationError("hours must be one of %s" % ", ".join(str(h) for h in _HOURS))
        deployments = self.store.query(C.DEPLOYMENTS, {"deployed_revision": {"$gte": 1}},
                                       fields=["content_id", "catalog_key", "title", "saved_search",
                                               "live_status"], limit=2000)
        rows: Dict[str, Dict[str, Any]] = {}
        available, reason = True, ""
        if deployments:
            try:
                result = self.search.oneshot(HEALTH_SPL, timeout=60.0, max_count=5000,
                                             earliest="-%dh" % hours, latest="now")
                rows = {str(r.get("savedsearch_name") or ""): r for r in result.rows}
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
            status = classify(enabled, row) if available else ("disabled" if not enabled else "unknown")
            counts[status] = counts.get(status, 0) + 1
            items.append({
                "content_id": d.get("content_id"), "catalog_key": d.get("catalog_key"), "title": d.get("title"),
                "saved_search": name, "live_status": d.get("live_status"), "health": status,
                "runs": int(_num(row.get("runs"))), "succeeded": int(_num(row.get("succeeded"))),
                "skipped": int(_num(row.get("skipped"))), "other": int(_num(row.get("other"))),
                "runs_with_results": int(_num(row.get("runs_with_results"))),
                "last_run": _num(row.get("last_run")) or None, "last_status": row.get("last_status"),
                "last_result_count": int(_num(row.get("last_result_count"))) if row else None,
            })
        return {"available": available, "reason": reason, "hours": hours, "items": items, "counts": counts}

    def _can_read_internal(self) -> bool:
        result = self.search.oneshot(VISIBILITY_SPL, timeout=30.0, max_count=1, earliest="-1h", latest="now")
        return bool(result.rows) and _num(result.rows[0].get("count")) > 0

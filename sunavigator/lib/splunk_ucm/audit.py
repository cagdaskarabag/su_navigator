"""Audit trail: append-only records in ``uc_audit`` mirrored to the app log."""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from .log import get_logger
from .storage import collections as C
from .storage.kvstore import DocumentStore
from .util import epoch_now, new_id, utc_now_iso

log = get_logger(__name__)

_MAX_DETAIL_CHARS = 8000
CHAIN_FIELDS = ("_key", "time", "time_iso", "actor", "action", "object_type", "object_id", "outcome", "details",
                "prev_hash")
VERIFY_LIMIT = 50000
LISTED = 25
PAGE = 5000


def _canon(value: Any) -> Any:
    """Make a value hash the same before and after the KV Store, which may return 100.0 as 100."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {str(k): _canon(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    return value


def row_hash(doc: Dict[str, Any]) -> str:
    """SHA-256 over the row's own fields and the hash of the row written before it (D-075)."""
    body = json.dumps({k: _canon(doc.get(k)) for k in CHAIN_FIELDS}, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditService:
    def __init__(self, store: DocumentStore):
        self.store = store

    def record(self, actor: str, action: str, object_type: str, object_id: str,
               outcome: str = "success", details: Optional[Dict[str, Any]] = None) -> str:
        details = details or {}
        text = repr(details)
        if len(text) > _MAX_DETAIL_CHARS:
            details = {"truncated": True, "preview": text[:_MAX_DETAIL_CHARS]}
        doc = {
            "_key": new_id(), "time": epoch_now(), "time_iso": utc_now_iso(), "actor": actor or "unknown",
            "action": action, "object_type": object_type, "object_id": object_id,
            "outcome": outcome, "details": details,
        }
        log.info("audit", extra={"audit_action": action, "actor": doc["actor"], "object_type": object_type,
                                 "object_id": object_id, "outcome": outcome})
        try:
            doc["prev_hash"] = self._head()
            doc["hash"] = row_hash(doc)
            self.store.upsert(C.AUDIT, doc)
        except Exception:  # audit storage failure must be visible but not mask the original operation
            log.exception("audit write failed", extra={"audit_action": action})
        return doc["_key"]

    def written_within(self, action: str, object_id: str, seconds: float, now: Optional[float] = None) -> bool:
        """Whether a row for this action and object, by anyone, was written in the last ``seconds`` (0 turns the check off)."""
        if seconds <= 0:
            return False
        cutoff = (epoch_now() if now is None else now) - seconds
        rows = self.store.query(C.AUDIT, {"$and": [{"action": action}, {"object_id": object_id},
                                                   {"time": {"$gte": cutoff}}]}, limit=1, fields=["_key"])
        return bool(rows)

    def recent(self, limit: int = 50, action_prefix: str = "") -> List[Dict[str, Any]]:
        query = {"action": {"$regex": "^" + re.escape(action_prefix)}} if action_prefix else None
        return self.store.query(C.AUDIT, query, sort=[("time", -1)], limit=limit)

    def _head(self) -> str:
        """Hash of the newest chained row; empty when there is none or it cannot be read."""
        try:
            rows = self.store.query(C.AUDIT, None, sort=[("time", -1)], limit=1, fields=["hash"])
        except Exception:
            return ""
        return str(rows[0].get("hash") or "") if rows else ""

    def verify_chain(self, limit: int = VERIFY_LIMIT) -> Dict[str, Any]:
        """Re-compute every row's hash and check each row's link to its predecessor.

        Finds a row that was edited (its hash no longer matches) and a row that was deleted from the middle (a successor
        names a hash that no row has). It cannot find the newest rows being deleted, or a collection rewritten end to end
        by someone who can write it: record ``head`` somewhere outside Splunk to cover those cases.
        """
        rows: List[Dict[str, Any]] = []
        while len(rows) <= limit:
            page = self.store.query(C.AUDIT, None, sort=[("time", 1), ("_key", 1)], skip=len(rows),
                                    limit=min(PAGE, limit + 1 - len(rows)))
            rows.extend(page)
            if len(page) < PAGE:
                break
        truncated = len(rows) > limit
        rows = rows[:limit]
        chained = [r for r in rows if r.get("hash")]
        known = {r["hash"] for r in chained}
        modified: List[Dict[str, Any]] = []
        missing: List[Dict[str, Any]] = []
        restarts: List[Dict[str, Any]] = []
        links: Dict[str, int] = {}
        for index, row in enumerate(chained):
            ref = {"key": row["_key"], "time": row.get("time_iso"), "action": row.get("action")}
            if row_hash(row) != row["hash"]:
                modified.append(ref)
            prev = row.get("prev_hash") or ""
            links[prev] = links.get(prev, 0) + 1
            if not prev:
                if index:
                    restarts.append(ref)
            elif prev not in known and index:
                missing.append(ref)
        branches = sum(n - 1 for p, n in links.items() if p and n > 1)
        ok = not (modified or missing or restarts)
        return {"ok": ok, "rows": len(rows), "chained": len(chained), "legacy": len(rows) - len(chained),
                "modified": modified[:LISTED], "modified_count": len(modified),
                "missing_predecessor": missing[:LISTED], "missing_count": len(missing),
                "restarts": restarts[:LISTED], "restart_count": len(restarts), "branches": branches,
                "head": chained[-1]["hash"] if chained else "", "truncated": truncated,
                "first_time": chained[0].get("time_iso") if chained else ""}

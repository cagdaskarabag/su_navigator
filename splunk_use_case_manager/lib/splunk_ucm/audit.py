"""Audit trail: append-only records in ``uc_audit`` mirrored to the app log."""

import re
from typing import Any, Dict, List, Optional

from .log import get_logger
from .storage import collections as C
from .storage.kvstore import DocumentStore
from .util import epoch_now, new_id, utc_now_iso

log = get_logger(__name__)

_MAX_DETAIL_CHARS = 8000


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
            self.store.upsert(C.AUDIT, doc)
        except Exception:  # audit storage failure must be visible but not mask the original operation
            log.exception("audit write failed", extra={"audit_action": action})
        return doc["_key"]

    def recent(self, limit: int = 50, action_prefix: str = "") -> List[Dict[str, Any]]:
        query = {"action": {"$regex": "^" + re.escape(action_prefix)}} if action_prefix else None
        return self.store.query(C.AUDIT, query, sort=[("time", -1)], limit=limit)

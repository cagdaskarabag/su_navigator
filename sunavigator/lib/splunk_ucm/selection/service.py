"""Per-user selection of use cases (bookmark, select, defer, reject).

Rows are keyed by user + content id. Sync never writes this collection.
The REST handler only reads and writes the caller's own rows.
"""

from typing import Any, Dict, List, Optional

from ..audit import AuditService
from ..catalog.detail import key_from_id
from ..errors import NotFoundError, ValidationError
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..util import safe_key, utc_now_iso

INTENTS = ("bookmark", "select", "defer", "reject")
BACKLOG = ("select", "defer")
MAX_COUNT = 500


def selection_key(user: str, content_id: str) -> str:
    return safe_key("sel", user, content_id)


class SelectionService:
    def __init__(self, store: DocumentStore, audit: AuditService):
        self.store = store
        self.audit = audit

    def get(self, user: str, content_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.SELECTIONS, selection_key(user, content_id))

    def list_for(self, user: str, intent: Optional[str] = None, offset: int = 0,
                 count: int = 50) -> Dict[str, Any]:
        offset = max(0, offset)
        count = max(1, min(MAX_COUNT, count))
        query: Dict[str, Any] = {"user": user}
        if intent:
            if intent == "backlog":
                query = {"$and": [{"user": user}, {"$or": [{"intent": i} for i in BACKLOG]}]}
            elif intent in INTENTS:
                query["intent"] = intent
            else:
                raise ValidationError("invalid intent")
        rows = self.store.query(C.SELECTIONS, query, sort=[("priority", -1), ("updated_at", -1)],
                                skip=offset, limit=count + 1)
        items = [self._join(r) for r in rows[:count]]
        return {"items": items, "offset": offset, "count": min(count, len(items)),
                "has_more": len(rows) > count}

    def upsert(self, user: str, content_id: str, intent: str, notes: str = "",
               priority: int = 50) -> Dict[str, Any]:
        if intent not in INTENTS:
            raise ValidationError("invalid intent", {"allowed": list(INTENTS)})
        if not 0 <= int(priority) <= 100:
            raise ValidationError("priority must be 0-100")
        if len(notes) > 500:
            raise ValidationError("notes too long")
        key = key_from_id(content_id)
        catalog = self.store.get(C.CATALOG, key)
        if not catalog:
            raise NotFoundError("use case not found", {"id": content_id})
        cid = catalog.get("content_id") or content_id
        existing = self.store.get(C.SELECTIONS, selection_key(user, cid)) or {}
        doc = {
            "_key": selection_key(user, cid), "doc_schema": DOC_SCHEMA, "user": user,
            "content_id": cid, "catalog_key": key, "intent": intent,
            "notes": notes, "priority": int(priority),
            "created_at": existing.get("created_at") or utc_now_iso(),
            "updated_at": utc_now_iso(),
        }
        self.store.upsert(C.SELECTIONS, doc)
        self.audit.record(user, "selection.upsert", "selection", cid,
                          details={"intent": intent, "priority": int(priority)})
        return self._join(doc)

    def delete(self, user: str, content_id: str) -> None:
        cid = content_id
        try:
            catalog = self.store.get(C.CATALOG, key_from_id(content_id))
            if catalog:
                cid = catalog.get("content_id") or content_id
        except ValidationError:
            pass
        key = selection_key(user, cid)
        if self.store.get(C.SELECTIONS, key) is None:
            raise NotFoundError("selection not found")
        self.store.delete(C.SELECTIONS, key)
        self.audit.record(user, "selection.delete", "selection", cid)

    def for_use_case(self, user: str, content_id: str) -> Optional[Dict[str, Any]]:
        try:
            key = key_from_id(content_id)
        except ValidationError:
            return None
        catalog = self.store.get(C.CATALOG, key)
        cid = (catalog or {}).get("content_id") or content_id
        return self.store.get(C.SELECTIONS, selection_key(user, cid))

    def _join(self, row: Dict[str, Any]) -> Dict[str, Any]:
        catalog = self.store.get(C.CATALOG, row.get("catalog_key") or "") or {}
        readiness = self.store.get(C.READINESS, row.get("catalog_key") or "") or {}
        out = dict(row)
        out["title"] = catalog.get("title", "")
        out["criticality"] = catalog.get("criticality", "")
        out["category_name"] = catalog.get("category_name", "")
        out["domains"] = catalog.get("domains") or []
        out["provider_status"] = catalog.get("provider_status", "")
        out["readiness_state"] = readiness.get("state")
        out["readiness_score"] = readiness.get("score")
        return out

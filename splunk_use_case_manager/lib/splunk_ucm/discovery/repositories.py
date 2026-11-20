"""Repositories for discovered sources, mappings and discovery jobs."""

from typing import Any, Dict, List, Optional

from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso
from .keys import mapping_key


class SourceRepository:
    def __init__(self, store: DocumentStore):
        self.store = store

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.ENVIRONMENT_SOURCES, key)

    def save(self, docs: List[Dict[str, Any]]) -> None:
        if docs:
            self.store.batch_save(C.ENVIRONMENT_SOURCES, docs)

    def list_active(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"status": "active"}
        if kind:
            query["kind"] = kind
        return self.store.query(C.ENVIRONMENT_SOURCES, query, fields=["_key", "kind", "index"])

    def list_all(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.store.query(C.ENVIRONMENT_SOURCES, {"kind": kind} if kind else None)

    def mark_missing(self, keys: List[str], when: str) -> int:
        changed = 0
        for key in keys:
            doc = self.store.get(C.ENVIRONMENT_SOURCES, key)
            if not doc or doc.get("status") == "missing":
                continue
            doc["status"] = "missing"
            doc["missing_at"] = when
            self.store.upsert(C.ENVIRONMENT_SOURCES, doc)
            changed += 1
        return changed


class MappingRepository:
    def __init__(self, store: DocumentStore):
        self.store = store

    def get(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.SOURCE_MAPPINGS, mapping_key(kind, value))

    def get_key(self, key: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.SOURCE_MAPPINGS, key)

    def save(self, doc: Dict[str, Any]) -> None:
        self.store.upsert(C.SOURCE_MAPPINGS, doc)

    def delete(self, key: str) -> None:
        self.store.delete(C.SOURCE_MAPPINGS, key)

    def list(self, kind: Optional[str] = None, origin: Optional[str] = None,
             offset: int = 0, count: int = 50) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if kind:
            query["kind"] = kind
        if origin:
            query["origin"] = origin
        return self.store.query(C.SOURCE_MAPPINGS, query or None, sort=[("kind", 1), ("value", 1)],
                                skip=offset, limit=count)


class DiscoveryStateRepository:
    STATE_KEY = "discovery::local"
    JOB_RETENTION = 50

    def __init__(self, store: DocumentStore):
        self.store = store

    def state(self) -> Dict[str, Any]:
        return self.store.get(C.SYNC_STATE, self.STATE_KEY) or {
            "_key": self.STATE_KEY, "doc_type": "discovery_state"}

    def save_state(self, state: Dict[str, Any]) -> None:
        state["_key"] = self.STATE_KEY
        state["doc_type"] = "discovery_state"
        state["updated_at"] = utc_now_iso()
        self.store.upsert(C.SYNC_STATE, state)

    def save_job(self, job: Dict[str, Any]) -> None:
        job["updated_at"] = utc_now_iso()
        self.store.upsert(C.SYNC_STATE, job)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.SYNC_STATE, "djob::" + job_id)

    def jobs(self, status: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"doc_type": "discovery_job"}
        if status:
            query["status"] = status
        return self.store.query(C.SYNC_STATE, query, sort=[("requested_at", -1)], limit=limit)

    def next_queued(self) -> Optional[Dict[str, Any]]:
        rows = self.store.query(C.SYNC_STATE, {"doc_type": "discovery_job", "status": "queued"},
                                sort=[("requested_at", 1)], limit=1)
        return rows[0] if rows else None

    def prune(self) -> int:
        rows = self.store.query(C.SYNC_STATE, {"doc_type": "discovery_job"},
                                sort=[("requested_at", -1)], skip=self.JOB_RETENTION, fields=["_key"])
        for row in rows:
            self.store.delete(C.SYNC_STATE, row["_key"])
        return len(rows)


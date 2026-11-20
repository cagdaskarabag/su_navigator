"""Typed repositories over the document store.

Provider-owned collections (catalog, content, categories) are written only by
the sync/import services. Customer-owned collections are never touched here.
"""

import dataclasses
import json
from typing import Any, Dict, List, Optional

from ..util import chunked, utc_now_iso
from . import collections as C
from .kvstore import DocumentStore


def encode_raw(raw: Dict[str, Any]) -> str:
    """Raw provider records are stored as JSON text: KV Store rejects keys
    containing ``$`` or ``.`` (e.g. ``$schema``) and upstream keys are untrusted."""
    return json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def decode_raw(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not doc or not isinstance(doc.get("raw_json"), str):
        return None
    try:
        raw = json.loads(doc["raw_json"])
    except ValueError:
        return None
    return raw if isinstance(raw, dict) else None


@dataclasses.dataclass
class KnownRecord:
    key: str
    blob_sha: str
    source_hash: str
    normalizer_version: str
    provider_status: str


class ContentRepository:
    def __init__(self, store: DocumentStore):
        self.store = store

    def known_records(self, category_key: str) -> Dict[str, KnownRecord]:
        rows = self.store.query(C.CATALOG, {"category_key": category_key},
                                fields=["_key", "source_blob_sha", "source_hash",
                                        "normalizer_version", "provider_status"])
        return {r["_key"]: KnownRecord(r["_key"], r.get("source_blob_sha", ""), r.get("source_hash", ""),
                                       r.get("normalizer_version", ""), r.get("provider_status", ""))
                for r in rows}

    def save(self, catalog_docs: List[Dict[str, Any]], content_docs: List[Dict[str, Any]]) -> None:
        # Content first: a catalogue row must never point at missing content.
        self.store.batch_save(C.CONTENT, content_docs)
        self.store.batch_save(C.CATALOG, catalog_docs)

    def mark_status(self, keys: List[str], status: str) -> int:
        changed = 0
        for batch in chunked(keys, 200):
            rows = self.store.query(C.CATALOG, {"_key": {"$in": batch}})
            for row in rows:
                row["provider_status"] = status
                row["status_changed_at"] = utc_now_iso()
            if rows:
                self.store.batch_save(C.CATALOG, rows)
                changed += len(rows)
        return changed

    def get_catalog(self, key: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.CATALOG, key)

    def get_content(self, key: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.CONTENT, key)

    def iter_content(self, category_key: Optional[str] = None, page: int = 100):
        query = {"category_key": category_key} if category_key else None
        skip = 0
        while True:
            rows = self.store.query(C.CONTENT, query, sort=[("_key", 1)], skip=skip, limit=page)
            if not rows:
                return
            for row in rows:
                yield row
            skip += len(rows)


class CategoryRepository:
    def __init__(self, store: DocumentStore):
        self.store = store

    def list(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        query = {"provider": provider} if provider else None
        return self.store.query(C.CATEGORIES, query, sort=[("sort_order", 1)])

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.CATEGORIES, key)

    def save(self, doc: Dict[str, Any]) -> None:
        self.store.upsert(C.CATEGORIES, doc)


class SyncStateRepository:
    JOB_RETENTION = 200

    def __init__(self, store: DocumentStore):
        self.store = store

    @staticmethod
    def provider_key(provider: str) -> str:
        return "provider::" + provider

    def provider_state(self, provider: str) -> Dict[str, Any]:
        return self.store.get(C.SYNC_STATE, self.provider_key(provider)) or {
            "_key": self.provider_key(provider), "doc_type": "provider_state", "provider": provider}

    def save_provider_state(self, state: Dict[str, Any]) -> None:
        state["updated_at"] = utc_now_iso()
        self.store.upsert(C.SYNC_STATE, state)

    def save_job(self, job: Dict[str, Any]) -> None:
        job["updated_at"] = utc_now_iso()
        self.store.upsert(C.SYNC_STATE, job)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.SYNC_STATE, "job::" + job_id)

    def jobs(self, status: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"doc_type": "job"}
        if status:
            query["status"] = status
        return self.store.query(C.SYNC_STATE, query, sort=[("requested_at", -1)], limit=limit)

    def next_queued(self) -> Optional[Dict[str, Any]]:
        rows = self.store.query(C.SYNC_STATE, {"doc_type": "job", "status": "queued"},
                                sort=[("requested_at", 1)], limit=1)
        return rows[0] if rows else None

    def prune(self) -> int:
        rows = self.store.query(C.SYNC_STATE, {"doc_type": "job"}, sort=[("requested_at", -1)],
                                skip=self.JOB_RETENTION, fields=["_key"])
        for row in rows:
            self.store.delete(C.SYNC_STATE, row["_key"])
        return len(rows)

"""Re-derive ``uc_catalog`` summaries from stored raw records (no network).

Used after an app upgrade ships a newer normalizer on stacks without egress.
"""

from typing import Any, Dict, Optional

from ..catalog.detail import _category_from_doc
from ..catalog.summary import catalog_summary
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..storage.repositories import CategoryRepository, ContentRepository, decode_raw
from .provider import ProviderManifest, ProviderRecord
from .registry import normalizer_for


class ReindexService:
    def __init__(self, store: DocumentStore, batch: int = 200):
        self.store = store
        self.content = ContentRepository(store)
        self.categories = CategoryRepository(store)
        self.batch = batch

    def reindex(self, category_key: Optional[str] = None) -> Dict[str, Any]:
        cat_cache: Dict[str, Any] = {}
        pending = []
        counts = {"reindexed": 0, "skipped": 0}
        for stored in self.content.iter_content(category_key):
            prov = stored.get("provenance") or {}
            raw = decode_raw(stored)
            if raw is None or not prov:
                counts["skipped"] += 1
                continue
            ckey = stored.get("category_key", "")
            if ckey not in cat_cache:
                cat_cache[ckey] = _category_from_doc(self.categories.get(ckey) or {"_key": ckey})
            normalizer = normalizer_for(stored.get("provider", ""))
            manifest = ProviderManifest(
                provider=prov.get("provider", ""), provider_version=prov.get("provider_version", ""),
                source_ref=prov.get("source_ref", ""), requested_ref="", schema=None,
                schema_version=str(prov.get("source_schema", "")).split("@")[-1], categories=[],
                retrieved_at="")
            record = ProviderRecord(
                provider=prov.get("provider", ""), record_id=prov.get("provider_record_id", ""),
                category_id=cat_cache[ckey].category_id, path=prov.get("source_path", ""), raw=raw,
                raw_size=int(stored.get("raw_size") or 0), blob_sha=prov.get("source_blob_sha", ""),
                source_url=prov.get("source_url", ""))
            uc = normalizer.normalize(record, cat_cache[ckey], manifest, prov.get("imported_at", ""))
            summary = catalog_summary(uc)
            previous = self.content.get_catalog(uc.key) or {}
            summary["provider_status"] = previous.get("provider_status", summary["provider_status"])
            pending.append(summary)
            if len(pending) >= self.batch:
                self.store.batch_save(C.CATALOG, pending)
                counts["reindexed"] += len(pending)
                pending = []
        if pending:
            self.store.batch_save(C.CATALOG, pending)
            counts["reindexed"] += len(pending)
        return counts

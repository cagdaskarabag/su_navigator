"""Offline bundle import: same validation/normalization path as remote sync."""

import json
from typing import Any, Dict, Optional

from ..errors import ValidationError
from .registry import bundle_provider
from .sync import SyncService, new_job


class BundleImportService:
    def __init__(self, sync: SyncService, max_bytes: int):
        self.sync = sync
        self.max_bytes = max_bytes

    def import_bytes(self, payload: bytes, requested_by: str, allow_schema_change: bool = False,
                     categories: Optional[list] = None) -> Dict[str, Any]:
        if len(payload) > self.max_bytes:
            raise ValidationError("bundle exceeds size limit", {"limit_bytes": self.max_bytes})
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ValidationError("bundle is not valid UTF-8 JSON")
        return self.import_bundle(data, requested_by, allow_schema_change, categories)

    def import_bundle(self, data: Any, requested_by: str, allow_schema_change: bool = False,
                      categories: Optional[list] = None) -> Dict[str, Any]:
        provider = bundle_provider(data)
        bundle_cats = [c["category_id"] for c in data["categories"]]
        selected = [c for c in (categories or bundle_cats) if c in bundle_cats]
        if not selected:
            raise ValidationError("none of the requested categories are in the bundle")
        job = new_job(requested_by, provider.provider_id, selected, ref=str(data.get("source_ref", "")),
                      source="offline_bundle", allow_schema_change=allow_schema_change)
        # Runs inline; never visible to the background worker as "queued".
        job["status"] = "running"
        self.sync.enqueue(job)
        return self.sync.run(job, provider)

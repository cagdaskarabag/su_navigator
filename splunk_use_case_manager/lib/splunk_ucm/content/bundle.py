"""Offline content bundles (``ucm-content-bundle`` v1).

A bundle carries raw provider files *as text* so their git blob SHA can be
re-verified on import — integrity is tied to the upstream repository, not to
whoever transported the bundle::

    {
      "format": "ucm-content-bundle", "format_version": 1,
      "provider": "fenre", "provider_version": "8.28.0",
      "source_ref": "<commit sha or 'local:<sha256>'>", "created_at": "...",
      "schema": {...} | null,
      "categories": [{"category_id": "1", "slug": "cat-01-...", "path": "content/cat-01-...",
                      "metadata": {...}}],
      "records": [{"category_id": "1", "record_id": "1.1.1", "path": "...", "blob_sha": "...",
                   "content": "<raw JSON text>"}]
    }
"""

import hashlib
import json
import re
from typing import Any, Dict, List

from ..errors import IntegrityError, NotFoundError, ValidationError
from ..util import git_blob_sha, utc_now_iso
from .provider import (ContentProvider, Normalizer, ProviderCategory, ProviderManifest,
                       ProviderRecord, RecordListing)
from .validation import RecordValidator

BUNDLE_FORMAT = "ucm-content-bundle"
BUNDLE_VERSION = 1
MAX_BUNDLE_RECORDS = 25000


def _require(cond: bool, message: str, **details: Any) -> None:
    if not cond:
        raise ValidationError(message, details or None)


def parse_bundle(data: Any, max_records: int = MAX_BUNDLE_RECORDS) -> Dict[str, Any]:
    """Structurally validate a decoded bundle. Record content is validated later."""
    _require(isinstance(data, dict), "bundle must be a JSON object")
    _require(data.get("format") == BUNDLE_FORMAT, "unsupported bundle format")
    _require(data.get("format_version") == BUNDLE_VERSION, "unsupported bundle format_version")
    _require(isinstance(data.get("provider"), str) and re.match(r"^[a-z][a-z0-9_]{1,31}$", data["provider"]),
             "invalid provider id")
    cats = data.get("categories")
    recs = data.get("records")
    _require(isinstance(cats, list) and cats, "bundle has no categories")
    _require(isinstance(recs, list), "bundle has no records list")
    _require(len(recs) <= max_records, "bundle exceeds record limit", limit=max_records)
    cat_ids = set()
    for cat in cats:
        _require(isinstance(cat, dict) and isinstance(cat.get("category_id"), str)
                 and isinstance(cat.get("path"), str), "invalid category entry")
        cat_ids.add(cat["category_id"])
    for rec in recs:
        _require(isinstance(rec, dict), "invalid record entry")
        for field in ("category_id", "record_id", "path", "blob_sha", "content"):
            _require(isinstance(rec.get(field), str), "record entry missing %s" % field,
                     record_id=str(rec.get("record_id")))
        _require(rec["category_id"] in cat_ids, "record references unknown category",
                 record_id=rec["record_id"])
    if data.get("schema") is not None:
        _require(isinstance(data["schema"], dict), "schema must be an object")
    return data


class OfflineBundleProvider(ContentProvider):
    """Serves an imported bundle through the standard provider interface."""

    def __init__(self, bundle: Dict[str, Any], normalizer: Normalizer, validator_factory,
                 verify_blob_sha: bool = True):
        self.bundle = parse_bundle(bundle)
        self.provider_id = self.bundle["provider"]
        self._normalizer = normalizer
        self._validator_factory = validator_factory
        self.verify_blob_sha = verify_blob_sha
        self._by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for rec in self.bundle["records"]:
            self._by_cat.setdefault(rec["category_id"], []).append(rec)

    def _category_token(self, category_id: str) -> str:
        h = hashlib.sha256()
        for rec in sorted(self._by_cat.get(category_id, []), key=lambda r: r["path"]):
            h.update(("%s\0%s\n" % (rec["path"], rec["blob_sha"])).encode("utf-8"))
        return "bundle:" + h.hexdigest()

    def get_manifest(self) -> ProviderManifest:
        cats = []
        for cat in self.bundle["categories"]:
            meta = cat.get("metadata") if isinstance(cat.get("metadata"), dict) else {}
            name = meta.get("name") if isinstance(meta.get("name"), str) else cat.get("slug", cat["category_id"])
            count = meta.get("useCaseCount")
            cats.append(ProviderCategory(category_id=cat["category_id"], name=name,
                                         slug=str(cat.get("slug", "")), path=cat["path"],
                                         tree_sha=self._category_token(cat["category_id"]),
                                         metadata=meta, upstream_count=count if isinstance(count, int) else None))
        schema = self.bundle.get("schema")
        return ProviderManifest(
            provider=self.provider_id, provider_version=str(self.bundle.get("provider_version") or "unknown"),
            source_ref=str(self.bundle.get("source_ref") or "bundle"), requested_ref="offline-bundle",
            schema=schema, schema_version=str((schema or {}).get("version", "unknown")),
            categories=cats, retrieved_at=utc_now_iso(),
            warnings=[] if schema else ["bundle carries no schema; using provider default"],
            partial=self.bundle.get("partial") is True)

    def list_records(self, manifest, category):
        return [RecordListing(record_id=r["record_id"], path=r["path"], blob_sha=r["blob_sha"],
                              size=len(r["content"].encode("utf-8")))
                for r in self._by_cat.get(category.category_id, [])]

    def fetch_record(self, manifest, category, listing):
        rec = next((r for r in self._by_cat.get(category.category_id, []) if r["path"] == listing.path), None)
        if rec is None:
            raise NotFoundError("record not in bundle", {"path": listing.path})
        body = rec["content"].encode("utf-8")
        if self.verify_blob_sha and git_blob_sha(body) != rec["blob_sha"]:
            raise IntegrityError("blob hash mismatch in bundle", {"path": listing.path})
        try:
            raw = json.loads(rec["content"])
        except ValueError as exc:
            raise IntegrityError("record is not valid JSON", {"path": listing.path}) from exc
        return ProviderRecord(provider=self.provider_id, record_id=listing.record_id,
                              category_id=category.category_id, path=listing.path, raw=raw,
                              raw_size=len(body), blob_sha=rec["blob_sha"],
                              source_url="bundle:%s:%s" % (manifest.source_ref, listing.path))

    def get_use_case(self, manifest, record_id):
        for cat in manifest.categories:
            for listing in self.list_records(manifest, cat):
                if listing.record_id == record_id:
                    return self.fetch_record(manifest, cat, listing)
        raise NotFoundError("record not found", {"record_id": record_id})

    def normalizer(self):
        return self._normalizer

    def validator(self, manifest) -> RecordValidator:
        return self._validator_factory(manifest)

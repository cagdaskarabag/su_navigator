"""Use-case detail: canonical view derived on read from the stored raw record.

See docs/DECISIONS.md D-008. Derivation is deterministic, so the detail shown
matches what was summarised into ``uc_catalog`` at import time unless the
normalizer has since been upgraded (reported as ``normalized_with``).
"""

import re
from typing import Any, Dict, List

from ..content.provider import ProviderManifest, ProviderRecord
from ..content.registry import normalizer_for
from ..errors import NotFoundError, ValidationError
from ..model.canonical import Category
from ..storage.repositories import CategoryRepository, ContentRepository, decode_raw

_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_CONTENT_ID_RE = re.compile(r"^([a-z][a-z0-9_]{1,31}):(UC-[0-9.]{1,40})$")


def key_from_id(value: str) -> str:
    """Accept a storage key (``fenre_UC-1.1.1``) or a content id (``fenre:UC-1.1.1``)."""
    match = _CONTENT_ID_RE.match(value or "")
    if match:
        return "%s_%s" % (match.group(1), match.group(2))
    if _KEY_RE.match(value or ""):
        return value
    raise ValidationError("invalid use case id")


def _category_from_doc(doc: Dict[str, Any]) -> Category:
    return Category(key=doc.get("_key", ""), provider=doc.get("provider", ""),
                    category_id=str(doc.get("category_id", "")), name=doc.get("name", ""),
                    slug=doc.get("slug", ""), description=doc.get("description", ""),
                    domains=list(doc.get("domains") or []), subcategories=list(doc.get("subcategories") or []),
                    upstream_count=doc.get("upstream_count"), tree_sha=doc.get("tree_sha", ""))


class UseCaseDetailService:
    def __init__(self, content: ContentRepository, categories: CategoryRepository):
        self.content = content
        self.categories = categories

    def get(self, use_case_id: str) -> Dict[str, Any]:
        key = key_from_id(use_case_id)
        stored = self.content.get_content(key)
        catalog = self.content.get_catalog(key)
        if not stored or not catalog:
            raise NotFoundError("use case not found", {"id": use_case_id})
        raw = decode_raw(stored)
        if raw is None:
            raise NotFoundError("stored content for this use case is missing or unreadable",
                                {"key": key})
        prov = stored.get("provenance") or {}
        cat_doc = self.categories.get(stored.get("category_key", "")) or {"_key": stored.get("category_key", "")}
        normalizer = normalizer_for(stored.get("provider", ""))
        manifest = ProviderManifest(
            provider=prov.get("provider", ""), provider_version=prov.get("provider_version", ""),
            source_ref=prov.get("source_ref", ""), requested_ref="", schema=None,
            schema_version=str(prov.get("source_schema", "")).split("@")[-1], categories=[],
            retrieved_at="")
        record = ProviderRecord(
            provider=prov.get("provider", ""), record_id=prov.get("provider_record_id", ""),
            category_id=str(cat_doc.get("category_id", "")), path=prov.get("source_path", ""),
            raw=raw, raw_size=int(stored.get("raw_size") or 0),
            blob_sha=prov.get("source_blob_sha", ""), source_url=prov.get("source_url", ""))
        uc = normalizer.normalize(record, _category_from_doc(cat_doc), manifest, prov.get("imported_at", ""))
        out = uc.to_dict()
        out["provider_status"] = catalog.get("provider_status")
        out["normalized_with"] = normalizer.version
        out["stored_normalizer_version"] = stored.get("normalizer_version")
        out["validation_warnings"] = stored.get("validation_warnings") or []
        out["validation_warning_count"] = stored.get("validation_warning_count", 0)
        out["requirement_summary"] = self._requirement_summary(out["requirements"])
        return out

    @staticmethod
    def _requirement_summary(reqs: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_level: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for r in reqs:
            by_level[r["level"]] = by_level.get(r["level"], 0) + 1
            by_source[r["source"]] = by_source.get(r["source"], 0) + 1
        return {"total": len(reqs), "by_level": by_level, "by_source": by_source,
                "assessment": "not_assessed"}

"""Content provider over extractions staged in an import session.

The provider never touches the network: retrieval happened earlier, in the
background worker, and the user reviewed the result. Its manifest is always
``partial`` so importing a few articles never withdraws other Lantern content.
"""

from typing import Any, Dict, List

from ...storage.repositories import encode_raw
from ...util import utc_now_iso
from ..provider import (ContentProvider, Normalizer, ProviderCategory, ProviderManifest, ProviderRecord,
                        RecordListing)
from ..validation import RecordValidator
from .normalizer import (PROVIDER, LanternNormalizer, lantern_validation_policy, section_name,
                         section_segment, section_slug)
from .parser import EXTRACTION_VERSION
from .urls import path_of

SCHEMA_VERSION = "1.0"


class StagedLanternProvider(ContentProvider):
    provider_id = PROVIDER

    def __init__(self, raws: List[Dict[str, Any]], session_id: str):
        self._raws = list(raws)
        self._session_id = session_id
        self._by_id = {r["id"]: r for r in self._raws}

    def get_manifest(self) -> ProviderManifest:
        categories: Dict[str, ProviderCategory] = {}
        for raw in self._raws:
            slug = section_slug(raw)
            if slug not in categories:
                categories[slug] = ProviderCategory(
                    category_id=slug, name=section_name(raw), slug=slug, path="", tree_sha="",
                    metadata={"segment": section_segment(raw),
                              "description": "Articles imported from the Splunk Lantern section '%s'."
                                             % section_name(raw)})
        return ProviderManifest(provider=PROVIDER, provider_version=EXTRACTION_VERSION,
                                source_ref="session:" + self._session_id, requested_ref="",
                                schema=None, schema_version=SCHEMA_VERSION,
                                categories=list(categories.values()), retrieved_at=utc_now_iso(),
                                partial=True)

    def list_records(self, manifest: ProviderManifest, category: ProviderCategory) -> List[RecordListing]:
        return [RecordListing(record_id=r["id"], path=path_of(r["source_url"]), blob_sha=r["content_hash"],
                              size=len(encode_raw(r)))
                for r in self._raws if section_slug(r) == category.category_id]

    def _record(self, raw: Dict[str, Any]) -> ProviderRecord:
        return ProviderRecord(provider=PROVIDER, record_id=raw["id"], category_id=section_slug(raw),
                              path=path_of(raw["source_url"]), raw=raw, raw_size=len(encode_raw(raw)),
                              blob_sha=raw["content_hash"], source_url=raw["source_url"])

    def fetch_record(self, manifest: ProviderManifest, category: ProviderCategory,
                     listing: RecordListing) -> ProviderRecord:
        return self._record(self._by_id[listing.record_id])

    def get_use_case(self, manifest: ProviderManifest, record_id: str) -> ProviderRecord:
        return self._record(self._by_id[record_id])

    def normalizer(self) -> Normalizer:
        return LanternNormalizer()

    def validator(self, manifest: ProviderManifest) -> RecordValidator:
        return RecordValidator(lantern_validation_policy())

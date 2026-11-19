"""Content-provider abstraction.

A provider delivers *raw* records plus provenance. It never writes storage and
never returns canonical objects directly; normalization is a separate,
versioned step owned by the provider's ``Normalizer``.
"""

import abc
import dataclasses
from typing import Any, Dict, Iterator, List, Optional

from ..model.canonical import Category, UseCase
from .validation import RecordValidator


@dataclasses.dataclass
class ProviderCategory:
    category_id: str  # provider-native id, e.g. "1"
    name: str
    slug: str
    path: str
    tree_sha: str = ""  # change token; empty when the provider has none
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    upstream_count: Optional[int] = None


@dataclasses.dataclass
class ProviderManifest:
    provider: str
    provider_version: str
    source_ref: str  # immutable reference (commit SHA, bundle hash)
    requested_ref: str
    schema: Optional[Dict[str, Any]]
    schema_version: str
    categories: List[ProviderCategory]
    retrieved_at: str
    warnings: List[str] = dataclasses.field(default_factory=list)
    # A partial listing (e.g. a record-subset bundle) must never withdraw unlisted records.
    partial: bool = False

    def category(self, category_id: str) -> Optional[ProviderCategory]:
        for cat in self.categories:
            if cat.category_id == str(category_id):
                return cat
        return None

    def summary(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "provider_version": self.provider_version,
            "source_ref": self.source_ref,
            "requested_ref": self.requested_ref,
            "schema_version": self.schema_version,
            "retrieved_at": self.retrieved_at,
            "warnings": list(self.warnings),
            "partial": self.partial,
            "categories": [
                {"category_id": c.category_id, "name": c.name, "slug": c.slug,
                 "tree_sha": c.tree_sha, "upstream_count": c.upstream_count,
                 "description": c.metadata.get("description", "")}
                for c in self.categories
            ],
        }


@dataclasses.dataclass
class RecordListing:
    record_id: str
    path: str
    blob_sha: str  # change token for this record ("" when unknown)
    size: Optional[int] = None


@dataclasses.dataclass
class ProviderRecord:
    provider: str
    record_id: str
    category_id: str
    path: str
    raw: Dict[str, Any]
    raw_size: int
    blob_sha: str
    source_url: str


class Normalizer(abc.ABC):
    """Maps one provider's raw records to the canonical model."""

    version: str = "0"

    @abc.abstractmethod
    def normalize(self, record: ProviderRecord, category: Category,
                  manifest: ProviderManifest, imported_at: str) -> UseCase:
        """Return the canonical use case. Must be deterministic."""

    @abc.abstractmethod
    def normalize_category(self, category: ProviderCategory, provider: str) -> Category:
        """Return canonical category metadata."""

    @abc.abstractmethod
    def content_key(self, record_id: str) -> str:
        """Stable storage key for a provider-native record id."""


class ContentProvider(abc.ABC):
    """Source of use-case content.

    Implementations must treat all remote data as untrusted and must not
    execute or interpret SPL.
    """

    provider_id: str = ""

    @abc.abstractmethod
    def get_manifest(self) -> ProviderManifest:
        """Resolve version/ref and return category metadata with change tokens."""

    def list_categories(self) -> List[ProviderCategory]:
        return self.get_manifest().categories

    def get_provider_version(self) -> str:
        return self.get_manifest().provider_version

    @abc.abstractmethod
    def list_records(self, manifest: ProviderManifest,
                     category: ProviderCategory) -> List[RecordListing]:
        """List records in a category with their change tokens."""

    @abc.abstractmethod
    def fetch_record(self, manifest: ProviderManifest, category: ProviderCategory,
                     listing: RecordListing) -> ProviderRecord:
        """Fetch and integrity-check one raw record."""

    def list_use_cases(self, manifest: ProviderManifest,
                       category_ids: Optional[List[str]] = None) -> Iterator[RecordListing]:
        for cat in manifest.categories:
            if category_ids is None or cat.category_id in category_ids:
                for listing in self.list_records(manifest, cat):
                    yield listing

    @abc.abstractmethod
    def get_use_case(self, manifest: ProviderManifest, record_id: str) -> ProviderRecord:
        """Fetch a single record by provider-native id."""

    @abc.abstractmethod
    def normalizer(self) -> Normalizer:
        """Return the normalizer for this provider's records."""

    @abc.abstractmethod
    def validator(self, manifest: ProviderManifest) -> RecordValidator:
        """Return a validator bound to the schema of ``manifest``."""

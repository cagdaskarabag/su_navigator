"""In-memory view of the discovered environment used by all evaluators.

Loaded once per assessment job so evaluating thousands of use cases does not
issue a KV Store query per requirement.
"""

from typing import Any, Dict, List, Optional, Sequence

from .principal import PrincipalAccess

from ..discovery.repositories import DiscoveryStateRepository
from ..storage import collections as C
from ..storage.kvstore import DocumentStore


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


class EnvironmentSnapshot:
    def __init__(self, sources: List[Dict[str, Any]], mappings: List[Dict[str, Any]],
                 discovery_state: Dict[str, Any], validations: Optional[List[Dict[str, Any]]] = None,
                 profiles: Optional[List[Dict[str, Any]]] = None):
        self.discovery = discovery_state or {}
        self.principal: Optional[PrincipalAccess] = None
        self.validations: Dict[str, Dict[str, Any]] = {}
        for v in validations or []:
            cid = v.get("content_id") or v.get("_key")
            if cid:
                self.validations[cid] = v
                if v.get("_key"):
                    self.validations[v["_key"]] = v
        self.pairs_active: Dict[str, List[Dict[str, Any]]] = {}
        self.pairs_missing: Dict[str, List[Dict[str, Any]]] = {}
        self.indexes: Dict[str, Dict[str, Any]] = {}
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.app_labels: Dict[str, Dict[str, Any]] = {}
        self.app_packages: Dict[str, Dict[str, Any]] = {}
        self.datamodels: Dict[str, Dict[str, Any]] = {}
        self.objects: Dict[str, Dict[str, List[Dict[str, Any]]]] = {"macro": {}, "lookup": {}, "eventtype": {}}
        for doc in sources:
            kind = doc.get("kind")
            active = doc.get("status") == "active"
            if kind == "pair":
                target = self.pairs_active if active else self.pairs_missing
                target.setdefault(_lower(doc.get("sourcetype")), []).append(doc)
            elif kind == "index":
                self.indexes[_lower(doc.get("name"))] = doc
            elif kind == "app" and active:
                self.apps[_lower(doc.get("name"))] = doc
                if doc.get("label"):
                    self.app_labels[_lower(doc.get("label"))] = doc
                if doc.get("package_id"):
                    self.app_packages[_lower(doc.get("package_id"))] = doc
            elif kind == "datamodel" and active:
                self.datamodels[_lower(doc.get("name"))] = doc
            elif kind in self.objects and active:
                self.objects[kind].setdefault(_lower(doc.get("name")), []).append(doc)
        self.profiles: Dict[str, List[Dict[str, Any]]] = {}
        for p in profiles or []:
            self.profiles.setdefault(_lower(p.get("field")), []).append(p)
        self.mapped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for m in mappings:
            by_kind = self.mapped.setdefault(m.get("kind", ""), {})
            by_kind.setdefault(_lower(m.get("canonical_value")), []).append(m)

    @classmethod
    def load(cls, store: DocumentStore) -> "EnvironmentSnapshot":
        sources = store.query(C.ENVIRONMENT_SOURCES)
        mappings = store.query(C.SOURCE_MAPPINGS)
        validations = store.query(C.VALIDATION, fields=[
            "_key", "content_id", "parse_ok", "parse_error", "side_effects", "review_commands", "commands",
            "field_samples", "sampled_at", "source_hash", "cim_parse_ok", "access_scan"])
        profiles = store.query(C.FIELD_PROFILE, fields=["index", "sourcetype", "field", "sample_size", "fill_rate",
                                                         "placeholder_rate"], limit=50000)
        return cls(sources, mappings, DiscoveryStateRepository(store).state(), validations, profiles)

    def field_profiles(self, field: str, sourcetypes: Sequence[str]) -> List[Dict[str, Any]]:
        """Stored profiles of ``field`` in the sourcetypes the use case reads (all sourcetypes if it names none)."""
        rows = self.profiles.get(_lower(field), [])
        if sourcetypes:
            wanted = {_lower(s) for s in sourcetypes}
            narrowed = [r for r in rows if _lower(r.get("sourcetype")) in wanted]
            if narrowed:
                return narrowed
        return rows

    @property
    def discovered(self) -> bool:
        return bool(self.discovery.get("last_completed_at"))

    @property
    def include_internal(self) -> bool:
        return bool(self.discovery.get("include_internal"))

    @property
    def discovered_at(self) -> str:
        return str(self.discovery.get("last_completed_at") or "")

    @property
    def splunk_version(self) -> str:
        return str(self.discovery.get("splunk_version") or "")

    def all_pair_sourcetypes(self) -> List[str]:
        return list(self.pairs_active.keys())

    def aliases(self, kind: str, value: str) -> List[Dict[str, Any]]:
        """Mappings whose canonical value is ``value``; local mappings first."""
        rows = list(self.mapped.get(kind, {}).get(_lower(value), []))
        rows.sort(key=lambda m: 0 if m.get("origin") == "local" else 1)
        return rows

    def object(self, kind: str, name: str) -> List[Dict[str, Any]]:
        return list(self.objects.get(kind, {}).get(_lower(name), []))

    def app(self, name: str) -> Optional[Dict[str, Any]]:
        key = _lower(name)
        return self.apps.get(key) or self.app_packages.get(key) or self.app_labels.get(key)

    def validation(self, content_id: str, key: str = "") -> Optional[Dict[str, Any]]:
        return self.validations.get(content_id) or self.validations.get(key)

    def field_sample(self, content_id: str, field: str, key: str = "") -> Optional[Dict[str, Any]]:
        doc = self.validation(content_id, key)
        if not doc:
            return None
        want = _lower(field)
        for row in doc.get("field_samples") or []:
            if _lower(row.get("field")) == want:
                return row
        return None

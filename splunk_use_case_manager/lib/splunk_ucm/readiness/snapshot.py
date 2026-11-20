"""In-memory view of the discovered environment used by all evaluators.

Loaded once per assessment job so evaluating thousands of use cases does not
issue a KV Store query per requirement.
"""

from typing import Any, Dict, List, Optional

from ..discovery.repositories import DiscoveryStateRepository
from ..storage import collections as C
from ..storage.kvstore import DocumentStore


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


class EnvironmentSnapshot:
    def __init__(self, sources: List[Dict[str, Any]], mappings: List[Dict[str, Any]],
                 discovery_state: Dict[str, Any]):
        self.discovery = discovery_state or {}
        self.pairs_active: Dict[str, List[Dict[str, Any]]] = {}
        self.pairs_missing: Dict[str, List[Dict[str, Any]]] = {}
        self.indexes: Dict[str, Dict[str, Any]] = {}
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.app_labels: Dict[str, Dict[str, Any]] = {}
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
            elif kind == "datamodel" and active:
                self.datamodels[_lower(doc.get("name"))] = doc
            elif kind in self.objects and active:
                self.objects[kind].setdefault(_lower(doc.get("name")), []).append(doc)
        self.mapped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for m in mappings:
            by_kind = self.mapped.setdefault(m.get("kind", ""), {})
            by_kind.setdefault(_lower(m.get("canonical_value")), []).append(m)

    @classmethod
    def load(cls, store: DocumentStore) -> "EnvironmentSnapshot":
        sources = store.query(C.ENVIRONMENT_SOURCES)
        mappings = store.query(C.SOURCE_MAPPINGS)
        return cls(sources, mappings, DiscoveryStateRepository(store).state())

    @property
    def discovered(self) -> bool:
        return bool(self.discovery.get("last_completed_at"))

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
        return self.apps.get(key) or self.app_labels.get(key)

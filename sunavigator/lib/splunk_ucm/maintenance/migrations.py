"""Versioned, idempotent migrations of app state in KV Store (D-033).

The applied set lives in ``uc_sync_state`` under ``app::state``. A migration
is re-checked before it runs, so a partially applied one is simply resumed on
the next worker run.
"""

from typing import Any, Callable, Dict, List, Tuple

from .. import __version__
from ..catalog.derived import FACETS_KEY, compute_facets, facets_outdated, refresh_derived, scan_catalog
from ..content.fenre.normalizer import NORMALIZER_VERSION
from ..content.reindex import ReindexService
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso

STATE_KEY = "app::state"
STATE_SCHEMA = 1
# Summary version that migration 0001 brings a catalogue to. It is pinned: SUMMARY_VERSION 6 (0.9.0)
# is filled by the Reindex action, not by a migration (D-066).
MIGRATED_SUMMARY_VERSION = 5


def _outdated_summaries(store: DocumentStore) -> int:
    return store.count(C.CATALOG) - store.count(C.CATALOG, {"summary_version": {"$gte": MIGRATED_SUMMARY_VERSION}})


def _reindex_summaries(store: DocumentStore) -> Dict[str, Any]:
    return ReindexService(store).reindex()


def _outdated_normalizer(store: DocumentStore) -> int:
    return store.count(C.CATALOG) - store.count(C.CATALOG, {"normalizer_version": NORMALIZER_VERSION})


def _store_facets(store: DocumentStore) -> Dict[str, Any]:
    facets = compute_facets(scan_catalog(store))
    facets.update({"_key": FACETS_KEY, "doc_type": "catalog_facets", "computed_at": utc_now_iso()})
    store.upsert(C.SYNC_STATE, facets)
    return {"facets_version": facets["facets_version"], "summaries_outdated": facets["summary"]["outdated"]}


# (id, needed(store) -> bool, apply(store) -> details). Never reorder or remove entries.
MIGRATIONS: List[Tuple[str, Callable[[DocumentStore], bool], Callable[[DocumentStore], Dict[str, Any]]]] = [
    ("0001_catalog_summary_v%d" % MIGRATED_SUMMARY_VERSION, lambda s: _outdated_summaries(s) > 0, _reindex_summaries),
    # Derived-field requirements (D-040); readiness re-normalizes on its next run.
    ("0002_normalizer_%s" % NORMALIZER_VERSION, lambda s: _outdated_normalizer(s) > 0, _reindex_summaries),
    # Catalogue facet counts per domain, category, criticality and difficulty (D-059).
    ("0003_catalog_facets_v2", lambda s: facets_outdated(s) and s.count(C.CATALOG) > 0, refresh_derived),
    # Facet counts for providers, waves, stories and data sources (D-066). Stores the facets document
    # only; no catalogue summary is written, so the new filters stay empty until Reindex runs.
    ("0004_catalog_facets_v3", lambda s: facets_outdated(s) and s.count(C.CATALOG) > 0, _store_facets),
    # Data maturity counts (D-074). Like 0004: the facets only; the filter fills after Reindex.
    ("0005_catalog_facets_v4", lambda s: facets_outdated(s) and s.count(C.CATALOG) > 0, _store_facets),
    # Records written by an older provider normalizer (D-080). Only the facets; the records themselves need a re-import.
    ("0006_catalog_facets_v5", lambda s: facets_outdated(s) and s.count(C.CATALOG) > 0, _store_facets),
]


class MigrationRunner:
    def __init__(self, store: DocumentStore, clock: Callable[[], str] = utc_now_iso):
        self.store = store
        self.clock = clock

    def state(self) -> Dict[str, Any]:
        return self.store.get(C.SYNC_STATE, STATE_KEY) or {
            "_key": STATE_KEY, "doc_type": "app_state", "state_schema": STATE_SCHEMA, "applied": []}

    def pending(self) -> List[str]:
        applied = set(self.state().get("applied") or [])
        return [mid for mid, _, _ in MIGRATIONS if mid not in applied]

    def outdated(self) -> bool:
        return bool(self.pending()) or self.state().get("app_version") != __version__

    def run(self) -> List[Dict[str, Any]]:
        state = self.state()
        applied = list(state.get("applied") or [])
        results = []
        for mid, needed, apply in MIGRATIONS:
            if mid in applied:
                continue
            details = apply(self.store) if needed(self.store) else {"not_needed": True}
            applied.append(mid)
            results.append({"id": mid, "details": details})
            state.update({"applied": applied, "last_migration": mid, "last_migration_at": self.clock()})
            self._save(state)
        if state.get("app_version") != __version__:
            state.update({"previous_app_version": state.get("app_version", ""), "app_version": __version__,
                          "upgraded_at": self.clock()})
            self._save(state)
        return results

    def _save(self, state: Dict[str, Any]) -> None:
        state.update({"_key": STATE_KEY, "doc_type": "app_state", "state_schema": STATE_SCHEMA})
        self.store.upsert(C.SYNC_STATE, state)

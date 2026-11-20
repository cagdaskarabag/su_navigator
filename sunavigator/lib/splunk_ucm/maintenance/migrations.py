"""Versioned, idempotent migrations of app state in KV Store (D-033).

The applied set lives in ``uc_sync_state`` under ``app::state``. A migration
is re-checked before it runs, so a partially applied one is simply resumed on
the next worker run.
"""

from typing import Any, Callable, Dict, List, Tuple

from .. import __version__
from ..catalog.summary import SUMMARY_VERSION
from ..content.reindex import ReindexService
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso

STATE_KEY = "app::state"
STATE_SCHEMA = 1


def _outdated_summaries(store: DocumentStore) -> int:
    return store.count(C.CATALOG) - store.count(C.CATALOG, {"summary_version": {"$gte": SUMMARY_VERSION}})


def _reindex_summaries(store: DocumentStore) -> Dict[str, Any]:
    return ReindexService(store).reindex()


# (id, needed(store) -> bool, apply(store) -> details). Never reorder or remove entries.
MIGRATIONS: List[Tuple[str, Callable[[DocumentStore], bool], Callable[[DocumentStore], Dict[str, Any]]]] = [
    ("0001_catalog_summary_v%d" % SUMMARY_VERSION, lambda s: _outdated_summaries(s) > 0, _reindex_summaries),
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

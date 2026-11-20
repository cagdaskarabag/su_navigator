"""Source-mapping registry.

Local (administrator) mappings are never overwritten by auto-discovery
(docs/DECISIONS.md D-022). Auto mappings are exact or heuristic matches of
discovered values against the imported catalogue; they are labelled
``medium`` / ``low`` confidence and are not evidence of readiness.
"""

from typing import Any, Dict, List, Optional

from ..errors import NotFoundError, ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso
from .keys import mapping_key
from .repositories import MappingRepository

KINDS = ("sourcetype", "index", "datamodel", "addon")
ORIGINS = ("local", "auto_exact", "auto_heuristic")
CONFIDENCE = {"local": "high", "auto_exact": "medium", "auto_heuristic": "low"}
CANONICAL_TYPE = {
    "sourcetype": "sourcetype", "index": "index", "datamodel": "cim_model", "addon": "addon",
}


class MappingService:
    def __init__(self, store: DocumentStore):
        self.store = store
        self.repo = MappingRepository(store)

    def get(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        _check_kind(kind)
        return self.repo.get(kind, value)

    def upsert_local(self, kind: str, value: str, canonical_value: str, actor: str,
                     notes: str = "", confidence: str = "high") -> Dict[str, Any]:
        _check_kind(kind)
        value = _value(value)
        canonical_value = _value(canonical_value or value)
        if confidence not in ("high", "medium", "low"):
            raise ValidationError("invalid confidence")
        if len(notes) > 500:
            raise ValidationError("notes too long")
        existing = self.repo.get(kind, value)
        doc = existing or {}
        doc.update({
            "_key": mapping_key(kind, value), "doc_schema": 1, "kind": kind, "value": value,
            "canonical_type": CANONICAL_TYPE[kind], "canonical_value": canonical_value,
            "origin": "local", "confidence": confidence, "notes": notes,
            "updated_by": actor, "updated_at": utc_now_iso(),
            "catalog_count": self._catalog_count(kind, canonical_value),
        })
        self.repo.save(doc)
        return doc

    def delete_local(self, kind: str, value: str, actor: str) -> None:
        _check_kind(kind)
        existing = self.repo.get(kind, value)
        if existing is None:
            raise NotFoundError("mapping not found")
        if existing.get("origin") != "local":
            raise ValidationError("only local mappings can be deleted; create a local override instead")
        self.repo.delete(existing["_key"])

    def apply_auto(self, kind: str, discovered_values: List[str]) -> Dict[str, int]:
        _check_kind(kind)
        catalog_values = self._catalog_values(kind)
        lower = {v.lower(): v for v in catalog_values}
        added = updated = skipped = 0
        for raw in discovered_values:
            if not raw:
                continue
            exact = raw in catalog_values
            heuristic = (not exact) and raw.lower() in lower
            if not exact and not heuristic:
                continue
            origin = "auto_exact" if exact else "auto_heuristic"
            canonical = raw if exact else lower[raw.lower()]
            existing = self.repo.get(kind, raw)
            if existing and existing.get("origin") == "local":
                skipped += 1
                continue
            doc = {
                "_key": mapping_key(kind, raw), "doc_schema": 1, "kind": kind, "value": raw,
                "canonical_type": CANONICAL_TYPE[kind], "canonical_value": canonical,
                "origin": origin, "confidence": CONFIDENCE[origin], "notes": "",
                "updated_by": "discovery", "updated_at": utc_now_iso(),
                "catalog_count": self._catalog_count(kind, canonical),
            }
            self.repo.save(doc)
            if existing:
                updated += 1
            else:
                added += 1
        return {"added": added, "updated": updated, "skipped_local": skipped}

    def _catalog_values(self, kind: str) -> set:
        field = {"sourcetype": "sourcetypes", "index": "indexes", "datamodel": "datamodels",
                 "addon": "addons"}[kind]
        values = set()
        for row in self.store.query(C.CATALOG, {"provider_status": "active"}, fields=[field]):
            for item in row.get(field) or []:
                if isinstance(item, str) and item:
                    values.add(item)
        return values

    def _catalog_count(self, kind: str, value: str) -> int:
        field = {"sourcetype": "sourcetypes", "index": "indexes", "datamodel": "datamodels",
                 "addon": "addons"}[kind]
        return self.store.count(C.CATALOG, {"provider_status": "active", field: value})


def _check_kind(kind: str) -> None:
    if kind not in KINDS:
        raise ValidationError("invalid mapping kind", {"allowed": list(KINDS)})


def _value(value: str) -> str:
    text = (value or "").strip()
    if not text or len(text) > 150 or "\x00" in text:
        raise ValidationError("invalid mapping value")
    return text

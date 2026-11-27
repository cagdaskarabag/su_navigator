"""Clause-level compliance evidence: regulation → clause → use case → readiness → deployment.

Rows are built from KV state only (catalogue, stored raw records, readiness,
deployments, discovery state) and sorted, so the same state always yields
the same pack, byte for byte. The pack carries no wall-clock time; its
``as_of`` fields are the timestamps recorded in that state.
"""

import csv
import hashlib
import io
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..content.reindex import StoredNormalizer
from ..errors import ValidationError
from ..readiness import ENGINE_VERSION
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..storage.repositories import CategoryRepository
from .coverage import _RANK, LEVELS, clause_sort_key

MAX_EVIDENCE_USE_CASES = 5000
BATCH = 200
TEXT_CAP = 4000

COLUMNS = (
    "framework", "regulation", "framework_version", "clause", "content_id", "title", "criticality",
    "level", "gap", "readiness_state", "readiness_score", "readiness_evaluated_at", "readiness_stale",
    "deployment_state", "live_status", "saved_search", "deployed_revision", "live_drift",
    "mode", "assurance", "requires_sme_review", "control_objective", "evidence_artifact",
    "assurance_rationale", "clause_url", "provider", "provider_record_id", "source_ref",
    "source_blob_sha", "normalizer_version", "imported_at",
)
FORMATS = ("json", "csv")


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text[:1] in ("\t", "\r") or text.lstrip()[:1] in ("=", "+", "-", "@"):
        text = "'" + text
    return text


class EvidenceService:
    def __init__(self, store: DocumentStore):
        self.store = store

    def rows(self, framework: str, levels: Dict[str, Dict[str, Any]], clause: str = "") -> List[Dict[str, Any]]:
        if not framework.startswith("regulation:"):
            raise ValidationError("evidence is available for regulation frameworks only")
        keys = sorted(k for k, uc in levels.items() if framework in uc["frameworks"])
        if len(keys) > MAX_EVIDENCE_USE_CASES:
            raise ValidationError("too many use cases map to this regulation; narrow it to one clause",
                                  {"use_cases": len(keys), "limit": MAX_EVIDENCE_USE_CASES})
        disc = self.store.get(C.SYNC_STATE, "discovery::local") or {}
        normalizer = StoredNormalizer(CategoryRepository(self.store))
        out: List[Dict[str, Any]] = []
        for start in range(0, len(keys), BATCH):
            batch = keys[start:start + BATCH]
            contents = self._by_key(C.CONTENT, batch)
            catalog = self._by_key(C.CATALOG, batch, ["_key", "source_hash"])
            readiness = self._by_key(C.READINESS, batch, ["_key", "state", "score", "evaluated_at",
                                                          "engine_version", "discovery_at", "source_hash"])
            deployments = {d.get("catalog_key"): d for d in self.store.query(
                C.DEPLOYMENTS, {"catalog_key": {"$in": batch}},
                fields=["catalog_key", "state", "live_status", "saved_search", "deployed_revision", "live_drift"])}
            for key in batch:
                stored = contents.get(key)
                uc = normalizer.normalize(stored) if stored else None
                if uc is None:
                    continue
                for m in uc.framework_mappings:
                    if m.framework != framework or (clause and m.object_id != clause):
                        continue
                    out.append(self._row(framework, m, uc, levels[key], readiness.get(key),
                                         deployments.get(key), catalog.get(key) or {}, disc))
        out.sort(key=lambda r: (clause_sort_key(r["clause"]), r["framework_version"], r["content_id"]))
        return out

    def _by_key(self, collection: str, keys: List[str], fields: Optional[List[str]] = None) -> Dict[str, Dict]:
        return {d["_key"]: d for d in self.store.query(collection, {"_key": {"$in": keys}}, fields=fields)}

    @staticmethod
    def _row(framework, m, uc, level_info, rd, dep, catalog, disc) -> Dict[str, Any]:
        a = m.attributes
        stale = None
        if rd:
            stale = bool((disc.get("last_completed_at") and disc.get("last_completed_at") != rd.get("discovery_at"))
                         or (catalog.get("source_hash") and catalog.get("source_hash") != rd.get("source_hash"))
                         or rd.get("engine_version") != ENGINE_VERSION)
        saved = (dep or {}).get("saved_search")
        level = level_info["level"]
        prov = uc.provenance
        return {
            "framework": framework, "regulation": a.get("regulation_label") or framework[len("regulation:"):],
            "framework_version": m.framework_version or "", "clause": m.object_id,
            "content_id": uc.content_id, "title": uc.title, "criticality": uc.criticality,
            "level": level, "gap": _RANK[level] < _RANK["ready"],
            "readiness_state": (rd or {}).get("state") or "not_assessed",
            "readiness_score": (rd or {}).get("score"),
            "readiness_evaluated_at": (rd or {}).get("evaluated_at") or "",
            "readiness_stale": stale,
            "deployment_state": (dep or {}).get("state") or "",
            "live_status": (dep or {}).get("live_status") or "",
            "saved_search": (saved.get("name") if isinstance(saved, dict) else saved) or "",
            "deployed_revision": (dep or {}).get("deployed_revision"),
            "live_drift": bool((dep or {}).get("live_drift")) if dep else None,
            "mode": a.get("mode") or "", "assurance": a.get("assurance") or "",
            "requires_sme_review": a.get("requires_sme_review"),
            "control_objective": (a.get("control_objective") or "")[:TEXT_CAP],
            "evidence_artifact": (a.get("evidence_artifact") or "")[:TEXT_CAP],
            "assurance_rationale": (a.get("assurance_rationale") or "")[:TEXT_CAP],
            "clause_url": a.get("clause_url") or "",
            "provider": prov.provider, "provider_record_id": prov.provider_record_id,
            "source_ref": prov.source_ref, "source_blob_sha": prov.source_blob_sha,
            "normalizer_version": prov.normalizer_version, "imported_at": prov.imported_at,
        }

    def clause_summary(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        table: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for r in rows:
            entry = table.setdefault((r["clause"], r["framework_version"]), {
                "clause": r["clause"], "framework_version": r["framework_version"], "use_cases": 0,
                "counts": {name: 0 for name in LEVELS}, "level": "catalogue"})
            entry["use_cases"] += 1
            for name in LEVELS:
                if _RANK[r["level"]] >= _RANK[name]:
                    entry["counts"][name] += 1
            if _RANK[r["level"]] > _RANK[entry["level"]]:
                entry["level"] = r["level"]
        out = sorted(table.values(), key=lambda e: (clause_sort_key(e["clause"]), e["framework_version"]))
        for e in out:
            e["gap"] = _RANK[e["level"]] < _RANK["ready"]
        return out

    def pack(self, framework: str, levels: Dict[str, Dict[str, Any]], fmt: str = "json",
             clause: str = "") -> Dict[str, Any]:
        if fmt not in FORMATS:
            raise ValidationError("format must be json or csv")
        rows = self.rows(framework, levels, clause)
        clauses = self.clause_summary(rows)
        disc = self.store.get(C.SYNC_STATE, "discovery::local") or {}
        meta = {
            "framework": framework, "clause": clause or None, "engine_version": ENGINE_VERSION,
            "discovery_as_of": disc.get("last_completed_at") or "",
            "readiness_as_of": max((r["readiness_evaluated_at"] for r in rows), default=""),
            "content_as_of": max((r["imported_at"] for r in rows), default=""),
            "source_refs": sorted({r["source_ref"] for r in rows if r["source_ref"]}),
            "rows": len(rows), "clauses": len(clauses), "gaps": sum(1 for c in clauses if c["gap"]),
            "columns": list(COLUMNS),
        }
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\r\n")
            writer.writerow(COLUMNS)
            for r in rows:
                writer.writerow([_cell(r[c]) for c in COLUMNS])
            content = buf.getvalue()
        else:
            content = json.dumps({"meta": meta, "clauses": clauses, "rows": rows},
                                 sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        slug = re.sub(r"[^a-z0-9._-]+", "-", (framework[len("regulation:"):] + ("-" + clause if clause else "")).lower())
        return {"meta": meta, "format": fmt, "filename": "evidence-%s.%s" % (slug.strip("-") or "regulation", fmt),
                "content": content, "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}

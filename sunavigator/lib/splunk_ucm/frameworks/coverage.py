"""Framework coverage: catalogue → readiness → deployment → operation (D-030, D-031).

Each use case gets one level, the furthest it has reached:

    catalogue < ready < deployed < enabled < operational

``ready`` is readiness state ``ready``; ``deployed`` means a revision is in a
saved search (disabled); ``enabled`` means the saved search is enabled;
``operational`` additionally needs a successful scheduled run in the health
window (only when operational health is requested and available).

ATT&CK ids are resolved against one framework version: revoked ids follow
their ``revoked-by`` replacement and are listed as remapped; deprecated and
unknown ids are listed as unresolved, never dropped silently. A sub-technique
also counts towards its parent.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import dedupe

LEVELS = ("catalogue", "ready", "deployed", "enabled", "operational")
_RANK = {name: i for i, name in enumerate(LEVELS)}
PAGE = 5000
LEVEL_LABELS = {"catalogue": "In catalogue", "ready": "Data ready", "deployed": "Deployed", "enabled": "Enabled",
                "operational": "Running successfully"}
NAVIGATOR_COLORS = {"catalogue": "#dbe9f6", "ready": "#a8d5a2", "deployed": "#5fb760", "enabled": "#1e7b34",
                    "operational": "#0b4d1f"}


def _iter(store: DocumentStore, collection: str, query: Optional[Dict[str, Any]],
          fields: List[str]) -> Iterable[Dict[str, Any]]:
    skip = 0
    while True:
        rows = store.query(collection, query, sort=[("_key", 1)], skip=skip, limit=PAGE, fields=fields)
        for row in rows:
            yield row
        if len(rows) < PAGE:
            return
        skip += PAGE


def clause_sort_key(clause: str) -> Tuple:
    """Natural order: ``A.5.10`` after ``A.5.9``."""
    parts = re.split(r"(\d+)", clause.lower())
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts if p != "")


def _empty_counts() -> Dict[str, int]:
    return {name: 0 for name in LEVELS}


class CoverageService:
    def __init__(self, store: DocumentStore):
        self.store = store

    def use_case_levels(self, operational: Optional[Dict[str, str]] = None,
                        domain: str = "") -> Dict[str, Dict[str, Any]]:
        """content key → {level, mitre_ids, frameworks, controls, title, criticality, domains}."""
        query: Dict[str, Any] = {"provider_status": "active"}
        if domain:
            query = {"$and": [query, {"domains": domain}]}
        out: Dict[str, Dict[str, Any]] = {}
        for row in _iter(self.store, C.CATALOG, query,
                         ["_key", "content_id", "title", "criticality", "domains", "mitre_ids", "frameworks",
                          "framework_controls"]):
            out[row["_key"]] = {"content_id": row.get("content_id"), "title": row.get("title", ""),
                                "criticality": row.get("criticality", ""), "domains": row.get("domains") or [],
                                "mitre_ids": row.get("mitre_ids") or [], "frameworks": row.get("frameworks") or [],
                                "controls": row.get("framework_controls") or [], "level": "catalogue"}
        for row in _iter(self.store, C.READINESS, {"state": "ready"}, ["_key", "state"]):
            if row["_key"] in out:
                out[row["_key"]]["level"] = "ready"
        for row in _iter(self.store, C.DEPLOYMENTS, {"deployed_revision": {"$gte": 1}},
                         ["catalog_key", "live_status", "content_id"]):
            item = out.get(row.get("catalog_key") or "")
            if item is None:
                continue
            level = "enabled" if row.get("live_status") == "enabled" else "deployed"
            if level == "enabled" and operational and operational.get(row.get("content_id")) == "operational":
                level = "operational"
            if _RANK[level] > _RANK[item["level"]]:
                item["level"] = level
        return out

    @staticmethod
    def _bump(entry: Dict[str, Any], level: str, key: str) -> None:
        if key in entry["_seen"]:
            return
        entry["_seen"].add(key)
        entry["counts"]["catalogue"] += 1
        for name in LEVELS[1:]:
            if _RANK[level] >= _RANK[name]:
                entry["counts"][name] += 1
        if _RANK[level] > _RANK.get(entry["level"] or "", -1):
            entry["level"] = level

    def attack_matrix(self, definition: Dict[str, Any], levels: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        domain = definition.get("domain")
        techniques = {t["id"]: t for t in definition["techniques"]}
        revoked = definition.get("revoked") or {}
        deprecated = set(definition.get("deprecated") or [])
        cells: Dict[str, Dict[str, Any]] = {
            tid: {"counts": _empty_counts(), "level": None, "_seen": set(), "direct": 0, "via_sub": 0}
            for tid in techniques}
        remapped: Dict[Tuple[str, str], List[str]] = {}
        unresolved: Dict[Tuple[str, str], List[str]] = {}
        for key, uc in levels.items():
            for raw_id in dedupe(uc["mitre_ids"]):
                if raw_id.startswith("TA"):
                    continue
                if domain == "ics" and not raw_id.startswith("T0"):
                    continue
                if domain == "enterprise" and raw_id.startswith("T0"):
                    continue
                tid = raw_id
                if tid not in techniques and tid in revoked:
                    target = revoked[tid]
                    remapped.setdefault((tid, target), []).append(uc["content_id"])
                    tid = target
                if tid not in techniques:
                    reason = "deprecated" if raw_id in deprecated else "unknown"
                    unresolved.setdefault((raw_id, reason), []).append(uc["content_id"])
                    continue
                cell = cells[tid]
                self._bump(cell, uc["level"], key)
                cell["direct"] += 1
                parent = techniques[tid].get("parent")
                if parent and parent in cells:
                    self._bump(cells[parent], uc["level"], key)
                    cells[parent]["via_sub"] += 1
        tactics = []
        totals = {"techniques": 0, "covered": _empty_counts()}
        for tac in definition["tactics"]:
            parents = [t for t in definition["techniques"] if tac["id"] in t["tactics"] and not t.get("parent")]
            column = []
            for t in sorted(parents, key=lambda x: x["name"].lower()):
                subs = [s for s in definition["techniques"] if s.get("parent") == t["id"]]
                column.append(self._cell(t, cells[t["id"]], [self._cell(s, cells[s["id"]], []) for s in
                                                            sorted(subs, key=lambda x: x["id"])]))
            tactics.append({"id": tac["id"], "name": tac["name"], "techniques": column,
                            "covered": sum(1 for c in column if c["level"])})
        for tid, t in techniques.items():
            if t.get("parent"):
                continue
            totals["techniques"] += 1
            for name in LEVELS:
                if cells[tid]["counts"][name]:
                    totals["covered"][name] += 1
        return {
            "framework_id": definition["framework_id"], "version": definition["version"],
            "name": definition["name"], "domain": domain, "attribution": definition.get("attribution", ""),
            "tactics": tactics, "totals": totals,
            "remapped": [{"from": a, "to": b, "use_cases": sorted(v)[:50], "count": len(v)}
                         for (a, b), v in sorted(remapped.items())],
            "unresolved": [{"id": a, "reason": r, "use_cases": sorted(v)[:50], "count": len(v)}
                           for (a, r), v in sorted(unresolved.items())],
            "levels": list(LEVELS),
        }

    @staticmethod
    def navigator_layer(matrix: Dict[str, Any], operational: bool = False) -> Dict[str, Any]:
        """ATT&CK Navigator layer (format 4.5); score is the level rank, 1 = in catalogue."""
        levels = list(LEVELS) if operational else list(LEVELS[:-1])
        techniques: Dict[str, Dict[str, Any]] = {}

        def add(cell: Dict[str, Any]) -> None:
            if not cell["level"]:
                return
            c = cell["counts"]
            techniques.setdefault(cell["id"], {
                "techniqueID": cell["id"], "score": _RANK[cell["level"]] + 1,
                "color": NAVIGATOR_COLORS[cell["level"]], "enabled": True, "showSubtechniques": False,
                "comment": "%s: %d use case(s) in catalogue, %d ready, %d deployed, %d enabled" % (
                    LEVEL_LABELS[cell["level"]], c["catalogue"], c["ready"], c["deployed"], c["enabled"])
                + (", %d running successfully" % c["operational"] if operational else ""),
                "metadata": [{"name": "level", "value": cell["level"]},
                             {"name": "use_cases", "value": str(c["catalogue"])}],
            })

        for tac in matrix["tactics"]:
            for t in tac["techniques"]:
                add(t)
                for s in t["subs"]:
                    add(s)
                    if s["level"]:
                        techniques[t["id"]]["showSubtechniques"] = True
        domain = "ics-attack" if matrix["domain"] == "ics" else "enterprise-attack"
        return {
            "name": "SUNavigator coverage", "domain": domain,
            "versions": {"attack": matrix["version"].split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
            "description": "Furthest level reached per technique in %s %s: %s." % (
                matrix["name"], matrix["version"], ", ".join("%d = %s" % (i + 1, LEVEL_LABELS[n])
                                                            for i, n in enumerate(levels))),
            "sorting": 0, "hideDisabled": False,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "gradient": {"colors": ["#ffffff", NAVIGATOR_COLORS[levels[-1]]], "minValue": 0, "maxValue": len(levels)},
            "legendItems": [{"label": LEVEL_LABELS[n], "color": NAVIGATOR_COLORS[n]} for n in levels],
            "techniques": [techniques[k] for k in sorted(techniques)],
        }

    @staticmethod
    def _cell(t: Dict[str, Any], cell: Dict[str, Any], subs: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"id": t["id"], "name": t["name"], "level": cell["level"], "counts": cell["counts"],
                "direct": cell["direct"], "via_sub": cell["via_sub"], "subs": subs}

    def technique_use_cases(self, definition: Dict[str, Any], technique_id: str,
                            levels: Dict[str, Dict[str, Any]], limit: int = 200) -> List[Dict[str, Any]]:
        revoked = definition.get("revoked") or {}
        subs = {t["id"] for t in definition["techniques"] if t.get("parent") == technique_id}
        out = []
        for uc in levels.values():
            resolved = {revoked.get(i, i) for i in uc["mitre_ids"]}
            if technique_id in resolved or resolved & subs:
                out.append({"content_id": uc["content_id"], "title": uc["title"], "criticality": uc["criticality"],
                            "level": uc["level"], "via": sorted(resolved & (subs | {technique_id}))})
        out.sort(key=lambda r: (-_RANK[r["level"]], r["content_id"]))
        return out[:limit]

    def frameworks_summary(self, levels: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generic coverage for every framework the catalogue maps to (regulations and ATT&CK)."""
        table: Dict[str, Dict[str, Any]] = {}
        for key, uc in levels.items():
            controls_by_fw: Dict[str, List[str]] = {}
            for ref in uc["controls"]:
                fw, _, control = ref.partition("#")
                controls_by_fw.setdefault(fw, []).append(control)
            for fw in dedupe(uc["frameworks"]):
                entry = table.setdefault(fw, {"framework": fw, "counts": _empty_counts(), "level": None,
                                              "_seen": set(), "controls": set()})
                self._bump(entry, uc["level"], key)
                entry["controls"].update(controls_by_fw.get(fw, []))
        out = []
        for fw, entry in sorted(table.items(), key=lambda kv: (-kv[1]["counts"]["catalogue"], kv[0])):
            out.append({"framework": fw, "counts": entry["counts"], "controls": len(entry["controls"]),
                        "kind": "attack" if fw == "mitre_attack" else (
                            "regulation" if fw.startswith("regulation:") else "other")})
        return out

    def framework_controls(self, framework: str, levels: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        table: Dict[str, Dict[str, Any]] = {}
        prefix = framework + "#"
        for key, uc in levels.items():
            for ref in uc["controls"]:
                if not ref.startswith(prefix):
                    continue
                control = ref[len(prefix):]
                entry = table.setdefault(control, {"control": control, "counts": _empty_counts(), "level": None,
                                                   "_seen": set(), "use_cases": []})
                self._bump(entry, uc["level"], key)
                if len(entry["use_cases"]) < 20:
                    entry["use_cases"].append(uc["content_id"])
        return [{"control": e["control"], "counts": e["counts"], "level": e["level"], "use_cases": e["use_cases"],
                 "gap": _RANK[e["level"]] < _RANK["ready"]}
                for _, e in sorted(table.items(), key=lambda kv: clause_sort_key(kv[0]))]

"""Control catalogues (``ucm.framework/2``, D-076).

A catalogue is the reference list of a control framework: families, controls and enhancements with a title, a parent
and a withdrawn flag. It is what makes an *unmapped* control visible: coverage that starts from the content's mappings
can only show clauses somebody mapped. Catalogues are reference data; SUNavigator ships identifiers and titles only.

``version_label`` is the text a person reads ("Rev. 5.2.0"); ``sort_key`` is the numeric tuple that orders versions.
"""

import re
from typing import Any, Dict, List, Optional

from ..errors import ValidationError
from .coverage import LEVELS, _RANK, CoverageService, _empty_counts, clause_sort_key

FORMAT_V2 = "ucm.framework/2"
KINDS = ("family", "function", "category", "control", "enhancement", "requirement", "subcategory")
ASSESSED = ("control", "enhancement", "requirement", "subcategory")
MATCH_RULES = ("exact", "nist-800-53")
MAX_CONTROLS = 20000
_FW_ID = re.compile(r"^[a-z][a-z0-9_\-]{1,63}$")
_REG_ID = re.compile(r"^[a-z0-9][a-z0-9\-]{0,63}$")
_CONTROL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._()\-]{0,47}$")
_NIST53 = re.compile(r"^([A-Z]{2})-0*(\d+)(?:[(.]0*(\d+)\)?)?$")
MAX_UNMATCHED = 300


def canonical(clause: str, rule: str) -> str:
    """The spelling a clause is compared in: ``AC-02(01)``, ``ac-2.1`` and ``AC-2(1)`` are one control."""
    text = "".join(str(clause).split()).upper()
    if rule == "nist-800-53":
        match = _NIST53.match(text)
        if match:
            base = "%s-%d" % (match.group(1), int(match.group(2)))
            return base + ("(%d)" % int(match.group(3)) if match.group(3) else "")
    return text


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValidationError("%s must be a non-empty string of at most %d characters" % (name, limit))
    return value.strip()


def validate_controls_definition(doc: Dict[str, Any]) -> Dict[str, Any]:
    fw_id = str(doc.get("framework_id") or "")
    if not _FW_ID.match(fw_id):
        raise ValidationError("invalid framework_id")
    sort_key = doc.get("sort_key")
    if (not isinstance(sort_key, list) or not 1 <= len(sort_key) <= 4 or
            not all(isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= 9999 for n in sort_key)):
        raise ValidationError("sort_key must be one to four whole numbers")
    label = _text(doc.get("version_label"), "version_label", 40)
    rule = str(doc.get("match") or "exact")
    if rule not in MATCH_RULES:
        raise ValidationError("match must be one of %s" % ", ".join(MATCH_RULES))
    regs = doc.get("regulation_ids") or [fw_id]
    if not isinstance(regs, list) or not 1 <= len(regs) <= 10 or not all(_REG_ID.match(str(r)) for r in regs):
        raise ValidationError("invalid regulation_ids")
    items = doc.get("controls")
    if not isinstance(items, list) or not items or len(items) > MAX_CONTROLS:
        raise ValidationError("controls must be a non-empty list of at most %d" % MAX_CONTROLS)
    controls: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    canon: Dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict) or not _CONTROL_ID.match(str(item.get("id") or "")):
            raise ValidationError("invalid control id")
        ident = item["id"]
        if ident in seen:
            raise ValidationError("duplicate control %s" % ident)
        kind = str(item.get("kind") or "")
        if kind not in KINDS:
            raise ValidationError("control %s has an unknown kind" % ident)
        parent = item.get("parent")
        if parent is not None and parent not in seen:
            raise ValidationError("control %s names a parent that is not listed before it" % ident)
        key = canonical(ident, rule)
        if key in canon:
            raise ValidationError("controls %s and %s are the same control" % (canon[key], ident))
        canon[key] = ident
        seen[ident] = len(controls)
        entry: Dict[str, Any] = {"id": ident, "title": _text(item.get("title"), "control title", 600),
                                 "parent": parent, "kind": kind}
        if item.get("withdrawn") is True:
            entry["withdrawn"] = True
        controls.append(entry)
    return {
        "format": FORMAT_V2, "kind": "controls", "framework_id": fw_id,
        "framework": str(doc.get("framework") or fw_id)[:64], "name": _text(doc.get("name"), "name", 200),
        "regulation_ids": [str(r) for r in regs], "version": ".".join(str(n) for n in sort_key),
        "version_label": label, "sort_key": list(sort_key), "match": rule,
        "modified": str(doc.get("modified") or "")[:40], "source_version": str(doc.get("source_version") or "")[:40],
        "source": str(doc.get("source") or "")[:500], "source_sha256": str(doc.get("source_sha256") or "")[:64],
        "attribution": str(doc.get("attribution") or "")[:1000], "controls": controls,
    }


def catalogue_coverage(definition: Dict[str, Any], levels: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Every control of the catalogue with the use cases mapped to it; controls nobody mapped are listed too."""
    rule = definition.get("match") or "exact"
    prefixes = tuple("regulation:%s#" % r for r in definition.get("regulation_ids") or [])
    index = {canonical(c["id"], rule): c["id"] for c in definition["controls"]}
    entries: Dict[str, Dict[str, Any]] = {
        c["id"]: {"counts": _empty_counts(), "level": None, "_seen": set(), "use_cases": [], "clauses": []}
        for c in definition["controls"]}
    unmatched: Dict[str, Dict[str, Any]] = {}
    for key, uc in levels.items():
        for ref in uc["controls"]:
            if not prefixes or not ref.startswith(prefixes):
                continue
            clause = ref.partition("#")[2]
            target = index.get(canonical(clause, rule))
            if target is None:
                entry = unmatched.setdefault(clause, {"counts": _empty_counts(), "level": None, "_seen": set(),
                                                      "use_cases": []})
            else:
                entry = entries[target]
                if clause not in entry["clauses"] and len(entry["clauses"]) < 5:
                    entry["clauses"].append(clause)
            CoverageService._bump(entry, uc["level"], key)
            if len(entry["use_cases"]) < 20 and uc["content_id"] not in entry["use_cases"]:
                entry["use_cases"].append(uc["content_id"])
    rows: List[Dict[str, Any]] = []
    by_id: Dict[str, Dict[str, Any]] = {}
    for c in definition["controls"]:
        e = entries[c["id"]]
        row = {"id": c["id"], "title": c["title"], "parent": c["parent"], "kind": c["kind"],
               "withdrawn": bool(c.get("withdrawn")), "level": e["level"], "counts": e["counts"],
               "use_cases": e["use_cases"], "clauses": e["clauses"], "mapped": e["counts"]["catalogue"] > 0,
               "gap": (c["kind"] in ASSESSED and not c.get("withdrawn") and _RANK[e["level"] or "catalogue"] < _RANK["ready"]),
               "below": {"controls": 0, "mapped": 0, "ready": 0, "enabled": 0}}
        rows.append(row)
        by_id[c["id"]] = row
    totals = {"controls": 0, "mapped": 0, "unmapped": 0, "ready": 0, "deployed": 0, "enabled": 0,
              "withdrawn": 0, "mapped_to_withdrawn": 0}
    for row in rows:
        if row["kind"] not in ASSESSED:
            continue
        if row["withdrawn"]:
            totals["withdrawn"] += 1
            totals["mapped_to_withdrawn"] += 1 if row["mapped"] else 0
            continue
        rank = _RANK[row["level"] or "catalogue"]
        totals["controls"] += 1
        totals["mapped"] += 1 if row["mapped"] else 0
        totals["ready"] += 1 if rank >= _RANK["ready"] else 0
        totals["deployed"] += 1 if rank >= _RANK["deployed"] else 0
        totals["enabled"] += 1 if rank >= _RANK["enabled"] else 0
        parent = row["parent"]
        while parent:
            below = by_id[parent]["below"]
            below["controls"] += 1
            below["mapped"] += 1 if row["mapped"] else 0
            below["ready"] += 1 if rank >= _RANK["ready"] else 0
            below["enabled"] += 1 if rank >= _RANK["enabled"] else 0
            parent = by_id[parent]["parent"]
    totals["unmapped"] = totals["controls"] - totals["mapped"]
    other = [{"clause": clause, "counts": e["counts"], "level": e["level"], "use_cases": e["use_cases"]}
             for clause, e in sorted(unmatched.items(), key=lambda kv: clause_sort_key(kv[0]))]
    return {
        "catalogue": {k: definition.get(k, "") for k in ("framework_id", "framework", "name", "version", "version_label",
                                                         "modified", "source_version", "source", "attribution")},
        "regulation_ids": definition.get("regulation_ids") or [], "totals": totals, "controls": rows,
        "unmatched": other[:MAX_UNMATCHED], "unmatched_count": len(other),
        "levels": list(LEVELS),
    }

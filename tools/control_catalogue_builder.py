"""Reduce a NIST OSCAL catalogue to the app's control-catalogue format (``ucm.framework/2``).

Input: an OSCAL catalogue JSON from https://github.com/usnistgov/oscal-content (SP 800-53 Rev 5, SP 800-171 Rev 3,
CSF 2.0). Output: identifiers, titles, hierarchy and a withdrawn flag only. No control prose is copied, apart from the
one-sentence CSF subcategory statement that serves as its title. Usage:

    python3 tools/control_catalogue_builder.py nist-800-53 NIST_SP-800-53_rev5_catalog.json out/ [source-url]
"""

import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

ATTRIBUTION = ("Source: NIST OSCAL content, https://github.com/usnistgov/oscal-content. NIST publications are works of "
               "the U.S. Government and are not subject to copyright in the United States; NIST requests attribution.")

SPECS: Dict[str, Dict[str, Any]] = {
    "nist-800-53": {
        "framework": "NIST SP 800-53", "name": "NIST SP 800-53 Security and Privacy Controls for Information Systems "
        "and Organizations", "version_label": "Rev. 5.2.0", "sort_key": [5, 2, 0], "kinds": ["family", "control", "enhancement"],
        "match": "nist-800-53"},
    "nist-800-171": {
        "framework": "NIST SP 800-171", "name": "NIST SP 800-171 Protecting Controlled Unclassified Information in "
        "Nonfederal Systems and Organizations", "version_label": "Rev. 3", "sort_key": [3], "kinds": ["family", "requirement"],
        "match": "exact"},
    "nist-csf": {
        "framework": "NIST CSF", "name": "NIST Cybersecurity Framework", "version_label": "2.0", "sort_key": [2, 0],
        "kinds": ["function", "category", "subcategory"], "match": "exact"},
}


def _prop(node: Dict[str, Any], name: str, plain: bool = False) -> str:
    for p in node.get("props") or []:
        if p.get("name") == name and (not plain or not p.get("class")):
            return str(p.get("value") or "")
    return ""


def _statement(node: Dict[str, Any]) -> str:
    for part in node.get("parts") or []:
        if part.get("name") == "statement" and isinstance(part.get("prose"), str):
            return part["prose"].strip()
    return ""


def display_id(framework_id: str, node: Dict[str, Any], depth: int) -> str:
    raw = str(node.get("id") or "")
    if framework_id == "nist-800-53":
        label = _prop(node, "label", plain=True)
        return label or raw.upper()
    if framework_id == "nist-800-171":
        return _prop(node, "sort-id") or raw.replace("SP_800_171_", "")
    return raw


def build(framework_id: str, catalog: Dict[str, Any], source: str = "", sha256: str = "") -> Dict[str, Any]:
    spec = SPECS[framework_id]
    kinds = spec["kinds"]
    out: List[Dict[str, Any]] = []

    def visit(node: Dict[str, Any], parent: Optional[str], depth: int) -> None:
        kind = kinds[min(depth, len(kinds) - 1)]
        ident = display_id(framework_id, node, depth)
        title = str(node.get("title") or "").strip()
        if kind == "subcategory":
            title = _statement(node) or title
        entry: Dict[str, Any] = {"id": ident, "title": title, "parent": parent, "kind": kind}
        if _prop(node, "status") == "withdrawn":
            entry["withdrawn"] = True
        out.append(entry)
        for child in sorted(node.get("controls") or [], key=lambda c: _prop(c, "sort-id") or str(c.get("id"))):
            visit(child, ident, depth + 1)
        for child in node.get("groups") or []:
            visit(child, ident, depth + 1)

    for group in catalog["catalog"]["groups"]:
        visit(group, None, 0)
    meta = catalog["catalog"].get("metadata") or {}
    return {
        "format": "ucm.framework/2", "kind": "controls", "framework_id": framework_id,
        "framework": spec["framework"], "regulation_ids": [framework_id], "name": spec["name"],
        "version_label": spec["version_label"], "sort_key": spec["sort_key"], "match": spec["match"],
        "modified": str(meta.get("last-modified") or "")[:40], "source_version": str(meta.get("version") or "")[:40],
        "source": source[:500], "source_sha256": sha256, "attribution": ATTRIBUTION, "controls": out,
    }


def main(argv: List[str]) -> int:
    if len(argv) < 4 or argv[1] not in SPECS:
        print(__doc__)
        return 2
    with open(argv[2], "rb") as handle:
        raw = handle.read()
    definition = build(argv[1], json.loads(raw.decode("utf-8")), argv[4] if len(argv) > 4 else "",
                       hashlib.sha256(raw).hexdigest())
    os.makedirs(argv[3], exist_ok=True)
    name = "%s-%s.json" % (argv[1], ".".join(str(n) for n in definition["sort_key"]))
    with open(os.path.join(argv[3], name), "w", encoding="utf-8") as handle:
        json.dump(definition, handle, separators=(",", ":"), ensure_ascii=False)
    print("%s: %d controls" % (name, len(definition["controls"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

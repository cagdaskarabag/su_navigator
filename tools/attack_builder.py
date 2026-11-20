"""Reduce a MITRE ATT&CK STIX 2.1 bundle to the app's compact framework format.

Input: a domain bundle from https://github.com/mitre-attack/attack-stix-data
(``enterprise-attack-<v>.json`` or ``ics-attack-<v>.json``), ~50 MB.
Output: ``ucm.framework/1`` JSON (tactics in matrix order, techniques and
sub-techniques with tactic membership, revoked/deprecated ids), ~100 KB, which
``POST /services/ucm/frameworks/import`` accepts and the app bundles.
"""

import hashlib
import json
import sys
from typing import Any, Dict, List, Optional

ATTRIBUTION = ("MITRE ATT&CK\u00ae. \u00a9 The MITRE Corporation. This work is reproduced and distributed "
               "with the permission of The MITRE Corporation. https://attack.mitre.org/resources/legal-and-branding/terms-of-use/")
DOMAINS = {"enterprise-attack": "enterprise", "ics-attack": "ics", "mobile-attack": "mobile"}
NAMES = {"enterprise": "MITRE ATT&CK Enterprise", "ics": "MITRE ATT&CK ICS", "mobile": "MITRE ATT&CK Mobile"}


def _external_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack") and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def build(bundle: Dict[str, Any], version: str, source: str = "", sha256: str = "") -> Dict[str, Any]:
    objects = bundle.get("objects") or []
    by_ref = {o.get("id"): o for o in objects if isinstance(o, dict)}
    domain = ""
    matrix = None
    for o in objects:
        if o.get("type") == "x-mitre-matrix" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            matrix = o
            domain = DOMAINS.get((o.get("x_mitre_domains") or [""])[0], "")
            break
    if matrix is None:
        raise ValueError("bundle has no x-mitre-matrix")
    if not domain:
        for d in (by_ref.get(r, {}).get("x_mitre_domains") for r in matrix.get("tactic_refs") or []):
            if d:
                domain = DOMAINS.get(d[0], "")
                break
    tactics: List[Dict[str, Any]] = []
    short_to_id: Dict[str, str] = {}
    for ref in matrix.get("tactic_refs") or []:
        tac = by_ref.get(ref)
        if not tac:
            continue
        tid = _external_id(tac)
        short = tac.get("x_mitre_shortname") or ""
        if tid:
            tactics.append({"id": tid, "name": tac.get("name", ""), "shortname": short})
            short_to_id[short] = tid
    revoked_by: Dict[str, str] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = by_ref.get(o.get("source_ref")), by_ref.get(o.get("target_ref"))
            if src and dst and _external_id(src) and _external_id(dst):
                revoked_by[_external_id(src)] = _external_id(dst)
    techniques: List[Dict[str, Any]] = []
    deprecated: List[str] = []
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        tid = _external_id(o)
        if not tid:
            continue
        if o.get("revoked"):
            continue
        if o.get("x_mitre_deprecated"):
            deprecated.append(tid)
            continue
        tac_ids = []
        for phase in o.get("kill_chain_phases") or []:
            tac = short_to_id.get(phase.get("phase_name", ""))
            if tac and tac not in tac_ids:
                tac_ids.append(tac)
        techniques.append({
            "id": tid, "name": o.get("name", ""), "tactics": tac_ids,
            "parent": tid.split(".")[0] if "." in tid else None,
            "platforms": sorted(o.get("x_mitre_platforms") or [])[:12],
        })
    techniques.sort(key=lambda t: (t["parent"] or t["id"], t["id"]))
    return {
        "format": "ucm.framework/1",
        "framework": "mitre_attack",
        "framework_id": "mitre_attack_" + domain,
        "domain": domain,
        "name": NAMES.get(domain, "MITRE ATT&CK"),
        "version": version,
        "modified": matrix.get("modified", ""),
        "source": source,
        "source_sha256": sha256,
        "attribution": ATTRIBUTION,
        "tactics": tactics,
        "techniques": techniques,
        "revoked": dict(sorted(revoked_by.items())),
        "deprecated": sorted(set(deprecated)),
    }


def main(argv: List[str]) -> int:
    if len(argv) < 4:
        sys.stderr.write("usage: attack_builder.py <stix bundle.json> <version> <output.json> [source url]\n")
        return 2
    with open(argv[1], "rb") as handle:
        raw = handle.read()
    out = build(json.loads(raw.decode("utf-8")), argv[2], argv[4] if len(argv) > 4 else "",
                hashlib.sha256(raw).hexdigest())
    with open(argv[3], "w", encoding="utf-8") as handle:
        json.dump(out, handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
    sys.stdout.write("%s %s: %d tactics, %d techniques, %d revoked, %d deprecated\n" % (
        out["framework_id"], out["version"], len(out["tactics"]), len(out["techniques"]),
        len(out["revoked"]), len(out["deprecated"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

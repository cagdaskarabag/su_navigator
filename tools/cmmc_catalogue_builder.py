"""Build the CMMC 2.0 Level 2 control catalogue from the public DoD scoring methodology.

Input: the text of "NIST SP 800-171 DoD Assessment Methodology, Version 1.2.1" (June 24, 2020), extracted from the PDF
with any tool (for example ``pypdf``). The annex lists the 110 SP 800-171 Rev. 2 requirements with their value; Section 5
names the requirements worth 5 and 3 points. The two sources must agree or the build fails. CMMC Level 2 uses the same 110
requirements, labelled ``<DOMAIN>.L2-3.x.y`` (the labels the content catalogues use).

    python3 tools/cmmc_catalogue_builder.py methodology.txt out/ [source-url] [sha256]
"""

import json
import os
import re
import sys
from typing import Any, Dict, List

ATTRIBUTION = ("Requirement wording: NIST SP 800-171 Rev. 2. Values and partial-credit rules: NIST SP 800-171 DoD "
               "Assessment Methodology, Version 1.2.1 (U.S. Department of Defense, June 24, 2020). Both are U.S. "
               "Government publications. SUNavigator is not endorsed by NIST or the Department of Defense.")
DOMAINS = {1: ("AC", "Access Control"), 2: ("AT", "Awareness and Training"), 3: ("AU", "Audit and Accountability"),
           4: ("CM", "Configuration Management"), 5: ("IA", "Identification and Authentication"), 6: ("IR", "Incident Response"),
           7: ("MA", "Maintenance"), 8: ("MP", "Media Protection"), 9: ("PS", "Personnel Security"),
           10: ("PE", "Physical Protection"), 11: ("RA", "Risk Assessment"), 12: ("CA", "Security Assessment"),
           13: ("SC", "System and Communications Protection"), 14: ("SI", "System and Information Integrity")}
FIVE = ("3.1.1 3.1.2 3.2.1 3.2.2 3.3.1 3.4.1 3.4.2 3.5.1 3.5.2 3.6.1 3.6.2 3.7.2 3.8.3 3.9.2 3.10.1 3.10.2 3.12.1 3.12.3 "
        "3.13.1 3.13.2 3.14.1 3.14.2 3.14.3 3.1.12 3.1.13 3.1.16 3.1.17 3.1.18 3.3.5 3.4.5 3.4.6 3.4.7 3.4.8 3.5.10 "
        "3.7.5 3.8.7 3.11.2 3.13.5 3.13.6 3.13.15 3.14.4 3.14.6").split()
THREE = "3.3.2 3.7.1 3.8.1 3.8.2 3.9.1 3.11.1 3.12.2 3.1.5 3.1.19 3.7.4 3.8.8 3.13.8 3.14.5 3.14.7".split()
PARTIAL = {"3.5.3": 3, "3.13.11": 3}
NOT_SCORED = {"3.12.4"}


def parse_annex(text: str) -> List[Dict[str, str]]:
    start = text.index("Security Requirement Value Comment")
    lines = text[start:].split("\n")
    clean: List[str] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("NIST SP 800-171 DoD Assessment Methodology, Version"):
            i += 2
            if i < len(lines) and re.match(r"^\s*\d+\s*$", lines[i]):
                i += 1
            continue
        clean.append(lines[i])
        i += 1
    entries: List[List[str]] = []
    for line in clean[1:]:
        if re.match(r"^\s*Annex B", line):
            break
        if not line.strip() or re.match(r"^\s*(Security Requirement Value Comment|NIST SP 800-171 DoD Assessment Scoring Template)\s*$", line):
            continue
        match = re.match(r"^(3\.\d+\.\d+)\*?\s+(.*)$", line)
        if match:
            entries.append([match.group(1), match.group(2).strip()])
        elif entries:
            entries[-1][1] += " " + line.strip()
    out = []
    for ident, body in entries:
        match = re.match(r"^(.*?)\s+(NA|\d(?: to \d)?)(?:\s+(.*))?$", body)
        if not match:
            raise ValueError("cannot read the value of %s: %r" % (ident, body))
        text = re.sub(r"([a-z])- ([a-z])", r"\1-\2", match.group(1).strip().rstrip(".")) + "."
        out.append({"id": ident, "text": text, "value": match.group(2)})
    return out


def check(entries: List[Dict[str, str]]) -> None:
    if len(entries) != 110 or len({e["id"] for e in entries}) != 110:
        raise ValueError("expected 110 requirements, read %d" % len(entries))
    for e in entries:
        ident = e["id"]
        if ident in PARTIAL:
            expected = "3 to 5"
        elif ident in NOT_SCORED:
            expected = "NA"
        else:
            expected = "5" if ident in FIVE else "3" if ident in THREE else "1"
        if e["value"] != expected:
            raise ValueError("%s: annex says %s, Section 5 says %s" % (ident, e["value"], expected))


def build(text: str, source: str = "", sha256: str = "") -> Dict[str, Any]:
    entries = parse_annex(text)
    check(entries)
    controls: List[Dict[str, Any]] = []
    by_family: Dict[int, List[Dict[str, str]]] = {}
    for e in entries:
        by_family.setdefault(int(e["id"].split(".")[1]), []).append(e)
    for number in sorted(DOMAINS):
        code, title = DOMAINS[number]
        controls.append({"id": code, "title": title, "parent": None, "kind": "family"})
        for e in sorted(by_family[number], key=lambda x: int(x["id"].split(".")[2])):
            entry: Dict[str, Any] = {"id": "%s.L2-%s" % (code, e["id"]), "title": e["text"], "parent": code, "kind": "requirement"}
            if e["id"] in NOT_SCORED:
                entry["weight"] = 0
                entry["precondition"] = True
            else:
                entry["weight"] = 5 if (e["id"] in FIVE or e["id"] in PARTIAL) else 3 if e["id"] in THREE else 1
                if e["id"] in PARTIAL:
                    entry["partial_weight"] = PARTIAL[e["id"]]
            controls.append(entry)
    return {
        "format": "ucm.framework/2", "kind": "controls", "framework_id": "cmmc-l2", "framework": "CMMC 2.0 Level 2",
        "name": "CMMC 2.0 Level 2 (110 requirements of NIST SP 800-171 Rev. 2)", "regulation_ids": ["cmmc"],
        "version_label": "2.0 Level 2", "sort_key": [2, 0], "match": "exact",
        "scoring": {"method": "dod-800-171-1.2.1", "start": 110,
                    "note": "Each requirement that is not implemented subtracts its value from 110; a plan of action does not "
                            "reduce the deduction. 3.5.3 and 3.13.11 subtract 3 when partly implemented and 5 when not. "
                            "3.12.4 (a system security plan) is a precondition: without it the assessment cannot be completed."},
        "source": source[:500], "source_sha256": sha256, "attribution": ATTRIBUTION, "controls": controls,
    }


def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    with open(argv[1], "r", encoding="utf-8") as handle:
        definition = build(handle.read(), argv[3] if len(argv) > 3 else "", argv[4] if len(argv) > 4 else "")
    os.makedirs(argv[2], exist_ok=True)
    path = os.path.join(argv[2], "cmmc-l2-2.0.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(definition, handle, separators=(",", ":"), ensure_ascii=False)
    print("%s: %d entries" % (path, len(definition["controls"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

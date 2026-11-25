"""Data evidence: was the data a use case reads actually seen (D-070, issue #13).

Readiness answers "is everything the content needs installed and configured". Data evidence
answers a different question from the same stored results: did discovery or sampling see the
events, populated data models and fields the search reads. It never changes a readiness state
or score; it is stored next to them as ``data_state`` and ``data_evidence``.

Per requirement (collapsed any-of members are skipped, informational ones too):

* sourcetype: present -> seen, stale -> stale, not found / no longer seen -> missing
* index: has events -> seen, empty / unavailable / undefined -> missing
* cim_model: populated yes -> seen, populated no or model missing -> missing, otherwise unverified
* field: sampled present -> seen, sampled absent -> missing, not sampled -> unverified;
  ``field_profile`` evidence (D-070) adds the fill rate when a profile exists

States: ``seen`` (nothing missing or stale, at least one seen), ``partial`` (some seen, some
missing or stale), ``none`` (something missing, nothing seen), ``unverified`` (nothing decided
either way) and ``not_applicable`` (the use case names no data requirement).
"""

from typing import Any, Dict, List, Optional, Sequence

from .evaluators import MET, NOT_MET, PARTIAL, UNKNOWN, UNVERIFIED

# A field counts as seen when at least this share of sampled events fill it and no more than
# this share hold a placeholder (D-070). Below either bound it is missing data, not unverified.
MIN_FILL_RATE = 0.5
MAX_PLACEHOLDER_RATE = 0.2

DATA_SEEN, DATA_PARTIAL, DATA_NONE, DATA_UNVERIFIED, DATA_NOT_APPLICABLE = (
    "seen", "partial", "none", "unverified", "not_applicable")
DATA_STATES = (DATA_SEEN, DATA_PARTIAL, DATA_NONE, DATA_UNVERIFIED, DATA_NOT_APPLICABLE)
DATA_TYPES = ("sourcetype", "index", "cim_model", "field", "event_condition")
MAX_LISTED = 10

SEEN, MISSING, STALE, NOT_DECIDED = "seen", "missing", "stale", "unverified"


def requirement_evidence(r: Dict[str, Any]) -> Optional[str]:
    """seen / missing / stale / unverified for one stored requirement result, None when not a data requirement."""
    kind = r.get("type")
    status = r.get("status")
    if kind not in DATA_TYPES or r.get("collapsed") or r.get("level") == "informational":
        return None
    if kind == "cim_model":
        if status == NOT_MET:
            return MISSING
        populated = r.get("populated")
        if populated == "yes":
            return SEEN
        if populated == "no":
            return MISSING
        return NOT_DECIDED
    if kind == "field" and r.get("profile"):
        profile = r["profile"]
        if float(profile.get("fill_rate") or 0) < MIN_FILL_RATE or \
                float(profile.get("placeholder_rate") or 0) > MAX_PLACEHOLDER_RATE:
            return MISSING
        return SEEN
    if kind == "sourcetype" and status == PARTIAL:
        return STALE
    if kind == "field" and status not in (MET, NOT_MET, UNVERIFIED, UNKNOWN):
        return None
    if status == MET:
        return SEEN
    if status in (NOT_MET, PARTIAL):
        return MISSING
    return NOT_DECIDED


def data_evidence(results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    seen = unverified = 0
    missing: List[Dict[str, Any]] = []
    stale: List[Dict[str, Any]] = []
    for r in results:
        kind = requirement_evidence(r)
        if kind is None:
            continue
        ref = {"type": r.get("type"), "value": r.get("value"), "code": r.get("code"), "level": r.get("level")}
        if r.get("any_of"):
            ref["value"] = "any of " + ", ".join(r["any_of"])
        if r.get("profile"):
            ref["fill_rate"] = r["profile"].get("fill_rate")
            ref["placeholder_rate"] = r["profile"].get("placeholder_rate")
        if kind == SEEN:
            seen += 1
        elif kind == MISSING:
            missing.append(ref)
        elif kind == STALE:
            stale.append(ref)
        else:
            unverified += 1
    bad = len(missing) + len(stale)
    if not (seen or bad or unverified):
        state = DATA_NOT_APPLICABLE
    elif bad and not seen:
        state = DATA_NONE
    elif bad:
        state = DATA_PARTIAL
    elif seen:
        state = DATA_SEEN
    else:
        state = DATA_UNVERIFIED
    missing_fields = [m["value"] for m in missing if m["type"] == "field"]
    return {"state": state, "seen": seen, "unverified": unverified, "missing_count": len(missing),
            "stale_count": len(stale), "missing": missing[:MAX_LISTED], "stale": stale[:MAX_LISTED],
            "missing_fields": missing_fields[:MAX_LISTED]}


def summary_line(ev: Dict[str, Any]) -> str:
    """One sentence for the recommender and the use-case page."""
    state = ev.get("state")
    names = ", ".join("%s %s" % (m["type"], m["value"]) for m in (ev.get("missing") or [])[:3])
    if state == DATA_SEEN:
        return "Data seen: all %d checked data requirement%s had data at discovery%s." % (
            ev["seen"], "" if ev["seen"] == 1 else "s",
            " (%d more not verified)" % ev["unverified"] if ev.get("unverified") else "")
    if state == DATA_PARTIAL:
        return "Data partly seen: %d seen, %d missing or stale%s." % (
            ev["seen"], ev["missing_count"] + ev["stale_count"], " (" + names + ")" if names else "")
    if state == DATA_NONE:
        return "No data seen for what this search reads%s." % (" (" + names + ")" if names else "")
    if state == DATA_UNVERIFIED:
        return "Data not verified: no data requirement could be checked (run discovery's populated check or sample fields)."
    return "The use case names no data requirement."

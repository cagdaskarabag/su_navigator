"""One evaluator per requirement type.

Every evaluator returns a result dict::

    {"status": met|partial|not_met|unknown|unverified|not_applicable,
     "code": short machine reason, "detail": human sentence,
     "observed": [up to 5 evidence rows], "via_mapping": {...} | None}

``unverified`` means the requirement type cannot be checked from the
inventory (fields, event conditions, permissions). It is reported but kept out
of the coverage denominator so it neither inflates nor deflates the score.
"""

import dataclasses
import fnmatch
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..discovery.apps import app_candidates
from ..discovery.populated import NO as POPULATED_NO, UNVERIFIED as POPULATED_UNVERIFIED, YES as POPULATED_YES, reason_text
from .principal import check_access, known_index_docs
from .snapshot import EnvironmentSnapshot

MET, PARTIAL, NOT_MET, UNKNOWN, UNVERIFIED, NOT_APPLICABLE = (
    "met", "partial", "not_met", "unknown", "unverified", "not_applicable")
STATUSES = (MET, PARTIAL, NOT_MET, UNKNOWN, UNVERIFIED, NOT_APPLICABLE)
MAX_OBSERVED = 5

@dataclasses.dataclass
class EvaluationSettings:
    stale_hours: int = 24


def result(status: str, code: str, detail: str, observed: Optional[List[Dict[str, Any]]] = None,
           via: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"status": status, "code": code, "detail": detail,
            "observed": (observed or [])[:MAX_OBSERVED], "via_mapping": via}


def _via(mapping: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not mapping:
        return None
    return {"origin": mapping.get("origin"), "value": mapping.get("value"),
            "confidence": mapping.get("confidence")}


def _pair_row(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {"index": doc.get("index"), "sourcetype": doc.get("sourcetype"),
            "window_count": doc.get("window_count"), "age_seconds": doc.get("age_seconds"),
            "status": doc.get("status")}


def _age_text(seconds: Optional[int]) -> str:
    if seconds is None:
        return "unknown age"
    if seconds < 3600:
        return "%d min old" % (seconds // 60)
    if seconds < 86400:
        return "%.1f h old" % (seconds / 3600.0)
    return "%.1f d old" % (seconds / 86400.0)


# -- data -------------------------------------------------------------------

def eval_sourcetype(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    value = (req.get("value") or "").strip()
    if not value:
        return result(UNKNOWN, "empty_value", "Requirement has no sourcetype value.")
    candidates: List[Tuple[str, Optional[Dict[str, Any]]]] = [(value, None)]
    for mapping in snap.aliases("sourcetype", value):
        candidates.append((mapping.get("value") or "", mapping))

    active: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]] = []
    missing: List[Dict[str, Any]] = []
    for cand, mapping in candidates:
        key = cand.lower()
        if any(ch in key for ch in "*?"):
            for st in snap.all_pair_sourcetypes():
                if fnmatch.fnmatchcase(st, key):
                    active.extend((d, mapping) for d in snap.pairs_active[st])
            continue
        active.extend((d, mapping) for d in snap.pairs_active.get(key, []))
        missing.extend(snap.pairs_missing.get(key, []))

    if active:
        active.sort(key=lambda dm: (dm[0].get("age_seconds") is None, dm[0].get("age_seconds") or 0))
        freshest, mapping = active[0]
        observed = [_pair_row(d) for d, _ in active]
        age = freshest.get("age_seconds")
        indexes = sorted({d.get("index") for d, _ in active})
        where = "in %s" % ", ".join(indexes[:3]) + (" and %d more" % (len(indexes) - 3) if len(indexes) > 3 else "")
        if age is not None and age > settings.stale_hours * 3600:
            return result(PARTIAL, "stale", "Seen %s, but newest event is %s (threshold %d h)."
                          % (where, _age_text(age), settings.stale_hours), observed, _via(mapping))
        return result(MET, "present", "Seen %s; newest event %s." % (where, _age_text(age)),
                      observed, _via(mapping))
    if missing:
        return result(NOT_MET, "no_longer_seen",
                      "Seen in an earlier discovery run but not in the latest window.",
                      [_pair_row(d) for d in missing])
    window = "%s to %s" % (snap.discovery.get("earliest", "?"), snap.discovery.get("latest", "?"))
    note = "" if snap.include_internal else (
        " Internal indexes were not scanned ([discovery] include_internal = false), so a sourcetype that "
        "lives only in _internal or _audit is not seen.")
    return result(NOT_MET, "not_found", "No events for this sourcetype in the discovery window (%s).%s" % (window, note))


def _internal_not_scanned(name: str) -> Dict[str, Any]:
    return result(UNVERIFIED, "internal_not_scanned",
                  "%s is an internal index and the last discovery ran without internal indexes ([discovery] "
                  "include_internal = false), so it was not checked. Run discovery with Include internal indexes "
                  "to verify it." % name)


def eval_index(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    value = (req.get("value") or "").strip()
    names = [value] + [m.get("value") or "" for m in snap.aliases("index", value)]
    for name in names:
        doc = snap.indexes.get(name.lower())
        if not doc:
            continue
        if (doc.get("is_internal") or name.startswith("_")) and not snap.include_internal:
            return _internal_not_scanned(doc.get("name") or name)
        row = {"name": doc.get("name"), "status": doc.get("status"), "window_count": doc.get("window_count"),
               "age_seconds": doc.get("age_seconds"), "disabled": doc.get("disabled")}
        if doc.get("status") != "active" or doc.get("disabled"):
            return result(NOT_MET, "index_unavailable", "Index exists but is disabled or no longer listed.", [row])
        if not doc.get("window_count"):
            return result(PARTIAL, "index_empty", "Index exists but had no events in the discovery window.", [row])
        return result(MET, "present", "Index has events in the discovery window.", [row])
    if value.startswith("_") and not snap.include_internal:
        return _internal_not_scanned(value)
    return result(NOT_MET, "not_found", "Index is not defined on this deployment.")


def populated_text(doc: Dict[str, Any]) -> Tuple[str, str]:
    """(populated, sentence) from the discovery fields of a data model; absent fields mean unverified."""
    state = doc.get("populated")
    if state not in (POPULATED_YES, POPULATED_NO):
        reason = doc.get("populated_reason") or "predates_check"
        why = reason_text(reason)
        return POPULATED_UNVERIFIED, "populated: unverified%s" % (" (%s)" % why if why else "")
    window = doc.get("populated_window") or "-24h"
    span = "the last %s" % window.lstrip("-").replace("h", " h").replace("d", " d")
    if state == POPULATED_YES:
        return state, "populated: yes (%s events in %s at discovery)" % (doc.get("populated_count"), span)
    return state, "populated: no (the discovery check found no events in %s)" % span


def eval_cim_model(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    value = (req.get("value") or "").strip()
    names = [(value, None)] + [(m.get("value") or "", m) for m in snap.aliases("datamodel", value)]
    for name, mapping in names:
        doc = snap.datamodels.get(name.lower())
        if doc:
            populated, sentence = populated_text(doc)
            row = {"name": doc.get("name"), "app": doc.get("app"), "accelerated": doc.get("accelerated"),
                   "populated": populated}
            if populated != POPULATED_UNVERIFIED:
                row["populated_count"] = doc.get("populated_count")
            if populated == POPULATED_NO:
                out = result(PARTIAL, "model_empty",
                             "Data model definition is installed but holds no events (%s). Searches that read it "
                             "return nothing. Check data ingestion: that the sources which feed this model are "
                             "sending data, that their add-ons tag and normalise events to it, and that the "
                             "scheduled account can read the indexes it searches." % sentence,
                             [row], _via(mapping))
            else:
                out = result(MET, "model_present",
                             "Data model definition is installed; %s. Which fields it holds and whether its "
                             "acceleration is current are not verified." % sentence, [row], _via(mapping))
            out["populated"] = populated
            if populated == POPULATED_UNVERIFIED:
                out["populated_reason"] = doc.get("populated_reason") or "predates_check"
            return out
    return result(NOT_MET, "model_missing", "Data model is not installed (install the CIM add-on).")


def eval_datamodel_acceleration(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    value = (req.get("value") or "").strip()
    doc = snap.datamodels.get(value.lower())
    if not doc:
        return result(NOT_MET, "model_missing", "Data model is not installed, so it cannot be accelerated.")
    row = {"name": doc.get("name"), "app": doc.get("app"), "accelerated": doc.get("accelerated")}
    if doc.get("accelerated"):
        return result(MET, "accelerated", "Data model acceleration is enabled.", [row])
    return result(NOT_MET, "not_accelerated",
                  "SPL uses summariesonly=t but the data model is not accelerated.", [row])


# -- apps -------------------------------------------------------------------

def _version_tuple(text: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", text or "")
    return tuple(int(p) for p in parts[:4])


def _find_app(snap: EnvironmentSnapshot, req) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    for name, how in app_candidates(req):
        doc = snap.app(name)
        if doc:
            return doc, None, how
    for mapping in snap.aliases("addon", (req.get("value") or "").strip()):
        doc = snap.app(mapping.get("value") or "")
        if doc:
            return doc, mapping, "mapping"
    return None, None, ""


def _app_row(doc: Dict[str, Any], how: str) -> Dict[str, Any]:
    return {"name": doc.get("name"), "label": doc.get("label"), "version": doc.get("version"),
            "matched_by": how}


def eval_addon(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    doc, mapping, how = _find_app(snap, req)
    if not doc:
        return result(NOT_MET, "not_installed", "No installed app matches this add-on by name, label or Splunkbase id.")
    row = _app_row(doc, how)
    minimum = (req.get("attributes") or {}).get("min_version") or ""
    if minimum and doc.get("version") and _version_tuple(doc["version"]) < _version_tuple(minimum):
        return result(PARTIAL, "version_below_minimum", "Installed version %s is below the documented minimum %s."
                      % (doc["version"], minimum), [row], _via(mapping))
    return result(MET, "installed", "Installed as %s %s." % (doc.get("name"), doc.get("version") or ""),
                  [row], _via(mapping))


def eval_product(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    doc, mapping, how = _find_app(snap, req)
    if not doc:
        return result(NOT_MET, "not_installed", "Premium product is not installed on this search head.")
    return result(MET, "installed", "Installed as %s." % doc.get("name"), [_app_row(doc, how)], _via(mapping))


# -- knowledge objects ------------------------------------------------------

def _object_eval(kind: str, label: str):
    def evaluate(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
        value = (req.get("value") or "").strip()
        docs = snap.object(kind, value)
        if kind == "lookup" and not docs and not value.lower().endswith(".csv"):
            docs = snap.object(kind, value + ".csv")
        if not docs:
            return result(NOT_MET, "not_found", "%s is not defined on this search head." % label)
        rows = [{"name": d.get("name"), "app": d.get("app"), "sharing": d.get("sharing")} for d in docs]
        if any(d.get("sharing") == "global" for d in docs):
            return result(MET, "present_global", "%s is shared globally." % label, rows)
        apps = sorted({d.get("app") or "?" for d in docs})
        return result(PARTIAL, "app_scoped",
                      "%s exists but is only visible in %s; a search in another app will not see it."
                      % (label, ", ".join(apps[:3])), rows)
    return evaluate


eval_macro = _object_eval("macro", "Macro")
eval_lookup = _object_eval("lookup", "Lookup")
eval_eventtype = _object_eval("eventtype", "Eventtype")


# -- platform ---------------------------------------------------------------

def eval_version(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    current = snap.splunk_version
    if not current:
        return result(UNKNOWN, "version_unknown", "Splunk version was not recorded by discovery.")
    cur = _version_tuple(current)
    tokens = [t.strip() for t in (req.get("value") or "").split(",") if t.strip()]
    parsed = False
    for token in tokens:
        low = token.lower()
        if low == "cloud":
            continue
        want = _version_tuple(low)
        if not want:
            continue
        parsed = True
        if low.endswith("+") and cur >= want:
            return result(MET, "version_supported", "Splunk %s satisfies %s." % (current, token))
        if low.endswith(".x") and cur[:len(want)] == want:
            return result(MET, "version_supported", "Splunk %s matches %s." % (current, token))
        if cur[:len(want)] == want:
            return result(MET, "version_supported", "Splunk %s matches %s." % (current, token))
    if not parsed:
        return result(UNKNOWN, "version_unparsed", "Validated versions could not be parsed: %s" % req.get("value"))
    return result(NOT_MET, "version_not_listed",
                  "Splunk %s is not among the validated versions (%s)." % (current, req.get("value")))


def eval_spl_validity(req, snap: EnvironmentSnapshot, settings: EvaluationSettings,
                     content_id: str = "", key: str = ""):
    if (req.get("value") or "") == "missing":
        return result(NOT_MET, "no_spl", "The provider record has no SPL to deploy.")
    doc = snap.validation(content_id, key)
    if not doc:
        return result(UNVERIFIED, "not_parsed", "Primary SPL has not been parsed with Splunk's search parser.")
    observed = [{"parse_ok": doc.get("parse_ok"), "error": doc.get("parse_error"),
                 "commands": doc.get("commands") or [], "side_effects": doc.get("side_effects") or []}]
    if not doc.get("parse_ok"):
        return result(NOT_MET, "parse_error", "Splunk rejected the search: %s" % (doc.get("parse_error") or "parse failed"),
                      observed)
    if doc.get("side_effects"):
        return result(PARTIAL, "side_effects",
                      "Search parses but contains side-effect commands (%s); it will not be previewed or auto-deployed."
                      % ", ".join(doc["side_effects"]), observed)
    if doc.get("review_commands"):
        observed[0]["review_commands"] = doc["review_commands"]
        return result(PARTIAL, "review_commands",
                      "Search parses but runs commands SUN cannot verify as read-only (%s); preview is refused and "
                      "approval needs an explicit acknowledgment." % ", ".join(doc["review_commands"]), observed)
    return result(MET, "parsed", "Splunk parsed the primary search (%s)." % ", ".join(doc.get("commands") or []),
                  observed)


_UNSAMPLED_DETAIL = {
    "sample_truncated": "The sample result was truncated, so absence of this field is not evidence.",
    "sample_failed": "The sample search failed for every matching sourcetype.",
    "sample_empty": "The sample window before the newest discovered event held no events, so absence of this "
                    "field is not evidence.",
}


def eval_field(req, snap: EnvironmentSnapshot, settings: EvaluationSettings,
               content_id: str = "", key: str = ""):
    made = (req.get("attributes") or {}).get("derived_in_spl")
    if made:
        return result(NOT_APPLICABLE, "derived_in_spl",
                      "Produced by %s in the search; raw events are not expected to carry it." % made)
    sample = snap.field_sample(content_id, req.get("value") or "", key)
    if sample is None:
        return result(UNVERIFIED, "not_sampled", "Field has not been sampled. Run validation on this use case.")
    row = {"field": sample.get("field"), "count": sample.get("count"), "index": sample.get("index"),
           "sourcetype": sample.get("sourcetype")}
    if not sample.get("sampled"):
        reason = sample.get("reason") or "not_sampled"
        return result(UNVERIFIED, reason, _UNSAMPLED_DETAIL.get(
            reason, "No active sourcetype was available to sample this field."), [row])
    if sample.get("present"):
        where = sample.get("sourcetype") or "sample"
        return result(MET, "sampled_present", "Field seen in the bounded sample (%s, %s events)."
                      % (where, sample.get("count")), [row])
    return result(NOT_MET, "sampled_absent",
                  "Field was not present in the bounded sample of matching sourcetypes.", [row])


def eval_permission(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    attrs = req.get("attributes") or {}
    evidence: Dict[str, List[str]] = {}
    for st in attrs.get("scan", {}).get("sourcetypes") or []:
        evidence[st] = sorted({d.get("index") for d in snap.pairs_active.get(st.lower(), []) if d.get("index")})
    return check_access(snap.principal, attrs.get("scan"), known_index_docs(snap.indexes), evidence)


def eval_other(req, snap: EnvironmentSnapshot, settings: EvaluationSettings):
    value = req.get("value") or ""
    if value.startswith("eventtype="):
        return eval_eventtype(dict(req, value=value.split("=", 1)[1]), snap, settings)
    return result(UNVERIFIED, "not_evaluable", "This requirement cannot be checked from the inventory.")


def _unverified(code: str, detail: str) -> Callable:
    def evaluate(req, snap, settings):
        return result(UNVERIFIED, code, detail)
    return evaluate


EVALUATORS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "sourcetype": eval_sourcetype,
    "index": eval_index,
    "cim_model": eval_cim_model,
    "datamodel_acceleration": eval_datamodel_acceleration,
    "addon": eval_addon,
    "product": eval_product,
    "macro": eval_macro,
    "lookup": eval_lookup,
    "version": eval_version,
    "spl_validity": eval_spl_validity,
    "other": eval_other,
    "field": eval_field,
    "event_condition": _unverified("requires_data_sampling", "Event conditions need a bounded data sample (WP4)."),
    "freshness": _unverified("not_evaluable", "No freshness target is defined for this requirement."),
    "permission": eval_permission,
    "data_source": _unverified("not_evaluable", "Free-text data source; map it to a sourcetype to evaluate."),
}


def evaluate(req: Dict[str, Any], snap: EnvironmentSnapshot, settings: EvaluationSettings,
             content_id: str = "", key: str = "") -> Dict[str, Any]:
    fn = EVALUATORS.get(req.get("type") or "")
    if fn is None:
        return result(UNVERIFIED, "no_evaluator", "No evaluator for this requirement type.")
    try:
        return fn(req, snap, settings, content_id, key)
    except TypeError:
        return fn(req, snap, settings)

"""Additive ESCU record fields from the ``security_content`` repository (Sprint 16, D-073).

The app never reads YAML. ``tools/escu_enrich.py`` loads a pinned checkout of
https://github.com/splunk/security_content (Apache-2.0), and this module merges the parsed
dictionaries into the records ``package.build_bundle`` produces. Everything here is bounded and
pure: the same inputs give the same record, and a record without a matching detection is left as it was.

Fields added to a record (all optional, all additive):

* ``status``: ``production``, ``experimental`` or ``deprecated`` (upstream lifecycle).
* ``dataSourceDetails``: per data source named by the detection, its sourcetype, source, the event
  separator (a field and one value, for example ``eventName=DescribeImageScanFindings``) and the
  supported add-ons.
* ``supportedTA``: the add-ons across those data sources (name, Splunkbase URL, tested version).
* ``drilldowns``: names and searches of the detection's drilldowns.
* ``riskEntities``: risk-based-alerting entities (field, type, score).
* ``tests``: references to attack data (URL, sourcetype, source). Nothing is downloaded.
* ``macroDefinitions``: ESCU's reference definition of each macro the search uses.
* ``howToImplement``, ``knownFalsePositives``: the detection's own guidance.
"""

import re
from typing import Any, Dict, Iterable, List, Optional

MAX_SOURCES = 10
MAX_TA = 10
MAX_DRILLDOWNS = 6
MAX_ENTITIES = 6
MAX_TESTS = 8
MAX_ATTACK_DATA = 12
MAX_MACROS = 30
MAX_TEXT = 2000
MAX_SEARCH = 2000
MAX_DEFINITION = 500

_MACRO = re.compile(r"`([A-Za-z0-9_]+)(?:\([^`]*\))?`")
_FIELD = re.compile(r"^[A-Za-z_][\w.\-]{0,99}$")
_VALUE = re.compile(r"^[A-Za-z0-9_.:\-/ ]{1,100}$")
_SOURCETYPE = re.compile(r"^[A-Za-z0-9_:.\-/]{1,200}$")
_HTTPS = re.compile(r"^https://[^\s\"'<>]{1,500}$")
_STATUSES = ("production", "experimental", "deprecated")


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value).split())[:limit] if isinstance(value, (str, int, float)) else ""


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        value = [value]
    return [v.strip() for v in value if isinstance(v, str) and v.strip()] if isinstance(value, list) else []


def _tas(value: Any) -> List[Dict[str, str]]:
    out = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict) or not _text(item.get("name"), 200):
            continue
        url = item.get("url") if isinstance(item.get("url"), str) and _HTTPS.match(item["url"]) else ""
        out.append({"name": _text(item["name"], 200), "url": url, "version": _text(item.get("version"), 40)})
    return out


def macro_names(search: str) -> List[str]:
    seen: List[str] = []
    for name in _MACRO.findall(search or ""):
        if name not in seen:
            seen.append(name)
    return seen


def _data_sources(names: Iterable[str], sources: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for name in names:
        src = sources.get(name)
        if not isinstance(src, dict):
            continue
        sourcetype = _text(src.get("sourcetype"), 200)
        field = _text(src.get("separator"), 100)
        value = _text(src.get("separator_value"), 100)
        entry: Dict[str, Any] = {"name": _text(src.get("name") or name, 200),
                                 "sourcetype": sourcetype if _SOURCETYPE.match(sourcetype) else "",
                                 "source": _text(src.get("source"), 300)}
        if field and value and _FIELD.match(field) and _VALUE.match(value):
            entry["separator"] = field
            entry["separatorValue"] = value
        entry["supportedTA"] = _tas(src.get("supported_TA"))[:MAX_TA]
        out.append(entry)
        if len(out) >= MAX_SOURCES:
            break
    return out


def _drilldowns(value: Any) -> List[Dict[str, str]]:
    out = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict) and _text(item.get("name"), 300):
            out.append({"name": _text(item["name"], 300), "search": _text(item.get("search"), MAX_SEARCH)})
        if len(out) >= MAX_DRILLDOWNS:
            break
    return out


def _entities(detection: Dict[str, Any]) -> List[Dict[str, Any]]:
    block = detection.get("intermediate_findings") or detection.get("rba") or {}
    items = (block.get("entities") or block.get("risk_objects") or []) if isinstance(block, dict) else []
    out = []
    for item in items:
        if not isinstance(item, dict) or not _FIELD.match(str(item.get("field") or "")):
            continue
        score = item.get("score")
        out.append({"field": item["field"], "type": _text(item.get("type"), 40),
                    "score": score if isinstance(score, int) and 0 <= score <= 100 else None,
                    "message": _text(item.get("message"), 300)})
        if len(out) >= MAX_ENTITIES:
            break
    return out


def _tests(value: Any) -> List[Dict[str, Any]]:
    out = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        data = []
        for ref in item.get("attack_data") or []:
            if isinstance(ref, dict) and isinstance(ref.get("data"), str) and _HTTPS.match(ref["data"]):
                data.append({"url": ref["data"], "sourcetype": _text(ref.get("sourcetype"), 200),
                             "source": _text(ref.get("source"), 300)})
            if len(data) >= MAX_ATTACK_DATA:
                break
        out.append({"name": _text(item.get("name"), 200), "type": _text(item.get("test_type"), 40),
                    "attackData": data})
        if len(out) >= MAX_TESTS:
            break
    return out


def enrich(raw: Dict[str, Any], detection: Optional[Dict[str, Any]], sources: Dict[str, Dict[str, Any]],
           macros: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Return ``raw`` with the additive fields; ``raw`` itself is not modified."""
    if not isinstance(detection, dict):
        return dict(raw)
    out = dict(raw)
    status = _text(detection.get("status"), 20).lower()
    if status in _STATUSES:
        out["status"] = status
    details = _data_sources(_strings(detection.get("data_source")), sources)
    if details:
        out["dataSourceDetails"] = details
        seen, tas = set(), []
        for d in details:
            for ta in d["supportedTA"]:
                if ta["name"] not in seen:
                    seen.add(ta["name"])
                    tas.append(ta)
        if tas:
            out["supportedTA"] = tas[:MAX_TA]
    drilldowns = _drilldowns(detection.get("drilldown_searches"))
    if drilldowns:
        out["drilldowns"] = drilldowns
    entities = _entities(detection)
    if entities:
        out["riskEntities"] = entities
    tests = _tests(detection.get("tests"))
    if tests:
        out["tests"] = tests
    definitions = {}
    for name in macro_names(out.get("search") or ""):
        macro = macros.get(name)
        if isinstance(macro, dict) and isinstance(macro.get("definition"), str):
            definitions[name] = _text(macro["definition"], MAX_DEFINITION)
        if len(definitions) >= MAX_MACROS:
            break
    if definitions:
        out["macroDefinitions"] = definitions
    for source_key, key in (("how_to_implement", "howToImplement"), ("known_false_positives", "knownFalsePositives")):
        text = _text(detection.get(source_key), MAX_TEXT)
        if text:
            out[key] = text
    return out


SIMPLE_SOURCETYPE = re.compile(r"""^\s*(?:sourcetype|source)\s*=\s*"?([A-Za-z0-9_:.\-/]+)"?\s*$""")


def macro_sourcetype(definition: str) -> str:
    """The sourcetype a macro's definition reduces to, only when it is exactly ``sourcetype=<name>``."""
    match = SIMPLE_SOURCETYPE.match(definition or "")
    if match and (definition or "").lstrip().lower().startswith("sourcetype"):
        return match.group(1)
    return ""

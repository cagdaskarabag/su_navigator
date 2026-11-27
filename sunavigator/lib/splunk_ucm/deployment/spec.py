"""Deployment specification: validated input → saved-search settings."""

import re
from typing import Any, Dict

from ..errors import ValidationError
from ..util import sha256_text
from . import actions as actions_mod
from .savedsearch import MANAGED_MARKER

SPL_SOURCES = ("primary", "cim", "custom")
ALERT_MODES = ("none", "track")
SEVERITIES = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# Five-field cron: digits, ranges, lists, steps and "*" only (no macros such as @daily).
_CRON_FIELD = re.compile(r"^(\*|\d{1,2}(-\d{1,2})?)(/\d{1,2})?(,(\*|\d{1,2}(-\d{1,2})?)(/\d{1,2})?)*$")
_TIME = re.compile(r"^(now|[-+]\d{1,4}[smhdwy](@[smhdwy]\d?)?|@[smhdwy]|rt|rt-\d{1,4}[smhdwy])$")
_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9 _.:()\-]+")
_PERIOD = re.compile(r"^\d{1,4}[smhd]$")
_FIELD = re.compile(r"^[A-Za-z_][\w.:\-]{0,99}$")
MAX_SCHEDULE_WINDOW = 1440
MAX_SUPPRESS_FIELDS = 10
MAX_CUSTOM_SPL = 20000


def validate_cron(value: str) -> str:
    text = " ".join((value or "").split())
    parts = text.split(" ")
    if len(parts) != 5 or not all(_CRON_FIELD.match(p) for p in parts):
        raise ValidationError("cron must have five fields (minute hour day month weekday)", {"value": text[:60]})
    return text


def validate_time(value: str, name: str) -> str:
    text = (value or "").strip()
    if not _TIME.match(text) or text.startswith("rt"):
        raise ValidationError("invalid %s" % name, {"value": text[:40], "allowed": "now, -15m, -1h@h, @d"})
    return text


def validate_schedule_window(value: str) -> str:
    text = (value or "").strip().lower()
    if text == "auto":
        return text
    if text.isdigit() and int(text) <= MAX_SCHEDULE_WINDOW:
        return str(int(text))
    raise ValidationError("schedule_window must be auto or 0-%d minutes" % MAX_SCHEDULE_WINDOW, {"value": text[:20]})


def validate_suppression(period: str, fields: str, mode: str):
    period = (period or "").strip()
    names = [f.strip() for f in str(fields or "").split(",") if f.strip()]
    if not period:
        if names:
            raise ValidationError("suppress_fields needs a suppress_period")
        return "", ""
    if mode != "track":
        raise ValidationError("suppression applies to alerts (alert_mode track) only")
    if not _PERIOD.match(period):
        raise ValidationError("suppress_period must look like 30m, 1h or 1d", {"value": period[:20]})
    bad = [f for f in names if not _FIELD.match(f)]
    if bad or len(names) > MAX_SUPPRESS_FIELDS:
        raise ValidationError("suppress_fields must be up to %d field names" % MAX_SUPPRESS_FIELDS,
                              {"invalid": bad[:5]})
    return period, ",".join(names)


def saved_search_name(record_id: str, title: str) -> str:
    clean = " ".join(_NAME_UNSAFE.sub(" ", title or "").split())
    name = "SUN - %s - %s" % (record_id, clean) if clean else "SUN - %s" % record_id
    return name[:100].rstrip(" -")


def normalize_spec(body: Dict[str, Any], defaults: Dict[str, str]) -> Dict[str, Any]:
    source = str(body.get("spl_source") or "primary")
    if source not in SPL_SOURCES:
        raise ValidationError("spl_source must be one of %s" % ", ".join(SPL_SOURCES))
    custom = body.get("custom_spl") or ""
    if source == "custom":
        if not isinstance(custom, str) or not custom.strip():
            raise ValidationError("custom_spl is required when spl_source is custom")
        if len(custom) > MAX_CUSTOM_SPL or "\x00" in custom:
            raise ValidationError("custom_spl is too large or contains NUL bytes")
    mode = str(body.get("alert_mode") or defaults.get("alert_mode") or "track")
    if mode not in ALERT_MODES:
        raise ValidationError("alert_mode must be one of %s" % ", ".join(ALERT_MODES))
    severity = str(body.get("severity") or "medium")
    if severity not in SEVERITIES:
        raise ValidationError("severity must be one of %s" % ", ".join(SEVERITIES))
    try:
        threshold = int(body.get("threshold") if body.get("threshold") not in (None, "") else 0)
    except (TypeError, ValueError):
        raise ValidationError("threshold must be an integer")
    if not 0 <= threshold <= 1000000:
        raise ValidationError("threshold must be 0-1000000")
    notes = str(body.get("notes") or "")
    if len(notes) > 1000:
        raise ValidationError("notes too long")
    period, fields = validate_suppression(str(body.get("suppress_period") or ""),
                                          str(body.get("suppress_fields") or ""), mode)
    return {
        "spl_source": source,
        "custom_spl": custom.strip() if source == "custom" else "",
        "cron": validate_cron(str(body.get("cron") or defaults.get("cron") or "*/15 * * * *")),
        "earliest": validate_time(str(body.get("earliest") or defaults.get("earliest") or "-20m@m"), "earliest"),
        "latest": validate_time(str(body.get("latest") or defaults.get("latest") or "-5m@m"), "latest"),
        "schedule_window": validate_schedule_window(
            str(body.get("schedule_window") or defaults.get("schedule_window") or "auto")),
        "suppress_period": period, "suppress_fields": fields,
        "alert_mode": mode, "severity": severity, "threshold": threshold, "notes": notes,
    }


def description(content_id: str, revision: int) -> str:
    return "%s. content_id=%s revision=%d. Edit through the app; direct changes are reported as drift." % (
        MANAGED_MARKER, content_id, revision)


def is_managed_by_us(live: Dict[str, Any], content_id: str) -> bool:
    text = str(live.get("description") or "")
    return MANAGED_MARKER in text and ("content_id=%s " % content_id) in text


def settings_for(revision: Dict[str, Any], content_id: str, disabled: bool = True) -> Dict[str, str]:
    settings = {
        "search": revision["spl"],
        "description": description(content_id, revision["rev"]),
        "disabled": "1" if disabled else "0",
        "is_scheduled": "1",
        "cron_schedule": revision["cron"],
        "dispatch.earliest_time": revision["earliest"],
        "dispatch.latest_time": revision["latest"],
        "request.ui_dispatch_app": "search",
    }
    if revision["alert_mode"] == "track":
        settings.update({
            "alert_type": "number of events", "alert_comparator": "greater than",
            "alert_threshold": str(revision["threshold"]), "alert.track": "1",
            "alert.severity": str(SEVERITIES[revision["severity"]]),
        })
    else:
        settings.update({"alert_type": "always", "alert.track": "0"})
    # Revisions frozen before these keys existed leave Splunk's values alone.
    if "schedule_window" in revision:
        settings["schedule_window"] = revision["schedule_window"]
    if "suppress_period" in revision:
        if _suppressed(revision):
            settings.update({"alert.suppress": "1", "alert.suppress.period": revision["suppress_period"],
                             "alert.suppress.fields": revision.get("suppress_fields") or ""})
        else:
            settings["alert.suppress"] = "0"
    if "actions" in revision:
        settings.update(actions_mod.settings(revision["actions"]))
    return settings


def _suppressed(revision: Dict[str, Any]) -> bool:
    return bool(revision.get("suppress_period")) and revision.get("alert_mode") == "track"


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("1", "true", "yes", "on")


def _fields(value: Any) -> str:
    return ",".join(f.strip() for f in str(value or "").split(",") if f.strip())


def spl_hash(spl: str) -> str:
    return sha256_text(" ".join((spl or "").split()))


_FALSE_WORDS = ("0", "false", "no", "off")


def _alert_value(key: str, value: Any) -> str:
    text = str(value if value is not None else "").strip().lower()
    if key == "alert.track":
        if _truthy(value):
            return "1"
        return "0" if text in _FALSE_WORDS else text
    return text


def _alert_drift(revision: Dict[str, Any], live: Dict[str, Any]) -> list:
    """The alert trigger the app wrote (issue #48): type, comparator, threshold, tracking and severity."""
    if revision.get("alert_mode") == "track":
        expected = {"alert_type": "number of events", "alert_comparator": "greater than",
                    "alert_threshold": str(revision["threshold"]), "alert.track": "1",
                    "alert.severity": str(SEVERITIES[revision["severity"]])}
    elif revision.get("alert_mode"):
        expected = {"alert_type": "always", "alert.track": "0"}
    else:
        return []
    return [{"field": key, "expected": want, "observed": live.get(key)}
            for key, want in expected.items() if _alert_value(key, live.get(key)) != want]


def drift(revision: Dict[str, Any], live: Dict[str, Any], expected_disabled: bool, owner: str = "") -> list:
    out = []
    if owner and live.get("owner") != owner:
        out.append({"field": "owner", "expected": owner, "observed": live.get("owner")})
    if spl_hash(live.get("search") or "") != revision["spl_hash"]:
        out.append({"field": "search", "detail": "search text differs from revision %d" % revision["rev"]})
    if " ".join(str(live.get("cron_schedule") or "").split()) != revision["cron"]:
        out.append({"field": "cron_schedule", "expected": revision["cron"], "observed": live.get("cron_schedule")})
    for key, expected in (("dispatch.earliest_time", revision["earliest"]),
                          ("dispatch.latest_time", revision["latest"])):
        if str(live.get(key) or "") != expected:
            out.append({"field": key, "expected": expected, "observed": live.get(key)})
    if "schedule_window" in revision and str(live.get("schedule_window") or "0").lower() != revision["schedule_window"]:
        out.append({"field": "schedule_window", "expected": revision["schedule_window"],
                    "observed": live.get("schedule_window")})
    if "suppress_period" in revision:
        expected_on = _suppressed(revision)
        if _truthy(live.get("alert.suppress")) != expected_on:
            out.append({"field": "alert.suppress", "expected": expected_on, "observed": live.get("alert.suppress")})
        elif expected_on:
            for key, expected, observed in (
                    ("alert.suppress.period", revision["suppress_period"], str(live.get("alert.suppress.period") or "")),
                    ("alert.suppress.fields", _fields(revision.get("suppress_fields")),
                     _fields(live.get("alert.suppress.fields")))):
                if observed != expected:
                    out.append({"field": key, "expected": expected, "observed": live.get(key)})
    out.extend(_alert_drift(revision, live))
    if "actions" in revision:
        out.extend(actions_mod.drift(revision["actions"], live))
    else:
        actions = [a.strip() for a in str(live.get("actions") or "").split(",") if a.strip()]
        if actions:
            out.append({"field": "actions", "expected": "", "observed": ",".join(actions)})
    if not live.get("is_scheduled"):
        out.append({"field": "is_scheduled", "expected": True, "observed": False})
    if bool(live.get("disabled")) != expected_disabled:
        out.append({"field": "disabled", "expected": expected_disabled, "observed": bool(live.get("disabled"))})
    return out

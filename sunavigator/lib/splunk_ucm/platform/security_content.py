"""Read-only hand-off to Splunk Enterprise Security and the ES Content Update app (docs/DECISIONS.md D-067).

SUNavigator never creates ES-managed content and never writes into another app. This module only
*reads*, with the REST handler's system token (a viewer cannot read other apps' saved searches):

* whether the ES app and the ESCU app are installed, and their versions;
* for an ESCU use case, the state of the saved-search stanza ESCU shipped for it.

Everything here ends in a value, never an exception: a missing system session, a 403 or a
transport failure yields ``unverified`` with a reason. Reads are cached for a short time in the
persistent REST handler process.

Everything that depends on ES being present is unvalidated: the product has no ES lab. What was
checked: the ES app id on the Splunkbase API (app 263, ``SplunkEnterpriseSecuritySuite``, releases
8.x) and the ESCU stanza layout on a real ESCU 6.11.1 install. The ES Content Management URL path is
built from the app id and is not verified for any ES version.
"""

import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from ..errors import StorageError
from ..storage.transport import SplunkdTransport
from ..util import utc_now_iso

ES_APP_IDS = ("SplunkEnterpriseSecuritySuite",)
ESCU_APP_ID = "DA-ESS-ContentUpdate"
CONTENT_MANAGEMENT_VIEW = "ess_content_management"
CACHE_SECONDS = 60
CACHE_MAX = 500
MAX_STANZA_NAME = 300
_APP_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

APP_INSTALLED, APP_DISABLED, APP_NOT_INSTALLED, APP_UNVERIFIED = "installed", "disabled", "not_installed", "unverified"
ST_ENABLED, ST_DISABLED, ST_NOT_FOUND, ST_UNVERIFIED = "enabled", "disabled", "not_found", "unverified"

COVERAGE_NOTE = ("Enabled in ES or in ESCU is shown here only. It does not count as enabled in SUN coverage, "
                 "which counts searches SUN deployed.")
LINK_NOTE = ("The link is built from the ES app id. The exact path of Content Management varies by ES version "
             "and was not verified; in ES 8 the menu route is Security content, then Content management.")
PARALLEL_TEXT = ("A SUN deployment creates a separate plain scheduled search next to ESCU's. It has no ES notable or "
                 "risk actions and ES Content Management does not manage it. If ESCU's copy is enabled, both run and "
                 "can produce duplicate results.")

_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def clear_cache() -> None:
    _CACHE.clear()


def _cached(key: str, now: float) -> Optional[Dict[str, Any]]:
    hit = _CACHE.get(key)
    if hit and now - hit[0] < CACHE_SECONDS:
        return dict(hit[1])
    return None


def _remember(key: str, now: float, value: Dict[str, Any]) -> None:
    if len(_CACHE) >= CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = (now, dict(value))


def _flag(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("1", "true", "t", "yes")


def _first_content(data: Any) -> Dict[str, Any]:
    entries = (data or {}).get("entry") or [] if isinstance(data, dict) else []
    content = entries[0].get("content") if entries and isinstance(entries[0], dict) else None
    return content if isinstance(content, dict) else {}


class SecurityContentReader:
    def __init__(self, transport: Optional[SplunkdTransport], clock: Callable[[], float] = time.monotonic):
        self.t = transport
        self.clock = clock

    def app(self, app_id: str) -> Dict[str, Any]:
        base = {"app_id": app_id, "state": APP_UNVERIFIED, "version": "", "label": "", "reason": ""}
        if self.t is None:
            return dict(base, reason="no system session")
        if not _APP_ID.match(app_id):
            return dict(base, reason="invalid app id")
        key = "app:" + app_id
        now = self.clock()
        hit = _cached(key, now)
        if hit is not None:
            return hit
        try:
            data = self.t.json("GET", "/services/apps/local/%s" % quote(app_id, safe=""))
        except StorageError as exc:
            if exc.status == 404:
                out = dict(base, state=APP_NOT_INSTALLED)
                _remember(key, now, out)
                return out
            return dict(base, reason="read failed (HTTP %s)" % (exc.status or "error"))
        except Exception as exc:
            return dict(base, reason=("read failed: %s" % exc)[:120])
        content = _first_content(data)
        if not content:
            return dict(base, reason="empty response")
        out = dict(base, state=APP_DISABLED if _flag(content.get("disabled")) else APP_INSTALLED,
                   version=str(content.get("version") or ""), label=str(content.get("label") or app_id))
        _remember(key, now, out)
        return out

    def overview(self) -> Dict[str, Any]:
        """ES and ESCU presence. ES is the first of ``ES_APP_IDS`` that is installed, else the last answer."""
        es = {"app_id": ES_APP_IDS[0], "state": APP_NOT_INSTALLED, "version": "", "label": "", "reason": ""}
        for app_id in ES_APP_IDS:
            es = self.app(app_id)
            if es["state"] in (APP_INSTALLED, APP_DISABLED):
                break
        return {"es": es, "escu": self.app(ESCU_APP_ID), "read_at": utc_now_iso()}

    def stanza(self, name: str) -> Dict[str, Any]:
        base = {"name": name, "state": ST_UNVERIFIED, "reason": "", "scheduled": None, "cron": "",
                "earliest": "", "latest": "", "notable": None, "risk": None, "actions": [],
                "read_at": utc_now_iso()}
        if self.t is None:
            return dict(base, reason="no system session")
        if not name or len(name) > MAX_STANZA_NAME or _CONTROL.search(name) or "/" in name:
            return dict(base, reason="no usable stanza name for this record")
        key = "stanza:" + name
        now = self.clock()
        hit = _cached(key, now)
        if hit is not None:
            return hit
        path = "/servicesNS/nobody/%s/saved/searches/%s" % (quote(ESCU_APP_ID, safe=""), quote(name, safe=""))
        try:
            data = self.t.json("GET", path)
        except StorageError as exc:
            if exc.status == 404:
                out = dict(base, state=ST_NOT_FOUND, reason="the installed ESCU app has no saved search with this name")
                _remember(key, now, out)
                return out
            return dict(base, reason="read failed (HTTP %s)" % (exc.status or "error"))
        except Exception as exc:
            return dict(base, reason=("read failed: %s" % exc)[:120])
        content = _first_content(data)
        if not content or "disabled" not in content:
            return dict(base, reason="the saved search could not be interpreted")
        actions = [a.strip() for a in str(content.get("actions") or "").split(",") if a.strip()]
        out = dict(base, state=ST_DISABLED if _flag(content.get("disabled")) else ST_ENABLED,
                   scheduled=_flag(content.get("is_scheduled")), cron=str(content.get("cron_schedule") or ""),
                   earliest=str(content.get("dispatch.earliest_time") or ""),
                   latest=str(content.get("dispatch.latest_time") or ""),
                   notable=_flag(content.get("action.notable")) or "notable" in actions,
                   risk=_flag(content.get("action.risk")) or "risk" in actions, actions=actions[:10])
        _remember(key, now, out)
        return out


def stanza_name_for(uc_provider: str, record_id: str, title: str, extras: Dict[str, Any]) -> str:
    """The saved-search name ESCU shipped for a record: the stanza the importer stored, else ``ESCU - <title> - Rule``."""
    if uc_provider != "escu":
        return ""
    stored = (extras or {}).get("stanza")
    if isinstance(stored, str) and stored.strip():
        return stored.strip()
    return "ESCU - %s - Rule" % title if title else ""


def es_link(es: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if es.get("state") != APP_INSTALLED or not _APP_ID.match(es.get("app_id") or ""):
        return None
    app_id = es["app_id"]
    return {"app_id": app_id, "content_management_view": CONTENT_MANAGEMENT_VIEW, "verified": False, "note": LINK_NOTE}


def build_handoff(overview: Dict[str, Any], stanza: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The card for one ESCU record. ``stanza`` is None when ESCU is not installed (nothing to read)."""
    es, escu = overview["es"], overview["escu"]
    es_installed = es["state"] == APP_INSTALLED
    st = (stanza or {}).get("state") or ST_UNVERIFIED
    if escu["state"] == APP_NOT_INSTALLED:
        code = "escu_not_installed"
        text = ("The ESCU app is not installed on this search head, so there is no shipped search to enable. "
                "SUN can deploy an independent copy.")
    elif escu["state"] != APP_INSTALLED:
        code = "unverified"
        text = ("SUN could not read the ESCU app (%s). Check ES Content Management or Settings, Searches, reports, and "
                "alerts for the shipped search before deploying a copy." % (escu.get("reason") or escu["state"]))
    elif st == ST_NOT_FOUND:
        code = "stanza_not_found"
        text = ("The installed ESCU version %s has no saved search with this name; it may have been renamed or "
                "removed. SUN can deploy an independent copy." % (escu.get("version") or ""))
    elif st == ST_UNVERIFIED:
        code = "unverified"
        text = ("The state of the shipped search could not be read (%s). Do not assume it is disabled."
                % ((stanza or {}).get("reason") or "unknown reason"))
    elif es_installed:
        code = "enable_in_es"
        text = ("Enterprise Security is installed. Enable this detection in ES Content Management so ES manages it "
                "with its notable and risk actions. SUN does not create ES-managed content and never writes into "
                "another app.")
    elif es["state"] == APP_UNVERIFIED:
        code = "es_unverified"
        text = ("Whether Enterprise Security is installed could not be determined (%s). If it is, enable the "
                "detection in ES Content Management." % (es.get("reason") or "unknown reason"))
    else:
        code = "escu_without_es"
        text = ("ESCU is installed without Enterprise Security: the shipped search is %s and nothing manages it. "
                "SUN can deploy an independent copy, a plain scheduled search without ES actions."
                % ("enabled" if st == ST_ENABLED else "disabled"))
    warning = escu["state"] == APP_INSTALLED and (es_installed or st == ST_ENABLED)
    return {
        "provider": "escu", "code": code, "text": text,
        "es": es, "escu": escu, "stanza": stanza,
        "es_link": es_link(es),
        "parallel_copy": {"warn": bool(warning), "text": PARALLEL_TEXT if warning else "",
                          "es_installed": es_installed, "escu_enabled": st == ST_ENABLED},
        "coverage_note": COVERAGE_NOTE,
        "validated": "ESCU-only behaviour was verified on a lab with ESCU and no ES. Behaviour with ES installed is "
                     "mocked in tests and unvalidated (no ES lab).",
        "read_at": overview.get("read_at"),
    }


def handoff_for(reader: SecurityContentReader, provider: str, record_id: str, title: str,
                extras: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """None for a record that is not from ESCU; otherwise the card. Never raises."""
    name = stanza_name_for(provider, record_id, title, extras)
    if not name:
        return None
    try:
        overview = reader.overview()
        stanza = reader.stanza(name) if overview["escu"]["state"] == APP_INSTALLED else None
        return build_handoff(overview, stanza)
    except Exception as exc:
        return {"provider": "escu", "code": "unverified", "text": "The ES/ESCU state could not be read: %s" % str(exc)[:120],
                "es": None, "escu": None, "stanza": None, "es_link": None,
                "parallel_copy": {"warn": False, "text": "", "es_installed": False, "escu_enabled": False},
                "coverage_note": COVERAGE_NOTE, "validated": "", "read_at": utc_now_iso()}


def deploy_record(handoff: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """What a draft revision keeps when the warning applied; None when there is nothing to record."""
    if not handoff or not (handoff.get("parallel_copy") or {}).get("warn"):
        return None
    pc = handoff["parallel_copy"]
    stanza = handoff.get("stanza") or {}
    return {"warned": True, "es_installed": bool(pc.get("es_installed")), "escu_enabled": bool(pc.get("escu_enabled")),
            "stanza": stanza.get("name") or "", "stanza_state": stanza.get("state") or "",
            "read_at": handoff.get("read_at") or ""}

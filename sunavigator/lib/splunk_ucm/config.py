"""App configuration (``ucm.conf``) read through splunkd's configs endpoint.

Values are strings in .conf files; typed accessors apply defaults and bounds.
Secrets are never stored here (see ``secrets.py``).
"""

from typing import Any, Dict, Optional
from urllib.parse import quote

from . import APP_NAME
from .errors import StorageError
from .storage.transport import SplunkdTransport

DEFAULTS: Dict[str, Dict[str, str]] = {
    "provider:fenre": {
        "enabled": "true", "remote_sync_enabled": "true", "owner": "fenre",
        "repo": "splunk-monitoring-use-cases", "ref": "main", "allowed_refs": "main", "api_base": "https://api.github.com",
        "raw_base": "https://raw.githubusercontent.com", "content_root": "content",
        "schema_path": "schemas/uc.schema.json", "version_path": "VERSION", "allowed_hosts": "",
        "fetch_concurrency": "4", "timeout": "30", "max_attempts": "4", "proxy_url": "", "ca_bundle": "",
    },
    "sync": {"schedule_interval_hours": "0", "job_timeout_seconds": "3600", "max_invalid_ratio": "0.2"},
    "import": {"max_bundle_mb": "50"},
    "controltest": {"index": "ucm_controltest"},
    "catalog": {"max_page_size": "100", "max_join_keys": "2000"},
    "discovery": {
        "earliest": "-7d", "latest": "now", "include_internal": "false",
        "max_pairs": "5000", "search_timeout_seconds": "120", "job_timeout_seconds": "600",
        "schedule_interval_hours": "0",
    },
    "readiness": {
        "auto_assess": "true", "stale_hours": "24", "ready_threshold": "90", "partial_threshold": "50",
        "min_coverage": "0.5", "job_timeout_seconds": "3600",
    },
    "validation": {
        "earliest": "-15m", "latest": "now", "preview_max_events": "50",
        "preview_timeout_seconds": "30", "sample_events": "200", "sample_timeout_seconds": "30",
    },
    "deployment": {
        "require_approval": "true", "allow_self_approval": "false", "block_enable_states": "blocked",
        "default_cron": "*/15 * * * *", "default_earliest": "-15m", "default_latest": "now",
        "default_alert_mode": "track", "max_revisions": "20", "verify_interval_minutes": "60",
    },
    "retention": {"audit_days": "365", "job_history": "50", "interval_hours": "24"},
}

_TRUE = {"1", "true", "t", "yes", "y", "on"}


class AppConfig:
    def __init__(self, stanzas: Dict[str, Dict[str, str]]):
        merged = {name: dict(values) for name, values in DEFAULTS.items()}
        for name, values in stanzas.items():
            merged.setdefault(name, {}).update({k: str(v) for k, v in values.items()})
        self.stanzas = merged

    def get(self, stanza: str, key: str, default: str = "") -> str:
        return self.stanzas.get(stanza, {}).get(key, default)

    def get_bool(self, stanza: str, key: str, default: bool = False) -> bool:
        value = self.get(stanza, key, "")
        return value.strip().lower() in _TRUE if value else default

    def get_int(self, stanza: str, key: str, default: int, lo: int, hi: int) -> int:
        try:
            value = int(self.get(stanza, key, str(default)))
        except ValueError:
            value = default
        return max(lo, min(hi, value))

    def get_float(self, stanza: str, key: str, default: float, lo: float, hi: float) -> float:
        try:
            value = float(self.get(stanza, key, str(default)))
        except ValueError:
            value = default
        return max(lo, min(hi, value))

    def provider_settings(self, provider: str) -> Dict[str, str]:
        return dict(self.stanzas.get("provider:" + provider, {}))


_INTERNAL_KEYS = {"eai:acl", "eai:appName", "eai:userName", "disabled"}


def load_config(transport: Optional[SplunkdTransport], app: str = APP_NAME) -> AppConfig:
    if transport is None:
        return AppConfig({})
    path = "/servicesNS/nobody/%s/configs/conf-ucm" % quote(app)
    try:
        data = transport.json("GET", path, {"count": "0"})
    except StorageError as exc:
        if exc.status == 404:
            return AppConfig({})
        raise
    stanzas: Dict[str, Dict[str, str]] = {}
    for entry in (data or {}).get("entry", []):
        content: Dict[str, Any] = entry.get("content") or {}
        stanzas[entry.get("name", "")] = {k: v for k, v in content.items()
                                          if k not in _INTERNAL_KEYS and not k.startswith("eai:")
                                          and isinstance(v, (str, int, float, bool))}
    return AppConfig(stanzas)

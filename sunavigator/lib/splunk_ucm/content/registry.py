"""Provider registry: maps provider ids to implementations and normalizers."""

from typing import Any, Callable, Dict

from ..errors import ValidationError
from .bundle import OfflineBundleProvider
from .fenre.normalizer import FenreNormalizer, fenre_validation_policy
from .fenre.provider import FenreConfig, FenreJsonProvider, load_bundled_schema
from .http import HttpConfig
from .provider import ContentProvider, Normalizer, ProviderManifest
from .validation import RecordValidator

_NORMALIZERS: Dict[str, Callable[[], Normalizer]] = {"fenre": FenreNormalizer}


def _fenre_validator(manifest: ProviderManifest) -> RecordValidator:
    return RecordValidator(fenre_validation_policy(), manifest.schema or load_bundled_schema())


_VALIDATORS: Dict[str, Callable[[ProviderManifest], RecordValidator]] = {"fenre": _fenre_validator}


def supported_providers():
    return sorted(_NORMALIZERS)


def normalizer_for(provider_id: str) -> Normalizer:
    try:
        return _NORMALIZERS[provider_id]()
    except KeyError:
        raise ValidationError("unsupported provider", {"provider": provider_id})


def bundle_provider(bundle: Dict[str, Any]) -> OfflineBundleProvider:
    provider_id = bundle.get("provider") if isinstance(bundle, dict) else None
    if provider_id not in _NORMALIZERS:
        raise ValidationError("unsupported provider in bundle", {"provider": provider_id})
    return OfflineBundleProvider(bundle, normalizer_for(provider_id), _VALIDATORS[provider_id])


def remote_provider(provider_id: str, settings: Dict[str, Any], token: str = "",
                    ref_override: str = "") -> ContentProvider:
    if provider_id != "fenre":
        raise ValidationError("unsupported remote provider", {"provider": provider_id})
    cfg = FenreConfig(
        owner=settings.get("owner", "fenre"), repo=settings.get("repo", "splunk-monitoring-use-cases"),
        ref=ref_override or settings.get("ref", "main"),
        api_base=settings.get("api_base", "https://api.github.com"),
        raw_base=settings.get("raw_base", "https://raw.githubusercontent.com"),
        content_root=settings.get("content_root", "content"),
        schema_path=settings.get("schema_path", "schemas/uc.schema.json"),
        version_path=settings.get("version_path", "VERSION"),
        fetch_concurrency=int(settings.get("fetch_concurrency", 4)), token=token)
    from urllib.parse import urlparse
    hosts = [urlparse(cfg.api_base).hostname or "", urlparse(cfg.raw_base).hostname or ""]
    extra = [h.strip() for h in str(settings.get("allowed_hosts", "")).split(",") if h.strip()]
    allowed = set(extra or hosts)
    if not set(hosts) <= allowed:
        raise ValidationError("provider hosts are not in allowed_hosts", {"hosts": hosts})
    http = HttpConfig(allowed_hosts=sorted(allowed), timeout=float(settings.get("timeout", 30)),
                      max_attempts=int(settings.get("max_attempts", 4)),
                      proxy_url=settings.get("proxy_url", ""), ca_bundle=settings.get("ca_bundle", ""))
    return FenreJsonProvider(cfg, http_config=http)

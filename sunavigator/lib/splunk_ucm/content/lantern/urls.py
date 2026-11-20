"""Splunk Lantern URL validation and canonicalization.

Only ``https://lantern.splunk.com/<page>`` is accepted. Validation uses URL
parsing, never substring matching, and runs before any network request and
again on every redirect target and discovered link.
"""

import hashlib
import ipaddress
import posixpath
import re
from typing import Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urljoin, urlsplit

from ...errors import ValidationError

HOST = "lantern.splunk.com"
BASE_URL = "https://" + HOST
MAX_URL_LENGTH = 2048

# MindTouch namespaces and service paths that are never use-case content.
_BLOCKED_PREFIXES = ("/@", "/deki/", "/special:", "/template:", "/user:", "/user_talk:", "/talk:",
                     "/file:", "/index.php")
_FILE_EXTENSIONS = (".pdf", ".zip", ".gz", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                    ".mp4", ".mov", ".mp3", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
                    ".json", ".xml", ".txt", ".js", ".css", ".tgz", ".spl", ".exe", ".dmg")
_CONTROL = re.compile(r"[\x00-\x20\x7f\\]")
# Characters kept literally in canonical paths; everything else is percent-encoded.
_PATH_SAFE = "/_-.~()!*:@'"
RECORD_ID_RE = re.compile(r"^LN-[0-9a-f]{20}$")


class LanternUrlError(ValidationError):
    code = "invalid_lantern_url"

    def __init__(self, reason: str, message: str, url: str = ""):
        super().__init__(message, {"reason": reason, "url": url[:200]})
        self.reason = reason


def _is_ip_literal(host: str) -> bool:
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    # Integer, octal and hex host forms that some resolvers treat as IPv4.
    return bool(re.match(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}$", candidate, re.IGNORECASE))


def _canonical_path(raw_path: str, url: str) -> str:
    try:
        path = unquote(raw_path or "/", encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise LanternUrlError("malformed", "The URL path is not valid UTF-8.", url)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path) or "\\" in path:
        raise LanternUrlError("malformed", "The URL path contains control characters.", url)
    path = path.replace(" ", "_")
    if not path.startswith("/"):
        path = "/" + path
    segments = path.split("/")
    if any(seg in ("..", ".") for seg in segments):
        raise LanternUrlError("malformed", "The URL path must not contain '.' or '..' segments.", url)
    path = posixpath.normpath(re.sub(r"/{2,}", "/", path))
    if path != "/":
        path = path.rstrip("/")
    return path


def validate_url(url: str) -> str:
    """Return the canonical form of a Lantern page URL or raise :class:`LanternUrlError`."""
    if not isinstance(url, str) or not url.strip():
        raise LanternUrlError("empty", "Enter the URL of a Splunk Lantern page.")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise LanternUrlError("too_long", "The URL is longer than %d characters." % MAX_URL_LENGTH, url)
    if _CONTROL.search(url):
        raise LanternUrlError("malformed", "The URL contains spaces, backslashes or control characters.", url)
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise LanternUrlError("malformed", "The URL could not be parsed.", url)
    scheme = parts.scheme.lower()
    if scheme == "http":
        raise LanternUrlError("not_https", "Only https:// URLs are accepted. Use https://%s/..." % HOST, url)
    if scheme != "https":
        raise LanternUrlError("unsupported_scheme", "Only https:// URLs on %s are accepted." % HOST, url)
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise LanternUrlError("credentials", "URLs containing user names or passwords are not accepted.", url)
    host = (parts.hostname or "").lower()
    if not host:
        raise LanternUrlError("malformed", "The URL has no host name.", url)
    if _is_ip_literal(host):
        raise LanternUrlError("ip_address", "IP addresses are not accepted; use https://%s/..." % HOST, url)
    if host != HOST:
        raise LanternUrlError("host_not_allowed", "Only pages on %s are accepted (got %s)." % (HOST, host[:100]), url)
    if port not in (None, 443):
        raise LanternUrlError("port_not_allowed", "Only the default https port is accepted.", url)

    raw_path = parts.path
    query = parse_qs(parts.query, keep_blank_values=False)
    # MindTouch also serves pages as /?title=<path> and /index.php?title=<path>.
    if raw_path in ("", "/", "/index.php") and query.get("title"):
        raw_path = "/" + query["title"][0].lstrip("/")
    path = _canonical_path(raw_path, url)
    lowered = path.lower()
    if any(lowered.startswith(p) for p in _BLOCKED_PREFIXES):
        raise LanternUrlError("unsupported_page", "This is a Lantern service or account page, not a content page.", url)
    if lowered.endswith(_FILE_EXTENSIONS):
        raise LanternUrlError("unsupported_page", "This URL points to a file, not a Lantern article.", url)
    return BASE_URL + quote(path, safe=_PATH_SAFE)


def try_canonical(url: str) -> Tuple[Optional[str], str]:
    """``(canonical, "")`` or ``(None, reason)`` without raising."""
    try:
        return validate_url(url), ""
    except LanternUrlError as exc:
        return None, exc.reason


def resolve_link(base_url: str, href: str) -> Tuple[Optional[str], str]:
    """Resolve a link found on ``base_url``; returns ``(canonical, "")`` or ``(None, reason)``."""
    href = (href or "").strip()
    if not href or href.startswith("#"):
        return None, "anchor"
    if re.match(r"^(mailto|javascript|data|tel|ftp|file):", href, re.IGNORECASE):
        return None, "unsupported_scheme"
    absolute = urljoin(base_url, href)
    if urlsplit(absolute).scheme.lower() == "http":
        absolute = "https" + absolute[4:]
    return try_canonical(absolute)


def path_of(canonical_url: str) -> str:
    return unquote(urlsplit(canonical_url).path)


def path_segments(canonical_url: str):
    return [s for s in path_of(canonical_url).split("/") if s]


def record_id_for(canonical_url: str) -> str:
    """Stable record id derived from the canonical URL (the article's identity)."""
    digest = hashlib.sha256(path_of(canonical_url).encode("utf-8")).hexdigest()
    return "LN-" + digest[:20]


def segment_label(segment: str) -> str:
    return unquote(segment).replace("_", " ").strip()

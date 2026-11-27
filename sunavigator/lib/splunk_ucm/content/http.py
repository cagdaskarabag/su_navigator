"""Outbound HTTPS client for content providers.

* https only, host allowlist (checked again on every redirect), TLS verification always on
* credentials are dropped when a redirect leaves the host
* response size cap enforced while streaming
* retries with exponential backoff + jitter on transient failures; honours
  ``Retry-After`` and GitHub's ``X-RateLimit-Reset`` within a bounded wait
"""

import dataclasses
import random
import ssl
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

from .. import __version__
from ..errors import ProviderError, RateLimitedError
from ..log import get_logger

log = get_logger(__name__)

_RETRY_STATUS = {429, 500, 502, 503, 504}


@dataclasses.dataclass
class HttpConfig:
    allowed_hosts: Sequence[str]
    timeout: float = 30.0
    max_bytes: int = 8 * 1024 * 1024
    max_attempts: int = 4
    backoff_base: float = 2.0
    backoff_max: float = 32.0
    max_rate_limit_wait: float = 60.0
    proxy_url: str = ""
    ca_bundle: str = ""
    user_agent: str = "sunavigator/" + __version__


@dataclasses.dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes
    url: str


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an https URL on the allowlist; never forward credentials to another host."""

    def __init__(self, check: Callable[[str], None]):
        super().__init__()
        self._check = check

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urljoin(req.full_url, newurl)
        self._check(target)
        redirected = super().redirect_request(req, fp, code, msg, headers, target)
        if redirected is not None and (urlparse(target).hostname or "").lower() != (urlparse(req.full_url).hostname or "").lower():
            for name in ("Authorization", "Cookie", "Proxy-Authorization"):
                redirected.remove_header(name)
        return redirected


class HttpFetcher:
    def __init__(self, config: HttpConfig, sleep: Callable[[float], None] = time.sleep,
                 opener: Optional[Callable[..., object]] = None):
        self.config = config
        self._sleep = sleep
        self._opener = opener or self._build_opener()
        self.request_count = 0

    def _build_opener(self) -> Callable[..., object]:
        ctx = ssl.create_default_context(cafile=self.config.ca_bundle or None)
        handlers = [urllib.request.HTTPSHandler(context=ctx), _CheckedRedirects(self.check_url)]
        if self.config.proxy_url:
            handlers.append(urllib.request.ProxyHandler({"https": self.config.proxy_url}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        return urllib.request.build_opener(*handlers).open

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ProviderError("refusing non-https URL", {"url": url})
        host = (parsed.hostname or "").lower()
        if host not in {h.lower() for h in self.config.allowed_hosts}:
            raise ProviderError("host not in allowlist", {"host": host})

    def get(self, url: str, headers: Optional[Dict[str, str]] = None,
            max_bytes: Optional[int] = None) -> HttpResponse:
        self.check_url(url)
        limit = max_bytes or self.config.max_bytes
        req_headers = {"User-Agent": self.config.user_agent}
        req_headers.update(headers or {})
        last_error: Optional[Exception] = None
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                status, resp_headers, body = self._once(url, req_headers, limit)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                last_error = exc
                log.warning("http transient failure", extra={"url": url, "attempt": attempt,
                                                             "error": str(exc)})
                self._backoff(attempt, None)
                continue
            if status < 400:
                return HttpResponse(status, resp_headers, body, url)
            wait = self._rate_limit_wait(status, resp_headers)
            if wait is not None:
                if wait > self.config.max_rate_limit_wait:
                    reset = resp_headers.get("x-ratelimit-reset")
                    raise RateLimitedError(
                        "provider rate limit exceeded", float(reset) if reset else None,
                        details={"url": url, "status": status})
                self._sleep(wait)
                continue
            if status in _RETRY_STATUS and attempt < self.config.max_attempts:
                self._backoff(attempt, resp_headers.get("retry-after"))
                continue
            raise ProviderError("HTTP %d from provider" % status,
                                {"url": url, "status": status})
        raise ProviderError("provider unreachable after retries",
                            {"url": url, "error": str(last_error) if last_error else ""})

    def _once(self, url: str, headers: Dict[str, str], limit: int) -> Tuple[int, Dict[str, str], bytes]:
        self.request_count += 1
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            resp = self._opener(req, timeout=self.config.timeout)
        except urllib.error.HTTPError as exc:
            hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
            return exc.code, hdrs, b""
        try:
            status = getattr(resp, "status", None) or resp.getcode()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            declared = hdrs.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                raise ProviderError("response exceeds size limit", {"url": url, "limit": limit})
            chunks = []
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ProviderError("response exceeds size limit", {"url": url, "limit": limit})
                chunks.append(chunk)
            return status, hdrs, b"".join(chunks)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()

    def _rate_limit_wait(self, status: int, headers: Dict[str, str]) -> Optional[float]:
        if status not in (403, 429):
            return None
        if headers.get("x-ratelimit-remaining") == "0":
            reset = headers.get("x-ratelimit-reset", "")
            try:
                return max(0.0, float(reset) - time.time()) + 1.0
            except ValueError:
                return self.config.max_rate_limit_wait + 1
        retry_after = headers.get("retry-after")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                return None
        return None

    def _backoff(self, attempt: int, retry_after: Optional[str]) -> None:
        if attempt >= self.config.max_attempts:
            return
        delay = min(self.config.backoff_max, self.config.backoff_base ** attempt)
        if retry_after:
            try:
                delay = min(self.config.backoff_max, float(retry_after))
            except ValueError:
                pass
        self._sleep(delay + random.uniform(0, delay / 4))  # nosec - jitter, not crypto

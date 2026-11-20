"""SSRF-safe, rate-limited retrieval of Splunk Lantern pages.

* Every URL (including each redirect target) passes :func:`urls.validate_url`.
* The host name is resolved once per request; private, loopback, link-local,
  multicast and reserved addresses are refused and the TLS connection is made
  to the vetted address (with SNI and certificate checks for the real host),
  so DNS rebinding cannot redirect the request.
* Redirects are followed manually and bounded; responses are bounded in time
  and size and must be HTML. robots.txt rules and crawl delay are honoured.
"""

import dataclasses
import http.client
import ipaddress
import re
import socket
import ssl
import time
import zlib
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlsplit

from ... import __version__
from ...errors import ProviderError
from .robots import RobotsPolicy
from .urls import BASE_URL, HOST, LanternUrlError, validate_url

USER_AGENT = "SUNavigator/%s (Splunk app; user-directed Lantern import)" % __version__
_REDIRECTS = (301, 302, 303, 307, 308)
_HTML_TYPES = ("text/html", "application/xhtml+xml")
_ROBOTS_TTL = 24 * 3600


class LanternFetchError(ProviderError):
    """Retrieval failed; ``code`` is one of the ``lantern_*`` codes below."""

    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.code = code


@dataclasses.dataclass
class FetchSettings:
    timeout: float = 15.0
    max_bytes: int = 3 * 1024 * 1024
    max_redirects: int = 3
    min_interval: float = 5.0
    max_interval: float = 60.0
    max_requests: int = 100
    retries: int = 1
    proxy_url: str = ""
    ca_bundle: str = ""


@dataclasses.dataclass
class FetchResult:
    url: str
    status: int
    content_type: str
    text: str
    redirects: List[str]
    size: int


def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_private or ip.is_loopback
                                       or ip.is_link_local or ip.is_reserved or ip.is_unspecified)


def system_resolver(host: str) -> List[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to a pre-vetted IP that still verifies the real host's certificate."""

    def __init__(self, host: str, address: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._address = address
        self._ssl_context = context

    def connect(self) -> None:
        sock = socket.create_connection((self._address, 443), self.timeout)
        self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)


class Response:
    """Minimal response surface the fetcher needs (also implemented by test fakes)."""

    def __init__(self, status: int, headers: Dict[str, str], reader: Callable[[int], bytes],
                 closer: Optional[Callable[[], None]] = None):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self._reader = reader
        self._closer = closer

    def read(self, amount: int) -> bytes:
        return self._reader(amount)

    def close(self) -> None:
        if self._closer:
            self._closer()


class HttpsTransport:
    """Real network transport: DNS vetting, IP pinning, TLS verification, optional CONNECT proxy."""

    def __init__(self, settings: FetchSettings, resolver: Callable[[str], Sequence[str]] = system_resolver):
        self.settings = settings
        self.resolver = resolver

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.settings.ca_bundle or None)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def vetted_address(self, host: str) -> str:
        if host != HOST:
            raise LanternFetchError("lantern_network_blocked", "Refusing to connect to %s." % host[:100])
        try:
            addresses = list(self.resolver(host))
        except (OSError, UnicodeError) as exc:
            raise LanternFetchError("lantern_unavailable", "Could not resolve %s: %s" % (host, exc))
        if not addresses:
            raise LanternFetchError("lantern_unavailable", "%s did not resolve to any address." % host)
        blocked = [a for a in addresses if not _is_public(a)]
        if blocked:
            raise LanternFetchError(
                "lantern_network_blocked",
                "%s resolved to a non-public address; the request was blocked." % host,
                {"addresses": blocked[:5]})
        return addresses[0]

    def open(self, host: str, path: str, headers: Dict[str, str], timeout: float) -> Response:
        context = self._context()
        if self.settings.proxy_url:
            proxy = urlsplit(self.settings.proxy_url)
            if proxy.scheme != "http" or not proxy.hostname:
                raise LanternFetchError("lantern_config", "proxy_url must be an http:// CONNECT proxy.")
            conn: http.client.HTTPSConnection = http.client.HTTPSConnection(
                proxy.hostname, proxy.port or 3128, timeout=timeout, context=context)
            conn.set_tunnel(host, 443)
        else:
            conn = _PinnedHTTPSConnection(host, self.vetted_address(host), timeout, context)
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        return Response(resp.status, dict(resp.getheaders()), resp.read, conn.close)


class RateGate:
    """Spaces requests at least ``interval`` seconds apart, across processes when ``state`` persists."""

    def __init__(self, interval: float, load: Optional[Callable[[], float]] = None,
                 save: Optional[Callable[[float], None]] = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self.interval = interval
        self._load = load
        self._save = save
        self._clock = clock
        self._sleep = sleep
        self._last = 0.0

    def wait(self) -> None:
        last = self._last
        if self._load:
            try:
                last = max(last, float(self._load() or 0.0))
            except (TypeError, ValueError):
                pass
        delay = last + self.interval - self._clock()
        if delay > 0:
            self._sleep(min(delay, self.interval))
        self._last = self._clock()
        if self._save:
            self._save(self._last)


class LanternFetcher:
    def __init__(self, settings: Optional[FetchSettings] = None, transport: Any = None,
                 gate: Optional[RateGate] = None,
                 robots_load: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
                 robots_save: Optional[Callable[[Dict[str, Any]], None]] = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self.settings = settings or FetchSettings()
        self.transport = transport or HttpsTransport(self.settings)
        self.gate = gate or RateGate(self.settings.min_interval, clock=clock, sleep=sleep)
        self._robots_load = robots_load
        self._robots_save = robots_save
        self._robots: Optional[RobotsPolicy] = None
        self._clock = clock
        self._sleep = sleep
        self.requests_made = 0

    # -- robots ---------------------------------------------------------------------------------
    def robots(self) -> RobotsPolicy:
        if self._robots is not None:
            return self._robots
        cached = self._robots_load() if self._robots_load else None
        if cached and self._clock() - float(cached.get("fetched_at") or 0) < _ROBOTS_TTL:
            self._robots = self._policy_from(cached)
        else:
            doc = self._download_robots()
            if self._robots_save:
                self._robots_save(doc)
            self._robots = self._policy_from(doc)
        if self._robots.crawl_delay:
            delay = min(self._robots.crawl_delay, self.settings.max_interval)
            self.gate.interval = max(self.gate.interval, delay)
        return self._robots

    @staticmethod
    def _policy_from(doc: Dict[str, Any]) -> RobotsPolicy:
        status = int(doc.get("status") or 0)
        if status in (401, 403):
            return RobotsPolicy.deny_everything()
        if status >= 400 or not doc.get("text"):
            return RobotsPolicy.allow_everything()
        return RobotsPolicy.parse(doc.get("text", ""))

    def _download_robots(self) -> Dict[str, Any]:
        try:
            resp = self._request("/robots.txt")
        except LanternFetchError as exc:
            raise LanternFetchError("lantern_unavailable",
                                    "robots.txt could not be retrieved, so no pages were requested: %s" % exc.message)
        try:
            if resp.status >= 500:
                raise LanternFetchError("lantern_unavailable",
                                        "robots.txt returned HTTP %d; no pages were requested." % resp.status)
            text = ""
            if resp.status == 200:
                text = self._read_body(resp, 512 * 1024).decode("utf-8", "replace")
            return {"status": resp.status, "text": text, "fetched_at": self._clock()}
        finally:
            resp.close()

    # -- pages ----------------------------------------------------------------------------------
    def fetch_page(self, url: str) -> FetchResult:
        current = validate_url(url)
        redirects: List[str] = []
        policy = self.robots()
        for _ in range(self.settings.max_redirects + 1):
            path = current[len(BASE_URL):] or "/"
            if not policy.allowed(path):
                raise LanternFetchError("lantern_robots_disallowed",
                                        "Lantern's robots.txt does not allow automated access to this page.",
                                        {"url": current})
            resp = self._request_with_retry(path)
            try:
                if resp.status in _REDIRECTS:
                    location = resp.headers.get("location", "")
                    if not location:
                        raise LanternFetchError("lantern_unavailable", "Redirect without a Location header.")
                    target = urljoin(current, location)
                    try:
                        current = validate_url(target)
                    except LanternUrlError as exc:
                        raise LanternFetchError("lantern_redirect_rejected",
                                                "The page redirected outside Splunk Lantern (%s); not followed."
                                                % exc.reason, {"location": target[:200]})
                    redirects.append(current)
                    continue
                return self._finish(current, resp, redirects)
            finally:
                resp.close()
        raise LanternFetchError("lantern_redirect_rejected",
                                "Too many redirects (limit %d)." % self.settings.max_redirects)

    def _finish(self, url: str, resp: Response, redirects: List[str]) -> FetchResult:
        if resp.status in (404, 410):
            raise LanternFetchError("lantern_not_found", "The page does not exist on Splunk Lantern (HTTP %d)."
                                    % resp.status, {"url": url})
        if resp.status in (401, 403):
            raise LanternFetchError("lantern_unavailable", "Splunk Lantern refused access to the page (HTTP %d)."
                                    % resp.status, {"url": url})
        if resp.status != 200:
            raise LanternFetchError("lantern_unavailable", "Splunk Lantern returned HTTP %d." % resp.status,
                                    {"url": url})
        ctype = resp.headers.get("content-type", "")
        mime = ctype.split(";", 1)[0].strip().lower()
        if mime not in _HTML_TYPES:
            raise LanternFetchError("lantern_not_html", "The URL did not return an HTML page (%s)."
                                    % (mime or "no content type"), {"url": url})
        body = self._read_body(resp, self.settings.max_bytes)
        charset = "utf-8"
        match = re.search(r"charset=([A-Za-z0-9._-]+)", ctype)
        if match:
            charset = match.group(1)
        try:
            text = body.decode(charset, "replace")
        except LookupError:
            text = body.decode("utf-8", "replace")
        return FetchResult(url=url, status=resp.status, content_type=mime, text=text,
                           redirects=redirects, size=len(body))

    def _read_body(self, resp: Response, limit: int) -> bytes:
        declared = resp.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            raise LanternFetchError("lantern_too_large", "The page is larger than the %d KB limit."
                                    % (limit // 1024))
        deadline = time.monotonic() + self.settings.timeout * 2
        chunks: List[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise LanternFetchError("lantern_timeout", "Reading the page took too long.")
            try:
                chunk = resp.read(65536)
            except socket.timeout:
                raise LanternFetchError("lantern_timeout", "Timed out reading the page.")
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise LanternFetchError("lantern_too_large", "The page is larger than the %d KB limit."
                                        % (limit // 1024))
            chunks.append(chunk)
        body = b"".join(chunks)
        encoding = resp.headers.get("content-encoding", "identity").lower().strip()
        if encoding in ("gzip", "x-gzip", "deflate"):
            wbits = 16 + zlib.MAX_WBITS if "gzip" in encoding else zlib.MAX_WBITS
            decoder = zlib.decompressobj(wbits)
            try:
                body = decoder.decompress(body, limit + 1)
            except zlib.error:
                raise LanternFetchError("lantern_unavailable", "The page could not be decompressed.")
            if len(body) > limit or decoder.unconsumed_tail:
                raise LanternFetchError("lantern_too_large", "The page is larger than the %d KB limit."
                                        % (limit // 1024))
        elif encoding not in ("", "identity"):
            raise LanternFetchError("lantern_unavailable", "Unsupported content encoding %s." % encoding[:40])
        return body

    def _request_with_retry(self, path: str) -> Response:
        attempt = 0
        while True:
            resp = self._request(path)
            if resp.status in (429, 502, 503, 504) and attempt < self.settings.retries:
                retry_after = resp.headers.get("retry-after", "")
                wait = float(retry_after) if retry_after.isdigit() else self.settings.min_interval * 2
                resp.close()
                if wait > 60:
                    raise LanternFetchError("lantern_rate_limited",
                                            "Splunk Lantern asked to retry after %d seconds; try again later."
                                            % int(wait))
                self._sleep(wait)
                attempt += 1
                continue
            if resp.status == 429:
                resp.close()
                raise LanternFetchError("lantern_rate_limited", "Splunk Lantern is rate limiting requests; "
                                        "try again later.")
            return resp

    def _request(self, path: str) -> Response:
        if self.requests_made >= self.settings.max_requests:
            raise LanternFetchError("lantern_request_limit", "The request limit for this operation (%d) was reached."
                                    % self.settings.max_requests)
        self.gate.wait()
        self.requests_made += 1
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.5",
                   "Accept-Encoding": "gzip", "Connection": "close"}
        try:
            return self.transport.open(HOST, path, headers, self.settings.timeout)
        except LanternFetchError:
            raise
        except socket.timeout:
            raise LanternFetchError("lantern_timeout", "Timed out connecting to Splunk Lantern.")
        except ssl.SSLError as exc:
            raise LanternFetchError("lantern_tls_error", "TLS verification with Splunk Lantern failed: %s"
                                    % getattr(exc, "reason", exc))
        except (OSError, http.client.HTTPException) as exc:
            raise LanternFetchError("lantern_unavailable", "Could not reach Splunk Lantern: %s" % exc)

"""Test doubles for the Splunk Lantern provider: a fake site, a fake clock, no network.

The fixture pages in tests/fixtures/lantern imitate Lantern's MindTouch markup
(body classes, content container, sections, classification, breadcrumbs,
featured-article blocks, guide listings and ``pre.language-none`` searches).
All of their text and searches are written for the tests; no Lantern article
content is copied. Paths mirror real Lantern URLs so URL handling is realistic.
"""

import gzip
import os
from typing import Callable, Dict, List, Optional, Tuple, Union

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.content.lantern.fetcher import FetchSettings, LanternFetcher, RateGate, Response
from splunk_ucm.content.lantern.urls import BASE_URL, validate_url

FIXTURES = os.path.join(helpers.ROOT, "tests", "fixtures", "lantern")

CISCO = BASE_URL + "/Splunk_and_Cisco_Use_Cases"
SECURITY = BASE_URL + "/Security_Use_Cases"
GUIDE = BASE_URL + "/Security_Use_Cases/Threat_Investigation"
EMPTY = BASE_URL + "/Security_Use_Cases/Empty_Guide"
ARTICLE = BASE_URL + "/Security_Use_Cases/Threat_Investigation/Investigating_phishing_attacks"
SINGLE = BASE_URL + "/Splunk_and_Cisco_Use_Cases/Sharing_information_in_a_global_operation"
MINIMAL = BASE_URL + "/Observability_Use_Cases/Troubleshoot/Short_note"
CISCO_ARTICLES = [
    BASE_URL + "/Security_Use_Cases/Security_Monitoring/Monitoring_Cisco_switches%2C_routers%2C_WLAN_"
               "controllers_and_access_points",
    BASE_URL + "/Observability_Use_Cases/Troubleshoot/Assuring_enterprise_WAN_services",
    BASE_URL + "/Security_Use_Cases/Threat_Hunting/Hunting_threats_in_firewall_logs",
]


def fixture(name: str) -> str:
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return handle.read()


def article_html(canonical_url: str, title: str, spl: str = "index=main sourcetype=test | stats count BY host",
                 intro: str = "") -> str:
    """A small synthetic topic article (used for collection children)."""
    intro = intro or ("Test introduction for %s. It explains the operational problem, the data that is needed and "
                      "the outcome the team expects after applying the guidance." % title)
    return """<!DOCTYPE html><html><head><link rel="canonical" href="%s"></head>
<body class="columbia-page-main columbia-article-topic"><h1 id="title">%s</h1>
<section class="mt-content-container"><p>%s</p>
<div class="mt-section"><h2>Data required</h2><ul><li>Test data source</li></ul></div>
<div class="mt-section"><h2>How to use Splunk software for this use case</h2>
<p>Run the following test search and review the results with the owning team before acting on them.</p>
<pre class="language-none">%s</pre></div>
<div class="mt-section"><h2>Possible outcomes</h2><p>Test outcome.</p></div>
</section></body></html>""" % (canonical_url, title, intro, spl)


Page = Union[str, Tuple[int, Dict[str, str], bytes], Callable[[], Response]]


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start
        self.sleeps: List[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeLanternSite:
    """Transport double keyed by request path; records every request it receives."""

    def __init__(self, robots: Optional[str] = None, robots_status: int = 200):
        self.pages: Dict[str, Page] = {}
        self.requests: List[Tuple[str, str, Dict[str, str]]] = []
        self.robots = fixture("robots.txt") if robots is None else robots
        self.robots_status = robots_status

    @staticmethod
    def path_for(url: str) -> str:
        return validate_url(url)[len(BASE_URL):] or "/"

    def add(self, url: str, page: Page) -> "FakeLanternSite":
        self.pages[self.path_for(url)] = page
        return self

    def add_fixture(self, url: str, name: str) -> "FakeLanternSite":
        return self.add(url, fixture(name))

    def redirect(self, url: str, location: str, status: int = 301) -> "FakeLanternSite":
        self.pages[self.path_for(url)] = (status, {"Location": location}, b"")
        return self

    def page_requests(self) -> List[str]:
        return [path for _host, path, _h in self.requests if path != "/robots.txt"]

    def open(self, host: str, path: str, headers: Dict[str, str], timeout: float) -> Response:
        self.requests.append((host, path, dict(headers)))
        if path == "/robots.txt":
            return _response(self.robots_status, {"Content-Type": "text/plain"}, self.robots.encode("utf-8"))
        page = self.pages.get(path)
        if page is None:
            return _response(404, {"Content-Type": "text/html"}, b"<html><body>Not found</body></html>")
        if callable(page):
            return page()
        if isinstance(page, tuple):
            status, hdrs, body = page
            return _response(status, hdrs, body)
        return _response(200, {"Content-Type": "text/html; charset=utf-8"}, page.encode("utf-8"))


def _response(status: int, headers: Dict[str, str], body: bytes, chunk: int = 8192) -> Response:
    state = {"pos": 0}

    def read(amount: int) -> bytes:
        start = state["pos"]
        piece = body[start:start + min(amount, chunk)]
        state["pos"] = start + len(piece)
        return piece

    return Response(status, headers, read)


def html_response(body: bytes, status: int = 200, **headers: str) -> Callable[[], Response]:
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    hdrs.update({k.replace("_", "-"): v for k, v in headers.items()})
    return lambda: _response(status, hdrs, body)


def gzip_page(html: str) -> Callable[[], Response]:
    return html_response(gzip.compress(html.encode("utf-8")), Content_Encoding="gzip")


def make_fetcher(site: FakeLanternSite, clock: Optional[FakeClock] = None, **settings) -> LanternFetcher:
    clock = clock or FakeClock()
    fs = FetchSettings(**settings)
    gate = RateGate(fs.min_interval, clock=clock.time, sleep=clock.sleep)
    return LanternFetcher(fs, transport=site, gate=gate, clock=clock.time, sleep=clock.sleep)


def standard_site() -> FakeLanternSite:
    """Every fixture page at its Lantern path, plus small articles for the Cisco collection entries."""
    site = FakeLanternSite()
    site.add_fixture(CISCO, "collection_cisco.html")
    site.add_fixture(SECURITY, "collection_security.html")
    site.add_fixture(GUIDE, "collection_guide.html")
    site.add_fixture(EMPTY, "collection_empty.html")
    site.add_fixture(ARTICLE, "article_full.html")
    site.add_fixture(SINGLE, "article_single_spl.html")
    site.add_fixture(MINIMAL, "article_minimal.html")
    site.add_fixture(BASE_URL + "/", "home.html")
    site.add_fixture(BASE_URL + "/Security_Use_Cases/Broken_page", "malformed.html")
    site.add_fixture(BASE_URL + "/Observability_Use_Cases/A", "unknown_template.html")
    titles = ["Monitoring Cisco switches, routers, WLAN controllers and access points",
              "Assuring enterprise WAN services", "Hunting threats in firewall logs"]
    for url, title in zip(CISCO_ARTICLES, titles):
        site.add(url, article_html(url, title, "index=netops sourcetype=cisco:ios | stats count BY host"))
    for name in ("Implementing_risk-based_alerting", "Building_a_SOAR_playbook"):
        url = GUIDE + "/" + name
        site.add(url, article_html(url, name.replace("_", " ")))
    return site


def session_fetcher(site: FakeLanternSite, clock: Optional[FakeClock] = None):
    """Factory for LanternWorker / tests: a fake-transport fetcher with the service's KV gate and robots cache."""
    clock = clock or FakeClock()

    def factory(service) -> LanternFetcher:
        real = service.make_fetcher()
        real.transport = site
        real.gate._clock = clock.time
        real.gate._sleep = clock.sleep
        real._clock = clock.time
        real._sleep = clock.sleep
        return real
    return factory


def drain(service, fetcher_factory, limit: int = 20) -> int:
    """Run the worker loop until no session is queued."""
    runs = 0
    while runs < limit:
        session = service.next_queued()
        if session is None:
            return runs
        service.process(session, fetcher_factory(service))
        runs += 1
    raise AssertionError("sessions kept re-queueing")

"""Splunk Lantern URL validation, robots.txt handling and the SSRF-safe fetcher (no network)."""

import socket
import unittest

import helpers  # noqa: F401
import lantern_fakes as LF
from splunk_ucm.content.lantern.fetcher import FetchSettings, HttpsTransport, LanternFetchError, RateGate
from splunk_ucm.content.lantern.robots import RobotsPolicy
from splunk_ucm.content.lantern.urls import (
    BASE_URL, LanternUrlError, RECORD_ID_RE, record_id_for, resolve_link, try_canonical, validate_url)


class UrlValidationTest(unittest.TestCase):
    def reason(self, url):
        with self.assertRaises(LanternUrlError) as ctx:
            validate_url(url)
        self.assertEqual(ctx.exception.code, "invalid_lantern_url")
        return ctx.exception.reason

    def test_accepts_and_canonicalizes_lantern_pages(self):
        cases = {
            "https://lantern.splunk.com/Splunk_and_Cisco_Use_Cases": LF.CISCO,
            "  https://lantern.splunk.com/Splunk_and_Cisco_Use_Cases/  ": LF.CISCO,
            "https://LANTERN.splunk.COM/Splunk_and_Cisco_Use_Cases#Security": LF.CISCO,
            "https://lantern.splunk.com/Splunk_and_Cisco_Use_Cases?utm_source=x": LF.CISCO,
            "https://lantern.splunk.com:443/Splunk_and_Cisco_Use_Cases": LF.CISCO,
            "https://lantern.splunk.com/?title=Splunk_and_Cisco_Use_Cases": LF.CISCO,
            "https://lantern.splunk.com/index.php?title=Splunk_and_Cisco_Use_Cases": LF.CISCO,
            "https://lantern.splunk.com//Splunk_and_Cisco_Use_Cases": LF.CISCO,
            "https://lantern.splunk.com/": BASE_URL + "/",
        }
        for given, expected in cases.items():
            self.assertEqual(validate_url(given), expected, given)

    def test_encoding_is_normalized_consistently(self):
        encoded = validate_url(LF.CISCO_ARTICLES[0])
        decoded = validate_url(LF.CISCO_ARTICLES[0].replace("%2C", ","))
        lower = validate_url(LF.CISCO_ARTICLES[0].replace("%2C", "%2c"))
        self.assertEqual(encoded, decoded)
        self.assertEqual(encoded, lower)
        self.assertIn("%2C", encoded)
        self.assertEqual(validate_url("https://lantern.splunk.com/A%20page"), BASE_URL + "/A_page")

    def test_rejects_lookalike_hosts(self):
        for url in ("https://lantern.splunk.com.evil.example/Security_Use_Cases",
                    "https://evil-lantern.splunk.com/Security_Use_Cases",
                    "https://xlantern.splunk.com/x", "https://lantern-splunk.com/x",
                    "https://lantern.splunk.co/x", "https://splunk.com/x", "https://docs.splunk.com/x",
                    "https://lantern.splunk.c\u03bfm/x", "https://xn--lantern-xyz.splunk.com/x",
                    "https://lantern.splunk.com./x"):
            self.assertEqual(self.reason(url), "host_not_allowed", url)

    def test_rejects_wrong_scheme(self):
        self.assertEqual(self.reason("http://lantern.splunk.com/Security_Use_Cases"), "not_https")
        for url in ("ftp://lantern.splunk.com/x", "javascript:alert(1)", "file:///etc/passwd",
                    "lantern.splunk.com/Security_Use_Cases", "//lantern.splunk.com/x"):
            self.assertEqual(self.reason(url), "unsupported_scheme", url)

    def test_rejects_credentials_and_userinfo_tricks(self):
        for url in ("https://user:pw@lantern.splunk.com/x", "https://user@lantern.splunk.com/x",
                    "https://lantern.splunk.com@evil.example/x", "https://lantern.splunk.com:443@evil.example/"):
            self.assertEqual(self.reason(url), "credentials", url)

    def test_rejects_ip_addresses_in_every_form(self):
        for url in ("https://127.0.0.1/x", "https://10.0.0.5/x", "https://169.254.169.254/latest/meta-data",
                    "https://[::1]/x", "https://[fd00::1]/x", "https://2130706433/x", "https://0x7f000001/x",
                    "https://0177.0.0.1/x", "https://127.1/x"):
            self.assertEqual(self.reason(url), "ip_address", url)

    def test_rejects_ports_and_malformed(self):
        self.assertEqual(self.reason("https://lantern.splunk.com:8443/x"), "port_not_allowed")
        self.assertEqual(self.reason("https://lantern.splunk.com:99999/x"), "malformed")
        self.assertEqual(self.reason("https://lantern.splunk.com/a b"), "malformed")
        self.assertEqual(self.reason("https://lantern.splunk.com\\@evil.example/"), "malformed")
        self.assertEqual(self.reason("https://lantern.splunk.com/x\x00y"), "malformed")
        self.assertEqual(self.reason("https://lantern.splunk.com/a/%2e%2e/b"), "malformed")
        self.assertEqual(self.reason("https://lantern.splunk.com/a/../b"), "malformed")
        self.assertEqual(self.reason("https://lantern.splunk.com/%ff"), "malformed")
        self.assertEqual(self.reason("https:///x"), "malformed")
        self.assertEqual(self.reason(""), "empty")
        self.assertEqual(self.reason("https://lantern.splunk.com/" + "a" * 3000), "too_long")

    def test_rejects_service_namespaces_and_files(self):
        for url in ("https://lantern.splunk.com/Special:Search?q=x", "https://lantern.splunk.com/@api/deki/pages",
                    "https://lantern.splunk.com/@go/page/123", "https://lantern.splunk.com/Template:Header",
                    "https://lantern.splunk.com/User:someone", "https://lantern.splunk.com/deki/cp",
                    "https://lantern.splunk.com/?title=Special:Search",
                    "https://lantern.splunk.com/files/guide.pdf", "https://lantern.splunk.com/a/b.zip"):
            self.assertEqual(self.reason(url), "unsupported_page", url)

    def test_resolve_link_and_record_ids(self):
        self.assertEqual(resolve_link(LF.CISCO, "Sharing_information"), (BASE_URL + "/Sharing_information", ""))
        self.assertEqual(resolve_link(LF.GUIDE, "/Security_Use_Cases")[0], LF.SECURITY)
        self.assertEqual(resolve_link(LF.CISCO, "http://lantern.splunk.com/Security_Use_Cases")[0], LF.SECURITY)
        self.assertEqual(resolve_link(LF.CISCO, "#top"), (None, "anchor"))
        self.assertEqual(resolve_link(LF.CISCO, "mailto:a@b.c"), (None, "unsupported_scheme"))
        self.assertEqual(resolve_link(LF.CISCO, "https://www.cisco.com/"), (None, "host_not_allowed"))
        self.assertEqual(try_canonical("http://x")[1], "not_https")
        rid = record_id_for(LF.ARTICLE)
        self.assertRegex(rid, RECORD_ID_RE)
        self.assertEqual(rid, record_id_for(validate_url(LF.ARTICLE + "/?x=1#y")))
        self.assertEqual(record_id_for(LF.CISCO_ARTICLES[0]),
                         record_id_for(validate_url(LF.CISCO_ARTICLES[0].replace("%2C", ","))))
        self.assertNotEqual(rid, record_id_for(LF.SINGLE))


class RobotsTest(unittest.TestCase):
    def test_lantern_style_rules(self):
        policy = RobotsPolicy.parse(LF.fixture("robots.txt"))
        self.assertTrue(policy.allowed("/Splunk_and_Cisco_Use_Cases"))
        self.assertTrue(policy.allowed("/Security_Use_Cases/Threat_Investigation"))
        self.assertFalse(policy.allowed("/Special:Search"))
        self.assertFalse(policy.allowed("/?title=Special:Search"))
        self.assertFalse(policy.allowed("/Some_Page?action=edit"))
        self.assertFalse(policy.allowed("/@api/deki/pages"))
        self.assertTrue(policy.allowed("/@api/deki/files/12/image.png"))
        self.assertEqual(policy.crawl_delay, 5)

    def test_specific_agent_group_wins_and_longest_match(self):
        policy = RobotsPolicy.parse("User-agent: *\nDisallow: /\n\nUser-agent: SUNavigator\n"
                                    "Disallow: /Private\nAllow: /Private/Public$\n")
        self.assertTrue(policy.allowed("/Security_Use_Cases"))
        self.assertFalse(policy.allowed("/Private/x"))
        self.assertTrue(policy.allowed("/Private/Public"))
        self.assertFalse(policy.allowed("/Private/Public/more"))

    def test_degenerate_inputs(self):
        self.assertTrue(RobotsPolicy.parse("").allowed("/anything"))
        self.assertTrue(RobotsPolicy.parse("garbage\nDisallow:\n").allowed("/x"))
        self.assertFalse(RobotsPolicy.deny_everything().allowed("/x"))
        self.assertIsNone(RobotsPolicy.parse("User-agent: *\nCrawl-delay: soon\n").crawl_delay)


class TransportVettingTest(unittest.TestCase):
    def transport(self, addresses):
        return HttpsTransport(FetchSettings(), resolver=lambda host: addresses)

    def test_blocks_private_loopback_link_local_and_mapped(self):
        for addrs in (["127.0.0.1"], ["10.1.2.3"], ["192.168.0.1"], ["172.16.4.4"], ["169.254.169.254"],
                      ["::1"], ["fe80::1"], ["fd12::1"], ["::ffff:127.0.0.1"], ["100.64.0.1"], ["0.0.0.0"],
                      ["203.0.113.10", "10.0.0.1"]):
            with self.assertRaises(LanternFetchError) as ctx:
                self.transport(addrs).vetted_address("lantern.splunk.com")
            self.assertEqual(ctx.exception.code, "lantern_network_blocked", addrs)

    def test_public_address_is_pinned(self):
        self.assertEqual(self.transport(["151.101.1.1"]).vetted_address("lantern.splunk.com"), "151.101.1.1")

    def test_refuses_other_hosts_and_resolution_failures(self):
        with self.assertRaises(LanternFetchError) as ctx:
            self.transport(["151.101.1.1"]).vetted_address("evil.example")
        self.assertEqual(ctx.exception.code, "lantern_network_blocked")

        def broken(host):
            raise socket.gaierror("no such host")
        with self.assertRaises(LanternFetchError) as ctx:
            HttpsTransport(FetchSettings(), resolver=broken).vetted_address("lantern.splunk.com")
        self.assertEqual(ctx.exception.code, "lantern_unavailable")
        with self.assertRaises(LanternFetchError):
            self.transport([]).vetted_address("lantern.splunk.com")

    def test_rejects_non_http_proxy(self):
        transport = HttpsTransport(FetchSettings(proxy_url="socks5://proxy:1080"))
        with self.assertRaises(LanternFetchError) as ctx:
            transport.open("lantern.splunk.com", "/", {}, 5)
        self.assertEqual(ctx.exception.code, "lantern_config")


class FetcherTest(unittest.TestCase):
    def setUp(self):
        self.site = LF.standard_site()
        self.clock = LF.FakeClock()

    def fetcher(self, **kw):
        return LF.make_fetcher(self.site, self.clock, **kw)

    def code(self, fetcher, url):
        with self.assertRaises(LanternFetchError) as ctx:
            fetcher.fetch_page(url)
        return ctx.exception.code

    def test_fetches_html_with_identifying_headers(self):
        result = self.fetcher().fetch_page(LF.CISCO + "/")
        self.assertEqual(result.url, LF.CISCO)
        self.assertEqual(result.status, 200)
        self.assertIn("Splunk and Cisco Use Cases", result.text)
        host, path, headers = self.site.requests[-1]
        self.assertEqual((host, path), ("lantern.splunk.com", "/Splunk_and_Cisco_Use_Cases"))
        self.assertTrue(headers["User-Agent"].startswith("SUNavigator/"))
        self.assertEqual(self.site.requests[0][1], "/robots.txt")

    def test_invalid_url_never_reaches_the_network(self):
        with self.assertRaises(LanternUrlError):
            self.fetcher().fetch_page("https://lantern.splunk.com.evil.example/")
        self.assertEqual(self.site.requests, [])

    def test_follows_validated_redirects(self):
        self.site.redirect(BASE_URL + "/Old_Cisco", "/Splunk_and_Cisco_Use_Cases", 301)
        result = self.fetcher().fetch_page(BASE_URL + "/Old_Cisco")
        self.assertEqual(result.url, LF.CISCO)
        self.assertEqual(result.redirects, [LF.CISCO])

    def test_rejects_redirects_off_lantern(self):
        for location in ("https://evil.example/", "http://lantern.splunk.com/Security_Use_Cases",
                         "https://169.254.169.254/latest", "https://lantern.splunk.com/Special:Login",
                         "https://user@lantern.splunk.com/x"):
            self.site.redirect(BASE_URL + "/Moved", location, 302)
            self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Moved"), "lantern_redirect_rejected", location)

    def test_redirect_limit(self):
        self.site.redirect(BASE_URL + "/Loop_A", "/Loop_B").redirect(BASE_URL + "/Loop_B", "/Loop_A")
        self.assertEqual(self.code(self.fetcher(max_redirects=3), BASE_URL + "/Loop_A"), "lantern_redirect_rejected")
        self.assertEqual(len(self.site.page_requests()), 4)

    def test_status_mapping(self):
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Does_not_exist"), "lantern_not_found")
        self.site.add(BASE_URL + "/Gone", (410, {"Content-Type": "text/html"}, b""))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Gone"), "lantern_not_found")
        self.site.add(BASE_URL + "/Denied", (403, {"Content-Type": "text/html"}, b""))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Denied"), "lantern_unavailable")
        self.site.add(BASE_URL + "/Down", (503, {"Content-Type": "text/html"}, b""))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Down"), "lantern_unavailable")

    def test_retries_once_after_rate_limit(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                return LF._response(429, {"Retry-After": "7"}, b"")
            return LF._response(200, {"Content-Type": "text/html"}, LF.fixture("article_minimal.html").encode())
        self.site.add(BASE_URL + "/Flaky", flaky)
        result = self.fetcher().fetch_page(BASE_URL + "/Flaky")
        self.assertEqual(result.status, 200)
        self.assertIn(7.0, self.clock.sleeps)
        self.site.add(BASE_URL + "/Busy", (429, {"Retry-After": "3600"}, b""))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Busy"), "lantern_rate_limited")
        self.site.add(BASE_URL + "/Busy", (429, {}, b""))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Busy"), "lantern_rate_limited")

    def test_content_type_and_size_limits(self):
        self.site.add(BASE_URL + "/Data", (200, {"Content-Type": "application/json"}, b"{}"))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Data"), "lantern_not_html")
        self.site.add(BASE_URL + "/Untyped", (200, {}, b"<html></html>"))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Untyped"), "lantern_not_html")
        big = b"<html>" + b"x" * 200_000
        self.site.add(BASE_URL + "/Big", (200, {"Content-Type": "text/html"}, big))
        self.assertEqual(self.code(self.fetcher(max_bytes=100_000), BASE_URL + "/Big"), "lantern_too_large")
        self.site.add(BASE_URL + "/Declared", (200, {"Content-Type": "text/html", "Content-Length": "999999999"},
                                               b"<html></html>"))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Declared"), "lantern_too_large")

    def test_gzip_is_decoded_and_bombs_are_capped(self):
        self.site.add(BASE_URL + "/Zipped", LF.gzip_page(LF.fixture("article_full.html")))
        self.assertIn("Investigating phishing attacks", self.fetcher().fetch_page(BASE_URL + "/Zipped").text)
        self.site.add(BASE_URL + "/Bomb", LF.gzip_page("<html>" + "A" * 5_000_000))
        self.assertEqual(self.code(self.fetcher(max_bytes=1_000_000), BASE_URL + "/Bomb"), "lantern_too_large")
        self.site.add(BASE_URL + "/Corrupt", LF.html_response(b"not gzip", Content_Encoding="gzip"))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Corrupt"), "lantern_unavailable")
        self.site.add(BASE_URL + "/Brotli", LF.html_response(b"x", Content_Encoding="br"))
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Brotli"), "lantern_unavailable")

    def test_timeouts_and_transport_errors(self):
        def slow_read():
            def read(_n):
                raise socket.timeout("timed out")
            return LF.Response(200, {"Content-Type": "text/html"}, read)
        self.site.add(BASE_URL + "/Slow", slow_read)
        self.assertEqual(self.code(self.fetcher(), BASE_URL + "/Slow"), "lantern_timeout")

        class Raising(LF.FakeLanternSite):
            def __init__(self, exc):
                super().__init__()
                self.exc = exc

            def open(self, host, path, headers, timeout):
                if path == "/robots.txt":
                    return super().open(host, path, headers, timeout)
                raise self.exc
        for exc, code in ((socket.timeout("t"), "lantern_timeout"), (ConnectionRefusedError("no"), "lantern_unavailable")):
            fetcher = LF.make_fetcher(Raising(exc), self.clock)
            with self.assertRaises(LanternFetchError) as ctx:
                fetcher.fetch_page(LF.CISCO)
            self.assertEqual(ctx.exception.code, code)

    def test_charset_is_honoured(self):
        body = "<html><body><h1>Caf\u00e9</h1></body></html>".encode("latin-1")
        self.site.add(BASE_URL + "/Latin", (200, {"Content-Type": "text/html; charset=iso-8859-1"}, body))
        self.assertIn("Caf\u00e9", self.fetcher().fetch_page(BASE_URL + "/Latin").text)

    def test_robots_disallow_blocks_before_request(self):
        self.site.robots = "User-agent: *\nDisallow: /Security_Use_Cases\nCrawl-delay: 5\n"
        self.assertEqual(self.code(self.fetcher(), LF.SECURITY), "lantern_robots_disallowed")
        self.assertEqual(self.site.page_requests(), [])

    def test_robots_unavailable_stops_everything(self):
        self.site.robots_status = 503
        self.assertEqual(self.code(self.fetcher(), LF.CISCO), "lantern_unavailable")
        self.assertEqual(self.site.page_requests(), [])

    def test_robots_status_semantics(self):
        self.site.robots_status = 404
        self.assertEqual(self.fetcher().fetch_page(LF.CISCO).status, 200)
        self.site.robots_status = 401
        self.assertEqual(self.code(self.fetcher(), LF.CISCO), "lantern_robots_disallowed")

    def test_robots_cache_is_reused(self):
        cache = {}
        fetcher = LF.make_fetcher(self.site, self.clock)
        fetcher._robots_save = lambda doc: cache.update(doc=doc)
        fetcher.fetch_page(LF.CISCO)
        again = LF.make_fetcher(self.site, self.clock)
        again._robots_load = lambda: cache["doc"]
        before = len(self.site.requests)
        again.fetch_page(LF.SECURITY)
        self.assertEqual([p for _h, p, _x in self.site.requests[before:]], ["/Security_Use_Cases"])

    def test_crawl_delay_spaces_requests(self):
        fetcher = self.fetcher(min_interval=1)
        fetcher.fetch_page(LF.CISCO)
        fetcher.fetch_page(LF.SECURITY)
        fetcher.fetch_page(LF.GUIDE)
        self.assertEqual(fetcher.gate.interval, 5)
        self.assertGreaterEqual(len([s for s in self.clock.sleeps if s >= 4.9]), 2)

    def test_rate_gate_is_shared_through_state(self):
        clock = LF.FakeClock()
        state = {"last": clock.time()}
        gate = RateGate(5, load=lambda: state["last"], save=lambda v: state.update(last=v),
                        clock=clock.time, sleep=clock.sleep)
        gate.wait()
        self.assertEqual(clock.sleeps, [5.0])
        self.assertEqual(state["last"], clock.time())

    def test_request_limit(self):
        fetcher = self.fetcher(max_requests=2)
        fetcher.fetch_page(LF.CISCO)
        self.assertEqual(self.code(fetcher, LF.SECURITY), "lantern_request_limit")


if __name__ == "__main__":
    unittest.main()

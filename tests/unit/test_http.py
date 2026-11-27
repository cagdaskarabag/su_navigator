import http.server
import io
import threading
import time
import unittest
import urllib.error
import urllib.request
from email.message import Message

import helpers  # noqa: F401
from splunk_ucm.content.http import HttpConfig, HttpFetcher, _CheckedRedirects
from splunk_ucm.errors import ProviderError, RateLimitedError


class FakeResponse:
    def __init__(self, body=b"ok", status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self._buf = io.BytesIO(body)

    def read(self, n=-1):
        return self._buf.read(n)

    def close(self):
        pass


def http_error(code, headers=None):
    msg = Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError("https://api.github.com/x", code, "err", msg, None)


class ScriptedOpener:
    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    def __call__(self, req, timeout=None):
        self.calls.append((req.full_url, dict(req.header_items())))
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def fetcher(opener, **kw):
    sleeps = []
    cfg = HttpConfig(allowed_hosts=["api.github.com", "raw.githubusercontent.com"], **kw)
    return HttpFetcher(cfg, sleep=sleeps.append, opener=opener), sleeps


class HttpFetcherTest(unittest.TestCase):
    def test_success_sets_user_agent(self):
        opener = ScriptedOpener(FakeResponse(b"hello"))
        f, _ = fetcher(opener)
        self.assertEqual(f.get("https://api.github.com/x").body, b"hello")
        headers = {k.lower(): v for k, v in opener.calls[0][1].items()}
        self.assertTrue(headers["user-agent"].startswith("splunk-use-case-manager/"))

    def test_rejects_non_https_and_unlisted_hosts(self):
        f, _ = fetcher(ScriptedOpener())
        for url in ("http://api.github.com/x", "https://evil.example.com/x", "file:///etc/passwd",
                    "https://api.github.com.evil.com/x"):
            with self.assertRaises(ProviderError):
                f.get(url)

    def test_retries_transient_errors_then_succeeds(self):
        opener = ScriptedOpener(urllib.error.URLError("reset"), http_error(503), FakeResponse(b"ok"))
        f, sleeps = fetcher(opener)
        self.assertEqual(f.get("https://api.github.com/x").body, b"ok")
        self.assertEqual(len(opener.calls), 3)
        self.assertEqual(len(sleeps), 2)

    def test_gives_up_after_max_attempts(self):
        opener = ScriptedOpener(*[http_error(502)] * 4)
        f, _ = fetcher(opener, max_attempts=4)
        with self.assertRaises(ProviderError) as ctx:
            f.get("https://api.github.com/x")
        self.assertEqual(ctx.exception.details.get("status"), 502)
        self.assertEqual(len(opener.calls), 4)

    def test_client_errors_not_retried(self):
        opener = ScriptedOpener(http_error(404))
        f, _ = fetcher(opener)
        with self.assertRaises(ProviderError):
            f.get("https://api.github.com/x")
        self.assertEqual(len(opener.calls), 1)

    def test_rate_limit_exhausted_raises_with_reset(self):
        reset = str(int(time.time()) + 3600)
        opener = ScriptedOpener(http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}))
        f, _ = fetcher(opener)
        with self.assertRaises(RateLimitedError) as ctx:
            f.get("https://api.github.com/x")
        self.assertEqual(ctx.exception.reset_epoch, float(reset))

    def test_short_rate_limit_wait_is_honoured(self):
        opener = ScriptedOpener(http_error(429, {"Retry-After": "2"}), FakeResponse(b"ok"))
        f, sleeps = fetcher(opener)
        self.assertEqual(f.get("https://api.github.com/x").body, b"ok")
        self.assertEqual(sleeps, [2.0])

    def test_size_cap_enforced_for_declared_and_streamed_bodies(self):
        f, _ = fetcher(ScriptedOpener(FakeResponse(b"x" * 10, headers={"Content-Length": "999999"})))
        with self.assertRaises(ProviderError):
            f.get("https://api.github.com/x", max_bytes=100)
        f, _ = fetcher(ScriptedOpener(FakeResponse(b"x" * 200000)))
        with self.assertRaises(ProviderError):
            f.get("https://api.github.com/x", max_bytes=100000)


class RedirectTest(unittest.TestCase):
    """Issue #49: a redirect is checked like the first request and never carries credentials to another host."""

    def handler(self):
        f, _ = fetcher(ScriptedOpener())
        return _CheckedRedirects(f.check_url)

    def request(self, url="https://api.github.com/x"):
        return urllib.request.Request(url, headers={"Authorization": "Bearer SECRET", "User-Agent": "t"})

    def redirect(self, target, url="https://api.github.com/x", code=302):
        return self.handler().redirect_request(self.request(url), None, code, "Found", Message(), target)

    def test_redirect_to_an_unlisted_host_is_refused(self):
        for target in ("https://evil.example.com/x", "https://api.github.com.evil.com/x", "https://127.0.0.1:8089/x",
                       "https://169.254.169.254/latest/meta-data"):
            with self.assertRaises(ProviderError, msg=target):
                self.redirect(target)

    def test_redirect_to_plain_http_or_another_scheme_is_refused(self):
        for target in ("http://api.github.com/x", "http://raw.githubusercontent.com/x", "file:///etc/passwd",
                       "ftp://api.github.com/x"):
            with self.assertRaises(ProviderError, msg=target):
                self.redirect(target)

    def test_a_relative_redirect_stays_on_the_host_and_keeps_the_token(self):
        new = self.redirect("/other/path")
        self.assertEqual(new.full_url, "https://api.github.com/other/path")
        self.assertEqual(new.get_header("Authorization"), "Bearer SECRET")

    def test_redirect_to_another_allowed_host_drops_credentials(self):
        new = self.redirect("https://raw.githubusercontent.com/o/r/main/f.json")
        self.assertEqual(new.full_url, "https://raw.githubusercontent.com/o/r/main/f.json")
        self.assertIsNone(new.get_header("Authorization"))
        self.assertEqual(new.get_header("User-agent"), "t")

    def test_a_redirect_loop_is_cut_by_urllib(self):
        self.assertEqual(self.handler().max_redirections, 10)

    def test_the_real_opener_does_not_follow_a_redirect_to_an_internal_server(self):
        seen = []

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        target = http.server.HTTPServer(("127.0.0.1", 0), Target)

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/secret" % target.server_address[1])
                self.end_headers()

            def log_message(self, *args):
                pass

        redirector = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        for server in (target, redirector):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            f, _ = fetcher(ScriptedOpener())
            opener = urllib.request.build_opener(_CheckedRedirects(f.check_url))
            with self.assertRaises(ProviderError):
                opener.open(self.request("http://127.0.0.1:%d/start" % redirector.server_address[1]), timeout=5)
        finally:
            for server in (target, redirector):
                server.shutdown()
                server.server_close()
        self.assertEqual(seen, [])

    def test_the_default_opener_uses_the_checked_handler(self):
        f = HttpFetcher(HttpConfig(allowed_hosts=["api.github.com"]))
        names = [type(h).__name__ for h in f._opener.__self__.handlers]
        self.assertIn("_CheckedRedirects", names)
        self.assertNotIn("HTTPRedirectHandler", names)


if __name__ == "__main__":
    unittest.main()

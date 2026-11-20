import io
import time
import unittest
import urllib.error
from email.message import Message

import helpers  # noqa: F401
from splunk_ucm.content.http import HttpConfig, HttpFetcher
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


if __name__ == "__main__":
    unittest.main()

"""Management-port HTTP transport for operator tools and live integration tests.

Kept outside the app package: the app talks to splunkd only through
``splunk.rest`` (see ``splunk_ucm.storage.transport``).
"""

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                "sunavigator", "lib"))

from splunk_ucm.errors import StorageError  # noqa: E402
from splunk_ucm.storage.transport import SplunkdTransport  # noqa: E402


class HttpTransport(SplunkdTransport):
    def __init__(self, base_url: str, token: str = "", username: str = "", password: str = "",
                 verify_tls: bool = True, ca_bundle: str = ""):
        self.base_url = base_url.rstrip("/")
        if token:
            self._auth = "Splunk " + token
        elif username:
            raw = ("%s:%s" % (username, password)).encode("utf-8")
            self._auth = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            raise ValueError("token or username required")
        if verify_tls:
            self._ctx = ssl.create_default_context(cafile=ca_bundle or None)
        else:
            # Explicit opt-in for local development against a self-signed splunkd.
            self._ctx = ssl._create_unverified_context()  # nosec

    def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        headers = {"Authorization": self._auth}
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form, doseq=True).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=timeout) as resp:  # nosec - fixed base URL
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read() or b""
        except (urllib.error.URLError, OSError) as exc:
            raise StorageError("splunkd connection failed: %s" % exc) from exc

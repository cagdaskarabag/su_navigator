"""SUNavigator never reads, stores, bundles or depends on Splunk Security Essentials (decision D-084, S5).

SSE is licensed under the Splunk General Terms, not Apache-2.0, and has no public source repository. Nothing in
the app or its tools may touch it. Documentation may name it (to say it is excluded) and the third-party Fenre fixtures quote it as text;
code, configuration and our own fixtures may not.
"""

import os
import re
import unittest

import helpers

PATTERN = re.compile(r"security[_ ]essentials|splunk_sse|\bsse_(?:app|import|content)|splunkbase\.splunk\.com/app/3435|\bssenav\b", re.IGNORECASE)
TEXT = (".py", ".js", ".conf", ".json", ".xml", ".html", ".csv", ".txt", ".spec", ".meta", ".manifest", ".sh", ".yml",
        ".yaml")
SELF = os.path.abspath(__file__)


def _files():
    for base in ("sunavigator", "tools", "tests"):
        for root, dirs, names in os.walk(os.path.join(helpers.ROOT, base)):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules", "fenre")]
            for name in names:
                full = os.path.join(root, name)
                if os.path.abspath(full) != SELF and name.endswith(TEXT):
                    yield full


class NoSseTest(unittest.TestCase):
    def test_no_code_configuration_or_fixture_refers_to_sse(self):
        hits = []
        for path in _files():
            with open(path, encoding="utf-8", errors="ignore") as handle:
                for number, line in enumerate(handle, 1):
                    if PATTERN.search(line):
                        hits.append("%s:%d" % (os.path.relpath(path, helpers.ROOT), number))
        self.assertEqual(hits, [], "SSE must not appear in code, config or fixtures (D-084 / S5)")

    def test_the_guard_matches_what_it_is_meant_to_catch(self):
        for sample in ("Splunk_Security_Essentials", "security essentials", "/app/3435".replace("/app/3435", "splunkbase.splunk.com/app/3435")):
            self.assertTrue(PATTERN.search(sample), sample)
        self.assertFalse(PATTERN.search("essential"))
        self.assertFalse(PATTERN.search("Security Service Edge (SSE)"))
        self.assertFalse(PATTERN.search("ESCU content"))


if __name__ == "__main__":
    unittest.main()

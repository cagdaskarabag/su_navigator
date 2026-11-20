"""Read-only checks against the REAL Splunk Lantern site.

Skipped unless UCM_LIVE_LANTERN=1. They use the production fetcher (DNS
vetting, TLS verification, robots.txt, at least 5 seconds between requests)
and request at most four pages. Lantern's layout can change; a failure here
means the extractor may need attention, not that unit behaviour regressed.
Optional: UCM_LANTERN_PROXY=http://proxy:3128 and UCM_LANTERN_CA_BUNDLE=/path.
"""

import os
import unittest

import helpers  # noqa: F401
from splunk_ucm.content.lantern import parser as P
from splunk_ucm.content.lantern.fetcher import FetchSettings, LanternFetcher
from splunk_ucm.content.lantern.sessions import preview_usecase

LIVE = os.environ.get("UCM_LIVE_LANTERN") == "1"
CISCO = "https://lantern.splunk.com/Splunk_and_Cisco_Use_Cases"


@unittest.skipUnless(LIVE, "set UCM_LIVE_LANTERN=1 to contact lantern.splunk.com")
class LiveLanternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fetcher = LanternFetcher(FetchSettings(max_requests=5,
                                                   proxy_url=os.environ.get("UCM_LANTERN_PROXY", ""),
                                                   ca_bundle=os.environ.get("UCM_LANTERN_CA_BUNDLE", "")))

    def test_cisco_collection_and_one_article(self):
        result = self.fetcher.fetch_page(CISCO)
        page, kind = P.parse(result.text, result.url)
        self.assertEqual(kind.kind, P.KIND_COLLECTION, kind.reason)
        collection = P.parse_collection(page)
        self.assertGreaterEqual(len(collection.items), 5)
        self.assertGreaterEqual(len(collection.categories), 2)
        urls = [i["url"] for i in collection.items]
        self.assertEqual(len(urls), len(set(urls)))
        self.assertTrue(all(u.startswith("https://lantern.splunk.com/") for u in urls))

        first = next(i for i in collection.items if i["kind_guess"] == P.KIND_ARTICLE)
        article = self.fetcher.fetch_page(first["url"])
        page, kind = P.parse(article.text, article.url)
        self.assertEqual(kind.kind, P.KIND_ARTICLE, kind.reason)
        raw = P.extract_article(page, "2026-01-01T00:00:00Z")
        self.assertTrue(raw["title"])
        self.assertTrue(raw["blocks"])
        uc = preview_usecase(raw)
        self.assertTrue(uc["content_id"].startswith("lantern:LN-"))
        self.assertLessEqual(self.fetcher.requests_made, 3)


if __name__ == "__main__":
    unittest.main()

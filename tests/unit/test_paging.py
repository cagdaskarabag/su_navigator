"""Paged list responses report the page size they used and the next offset (D-068)."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.readiness.query import ReadinessFilter, ReadinessQueryService
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore


class ReadinessPagingTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.store.batch_save(C.READINESS, [{"_key": "uc%04d" % i, "state": "ready", "score_sort": i,
                                             "criticality_rank": 1, "title": "t%04d" % i} for i in range(250)])
        self.service = ReadinessQueryService(self.store, max_page_size=100)

    def walk(self, requested):
        seen, offset = [], 0
        while offset is not None:
            page = self.service.search(ReadinessFilter(offset=offset, count=requested, sort="title"))
            seen.extend(row["_key"] for row in page["items"])
            offset = page["next_offset"]
        return seen

    def test_request_above_the_cap_returns_the_capped_page_size(self):
        page = self.service.search(ReadinessFilter(count=500, sort="title"))
        self.assertEqual((page["count"], len(page["items"]), page["has_more"], page["next_offset"]),
                         (100, 100, True, 100))

    def test_following_next_offset_returns_every_row_once(self):
        for requested in (25, 100, 500):
            with self.subTest(count=requested):
                seen = self.walk(requested)
                self.assertEqual(len(seen), 250)
                self.assertEqual(len(set(seen)), 250)

    def test_last_page_has_no_next_offset(self):
        page = self.service.search(ReadinessFilter(offset=200, count=100, sort="title"))
        self.assertEqual((len(page["items"]), page["has_more"], page["next_offset"]), (50, False, None))


if __name__ == "__main__":
    unittest.main()

import unittest

from splunk_ucm.errors import UnsupportedOperation, ValidationError
from splunk_ucm.platform.search import ONESHOT_ROW_CEILING, SearchClient


class SplunkdOneshot:
    """POST search/jobs exec_mode=oneshot as splunkd 10.2.9 answers it.

    ``count`` limits the rows returned (default 100, 0 = all) up to maxresultrows;
    ``max_count`` does not limit rows of a transforming search.
    """

    def __init__(self, rows=None, messages=None):
        self.rows = rows or []
        self.messages = messages or []
        self.forms = []

    def json(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        self.forms.append(dict(form or {}))
        count = int((form or {}).get("count", 100))
        limit = min(count or ONESHOT_ROW_CEILING, ONESHOT_ROW_CEILING)
        return {"results": [dict(r) for r in self.rows[:limit]], "messages": list(self.messages)}


def rows(n):
    return [{"i": str(i)} for i in range(n)]


class OneshotContractTest(unittest.TestCase):
    def test_more_than_100_rows_are_returned(self):
        t = SplunkdOneshot(rows(250))
        result = SearchClient(t).oneshot("| tstats count by sourcetype", max_count=5000)
        self.assertEqual(len(result.rows), 250)
        self.assertFalse(result.truncated)

    def test_requests_one_sentinel_row(self):
        t = SplunkdOneshot(rows(3))
        SearchClient(t).oneshot("| makeresults", max_count=40)
        self.assertEqual(t.forms[0]["count"], "41")
        self.assertEqual(t.forms[0]["max_count"], "41")
        self.assertEqual(t.forms[0]["exec_mode"], "oneshot")

    def test_truncated_only_when_more_rows_exist(self):
        client = SearchClient(SplunkdOneshot(rows(100)))
        exact = client.oneshot("| makeresults", max_count=100)
        self.assertEqual(len(exact.rows), 100)
        self.assertFalse(exact.truncated)
        below = SearchClient(SplunkdOneshot(rows(99))).oneshot("| makeresults", max_count=100)
        self.assertFalse(below.truncated)
        over = SearchClient(SplunkdOneshot(rows(101))).oneshot("| makeresults", max_count=100)
        self.assertEqual(len(over.rows), 100)
        self.assertTrue(over.truncated)

    def test_limit_stays_below_maxresultrows(self):
        t = SplunkdOneshot(rows(ONESHOT_ROW_CEILING + 10))
        result = SearchClient(t).oneshot("| makeresults", max_count=10 ** 6)
        self.assertEqual(t.forms[0]["count"], str(ONESHOT_ROW_CEILING))
        self.assertEqual(len(result.rows), ONESHOT_ROW_CEILING - 1)
        self.assertTrue(result.truncated)

    def test_minimum_limit_is_one(self):
        t = SplunkdOneshot(rows(5))
        result = SearchClient(t).oneshot("| makeresults", max_count=0)
        self.assertEqual(t.forms[0]["count"], "2")
        self.assertEqual(len(result.rows), 1)
        self.assertTrue(result.truncated)

    def test_preview_uses_the_same_contract(self):
        t = SplunkdOneshot(rows(60))
        result = SearchClient(t).preview("search index=main", max_count=50)
        self.assertEqual(t.forms[0]["count"], "51")
        self.assertEqual(len(result.rows), 50)
        self.assertTrue(result.truncated)
        self.assertEqual(t.forms[0]["earliest_time"], "-15m")

    def test_only_generating_searches(self):
        with self.assertRaises(ValidationError):
            SearchClient(SplunkdOneshot()).oneshot("search index=main")

    def test_search_errors_raise(self):
        t = SplunkdOneshot(messages=[{"type": "FATAL", "text": "Unknown search command 'x'"}])
        with self.assertRaises(UnsupportedOperation):
            SearchClient(t).oneshot("| x")


if __name__ == "__main__":
    unittest.main()

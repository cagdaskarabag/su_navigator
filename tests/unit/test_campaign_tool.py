import os
import sys
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.errors import UnsupportedOperation
from splunk_ucm.platform.search import SearchResult

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import controltest_campaign as cc  # noqa: E402


class FakeSearch:
    def __init__(self, error=None):
        self.queries = []
        self.error = error

    def preview(self, query, **kw):
        self.queries.append((query, kw))
        if self.error:
            raise self.error
        return SearchResult([{"deleted": "5"}], [], False)


class CampaignToolTest(unittest.TestCase):
    FIXTURE = {"positive": "2026-04-16T08:00:00Z x\n"}

    def test_static_result_scopes_and_derives_the_window_without_splunk(self):
        case = {"title": "t", "spl": "index=a earliest=-1h | stats count"}
        out = cc.static_result("1.1.1", case, self.FIXTURE, "ucm_controltest")
        self.assertEqual(out["status"], "scopable")
        self.assertTrue(out["window"]["derived"])

    def test_static_result_reports_what_cannot_be_scoped(self):
        out = cc.static_result("1.1.2", {"title": "t", "spl": "| tstats count where index=a"}, self.FIXTURE, "t")
        self.assertEqual(out["status"], "not_runnable")
        self.assertIn("cannot be redirected", out["reason"])
        self.assertEqual(cc.static_result("1.1.3", None, self.FIXTURE, "t")["status"], "not_runnable")

    def test_delete_is_scoped_to_this_runs_markers_and_reports_refusal(self):
        search = FakeSearch()
        out = cc.delete_events(search, "ucm_controltest", 1790000000.9)
        self.assertTrue(out["deleted"])
        query = search.queries[0][0]
        self.assertIn('index=ucm_controltest source="ucm-ct-*" _indextime>=1790000000 | delete', query)
        refused = cc.delete_events(FakeSearch(UnsupportedOperation("no delete capability")), "ucm_controltest", 1.0)
        self.assertFalse(refused["deleted"])

    def test_report_has_summary_and_one_row_per_fixture_in_numeric_order(self):
        data = {"results": [{"uc_id": "1.10.1", "status": "failed", "reason": "r | x"},
                            {"uc_id": "1.2.1", "status": "passed", "reason": ""},
                            {"uc_id": "1.3.1", "status": "failed", "reason": "r"}]}
        text = cc.render_report(data, {"1.10.1": {"class": "upstream content defect", "evidence": "e|v"}})
        rows = [line for line in text.splitlines() if line.startswith("| UC-")]
        self.assertEqual([r.split(" | ")[0] for r in rows], ["| UC-1.2.1", "| UC-1.3.1", "| UC-1.10.1"])
        self.assertIn("e\\|v", text)
        self.assertIn("| unclassified | 1 |", text)
        self.assertIn("| SUN defect | 0 |", text)
        self.assertIn("| passed | 1 |", text)
        self.assertIn("| upstream content defect | 1 |", text)
        self.assertIn("| **total** | **3** |", text)
        self.assertEqual(cc.summarize(data["results"])["failed"], 2)


if __name__ == "__main__":
    unittest.main()

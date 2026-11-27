"""A control test that finds nothing says which sourcetype the events were really indexed with."""

import unittest

from unit.test_controltest import CLOCK, FakeSplunk, ct


def fixture(**kw):
    out = {"uc_id": "9.1.2", "sourcetype": "WinEventLog:Security", "host": "dc-lab-1", "min_count": 1,
           "positive": "hit one\n", "negative": ""}
    out.update(kw)
    return out


SPL = 'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4740'


def runner(splunk, seen):
    calls = []

    def sourcetypes_of(index, marker):
        calls.append((index, marker))
        return seen

    return ct.ControlTestRunner(splunk.ingest, splunk.count, splunk.search, sleep=lambda s: None, settle=5.0,
                                clock=lambda: CLOCK, sourcetypes_of=sourcetypes_of), calls


class SourcetypeDiagnosticTest(unittest.TestCase):
    def failing_splunk(self):
        return FakeSplunk(row_fields=None)

    def test_rewritten_sourcetype_is_named_in_the_reason(self):
        splunk = self.failing_splunk()
        run, calls = runner(splunk, ["WinEventLog"])
        result = run.run(SPL, fixture(positive="miss one\n"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("indexed as WinEventLog", result["reason"])
        self.assertIn("rewrote it on ingest", result["reason"])
        self.assertEqual(result["positive"]["indexed_sourcetypes"], ["WinEventLog"])
        self.assertEqual(len(calls), 1)

    def test_unchanged_sourcetype_adds_nothing(self):
        run, _ = runner(self.failing_splunk(), ["WinEventLog:Security"])
        result = run.run(SPL, fixture(positive="miss one\n"))
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("rewrote", result["reason"])
        self.assertNotIn("indexed_sourcetypes", result["positive"])

    def test_passing_run_does_not_ask(self):
        run, calls = runner(self.failing_splunk(), ["WinEventLog"])
        result = run.run(SPL, fixture())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(calls, [])

    def test_lookup_failure_leaves_the_verdict_alone(self):
        splunk = self.failing_splunk()

        def broken(index, marker):
            raise ct.StorageError("splunkd returned HTTP 500")

        run = ct.ControlTestRunner(splunk.ingest, splunk.count, splunk.search, sleep=lambda s: None, settle=5.0,
                                   clock=lambda: CLOCK, sourcetypes_of=broken)
        result = run.run(SPL, fixture(positive="miss one\n"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("positive run returned 0 rows", result["reason"])


if __name__ == "__main__":
    unittest.main()

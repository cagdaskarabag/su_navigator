"""Schedule arithmetic, jitter and schedule advisories (D-069)."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.deployment.schedule import (advisories, cadence_seconds, jittered_cron, offset_seconds,
                                            window_seconds)
from splunk_ucm.deployment.spec import validate_cron
from splunk_ucm.spl.findings import finding, from_lint
from splunk_ucm.spl.lint import lint


class CadenceTest(unittest.TestCase):
    def test_regular_schedules(self):
        for cron, seconds in (("* * * * *", 60), ("*/5 * * * *", 300), ("*/15 * * * *", 900),
                              ("7-59/15 * * * *", 900), ("0,30 * * * *", 1800), ("12 * * * *", 3600),
                              ("0 */4 * * *", 14400), ("30 2 * * *", 86400)):
            with self.subTest(cron=cron):
                self.assertEqual(cadence_seconds(cron), seconds)

    def test_irregular_schedules_have_no_cadence(self):
        for cron in ("0,10,30 * * * *", "0 9 * * 1-5", "*/7 * * * *", "0 0 1 * *", "bad", ""):
            with self.subTest(cron=cron):
                self.assertIsNone(cadence_seconds(cron))


class WindowTest(unittest.TestCase):
    def test_offsets_and_windows(self):
        self.assertEqual(offset_seconds("now"), 0)
        self.assertEqual(offset_seconds("-20m@m"), -1200)
        self.assertEqual(offset_seconds("-1h@h"), -3600)
        self.assertIsNone(offset_seconds("@d"))
        self.assertEqual(window_seconds("-20m@m", "-5m@m"), 900)
        self.assertIsNone(window_seconds("-5m", "-20m"))


class JitterTest(unittest.TestCase):
    def test_default_step_cron_gets_a_stable_offset(self):
        first = jittered_cron("*/15 * * * *", "fenre_UC-1.1.1")
        self.assertEqual(first, jittered_cron("*/15 * * * *", "fenre_UC-1.1.1"))
        self.assertRegex(first, r"^(\*/15|\d{1,2}-59/15) \* \* \* \*$")
        self.assertEqual(validate_cron(first), first)
        self.assertEqual(cadence_seconds(first), 900)
        offsets = {jittered_cron("*/15 * * * *", "uc%d" % i) for i in range(60)}
        self.assertGreater(len(offsets), 5)

    def test_other_crons_are_left_alone(self):
        for cron in ("0 * * * *", "*/15 2 * * *", "* * * * *", "*/7 * * * *", "5,35 * * * *"):
            with self.subTest(cron=cron):
                self.assertEqual(jittered_cron(cron, "x"), cron)


class ScheduleAdvisoryTest(unittest.TestCase):
    def codes(self, *args):
        return [f["code"] for f in advisories(*args)]

    def test_default_schedule_is_clean(self):
        self.assertEqual(self.codes("*/15 * * * *", "-20m@m", "-5m@m"), [])
        self.assertEqual(self.codes("*/15 * * * *", "-35m@m", "-5m@m"), ["S003"])
        self.assertEqual(self.codes("*/15 * * * *", "-35m@m", "-5m@m", "30m"), [])

    def test_findings(self):
        self.assertIn("S001", self.codes("* * * * *", "-1m", "now"))
        self.assertIn("S002", self.codes("0 * * * *", "-15m", "now"))
        self.assertIn("S004", self.codes("*/15 * * * *", "-15m", "now"))
        self.assertIn("S005", self.codes("0 9 * * 1-5", "-24h", "now"))
        gap = [f for f in advisories("0 * * * *", "-15m", "now") if f["code"] == "S002"][0]
        self.assertEqual((gap["severity"], gap["category"]), ("warning", "schedule"))
        self.assertEqual(gap["evidence"], {"window_seconds": 900, "cadence_seconds": 3600})
        self.assertIn("15m", gap["message"])


class FindingRecordTest(unittest.TestCase):
    def test_shape_and_validation(self):
        self.assertEqual(set(finding("S001", "schedule", "info", "m")), {"code", "category", "severity", "message", "evidence"})
        with self.assertRaises(ValueError):
            finding("X", "other", "info", "m")
        with self.assertRaises(ValueError):
            finding("X", "lint", "error", "m")

    def test_lint_findings_convert(self):
        items = from_lint(lint("index=a match(x, \"y\") | stats count"))
        self.assertEqual([i["code"] for i in items], ["L001"])
        self.assertEqual(items[0]["category"], "lint")


if __name__ == "__main__":
    unittest.main()

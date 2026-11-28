"""The usage census prints counts only (STRATEGY_ROADMAP phase 1)."""

import importlib.util
import json
import os
import unittest

import helpers  # noqa: F401  (sets sys.path)

spec = importlib.util.spec_from_file_location("usage_census", os.path.join(helpers.ROOT, "tools", "usage_census.py"))
census_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census_mod)

NOW = 1_800_000_000.0
DAY = 86400.0


def row(action, days_ago, actor="alice"):
    return {"action": action, "actor": actor, "time": NOW - days_ago * DAY}


class CensusTest(unittest.TestCase):
    ROWS = [row("deployment.draft", 1), row("deployment.controltest", 2, "bob"), row("discovery.completed", 3, "system"),
            row("assessment.set", 5), row("assessment.set", 6, "carol"), row("poam.created", 7),
            row("dashboard.created", 8), row("deployment.draft", 200), row("something.new", 1)]

    def test_modules_counts_people_and_window(self):
        out = census_mod.census(self.ROWS, NOW, 90)
        m = out["modules"]
        self.assertEqual((m["deployment"]["rows"], m["deployment"]["people"]), (1, 1))
        self.assertEqual((m["control_tests"]["rows"], m["control_tests"]["people"]), (1, 1))
        self.assertEqual((m["compliance"]["rows"], m["compliance"]["people"]), (3, 2))
        self.assertEqual(m["dashboards"]["rows"], 1)
        self.assertEqual((m["discovery"]["rows"], m["discovery"]["people"]), (1, 0))
        self.assertEqual(m["other"]["rows"], 1)
        self.assertEqual(m["compliance"]["last_days_ago"], 5.0)
        self.assertIsNone(m["selection"]["last_days_ago"])
        self.assertEqual(out["summary"]["core_rows"], 3)
        self.assertEqual(out["summary"]["compliance_and_dashboard_rows"], 4)

    def test_output_has_no_names_or_ids(self):
        text = json.dumps(census_mod.census(self.ROWS, NOW, 90)) + census_mod.render(census_mod.census(self.ROWS, NOW, 90))
        for secret in ("alice", "bob", "carol"):
            self.assertNotIn(secret, text)

    def test_empty_log(self):
        out = census_mod.census([], NOW, 30)
        self.assertIsNone(out["summary"]["compliance_share"])
        self.assertIn("never", census_mod.render(out))


if __name__ == "__main__":
    unittest.main()

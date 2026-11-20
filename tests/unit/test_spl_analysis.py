import unittest

import helpers  # noqa: F401
from splunk_ucm.spl.analysis import analyze


class SplAnalysisTest(unittest.TestCase):
    def test_extracts_index_sourcetype_and_negation(self):
        a = analyze('index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 '
                    'NOT sourcetype=foo* | stats count by user')
        self.assertEqual(a.positive("indexes"), ["wineventlog"])
        self.assertEqual(a.positive("sourcetypes"), ["WinEventLog:Security"])
        negated = [v for v in a.sourcetypes if v.negated]
        self.assertEqual(len(negated), 1)
        self.assertTrue(negated[0].wildcard)
        self.assertEqual(a.generating_command, "search")
        self.assertIn("stats", a.commands)

    def test_quoted_pipes_do_not_split_pipeline(self):
        a = analyze('index=main "a | delete" | eval x="| outputlookup y" | table x')
        self.assertNotIn("delete", a.commands)
        self.assertNotIn("outputlookup", a.commands)
        self.assertEqual(a.side_effect_commands, [])

    def test_side_effect_commands_flagged(self):
        a = analyze("index=main | outputlookup bad.csv")
        self.assertIn("outputlookup", a.side_effect_commands)
        self.assertEqual(a.lookups_written, ["bad.csv"])
        self.assertIn("side_effect_commands", a.warnings)
        self.assertIn("delete", analyze("index=main | delete").side_effect_commands)

    def test_macros_with_arity_and_lookups(self):
        a = analyze("`my_macro(2,3)` | `plain` | lookup assets ip OUTPUT owner")
        self.assertIn("my_macro(2)", a.macros)
        self.assertIn("plain", a.macros)
        self.assertEqual(a.lookups, ["assets"])

    def test_tstats_datamodel(self):
        a = analyze("| tstats summariesonly=t count from datamodel=Authentication.Authentication "
                    "where Authentication.action=failure by _time span=1h")
        self.assertEqual(a.generating_command, "tstats")
        self.assertEqual(a.datamodels, ["Authentication.Authentication"])

    def test_subsearch_detected_and_commands_after_bracket_not_misread(self):
        a = analyze("index=a [search index=b | fields user] | stats count")
        self.assertTrue(a.has_subsearch)
        self.assertEqual(sorted(a.positive("indexes")), ["a", "b"])
        self.assertIn("stats", a.commands)

    def test_unbounded_index(self):
        self.assertTrue(analyze("index=* | stats count").unbounded_index)
        self.assertFalse(analyze("index=main | stats count").unbounded_index)

    def test_empty_and_garbage_input_do_not_raise(self):
        for spl in ("", "   ", "|", "]]]", '"unterminated', "`", None):
            analyze(spl or "")


if __name__ == "__main__":
    unittest.main()

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

    def produced(self, spl):
        return {k: (v["command"], v["read_before"]) for k, v in analyze(spl).produced_fields.items()}

    def test_produced_fields_by_command(self):
        cases = {
            'index=a | eval x=if(a=1, b, c), y=case(z="1,2", 1) | stats count(x) by y':
                {"x": ("eval", False), "y": ("eval", False)},
            "index=a | stats count as n dc(src) as srcs by user":
                {"n": ("stats", False), "srcs": ("stats", False)},
            "index=a | stats count by user | eventstats avg(count) as avg_n":
                {"count": ("stats", False), "avg_n": ("eventstats", False)},
            "index=a | rename src_ip as src, dest_ip as dest": {"src": ("rename", False), "dest": ("rename", False)},
            'index=a | rex field=_raw "user=(?<user>\\S+) from (?P<ip>\\S+)"':
                {"user": ("rex", False), "ip": ("rex", False)},
            'index=a | rex mode=sed "s/a/b/g"': {},
            "index=a | spath input=p path=a.b output=ab | spath path=c.d": {"ab": ("spath", False),
                                                                              "c.d": ("spath", False)},
            "index=a | lookup t ip as dest_ip OUTPUTNEW owner AS o, crit": {"o": ("lookup", False),
                                                                           "crit": ("lookup", False)},
            "index=a | top user": {"count": ("top", False), "percent": ("top", False)},
            "index=a | iplocation src": {k: ("iplocation", False) for k in ("City", "Country", "Region", "lat", "lon")},
            "index=a | rename * as x_*": {},
        }
        for spl, expected in cases.items():
            self.assertEqual(self.produced(spl), expected, spl)

    def test_read_before_production(self):
        self.assertEqual(self.produced("index=a | eval user=lower(user)"), {"user": ("eval", True)})
        self.assertEqual(self.produced("index=a src=1 | eval src=src+1"), {"src": ("eval", True)})
        self.assertEqual(self.produced("index=a | stats sum(bytes) as bytes"), {"bytes": ("stats", True)})
        self.assertEqual(self.produced("index=a | eval a=lower(TargetUserName)")["a"], ("eval", False))
        self.assertEqual(self.produced("index=a | stats count by src_ip | rename src_ip as src")["src"],
                         ("rename", False))
        self.assertEqual(self.produced("index=a src.ip=1 | eval src=1")["src"], ("eval", False))

    def test_empty_and_garbage_input_do_not_raise(self):
        for spl in ("", "   ", "|", "]]]", '"unterminated', "`", None):
            analyze(spl or "")


if __name__ == "__main__":
    unittest.main()

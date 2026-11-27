"""Splunk runs subsearches while it parses a search, so a subsearch with a side-effect command never reaches the parser."""

import unittest

from splunk_ucm.errors import ValidationError
from splunk_ucm.platform.search import ParseResult
from splunk_ucm.spl.analysis import subsearch_side_effects
from splunk_ucm.spl.parser import parse


class CountingClient:
    def __init__(self):
        self.sent = []

    def parse(self, q, app=""):
        self.sent.append(q)
        return ParseResult(True, ["search"], [], "", "", {})


class SubsearchSideEffectsTest(unittest.TestCase):
    def test_found_inside_a_subsearch(self):
        for spl, expected in (
            ("| makeresults | append [ | makeresults | outputlookup x.csv ]", ["outputlookup"]),
            ("index=a [search index=b | collect index=c | fields x]", ["collect"]),
            ("| makeresults | append [ search index=a | append [ | makeresults | delete ] ]", ["delete"]),
            ("index=a [ | makeresults\n| outputcsv f ]", ["outputcsv"]),
            ("index=a `m` [ | makeresults | `x` ``` [ ``` | sendemail to=a ]", ["sendemail"]),
            ("| makeresults | append [ ```a`b``` | makeresults | outputlookup x.csv ]", ["outputlookup"]),
        ):
            self.assertEqual(subsearch_side_effects(spl), expected, spl)

    def test_not_found_outside_a_subsearch_or_in_text(self):
        for spl in ("| makeresults | outputlookup x.csv", 'index=a "[ | outputlookup x ]"',
                    "index=a [ | inputlookup x ] | outputlookup y", "", "index=a | stats count"):
            self.assertEqual(subsearch_side_effects(spl), [], spl)


class ParseGuardTest(unittest.TestCase):
    def test_guarded_search_is_not_sent(self):
        client = CountingClient()
        with self.assertRaises(ValidationError) as ctx:
            parse(client, "| makeresults | append [ | makeresults | outputlookup x.csv ]", app="sunavigator")
        self.assertEqual(client.sent, [])
        self.assertIn("outputlookup", ctx.exception.message)
        self.assertEqual(ctx.exception.details["commands"], ["outputlookup"])

    def test_top_level_side_effect_is_still_parsed(self):
        client = CountingClient()
        result = parse(client, "| makeresults | outputlookup x.csv", app="sunavigator")
        self.assertTrue(result.ok)
        self.assertEqual(len(client.sent), 1)


if __name__ == "__main__":
    unittest.main()

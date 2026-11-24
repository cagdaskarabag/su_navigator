import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.platform.search import ParseResult
from splunk_ucm.spl.policy import classify, command_exists, expanded_pipeline, parse_extra_safe


def parsed(*commands, ok=True):
    """ParseResult shaped like /search/parser output: (command, args) pairs."""
    raw = {"commands": [{"command": c, "args": a} for c, a in commands]}
    return ParseResult(ok, [c for c, _ in commands], [], raw=raw)


class ClassifyTest(unittest.TestCase):
    def test_read_only_search_is_clean(self):
        p = classify('index=main sourcetype=x | eval a="| map | outputlookup" | stats count by host '
                     '| append [| tstats count where index=_internal by sourcetype] | where count>0')
        self.assertEqual((p.side_effects, p.indirect, p.unknown), ([], [], []))

    def test_side_effect_denylist(self):
        for spl, cmd in (("| makeresults | summaryindex index=s", "summaryindex"),
                         ("| makeresults | dbxoutput output=o", "dbxoutput"),
                         ("| makeresults | runshellscript x.sh", "runshellscript"),
                         ("index=main | fit LinearRegression a from b into m1", "fit into"),
                         ("| makeresults | append [| makeresults | collect index=s]", "collect")):
            self.assertIn(cmd, classify(spl).side_effects, spl)
        self.assertEqual(classify("index=main | fit LinearRegression a from b").side_effects, [])

    def test_indirect_execution(self):
        for spl, cmd in (("| makeresults | map search=\"search index=x\"", "map"),
                         ("| savedsearch \"Errors\"", "savedsearch"),
                         ("| loadjob savedsearch=\"admin:search:x\"", "loadjob"),
                         ("| rest /services/server/info", "rest"),
                         ("| dbxquery connection=c query=\"select 1\"", "dbxquery"),
                         ("| from savedsearch:Errors", "savedsearch: dataset"),
                         ("| union datamodel:Authentication savedsearch:x", "savedsearch: dataset"),
                         ("index=a | append [search index=b | map search=\"search index=c\"]", "map")):
            p = classify(spl)
            self.assertIn(cmd, p.indirect, spl)
            self.assertIn(cmd, p.review, spl)
        self.assertEqual(classify("| from datamodel:Authentication | head 1").indirect, [])

    def test_unknown_commands_need_review(self):
        p = classify("index=main | apply my_model | cyberchef infield=a")
        self.assertEqual(p.unknown, ["apply", "cyberchef"])
        self.assertEqual(p.review, ["apply", "cyberchef"])
        self.assertEqual(classify("index=main | apply my_model", extra_safe=["apply"]).unknown, [])

    def test_extra_safe_cannot_clear_side_effect_or_indirect(self):
        self.assertEqual(parse_extra_safe(" Apply, cyberchef,outputlookup,map,rest, bad-name ,apply"),
                         ["apply", "cyberchef"])
        p = classify("| makeresults | map search=x | outputlookup y.csv", extra_safe=["map", "outputlookup"])
        self.assertEqual(p.indirect, ["map"])
        self.assertEqual(p.side_effects, ["outputlookup"])

    def test_commands_hidden_in_macros_inside_subsearches(self):
        spl = "| makeresults | append [ `inner` ] | `outer`"
        self.assertEqual(classify(spl).side_effects, [])
        p = parsed(("makeresults", ""), ("append", " [ | makeresults | outputlookup probe.csv]"),
                   ("eval", " a=1 "), ("map", ' search="search index=x"'))
        self.assertEqual(expanded_pipeline(p),
                         '| makeresults  | append  [ | makeresults | outputlookup probe.csv] | eval  a=1  '
                         '| map  search="search index=x"')
        result = classify(spl, p)
        self.assertEqual(result.side_effects, ["outputlookup"])
        self.assertEqual(result.indirect, ["map"])

    def test_static_artifacts_dropped_only_when_splunk_parsed(self):
        spl = "index=main | search dest=$dest|s$"
        static = classify(spl)
        self.assertEqual(static.unknown, ["s"])
        ok = parsed(("search", " index=main"), ("search", " dest=x"))
        self.assertEqual(classify(spl, ok, exists=lambda n: False).unknown, [])
        self.assertEqual(classify(spl, ok, exists=lambda n: True).unknown, static.unknown)
        failed = parsed(("search", " index=main"), ok=False)
        self.assertEqual(classify(spl, failed, exists=lambda n: False).unknown, static.unknown)

    def test_parser_reported_commands_are_never_dropped(self):
        p = parsed(("search", " index=main"), ("apply", " m"))
        self.assertEqual(classify("index=main | `run_model`", p, exists=lambda n: False).unknown, ["apply"])


COMMAND_TABLE = [
    ("read_only", c) for c in (
        "stats", "eval", "where", "table", "fields", "rename", "rex", "spath", "lookup", "inputlookup",
        "tstats", "mstats", "datamodel", "timechart", "chart", "eventstats", "streamstats", "dedup", "sort",
        "head", "tail", "top", "rare", "bin", "fillnull", "makemv", "mvexpand", "transaction", "join",
        "append", "appendcols", "appendpipe", "union", "multisearch", "foreach", "iplocation", "metadata",
        "dbinspect", "fieldsummary", "makeresults", "tojson", "fromjson", "xyseries", "untable", "convert",
        "addtotals", "predict", "localize", "regex", "search", "return", "format", "geostats", "walklex",
    )
] + [
    ("side_effect", c) for c in (
        "outputlookup", "outputcsv", "collect", "mcollect", "meventcollect", "tscollect", "sendemail",
        "sendalert", "delete", "script", "run", "sendresults", "summaryindex", "dbxoutput", "runshellscript",
        "deletemodel", "dump", "crawl", "outputtelemetry",
    )
] + [
    ("indirect", c) for c in ("map", "savedsearch", "loadjob", "rest", "dbxquery", "dbxlookup", "dbxinputs")
] + [
    ("unknown", c) for c in ("apply", "fit", "summary", "cyberchef", "ldapsearch", "relative_entropy")
]


class CommandTableTest(unittest.TestCase):
    def test_classification_table(self):
        self.assertGreaterEqual(len(COMMAND_TABLE), 60)
        for expected, cmd in COMMAND_TABLE:
            p = classify("| makeresults | %s x" % cmd)
            got = ("side_effect" if cmd in p.side_effects else "indirect" if cmd in p.indirect
                   else "unknown" if cmd in p.unknown else "read_only")
            self.assertEqual(got, expected, cmd)


class CommandExistsTest(unittest.TestCase):
    class Client:
        def __init__(self, known):
            self.known = known
            self.calls = []

        def parse(self, q, app=""):
            self.calls.append((q, app))
            name = q.rsplit("|", 1)[1].strip()
            if name in self.known:
                return ParseResult(True, ["makeresults", name], [])
            return ParseResult(False, [], [{"type": "FATAL", "text": "Unknown search command '%s'." % name}])

    def test_probe(self):
        c = self.Client({"apply"})
        self.assertTrue(command_exists(c, "apply", "sunavigator"))
        self.assertFalse(command_exists(c, "tier0", "sunavigator"))
        self.assertEqual(c.calls[0], ("| makeresults | apply", "sunavigator"))


if __name__ == "__main__":
    unittest.main()

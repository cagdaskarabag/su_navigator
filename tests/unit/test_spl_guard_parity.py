"""The browser's SPL guard (ucm_common.js) mirrors the server-side policy (D-058)."""

import ast
import glob
import json
import os
import re
import shutil
import subprocess
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.spl.analysis import GENERATING_COMMANDS, SIDE_EFFECT_COMMANDS, analyze
from splunk_ucm.spl.policy import HIDDEN_SPL_COMMANDS, INDIRECT_COMMANDS, classify

HERE = os.path.dirname(__file__)
COMMON = os.path.join(HERE, "..", "..", "sunavigator", "appserver", "static", "ucm_common.js")
CLI = os.path.join(HERE, "..", "js", "spl_guard_cli.js")
FIXTURES = os.path.join(HERE, "..", "fixtures")


def wrap_map(inner, prefix):
    """``prefix | map search="inner"`` with the inner search escaped the way Splunk expects."""
    return 'search %s | map search="%s"' % (prefix, inner.replace("\\", "\\\\").replace('"', '\\"'))


EXTRA = [
    "", "index=main", "| makeresults | outputlookup x.csv", "index=a | stats count | Outputlookup x", 'index=a "| delete" | stats count',
    "index=a | eval a=\"[|collect]\" | table a", "| makeresults | append [| makeresults | collect index=s]",
    "index=a | fit LinearRegression a from b into m1", "index=a | fit LinearRegression a from b",
    "| from savedsearch:Errors", "| union datamodel:Authentication savedsearch:x", "| rest /services/server/info",
    "index=a `outputlookup_wrapper(1)` | stats count", "index=a | `m` | `n(a,b)`", "index=a | map search=\"search index=x\"",
    "search index=a | head 1\n| sendemail to=x",
    'index=a | map search="search index=b | collect index=c"', 'index=a | map search="search index=b | outputlookup x.csv"',
    '| rest /services/server/info | map search="| sendemail to=a@b.c"', 'index=a | map search="search index=b | delete"',
    'index=a | map search="search index=b | head 1" maxsearches=5', 'index=a | map maxsearches=5 search="search index=b | head 1"',
    'index=a | map search="search index=b | map search=\\"search c | outputlookup z\\""',
    wrap_map(wrap_map(wrap_map(wrap_map('search d | outputlookup z', 'c'), 'b'), 'a'), 'x'),
    wrap_map(wrap_map(wrap_map('search c | outputlookup z', 'b'), 'a'), 'x'),
    'index=a | map savedsearch="Errors"', "index=a | map search=x", 'index=a | map search="search `m`"',
    'index=a | map search="| from savedsearch:Errors"', 'index=a | map search="| savedsearch Errors"',
    'index=a | map search="search index=b | fit LinearRegression a from b into m1"',
    'index=a | map search="search index=b | dbxquery connection=c query=\\"select 1\\""',
    '| loadjob savedsearch="admin:search:x"', '| dbxquery connection=c query="select 1"', '| savedsearch "Errors"',
    'index=a | eval a="map search=\\"x | collect\\"" | table a', 'index=a | append [| makeresults | map search="search x | collect index=s"]',
    "index=a | mapper search=\"x | collect\"", 'index=a | map search="search index=b" | map search="search index=c | sendemail to=x"', "[| outputlookup z] index=a", "index=a [search index=b | delete]",
    "| tstats count where index=x by host | where count>1 | script python x", "index=a | run foo",
    "| makeresults | eval x=\"a`b\" | outputcsv y", "index=a\n|\n  outputlookup\n  z",
] + [
    # D-068: a side-effect command as the first command of a bracket, an unprefixed search or a map string.
    "| makeresults | appendpipe [ collect index=x ]", "| makeresults | appendpipe [collect index=x]",
    "| makeresults | appendpipe [ COLLECT index=x ]", "| makeresults | appendpipe [ outputlookup x.csv ]",
    "| makeresults | append [ outputlookup x.csv ]", "| makeresults | appendcols [ collect index=x ]",
    "| makeresults | union [ collect index=x ]", "| makeresults | join type=left a [ collect index=x ]",
    "| makeresults | multisearch [ collect index=x ]", "| makeresults | append [ delete ]",
    "| makeresults | appendpipe [ sendalert a ]", "| makeresults | appendpipe [ dump basefilename=x ]",
    "| makeresults | appendpipe [ stats count ] | appendpipe [ collect index=x ]",
    '| makeresults | map search="collect index=x"', '| makeresults | map search="outputlookup x.csv"',
    '| makeresults | append [ map search="search a | collect index=x" ]', "collect index=x", "outputlookup x.csv",
    "| makeresults | appendpipe [ customcmd a=1 ]", "| makeresults | append [ inputlookup x.csv ]",
    "index=a [ search index=b | fields host ]", "index=a [ index=b | fields host ]", "index=a [ delete=1 ]",
    "index=a | join host [ search index=b ]", "delete OR removed index=a", "| makeresults | appendpipe [ eval x=1 ]",
]


def module_strings(path):
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and ("|" in n.value or "index=" in n.value) and len(n.value) < 5000]


def fixture_spl():
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and "spl" in key.lower():
                    found.append(value)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
    for path in glob.glob(os.path.join(FIXTURES, "**", "*.json"), recursive=True):
        with open(path, encoding="utf-8") as handle:
            try:
                walk(json.load(handle))
            except ValueError:
                pass
    return found


def corpus():
    items = list(EXTRA) + fixture_spl()
    for name in ("test_spl_analysis.py", "test_spl_policy.py", "test_validation.py", "test_readiness.py"):
        items.extend(module_strings(os.path.join(HERE, name)))
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def js_list(name):
    with open(COMMON, encoding="utf-8") as handle:
        block = handle.read().split("var %s = [" % name, 1)[1].split("];", 1)[0]
    return re.findall(r'"(\w+)"', block)


class GuardListsTest(unittest.TestCase):
    def test_side_effect_list_equals_python(self):
        self.assertEqual(sorted(js_list("SIDE_EFFECT_COMMANDS")), sorted(SIDE_EFFECT_COMMANDS))

    def test_indirect_list_equals_python(self):
        self.assertEqual(sorted(js_list("INDIRECT_COMMANDS")), sorted(INDIRECT_COMMANDS))

    def test_hidden_list_equals_python(self):
        self.assertEqual(sorted(js_list("HIDDEN_SPL_COMMANDS")), sorted(HIDDEN_SPL_COMMANDS))

    def test_generating_list_equals_python(self):
        self.assertEqual(sorted(js_list("GENERATING_COMMANDS")), sorted(GENERATING_COMMANDS))

    def test_hidden_is_a_subset_of_indirect(self):
        self.assertTrue(HIDDEN_SPL_COMMANDS <= INDIRECT_COMMANDS)

    def test_fit_into_and_savedsearch_dataset_patterns_are_mirrored(self):
        with open(COMMON, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn(r"/(?:^|[|\[])\s*fit\b[^|\]]*?\binto\b/i", source)
        self.assertIn("savedsearch:", source)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class GuardParityTest(unittest.TestCase):
    def test_commands_and_policy_match_python_on_the_corpus(self):
        items = corpus()
        self.assertGreater(len(items), 60)
        result = subprocess.run(["node", CLI], input=json.dumps(items), capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        js = json.loads(result.stdout)
        self.assertEqual(len(js), len(items))
        for spl, got in zip(items, js):
            with self.subTest(spl=spl[:80]):
                py = classify(spl)
                self.assertEqual(got["commands"], analyze(spl).commands)
                self.assertEqual(got["side"], py.side_effects)
                self.assertEqual(got["indirect"], py.indirect)
                self.assertEqual(got["nested"], py.nested)
                self.assertEqual(got["hidden"], py.hidden)
                self.assertEqual(got["macros"], bool(analyze(spl).macros))


if __name__ == "__main__":
    unittest.main()

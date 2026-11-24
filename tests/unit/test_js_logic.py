"""Runs the dependency-free Node tests of the browser modules (tests/js) when Node is installed."""

import glob
import os
import shutil
import subprocess
import unittest

JS_DIR = os.path.join(os.path.dirname(__file__), "..", "js")
STATIC = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "appserver", "static")


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class JsLogicTest(unittest.TestCase):
    def test_node_suites(self):
        suites = sorted(glob.glob(os.path.join(JS_DIR, "test_*.js")))
        self.assertTrue(suites)
        for suite in suites:
            with self.subTest(suite=os.path.basename(suite)):
                result = subprocess.run(["node", suite], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class AssetCacheBustingTest(unittest.TestCase):
    """Splunk caches static files for a year under a URL carrying the app build.

    A module id such as "../app/sunavigator/ucm_common" is fetched without that build number, and
    splunk.util.make_url in the browser always writes app build 0. The shared module is therefore
    requested from the directory of ucm.css, which the dashboard XML loads under the busted URL.
    """

    def view_scripts(self):
        names = sorted(n for n in os.listdir(STATIC) if n.startswith("ucm_") and n.endswith(".js") and n != "ucm_common.js")
        self.assertTrue(names)
        return names

    def test_views_load_common_with_the_app_build(self):
        for name in self.view_scripts():
            with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
                source = handle.read()
            self.assertIn('link[href*="/app/sunavigator/ucm.css"]', source, name)
            self.assertIn('require(["jquery", ucmCommonUrl, "splunkjs/mvc/simplexml/ready!"], ucmViewMain);', source, name)
            self.assertNotIn('"../app/sunavigator/ucm_common",\n', source, name)

    def test_views_declare_the_stylesheet_the_loader_relies_on(self):
        views = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "default", "data", "ui", "views")
        for name in self.view_scripts():
            xml = os.path.join(views, name[:-3] + ".xml")
            with open(xml, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn('script="%s"' % name, text, name)
            self.assertIn('stylesheet="ucm.css"', text, name)

    def test_build_is_a_positive_integer(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "default", "app.conf")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        install = text.split("[install]", 1)[1].split("[", 1)[0]
        build = [line.split("=", 1)[1].strip() for line in install.splitlines() if line.startswith("build")]
        self.assertEqual(len(build), 1)
        self.assertTrue(build[0].isdigit() and int(build[0]) >= 2, build)


if __name__ == "__main__":
    unittest.main()

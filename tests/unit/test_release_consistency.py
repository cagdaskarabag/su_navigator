import os
import re
import unittest

import helpers  # noqa: F401  (sets sys.path)
import splunk_ucm

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


class ReleaseConsistencyTest(unittest.TestCase):
    """The version and the test count are written by hand in several files (issue #8)."""

    version = splunk_ucm.__version__

    def test_app_conf_carries_the_version_twice(self):
        versions = re.findall(r"^version = (\S+)", read("sunavigator", "default", "app.conf"), re.MULTILINE)
        self.assertEqual(versions, [self.version, self.version])

    def test_manifest_version(self):
        self.assertIn('"version": "%s"' % self.version, read("sunavigator", "app.manifest"))

    def test_readme_names_the_package_of_this_version(self):
        text = read("README.md")
        self.assertEqual(set(re.findall(r"sunavigator-(\d+\.\d+\.\d+)\.tar\.gz", text)), {self.version})

    def test_operator_guide_is_for_this_version(self):
        text = read("docs", "OPERATOR_GUIDE.md")
        self.assertTrue(text.startswith("# SUNavigator %s " % self.version))
        self.assertIn("**SUNavigator\n%s**" % self.version, text)
        self.assertIn("## 12. Known limitations (%s)" % self.version, text)
        packages = re.findall(r"sunavigator-(0\.(?:8|9)\.\d+|[1-9]\d*\.\d+\.\d+)\.tar\.gz", text)
        self.assertEqual(set(packages), {self.version})
        first = re.search(r"^## What changed in \d+\.\d+\.x\n.*?^### (\d+\.\d+\.\d+)", text, re.MULTILINE | re.DOTALL)
        self.assertEqual(first.group(1), self.version)

    def test_latest_decision_record_names_this_version(self):
        records = re.findall(r"^## (D-\d+) .*\n+\*(\d+\.\d+\.\d+)", read("docs", "DECISIONS.md"), re.MULTILINE)
        self.assertEqual(records[-1][1], self.version, records[-1])

    def test_readme_unit_test_count_is_current(self):
        loader = unittest.TestLoader()
        actual = loader.discover(os.path.join(ROOT, "tests", "unit"), top_level_dir=os.path.join(ROOT, "tests")).countTestCases()
        text = read("README.md")
        badge = int(re.search(r"unit%20tests-(\d+)%20passed", text).group(1))
        listed = int(re.search(r"(\d+) mocked unit tests", text).group(1))
        self.assertEqual((badge, listed), (actual, actual))


if __name__ == "__main__":
    unittest.main()

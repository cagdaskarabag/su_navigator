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
        packages = re.findall(r"sunavigator-(0\.(?:8|9|10)\.\d+|[1-9]\d*\.\d+\.\d+)\.tar\.gz", text)
        self.assertEqual(set(packages), {self.version})
        first = re.search(r"^## What changed in \d+\.\d+\.x(?: and [\d.]+)?\n.*?^### (\d+\.\d+\.\d+)", text, re.MULTILINE | re.DOTALL)
        self.assertEqual(first.group(1), self.version)

    def test_readme_version_badge_matches_the_app_version(self):
        badge = re.search(r"img\.shields\.io/badge/version-(\d+)\.(\d+)\.x-", read("README.md"))
        self.assertIsNotNone(badge, "README has no version badge of the form version-X.Y.x")
        major, minor = self.version.split(".")[:2]
        self.assertEqual((badge.group(1), badge.group(2)), (major, minor))

    def test_readme_badge_link_points_at_an_existing_operator_guide_heading(self):
        link = re.search(r"badge/version-[^)]*\)\]\(docs/OPERATOR_GUIDE\.md#([^)]+)\)", read("README.md")).group(1)
        anchors = set()
        for line in read("docs", "OPERATOR_GUIDE.md").splitlines():
            if line.startswith("#"):
                title = line.lstrip("#").strip().lower()
                anchors.add(re.sub(r"[^a-z0-9 _-]", "", title).replace(" ", "-"))
        self.assertIn(link, anchors)

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


class LicenceFilesTest(unittest.TestCase):
    """The package carries the same licence and notices as the repository (D-068)."""

    def test_package_copies_equal_the_repository_files(self):
        self.assertEqual(read("sunavigator", "LICENSE"), read("LICENSE"))
        self.assertEqual(read("sunavigator", "THIRD_PARTY_NOTICES.md"), read("THIRD_PARTY_NOTICES.md"))

    def test_fenre_licence_sits_next_to_the_shipped_schema(self):
        self.assertEqual(read("sunavigator", "lib", "splunk_ucm", "content", "fenre", "LICENSE"),
                         read("tests", "fixtures", "fenre", "LICENSE"))
        self.assertIn("Fredrik Lima Sudmann", read("THIRD_PARTY_NOTICES.md"))

    def test_repository_licence_is_apache_2_with_notice(self):
        licence = read("LICENSE")
        self.assertIn("Apache License", licence)
        self.assertIn("Version 2.0, January 2004", licence)
        self.assertNotIn("all rights reserved", licence.lower())
        self.assertIn("Copyright 2026", read("NOTICE"))
        self.assertEqual(read("sunavigator", "NOTICE"), read("NOTICE"))

    def test_manifest_names_the_licence(self):
        import json
        manifest = json.loads(read("sunavigator", "app.manifest"))
        self.assertIn("Apache-2.0", manifest["info"]["license"]["name"])
        self.assertEqual(manifest["info"]["license"]["text"], "LICENSE")

    def test_readme_credits_both_content_sources(self):
        text = read("README.md")
        self.assertIn("MIT", text)
        self.assertIn("Apache License 2.0", text)


if __name__ == "__main__":
    unittest.main()

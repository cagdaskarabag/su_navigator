"""The scheduler role cannot run side-effect commands (D-068)."""

import os
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.conf import parse

AUTHORIZE = os.path.join(os.path.dirname(__file__), "..", "..", "sunavigator", "default", "authorize.conf")

# Capabilities of Splunk's role_user that let a search write or send data.
WRITE_CAPABILITIES = ("run_collect", "run_mcollect", "run_dump", "run_sendalert", "output_file",
                      "upload_lookup_files", "rest_properties_set", "edit_own_objects")


def role(name):
    with open(AUTHORIZE, encoding="utf-8") as handle:
        return dict(parse(handle.read()))["role_" + name]


class SchedulerRoleTest(unittest.TestCase):
    def test_does_not_import_roles(self):
        # A role cannot disable a capability it imports (measured on 10.2.9).
        self.assertNotIn("importRoles", role("ucm_scheduler"))

    def test_runs_searches_on_a_schedule(self):
        settings = role("ucm_scheduler")
        self.assertEqual(settings.get("search"), "enabled")
        self.assertEqual(settings.get("schedule_search"), "enabled")

    def test_write_capabilities_are_not_granted(self):
        settings = role("ucm_scheduler")
        for capability in WRITE_CAPABILITIES:
            with self.subTest(capability=capability):
                self.assertNotEqual(settings.get(capability), "enabled")
        # [default] in Splunk's authorize.conf grants these to every role.
        self.assertEqual(settings.get("run_collect"), "disabled")
        self.assertEqual(settings.get("run_mcollect"), "disabled")

    def test_index_access_is_explicit(self):
        settings = role("ucm_scheduler")
        self.assertEqual(settings.get("srchIndexesAllowed"), "*")
        self.assertEqual(settings.get("srchIndexesDefault"), "main")


if __name__ == "__main__":
    unittest.main()

"""Every data file in the app package has a recorded origin, and third-party ones are named in the notices.

STRATEGY / legal analysis L1: a new bundled data file cannot be added without deciding where it came from.
"""

import os
import unittest

import helpers

CODE = (".py", ".js", ".css", ".xml", ".conf", ".meta", ".spec", ".manifest", ".pyc")
OWN = "own"
THIRD = "third-party"

INVENTORY = {
    "sunavigator/lib/splunk_ucm/content/fenre/domain_map.json": OWN,
    "sunavigator/lib/splunk_ucm/content/fenre/uc.schema.json": THIRD,
    "sunavigator/lib/splunk_ucm/content/fenre/LICENSE": THIRD,
    "sunavigator/lib/splunk_ucm/frameworks/data/mitre_attack_enterprise-20.1.json": THIRD,
    "sunavigator/lib/splunk_ucm/frameworks/data/mitre_attack_ics-20.1.json": THIRD,
    "sunavigator/lib/splunk_ucm/frameworks/data/controls/nist-800-53-5.2.0.json": THIRD,
    "sunavigator/lib/splunk_ucm/frameworks/data/controls/nist-800-171-3.json": THIRD,
    "sunavigator/lib/splunk_ucm/frameworks/data/controls/nist-csf-2.0.json": THIRD,
    "sunavigator/lib/splunk_ucm/frameworks/data/controls/cmmc-l2-2.0.json": THIRD,
    "sunavigator/LICENSE": OWN,
    "sunavigator/NOTICE": OWN,
    "sunavigator/THIRD_PARTY_NOTICES.md": OWN,
    "sunavigator/README/inputs.conf.spec": OWN,
    "sunavigator/README/ucm.conf.spec": OWN,
    "sunavigator/static/appIcon.png": OWN,
    "sunavigator/static/appIcon_2x.png": OWN,
    "sunavigator/static/appIconAlt.png": OWN,
    "sunavigator/static/appIconAlt_2x.png": OWN,
    "sunavigator/static/appLogo.png": OWN,
    "sunavigator/static/appLogo_2x.png": OWN,
}


def _data_files():
    base = os.path.join(helpers.ROOT, "sunavigator")
    for root, dirs, names in os.walk(base):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in names:
            if name.endswith(CODE) and not name.endswith(".spec"):
                continue
            yield os.path.relpath(os.path.join(root, name), helpers.ROOT).replace(os.sep, "/")


class NoticesInventoryTest(unittest.TestCase):
    def test_every_data_file_has_a_recorded_origin(self):
        found = set(_data_files())
        self.assertEqual(sorted(found - set(INVENTORY)), [],
                         "new data file: add it to INVENTORY with its origin and, if third-party, to THIRD_PARTY_NOTICES.md")
        self.assertEqual(sorted(set(INVENTORY) - found), [], "inventory names a file that is not in the package")

    def test_third_party_files_are_named_in_the_notices(self):
        with open(os.path.join(helpers.ROOT, "sunavigator", "THIRD_PARTY_NOTICES.md"), encoding="utf-8") as handle:
            notices = handle.read()
        for path, origin in INVENTORY.items():
            if origin != THIRD:
                continue
            name = os.path.basename(path)
            stem = name.split("-20.1")[0] if name.startswith("mitre_attack_") else name
            self.assertTrue(path in notices or stem in notices or name in notices or "mitre_attack_*" in notices and name.startswith("mitre_attack_")
                            or (name == "LICENSE" and "content/fenre/LICENSE" in notices), path)


if __name__ == "__main__":
    unittest.main()

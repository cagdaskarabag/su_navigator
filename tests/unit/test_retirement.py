"""The assessment, POA&M and evidence-snapshot module is retired (D-086). Nothing of it may come back by accident."""

import os
import re
import unittest

import helpers
from splunk_ucm.api.app import CAP_ADMIN, build_router
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog

RETIRED_PREFIXES = ("assessment", "poam")


def read(*parts):
    with open(os.path.join(helpers.ROOT, "sunavigator", *parts), encoding="utf-8") as handle:
        return handle.read()


class RetirementTest(unittest.TestCase):
    def test_no_route_of_the_module_is_registered(self):
        paths = {p for _, p in build_router().routes}
        self.assertEqual(sorted(p for p in paths if p.split("/")[0] in RETIRED_PREFIXES), [])

    def test_the_retired_routes_answer_unknown_even_for_an_administrator(self):
        ctx = make_ctx(InMemoryStore(), [CAP_ADMIN])
        for method, path in (("GET", "assessment"), ("POST", "assessment"), ("GET", "poam"), ("POST", "poam/close"),
                             ("GET", "assessment/snapshot")):
            status, body = call(ctx, method, path, {"framework_id": "cmmc-l2"} if method == "GET" else None, b"{}")
            self.assertEqual(status, 404, (method, path))
            self.assertEqual(body["error"]["code"], "not_found", (method, path))

    def test_the_control_catalogue_and_mapping_stay(self):
        ctx = make_ctx(loaded_catalog(), [])
        for path, query in (("frameworks", None), ("frameworks/matrix", None),
                            ("frameworks/catalogue", {"framework_id": "cmmc-l2"})):
            status, body = call(ctx, "GET", path, query)
            self.assertNotEqual(status, 404, (path, body))

    def test_no_capability_or_role_for_the_module_is_defined(self):
        conf = read("default", "authorize.conf")
        self.assertNotIn("ucm_assess", conf)
        self.assertNotIn("ucm_compliance_assessor", conf)
        self.assertNotIn("ucm_compliance_assessor", read("metadata", "default.meta"))

    def test_splunk_web_exposes_no_route_of_the_module(self):
        self.assertIsNone(re.search(r"pattern = ucm/(assessment|poam)", read("default", "web.conf")))

    def test_the_feature_switch_is_gone(self):
        self.assertNotIn("[features]", read("default", "ucm.conf"))
        self.assertNotIn("[features]", read("README", "ucm.conf.spec"))
        self.assertFalse(os.path.exists(os.path.join(helpers.ROOT, "sunavigator", "lib", "splunk_ucm", "frameworks", "assessment.py")))
        self.assertFalse(os.path.exists(os.path.join(helpers.ROOT, "sunavigator", "lib", "splunk_ucm", "frameworks", "poam_rules.py")))

    def test_the_browser_asks_for_no_retired_endpoint(self):
        js = read("appserver", "static", "ucm_coverage.js")
        self.assertIsNone(re.search(r"""["'](assessment|poam)[/"']""", js))
        self.assertNotIn("ucm_assess", js)
        self.assertNotIn("canAssess", js)


if __name__ == "__main__":
    unittest.main()

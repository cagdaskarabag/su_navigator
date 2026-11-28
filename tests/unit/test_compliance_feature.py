"""``[features] compliance`` (D-085): off by default; the server refuses the module, the UI is told, nothing else changes."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.api.app import CAP_ASSESS, CAP_ADMIN, build_router
from splunk_ucm.config import AppConfig
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import loaded_catalog

COMPLIANCE_ROUTES = [("GET", "assessment"), ("GET", "assessment/control"), ("POST", "assessment"),
                     ("POST", "assessment/clear"), ("POST", "assessment/snapshot"), ("GET", "assessment/snapshots"),
                     ("GET", "assessment/snapshot"), ("GET", "poam"), ("POST", "poam"), ("POST", "poam/update"),
                     ("POST", "poam/close"), ("POST", "poam/reopen")]
OFF = AppConfig({})
ON = AppConfig({"features": {"compliance": "true"}})


class ComplianceFeatureTest(unittest.TestCase):
    def test_the_module_is_off_by_default(self):
        self.assertFalse(OFF.get_bool("features", "compliance", True))

    def test_every_compliance_route_answers_404_feature_disabled_even_for_an_administrator(self):
        routes = set(build_router().routes)
        for method, path in COMPLIANCE_ROUTES:
            self.assertIn((method, path), routes)
        ctx = make_ctx(InMemoryStore(), [CAP_ASSESS, CAP_ADMIN], config=OFF)
        for method, path in COMPLIANCE_ROUTES:
            body = {"framework_id": "cmmc-l2"} if method == "POST" else None
            status, out = call(ctx, method, path, {"framework_id": "cmmc-l2"} if method == "GET" else None, body or b"")
            self.assertEqual(status, 404, (method, path))
            self.assertEqual(out["error"]["code"] if "error" in out else out.get("code"), "feature_disabled", (method, path, out))

    def test_every_route_in_the_module_is_listed_here(self):
        guarded = {(m, p) for m, p in build_router().routes if p.startswith(("assessment", "poam"))}
        self.assertEqual(sorted(guarded), sorted(COMPLIANCE_ROUTES))

    def test_the_same_routes_work_when_the_module_is_on(self):
        ctx = make_ctx(InMemoryStore(), [CAP_ASSESS], config=ON)
        status, out = call(ctx, "GET", "poam", {"framework_id": "cmmc-l2"})
        self.assertEqual(status, 200, out)

    def test_catalogues_and_mapping_stay_on_with_the_module_off(self):
        ctx = make_ctx(loaded_catalog(), [], config=OFF)
        for path, query in (("frameworks", None), ("frameworks/matrix", None), ("frameworks/catalogue", {"framework_id": "cmmc-l2"}),
                            ("frameworks/controls", {"framework": "mitre_attack_enterprise"})):
            status, out = call(ctx, "GET", path, query)
            self.assertNotEqual(status, 404, (path, out))

    def test_the_frameworks_response_tells_the_page(self):
        status, out = call(make_ctx(loaded_catalog(), [], config=OFF), "GET", "frameworks")
        self.assertEqual((status, out["features"]), (200, {"compliance": False}))
        status, out = call(make_ctx(loaded_catalog(), [], config=ON), "GET", "frameworks")
        self.assertEqual(out["features"], {"compliance": True})

    def test_the_shipped_configuration_agrees_with_the_default(self):
        import os
        with open(os.path.join(helpers.ROOT, "sunavigator", "default", "ucm.conf"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("[features]\ncompliance = false\n", text)


if __name__ == "__main__":
    unittest.main()

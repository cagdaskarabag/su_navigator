"""The hardening release: the eleven low-severity items of issue #51 (D-082)."""

import os
import re
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.config import AppConfig
from unit.test_api_worker import call, make_ctx
from unit.test_deployment import UC, approved, service


def meta_stanza(name):
    with open(os.path.join(helpers.ROOT, "sunavigator", "metadata", "default.meta"), encoding="utf-8") as handle:
        text = handle.read()
    block = re.search(r"^\[%s\]\n((?:(?!\[).*\n?)*)" % re.escape(name), text, re.MULTILINE)
    return block.group(1)


def writers(name):
    access = re.search(r"write : \[ ([^\]]*) \]", meta_stanza(name)).group(1)
    return [w.strip() for w in access.split(",")]


class RolesAndAuditTest(unittest.TestCase):
    def test_item_1_ucm_admin_cannot_write_deployed_saved_searches(self):
        self.assertEqual(writers("savedsearches"), ["admin", "sc_admin"])

    def verified_rows(self, store):
        return [r for r in store.query("uc_audit", {}, limit=500) if r.get("action") == "deployment.verified"]

    def test_item_2_repeated_verify_writes_one_audit_row_per_window(self):
        svc, store, saved = service()
        approved(svc)
        svc.deploy("bob", UC)
        before = len(self.verified_rows(store))
        for _ in range(5):
            svc.verify("carol", UC)
        self.assertEqual(len(self.verified_rows(store)) - before, 1)

    def test_item_2_a_change_in_the_result_is_always_written(self):
        svc, store, saved = service()
        approved(svc)
        name = svc.deploy("bob", UC)["saved_search"]["name"]
        svc.verify("carol", UC)
        first = len(self.verified_rows(store))
        saved.items[name]["cron_schedule"] = "0 * * * *"
        svc.verify("carol", UC)
        svc.verify("carol", UC)
        self.assertEqual(len(self.verified_rows(store)) - first, 1)

    def test_item_2_window_zero_writes_every_time(self):
        svc, store, saved = service(verify_audit_window_seconds=0)
        approved(svc)
        svc.deploy("bob", UC)
        before = len(self.verified_rows(store))
        for _ in range(3):
            svc.verify("carol", UC)
        self.assertEqual(len(self.verified_rows(store)) - before, 3)

    def test_item_2_audit_verify_is_a_post_and_throttled(self):
        from splunk_ucm.storage.kvstore import InMemoryStore
        store = InMemoryStore()
        ctx = make_ctx(store, ["ucm_admin"], AppConfig({}))
        self.assertEqual(call(ctx, "GET", "audit/verify")[0], 405)
        for _ in range(4):
            status, body = call(ctx, "POST", "audit/verify")
            self.assertEqual(status, 200)
            self.assertTrue(body["ok"])
        rows = [r for r in store.query("uc_audit", {}, limit=50) if r.get("action") == "audit.verified"]
        self.assertEqual(len(rows), 1)

    def test_item_2_audit_verify_still_needs_a_capability(self):
        from splunk_ucm.storage.kvstore import InMemoryStore
        self.assertEqual(call(make_ctx(InMemoryStore(), []), "POST", "audit/verify")[0], 403)


class SaveTokenTest(unittest.TestCase):
    def test_item_3_two_saves_from_the_same_version_are_told_apart(self):
        from splunk_ucm.errors import ConflictError
        from splunk_ucm.storage import collections as C
        svc, store, _ = service()
        svc.save_draft("alice", UC, {})
        real = store.upsert
        rival_wrote = []

        def with_rival(collection, doc):
            real(collection, doc)
            if collection == C.DEPLOYMENTS and not rival_wrote:
                rival_wrote.append(True)
                other = dict(doc)
                other["save_token"] = "someone-else"
                real(collection, other)
        store.upsert = with_rival
        with self.assertRaises(ConflictError) as raised:
            svc.submit("alice", UC)
        self.assertEqual(raised.exception.details["code"], "concurrent_update_detected")

    def test_item_3_the_token_is_stored_but_not_returned(self):
        from splunk_ucm.deployment.service import deployment_key
        from splunk_ucm.storage import collections as C
        svc, store, _ = service()
        doc = svc.save_draft("alice", UC, {})
        self.assertNotIn("save_token", doc)
        stored = store.get(C.DEPLOYMENTS, deployment_key("fenre_UC-9.1.1"))
        self.assertTrue(stored["save_token"])
        first = stored["save_token"]
        svc.submit("alice", UC)
        self.assertNotEqual(store.get(C.DEPLOYMENTS, deployment_key("fenre_UC-9.1.1"))["save_token"], first)


class DraftAuditTest(unittest.TestCase):
    def draft_rows(self, store):
        return [r for r in store.query("uc_audit", {}, limit=500) if r.get("action") == "deployment.draft"]

    def test_item_4_the_draft_row_says_which_state_it_replaced(self):
        svc, store, _ = service()
        svc.save_draft("alice", UC, {})
        svc.save_draft("alice", UC, {"severity": "high"})
        svc.submit("alice", UC)
        svc.save_draft("mallory", UC, {"severity": "low"})
        rows = sorted(self.draft_rows(store), key=lambda r: r["time"])
        self.assertEqual([(r["details"]["from"], r["details"]["replaced_draft"]) for r in rows],
                         [("none", False), ("draft", True), ("pending_approval", False)])
        self.assertEqual(rows[-1]["actor"], "mallory")
        self.assertEqual(rows[-1]["details"]["revision"], 2)


class WildcardAndChainTest(unittest.TestCase):
    def check(self, allowed, pattern="fw_*", known=("fw_a", "fw_b", "fw_c")):
        from splunk_ucm.readiness.principal import PrincipalAccess, check_access
        principal = PrincipalAccess("svc", roles=["r"], allowed=allowed)
        scan = {"indexes": [pattern], "reads_indexes": True, "uses_default": False, "unverified": [], "sourcetypes": []}
        return check_access(principal, scan, [{"name": k} for k in known])

    def test_item_5_a_wildcard_the_account_only_partly_covers_is_partial(self):
        result = self.check(["fw_a"])
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["code"], "index_not_accessible")
        self.assertIn("fw_b", result["detail"])
        row = result["observed"][0]
        self.assertTrue(row["partial"] and row["searchable"])
        self.assertIn("matches 3 indexes", row["reason"])

    def test_item_5_a_wildcard_fully_covered_is_met_and_not_covered_is_not_met(self):
        self.assertEqual(self.check(["fw_*"])["status"], "met")
        self.assertEqual(self.check(["other"])["status"], "not_met")

    def test_item_5_the_verify_result_lists_the_rows_that_share_a_predecessor(self):
        from splunk_ucm.audit import AuditService, row_hash
        from splunk_ucm.storage import collections as C
        from splunk_ucm.storage.kvstore import InMemoryStore
        store = InMemoryStore()
        audit = AuditService(store)
        for i in range(3):
            audit.record("a", "deployment.draft", "deployment", "x%d" % i)
        rows = sorted(store.query(C.AUDIT, {}, limit=10), key=lambda r: r["time"])
        twin = {"_key": "zz", "time": rows[-1]["time"] + 0.5, "time_iso": "t", "actor": "b", "action": "deployment.twin",
                "object_type": "deployment", "object_id": "x", "outcome": "success", "details": {},
                "prev_hash": rows[-2]["hash"]}
        twin["hash"] = row_hash(twin)
        store.upsert(C.AUDIT, twin)
        result = audit.verify_chain()
        self.assertTrue(result["ok"])
        self.assertEqual(result["branches"], 1)
        self.assertEqual(sorted(r["action"] for r in result["branch_rows"]), ["deployment.draft", "deployment.twin"])
        clean = AuditService(InMemoryStore())
        clean.record("a", "x", "x", "x")
        self.assertEqual(clean.verify_chain()["branch_rows"], [])


class SplSplitTest(unittest.TestCase):
    def side_effects(self, spl):
        from splunk_ucm.spl.analysis import analyze
        return analyze(spl).side_effect_commands

    def test_item_6_a_backtick_inside_a_comment_does_not_hide_a_later_command(self):
        spl = "index=a [ ```a`b``` | makeresults | outputlookup x.csv ]"
        self.assertIn("outputlookup", self.side_effects(spl))

    def test_item_6_an_unpaired_backtick_hides_nothing(self):
        self.assertIn("outputlookup", self.side_effects("index=a ` | outputlookup x.csv"))
        self.assertIn("collect", self.side_effects("index=a | stats count ` | collect index=x"))
        self.assertIn("outputlookup", self.side_effects("index=a ```never closed | outputlookup x.csv"))

    def test_item_6_a_closed_comment_and_closed_macros_are_still_skipped(self):
        self.assertEqual(self.side_effects("index=a ```| outputlookup x``` | stats count"), [])
        self.assertEqual(self.side_effects("index=a `m` ``` note ``` `n(1)` | stats count"), [])
        self.assertIn("outputlookup", self.side_effects("index=a ```note``` | `m` | outputlookup x.csv"))

    def test_item_6_the_policy_refuses_the_case_from_the_review(self):
        from splunk_ucm.spl.policy import classify
        verdict = classify("index=a [ ```a`b``` | makeresults | outputlookup x.csv ]")
        self.assertIn("outputlookup", verdict.side_effects)


class PackageLimitsTest(unittest.TestCase):
    def archive(self, tmp, entries):
        import io
        import tarfile
        path = os.path.join(tmp, "p.tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    def test_item_7_a_symlinked_package_file_is_refused(self):
        import tempfile
        from splunk_ucm.content.escu import package
        from splunk_ucm.errors import ValidationError
        with tempfile.TemporaryDirectory() as tmp:
            outside = os.path.join(tmp, "outside.conf")
            with open(outside, "w") as handle:
                handle.write("[x]\nsearch = y\n")
            pkg = os.path.join(tmp, "pkg")
            os.makedirs(os.path.join(pkg, "default"))
            os.symlink(outside, os.path.join(pkg, "default", "savedsearches.conf"))
            with self.assertRaises(ValidationError) as raised:
                package.read_package(pkg)
            self.assertIn("symbolic link", raised.exception.message)

    def test_item_7_a_symlinked_default_directory_is_refused(self):
        import tempfile
        from splunk_ucm.content.escu import package
        from splunk_ucm.errors import ValidationError
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "elsewhere")
            os.makedirs(real)
            with open(os.path.join(real, "savedsearches.conf"), "w") as handle:
                handle.write("[x]\nsearch = y\n")
            pkg = os.path.join(tmp, "pkg")
            os.makedirs(pkg)
            os.symlink(real, os.path.join(pkg, "default"))
            with self.assertRaises(ValidationError):
                package.read_package(pkg)

    def test_item_7_a_plain_directory_still_reads(self):
        import tempfile
        from splunk_ucm.content.escu import package
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "default"))
            with open(os.path.join(tmp, "default", "savedsearches.conf"), "w") as handle:
                handle.write("[x]\nsearch = y\n")
            self.assertIn("default/savedsearches.conf", package.read_package(tmp)["files"])

    def test_item_7_an_archive_with_too_many_members_is_refused(self):
        import tempfile
        from unittest import mock
        from splunk_ucm.content.escu import package
        from splunk_ucm.errors import ValidationError
        with tempfile.TemporaryDirectory() as tmp:
            path = self.archive(tmp, [("default/savedsearches.conf", b"[x]\n")] + [("f%d" % i, b"") for i in range(10)])
            with mock.patch.object(package, "MAX_ARCHIVE_MEMBERS", 5):
                with self.assertRaises(ValidationError) as raised:
                    package.read_package(path)
            self.assertIn("too many members", raised.exception.message)
            self.assertIn("default/savedsearches.conf", package.read_package(path)["files"])

    def test_item_7_an_archive_that_unpacks_to_too_much_is_refused(self):
        import tempfile
        from unittest import mock
        from splunk_ucm.content.escu import package
        from splunk_ucm.errors import ValidationError
        with tempfile.TemporaryDirectory() as tmp:
            path = self.archive(tmp, [("default/savedsearches.conf", b"[x]\n"), ("big.bin", b"0" * 5000)])
            with mock.patch.object(package, "MAX_UNPACKED_BYTES", 1000):
                with self.assertRaises(ValidationError) as raised:
                    package.read_package(path)
            self.assertIn("too much data", raised.exception.message)


class RecordRobustnessTest(unittest.TestCase):
    def validator(self, schema=None):
        from splunk_ucm.content.fenre.normalizer import fenre_validation_policy
        from splunk_ucm.content.validation import RecordValidator
        return RecordValidator(fenre_validation_policy(512 * 1024), schema)

    def test_item_8_a_scalar_references_value_rejects_the_record_only(self):
        for bad in (5, "https://example.com", {"url": "https://example.com"}, True):
            result = self.validator().validate({"id": "1.1.1", "title": "t", "references": bad})
            self.assertFalse(result.ok, bad)
            self.assertIn("type_mismatch", [f.code for f in result.errors], bad)

    def test_item_8_references_as_a_list_still_checks_the_urls(self):
        result = self.validator().validate({"id": "1.1.1", "title": "t",
                                            "references": [{"url": "javascript:alert(1)"}, {"url": "https://a.example/x"}]})
        self.assertTrue(result.ok)
        self.assertEqual([f.code for f in result.warnings], ["non_http_url"])

    def test_item_8_an_invalid_regex_in_a_schema_does_not_crash_validation(self):
        schema = {"type": "object", "properties": {"title": {"type": "string", "pattern": "(["}}}
        from splunk_ucm.content.jsonschema_subset import SchemaValidator
        self.assertEqual(SchemaValidator(schema).invalid_patterns, ["(["])
        result = self.validator(schema).validate({"id": "1.1.1", "title": "t"})
        self.assertTrue(result.ok)

    def test_item_8_a_valid_pattern_still_applies(self):
        schema = {"type": "object", "properties": {"code": {"type": "string", "pattern": "^[a-z]+$"}}}
        result = self.validator(schema).validate({"id": "1.1.1", "title": "t", "code": "ABC"})
        self.assertIn("schema_pattern", [f.code for f in result.warnings])

    def test_item_8_an_upstream_schema_with_a_bad_pattern_falls_back_to_the_bundled_one(self):
        import json
        gh = helpers.FakeGitHub()
        schema = json.loads(gh.files["schemas/uc.schema.json"])
        schema.setdefault("properties", {})["x"] = {"type": "string", "pattern": "(["}
        gh.put("schemas/uc.schema.json", schema)
        manifest = helpers.fenre_provider(gh).get_manifest()
        self.assertTrue(any("bundled schema" in w and "regular expression" in w for w in manifest.warnings), manifest.warnings)
        self.assertEqual(manifest.schema_version, "1.11.0")


class RolesTransport:
    def __init__(self, default):
        self.default = default

    def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        import json
        if "/authentication/users/" in path:
            content = {"roles": ["r"]}
        else:
            content = {"srchIndexesAllowed": ["*"], "srchIndexesDefault": self.default}
        return 200, json.dumps({"entry": [{"content": content}]}).encode()


class TestIndexTest(unittest.TestCase):
    def run_test(self, index, default=None, with_roles=True):
        from splunk_ucm.storage.kvstore import InMemoryStore
        ctx = make_ctx(InMemoryStore(), ["ucm_deploy"], AppConfig({"controltest": {"index": index}}))
        if with_roles:
            ctx.system_transport = RolesTransport(default or [])
        return call(ctx, "POST", "deployment/controltest", body={"id": UC})

    def test_item_9_main_is_never_a_test_index(self):
        status, body = self.run_test("main", with_roles=False)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["details"]["code"], "test_index_is_default")

    def test_item_9_a_default_index_of_the_caller_is_refused(self):
        status, body = self.run_test("ucm_controltest", default=["ucm_controltest"])
        self.assertEqual((status, body["error"]["details"]["code"]), (409, "test_index_is_default"))
        status, body = self.run_test("ucm_controltest", default=["ucm_*"])
        self.assertEqual(status, 409, body)

    def test_item_9_a_dedicated_index_goes_on_to_the_normal_checks(self):
        status, body = self.run_test("ucm_controltest", default=["main"])
        self.assertNotEqual(body.get("error", {}).get("details", {}).get("code"), "test_index_is_default", body)

    def test_item_9_the_check_does_not_open_the_action_to_a_viewer(self):
        from splunk_ucm.storage.kvstore import InMemoryStore
        ctx = make_ctx(InMemoryStore(), [], AppConfig({"controltest": {"index": "main"}}))
        self.assertEqual(call(ctx, "POST", "deployment/controltest", body={"id": UC})[0], 403)


class CsvGuardTest(unittest.TestCase):
    def test_item_10_leading_whitespace_does_not_hide_a_formula(self):
        from splunk_ucm.frameworks.evidence import _cell
        for text in ("=1+1", " =1+1", "  +cmd", "\u00a0@SUM(A1)", "\n-2", "\t=x", "\r=x"):
            self.assertTrue(_cell(text).startswith("'"), repr(text))
        for text in ("plain", " plain", "a=b", "", "3-4"):
            self.assertEqual(_cell(text), text)

    def test_item_10_the_fenre_report_csv_uses_the_same_guard(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("fenre_report", os.path.join(helpers.ROOT, "tools", "fenre_report.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        text = module.csv_text([{"rule": "L001", "use_case": "1.1.1", "title": " =HYPERLINK(1)", "search": "index=a",
                                 "command": "x", "call": "y", "suggestion": "z"}])
        self.assertIn("' =HYPERLINK(1)", text)


class SelectionsClampTest(unittest.TestCase):
    def test_item_11_count_is_clamped(self):
        from splunk_ucm.selection.service import MAX_COUNT
        from unit.test_discovery import loaded_catalog
        store = loaded_catalog()
        ctx = make_ctx(store, [])
        for asked, expected in (("100000", MAX_COUNT), ("0", 1), ("-5", 1), ("25", 25)):
            status, body = call(ctx, "GET", "selections", {"count": asked})
            self.assertEqual(status, 200, body)
            seen = []
            real = store.query

            def spy(collection, query=None, **kw):
                seen.append(kw.get("limit"))
                return real(collection, query, **kw)
            store.query = spy
            call(ctx, "GET", "selections", {"count": asked})
            store.query = real
            self.assertEqual(seen[-1], expected + 1, (asked, seen))

    def test_item_11_a_negative_offset_is_treated_as_zero(self):
        from unit.test_discovery import loaded_catalog
        status, body = call(make_ctx(loaded_catalog(), []), "GET", "selections", {"offset": "-3"})
        self.assertEqual((status, body["offset"]), (200, 0))


if __name__ == "__main__":
    unittest.main()

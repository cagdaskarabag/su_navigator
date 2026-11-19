import copy
import unittest

import helpers
from splunk_ucm.content.fenre.normalizer import fenre_validation_policy
from splunk_ucm.content.fenre.provider import load_bundled_schema
from splunk_ucm.content.jsonschema_subset import SchemaValidator
from splunk_ucm.content.validation import RecordValidator, find_duplicates, is_safe_url


def codes(findings):
    return sorted({f.code for f in findings})


class SchemaSubsetTest(unittest.TestCase):
    def test_core_keywords(self):
        schema = {"type": "object", "required": ["a"], "additionalProperties": False,
                  "properties": {"a": {"type": "string", "pattern": "^x", "maxLength": 3},
                                 "b": {"type": "array", "items": {"enum": [1, 2]}, "uniqueItems": True},
                                 "c": {"oneOf": [{"type": "integer"}, {"type": "null"}]}}}
        v = SchemaValidator(schema)
        self.assertEqual(v.validate({"a": "xy", "b": [1, 2], "c": None}), [])
        kws = sorted(f.keyword for f in v.validate({"a": "yyyy", "b": [1, 1, 3], "d": 1}))
        self.assertEqual(kws, ["additionalProperties", "enum", "maxLength", "pattern", "uniqueItems"])
        self.assertEqual([f.keyword for f in v.validate({})], ["required"])

    def test_boolean_integer_distinction(self):
        v = SchemaValidator({"type": "integer"})
        self.assertTrue(v.validate(True))
        self.assertEqual(v.validate(3), [])

    def test_false_schema_rejects(self):
        v = SchemaValidator({"properties": {"x": False}})
        self.assertTrue(v.validate({"x": 1}))

    def test_upstream_schema_loads_and_reports_version(self):
        v = SchemaValidator(load_bundled_schema())
        self.assertEqual(v.version, "1.11.0")


class RecordValidatorTest(unittest.TestCase):
    def setUp(self):
        self.validator = RecordValidator(fenre_validation_policy(), load_bundled_schema())
        self.record = helpers.load_fixture_record("9.1.1")

    def test_real_fixture_records_are_valid(self):
        for rid in ("1.1.1", "5.2.14", "7.1.1", "8.1.1", "9.1.1", "9.1.2", "10.4.24", "13.1.1", "14.1.1",
                    "18.2.1"):
            res = self.validator.validate(helpers.load_fixture_record(rid))
            self.assertTrue(res.ok, (rid, [(f.code, f.path) for f in res.errors]))

    def test_missing_id_and_title_are_errors(self):
        rec = copy.deepcopy(self.record)
        del rec["id"]
        rec["title"] = "  "
        res = self.validator.validate(rec)
        self.assertFalse(res.ok)
        self.assertIn("invalid_id", codes(res.errors))
        self.assertIn("invalid_title", codes(res.errors))

    def test_malformed_id_rejected(self):
        for bad in ("9.1", "09.1.1", "9.1.1; drop", 911):
            rec = dict(self.record, id=bad)
            self.assertIn("invalid_id", codes(self.validator.validate(rec).errors), bad)

    def test_unknown_property_is_warning_not_error(self):
        rec = dict(self.record, someFutureField={"x": 1})
        res = self.validator.validate(rec)
        self.assertTrue(res.ok)
        self.assertIn("schema_additionalProperties", codes(res.warnings))

    def test_enum_drift_is_warning(self):
        rec = dict(self.record, criticality="catastrophic")
        res = self.validator.validate(rec)
        self.assertTrue(res.ok)
        self.assertTrue(res.warnings)

    def test_consumed_field_type_mismatch_is_error(self):
        rec = dict(self.record, mitreAttack="T1110")
        res = self.validator.validate(rec)
        self.assertFalse(res.ok)
        self.assertIn("type_mismatch", codes(res.errors))

    def test_size_and_spl_limits(self):
        res = self.validator.validate(self.record, raw_size=10 * 1024 * 1024)
        self.assertIn("too_large", codes(res.errors))
        rec = dict(self.record, spl="index=a\x00 | delete")
        self.assertIn("spl_control_chars", codes(self.validator.validate(rec).errors))
        rec = dict(self.record, spl="x" * (65 * 1024))
        self.assertIn("spl_too_long", codes(self.validator.validate(rec).errors))

    def test_unsafe_reference_urls_are_flagged(self):
        rec = dict(self.record, references=[{"url": "javascript:alert(1)", "title": "x"},
                                            {"url": "docs/local.md", "title": "y"}])
        res = self.validator.validate(rec)
        self.assertEqual([f.path for f in res.findings if f.code == "non_http_url"],
                         ["/references/0/url", "/references/1/url"])

    def test_non_object(self):
        self.assertIn("not_object", codes(self.validator.validate(["x"]).errors))

    def test_helpers(self):
        self.assertTrue(is_safe_url("https://example.com/a"))
        self.assertFalse(is_safe_url("javascript:alert(1)"))
        self.assertFalse(is_safe_url("//example.com"))
        self.assertEqual(find_duplicates(["a", "b", "a", "a"]), ["a"])


if __name__ == "__main__":
    unittest.main()

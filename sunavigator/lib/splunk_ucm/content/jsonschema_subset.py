"""Minimal JSON Schema (draft 2020-12) validator for a documented keyword subset.

Supported: type, enum, const, required, properties, additionalProperties,
items, minItems, maxItems, uniqueItems, minLength, maxLength, pattern,
minimum, maximum, oneOf, anyOf, allOf, not, format (uri, date, date-time).
Unsupported keywords are reported via ``unsupported_keywords`` so callers know
validation was partial — they are never silently treated as satisfied.
"""

import dataclasses
import datetime
import re
from typing import Any, Dict, List, Sequence, Set, Union
from urllib.parse import urlparse

PathT = List[Union[str, int]]

_ANNOTATIONS = {
    "$schema", "$id", "$comment", "title", "description", "default", "examples",
    "deprecated", "readOnly", "writeOnly", "version", "schemaVersion",
}
_SUPPORTED = {
    "type", "enum", "const", "required", "properties", "additionalProperties", "items",
    "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum",
    "maximum", "oneOf", "anyOf", "allOf", "not", "format",
}


@dataclasses.dataclass
class SchemaFinding:
    path: PathT
    keyword: str
    message: str

    @property
    def pointer(self) -> str:
        return "/" + "/".join(str(p) for p in self.path)


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    return False


def _check_format(value: str, fmt: str) -> bool:
    if fmt == "uri":
        parsed = urlparse(value)
        return bool(parsed.scheme) and bool(parsed.netloc or parsed.path)
    if fmt == "date":
        try:
            datetime.datetime.strptime(value, "%Y-%m-%d")
            return True
        except ValueError:
            return False
    if fmt == "date-time":
        try:
            datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False
    return True  # unknown formats are annotations per draft 2020-12


class SchemaValidator:
    def __init__(self, schema: Dict[str, Any]):
        if not isinstance(schema, dict):
            raise ValueError("schema must be an object")
        self.schema = schema
        self.unsupported_keywords: Set[str] = set()
        self.invalid_patterns: List[str] = []
        self._scan(schema)
        self._pattern_cache: Dict[str, Any] = {}

    def _scan(self, node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.startswith("x-"):
                    continue
                if key not in _SUPPORTED and key not in _ANNOTATIONS:
                    self.unsupported_keywords.add(key)
                if key == "pattern" and isinstance(value, str) and self._compile(value) is None:
                    self.invalid_patterns.append(value[:200])
                if key == "properties" and isinstance(value, dict):
                    for sub in value.values():
                        self._scan(sub)
                elif key in ("items", "additionalProperties", "not") and isinstance(value, dict):
                    self._scan(value)
                elif key in ("oneOf", "anyOf", "allOf") and isinstance(value, list):
                    for sub in value:
                        self._scan(sub)

    @property
    def version(self) -> str:
        return str(self.schema.get("version", ""))

    def validate(self, instance: Any) -> List[SchemaFinding]:
        findings: List[SchemaFinding] = []
        self._validate(instance, self.schema, [], findings)
        return findings

    @staticmethod
    def _compile(pattern: Any):
        try:
            return re.compile(pattern)
        except (re.error, TypeError, RecursionError, OverflowError):
            return None

    def _regex(self, pattern: str):
        if pattern not in self._pattern_cache:
            self._pattern_cache[pattern] = self._compile(pattern)
        return self._pattern_cache[pattern]

    def _validate(self, value: Any, schema: Any, path: PathT, out: List[SchemaFinding]) -> None:
        if schema is False:
            out.append(SchemaFinding(path, "false", "no value is allowed here"))
            return
        if not isinstance(schema, dict):
            return

        types = schema.get("type")
        if types is not None:
            names: Sequence[str] = types if isinstance(types, list) else [types]
            if not any(_is_type(value, n) for n in names):
                out.append(SchemaFinding(path, "type", "expected %s" % "/".join(names)))
                return  # further checks would be noise

        if "enum" in schema and value not in schema["enum"]:
            out.append(SchemaFinding(path, "enum", "value %r not in enum" % (value,)))
        if "const" in schema and value != schema["const"]:
            out.append(SchemaFinding(path, "const", "value does not match const"))

        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                out.append(SchemaFinding(path, "minLength", "shorter than %d" % schema["minLength"]))
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                out.append(SchemaFinding(path, "maxLength", "longer than %d" % schema["maxLength"]))
            if "pattern" in schema and self._regex(schema["pattern"]) is not None \
                    and not self._regex(schema["pattern"]).search(value):
                out.append(SchemaFinding(path, "pattern", "does not match %s" % schema["pattern"]))
            if "format" in schema and not _check_format(value, schema["format"]):
                out.append(SchemaFinding(path, "format", "not a valid %s" % schema["format"]))

        if _is_type(value, "number"):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(SchemaFinding(path, "minimum", "below %s" % schema["minimum"]))
            if "maximum" in schema and value > schema["maximum"]:
                out.append(SchemaFinding(path, "maximum", "above %s" % schema["maximum"]))

        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                out.append(SchemaFinding(path, "minItems", "fewer than %d items" % schema["minItems"]))
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                out.append(SchemaFinding(path, "maxItems", "more than %d items" % schema["maxItems"]))
            if schema.get("uniqueItems"):
                seen: List[Any] = []
                for item in value:
                    if item in seen:
                        out.append(SchemaFinding(path, "uniqueItems", "duplicate item %r" % (item,)))
                        break
                    seen.append(item)
            items = schema.get("items")
            if isinstance(items, dict):
                for i, item in enumerate(value):
                    self._validate(item, items, path + [i], out)

        if isinstance(value, dict):
            for req in schema.get("required", []):
                if req not in value:
                    out.append(SchemaFinding(path + [req], "required", "required property missing"))
            props = schema.get("properties", {})
            for key, sub in props.items():
                if key in value:
                    self._validate(value[key], sub, path + [key], out)
            addl = schema.get("additionalProperties", True)
            extra = [k for k in value if k not in props]
            if addl is False:
                for key in extra:
                    out.append(SchemaFinding(path + [key], "additionalProperties", "unknown property"))
            elif isinstance(addl, dict):
                for key in extra:
                    self._validate(value[key], addl, path + [key], out)

        for comb in ("allOf", "anyOf", "oneOf"):
            subs = schema.get(comb)
            if not isinstance(subs, list):
                continue
            results = []
            for sub in subs:
                sub_out: List[SchemaFinding] = []
                self._validate(value, sub, path, sub_out)
                results.append(sub_out)
            passing = sum(1 for r in results if not r)
            if comb == "allOf":
                for r in results:
                    out.extend(r)
            elif comb == "anyOf" and passing == 0:
                out.append(SchemaFinding(path, "anyOf", "matches none of the alternatives"))
            elif comb == "oneOf" and passing != 1:
                out.append(SchemaFinding(path, "oneOf", "matches %d alternatives, expected 1" % passing))

        if "not" in schema:
            sub_out = []
            self._validate(value, schema["not"], path, sub_out)
            if not sub_out:
                out.append(SchemaFinding(path, "not", "matches a disallowed schema"))

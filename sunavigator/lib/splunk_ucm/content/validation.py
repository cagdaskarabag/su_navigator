"""Validation of untrusted provider records (policy: docs/DECISIONS.md D-007).

Two layers:

1. Upstream schema (subset validator) — findings on fields the normalizer
   consumes become errors when they would corrupt normalization (type
   mismatches, missing id/title); additive evolution (unknown properties, new
   enum values) becomes a warning.
2. Safety checks independent of any schema — size limits, URL schemes, SPL
   length, identifier format.
"""

import dataclasses
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from .jsonschema_subset import SchemaFinding, SchemaValidator

ERROR = "error"
WARNING = "warning"

# Keywords whose violation reflects upstream additive change rather than broken data.
_TOLERATED_KEYWORDS = {"additionalProperties", "enum"}


@dataclasses.dataclass
class Finding:
    severity: str
    code: str
    path: str
    message: str


@dataclasses.dataclass
class ValidationResult:
    record_id: str
    findings: List[Finding] = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == ERROR for f in self.findings)

    @property
    def errors(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == ERROR]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == WARNING]

    def summary(self, limit: int = 5) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "ok": self.ok,
            "errors": [dataclasses.asdict(f) for f in self.errors[:limit]],
            "warning_count": len(self.warnings),
        }


@dataclasses.dataclass
class FieldContract:
    """Expected JSON type of a top-level field the normalizer reads."""

    name: str
    json_type: str  # string | array | object | integer
    item_type: Optional[str] = None


@dataclasses.dataclass
class ValidationPolicy:
    id_field: str = "id"
    id_pattern: str = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    title_field: str = "title"
    max_record_bytes: int = 512 * 1024
    max_spl_chars: int = 64 * 1024
    spl_fields: Tuple[str, ...] = ("spl", "cimSpl")
    url_fields: Tuple[str, ...] = ("references",)
    consumed: Tuple[FieldContract, ...] = ()


def _type_ok(value: Any, json_type: str) -> bool:
    if json_type == "string":
        return isinstance(value, str)
    if json_type == "array":
        return isinstance(value, list)
    if json_type == "object":
        return isinstance(value, dict)
    if json_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return True


def is_safe_url(url: Any) -> bool:
    if not isinstance(url, str) or len(url) > 2048:
        return False
    parsed = urlparse(url.strip())
    return parsed.scheme in ("https", "http") and bool(parsed.netloc)


class RecordValidator:
    def __init__(self, policy: ValidationPolicy, schema: Optional[Dict[str, Any]] = None):
        self.policy = policy
        self.schema_validator = SchemaValidator(schema) if schema else None
        self._consumed = {c.name: c for c in policy.consumed}
        self._id_re = re.compile(policy.id_pattern)

    @property
    def schema_version(self) -> str:
        return self.schema_validator.version if self.schema_validator else ""

    def validate(self, record: Any, raw_size: Optional[int] = None) -> ValidationResult:
        rid = str(record.get(self.policy.id_field, "")) if isinstance(record, dict) else ""
        result = ValidationResult(record_id=rid)
        add = result.findings.append
        if not isinstance(record, dict):
            add(Finding(ERROR, "not_object", "/", "record is not a JSON object"))
            return result

        size = raw_size if raw_size is not None else len(json.dumps(record))
        if size > self.policy.max_record_bytes:
            add(Finding(ERROR, "too_large", "/", "record is %d bytes (limit %d)"
                        % (size, self.policy.max_record_bytes)))

        rid_value = record.get(self.policy.id_field)
        if not isinstance(rid_value, str) or not self._id_re.match(rid_value):
            add(Finding(ERROR, "invalid_id", "/" + self.policy.id_field,
                        "missing or malformed content id"))
        title = record.get(self.policy.title_field)
        if not isinstance(title, str) or not title.strip():
            add(Finding(ERROR, "invalid_title", "/" + self.policy.title_field, "missing title"))

        for name, contract in self._consumed.items():
            if name not in record or record[name] is None:
                continue
            value = record[name]
            if not _type_ok(value, contract.json_type):
                add(Finding(ERROR, "type_mismatch", "/" + name,
                            "expected %s for consumed field" % contract.json_type))
                continue
            if contract.json_type == "array" and contract.item_type:
                for i, item in enumerate(value):
                    if not _type_ok(item, contract.item_type):
                        add(Finding(ERROR, "type_mismatch", "/%s/%d" % (name, i),
                                    "expected %s items" % contract.item_type))
                        break

        for name in self.policy.spl_fields:
            spl = record.get(name)
            if isinstance(spl, str) and len(spl) > self.policy.max_spl_chars:
                add(Finding(ERROR, "spl_too_long", "/" + name, "SPL exceeds size limit"))
            if isinstance(spl, str) and "\x00" in spl:
                add(Finding(ERROR, "spl_control_chars", "/" + name, "SPL contains NUL bytes"))

        for name in self.policy.url_fields:
            for i, ref in enumerate(record.get(name) or []):
                url = ref.get("url") if isinstance(ref, dict) else None
                # Non-http(s) links are never rendered as links; the normalizer drops
                # them or keeps repository-relative paths as plain text.
                if url is not None and not is_safe_url(url):
                    add(Finding(WARNING, "non_http_url", "/%s/%d/url" % (name, i),
                                "reference is not an absolute http(s) URL"))

        if self.schema_validator:
            for sf in self.schema_validator.validate(record):
                add(self._classify(sf))
        return result

    def _classify(self, sf: SchemaFinding) -> Finding:
        top = str(sf.path[0]) if sf.path else ""
        code = "schema_" + sf.keyword
        if sf.keyword in _TOLERATED_KEYWORDS:
            return Finding(WARNING, code, sf.pointer, sf.message)
        if top in (self.policy.id_field, self.policy.title_field):
            return Finding(ERROR, code, sf.pointer, sf.message)
        if top in self._consumed and sf.keyword == "type":
            return Finding(ERROR, code, sf.pointer, sf.message)
        return Finding(WARNING, code, sf.pointer, sf.message)


def find_duplicates(ids: Iterable[str]) -> List[str]:
    seen = set()
    dupes = []
    for rid in ids:
        if rid in seen and rid not in dupes:
            dupes.append(rid)
        seen.add(rid)
    return dupes

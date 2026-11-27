"""Post-deploy control test: Fenre ``samples/`` fixtures replayed against the deployed SPL (T-23, D-054, D-064).

A fixture is the raw ``positive.log`` (and ``negative.log`` when present) of one
use case, plus the manifest's ``expected`` block. For a deployed revision the runner:

1. splits the fixture into events and sends each one to splunkd's raw receiver,
   into the dedicated test index (``[controltest] index``), with the sourcetype
   from the manifest and a per-run ``source`` marker, so only this run's events
   can match;
2. waits until every event is searchable. A shortfall is inconclusive, not a fail;
3. runs the deployed SPL with the index filter of its search clauses rewritten to
   the test index and the marker, over a window derived from the fixture's own
   timestamps (``derive_window``). A positive run needs at least
   ``expected.min_count`` result rows, at most ``expected.max_count`` when set, and
   must satisfy every ``expected.fields`` assertion; a negative run needs no rows.

Verdicts: ``passed``, ``failed`` (the search ran and the assertions did not hold),
``content_error`` (Splunk reported a search error on the test data),
``inconclusive`` (the data was not searchable in time, the receiver failed or the
search timed out) and ``not_runnable`` (the SPL cannot be scoped to the test index).
Results stored before ``content_error`` existed keep their meaning and are not migrated.

Event boundaries: if the file separates events with blank lines, each block is
one event; otherwise each non-empty line is one event (``split_events``). Sending
each event on its own keeps Splunk from merging lines into one event. Events keep
the timestamps in the file; the marker, not the time, scopes the match.

The search's own ``earliest=``/``latest=`` terms are removed from its search clauses:
fixture timestamps are fixed and cannot match a production window, so the test
checks the search logic over the test window. Searches that cannot be scoped to the
test index are ``not_runnable`` and are never sent to a production index. The
fixture's manifest ``index`` and ``source`` are ignored. Re-running a control test
appends events to the test index; the marker keeps runs apart. Retention of that
index is an operator setting.
"""

import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..errors import StorageError, UcmError, UnsupportedOperation, ValidationError
from ..platform.search import SearchFailed

FIXTURE_FORMAT = "ucm-control-fixtures"
FIXTURE_VERSION = 1
DEFAULT_TEST_INDEX = "ucm_controltest"
MAX_FIXTURE_BYTES = 512 * 1024
MAX_FIXTURES_PER_IMPORT = 2000
MAX_EVENTS_PER_FIXTURE = 1000
WINDOW_EARLIEST = "-10y"
WINDOW_LATEST = "+1d"
MAX_RESULT_ROWS = 1000
SETTLE_SECONDS = 45.0
_SETTLE_STEP = 1.0
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_UC_ID = re.compile(r"^UC-(\d+(?:\.\d+)*)$")
_INDEX = re.compile(r"(?<![\w.])index\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s|)\"'\]]+)")
_NEGATED_INDEX = re.compile(r"\bindex\s*(!=|\bNOT\b|\bIN\b)|\bNOT\s+\(?\s*index\s*=", re.IGNORECASE)
_SOURCE_FILTER = re.compile(r"(?<![\w.])source\s*(=|!=|\bIN\b)", re.IGNORECASE)
_BREAKER_COMMANDS = frozenset((
    "tstats", "datamodel", "pivot", "from", "rest", "mstats", "dbinspect", "inputlookup", "metadata", "typer",
    "eventcount", "walklex", "metasearch", "loadjob", "history", "audit", "savedsearch", "map"))
_TIME_TERM = re.compile(r"(?<![\w.])(earliest|latest)\s*=\s*(\"[^\"]*\"|\S+)", re.IGNORECASE)


class NotRunnable(Exception):
    """The deployed SPL cannot be scoped to the test index."""


class _Inconclusive(Exception):
    pass


_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
            "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0"}
_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|.)", re.DOTALL)
_NUMBER = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")
_BLOCK_SCALAR = re.compile(r"^[|>][+\-0-9]*$")
_KEY = re.compile(r"""^("[^"]*"|'[^']*'|[A-Za-z_][\w.\-]*)\s*:(?:\s+(.*))?$""")
MAX_MANIFEST_DEPTH = 6


class ManifestSyntaxError(ValueError):
    pass


def _unescape(match: Any) -> str:
    token = match.group(1)
    if token[0] in "xu" and len(token) > 1:
        return chr(int(token[1:], 16))
    return _ESCAPES.get(token, "\\" + token)


def _quoted_end(text: str, start: int) -> int:
    """Index just past the quoted string that opens at ``start``; ``len(text)`` when it never closes."""
    quote, i = text[start], start + 1
    while i < len(text):
        if quote == '"' and text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            if quote == "'" and text[i + 1:i + 2] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return len(text)


def _strip_comment(text: str) -> str:
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "\"'" and (i == 0 or text[i - 1] in " \t[,"):
            i = _quoted_end(text, i)
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i]
        i += 1
    return text


def _scalar(text: str) -> Any:
    value = _strip_comment(text).strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return _ESCAPE.sub(_unescape, value[1:-1])
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if value.isdigit():
        return int(value)
    if _NUMBER.match(value):
        return float(value)
    return value


def _flow_items(inner: str) -> List[str]:
    items, start, i = [], 0, 0
    while i < len(inner):
        ch = inner[i]
        if ch in "\"'" and not inner[start:i].strip():
            end = _quoted_end(inner, i)
            if end >= len(inner) and (end == i + 1 or inner[end - 1] != ch):
                raise ManifestSyntaxError("unterminated quoted string in a list")
            i = end
            continue
        if ch == ",":
            items.append(inner[start:i])
            start = i + 1
        elif ch in "[]{}":
            raise ManifestSyntaxError("nested flow collections are not supported")
        i += 1
    if inner[start:].strip() or items:
        items.append(inner[start:])
    return [item for item in items if item.strip()]


def _value(text: str) -> Any:
    stripped = _strip_comment(text).strip()
    if stripped.startswith("["):
        if not stripped.endswith("]"):
            raise ManifestSyntaxError("multi-line lists are not supported")
        return [_scalar(item) for item in _flow_items(stripped[1:-1])]
    if stripped[:1] in "{&*!":
        raise ManifestSyntaxError("unsupported YAML construct: " + stripped[:1])
    return _scalar(stripped)


def _key_name(raw: str) -> str:
    return raw[1:-1] if raw[:1] in "\"'" else raw


class _Lines:
    def __init__(self, text: str):
        self.items: List[Tuple[int, str]] = []
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            expanded = raw.rstrip()
            if expanded[: len(expanded) - len(expanded.lstrip())].count("\t"):
                raise ManifestSyntaxError("tab indentation is not supported")
            self.items.append((len(expanded) - len(expanded.lstrip(" ")), expanded.lstrip(" ")))
        self.pos = 0

    def peek(self) -> Optional[Tuple[int, str]]:
        return self.items[self.pos] if self.pos < len(self.items) else None

    def skip_nested(self, indent: int) -> None:
        while self.pos < len(self.items) and self.items[self.pos][0] > indent:
            self.pos += 1


def _is_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _block(lines: _Lines, indent: int, depth: int) -> Any:
    if depth > MAX_MANIFEST_DEPTH:
        raise ManifestSyntaxError("manifest is nested too deeply")
    head = lines.peek()
    if head is None:
        return None
    return _sequence(lines, indent, depth) if _is_item(head[1]) else _mapping(lines, indent, depth)


def _mapping(lines: _Lines, indent: int, depth: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    while True:
        head = lines.peek()
        if head is None or head[0] < indent:
            return out
        if head[0] > indent or _is_item(head[1]):
            raise ManifestSyntaxError("unexpected indentation: " + head[1][:40])
        match = _KEY.match(head[1])
        if not match:
            raise ManifestSyntaxError("not a key: " + head[1][:40])
        lines.pos += 1
        key, rest = _key_name(match.group(1)), _strip_comment(match.group(2) or "").strip()
        if not rest:
            nxt = lines.peek()
            if nxt is not None and (nxt[0] > indent or (nxt[0] == indent and _is_item(nxt[1]))):
                out[key] = _block(lines, nxt[0], depth + 1)
            else:
                out[key] = None
        elif _BLOCK_SCALAR.match(rest):
            lines.skip_nested(indent)
            out[key] = ""
        else:
            out[key] = _value(rest)


def _sequence(lines: _Lines, indent: int, depth: int) -> List[Any]:
    out: List[Any] = []
    while True:
        head = lines.peek()
        if head is None or head[0] < indent or (head[0] == indent and not _is_item(head[1])):
            return out
        if head[0] > indent:
            raise ManifestSyntaxError("unexpected indentation: " + head[1][:40])
        rest = head[1][1:].lstrip(" ")
        offset = indent + len(head[1]) - len(rest)
        if not rest:
            lines.pos += 1
            nxt = lines.peek()
            out.append(_block(lines, nxt[0], depth + 1) if nxt is not None and nxt[0] > indent else None)
        elif _KEY.match(_strip_comment(rest).strip()):
            lines.items[lines.pos] = (offset, rest)
            out.append(_mapping(lines, offset, depth + 1))
        else:
            lines.pos += 1
            out.append(_value(rest))


def parse_manifest(text: str) -> Dict[str, Any]:
    """Read a Fenre ``manifest.yaml``: block mappings, block lists, flow lists of scalars and quoted scalars.

    This is not a YAML parser, so the app needs no YAML library. Block scalars
    (``notes: |``) are skipped. Anchors, tags, flow mappings, multi-line flow lists
    and tab indentation raise ``ManifestSyntaxError`` instead of being misread.
    """
    lines = _Lines(text)
    head = lines.peek()
    if head is None:
        return {}
    if head[0] != 0 or _is_item(head[1]):
        raise ManifestSyntaxError("a manifest must start with a top-level key")
    return _mapping(lines, 0, 0)


_BLANK_RUN = re.compile(r"\n[ \t]*\n(?:[ \t]*\n)*")


def split_events(text: str) -> List[str]:
    """Events of a fixture file.

    Blank-line separated blocks when the file has them, otherwise one event per non-empty line. When the
    first block opens with a timestamp, a later block without one continues the event before it: a Windows
    event whose message contains blank lines stays one event.
    """
    stripped = text.strip()
    if not _BLANK_RUN.search(stripped):
        return [line.strip() for line in stripped.splitlines() if line.strip()]
    blocks = [block.strip() for block in _BLANK_RUN.split(stripped) if block.strip()]
    if not blocks or not _starts_with_time(blocks[0]):
        return blocks
    events: List[str] = []
    for block in blocks:
        if events and not _starts_with_time(block):
            events[-1] += "\n\n" + block
        else:
            events.append(block)
    return events


def _starts_with_time(block: str) -> bool:
    return _event_time(block.splitlines()[0], 0.0) is not None


def _read_text(path: str) -> str:
    if os.path.getsize(path) > MAX_FIXTURE_BYTES:
        raise ValidationError("fixture file is too large", {"path": os.path.basename(path),
                                                            "limit_bytes": MAX_FIXTURE_BYTES})
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


MAX_FIELD_SPECS = 50
MAX_FIELD_VALUES = 100
MAX_REGEX_LENGTH = 256
MAX_VALUE_LENGTH = 2000
_FIELD_KEYS = {"name", "values", "min", "max", "regex"}
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_max_count(value: Any, uc_id: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError("max_count must be a non-negative integer", {"uc_id": uc_id})
    return value


def _check_fields(value: Any, uc_id: str) -> List[Dict[str, Any]]:
    """Validate and normalise ``expected.fields``; a spec the runner cannot honour refuses the fixture."""
    if not isinstance(value, list) or len(value) > MAX_FIELD_SPECS:
        raise ValidationError("expected.fields must be a list of at most %d entries" % MAX_FIELD_SPECS,
                              {"uc_id": uc_id})
    out = []
    for spec in value:
        if not isinstance(spec, dict) or not isinstance(spec.get("name"), str) or not spec["name"].strip():
            raise ValidationError("each expected.fields entry needs a name", {"uc_id": uc_id})
        extra = sorted(set(spec) - _FIELD_KEYS)
        if extra:
            raise ValidationError("expected.fields %s has unsupported keys: %s" % (spec["name"], ", ".join(extra)),
                                  {"uc_id": uc_id})
        item: Dict[str, Any] = {"name": spec["name"].strip()}
        if "values" in spec:
            values = spec["values"]
            if not isinstance(values, list) or len(values) > MAX_FIELD_VALUES \
                    or not all(isinstance(v, str) or _is_number(v) for v in values):
                raise ValidationError("expected.fields %s values must be a short list of scalars" % item["name"],
                                      {"uc_id": uc_id})
            item["values"] = [str(v) for v in values]
        for bound in ("min", "max"):
            if bound in spec:
                if not _is_number(spec[bound]):
                    raise ValidationError("expected.fields %s %s must be a number" % (item["name"], bound),
                                          {"uc_id": uc_id})
                item[bound] = spec[bound]
        if "regex" in spec:
            pattern = spec["regex"]
            if not isinstance(pattern, str) or len(pattern) > MAX_REGEX_LENGTH or _NESTED_QUANTIFIER.search(pattern):
                raise ValidationError("expected.fields %s regex is too long or has nested repetition"
                                      % item["name"], {"uc_id": uc_id})
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValidationError("expected.fields %s regex does not compile: %s" % (item["name"], exc),
                                      {"uc_id": uc_id}) from exc
            item["regex"] = pattern
        if len(item) > 1:
            out.append(item)
    return out


def _seen_values(rows: List[Dict[str, Any]], name: str) -> List[str]:
    seen: List[str] = []
    for row in rows:
        value = row.get(name)
        for part in value if isinstance(value, list) else [value]:
            if part is not None:
                seen.append(str(part)[:MAX_VALUE_LENGTH])
    return seen


def assert_fields(rows: List[Dict[str, Any]], fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-field results with the semantics of Fenre's ``run_uc_tests.py`` (``values``: any overlap;
    ``min``/``max``: over the numeric values; ``regex``: any match). Multivalue results count each value."""
    results = []
    for spec in fields:
        seen = _seen_values(rows, spec["name"])
        failures = []
        if "values" in spec:
            want, got = set(spec["values"]), set(seen)
            if not want & got:
                failures.append("expected one of %s, saw %s" % (sorted(want), sorted(got)[:5]))
        if "min" in spec or "max" in spec:
            numeric = []
            for text in seen:
                try:
                    numeric.append(float(text))
                except ValueError:
                    continue
            if not numeric:
                failures.append("no numeric values in %d results" % len(rows))
            else:
                if "min" in spec and min(numeric) < float(spec["min"]):
                    failures.append("min=%s is below expected min %s" % (min(numeric), spec["min"]))
                if "max" in spec and max(numeric) > float(spec["max"]):
                    failures.append("max=%s is above expected max %s" % (max(numeric), spec["max"]))
        if "regex" in spec:
            pattern = re.compile(spec["regex"])
            if not any(pattern.search(text) for text in seen):
                failures.append("no value matched regex %s" % spec["regex"])
        results.append({"name": spec["name"], "pass": not failures, "failures": failures,
                        "present": bool(seen)})
    return results


def fixture_from_directory(path: str, uc_id: str) -> Dict[str, Any]:
    try:
        manifest = parse_manifest(_read_text(os.path.join(path, "manifest.yaml")))
    except ManifestSyntaxError as exc:
        raise ValidationError("manifest.yaml uses unsupported YAML: %s" % exc, {"uc_id": uc_id}) from exc
    if str(manifest.get("uc_id", "")) != uc_id:
        raise ValidationError("manifest uc_id does not match its directory", {"uc_id": uc_id})
    sourcetype = str(manifest.get("sourcetype", "")).strip()
    if not sourcetype:
        raise ValidationError("manifest has no sourcetype", {"uc_id": uc_id})
    positive = _read_text(os.path.join(path, "positive.log"))
    if not positive.strip():
        raise ValidationError("positive.log is empty", {"uc_id": uc_id})
    neg_path = os.path.join(path, "negative.log")
    negative = _read_text(neg_path) if os.path.isfile(neg_path) else ""
    expected = manifest.get("expected")
    if expected is not None and not isinstance(expected, dict):
        raise ValidationError("manifest expected must be a mapping", {"uc_id": uc_id})
    expected = expected or {}
    unknown = sorted(set(expected) - {"min_count", "max_count", "fields"})
    if unknown:
        raise ValidationError("manifest expected has unsupported keys: " + ", ".join(unknown), {"uc_id": uc_id})
    min_count = expected.get("min_count", 1)
    if not isinstance(min_count, int) or min_count < 1:
        min_count = 1
    host = str(manifest.get("host") or "ucm-controltest").strip() or "ucm-controltest"
    out = {"uc_id": uc_id, "sourcetype": sourcetype, "host": host, "min_count": min_count,
           "positive": positive, "negative": negative}
    if "max_count" in expected:
        out["max_count"] = _check_max_count(expected["max_count"], uc_id)
    if expected.get("fields") is not None:
        fields = _check_fields(expected["fields"], uc_id)
        if fields:
            out["fields"] = fields
    return out


def expectations(fx: Dict[str, Any]) -> Dict[str, Any]:
    """The optional assertions of a validated fixture (``max_count``, ``fields``), normalised for storage."""
    out: Dict[str, Any] = {}
    if fx.get("max_count") is not None:
        out["max_count"] = fx["max_count"]
    fields = _check_fields(fx["fields"], fx["uc_id"]) if fx.get("fields") is not None else []
    if fields:
        out["fields"] = fields
    return out


def bundle_hash(bundle: Dict[str, Any]) -> str:
    text = json.dumps(bundle, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_fixture_bundle(samples_dir: str, provider: str = "fenre") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not os.path.isdir(samples_dir):
        raise ValidationError("samples directory does not exist", {"path": samples_dir})
    fixtures, skipped = [], []
    for name in sorted(os.listdir(samples_dir)):
        match = _UC_ID.match(name)
        if not match:
            continue
        full = os.path.join(samples_dir, name)
        if not os.path.isfile(os.path.join(full, "positive.log")):
            skipped.append({"uc_id": match.group(1), "reason": "no positive.log"})
            continue
        try:
            fixtures.append(fixture_from_directory(full, match.group(1)))
        except (UcmError, OSError, UnicodeDecodeError) as exc:
            skipped.append({"uc_id": match.group(1), "reason": getattr(exc, "message", str(exc))})
    bundle = {"format": FIXTURE_FORMAT, "format_version": FIXTURE_VERSION, "provider": provider,
              "fixtures": fixtures}
    return bundle, {"fixtures": len(fixtures), "skipped": skipped, "sha256": bundle_hash(bundle)}


def validate_bundle(data: Any) -> Tuple[str, List[Dict[str, Any]]]:
    if not isinstance(data, dict) or data.get("format") != FIXTURE_FORMAT \
            or data.get("format_version") != FIXTURE_VERSION:
        raise ValidationError("not a control fixture bundle")
    provider = data.get("provider")
    if not isinstance(provider, str) or not _NAME.match(provider):
        raise ValidationError("invalid provider id")
    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) > MAX_FIXTURES_PER_IMPORT:
        raise ValidationError("fixtures must be a list of at most %d entries" % MAX_FIXTURES_PER_IMPORT)
    for fx in fixtures:
        uc_id = fx.get("uc_id") if isinstance(fx, dict) else None
        if not isinstance(uc_id, str) or not _UC_ID.match("UC-" + uc_id):
            raise ValidationError("fixture has an invalid uc_id")
        if not isinstance(fx.get("sourcetype"), str) or not fx["sourcetype"].strip():
            raise ValidationError("fixture has no sourcetype", {"uc_id": uc_id})
        if not isinstance(fx.get("host"), str) or not fx["host"].strip():
            raise ValidationError("fixture has no host", {"uc_id": uc_id})
        for field in ("positive", "negative"):
            text = fx.get(field, "")
            if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_FIXTURE_BYTES:
                raise ValidationError("fixture %s must be a string of at most %d bytes"
                                      % (field, MAX_FIXTURE_BYTES), {"uc_id": uc_id})
            if len(split_events(text)) > MAX_EVENTS_PER_FIXTURE:
                raise ValidationError("fixture %s has more than %d events" % (field, MAX_EVENTS_PER_FIXTURE),
                                      {"uc_id": uc_id})
        if not str(fx.get("positive", "")).strip():
            raise ValidationError("fixture positive events are empty", {"uc_id": uc_id})
        min_count = fx.get("min_count", 1)
        if not isinstance(min_count, int) or isinstance(min_count, bool) or min_count < 1:
            raise ValidationError("min_count must be a positive integer", {"uc_id": uc_id})
        if fx.get("max_count") is not None:
            _check_max_count(fx["max_count"], uc_id)
        if fx.get("fields") is not None:
            _check_fields(fx["fields"], uc_id)
    return provider, fixtures


class _Structure:
    """A search's structure: ``mask`` is the text with the inside of quoted strings and macros blanked (same
    length); ``spans`` are the search clauses; ``commands`` the lower-cased command of every non-implicit
    segment; ``macros`` the macro names called."""

    def __init__(self, text: str):
        self.text = text
        self.macros: List[str] = []
        self.mask = self._mask()
        self.spans: List[Tuple[int, int]] = []
        self.generating: List[List[Tuple[int, int]]] = []
        self.commands: List[str] = []
        self._scan()

    def _mask(self) -> str:
        text, out, i = self.text, [], 0
        while i < len(text):
            ch = text[i]
            if text.startswith("```", i):
                end = text.find("```", i + 3)
                if end < 0:
                    raise NotRunnable("the search has an unterminated comment, so its structure cannot be read")
                out.append("   " + " " * (end - i - 3) + "   ")
                i = end + 3
            elif ch == "`":
                end = text.find("`", i + 1)
                if end < 0:
                    raise NotRunnable("the search has an unterminated macro, so its structure cannot be read")
                name = re.match(r"[\w.]*", text[i + 1:end].strip())
                self.macros.append(name.group(0) if name else "")
                out.append("`" + " " * (end - i - 1) + "`")
                i = end + 1
            elif ch == '"':
                end = i + 1
                while end < len(text) and text[end] != '"':
                    end += 2 if text[end] == "\\" else 1
                if end >= len(text):
                    raise NotRunnable("the search has an unterminated quote, so its structure cannot be read")
                out.append('"' + " " * (end - i - 1) + '"')
                i = end + 1
            else:
                out.append(ch)
                i += 1
        return "".join(out)

    def _scan(self) -> None:
        mask = self.mask
        stack: List[Dict[str, Any]] = [{"start": 0, "first": True, "pieces": [], "n": 0,
                                        "bar": mask.lstrip().startswith("|")}]

        def close(frame: Dict[str, Any], end: int) -> None:
            pieces = frame["pieces"] + [(frame["start"], end)]
            joined = "".join(mask[a:b] for a, b in pieces)
            command = re.match(r"[A-Za-z_]\w*", joined.lstrip())
            clause: List[Tuple[int, int]] = []
            if frame["first"] and not frame["bar"]:
                clause = list(pieces)
                self.spans.extend(pieces)
                word = re.match(r"([A-Za-z_]\w*)(?=\s|$)", joined.lstrip())
                if word and word.group(1).lower() in _BREAKER_COMMANDS:
                    self.commands.append(word.group(1).lower())
            else:
                if command:
                    self.commands.append(command.group(0).lower())
                if command and command.group(0).lower() == "search":
                    skip = len(joined) - len(joined.lstrip()) + command.end()
                    for a, b in pieces:
                        if skip >= b - a:
                            skip -= b - a
                            continue
                        clause.append((a + skip, b))
                        skip = 0
                    self.spans.extend(clause)
            if joined.strip():
                if frame["n"] == 0 and clause:
                    self.generating.append(clause)
                frame["n"] += 1

        for i, ch in enumerate(mask):
            frame = stack[-1]
            if ch == "|":
                close(frame, i)
                frame.update(start=i + 1, first=False, pieces=[], bar=False)
            elif ch == "[":
                frame["pieces"].append((frame["start"], i))
                stack.append({"start": i + 1, "first": True, "pieces": [], "n": 0,
                              "bar": mask[i + 1:].lstrip().startswith("|")})
            elif ch == "]":
                if len(stack) == 1:
                    raise NotRunnable("the search has unbalanced brackets, so its structure cannot be read")
                close(frame, i)
                stack.pop()
                stack[-1]["start"] = i + 1
        if len(stack) != 1:
            raise NotRunnable("the search has unbalanced brackets, so its structure cannot be read")
        close(stack[0], len(mask))

    def unmatched_clauses(self, pattern: Any) -> int:
        """How many search clauses that start a pipeline (the main search, a subsearch) have no match of ``pattern``."""
        matches = [(m.start(), m.end()) for m in pattern.finditer(self.mask)]
        return sum(1 for clause in self.generating
                   if not any(a <= ms and me <= b for a, b in clause for ms, me in matches))

    def rewrite(self, pattern: Any, replacement: str) -> Tuple[str, int]:
        """Replace every match of ``pattern`` (run on the mask) that lies inside a search clause."""
        out, last, count = [], 0, 0
        for match in pattern.finditer(self.mask):
            if any(start <= match.start() and match.end() <= end for start, end in self.spans):
                out.append(self.text[last:match.start()])
                out.append(replacement)
                last, count = match.end(), count + 1
        out.append(self.text[last:])
        return "".join(out), count


def scope_to_test_index(spl: str, test_index: str, marker: str) -> str:
    """Rewrite the index filters of the SPL's search clauses to the test index and run marker, or raise NotRunnable.

    Only search clauses are rewritten; ``eval``, ``where``, ``fields`` and the like keep their text, as do
    quoted strings. A search is refused when any clause that starts a pipeline (the search itself or a
    subsearch) has no index filter, and so is anything that
    could read another index: commands that generate or redirect data, macros (their expansion is not
    visible), negated or listed index filters, and a ``source`` filter (the run marker is the source).
    """
    struct = _Structure(spl or "")
    if _BREAKER_COMMANDS.intersection(struct.commands):
        raise NotRunnable("the search uses a command whose data cannot be redirected to the test index")
    if [name for name in struct.macros if name != "comment"]:
        raise NotRunnable("the search calls a macro, whose expansion cannot be scoped to the test index")
    if _NEGATED_INDEX.search(struct.mask):
        raise NotRunnable("the search negates or lists indexes; it cannot be scoped to the test index")
    if _SOURCE_FILTER.search(struct.mask):
        raise NotRunnable("the search filters on source, which the test run uses as its marker")
    out, rewritten = struct.rewrite(_INDEX, 'index=%s source="%s"' % (test_index, marker))
    if not rewritten:
        raise NotRunnable("the search names no index in a search clause, so it cannot be scoped to the test index")
    if struct.unmatched_clauses(_INDEX):
        raise NotRunnable("a search clause, such as a subsearch, names no index, so it cannot be scoped to the test index")
    return out


def pipeline_stages(spl: str) -> List[str]:
    """The top-level pipeline split at ``|`` (quotes and subsearches kept intact); the first stage is the search."""
    struct = _Structure(spl or "")
    stages, depth, start = [], 0, 0
    for i, ch in enumerate(struct.mask):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == "|" and depth == 0:
            stages.append(struct.text[start:i])
            start = i + 1
    stages.append(struct.text[start:])
    return [stage.strip() for stage in stages if stage.strip()]


def strip_time_terms(spl: str) -> str:
    """Remove ``earliest=``/``latest=`` terms from the search clauses; other commands keep theirs."""
    return _Structure(spl or "").rewrite(_TIME_TERM, " ")[0]


_TS_LOOKAHEAD = 128
_MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
WINDOW_PAD_SECONDS = 3600
NAIVE_PAD_SECONDS = 24 * 3600
_FUTURE_SLACK = 24 * 3600
_EPOCH = datetime(1970, 1, 1)


def _offset_seconds(text: Optional[str]) -> Optional[int]:
    if not text:
        return None
    if text == "Z":
        return 0
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    return sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)


def _year(text: str) -> int:
    return int(text) + 2000 if len(text) == 2 else int(text)


def _month(name: str) -> int:
    if name not in _MONTHS:
        raise ValueError(name)
    return _MONTHS[name]


def _yearless(now: float, month: str, day: str, hour: str, minute: str, second: str) -> datetime:
    """Syslog stamps carry no year: the current one, or the previous when that would be over a day ahead."""
    year = datetime.fromtimestamp(now, timezone.utc).year
    moment = datetime(year, _month(month), int(day), int(hour), int(minute), int(second))
    if (moment - _EPOCH).total_seconds() > now + _FUTURE_SLACK:
        moment = moment.replace(year=year - 1)
    return moment


# Each entry: a pattern and a builder returning (naive datetime, zone offset in seconds or None).
_TS_FORMATS = (
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?(?![\d:])"),
     lambda g, now: (datetime(int(g[0]), int(g[1]), int(g[2]), int(g[3]), int(g[4]), int(g[5])),
                     _offset_seconds(g[6]))),
    (re.compile(r"\b(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2})\.\d+ ([+-]\d{4})\b"),
     lambda g, now: (datetime(int(g[2]), int(g[0]), int(g[1]), int(g[3]), int(g[4]), int(g[5])),
                     _offset_seconds(g[6]))),
    (re.compile(r"\b(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})\b"),
     lambda g, now: (datetime(int(g[0]), int(g[1]), int(g[2]), int(g[3]), int(g[4]), int(g[5])), None)),
    (re.compile(r"\b(\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2}) (AM|PM)\b"),
     lambda g, now: (datetime(int(g[2]), int(g[0]), int(g[1]), int(g[3]) % 12 + (12 if g[6] == "PM" else 0),
                              int(g[4]), int(g[5])), None)),
    (re.compile(r"\b(\d{2})/(\d{2})/(\d{2}|\d{4})-(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\b"),
     lambda g, now: (datetime(_year(g[2]), int(g[0]), int(g[1]), int(g[3]), int(g[4]), int(g[5])), None)),
    (re.compile(r"\b[A-Z][a-z]{2} ([A-Z][a-z]{2}) ([ 0-9]\d) (\d{2}):(\d{2}):(\d{2}) (\d{4})\b"),
     lambda g, now: (datetime(int(g[5]), _month(g[0]), int(g[1]), int(g[2]), int(g[3]), int(g[4])), None)),
    (re.compile(r"\b([A-Z][a-z]{2}) ([ 0-9]\d) (\d{2}):(\d{2}):(\d{2})\b"),
     lambda g, now: (_yearless(now, *g), None)),
)


def _event_time(event: str, now: float) -> Optional[Tuple[float, bool]]:
    """Epoch seconds of the first timestamp in the leading text of an event, and whether it carried a zone.

    A zoneless time is read as UTC; the caller pads the window for that. Splunk reads only the leading
    characters of an event for its time (the rest is indexed at the current time), so a time further in
    is ignored here as well.
    """
    head = event[:_TS_LOOKAHEAD]
    for pattern, build in _TS_FORMATS:
        match = pattern.search(head)
        if not match:
            continue
        try:
            moment, offset = build(match.groups(), now)
        except ValueError:
            continue
        epoch = (moment - _EPOCH).total_seconds()
        return (epoch - offset, True) if offset is not None else (epoch, False)
    return None


def derive_window(events: List[str], now: Optional[float] = None) -> Dict[str, Any]:
    """Search window for a fixture: ``min - 1 h`` to ``max + 1 h`` of the event timestamps.

    Falls back to the wide window (``-10y`` to ``+1d``) when no event carries a parseable time. Events
    without one are indexed at the current time, so any such event moves the end of the window to ``+1d``.
    Zoneless times are read as UTC and padded by a day, because splunkd reads them in its own zone.
    """
    clock = time.time() if now is None else now
    stamps = [_event_time(event, clock) for event in events]
    found = [item for item in stamps if item is not None]
    if not found:
        return {"earliest": WINDOW_EARLIEST, "latest": WINDOW_LATEST, "derived": False}
    low = min(t - (WINDOW_PAD_SECONDS if zoned else NAIVE_PAD_SECONDS) for t, zoned in found)
    if len(found) < len(stamps):
        latest = WINDOW_LATEST
    else:
        latest = str(int(max(t + (WINDOW_PAD_SECONDS if zoned else NAIVE_PAD_SECONDS) for t, zoned in found)))
    return {"earliest": str(int(low)), "latest": latest, "derived": True}


class ContentError(Exception):
    """The deployed SPL failed on the test data (a Splunk search error, not a transport or timing problem)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def verdict(positive: Optional[Dict[str, Any]], negative: Optional[Dict[str, Any]]) -> str:
    if positive is None:
        return "inconclusive"
    if not positive["pass"] or (negative is not None and not negative["pass"]):
        return "failed"
    return "passed"


class ControlTestRunner:
    """Replays fixtures through injected I/O, so the verdict logic runs without Splunk.

    ``run_search(spl, marker, earliest, latest)`` returns the result rows (dicts) and raises
    ``ContentError`` when Splunk reports a search error.
    """

    def __init__(self, ingest: Callable[[str, str, str, str, str], None],
                 count_events: Callable[[str, str], int],
                 run_search: Callable[[str, str, str, str], List[Dict[str, Any]]],
                 test_index: str = DEFAULT_TEST_INDEX,
                 sleep: Callable[[float], None] = time.sleep, settle: float = SETTLE_SECONDS,
                 clock: Callable[[], float] = time.time):
        self.ingest = ingest
        self.count_events = count_events
        self.run_search = run_search
        self.test_index = test_index
        self.sleep = sleep
        self.settle = settle
        self.clock = clock

    def _indexed(self, marker: str, expected: int) -> int:
        """The marker's event count once it reaches ``expected``, stays put for two polls, or the settle time ends."""
        waited, last, stable = 0.0, -1, 0
        while True:
            count = self.count_events(self.test_index, marker)
            if count >= expected:
                return count
            stable = stable + 1 if count == last and count > 0 else 0
            last = count
            if stable >= 2 or waited >= self.settle:
                return count
            self.sleep(_SETTLE_STEP)
            waited += _SETTLE_STEP

    def _replay(self, spl: str, text: str, fixture: Dict[str, Any]) -> Tuple[int, Dict[str, Any], List[Dict[str, Any]]]:
        marker = "ucm-ct-" + uuid.uuid4().hex
        events = split_events(text)
        window = derive_window(events, self.clock())
        for event in events:
            self.ingest(event, self.test_index, fixture["sourcetype"], marker, fixture["host"])
        indexed = self._indexed(marker, len(events))
        if indexed == 0:
            raise _Inconclusive("no events from the fixture were indexed in the test index")
        if indexed < len(events):
            raise _Inconclusive("only %d of %d fixture events were indexed in time" % (indexed, len(events)))
        rows = self.run_search(scope_to_test_index(spl, self.test_index, marker), marker,
                               window["earliest"], window["latest"])
        return indexed, window, rows

    @staticmethod
    def _positive(indexed: int, window: Dict[str, Any], rows: List[Dict[str, Any]],
                  fixture: Dict[str, Any]) -> Dict[str, Any]:
        count = len(rows)
        out: Dict[str, Any] = {"indexed": indexed, "rows": count, "min_count": fixture["min_count"],
                               "window": window, "pass": count >= fixture["min_count"]}
        max_count = fixture.get("max_count")
        if max_count is not None:
            out["max_count"] = max_count
            out["pass"] = out["pass"] and count <= max_count
        if fixture.get("fields"):
            out["fields"] = assert_fields(rows, fixture["fields"])
            out["pass"] = out["pass"] and all(item["pass"] for item in out["fields"])
        return out

    def run(self, spl: str, fixture: Dict[str, Any]) -> Dict[str, Any]:
        base = {"test_index": self.test_index, "sourcetype": fixture["sourcetype"],
                "positive": None, "negative": None}
        try:
            spl = strip_time_terms(spl)
            scope_to_test_index(spl, self.test_index, "probe")
        except NotRunnable as exc:
            return dict(base, status="not_runnable", reason=str(exc))
        phase = "positive"
        try:
            indexed, window, rows = self._replay(spl, fixture["positive"], fixture)
            base["positive"] = self._positive(indexed, window, rows, fixture)
            if fixture["negative"].strip():
                phase = "negative"
                indexed, window, rows = self._replay(spl, fixture["negative"], fixture)
                base["negative"] = {"indexed": indexed, "rows": len(rows), "window": window, "pass": not rows}
        except NotRunnable as exc:
            return dict(base, status="not_runnable", reason=str(exc))
        except ContentError as exc:
            return dict(base, status="content_error", phase=phase,
                        reason="the search failed on the %s test data: %s" % (phase, exc.message[:500]))
        except _Inconclusive as exc:
            return dict(base, status="inconclusive", reason=str(exc))
        except (TimeoutError, UcmError) as exc:
            return dict(base, status="inconclusive", reason=getattr(exc, "message", str(exc))[:500])
        positive, negative = base["positive"], base["negative"]
        problems = []
        if positive["rows"] < positive["min_count"]:
            problems.append("positive run returned %d rows, expected at least %d"
                            % (positive["rows"], positive["min_count"]))
        if positive.get("max_count") is not None and positive["rows"] > positive["max_count"]:
            problems.append("positive run returned %d rows, expected at most %d"
                            % (positive["rows"], positive["max_count"]))
        for item in positive.get("fields", []):
            for failure in item["failures"]:
                problems.append("field %s: %s" % (item["name"], failure))
        if negative is not None and not negative["pass"]:
            problems.append("negative run returned %d rows, expected none" % negative["rows"])
        return dict(base, status=verdict(positive, negative), reason="; ".join(problems))


def _search_error_text(exc: Exception) -> Optional[str]:
    """The Splunk message of a failed search, or None when the exception is not a search error."""
    if isinstance(exc, SearchFailed):
        return "; ".join((exc.details or {}).get("messages") or []) or exc.message
    if isinstance(exc, StorageError) and exc.status == 400:
        body = (exc.details or {}).get("body") or ""
        try:
            messages = [m.get("text", "") for m in json.loads(body).get("messages", []) if isinstance(m, dict)]
        except (ValueError, AttributeError):
            messages = [m.replace('\\"', '"') for m in re.findall(r'"text"\s*:\s*"((?:[^"\\]|\\.)*)"', body)]
        return "; ".join(m for m in messages if m) or "splunkd rejected the search (HTTP 400)"
    return None


def splunk_runner(writer: Any, search: Any, app: str, test_index: str = DEFAULT_TEST_INDEX,
                  settle: float = SETTLE_SECONDS) -> ControlTestRunner:
    """Wire the runner to splunkd: the raw receiver for ingest, the caller's search session for SPL."""

    def ingest(event: str, index: str, sourcetype: str, source: str, host: str) -> None:
        status, _ = writer.post_raw("/services/receivers/simple",
                                    {"index": index, "sourcetype": sourcetype, "source": source, "host": host},
                                    event)
        if status != 200:
            raise StorageError("event receiver returned HTTP %d; check that the test index exists" % status)

    def count(index: str, marker: str) -> int:
        result = search.preview('search index=%s source="%s" | stats count AS n' % (index, marker),
                                app=app, earliest=WINDOW_EARLIEST, latest=WINDOW_LATEST, max_count=1)
        return int(result.rows[0].get("n", 0)) if result.rows else 0

    def run(spl: str, marker: str, earliest: str, latest: str) -> List[Dict[str, Any]]:
        query = spl.strip() if spl.lstrip().startswith("|") else "search " + spl.strip()
        try:
            result = search.preview(query, app=app, earliest=earliest, latest=latest,
                                    max_count=MAX_RESULT_ROWS, timeout=120.0, level="smart")
        except (UnsupportedOperation, StorageError) as exc:
            text = _search_error_text(exc)
            if text is None:
                raise
            raise ContentError(text) from exc
        return result.rows

    return ControlTestRunner(ingest, count, run, test_index=test_index, settle=settle)

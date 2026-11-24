"""Post-deploy control test: Fenre ``samples/`` fixtures replayed against the deployed SPL (T-23, D-054).

A fixture is the raw ``positive.log`` (and ``negative.log`` when present) of one
use case. For a deployed revision the runner:

1. splits the fixture into events and sends each one to splunkd's raw receiver,
   into the dedicated test index (``[controltest] index``), with the sourcetype
   from the manifest and a per-run ``source`` marker, so only this run's events
   can match;
2. waits until every event is searchable. A shortfall is inconclusive, not a fail;
3. runs the deployed SPL with its index filter rewritten to the test index and
   the marker. A positive run needs at least ``expected.min_count`` result rows;
   a negative run needs none.

Event boundaries: if the file separates events with blank lines, each block is
one event; otherwise each non-empty line is one event (``split_events``). Sending
each event on its own keeps Splunk from merging lines into one event. Events keep
the timestamps in the file, so the search window is wide (``-10y`` to ``+1d``);
the marker is what scopes the match.

The search's own ``earliest=``/``latest=`` terms are removed from the test copy:
fixture timestamps are fixed and cannot match a production window, so the test
checks the search logic over the test window. Searches that cannot be scoped to
the test index are ``not_runnable`` and are never sent to a production index. The fixture's manifest ``index`` and ``source`` are
ignored. Re-running a control test appends events to the test index; the marker
keeps runs apart. Retention of that index is an operator setting.
"""

import hashlib
import json
import os
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..errors import StorageError, UcmError, ValidationError

FIXTURE_FORMAT = "ucm-control-fixtures"
FIXTURE_VERSION = 1
DEFAULT_TEST_INDEX = "ucm_controltest"
MAX_FIXTURE_BYTES = 512 * 1024
MAX_FIXTURES_PER_IMPORT = 2000
MAX_EVENTS_PER_FIXTURE = 1000
WINDOW_EARLIEST = "-10y"
WINDOW_LATEST = "+1d"
SETTLE_SECONDS = 45.0
_SETTLE_STEP = 1.0
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_UC_ID = re.compile(r"^UC-(\d+(?:\.\d+)*)$")
_INDEX = re.compile(r"(?<![\w.])index\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s|)\"']+)")
_NEGATED_INDEX = re.compile(r"\bindex\s*(!=|\bNOT\b|\bIN\b)", re.IGNORECASE)
_SOURCE_FILTER = re.compile(r"(?<![\w.])source\s*(=|!=|\bIN\b)", re.IGNORECASE)
_SCOPE_BREAKERS = re.compile(r"\|\s*(tstats|datamodel|pivot|from|rest|mstats|dbinspect|inputlookup|metadata|typer)\b"
                             r"|\bsavedsearch\b|\bmap\b", re.IGNORECASE)
_TIME_TERM = re.compile(r"(?<![\w.])(earliest|latest)\s*=\s*(\"[^\"]*\"|\S+)", re.IGNORECASE)
_MANIFEST_KEY = re.compile(r"^\s+([A-Za-z_]\w*):\s*(.*)$")


class NotRunnable(Exception):
    """The deployed SPL cannot be scoped to the test index."""


class _Inconclusive(Exception):
    pass


def _scalar(text: str) -> Any:
    value = text.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    if value.isdigit():
        return int(value)
    return value


def parse_manifest(text: str) -> Dict[str, Any]:
    """Read the keys the control test uses from a Fenre ``manifest.yaml``.

    This is not a YAML parser. Top-level scalars and one level of nested scalars
    (``expected.min_count``) are read; block scalars and lists are skipped, so the
    app needs no YAML library.
    """
    out: Dict[str, Any] = {}
    section: Optional[str] = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] not in " \t":
            key, _, value = line.partition(":")
            section = key.strip()
            out[section] = _scalar(value) if value.strip() else {}
            continue
        match = _MANIFEST_KEY.match(line)
        if match and isinstance(out.get(section), dict):
            out[section][match.group(1)] = _scalar(match.group(2))
    return out


_BLANK_RUN = re.compile(r"\n[ \t]*\n(?:[ \t]*\n)*")


def split_events(text: str) -> List[str]:
    stripped = text.strip()
    blocks = _BLANK_RUN.split(stripped) if _BLANK_RUN.search(stripped) else stripped.splitlines()
    return [block.strip() for block in blocks if block.strip()]


def _read_text(path: str) -> str:
    if os.path.getsize(path) > MAX_FIXTURE_BYTES:
        raise ValidationError("fixture file is too large", {"path": os.path.basename(path),
                                                            "limit_bytes": MAX_FIXTURE_BYTES})
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def fixture_from_directory(path: str, uc_id: str) -> Dict[str, Any]:
    manifest = parse_manifest(_read_text(os.path.join(path, "manifest.yaml")))
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
    expected = manifest.get("expected") if isinstance(manifest.get("expected"), dict) else {}
    min_count = expected.get("min_count", 1)
    if not isinstance(min_count, int) or min_count < 1:
        min_count = 1
    host = str(manifest.get("host") or "ucm-controltest").strip() or "ucm-controltest"
    return {"uc_id": uc_id, "sourcetype": sourcetype, "host": host, "min_count": min_count,
            "positive": positive, "negative": negative}


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
    return provider, fixtures


def scope_to_test_index(spl: str, test_index: str, marker: str) -> str:
    """Rewrite the SPL's index filter to the test index and run marker, or raise NotRunnable."""
    text = spl or ""
    if _SCOPE_BREAKERS.search(text):
        raise NotRunnable("the search uses a command whose data cannot be redirected to the test index")
    if _NEGATED_INDEX.search(text):
        raise NotRunnable("the search negates or lists indexes; it cannot be scoped to the test index")
    if _SOURCE_FILTER.search(text):
        raise NotRunnable("the search filters on source, which the test run uses as its marker")
    if not _INDEX.search(text):
        raise NotRunnable("the search names no index, so it cannot be scoped to the test index")
    return _INDEX.sub(lambda _: 'index=%s source="%s"' % (test_index, marker), text)


def strip_time_terms(spl: str) -> str:
    return _TIME_TERM.sub(" ", spl or "")


def verdict(positive: Optional[Dict[str, Any]], negative: Optional[Dict[str, Any]]) -> str:
    if positive is None:
        return "inconclusive"
    if not positive["pass"] or (negative is not None and not negative["pass"]):
        return "failed"
    return "passed"


class ControlTestRunner:
    """Replays fixtures through injected I/O, so the verdict logic runs without Splunk."""

    def __init__(self, ingest: Callable[[str, str, str, str, str], None],
                 count_events: Callable[[str, str], int],
                 run_search: Callable[[str, str], int], test_index: str = DEFAULT_TEST_INDEX,
                 sleep: Callable[[float], None] = time.sleep, settle: float = SETTLE_SECONDS):
        self.ingest = ingest
        self.count_events = count_events
        self.run_search = run_search
        self.test_index = test_index
        self.sleep = sleep
        self.settle = settle

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

    def _replay(self, spl: str, text: str, fixture: Dict[str, Any]) -> Tuple[int, int]:
        marker = "ucm-ct-" + uuid.uuid4().hex
        events = split_events(text)
        for event in events:
            self.ingest(event, self.test_index, fixture["sourcetype"], marker, fixture["host"])
        indexed = self._indexed(marker, len(events))
        if indexed == 0:
            raise _Inconclusive("no events from the fixture were indexed in the test index")
        if indexed < len(events):
            raise _Inconclusive("only %d of %d fixture events were indexed in time" % (indexed, len(events)))
        return indexed, self.run_search(scope_to_test_index(spl, self.test_index, marker), marker)

    def run(self, spl: str, fixture: Dict[str, Any]) -> Dict[str, Any]:
        base = {"test_index": self.test_index, "sourcetype": fixture["sourcetype"],
                "positive": None, "negative": None}
        spl = strip_time_terms(spl)
        try:
            scope_to_test_index(spl, self.test_index, "probe")
        except NotRunnable as exc:
            return dict(base, status="not_runnable", reason=str(exc))
        try:
            indexed, rows = self._replay(spl, fixture["positive"], fixture)
            positive = {"indexed": indexed, "rows": rows, "min_count": fixture["min_count"],
                        "pass": rows >= fixture["min_count"]}
            negative = None
            if fixture["negative"].strip():
                indexed, neg_rows = self._replay(spl, fixture["negative"], fixture)
                negative = {"indexed": indexed, "rows": neg_rows, "pass": neg_rows == 0}
        except NotRunnable as exc:
            return dict(base, status="not_runnable", reason=str(exc))
        except _Inconclusive as exc:
            return dict(base, status="inconclusive", reason=str(exc))
        except (TimeoutError, UcmError) as exc:
            return dict(base, status="inconclusive", reason=getattr(exc, "message", str(exc))[:500])
        status = verdict(positive, negative)
        problems = []
        if not positive["pass"]:
            problems.append("positive run returned %d rows, expected at least %d"
                            % (positive["rows"], positive["min_count"]))
        if negative is not None and not negative["pass"]:
            problems.append("negative run returned %d rows, expected none" % negative["rows"])
        return dict(base, status=status, positive=positive, negative=negative, reason="; ".join(problems))


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

    def run(spl: str, marker: str) -> int:
        query = spl.strip() if spl.lstrip().startswith("|") else "search " + spl.strip()
        result = search.preview(query, app=app, earliest=WINDOW_EARLIEST, latest=WINDOW_LATEST,
                                max_count=1000, timeout=120.0)
        return len(result.rows)

    return ControlTestRunner(ingest, count, run, test_index=test_index, settle=settle)

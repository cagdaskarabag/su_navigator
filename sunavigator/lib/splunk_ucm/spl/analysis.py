"""Static (non-executing) SPL analysis.

Extracts the data and knowledge-object dependencies a search *appears* to have
so that readiness can form hypotheses. This is not a parser: anything it reports
is a hint with an explicit confidence, never proof. Authoritative syntax checks
use Splunk's own parser (WP4).
"""

import dataclasses
import re
from typing import Dict, List, Optional, Tuple

# Commands that write data, send data, or execute code. Their presence makes a
# search unsuitable for unattended preview and requires explicit review.
SIDE_EFFECT_COMMANDS = frozenset({
    "outputlookup", "outputcsv", "collect", "mcollect", "meventcollect", "tscollect",
    "sendemail", "sendalert", "delete", "script", "run", "sendresults",
})
# Commands that can amplify cost or reach outside the search scope.
HIGH_COST_COMMANDS = frozenset({"map", "join", "transaction", "rest", "dbxquery", "localize"})
GENERATING_COMMANDS = frozenset({
    "tstats", "mstats", "inputlookup", "rest", "datamodel", "from", "makeresults",
    "metadata", "metasearch", "dbinspect", "eventcount", "pivot", "search", "loadjob",
    "savedsearch", "dbxquery", "inputcsv", "mcatalog", "walklex", "union", "multisearch",
})

_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
_MACRO = re.compile(r"`\s*([A-Za-z0-9_\-.:]+)\s*(\(([^`]*)\))?\s*`")
_KV = re.compile(
    r"(?<![\w.:])(index|sourcetype|source|host|eventtype|tag)\s*(!=|==|=)\s*"
    r"(\x01+|[^\s|\]\)\(,]+)", re.IGNORECASE)
_IN = re.compile(r"(?<![\w.:])(index|sourcetype)\s+IN\s*\(([^)]*)\)", re.IGNORECASE)
_DATAMODEL_ARG = re.compile(r"(?<![\w.])datamodel\s*[=:]\s*\"?([A-Za-z0-9_]+)(?:\.([A-Za-z0-9_.]+))?", re.IGNORECASE)
_DATAMODEL_CMD = re.compile(r"^\s*datamodel\s+([A-Za-z0-9_]+)(?:\s+([A-Za-z0-9_]+))?", re.IGNORECASE)
_LOOKUP_CMD = re.compile(
    r"^\s*(lookup|inputlookup|outputlookup)\s+(?:(?:append|start|max|local|update|event_time_field|"
    r"override_if_empty|create_empty|key_field|createinapp|strict)\s*=\s*\S+\s+)*\"?([A-Za-z0-9_.\-]+)",
    re.IGNORECASE)
_TIME_BOUND = re.compile(r"(?<![\w.])(earliest|latest|_index_earliest|_index_latest)\s*=", re.IGNORECASE)
_NOT_BEFORE = re.compile(r"(?:^|\s)NOT\s*\(?\s*$")


@dataclasses.dataclass
class ExtractedValue:
    value: str
    wildcard: bool
    negated: bool = False


@dataclasses.dataclass
class SplAnalysis:
    commands: List[str] = dataclasses.field(default_factory=list)
    indexes: List[ExtractedValue] = dataclasses.field(default_factory=list)
    sourcetypes: List[ExtractedValue] = dataclasses.field(default_factory=list)
    sources: List[ExtractedValue] = dataclasses.field(default_factory=list)
    eventtypes: List[str] = dataclasses.field(default_factory=list)
    tags: List[str] = dataclasses.field(default_factory=list)
    datamodels: List[str] = dataclasses.field(default_factory=list)  # "Model" or "Model.Dataset"
    macros: List[str] = dataclasses.field(default_factory=list)  # "name" or "name(2)"
    lookups: List[str] = dataclasses.field(default_factory=list)
    lookups_written: List[str] = dataclasses.field(default_factory=list)
    side_effect_commands: List[str] = dataclasses.field(default_factory=list)
    high_cost_commands: List[str] = dataclasses.field(default_factory=list)
    has_time_bounds: bool = False
    has_subsearch: bool = False
    generating_command: Optional[str] = None
    unbounded_index: bool = False  # index=* or no index and not a generating command
    warnings: List[str] = dataclasses.field(default_factory=list)

    def positive(self, attr: str) -> List[str]:
        return _uniq(v.value for v in getattr(self, attr) if not v.negated)


def _uniq(values) -> List[str]:
    seen = set()
    out = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _mask_quotes(spl: str) -> str:
    """Replace the inside of double-quoted strings with \\x01, preserving offsets."""
    return _QUOTED.sub(lambda m: '"' + "\x01" * (len(m.group(0)) - 2) + '"', spl)


def _value_at(spl: str, masked: str, start: int, end: int) -> str:
    raw = spl[start:end]
    if masked[start:end].startswith('"') or raw.startswith('"'):
        raw = raw.strip('"')
    return raw.replace('\\"', '"')


# Segment kinds: a search clause at the start of the string or a subsearch,
# a command following "|", or the continuation of a clause after "]".
_LEVEL_START, _PIPE_START, _CONTINUATION = "level", "pipe", "cont"


def _split_pipeline(masked: str) -> Tuple[List[Tuple[int, int, str]], bool]:
    """Return ``(start, end, kind)`` for top-level and subsearch segments."""
    segments: List[Tuple[int, int, str]] = []
    has_sub = False
    starts: List[Tuple[int, str]] = [(0, _LEVEL_START)]
    in_macro = False
    for i, ch in enumerate(masked):
        if ch == "`":
            in_macro = not in_macro
        elif in_macro:
            continue
        elif ch == "[":
            has_sub = True
            segments.append((starts[-1][0], i, starts[-1][1]))
            starts[-1] = (i, _CONTINUATION)
            starts.append((i + 1, _LEVEL_START))
        elif ch == "]" and len(starts) > 1:
            s, kind = starts.pop()
            segments.append((s, i, kind))
            starts[-1] = (i + 1, _CONTINUATION)
        elif ch == "|":
            segments.append((starts[-1][0], i, starts[-1][1]))
            starts[-1] = (i + 1, _PIPE_START)
    segments.append((starts[-1][0], len(masked), starts[-1][1]))
    return [seg for seg in segments if masked[seg[0]:seg[1]].strip()], has_sub


def analyze(spl: str) -> SplAnalysis:
    """Analyse an SPL string without executing it."""
    result = SplAnalysis()
    if not spl or not spl.strip():
        result.warnings.append("empty_spl")
        return result
    masked = _mask_quotes(spl)

    for m in _MACRO.finditer(masked):
        name = m.group(1)
        args = m.group(3)
        if args is not None:
            arity = len([a for a in args.split(",")]) if args.strip() else 0
            name = "%s(%d)" % (name, arity)
        result.macros.append(name)
    result.macros = _uniq(result.macros)

    segments, result.has_subsearch = _split_pipeline(masked)
    stripped = spl.lstrip()
    first_cmd: Optional[str] = None
    for s, e, kind in segments:
        seg_masked = masked[s:e]
        if kind == _CONTINUATION:
            continue
        word = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", seg_masked)
        if kind == _LEVEL_START:
            # A clause that starts the search or a subsearch is an (implicit) search.
            cmd = "search"
        elif word:
            cmd = word.group(1).lower()
        else:
            continue
        if first_cmd is None:
            first_cmd = cmd
        result.commands.append(cmd)
        dm = _DATAMODEL_CMD.match(seg_masked)
        if dm and cmd == "datamodel":
            result.datamodels.append(dm.group(1) + ("." + dm.group(2) if dm.group(2) else ""))
        lk = _LOOKUP_CMD.match(seg_masked)
        if lk:
            name = spl[s:e][lk.start(2):lk.end(2)]
            if lk.group(1).lower() == "outputlookup":
                result.lookups_written.append(name)
            else:
                result.lookups.append(name)
    result.generating_command = first_cmd if stripped.startswith("|") else "search"
    result.lookups = _uniq(result.lookups)
    result.lookups_written = _uniq(result.lookups_written)
    result.side_effect_commands = _uniq(c for c in result.commands if c in SIDE_EFFECT_COMMANDS)
    result.high_cost_commands = _uniq(c for c in result.commands if c in HIGH_COST_COMMANDS)

    buckets: Dict[str, List[ExtractedValue]] = {
        "index": result.indexes, "sourcetype": result.sourcetypes, "source": result.sources,
    }
    for m in _KV.finditer(masked):
        field = m.group(1).lower()
        op = m.group(2)
        value = _value_at(spl, masked, m.start(3), m.end(3))
        if not value:
            continue
        prefix = masked[max(0, m.start() - 6):m.start()]
        negated = op == "!=" or bool(_NOT_BEFORE.search(prefix))
        if field in buckets:
            buckets[field].append(ExtractedValue(value, "*" in value, negated))
        elif field == "eventtype" and not negated:
            result.eventtypes.append(value)
        elif field == "tag" and not negated:
            result.tags.append(value)
    for m in _IN.finditer(masked):
        field = m.group(1).lower()
        raw_list = spl[m.start(2):m.end(2)]
        for item in raw_list.split(","):
            item = item.strip().strip('"')
            if item:
                buckets[field].append(ExtractedValue(item, "*" in item))
    for m in _DATAMODEL_ARG.finditer(masked):
        result.datamodels.append(m.group(1) + ("." + m.group(2) if m.group(2) else ""))

    result.datamodels = _uniq(result.datamodels)
    result.eventtypes = _uniq(result.eventtypes)
    result.tags = _uniq(result.tags)
    for attr in ("indexes", "sourcetypes", "sources"):
        dedup: Dict[Tuple[str, bool], ExtractedValue] = {}
        for v in getattr(result, attr):
            dedup.setdefault((v.value, v.negated), v)
        setattr(result, attr, list(dedup.values()))

    result.has_time_bounds = bool(_TIME_BOUND.search(masked))
    positive_idx = [v for v in result.indexes if not v.negated]
    if any(v.value == "*" for v in positive_idx):
        result.unbounded_index = True
    elif not positive_idx and result.generating_command == "search" and not result.macros \
            and not result.eventtypes and not result.tags:
        result.unbounded_index = True
        result.warnings.append("no_index_constraint")
    if result.side_effect_commands:
        result.warnings.append("side_effect_commands")
    return result

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
    "sendemail", "sendalert", "delete", "script", "run", "sendresults", "summaryindex",
    "dbxoutput", "runshellscript", "deletemodel", "dump", "crawl", "outputtelemetry",
})
# Commands that run SPL or reach data the search text does not show (policy, D-038).
INDIRECT_COMMANDS = frozenset({
    "map", "savedsearch", "loadjob", "rest", "dbxquery", "dbxlookup", "dbxinputs",
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

# Field production (D-040). Names a command creates, with the span they occupy in
# the segment so the rest of the segment can be checked for reads of the same name.
_NAME = r'"?([A-Za-z_][\w.:\-]*)"?'
_AS_TARGET = re.compile(r'(?<![\w.])as\s+"?([A-Za-z_*][\w.:\-*]*)"?', re.IGNORECASE)
_BY = re.compile(r"(?<![\w.])by\s", re.IGNORECASE)
_BARE_COUNT = re.compile(r"(?<![\w.(])(count|c)(?![\w.(])")
_REX_GROUP = re.compile(r"\(\?P?<([A-Za-z_]\w*)>")
_SPATH_OUTPUT = re.compile(r"(?<![\w.])output\s*=\s*" + _NAME, re.IGNORECASE)
_SPATH_PATH = re.compile(r"(?<![\w.])path\s*=\s*" + _NAME, re.IGNORECASE)
_LOOKUP_OUTPUT = re.compile(r"(?<![\w.])(OUTPUT|OUTPUTNEW)\s", re.IGNORECASE)
# In a search clause the value after a comparison is a literal, not a field read.
_SEARCH_VALUE = re.compile(r'(!=|==|<=|>=|=|<|>)(\s*(?:"[^"]*"|[^\s()\[\]|]+))')
_EVAL_TARGET = re.compile(r'^\s*"?([A-Za-z_][\w.:{}\-]*)"?\s*=(?!=)')
_AGGREGATING = frozenset({"stats", "eventstats", "streamstats", "tstats", "sistats", "chart", "timechart",
                          "geostats", "mstats", "sichart", "sitimechart"})
_AS_PRODUCERS = _AGGREGATING | frozenset({"bin", "bucket", "convert", "xyseries", "top", "rare"})
_FIXED_OUTPUTS = {
    "top": ("count", "percent"), "rare": ("count", "percent"), "transaction": ("duration", "eventcount"),
    "iplocation": ("City", "Country", "Region", "lat", "lon"),
    "addinfo": ("info_min_time", "info_max_time", "info_search_time", "info_sid"),
}


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
    # name -> {"command": first producing command, "read_before": the name is read earlier}
    produced_fields: Dict[str, Dict[str, object]] = dataclasses.field(default_factory=dict)
    # Positive sourcetypes that are alternatives within one search clause (D-041).
    # A value that is also the only sourcetype of another clause is in ``sole_sourcetypes``.
    sourcetype_groups: List[List[str]] = dataclasses.field(default_factory=list)
    sole_sourcetypes: List[str] = dataclasses.field(default_factory=list)

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


# Segment kinds: a clause at the start of the string, the first clause of a bracketed
# subsearch, a command following "|", or the continuation of a clause after "]".
_LEVEL_START, _SUB_START, _PIPE_START, _CONTINUATION = "level", "sub", "pipe", "cont"

# Splunk runs a leading command name as a command, not as a search term: at the start of a
# bracketed subsearch, of a search sent without "search"/"|" (REST, saved searches, map
# strings), and always inside appendpipe's subpipeline (D-068). Measured on 10.2.9.
_LEADING_COMMANDS = SIDE_EFFECT_COMMANDS | INDIRECT_COMMANDS
_SUB_LEADING_COMMANDS = _LEADING_COMMANDS | GENERATING_COMMANDS
_SUBPIPELINE_HOSTS = frozenset({"appendpipe"})
_WORD = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)")
_COMPARISON = re.compile(r"\s*(?:!=|[=<>])")


def _backtick_end(text: str, i: int) -> Optional[int]:
    """Where the macro (`` `name` ``) or comment (three backticks each side) that opens at ``i`` ends.

    None when it never closes. The caller then reads the backtick as an ordinary character, so every command after it
    stays visible: an unpaired backtick must not hide what follows (issue #51, item 6).
    """
    if text.startswith("```", i):
        close = text.find("```", i + 3)
        return close + 3 if close >= 0 else None
    close = text.find("`", i + 1)
    return close + 1 if close >= 0 else None


def _split_pipeline(masked: str) -> Tuple[List[Tuple[int, int, str]], bool]:
    """Return ``(start, end, kind)`` for top-level and subsearch segments."""
    segments: List[Tuple[int, int, str]] = []
    has_sub = False
    starts: List[Tuple[int, str]] = [(0, _LEVEL_START)]
    i = 0
    while i < len(masked):
        ch = masked[i]
        if ch == "`":
            end = _backtick_end(masked, i)
            if end is not None:
                i = end
                continue
        elif ch == "[":
            has_sub = True
            segments.append((starts[-1][0], i, starts[-1][1]))
            starts[-1] = (i, _CONTINUATION)
            starts.append((i + 1, _SUB_START))
        elif ch == "]" and len(starts) > 1:
            s, kind = starts.pop()
            segments.append((s, i, kind))
            starts[-1] = (i + 1, _CONTINUATION)
        elif ch == "|":
            segments.append((starts[-1][0], i, starts[-1][1]))
            starts[-1] = (i + 1, _PIPE_START)
        i += 1
    segments.append((starts[-1][0], len(masked), starts[-1][1]))
    return [seg for seg in segments if masked[seg[0]:seg[1]].strip()], has_sub


def _subsearch_hosts(masked: str, segments: List[Tuple[int, int, str]]) -> Dict[int, str]:
    """Start offset of each subsearch segment -> the command that holds the bracket."""
    by_end = {e: (s, kind) for s, e, kind in segments}
    hosts: Dict[int, str] = {}
    for s, _, kind in segments:
        if kind != _SUB_START or (s - 1) not in by_end:
            continue
        host_start, host_kind = by_end[s - 1]
        word = _WORD.match(masked[host_start:s - 1])
        if host_kind == _PIPE_START and word:
            hosts[s] = word.group(1).lower()
    return hosts


def _segment_command(seg_masked: str, kind: str, host: str = "") -> Optional[str]:
    """The command a segment runs, or None for the continuation of a clause."""
    if kind == _CONTINUATION:
        return None
    word = _WORD.match(seg_masked)
    if kind == _PIPE_START:
        return word.group(1).lower() if word else None
    if not word or _COMPARISON.match(seg_masked, word.end()):
        return "search"
    name = word.group(1).lower()
    if kind == _SUB_START and (host in _SUBPIPELINE_HOSTS or name in _SUB_LEADING_COMMANDS):
        return name
    return name if name in _LEADING_COMMANDS else "search"


def segment_commands(masked: str) -> List[Tuple[int, int, str, Optional[str]]]:
    """``(start, end, kind, command)`` for every segment of a quote-masked search."""
    segments, _ = _split_pipeline(masked)
    hosts = _subsearch_hosts(masked, segments)
    return [(s, e, kind, _segment_command(masked[s:e], kind, hosts.get(s, ""))) for s, e, kind in segments]


def subsearch_side_effects(spl: str) -> List[str]:
    """Side-effect commands that sit inside a ``[ ... ]`` subsearch.

    Splunk expands subsearches while it parses a search, so such a command runs even
    though the search itself is only being parsed.
    """
    if not spl or not spl.strip():
        return []
    masked = _mask_quotes(spl)
    depth_at = [0] * (len(masked) + 1)
    depth = 0
    i = 0
    while i < len(masked):
        ch = masked[i]
        if ch == "`":
            end = _backtick_end(masked, i)
            if end is not None:
                for j in range(i, min(end, len(masked)) + 1):
                    depth_at[j] = depth
                i = end
                continue
        elif ch == "[":
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
        depth_at[i + 1] = depth
        i += 1
    found = [cmd for s, _, _, cmd in segment_commands(masked)
             if cmd in SIDE_EFFECT_COMMANDS and depth_at[s] > 0]
    return _uniq(found)


def _top_level_parts(text: str, start: int) -> List[Tuple[int, str]]:
    """Split at commas outside parentheses; returns ``(offset, part)``."""
    parts, depth, begin = [], 0, start
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append((begin, text[begin:i]))
            begin = i + 1
    parts.append((begin, text[begin:]))
    return parts


def _produced_spans(cmd: str, raw: str, masked: str) -> List[Tuple[str, int, int]]:
    """``(name, start, end)`` of fields the command creates, offsets within the segment."""
    head = re.match(r"\s*[A-Za-z_]\w*", masked)
    body = head.end() if head else 0
    out: List[Tuple[str, int, int]] = []
    if cmd == "eval":
        for offset, part in _top_level_parts(masked, body):
            m = _EVAL_TARGET.match(part)
            if m:
                out.append((raw[offset + m.start(1):offset + m.end(1)], offset + m.start(1), offset + m.end(1)))
    elif cmd in _AS_PRODUCERS or cmd == "rename":
        by = _BY.search(masked, body) if cmd in _AGGREGATING else None
        end = by.start() if by else len(masked)
        for m in _AS_TARGET.finditer(masked, body, end):
            name = raw[m.start(1):m.end(1)]
            if "*" not in name:
                out.append((name, m.start(), m.end()))
        if cmd in _AGGREGATING:
            for m in _BARE_COUNT.finditer(masked, body, end):
                if not re.match(r"\s+as\s", masked[m.end():], re.IGNORECASE):
                    out.append((m.group(1), m.start(), m.end()))
    elif cmd == "rex" and not re.search(r"(?<![\w.])mode\s*=\s*sed", masked, re.IGNORECASE):
        out.extend((m.group(1), m.start(), m.end()) for m in _REX_GROUP.finditer(raw))
    elif cmd == "spath":
        m = _SPATH_OUTPUT.search(masked) or _SPATH_PATH.search(masked)
        if m:
            out.append((raw[m.start(1):m.end(1)], m.start(), m.end()))
    elif cmd == "lookup":
        m = _LOOKUP_OUTPUT.search(masked)
        if m:
            tokens = list(re.compile(r"[A-Za-z_][\w.:\-]*").finditer(masked, m.end()))
            i = 0
            while i < len(tokens):
                if i + 2 < len(tokens) and tokens[i + 1].group(0).lower() == "as":
                    out.append((tokens[i + 2].group(0), tokens[i].start(), tokens[i + 2].end()))
                    i += 3
                else:
                    out.append((tokens[i].group(0), tokens[i].start(), tokens[i].end()))
                    i += 1
    elif cmd == "strcat":
        m = re.search(r'([A-Za-z_][\w.:\-]*)\s*$', masked)
        if m:
            out.append((m.group(1), m.start(1), m.end(1)))
    for name in _FIXED_OUTPUTS.get(cmd, ()):
        out.append((name, len(masked), len(masked)))
    return out


def _reads(name: str, text: str) -> bool:
    return re.search(r"(?<![\w.:])%s(?![\w:]|\.\w)" % re.escape(name), text) is not None


def _record_produced(produced: Dict[str, Dict[str, object]], cmd: str, raw: str, masked: str,
                     before: str) -> None:
    spans = _produced_spans(cmd, raw, masked)
    if not spans:
        return
    rest = list(masked)
    for _, start, end in spans:
        rest[start:end] = " " * (end - start)
    rest_text = "".join(rest)
    for name, _, _ in spans:
        if name not in produced:
            produced[name] = {"command": cmd, "read_before": _reads(name, before) or _reads(name, rest_text)}


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
    hosts = _subsearch_hosts(masked, segments)
    read_text: List[str] = []
    stripped = spl.lstrip()
    first_cmd: Optional[str] = None
    for s, e, kind in segments:
        seg_masked = masked[s:e]
        if kind == _CONTINUATION:
            read_text.append(seg_masked)
            continue
        cmd = _segment_command(seg_masked, kind, hosts.get(s, ""))
        if cmd is None:
            continue
        if first_cmd is None:
            first_cmd = cmd
        result.commands.append(cmd)
        if kind == _PIPE_START:
            _record_produced(result.produced_fields, cmd, spl[s:e], seg_masked, "".join(read_text))
        read_text.append(_SEARCH_VALUE.sub(lambda m: m.group(1) + " " * len(m.group(2)), seg_masked)
                         if cmd == "search" else seg_masked)
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
    by_segment: Dict[int, List[str]] = {}

    def segment_of(pos: int) -> int:
        for i, (s, e, _) in enumerate(segments):
            if s <= pos < e:
                return i
        return -1

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
            if field == "sourcetype" and not negated:
                by_segment.setdefault(segment_of(m.start()), []).append(value)
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
                if field == "sourcetype":
                    by_segment.setdefault(segment_of(m.start()), []).append(item)
    for m in _DATAMODEL_ARG.finditer(masked):
        result.datamodels.append(m.group(1) + ("." + m.group(2) if m.group(2) else ""))

    for idx in sorted(by_segment):
        values = _uniq(by_segment[idx])
        if len(values) > 1:
            if values not in result.sourcetype_groups:
                result.sourcetype_groups.append(values)
        else:
            result.sole_sourcetypes.append(values[0])
    result.sole_sourcetypes = _uniq(result.sole_sourcetypes)
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

"""SPL execution policy (docs/DECISIONS.md D-038).

Every command in a search is classified:

* ``side_effect`` – writes, sends or executes (denylist). Preview and deployment refuse.
* ``indirect`` – runs SPL or reaches data the search text does not show (``map``,
  ``savedsearch``, ``savedsearch:`` datasets, ``rest``, ...). Preview refuses;
  approval needs an explicit acknowledgment.
* ``unknown`` – not on the read-only allowlist (custom and add-on commands).
  Treated like ``indirect``. ``[spl] extra_safe_commands`` in ucm.conf extends the
  allowlist; it can never clear a side-effect or indirect command.

Commands are collected from the raw SPL (static analysis, which sees subsearches)
and from the pipeline Splunk's parser returns, which has macros expanded
(including macros inside subsearches).

``map search="..."`` carries a search as a string. That string is analysed as well
(D-062): a side-effect command inside it is a side effect of the whole search. A ``map``
whose search cannot be read (``savedsearch=``, an unquoted value, a macro in the string,
nesting deeper than ``MAX_NESTING``) is reported in ``hidden``.

``hidden`` lists what the interactive search in the browser refuses: SPL or data the
search text does not show. Preview and deployment keep treating those commands as
``indirect``.
"""

import dataclasses
import re
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..platform.search import ParseResult, SearchClient
from .analysis import SIDE_EFFECT_COMMANDS, _PIPE_START, _mask_quotes, _split_pipeline, analyze

INDIRECT_COMMANDS = frozenset({
    "map", "savedsearch", "loadjob", "rest", "dbxquery", "dbxlookup", "dbxinputs",
})

# Indirect commands whose SPL or data the search text does not show; the browser's
# interactive search refuses them (D-062).
HIDDEN_SPL_COMMANDS = frozenset({"savedsearch", "loadjob", "dbxquery"})
MAX_NESTING = 3

# Built-in commands (Splunk Search Reference, 9.x/10.x) that only read or transform.
READ_ONLY_COMMANDS = frozenset({
    "abstract", "accum", "addcoltotals", "addinfo", "addtotals", "analyzefields", "anomalies",
    "anomalousvalue", "anomalydetection", "append", "appendcols", "appendpipe", "arules", "associate",
    "audit", "autoregress", "bin", "bucket", "bucketdir", "chart", "cluster", "cofilter", "concurrency",
    "contingency", "convert", "correlate", "ctable", "datamodel", "datamodelsimple", "dbinspect", "dedup",
    "delta", "diff", "erex", "eval", "eventcount", "eventstats", "extract", "fieldformat", "fields",
    "fieldsummary", "filldown", "fillnull", "findtypes", "folderize", "foreach", "format", "from",
    "fromjson", "gauge", "gentimes", "geom", "geomfilter", "geostats", "head", "highlight", "history",
    "iconify", "inputcsv", "inputlookup", "iplocation", "join", "kmeans", "kv", "kvform", "localize",
    "localop", "lookup", "makecontinuous", "makemv", "makeresults", "mcatalog", "metadata", "metasearch",
    "mpreview", "msearch", "mstats", "multikv", "multisearch", "mvcombine", "mvexpand", "nomv", "outlier",
    "outputtext", "overlap", "pivot", "predict", "rangemap", "rare", "redistribute", "regex", "reltime",
    "rename", "replace", "require", "return", "reverse", "rex", "rtorder", "scrub", "search", "searchtxn",
    "selfjoin", "set", "setfields", "sichart", "sirare", "sistats", "sitimechart", "sitop", "sort", "spath",
    "stats", "strcat", "streamstats", "table", "tags", "tail", "timechart", "timewrap", "tojson", "top",
    "transaction", "transpose", "trendline", "tstats", "typeahead", "typelearner", "typer", "union", "uniq",
    "untable", "walklex", "where", "x11", "xmlkv", "xmlunescape", "xpath", "xyseries",
})

_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_SAVEDSEARCH_DATASET = re.compile(r"(?<![\w.:])savedsearch:", re.IGNORECASE)
_MAP_SEARCH = re.compile(r'(?:^|[^\w.])search\s*=\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
_MAP_SAVED = re.compile(r"(?:^|[^\w.])savedsearch\s*=", re.IGNORECASE)
_ESCAPED = re.compile(r'\\(["\\])')
_COMMAND_WORD = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)")
_FIT_INTO = re.compile(r"(?:^|[|\[])\s*fit\b[^|\]]*?\binto\b", re.IGNORECASE)


@dataclasses.dataclass
class PolicyResult:
    commands: List[str] = dataclasses.field(default_factory=list)
    side_effects: List[str] = dataclasses.field(default_factory=list)
    indirect: List[str] = dataclasses.field(default_factory=list)
    unknown: List[str] = dataclasses.field(default_factory=list)
    nested: List[str] = dataclasses.field(default_factory=list)  # command names found inside map searches
    hidden: List[str] = dataclasses.field(default_factory=list)

    @property
    def review(self) -> List[str]:
        """Commands that block preview and need an approver's acknowledgment."""
        return _uniq(self.indirect + self.unknown)


def _uniq(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def parse_extra_safe(value: str) -> List[str]:
    """``extra_safe_commands`` from ucm.conf; side-effect and indirect names are dropped."""
    names = [v.strip().lower() for v in (value or "").split(",")]
    return [n for n in _uniq(names) if _NAME.match(n)
            and n not in SIDE_EFFECT_COMMANDS and n not in INDIRECT_COMMANDS]


def expanded_pipeline(parsed: Optional[ParseResult]) -> str:
    """The search as Splunk's parser returned it: macros expanded, subsearches inline."""
    if parsed is None or not isinstance(parsed.raw, dict):
        return ""
    parts = []
    for cmd in parsed.raw.get("commands") or []:
        if isinstance(cmd, dict) and cmd.get("command"):
            parts.append("%s %s" % (cmd["command"], cmd.get("args") or ""))
    return ("| " + " | ".join(parts)) if parts else ""


def command_exists(client: SearchClient, name: str, app: str = "") -> bool:
    """False only when Splunk reports ``name`` as an unknown search command."""
    probe = client.parse("| makeresults | %s" % name, app=app) if app else client.parse("| makeresults | %s" % name)
    return not any("unknown search command" in str(m.get("text", "")).lower() for m in probe.messages)


def _map_calls(spl: str) -> Tuple[List[str], int]:
    """The quoted ``search="..."`` of every ``map`` command, and how many ``map`` calls have no
    readable search (``savedsearch=``, an unquoted value)."""
    masked = _mask_quotes(spl)
    segments, _ = _split_pipeline(masked)
    searches: List[str] = []
    opaque = 0
    for start, end, kind in segments:
        if kind != _PIPE_START:
            continue
        word = _COMMAND_WORD.match(masked[start:end])
        if not word or word.group(1).lower() != "map":
            continue
        found = [_ESCAPED.sub(r"\1", m.group(1)) for m in _MAP_SEARCH.finditer(spl[start:end])]
        if not found or _MAP_SAVED.search(masked[start:end]):
            opaque += 1
        searches.extend(found)
    return searches, opaque


def _scan_nested(spl: str, depth: int, out: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Analyse the searches carried inside ``map`` strings, recursively (D-062)."""
    searches, opaque = _map_calls(spl)
    if opaque:
        out["hidden"].append("map (search not readable)")
    for inner in searches:
        if depth > MAX_NESTING:
            out["hidden"].append("map (nested too deeply)")
            continue
        info = analyze(inner)
        masked = _mask_quotes(inner)
        out["commands"].extend(info.commands)
        if info.macros:
            out["hidden"].append("map (macro in nested search)")
        if _FIT_INTO.search(masked):
            out["side"].append("fit into")
        if _SAVEDSEARCH_DATASET.search(masked):
            out["indirect"].append("savedsearch: dataset")
        _scan_nested(inner, depth + 1, out)
    return out


def classify(spl: str, parsed: Optional[ParseResult] = None, extra_safe: Sequence[str] = (),
             exists: Optional[Callable[[str], bool]] = None) -> PolicyResult:
    """``exists`` confirms unknown names that only static analysis found; it is consulted
    only when Splunk parsed the whole search (the parser rejects unknown commands, also
    in subsearches), so static mis-tokenisation does not flag literals as commands."""
    texts = [spl or ""]
    expanded = expanded_pipeline(parsed)
    if expanded:
        texts.append(expanded)
    commands: List[str] = list(parsed.commands) if parsed is not None else []
    side: List[str] = []
    indirect: List[str] = []
    nested: Dict[str, List[str]] = {"commands": [], "side": [], "indirect": [], "hidden": []}
    for text in texts:
        commands.extend(analyze(text).commands)
        masked = _mask_quotes(text)
        if _FIT_INTO.search(masked):
            side.append("fit into")
        if _SAVEDSEARCH_DATASET.search(masked):
            indirect.append("savedsearch: dataset")
        _scan_nested(text, 1, nested)
    commands = _uniq(c.lower() for c in commands)
    nested_commands = _uniq(c.lower() for c in nested["commands"])
    every = _uniq(commands + nested_commands)
    allowed = READ_ONLY_COMMANDS.union(extra_safe)
    side = _uniq([c for c in every if c in SIDE_EFFECT_COMMANDS] + side + nested["side"])
    indirect = _uniq([c for c in every if c in INDIRECT_COMMANDS] + indirect + nested["indirect"])
    hidden = _uniq([c for c in every if c in HIDDEN_SPL_COMMANDS]
                   + (["savedsearch: dataset"] if "savedsearch: dataset" in indirect else [])
                   + nested["hidden"])
    unknown = [c for c in every if c not in allowed and c not in SIDE_EFFECT_COMMANDS
               and c not in INDIRECT_COMMANDS]
    if "fit into" in side:
        unknown = [c for c in unknown if c != "fit"]
    if exists is not None and parsed is not None and parsed.ok:
        reported = set(c.lower() for c in parsed.commands)
        unknown = [c for c in unknown if c in reported or exists(c)]
    return PolicyResult(commands=commands, side_effects=side, indirect=indirect, unknown=unknown,
                        nested=nested_commands, hidden=hidden)

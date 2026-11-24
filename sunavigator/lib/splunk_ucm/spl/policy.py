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
"""

import dataclasses
import re
from typing import Callable, Iterable, List, Optional, Sequence

from ..platform.search import ParseResult, SearchClient
from .analysis import SIDE_EFFECT_COMMANDS, _mask_quotes, analyze

INDIRECT_COMMANDS = frozenset({
    "map", "savedsearch", "loadjob", "rest", "dbxquery", "dbxlookup", "dbxinputs",
})

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
_FIT_INTO = re.compile(r"(?:^|[|\[])\s*fit\b[^|\]]*?\binto\b", re.IGNORECASE)


@dataclasses.dataclass
class PolicyResult:
    commands: List[str] = dataclasses.field(default_factory=list)
    side_effects: List[str] = dataclasses.field(default_factory=list)
    indirect: List[str] = dataclasses.field(default_factory=list)
    unknown: List[str] = dataclasses.field(default_factory=list)

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
    for text in texts:
        commands.extend(analyze(text).commands)
        masked = _mask_quotes(text)
        if _FIT_INTO.search(masked):
            side.append("fit into")
        if _SAVEDSEARCH_DATASET.search(masked):
            indirect.append("savedsearch: dataset")
    commands = _uniq(c.lower() for c in commands)
    allowed = READ_ONLY_COMMANDS.union(extra_safe)
    side = _uniq([c for c in commands if c in SIDE_EFFECT_COMMANDS] + side)
    indirect = _uniq([c for c in commands if c in INDIRECT_COMMANDS] + indirect)
    unknown = [c for c in commands if c not in allowed and c not in SIDE_EFFECT_COMMANDS
               and c not in INDIRECT_COMMANDS]
    if "fit into" in side:
        unknown = [c for c in unknown if c != "fit"]
    if exists is not None and parsed is not None and parsed.ok:
        reported = set(c.lower() for c in parsed.commands)
        unknown = [c for c in unknown if c in reported or exists(c)]
    return PolicyResult(commands=commands, side_effects=side, indirect=indirect, unknown=unknown)

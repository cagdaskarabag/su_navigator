"""Advisory SPL lint (docs/DECISIONS.md D-065).

Static checks for searches that Splunk accepts but that cannot do what their author meant,
or that Splunk rejects with an error that does not say what to change. Findings are
advisory: they never change a gate, a readiness score or an approval, and the only thing
stored is the finding list in the validation document and in the deployment revision.

Every rule fires only for a construct that was shown, on Splunk Enterprise 10.2.9, to be
wrong whenever it appears (evidence per rule in D-065 and docs/upstream/FENRE_FINDINGS.md).
Quoted text and macro bodies are masked first, so a string that merely contains
``match(`` is never reported. A ``map search="..."`` string is linted as a search of its own.

* ``L001`` an eval function called as a search term: the ``search`` command does not
  evaluate functions, so the call is read as plain words.
* ``L002`` ``timechart``/``sitimechart`` with more than one ``by`` field: Splunk rejects it.
* ``L003`` ``match``, ``like`` or ``cidrmatch`` called with a number of arguments other
  than two in an eval-style command: Splunk rejects it.
* ``L004`` a regex string for ``match``/``replace`` that ends in one backslash after the
  eval string is unescaped, in an eval-style command: Splunk rejects it. In a search
  clause the call is never evaluated, so only ``L001`` applies there.
* ``L005`` a time modifier snapping to a number of units (``-6h@5m``) or to ``@w8``/``@w9``:
  ``tstats`` rejects it and a plain search silently selects nothing.
"""

import bisect
import re
from typing import Any, Dict, List, Optional, Tuple

from .analysis import SIDE_EFFECT_COMMANDS, _mask_quotes
from .policy import INDIRECT_COMMANDS, MAX_NESTING, READ_ONLY_COMMANDS, _ESCAPED, _MAP_SEARCH

SEVERITY = "warning"

RULES: Dict[str, str] = {
    "L001": "eval_function_in_search_clause",
    "L002": "timechart_multiple_by_fields",
    "L003": "function_argument_count",
    "L004": "regex_ends_in_backslash",
    "L005": "invalid_time_snap",
}

SEARCH_TERM_FUNCTIONS = (
    "match", "like", "cidrmatch", "isnull", "isnotnull", "isnum", "isint", "isstr", "isbool", "len", "lower",
    "upper", "mvcount", "mvfind", "mvindex", "mvfilter", "searchmatch", "tonumber", "tostring", "substr",
    "replace", "trim", "ltrim", "rtrim", "coalesce",
)
TWO_ARGUMENT_FUNCTIONS = ("match", "like", "cidrmatch")
REGEX_FUNCTIONS = ("match", "replace")

_KNOWN_COMMANDS = READ_ONLY_COMMANDS | SIDE_EFFECT_COMMANDS | INDIRECT_COMMANDS
_NOT_BEFORE = r"(?<![\w.:$@\-*/\\])"
_TERM_CALL = re.compile(_NOT_BEFORE + r"(%s)\s*\(" % "|".join(SEARCH_TERM_FUNCTIONS))
_CHECKED_CALL = re.compile(_NOT_BEFORE + r"(%s)\s*\(" % "|".join(sorted(set(TWO_ARGUMENT_FUNCTIONS + REGEX_FUNCTIONS))))
_WORD = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)")
_BY = re.compile(r"(?<![\w.])by\s", re.IGNORECASE)
_TIME_TERM = re.compile(r"(?<![\w.])(earliest|latest|_index_earliest|_index_latest)\s*=\s*", re.IGNORECASE)
_STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"$', re.DOTALL)
_BAD_SNAP = re.compile(r"@(?:\d|w[89])", re.IGNORECASE)
_TIME_VALUE = re.compile(r'"([^"]*)"|([^\s"\)\]|,]+)')
_TRAILING_BACKSLASHES = re.compile(r"\\+$")
_OPTION = re.compile(r"^\w+=")
_CALL_TEXT_LIMIT = 120


class _Piece:
    __slots__ = ("start", "end", "command", "segment")

    def __init__(self, start: int, end: int, command: str, segment: int):
        self.start, self.end, self.command, self.segment = start, end, command, segment


class _Level:
    __slots__ = ("start", "command", "first")

    def __init__(self, start: int, first: bool):
        self.start, self.command, self.first = start, "", first


def _blank_macros(masked: str) -> str:
    out = list(masked)
    inside = False
    for i, ch in enumerate(masked):
        if ch == "`":
            inside = not inside
            out[i] = " "
        elif inside:
            out[i] = " "
    return "".join(out)


def _command_of(masked: str, start: int, end: int, first: bool) -> str:
    word = _WORD.match(masked, start, end)
    if first:
        # The first clause of a search or subsearch is an implicit ``search``.
        if word and word.group(1).lower() in _KNOWN_COMMANDS and not re.match(r"\s*=", masked[word.end():end]):
            return word.group(1).lower()
        return "search"
    return word.group(1).lower() if word else ""


def _pieces(masked: str) -> List[_Piece]:
    """Command-sized pieces at every nesting level. A piece after ``]`` continues the command
    that opened the subsearch. ``segment`` numbers the top-level pipeline commands from 1."""
    pieces: List[_Piece] = []
    levels = [_Level(0, True)]
    segment = 1
    has_content = False

    def emit(level: _Level, end: int) -> None:
        if not masked[level.start:end].strip():
            return
        command = level.command or _command_of(masked, level.start, end, level.first)
        level.command = command
        pieces.append(_Piece(level.start, end, command, segment))

    macro = False
    for i, ch in enumerate(masked):
        if ch == "`":
            macro = not macro
            has_content = True
        elif macro:
            continue
        elif ch == "[":
            emit(levels[-1], i)
            levels.append(_Level(i + 1, True))
            has_content = True
        elif ch == "]" and len(levels) > 1:
            emit(levels[-1], i)
            levels.pop()
            levels[-1].start = i + 1
        elif ch == "|":
            emit(levels[-1], i)
            levels[-1].start, levels[-1].command, levels[-1].first = i + 1, "", False
            if len(levels) == 1 and has_content:
                segment += 1
                has_content = False
        elif not ch.isspace():
            has_content = True
    emit(levels[-1], len(masked))
    return pieces


def _close_paren(text: str, open_at: int, limit: int) -> int:
    depth = 0
    for i in range(open_at, limit):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_args(text: str, begin: int, end: int) -> List[Tuple[int, int]]:
    if not text[begin:end].strip():
        return []
    spans, depth, start = [], 0, begin
    for i in range(begin, end):
        ch = text[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
    spans.append((start, end))
    return spans


def _short(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _CALL_TEXT_LIMIT else text[:_CALL_TEXT_LIMIT - 3] + "..."


def _top_level_by(text: str, begin: int) -> int:
    depth = 0
    for m in _BY.finditer(text, begin):
        depth = text.count("(", begin, m.start()) - text.count(")", begin, m.start())
        if depth == 0:
            return m.end()
    return -1


def _by_fields(masked: str, begin: int, end: int) -> List[Tuple[int, int]]:
    """Field spans after a top-level ``by``: split at commas and white space outside parentheses,
    up to the first option (``limit=5``) or ``where`` clause."""
    spans, depth, start = [], 0, begin
    for i in range(begin, end):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and (ch == "," or ch.isspace()):
            spans.append((start, i))
            start = i + 1
    spans.append((start, end))
    fields: List[Tuple[int, int]] = []
    for s, e in spans:
        token = masked[s:e]
        if not token.strip():
            continue
        if token.lower() == "where" or _OPTION.match(token) or masked[e:end].lstrip().startswith("="):
            break
        fields.append((s, e))
    return fields


class _Collector:
    def __init__(self) -> None:
        self.items: Dict[Tuple[str, int, int, str], Dict[str, Any]] = {}

    def add(self, rule: str, segment: int, command: str, in_map: int, call: str, message: str,
            suggestion: str, key: str = "") -> None:
        ident = (rule, segment, in_map, key)
        found = self.items.get(ident)
        if found is not None:
            found["count"] += 1
            return
        self.items[ident] = {
            "rule": rule, "name": RULES[rule], "severity": SEVERITY, "segment": segment, "command": command,
            "in_map": in_map, "count": 1, "call": _short(call), "message": message, "suggestion": suggestion,
        }


def _rule_term_functions(spl: str, blanked: str, piece: _Piece, in_map: int, out: _Collector) -> None:
    text = blanked[piece.start:piece.end]
    reported_to = 0
    for m in _TERM_CALL.finditer(text):
        before = text[:m.start()].rstrip()
        if m.start() < reported_to or before and before[-1] in "=<>!":
            continue
        name = m.group(1)
        close = _close_paren(text, m.end() - 1, len(text))
        reported_to = close + 1 if close >= 0 else len(text)
        call = spl[piece.start + m.start():piece.start + (close + 1 if close >= 0 else len(text))]
        out.add("L001", piece.segment, piece.command, in_map, call,
                "%s(...) is used as a search term. The search command does not evaluate eval functions: the call is "
                "read as plain words, so the clause matches nothing (and under NOT, everything)." % name,
                "Test it after the search: | where %s" % _short(call), key=name)


def _rule_timechart(spl: str, blanked: str, piece: _Piece, in_map: int, out: _Collector) -> None:
    if piece.command not in ("timechart", "sitimechart"):
        return
    text = blanked[piece.start:piece.end]
    by = _top_level_by(text, 0)
    if by < 0:
        return
    fields = _by_fields(text, by, len(text))
    if len(fields) < 2:
        return
    names = [spl[piece.start + s:piece.start + e] for s, e in fields]
    listed = ", ".join(names)
    out.add("L002", piece.segment, piece.command, in_map, "by " + listed,
            "%s accepts one split-by field and Splunk rejects this search (the by clause lists %s)."
            % (piece.command, listed),
            "Use one field, or aggregate with stats: | bin _time span=1h | stats <same aggregation> by _time, %s"
            % listed)


def _rule_calls(spl: str, blanked: str, piece: _Piece, in_map: int, out: _Collector) -> None:
    if piece.command == "search":
        return
    text = blanked[piece.start:piece.end]
    for m in _CHECKED_CALL.finditer(text):
        name = m.group(1)
        close = _close_paren(text, m.end() - 1, len(text))
        if close < 0:
            continue
        args = _split_args(text, m.end(), close)
        call = spl[piece.start + m.start():piece.start + close + 1]
        if name in TWO_ARGUMENT_FUNCTIONS and len(args) != 2:
            out.add("L003", piece.segment, piece.command, in_map, call,
                    "%s() takes exactly two arguments but is called with %d; Splunk rejects the search."
                    % (name, len(args)),
                    {"match": 'Put the regex flags inside the pattern: match(field, "(?i)pattern")',
                     "like": 'like(field, "pattern%")',
                     "cidrmatch": 'cidrmatch("10.0.0.0/8", ip_field)'}[name], key=name)
        if name in REGEX_FUNCTIONS and len(args) >= 2:
            literal = _STRING.match(spl[piece.start + args[1][0]:piece.start + args[1][1]].strip())
            if not literal:
                continue
            run = _TRAILING_BACKSLASHES.search(literal.group(1))
            if run and (len(run.group(0)) // 2) % 2 == 1:
                fixed = literal.group(1) + run.group(0)
                out.add("L004", piece.segment, piece.command, in_map, call,
                        "The regex for %s() ends in a single backslash once the eval string is unescaped "
                        "(a regex backslash needs four in an eval string); Splunk rejects the search." % name,
                        'Write the end of the string as "...%s"' % fixed[-len(run.group(0)) * 2:], key=name)


def _rule_time_snap(spl: str, blanked: str, piece: _Piece, in_map: int, out: _Collector) -> None:
    text = blanked[piece.start:piece.end]
    for m in _TIME_TERM.finditer(text):
        raw = spl[piece.start + m.end():piece.end]
        value = _TIME_VALUE.match(raw)
        if not value:
            continue
        modifier = value.group(1) if value.group(1) is not None else value.group(2)
        if not _BAD_SNAP.search(modifier):
            continue
        simple = re.sub(r"@\d+([A-Za-z]+)", r"@\1", modifier)
        hint = ("Snap to one unit, for example %s, and use span=5m in bin, tstats or timechart if you need 5-minute buckets"
                % simple) if simple != modifier else "Use @w0 to @w7 for a day of the week"
        out.add("L005", piece.segment, piece.command, in_map, "%s=%s" % (m.group(1), modifier),
                "The time modifier %s snaps to a number of units, which Splunk does not support: tstats rejects it "
                "and a plain search selects nothing." % modifier, hint, key=modifier)


def _map_searches(spl: str, piece: _Piece) -> List[str]:
    return [_ESCAPED.sub(r"\1", m.group(1)) for m in _MAP_SEARCH.finditer(spl[piece.start:piece.end])]


def _lint(spl: str, in_map: int, out: _Collector) -> None:
    masked = _mask_quotes(spl)
    blanked = _blank_macros(masked)
    for piece in _pieces(masked):
        if piece.command == "search":
            _rule_term_functions(spl, blanked, piece, in_map, out)
        _rule_timechart(spl, blanked, piece, in_map, out)
        _rule_calls(spl, blanked, piece, in_map, out)
        _rule_time_snap(spl, blanked, piece, in_map, out)
        if piece.command == "map" and in_map < MAX_NESTING:
            for inner in _map_searches(spl, piece):
                nested = _Collector()
                _lint(inner, in_map + 1, nested)
                for finding in nested.items.values():
                    finding["segment"] = piece.segment
                    ident = (finding["rule"], piece.segment, finding["in_map"], finding["call"])
                    out.items.setdefault(ident, finding)


def lint(spl: Optional[str]) -> List[Dict[str, Any]]:
    """Advisory findings for one search, in the order they appear. Never raises for odd input
    other than a non-string."""
    if not spl or not spl.strip():
        return []
    out = _Collector()
    _lint(spl, 0, out)
    return sorted(out.items.values(), key=lambda f: (f["segment"], f["in_map"], f["rule"]))


def lint_search(spl: Optional[str], cim_spl: Optional[str] = None) -> List[Dict[str, Any]]:
    """Findings for a use case: the primary search, then its CIM search (marked ``search: cim``).
    Advisory output must never break the caller, so an unexpected failure yields no findings."""
    out: List[Dict[str, Any]] = []
    for kind, text in (("primary", spl), ("cim", cim_spl)):
        try:
            out.extend(dict(f, search=kind) for f in lint(text))
        except Exception:  # noqa: BLE001
            continue
    return out

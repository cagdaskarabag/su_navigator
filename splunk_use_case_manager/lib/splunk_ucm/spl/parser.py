"""Prepare SPL for Splunk's ``/services/search/parser`` (docs/DECISIONS.md D-026).

A leading ``index=`` is a generating search term, not a command; the parser
requires the ``search`` command or a generating ``|`` command.
"""

from typing import List

from ..errors import ValidationError
from ..platform.search import ParseResult, SearchClient
from .analysis import HIGH_COST_COMMANDS, SIDE_EFFECT_COMMANDS, analyze


def for_parser(spl: str) -> str:
    """Return the preferred parser form (search prefix when the first token is not a command)."""
    return parser_candidates(spl)[0]


def parser_candidates(spl: str) -> List[str]:
    text = (spl or "").strip()
    if not text:
        raise ValidationError("empty search")
    if len(text) > 200000:
        raise ValidationError("search is too large to parse")
    out: List[str] = []
    lowered = text.lstrip().lower()
    out.append(text)
    if not (lowered.startswith("|") or lowered.startswith("search ") or lowered.startswith("search\n")):
        out.append("search " + text)
    seen = []
    for item in out:
        if item not in seen:
            seen.append(item)
    return seen


def parse(client: SearchClient, spl: str) -> ParseResult:
    last = None
    for candidate in parser_candidates(spl):
        last = client.parse(candidate)
        if last.ok:
            last.normalized = candidate
            return last
    return last


def side_effects(commands: List[str]) -> List[str]:
    return [c for c in commands if c in SIDE_EFFECT_COMMANDS]


def high_cost(commands: List[str]) -> List[str]:
    return [c for c in commands if c in HIGH_COST_COMMANDS]


def combined_side_effects(spl: str, commands: List[str]) -> List[str]:
    """Union of parser commands and the static analyser (parser may not run if syntax fails)."""
    seen = []
    for name in list(commands) + analyze(spl).side_effect_commands:
        if name not in seen:
            seen.append(name)
    return [c for c in seen if c in SIDE_EFFECT_COMMANDS]

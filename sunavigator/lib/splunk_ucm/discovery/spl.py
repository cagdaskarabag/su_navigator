"""Construct bounded discovery searches from already-validated index names.

Imported use-case SPL is never an input here. Index names come from
``/services/data/indexes`` and must match ``INDEX_NAME``.
"""

import re
from typing import List, Sequence, Tuple

from ..errors import ValidationError

INDEX_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$")
RELATIVE_TIME = re.compile(r"^(now|-\d+[smhdw])$")
CHUNK = 40


def validate_index_name(name: str) -> str:
    if not isinstance(name, str) or not INDEX_NAME.match(name):
        raise ValidationError("invalid index name", {"value": str(name)[:80]})
    return name


def validate_time(value: str, name: str) -> str:
    text = (value or "").strip()
    if not RELATIVE_TIME.match(text):
        raise ValidationError("invalid %s" % name, {"value": text[:40],
                                                    "allowed": "now or -N{s,m,h,d,w}"})
    return text


def chunk_indexes(names: Sequence[str], size: int = CHUNK) -> List[List[str]]:
    valid = [validate_index_name(n) for n in names]
    return [valid[i:i + size] for i in range(0, len(valid), size)]


def tstats_by_index_sourcetype(indexes: Sequence[str], earliest: str, latest: str) -> str:
    """Return a generating ``tstats`` that counts events in a time window.

    ``earliest`` / ``latest`` are relative-time tokens, already validated.
    """
    if not indexes:
        raise ValidationError("tstats requires at least one index")
    earliest = validate_time(earliest, "earliest")
    latest = validate_time(latest, "latest")
    clause = " OR ".join("index=%s" % validate_index_name(n) for n in indexes)
    return ("| tstats count min(_time) as first_time max(_time) as last_time "
            "where (%s) earliest=%s latest=%s by index, sourcetype" % (clause, earliest, latest))


def tstats_searches(indexes: Sequence[str], earliest: str, latest: str,
                    chunk: int = CHUNK) -> List[Tuple[List[str], str]]:
    return [(group, tstats_by_index_sourcetype(group, earliest, latest))
            for group in chunk_indexes(indexes, chunk)]


FUTURE_EARLIEST = "+5m"
FUTURE_LATEST = "+10y"


def tstats_volume(indexes: Sequence[str], days: int) -> str:
    """Events per pair over the last ``days`` days, with first and last event time (D-070)."""
    if not indexes or not 1 <= int(days) <= 365:
        raise ValidationError("volume search needs indexes and 1 to 365 days")
    clause = " OR ".join("index=%s" % validate_index_name(n) for n in indexes)
    return ("| tstats count min(_time) as first_time max(_time) as last_time "
            "where (%s) earliest=-%dd latest=now by index, sourcetype" % (clause, int(days)))


def tstats_future(indexes: Sequence[str]) -> str:
    """Events time-stamped more than five minutes in the future, per pair (D-070)."""
    if not indexes:
        raise ValidationError("future search needs indexes")
    clause = " OR ".join("index=%s" % validate_index_name(n) for n in indexes)
    return ("| tstats count max(_time) as last_time where (%s) earliest=%s latest=%s by index, sourcetype"
            % (clause, FUTURE_EARLIEST, FUTURE_LATEST))

"""Schedule arithmetic for deployed searches: cadence, search window, jitter and advisories (D-069).

Advisories are findings in the common record shape (``spl.findings``). They never change a gate,
a score or an approval. Only five-field crons the deployment spec accepts are read; a cron whose
cadence cannot be derived (lists with uneven gaps, day or month restrictions) gives ``None`` and
no cadence advisory.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional

from ..spl.findings import finding

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
_RELATIVE = re.compile(r"^([-+])(\d{1,4})([smhdwy])(?:@[smhdwy]\d?)?$")
_STEP = re.compile(r"^(?:\*|(\d{1,2})-59)/(\d{1,2})$")


def cadence_seconds(cron: str) -> Optional[int]:
    """Seconds between runs for regular schedules, else None."""
    parts = " ".join((cron or "").split()).split(" ")
    if len(parts) != 5:
        return None
    minute, hour, dom, month, dow = parts
    if dom != "*" or month != "*" or dow != "*":
        return None
    minute_gap = _gap(minute, 60)
    if hour == "*":
        return minute_gap * 60 if minute_gap else None
    hour_gap = _gap(hour, 24)
    if hour_gap and minute.isdigit():
        return hour_gap * 3600
    return None


def _gap(field: str, size: int) -> Optional[int]:
    if field == "*":
        return 1
    step = _STEP.match(field)
    if step:
        n = int(step.group(2))
        return n if 0 < n <= size and size % n == 0 else None
    if field.isdigit():
        return size
    if re.match(r"^\d{1,2}(,\d{1,2})+$", field):
        values = sorted(int(v) for v in field.split(","))
        gaps = {b - a for a, b in zip(values, values[1:])} | {size - values[-1] + values[0]}
        return gaps.pop() if len(gaps) == 1 else None
    return None


def offset_seconds(value: str) -> Optional[int]:
    """``-20m@m`` -> -1200, ``now`` -> 0; snapping is ignored (a bound of one unit)."""
    text = (value or "").strip()
    if text == "now":
        return 0
    m = _RELATIVE.match(text)
    if not m:
        return None
    seconds = int(m.group(2)) * _UNIT_SECONDS[m.group(3)]
    return -seconds if m.group(1) == "-" else seconds


def window_seconds(earliest: str, latest: str) -> Optional[int]:
    start, end = offset_seconds(earliest), offset_seconds(latest)
    if start is None or end is None or end <= start:
        return None
    return end - start


def jittered_cron(cron: str, seed: str) -> str:
    """``*/N * * * *`` with a minute offset derived from ``seed``, so searches do not all start at :00."""
    parts = " ".join((cron or "").split()).split(" ")
    if len(parts) != 5:
        return cron
    step = re.match(r"^\*/(\d{1,2})$", parts[0])
    if not step or parts[1:] != ["*", "*", "*", "*"]:
        return cron
    n = int(step.group(1))
    if n < 2 or 60 % n:
        return cron
    offset = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16) % n
    if not offset:
        return cron
    return "%d-59/%d * * * *" % (offset, n)


def advisories(cron: str, earliest: str, latest: str, suppress_period: str = "") -> List[Dict[str, Any]]:
    """Schedule findings for a deployment revision."""
    out: List[Dict[str, Any]] = []
    cadence = cadence_seconds(cron)
    window = window_seconds(earliest, latest)
    if cadence == 60:
        out.append(finding("S001", "schedule", "warning",
                           "Runs every minute. Each run is a scheduled search; consider 5 minutes or more unless the "
                           "detection needs it.", {"cron": cron}))
    if cadence and window and window < cadence:
        out.append(finding("S002", "schedule", "warning",
                           "The search window (%s) is shorter than the time between runs (%s): events that fall "
                           "between two windows are never searched." % (_span(window), _span(cadence)),
                           {"window_seconds": window, "cadence_seconds": cadence}))
    if cadence and window and window > cadence and not suppress_period:
        out.append(finding("S003", "schedule", "info",
                           "The search window (%s) is longer than the time between runs (%s), so windows overlap and "
                           "the same event can alert twice; set a suppression period or align the window."
                           % (_span(window), _span(cadence)),
                           {"window_seconds": window, "cadence_seconds": cadence}))
    if (latest or "").strip() == "now":
        out.append(finding("S004", "schedule", "info",
                           "The window ends at now. Events indexed late (forwarder delay) are missed; a latest time "
                           "a few minutes back (for example -5m@m) catches them.", {"latest": latest}))
    if cadence is None:
        out.append(finding("S005", "schedule", "info",
                           "The time between runs cannot be derived from this cron, so window checks were skipped.",
                           {"cron": cron}))
    return out


def _span(seconds: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return "%d%s" % (seconds // size, unit)
    return "%ds" % seconds

"""Minimal reader and writer for Splunk ``.conf`` files (stdlib only, D-052).

Only what the app needs: ``[stanza]`` headers, ``key = value`` lines, ``#`` and
``;`` comments, and value continuation. A line that ends with a backslash
continues on the next line; the joined value keeps one newline per line break
(the form Splunk itself writes for multi-line ``search`` values). Continuation
lines are written and read without their leading indentation.
"""

from typing import Dict, List, Mapping, Tuple


class ConfError(ValueError):
    """A value cannot be written so that it reads back unchanged."""


def _check_name(name: str) -> None:
    if not name or any(c in name for c in "[]\r\n") or name != name.strip():
        raise ConfError("stanza name cannot be written to a .conf file")


def _value_lines(key: str, value: str) -> List[str]:
    if "\r" in value or "\x00" in value:
        raise ConfError("%s contains a carriage return or NUL" % key)
    lines = value.split("\n")
    for line in lines:
        if line != line.strip():
            raise ConfError("%s has leading or trailing whitespace on a line; normalise it first" % key)
        if line.endswith("\\"):
            raise ConfError("%s has a line ending in a backslash, which a .conf file reads as a continuation" % key)
    if len(lines) == 1:
        return ["%s = %s" % (key, value)]
    out = ["%s = %s \\" % (key, lines[0])]
    for line in lines[1:-1]:
        out.append(("    %s \\" % line) if line else "    \\")
    out.append("    %s" % lines[-1])
    return out


def write_stanza(name: str, settings: Mapping[str, str]) -> str:
    _check_name(name)
    out = ["[%s]" % name]
    for key in sorted(settings):
        if not key or any(c in key for c in "=[]\r\n") or key != key.strip():
            raise ConfError("setting name %r cannot be written" % key)
        out.extend(_value_lines(key, str(settings[key])))
    return "\n".join(out) + "\n"


def write(stanzas: List[Tuple[str, Mapping[str, str]]], header: List[str] = ()) -> str:
    parts = ["# %s" % line for line in header]
    parts.extend(write_stanza(name, settings) for name, settings in stanzas)
    return "\n".join(parts)


def parse(text: str) -> List[Tuple[str, Dict[str, str]]]:
    out: List[Tuple[str, Dict[str, str]]] = []
    current: Dict[str, str] = {}
    stanza = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        stripped = raw.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]") and "=" not in stripped.split("]")[0]:
            if stanza is not None:
                out.append((stanza, current))
            stanza, current = stripped[1:-1], {}
            continue
        if stanza is None or "=" not in raw:
            continue
        key, _, value = raw.partition("=")
        key = key.strip()
        value = value.lstrip()
        parts = []
        while value.endswith("\\") and i < len(lines):
            parts.append(value[:-1].rstrip())
            value = lines[i].strip()
            i += 1
        parts.append(value.rstrip() if parts else value.strip())
        current[key] = "\n".join(parts)
    if stanza is not None:
        out.append((stanza, current))
    return out

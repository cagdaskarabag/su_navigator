"""Index access of the account that runs deployed searches (docs/DECISIONS.md D-063).

A scheduled search runs with the rights of its owner (``[deployment] scheduled_owner``). An
index the owner may not search returns no events and no error, so a search can report
``success`` with zero results forever. This module reads the owner's roles with the REST
handler's system token, resolves the effective index access and compares it with the
indexes the SPL names.

Rules, as measured on Splunk 10.2.9 and documented in ``authorize.conf.spec``:

* a role's own and imported values (``imported_*``, already resolved through nested imports)
  are combined across every role the user holds;
* ``srchIndexesDisallowed`` wins over ``srchIndexesAllowed`` and ``srchIndexesDefault``;
* ``*`` matches only non-internal indexes, a pattern that starts with ``_`` matches internal
  indexes (``_*`` all of them), and a pattern that starts with ``*`` (``*audit``) never matches
  an internal index;
* a search without ``index=`` uses the default indexes that are also allowed; with none, it
  sees nothing.

The SPL side is a hint (``spl.analysis``), so every doubt ends in ``unverified``, never ``met``.
"""

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

from ..errors import StorageError
from ..spl.analysis import SplAnalysis, analyze
from ..storage import collections as C
from ..storage.transport import SplunkdTransport

MET, PARTIAL, NOT_MET, UNVERIFIED, NOT_APPLICABLE = "met", "partial", "not_met", "unverified", "not_applicable"

PRINCIPAL_OK, PRINCIPAL_NO_OWNER, PRINCIPAL_NOT_FOUND, PRINCIPAL_UNREADABLE = (
    "ok", "no_owner", "user_not_found", "unreadable")

MAX_PATTERNS = 200
MAX_OBSERVED = 5

# Commands that read events or index metadata and therefore depend on index access.
INDEX_READERS = frozenset({"search", "tstats", "mstats", "mcatalog", "from", "metadata", "metasearch",
                           "eventcount", "dbinspect", "pivot", "datamodel", "multisearch", "union"})
HIDDEN_SEARCH_COMMANDS = frozenset({"map", "savedsearch", "loadjob"})

_UNVERIFIED_TEXT = {
    "index_star": "it searches index=*, which covers whatever the account can see",
    "datamodel": "it reads a data model, whose indexes are set in the data model or its constraint macro",
    "tags": "it filters on tags, which resolve to events in indexes the search does not name",
    "eventtypes": "it filters on event types, which resolve to searches the SPL does not show",
    "macro_not_expanded": "it uses macros that could not be expanded, so the indexes they add are unknown",
    "hidden_search": "it runs another search (map, savedsearch or loadjob) whose indexes are not visible here",
    "index_pattern_unresolved": "an index pattern in the search matches no index known from discovery",
    "default_index_data_unknown": "it names no index, so it reads the default indexes and nothing shows whether "
                                  "its data is in them",
}


def _split_names(value: Any) -> List[str]:
    if value is None:
        return []
    items: Iterable[Any]
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = re.split(r"[;,]", str(value))
    out: List[str] = []
    for item in items:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
    return out[:MAX_PATTERNS]


def _text(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value if v).strip()
    return str(value or "").strip()


def _regex(pattern: str):
    return re.compile("^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$")


def pattern_matches(pattern: str, name: str) -> bool:
    """Splunk's index wildcard rule: ``*`` never reaches an internal index unless the pattern
    itself starts with ``_``."""
    p = (pattern or "").strip().lower()
    n = (name or "").strip().lower()
    if not p or not n:
        return False
    if n.startswith("_") and not p.startswith("_"):
        return False
    return _regex(p).match(n) is not None


def _first_match(patterns: Sequence[str], name: str) -> Optional[str]:
    for p in patterns:
        if pattern_matches(p, name):
            return p
    return None


class PrincipalAccess:
    """The scheduled owner's combined role settings."""

    def __init__(self, owner: str = "", status: str = PRINCIPAL_OK, reason: str = "",
                 roles: Optional[List[str]] = None, allowed: Optional[List[str]] = None,
                 disallowed: Optional[List[str]] = None, default: Optional[List[str]] = None,
                 filters: Optional[List[str]] = None, unreadable_roles: Optional[List[str]] = None):
        self.owner = owner
        self.status = status
        self.reason = reason
        self.roles = roles or []
        self.allowed = allowed or []
        self.disallowed = disallowed or []
        self.default = default or []
        self.filters = filters or []
        self.unreadable_roles = unreadable_roles or []

    @property
    def readable(self) -> bool:
        return self.status == PRINCIPAL_OK

    def to_dict(self) -> Dict[str, Any]:
        return {"owner": self.owner, "status": self.status, "reason": self.reason, "roles": self.roles,
                "allowed": self.allowed, "disallowed": self.disallowed, "default": self.default,
                "filters": self.filters, "unreadable_roles": self.unreadable_roles}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PrincipalAccess":
        return cls(**{k: data.get(k) for k in (
            "owner", "status", "reason", "roles", "allowed", "disallowed", "default", "filters",
            "unreadable_roles") if data.get(k) is not None})

    def covers(self, name: str) -> Tuple[bool, str]:
        """Whether the account can search index ``name``, and why not."""
        denied = _first_match(self.disallowed, name)
        if denied:
            return False, "disallowed by '%s'" % denied
        if _first_match(self.allowed, name):
            return True, ""
        if name.startswith("_"):
            return False, "no allowed pattern matches it ('*' does not include internal indexes; '_*' does)"
        return False, "no allowed pattern matches it"

    def default_indexes(self, known: Sequence[str]) -> List[str]:
        """Default indexes the account may also search; wildcard defaults expand over ``known``."""
        out: List[str] = []
        for pattern in self.default:
            p = pattern.strip().lower()
            candidates = [k for k in known if pattern_matches(p, k)] if "*" in p else [p]
            for name in candidates:
                if name and name not in out and self.covers(name)[0]:
                    out.append(name)
        return out

    @property
    def internal_access(self) -> bool:
        """Can the account search every internal index, for example ``_internal``?"""
        return self.covers("_internal")[0]

    def fingerprint(self) -> str:
        return hashlib.sha1(json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()[:16]

    def summary(self) -> Dict[str, Any]:
        """What the Overview card shows: no index lists, only the facts an operator needs."""
        return {"owner": self.owner, "status": self.status, "reason": self.reason, "roles": list(self.roles),
                "internal_access": self.internal_access if self.readable else None,
                "all_indexes_access": ("*" in self.allowed) if self.readable else None,
                "has_filter": bool(self.filters), "has_disallowed": bool(self.disallowed),
                "default_indexes": len(self.default), "unreadable_roles": list(self.unreadable_roles)}


def _get(transport: SplunkdTransport, path: str) -> Tuple[int, Dict[str, Any]]:
    status, body = transport.request("GET", path, {"output_mode": "json"}, timeout=30.0)
    if status != 200:
        return status, {}
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError):
        return 502, {}
    entries = data.get("entry") if isinstance(data, dict) else None
    if not entries or not isinstance(entries[0], dict):
        return 404, {}
    content = entries[0].get("content")
    return 200, content if isinstance(content, dict) else {}


def read_principal(transport: Optional[SplunkdTransport], owner: str) -> PrincipalAccess:
    """Read the owner's roles. Never raises: a failure is a status, so a check built on it
    ends as ``unverified`` and does not block anything."""
    owner = (owner or "").strip()
    if not owner:
        return PrincipalAccess(owner, PRINCIPAL_NO_OWNER,
                               "[deployment] scheduled_owner is not set in ucm.conf")
    if transport is None:
        return PrincipalAccess(owner, PRINCIPAL_UNREADABLE, "no system session is available to read roles")
    try:
        status, user = _get(transport, "/services/authentication/users/%s" % quote(owner, safe=""))
        if status == 404:
            return PrincipalAccess(owner, PRINCIPAL_NOT_FOUND, "user %s does not exist on this search head" % owner)
        if status != 200:
            return PrincipalAccess(owner, PRINCIPAL_UNREADABLE,
                                   "splunkd refused to read the user (HTTP %d)" % status)
        roles = _split_names(user.get("roles"))
        merged: Dict[str, List[str]] = {"allowed": [], "disallowed": [], "default": []}
        filters: List[str] = []
        unreadable: List[str] = []
        for role in roles:
            status, content = _get(transport, "/services/authorization/roles/%s" % quote(role, safe=""))
            if status != 200:
                unreadable.append(role)
                continue
            for key, own, imported in (("allowed", "srchIndexesAllowed", "imported_srchIndexesAllowed"),
                                       ("disallowed", "srchIndexesDisallowed", "imported_srchIndexesDisallowed"),
                                       ("default", "srchIndexesDefault", "imported_srchIndexesDefault")):
                for name in _split_names(content.get(own)) + _split_names(content.get(imported)):
                    if name.lower() not in merged[key]:
                        merged[key].append(name.lower())
            for key in ("srchFilter", "imported_srchFilter"):
                text = _text(content.get(key))
                if text and text not in filters:
                    filters.append(text)
    except StorageError as exc:
        return PrincipalAccess(owner, PRINCIPAL_UNREADABLE, "reading roles failed: %s" % exc.message[:200])
    if unreadable:
        return PrincipalAccess(owner, PRINCIPAL_UNREADABLE,
                               "splunkd refused to read role(s): %s" % ", ".join(unreadable), roles,
                               unreadable_roles=unreadable)
    return PrincipalAccess(owner, PRINCIPAL_OK, "", roles, merged["allowed"], merged["disallowed"],
                           merged["default"], filters)


# -- SPL side ------------------------------------------------------------------

def _positive(analysis: SplAnalysis) -> List[str]:
    return [v.value.lower() for v in analysis.indexes if not v.negated]


def scan_spl(spl: str, expanded: str = "") -> Dict[str, Any]:
    """The index facts of a search. ``expanded`` is the parser's macro-expanded pipeline when
    it is known; with it the macros are resolved, without it they are a reason to doubt."""
    static = analyze(spl)
    expanded_analysis = analyze(expanded) if expanded else None
    use = expanded_analysis or static
    names: List[str] = []
    for source in (static, expanded_analysis):
        if source is not None:
            for name in _positive(source):
                if name not in names:
                    names.append(name)
    reasons: List[str] = []
    if use.datamodels or static.datamodels:
        reasons.append("datamodel")
    if use.tags or static.tags:
        reasons.append("tags")
    if use.eventtypes or static.eventtypes:
        reasons.append("eventtypes")
    if any(n == "*" for n in names):
        reasons.append("index_star")
    macros_left = bool(static.macros) if expanded_analysis is None else bool(expanded_analysis.macros)
    if macros_left:
        reasons.append("macro_not_expanded")
    if HIDDEN_SEARCH_COMMANDS.intersection(use.commands) or HIDDEN_SEARCH_COMMANDS.intersection(static.commands):
        reasons.append("hidden_search")
    commands = set(use.commands) | set(static.commands)
    reads_indexes = bool(INDEX_READERS & commands) or static.generating_command == "search"
    names = [n for n in names if n != "*"]
    sourcetypes = [s for s in static.positive("sourcetypes") if "*" not in s]
    return {"indexes": names[:MAX_PATTERNS], "reads_indexes": reads_indexes,
            "uses_default": reads_indexes and not names and "index_star" not in reasons
            and "datamodel" not in reasons,
            "unverified": reasons, "sourcetypes": sourcetypes[:20],
            "expanded": expanded_analysis is not None}


def _result(status: str, code: str, detail: str, observed: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"status": status, "code": code, "detail": detail,
            "observed": (observed or [])[:MAX_OBSERVED], "via_mapping": None}


def _who(principal: PrincipalAccess) -> str:
    return principal.owner or "the scheduled owner"


def _reasons_text(reasons: Sequence[str]) -> str:
    return "; ".join(_UNVERIFIED_TEXT.get(r, r) for r in reasons)


def check_access(principal: Optional[PrincipalAccess], scan: Optional[Dict[str, Any]],
                 known: Sequence[Dict[str, Any]] = (), sourcetype_indexes: Optional[Dict[str, List[str]]] = None
                 ) -> Dict[str, Any]:
    """Compare what the search needs with what the account can search."""
    if principal is None:
        return _result(UNVERIFIED, "principal_not_read", "The scheduled owner's roles were not read, so index "
                       "access could not be checked.")
    if principal.status == PRINCIPAL_NO_OWNER:
        return _result(UNVERIFIED, "no_scheduled_owner",
                       "No scheduled owner is configured ([deployment] scheduled_owner), so deployed searches "
                       "cannot run as a dedicated account and their index access cannot be checked.")
    if principal.status == PRINCIPAL_NOT_FOUND:
        return _result(UNVERIFIED, "owner_not_found", "%s. Index access could not be checked." % principal.reason)
    if not principal.readable:
        return _result(UNVERIFIED, "roles_unreadable",
                       "The roles of %s could not be read (%s), so index access was not checked. This does not "
                       "block deployment." % (_who(principal), principal.reason))
    if scan is None:
        return _result(UNVERIFIED, "no_spl_scan", "The search has not been scanned for the indexes it reads.")
    if not scan.get("reads_indexes") and not scan.get("indexes") and not scan.get("unverified"):
        return _result(NOT_APPLICABLE, "no_index_read", "The search does not read events from an index.")

    known_names = [str(k.get("name") or "").lower() for k in known if k.get("name")]
    reasons = list(scan.get("unverified") or [])
    covered: List[str] = []
    uncovered: List[Tuple[str, str]] = []
    rows: List[Dict[str, Any]] = []

    def classify(name: str) -> None:
        ok, why = principal.covers(name)
        rows.append({"index": name, "searchable": ok, "reason": why})
        if ok:
            covered.append(name)
        else:
            uncovered.append((name, why))

    for pattern in scan.get("indexes") or []:
        if "*" in pattern:
            matches = [k for k in known_names if pattern_matches(pattern, k)]
            if not matches:
                if "index_pattern_unresolved" not in reasons:
                    reasons.append("index_pattern_unresolved")
                continue
            open_to = [m for m in matches if principal.covers(m)[0]]
            closed = [m for m in matches if m not in open_to]
            if open_to and closed:
                covered.extend(open_to)
                why = "it matches %d indexes and the account can search %d; not %s" % (
                    len(matches), len(open_to), ", ".join(closed[:3]) + (" and more" if len(closed) > 3 else ""))
                uncovered.append((pattern, why))
                rows.append({"index": pattern, "searchable": True, "partial": True, "reason": why})
            elif open_to:
                covered.extend(open_to)
                rows.append({"index": pattern, "searchable": True, "reason": ""})
            else:
                why = principal.covers(matches[0])[1]
                uncovered.append((pattern, why))
                rows.append({"index": pattern, "searchable": False, "reason": why})
        else:
            classify(pattern)

    if scan.get("uses_default"):
        defaults = principal.default_indexes(known_names)
        if not defaults:
            uncovered.append(("(default indexes)", "the account has no default index it may search"))
            rows.append({"index": "(default indexes)", "searchable": False,
                         "reason": "the account has no default index it may search"})
        else:
            evidence = (sourcetype_indexes or {})
            where = sorted({i for st in scan.get("sourcetypes") or [] for i in evidence.get(st, [])})
            if where and not set(where) & set(defaults):
                uncovered.append((where[0], "it holds the search's sourcetype but is not a default index"))
                rows.append({"index": where[0], "searchable": False,
                             "reason": "holds the sourcetype, but a search without index= does not read it"})
            elif where:
                covered.extend(defaults)
                rows.append({"index": ", ".join(defaults[:3]), "searchable": True, "reason": "default"})
            else:
                reasons.append("default_index_data_unknown")
                rows.append({"index": ", ".join(defaults[:3]), "searchable": True, "reason": "default"})

    warning = ""
    if principal.filters:
        warning = (" %s has a search filter (srchFilter: %s); it can hide events even where the index is "
                   "searchable." % (_who(principal), "; ".join(principal.filters)[:200]))

    if uncovered:
        names = ", ".join(n for n, _ in uncovered[:5])
        why = "; ".join("%s: %s" % (n, w) for n, w in uncovered[:3])
        roles = ", ".join(principal.roles) or "no role"
        status = PARTIAL if covered else NOT_MET
        head = ("%s can search some of the indexes this search reads, but not %s" if covered
                else "%s cannot search %s") % (_who(principal), names)
        return _result(status, "index_not_accessible",
                       "%s (%s; roles: %s). A scheduled run would return no events from them and still report "
                       "success. Grant the index to the role or the search will run blind.%s"
                       % (head, why, roles, warning), rows)
    if reasons:
        return _result(UNVERIFIED, reasons[0], "Index access could not be fully verified: %s.%s"
                       % (_reasons_text(reasons), warning), rows)
    return _result(MET, "index_accessible", "%s can search %s.%s" % (
        _who(principal), ", ".join(sorted(set(covered))[:5]), warning), rows)


def known_index_docs(snapshot_indexes: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [d for d in snapshot_indexes.values() if d.get("status") == "active" and not d.get("disabled")]


class SchedulerAccess:
    """Reads the scheduled owner's roles with the handler's system session and checks SPL against them.

    The read happens once per instance and never raises; a store or a REST failure ends in an
    ``unverified`` result.
    """

    def __init__(self, store: Any, transport: Optional[SplunkdTransport], owner: str):
        self.store = store
        self.transport = transport
        self.owner = (owner or "").strip()
        self._principal: Optional[PrincipalAccess] = None

    def principal(self) -> PrincipalAccess:
        if self._principal is None:
            self._principal = read_principal(self.transport, self.owner)
        return self._principal

    def _known(self) -> List[Dict[str, Any]]:
        try:
            return known_index_docs({d.get("name", "").lower(): d for d in self.store.query(
                C.ENVIRONMENT_SOURCES, {"kind": "index"}, fields=["name", "status", "disabled", "is_internal"])})
        except Exception:
            return []

    def _evidence(self, scan: Dict[str, Any]) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        if not scan.get("uses_default"):
            return out
        for st in (scan.get("sourcetypes") or [])[:10]:
            try:
                rows = self.store.query(C.ENVIRONMENT_SOURCES, {"kind": "pair", "sourcetype": st},
                                        fields=["index", "status"])
            except Exception:
                continue
            out[st] = sorted({r.get("index") for r in rows if r.get("index") and r.get("status") == "active"})
        return out

    def check(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        return check_access(self.principal(), scan, self._known(), self._evidence(scan))

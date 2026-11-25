"""Detections that already run in this environment, matched to catalogue use cases (F-13, D-074).

Discovery lists the saved searches the discovery account can read in other apps. For each one it computes the
hash of the SPL (the same whitespace-normalised SHA-256 the catalogue stores), looks for catalogue use cases with
that hash or a matching title, and stores a *proposal*. The SPL is hashed and dropped: it is never stored here, so
no role can read another app's search through SUNavigator. Only names (app, search title, owner, sharing) and
hashes are kept.

A person decides each proposal: accept (this search is that use case), reject, or reset. An accepted match makes
the use case show "enabled elsewhere" in coverage and on its page. It never changes SUNavigator's own levels:
a use case the app did not deploy is not "enabled" in SUN coverage, whatever other apps run.
"""

import dataclasses
import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional

from .. import APP_NAME
from ..audit import AuditService
from ..catalog.quality import spl_hash
from ..errors import NotFoundError, ValidationError
from ..storage import collections as C
from ..storage.kvstore import DocumentStore
from ..util import utc_now_iso

MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
STATES = ("proposed", "accepted", "rejected")
DECISIONS = ("accept", "reject", "reset")
BASIS_ORDER = {"spl_hash": 0, "title_mitre": 1, "title": 2}
PAGE = 5000


@dataclasses.dataclass
class ExternalSettings:
    enabled: bool = True
    max_searches: int = 20000
    max_candidates: int = 5


def external_key(app: str, name: str) -> str:
    return "xm_" + hashlib.sha256(("%s|%s" % (app, name)).encode("utf-8")).hexdigest()[:40]


def normalize_title(title: str) -> str:
    """Lower case words of a search title without ESCU's ``ESCU - `` prefix and `` - Rule`` suffix."""
    text = (title or "").lower().strip()
    text = re.sub(r"^escu\s*-\s*", "", text)
    text = re.sub(r"\s*-\s*(rule|lookup gen|gen)$", "", text)
    return " ".join(re.findall(r"[a-z0-9]+", text))


def mitre_ids(annotations: Any) -> List[str]:
    """Technique ids in an ES correlation search's ``annotations`` JSON; nothing else is read from it."""
    text = annotations if isinstance(annotations, str) else json.dumps(annotations or "")
    return sorted(set(MITRE.findall(text[:20000])))[:30]


def _catalogue(store: DocumentStore) -> Dict[str, Any]:
    by_hash: Dict[str, List[Dict[str, Any]]] = {}
    by_title: Dict[str, List[Dict[str, Any]]] = {}
    skip = 0
    while True:
        rows = store.query(C.CATALOG, {"provider_status": "active"}, sort=[("_key", 1)], skip=skip, limit=PAGE,
                           fields=["_key", "content_id", "title", "spl_hash", "mitre_ids", "provider"])
        for row in rows:
            ref = {"content_key": row["_key"], "content_id": row.get("content_id"), "title": row.get("title") or "",
                   "mitre": set(row.get("mitre_ids") or [])}
            if row.get("spl_hash"):
                by_hash.setdefault(row["spl_hash"], []).append(ref)
            key = normalize_title(row.get("title") or "")
            if key:
                by_title.setdefault(key, []).append(ref)
        if len(rows) < PAGE:
            return {"hash": by_hash, "title": by_title}
        skip += PAGE


def candidates_for(digest: str, title: str, mitre: Iterable[str], index: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for ref in index["hash"].get(digest, []) if digest else []:
        out[ref["content_key"]] = {"content_key": ref["content_key"], "content_id": ref["content_id"],
                                   "title": ref["title"][:200], "basis": "spl_hash"}
    wanted = set(mitre)
    for ref in index["title"].get(normalize_title(title), []):
        if ref["content_key"] in out:
            continue
        basis = "title_mitre" if wanted and wanted & ref["mitre"] else "title"
        out[ref["content_key"]] = {"content_key": ref["content_key"], "content_id": ref["content_id"],
                                   "title": ref["title"][:200], "basis": basis}
    ordered = sorted(out.values(), key=lambda c: (BASIS_ORDER[c["basis"]], c["content_id"] or ""))
    return ordered[: max(1, limit)]


def run_external(store: DocumentStore, inventory: Any, settings: ExternalSettings, job_id: str) -> Dict[str, Any]:
    """Refresh the proposals. Never raises for an unreadable listing: it reports and leaves the old rows."""
    summary: Dict[str, Any] = {"enabled": settings.enabled, "listed": 0, "matched": 0, "unmatched": 0, "proposed": 0,
                               "reset": 0, "missing": 0, "truncated": False, "available": True}
    if not settings.enabled:
        return summary
    lister = getattr(inventory, "list_saved_searches", None)
    if lister is None:
        summary["available"] = False
        return summary
    try:
        found = lister(settings.max_searches + 1)
    except Exception as exc:  # the account may not be allowed to list searches; not a discovery failure
        summary["available"] = False
        summary["reason"] = str(exc)[:200]
        return summary
    if len(found) > settings.max_searches:
        found, summary["truncated"] = found[: settings.max_searches], True
    index = _catalogue(store)
    now = utc_now_iso()
    existing = {r["_key"]: r for r in store.query(C.EXTERNAL_MATCHES, None, limit=50000)}
    seen: set = set()
    docs: List[Dict[str, Any]] = []
    for item in found:
        app, name = item.get("app") or "", item.get("name") or ""
        if not name or app == APP_NAME:
            continue
        summary["listed"] += 1
        digest = spl_hash(item.get("search") or "")
        mitre = mitre_ids(item.get("annotations"))
        cands = candidates_for(digest, name, mitre, index, settings.max_candidates)
        key = external_key(app, name)
        old = existing.get(key)
        if not cands and not (old and old.get("state") in ("accepted", "rejected")):
            summary["unmatched"] += 1
            continue
        summary["matched"] += 1
        seen.add(key)
        doc = {"_key": key, "doc_schema": C.DOC_SCHEMA, "app": app, "name": name[:300], "owner": item.get("owner") or "",
               "sharing": item.get("sharing") or "", "enabled": bool(item.get("enabled")),
               "scheduled": bool(item.get("scheduled")), "spl_hash": digest, "mitre_ids": mitre, "candidates": cands,
               "status": "active", "seen_at": now, "job_id": job_id, "state": "proposed", "content_key": "",
               "decided_by": "", "decided_at": ""}
        if old:
            for field in ("state", "content_key", "decided_by", "decided_at"):
                doc[field] = old.get(field) or doc[field]
            if old.get("state") in ("accepted", "rejected") and old.get("spl_hash") != digest:
                doc.update({"previous_state": old["state"], "previous_content_key": old.get("content_key") or "",
                            "state": "proposed", "content_key": "", "decided_by": "", "decided_at": ""})
                summary["reset"] += 1
        if doc["state"] == "proposed":
            summary["proposed"] += 1
        docs.append(doc)
    gone = []
    for key, old in existing.items():
        if key not in seen and old.get("status") != "missing" and not summary["truncated"]:
            old = dict(old, status="missing", enabled=False, seen_at=now)
            gone.append(old)
    summary["missing"] = len(gone)
    rows = docs + gone
    for start in range(0, len(rows), 500):
        store.batch_save(C.EXTERNAL_MATCHES, rows[start:start + 500])
    return summary


class ExternalMatchService:
    def __init__(self, store: DocumentStore, audit: AuditService):
        self.store = store
        self.audit = audit

    def list(self, state: str = "", offset: int = 0, count: int = 50) -> Dict[str, Any]:
        if state and state not in STATES:
            raise ValidationError("invalid state", {"value": state[:30]})
        query: Dict[str, Any] = {"state": state} if state else {}
        rows = self.store.query(C.EXTERNAL_MATCHES, query, sort=[("name", 1)], skip=max(0, offset),
                                limit=max(1, min(200, count)) + 1)
        has_more = len(rows) > count
        counts = {s: self.store.count(C.EXTERNAL_MATCHES, {"state": s}) for s in STATES}
        return {"items": [self.public(r) for r in rows[:count]], "offset": offset, "count": count, "has_more": has_more,
                "counts": counts}

    @staticmethod
    def public(row: Dict[str, Any]) -> Dict[str, Any]:
        keys = ("_key", "app", "name", "owner", "sharing", "enabled", "scheduled", "spl_hash", "mitre_ids", "candidates",
                "status", "seen_at", "state", "content_key", "decided_by", "decided_at", "previous_state")
        return {k: row.get(k) for k in keys}

    def decide(self, user: str, match_id: str, decision: str, content_key: str = "") -> Dict[str, Any]:
        if decision not in DECISIONS:
            raise ValidationError("invalid decision", {"allowed": list(DECISIONS)})
        row = self.store.get(C.EXTERNAL_MATCHES, match_id) if re.match(r"^xm_[0-9a-f]{40}$", match_id or "") else None
        if row is None:
            raise NotFoundError("no such match")
        if decision == "accept":
            chosen = [c for c in row.get("candidates") or [] if c.get("content_key") == content_key]
            if not chosen:
                raise ValidationError("the use case is not one of this search's candidates")
            row.update({"state": "accepted", "content_key": content_key})
        elif decision == "reject":
            row.update({"state": "rejected", "content_key": ""})
        else:
            row.update({"state": "proposed", "content_key": ""})
        row.update({"decided_by": user if decision != "reset" else "", "decided_at": utc_now_iso() if decision != "reset" else ""})
        self.store.upsert(C.EXTERNAL_MATCHES, row)
        self.audit.record(user, "external.%s" % {"accept": "accepted", "reject": "rejected", "reset": "reset"}[decision],
                          "external_match", match_id,
                          details={"app": row.get("app"), "name": row.get("name"), "content_key": row.get("content_key")})
        return self.public(row)

    def elsewhere(self) -> Dict[str, List[Dict[str, Any]]]:
        """content key -> accepted matches that are still present, with whether the search is enabled."""
        out: Dict[str, List[Dict[str, Any]]] = {}
        for row in self.store.query(C.EXTERNAL_MATCHES, {"state": "accepted", "status": "active"}, limit=50000):
            if row.get("content_key"):
                out.setdefault(row["content_key"], []).append(
                    {"app": row.get("app"), "name": row.get("name"), "enabled": bool(row.get("enabled"))})
        return out

    def for_content(self, content_key: str) -> List[Dict[str, Any]]:
        return self.elsewhere().get(content_key, [])

    def proposals_for(self, content_key: str) -> int:
        return sum(1 for r in self.store.query(C.EXTERNAL_MATCHES, {"state": "proposed", "status": "active"}, limit=50000)
                   if any(c.get("content_key") == content_key for c in r.get("candidates") or []))

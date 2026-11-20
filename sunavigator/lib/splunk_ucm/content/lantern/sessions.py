"""User-directed Splunk Lantern import sessions.

Workflow (docs/OPERATOR_GUIDE.md "Import from Splunk Lantern"):

1. ``inspect``  – the user submits a URL; it is validated and queued.
2. worker       – fetches and classifies the page (article / collection / unsupported)
                  and lists a collection's direct article links. No traversal.
3. ``fetch``    – the user selects articles; the worker extracts and stages them and
                  marks each as new, unchanged or updated (with a field-level diff).
   ``expand``   – optional, explicit: list the articles of selected sub-collections
                  (bounded by ``max_expand_depth``).
4. ``import``   – the user confirms a summary; staged extractions go through the
                  standard validation/normalization/sync path. Updates are applied only
                  when explicitly selected, and never touch customer-owned collections.

Sessions and staged extractions live in ``uc_lantern`` (admin-write only) and are
written with the system token after the REST handler's capability check.
"""

import dataclasses
import time
from typing import Any, Callable, Dict, List, Optional

from ...audit import AuditService
from ...config import AppConfig
from ...errors import ConflictError, NotFoundError, PermissionDenied, UcmError, ValidationError
from ...storage import collections as C
from ...storage.kvstore import DocumentStore
from ...storage.repositories import decode_raw, encode_raw
from ...util import chunked, epoch_now, new_id, utc_now_iso
from ..sync import SyncService, new_job
from ..validation import RecordValidator
from . import parser as P
from .fetcher import FetchSettings, LanternFetcher, LanternFetchError, RateGate
from .normalizer import PROVIDER, content_key, lantern_validation_policy
from .provider import StagedLanternProvider
from .urls import LanternUrlError, validate_url

DOC_SESSION = "session"
DOC_STAGE = "stage"
S_QUEUED = "queued"
S_RUNNING = "running"
S_READY = "ready"
S_FAILED = "failed"

ITEM_LISTED = "listed"
ITEM_QUEUED = "queued"
ITEM_FETCHED = "fetched"
ITEM_EXPANDED = "expanded"
ITEM_ERROR = "error"
ITEM_IMPORTED = "imported"
ITEM_DUPLICATE = "duplicate"

STATUS_NEW = "new"
STATUS_UNCHANGED = "unchanged"
STATUS_UPDATED = "updated"
STATUS_COLLECTION = "collection"

MODE_INSPECT = "inspect"
MODE_ARTICLE = "article"
MODE_EXPAND = "expand"

_SUMMARY_FIELDS = ("session_id", "requested_by", "created_at", "updated_at", "status", "phase", "start_url",
                   "progress", "requests_made", "last_import")


@dataclasses.dataclass
class LanternSettings:
    enabled: bool = True
    remote_fetch_enabled: bool = True
    max_articles_per_fetch: int = 25
    max_items_per_collection: int = 300
    max_session_items: int = 1000
    max_pages_per_session: int = 150
    max_expand_depth: int = 1
    max_expand_per_request: int = 5
    session_ttl_hours: int = 24
    max_active_sessions_per_user: int = 5
    worker_time_budget_seconds: float = 240.0
    fetch: FetchSettings = dataclasses.field(default_factory=FetchSettings)

    def public(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "remote_fetch_enabled": self.remote_fetch_enabled,
                "host": "lantern.splunk.com", "max_articles_per_fetch": self.max_articles_per_fetch,
                "max_items_per_collection": self.max_items_per_collection,
                "max_pages_per_session": self.max_pages_per_session, "max_expand_depth": self.max_expand_depth,
                "min_request_interval_seconds": self.fetch.min_interval,
                "session_ttl_hours": self.session_ttl_hours}


def settings_from_config(config: AppConfig) -> LanternSettings:
    s = "provider:lantern"
    return LanternSettings(
        enabled=config.get_bool(s, "enabled", True),
        remote_fetch_enabled=config.get_bool(s, "remote_fetch_enabled", True),
        max_articles_per_fetch=config.get_int(s, "max_articles_per_fetch", 25, 1, 50),
        max_items_per_collection=config.get_int(s, "max_items_per_collection", 300, 10, 1000),
        max_session_items=config.get_int(s, "max_session_items", 1000, 10, 3000),
        max_pages_per_session=config.get_int(s, "max_pages_per_session", 150, 5, 500),
        max_expand_depth=config.get_int(s, "max_expand_depth", 1, 0, 2),
        session_ttl_hours=config.get_int(s, "session_ttl_hours", 24, 1, 168),
        max_active_sessions_per_user=config.get_int(s, "max_active_sessions_per_user", 5, 1, 20),
        worker_time_budget_seconds=float(config.get_int(s, "worker_time_budget_seconds", 240, 30, 900)),
        fetch=FetchSettings(
            timeout=float(config.get_int(s, "timeout", 15, 3, 60)),
            max_bytes=config.get_int(s, "max_page_kb", 3072, 64, 10240) * 1024,
            max_redirects=config.get_int(s, "max_redirects", 3, 0, 5),
            min_interval=float(config.get_int(s, "min_request_interval_seconds", 5, 5, 60)),
            proxy_url=config.get(s, "proxy_url", "").strip(),
            ca_bundle=config.get(s, "ca_bundle", "").strip()))


def _error(exc: Exception) -> Dict[str, Any]:
    if isinstance(exc, UcmError):
        return {"code": exc.code, "message": exc.message}
    return {"code": "internal_error", "message": "unexpected error: %s" % type(exc).__name__}


class LanternSessionService:
    def __init__(self, store: DocumentStore, audit: AuditService, settings: Optional[LanternSettings] = None,
                 content_store: Optional[DocumentStore] = None, clock: Callable[[], float] = epoch_now,
                 iso_clock: Callable[[], str] = utc_now_iso):
        # ``store`` holds uc_lantern (system token); ``content_store`` reads/writes the catalogue.
        self.store = store
        self.content_store = content_store or store
        self.audit = audit
        self.settings = settings or LanternSettings()
        self.clock = clock
        self.iso_clock = iso_clock

    # -- persistence ----------------------------------------------------------------------------
    @staticmethod
    def _session_key(session_id: str) -> str:
        return "session::" + session_id

    @staticmethod
    def _stage_key(session_id: str, record_id: str) -> str:
        return "stage::%s::%s" % (session_id, record_id)

    def _save(self, session: Dict[str, Any]) -> None:
        session["updated_at"] = self.iso_clock()
        self.store.upsert(C.LANTERN, session)

    def get(self, session_id: str, user: str = "", is_admin: bool = True) -> Dict[str, Any]:
        if not isinstance(session_id, str) or not session_id.isalnum() or len(session_id) > 64:
            raise ValidationError("invalid session id")
        session = self.store.get(C.LANTERN, self._session_key(session_id))
        if not session or session.get("doc_type") != DOC_SESSION:
            raise NotFoundError("import session not found or expired")
        if not is_admin and session.get("requested_by") != user:
            raise PermissionDenied("this import session belongs to another user")
        return session

    def list_sessions(self, user: str, is_admin: bool, limit: int = 20) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"doc_type": DOC_SESSION}
        if not is_admin:
            query = {"$and": [query, {"requested_by": user}]}
        rows = self.store.query(C.LANTERN, query, sort=[("updated_at", -1)], limit=limit)
        out = []
        for row in rows:
            summary = {k: row.get(k) for k in _SUMMARY_FIELDS}
            page = row.get("page") or {}
            summary["page"] = {k: page.get(k) for k in ("kind", "title", "url", "reason")}
            summary["item_count"] = len(row.get("items") or [])
            summary["error_count"] = sum(1 for i in row.get("items") or [] if i.get("state") == ITEM_ERROR)
            out.append(summary)
        return out

    def _existing(self, record_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        found: Dict[str, Dict[str, Any]] = {}
        keys = [content_key(r) for r in record_ids]
        for batch in chunked(keys, 100):
            for doc in self.content_store.query(C.CATALOG, {"_key": {"$in": batch}},
                                                fields=["_key", "source_hash", "provider_status", "title",
                                                        "imported_at"]):
                found[doc["_key"]] = doc
        return found

    def _mark_in_sun(self, items: List[Dict[str, Any]]) -> None:
        existing = self._existing([i["record_id"] for i in items])
        for item in items:
            doc = existing.get(content_key(item["record_id"]))
            item["in_sun"] = doc is not None
            item["sun_hash"] = (doc or {}).get("source_hash", "")
            item["sun_imported_at"] = (doc or {}).get("imported_at", "")

    # -- user actions ---------------------------------------------------------------------------
    def _check_enabled(self) -> None:
        if not self.settings.enabled:
            raise ValidationError("Splunk Lantern import is disabled by the administrator.",
                                  {"reason": "disabled"})
        if not self.settings.remote_fetch_enabled:
            raise ValidationError("Retrieval from Splunk Lantern is disabled on this deployment "
                                  "(provider:lantern remote_fetch_enabled = false).", {"reason": "fetch_disabled"})

    def create(self, user: str, url: str) -> Dict[str, Any]:
        self._check_enabled()
        canonical = validate_url(url)
        active = self.store.query(C.LANTERN, {"$and": [{"doc_type": DOC_SESSION}, {"requested_by": user},
                                                        {"status": {"$in": [S_QUEUED, S_RUNNING]}}]}, limit=50)
        if len(active) >= self.settings.max_active_sessions_per_user:
            raise ConflictError("You already have %d Lantern requests in progress; wait for them to finish."
                                % len(active))
        session_id = new_id()
        now = self.iso_clock()
        session = {
            "_key": self._session_key(session_id), "doc_type": DOC_SESSION, "doc_schema": C.DOC_SCHEMA,
            "session_id": session_id, "requested_by": user, "created_at": now, "updated_at": now,
            "expires_at": self.clock() + self.settings.session_ttl_hours * 3600,
            "status": S_QUEUED, "phase": MODE_INSPECT, "start_url": canonical, "submitted_url": url.strip()[:2048],
            "page": None, "items": [], "pending": [{"url": canonical, "mode": MODE_INSPECT}],
            "progress": {"done": 0, "total": 1, "current": canonical}, "requests_made": 0, "errors": [],
            "last_import": None, "cancel_requested": False,
        }
        self._save(session)
        self.audit.record(user, "content.lantern.inspect_requested", "lantern_session", session_id,
                          details={"url": canonical})
        return session

    def _require_ready(self, session: Dict[str, Any]) -> None:
        if session.get("status") in (S_QUEUED, S_RUNNING):
            raise ConflictError("This session is still working; wait for the current step to finish.")
        if session.get("status") == S_FAILED or not session.get("page"):
            raise ConflictError("This session has no usable page; start a new import.")

    def _budget(self, session: Dict[str, Any], extra: int) -> None:
        if int(session.get("requests_made") or 0) + extra > self.settings.max_pages_per_session:
            raise ValidationError("This would exceed the page limit for one session (%d pages). Import the "
                                  "current selection first or start a new session."
                                  % self.settings.max_pages_per_session, {"reason": "page_limit"})

    def request_fetch(self, user: str, is_admin: bool, session_id: str, urls: List[str]) -> Dict[str, Any]:
        self._check_enabled()
        session = self.get(session_id, user, is_admin)
        self._require_ready(session)
        if not isinstance(urls, list) or not urls:
            raise ValidationError("select at least one article")
        if len(urls) > self.settings.max_articles_per_fetch:
            raise ValidationError("Select at most %d articles per step." % self.settings.max_articles_per_fetch,
                                  {"reason": "too_many"})
        by_url = {i["url"]: i for i in session["items"]}
        pending = []
        for url in urls:
            item = by_url.get(url) if isinstance(url, str) else None
            if item is None:
                raise ValidationError("an article is not part of this session", {"url": str(url)[:200]})
            if item.get("state") in (ITEM_QUEUED,):
                continue
            item["state"] = ITEM_QUEUED
            item.pop("error", None)
            pending.append({"url": url, "mode": MODE_ARTICLE})
        if not pending:
            raise ValidationError("the selected articles are already queued")
        self._budget(session, len(pending))
        session.update({"status": S_QUEUED, "phase": MODE_ARTICLE, "pending": pending, "cancel_requested": False,
                        "progress": {"done": 0, "total": len(pending), "current": pending[0]["url"]}})
        self._save(session)
        self.audit.record(user, "content.lantern.fetch_requested", "lantern_session", session_id,
                          details={"count": len(pending)})
        return session

    def request_expand(self, user: str, is_admin: bool, session_id: str, urls: List[str]) -> Dict[str, Any]:
        self._check_enabled()
        session = self.get(session_id, user, is_admin)
        self._require_ready(session)
        if not isinstance(urls, list) or not urls:
            raise ValidationError("select at least one sub-collection")
        if len(urls) > self.settings.max_expand_per_request:
            raise ValidationError("Expand at most %d sub-collections per step." % self.settings.max_expand_per_request)
        by_url = {i["url"]: i for i in session["items"]}
        pending = []
        for url in urls:
            item = by_url.get(url) if isinstance(url, str) else None
            if item is None:
                raise ValidationError("a sub-collection is not part of this session", {"url": str(url)[:200]})
            if item.get("kind") != P.KIND_COLLECTION and item.get("kind_guess") != P.KIND_COLLECTION:
                raise ValidationError("'%s' is not a collection page" % item.get("title", "")[:80])
            if int(item.get("depth") or 0) >= self.settings.max_expand_depth:
                raise ValidationError("Expanding deeper than %d level(s) is not allowed."
                                      % self.settings.max_expand_depth, {"reason": "depth_limit"})
            item["state"] = ITEM_QUEUED
            pending.append({"url": url, "mode": MODE_EXPAND})
        self._budget(session, len(pending))
        session.update({"status": S_QUEUED, "phase": MODE_EXPAND, "pending": pending, "cancel_requested": False,
                        "progress": {"done": 0, "total": len(pending), "current": pending[0]["url"]}})
        self._save(session)
        self.audit.record(user, "content.lantern.expand_requested", "lantern_session", session_id,
                          details={"urls": [p["url"] for p in pending]})
        return session

    def cancel(self, user: str, is_admin: bool, session_id: str) -> Dict[str, Any]:
        session = self.get(session_id, user, is_admin)
        if session.get("status") == S_QUEUED:
            self._finish_pending(session, cancelled=True)
            session["status"] = S_READY if session.get("page") else S_FAILED
        elif session.get("status") == S_RUNNING:
            session["cancel_requested"] = True
        self._save(session)
        return session

    def discard(self, user: str, is_admin: bool, session_id: str) -> None:
        session = self.get(session_id, user, is_admin)
        self._delete_session(session["session_id"])
        self.audit.record(user, "content.lantern.session_discarded", "lantern_session", session_id)

    def _delete_session(self, session_id: str) -> None:
        self.store.delete_query(C.LANTERN, {"$and": [{"doc_type": DOC_STAGE}, {"session_id": session_id}]})
        self.store.delete(C.LANTERN, self._session_key(session_id))

    def staged(self, user: str, is_admin: bool, session_id: str, url: str) -> Dict[str, Any]:
        session = self.get(session_id, user, is_admin)
        item = next((i for i in session["items"] if i["url"] == url), None)
        if item is None or not item.get("stage_key"):
            raise NotFoundError("no extraction preview is available for this article")
        raw = decode_raw(self.store.get(C.LANTERN, item["stage_key"]))
        if raw is None:
            raise NotFoundError("the extraction preview expired; fetch the article again")
        return {"item": item, "raw": raw}

    # -- worker ---------------------------------------------------------------------------------
    def next_queued(self) -> Optional[Dict[str, Any]]:
        rows = self.store.query(C.LANTERN, {"$and": [{"doc_type": DOC_SESSION}, {"status": S_QUEUED}]},
                                sort=[("updated_at", 1)], limit=1)
        return rows[0] if rows else None

    def recover_interrupted(self, max_age_seconds: float) -> int:
        """Re-queue sessions left ``running`` by a crashed or restarted worker."""
        recovered = 0
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock() - max_age_seconds))
        for row in self.store.query(C.LANTERN, {"$and": [{"doc_type": DOC_SESSION}, {"status": S_RUNNING}]},
                                    limit=20):
            if (row.get("updated_at") or "") < cutoff:
                row["status"] = S_QUEUED
                self._save(row)
                recovered += 1
        return recovered

    def cleanup_expired(self, limit: int = 50) -> int:
        rows = self.store.query(C.LANTERN, {"$and": [{"doc_type": DOC_SESSION},
                                                     {"expires_at": {"$lt": self.clock()}}]}, limit=limit)
        for row in rows:
            self._delete_session(row["session_id"])
        orphans = self.store.query(C.LANTERN, {"$and": [{"doc_type": DOC_STAGE},
                                                        {"expires_at": {"$lt": self.clock()}}]}, limit=limit)
        for row in orphans:
            self.store.delete(C.LANTERN, row["_key"])
        return len(rows)

    def make_fetcher(self) -> LanternFetcher:
        def load_gate() -> float:
            return float((self.store.get(C.LANTERN, "gate") or {}).get("last_request_at") or 0)

        def save_gate(value: float) -> None:
            self.store.upsert(C.LANTERN, {"_key": "gate", "doc_type": "gate", "last_request_at": value})

        def load_robots() -> Optional[Dict[str, Any]]:
            return self.store.get(C.LANTERN, "robots")

        def save_robots(doc: Dict[str, Any]) -> None:
            self.store.upsert(C.LANTERN, dict(doc, _key="robots", doc_type="robots"))

        settings = dataclasses.replace(self.settings.fetch, max_requests=self.settings.max_pages_per_session + 1)
        return LanternFetcher(settings, gate=RateGate(settings.min_interval, load_gate, save_gate),
                              robots_load=load_robots, robots_save=save_robots)

    def process(self, session: Dict[str, Any], fetcher: LanternFetcher,
                monotonic: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
        session["status"] = S_RUNNING
        self._save(session)
        deadline = monotonic() + self.settings.worker_time_budget_seconds
        before = fetcher.requests_made
        while session.get("pending"):
            fresh = self.store.get(C.LANTERN, session["_key"])
            if fresh is None:
                return {"session_id": session["session_id"], "status": "discarded"}
            if fresh.get("cancel_requested"):
                self._finish_pending(session, cancelled=True)
                break
            if monotonic() > deadline:
                break
            entry = session["pending"][0]
            session["progress"]["current"] = entry["url"]
            try:
                if entry["mode"] == MODE_INSPECT:
                    self._inspect(session, entry["url"], fetcher)
                elif entry["mode"] == MODE_ARTICLE:
                    self._fetch_article(session, entry["url"], fetcher)
                else:
                    self._expand(session, entry["url"], fetcher)
            except (LanternFetchError, LanternUrlError, ValidationError) as exc:
                self._entry_failed(session, entry, _error(exc))
            except Exception as exc:  # parser bugs must not wedge the session
                self._entry_failed(session, entry, {"code": "lantern_parse_failed",
                                                    "message": "The page could not be processed (%s)."
                                                               % type(exc).__name__})
            session["pending"].pop(0)
            session["progress"]["done"] = int(session["progress"].get("done") or 0) + 1
            session["requests_made"] = int(session.get("requests_made") or 0) + (fetcher.requests_made - before)
            before = fetcher.requests_made
            self._save(session)
        if session.get("pending"):
            session["status"] = S_QUEUED
        elif session.get("page"):
            session["status"] = S_READY
        else:
            session["status"] = S_FAILED
        session["cancel_requested"] = False
        self._save(session)
        return {"session_id": session["session_id"], "status": session["status"],
                "requests": session.get("requests_made")}

    def _finish_pending(self, session: Dict[str, Any], cancelled: bool) -> None:
        queued = {p["url"] for p in session.get("pending") or []}
        for item in session.get("items") or []:
            if item["url"] in queued and item.get("state") == ITEM_QUEUED:
                item["state"] = ITEM_FETCHED if item.get("status") else ITEM_LISTED
        session["pending"] = []
        if cancelled:
            session.setdefault("errors", []).append({"code": "cancelled", "message": "Cancelled by the user.",
                                                     "at": self.iso_clock()})

    def _entry_failed(self, session: Dict[str, Any], entry: Dict[str, Any], error: Dict[str, Any]) -> None:
        error = dict(error, url=entry["url"], at=self.iso_clock())
        session.setdefault("errors", []).append(error)
        session["errors"] = session["errors"][-50:]
        if entry["mode"] == MODE_INSPECT:
            session["page"] = None
            session["inspect_error"] = error
            return
        for item in session["items"]:
            if item["url"] == entry["url"]:
                item["state"] = ITEM_ERROR
                item["error"] = {"code": error["code"], "message": error["message"]}

    def _retrieve(self, url: str, fetcher: LanternFetcher):
        result = fetcher.fetch_page(url)
        page, classification = P.parse(result.text, result.url)
        return result, page, classification

    def _stage(self, session: Dict[str, Any], raw: Dict[str, Any]) -> str:
        key = self._stage_key(session["session_id"], raw["id"])
        self.store.upsert(C.LANTERN, {
            "_key": key, "doc_type": DOC_STAGE, "session_id": session["session_id"], "record_id": raw["id"],
            "url": raw["source_url"], "raw_json": encode_raw(raw), "raw_size": len(encode_raw(raw)),
            "content_hash": raw["content_hash"], "created_at": self.iso_clock(),
            "expires_at": session.get("expires_at", self.clock() + 86400)})
        return key

    def _new_item(self, entry: Dict[str, Any], depth: int, parent_url: str) -> Dict[str, Any]:
        item = dict(entry)
        item.update({"depth": depth, "parent_url": parent_url, "state": ITEM_LISTED, "kind": "", "status": "",
                     "in_sun": False, "sun_hash": "", "extraction": None, "changes": [], "stage_key": ""})
        return item

    def _apply_article(self, session: Dict[str, Any], item: Dict[str, Any], page: P.ParsedPage) -> None:
        raw = P.extract_article(page, self.iso_clock())
        duplicate = next((other for other in session["items"]
                          if other is not item and other.get("record_id") == raw["id"]
                          and other.get("state") in (ITEM_FETCHED, ITEM_IMPORTED)), None)
        item["url"], item["record_id"] = raw["source_url"], raw["id"]
        item["kind"] = P.KIND_ARTICLE
        if duplicate is not None:
            item["state"] = ITEM_DUPLICATE
            item["duplicate_of"] = duplicate["url"]
            return
        existing = self._existing([raw["id"]]).get(content_key(raw["id"]))
        item["in_sun"] = existing is not None
        item["sun_hash"] = (existing or {}).get("source_hash", "")
        item["sun_imported_at"] = (existing or {}).get("imported_at", "")
        if existing is None:
            item["status"] = STATUS_NEW
            item["changes"] = []
        elif existing.get("source_hash") == raw["content_hash"]:
            item["status"] = STATUS_UNCHANGED
            item["changes"] = []
        else:
            item["status"] = STATUS_UPDATED
            stored = decode_raw(self.content_store.get(C.CONTENT, content_key(raw["id"])))
            item["changes"] = P.diff_articles(stored, raw)
        item["extraction"] = P.article_summary(raw)
        item["title"] = raw["title"] or item.get("title", "")
        item["stage_key"] = self._stage(session, raw)
        item["state"] = ITEM_FETCHED

    def _inspect(self, session: Dict[str, Any], url: str, fetcher: LanternFetcher) -> None:
        result, page, classification = self._retrieve(url, fetcher)
        meta = page.meta
        session["page"] = {
            "kind": classification.kind, "reason": classification.reason, "signals": classification.signals,
            "page_type": meta.page_type, "title": meta.title, "url": meta.canonical_url, "requested_url": url,
            "redirects": result.redirects, "description": meta.description[:1000],
            "breadcrumbs": meta.breadcrumbs, "categories": [], "skipped": {}, "truncated": False, "empty": False,
        }
        session.pop("inspect_error", None)
        if classification.kind == P.KIND_ARTICLE:
            item = self._new_item({"url": meta.canonical_url, "record_id": "", "title": meta.title,
                                   "category": (meta.breadcrumbs[-1]["title"] if meta.breadcrumbs else ""),
                                   "subcategory": "", "kind_guess": P.KIND_ARTICLE, "role": "direct",
                                   "description": meta.description[:1000], "also_in": [], "position": 0}, 0, "")
            session["items"] = [item]
            self._apply_article(session, item, page)
        elif classification.kind == P.KIND_COLLECTION:
            collection = P.parse_collection(page, self.settings.max_items_per_collection)
            session["items"] = [self._new_item(i, 0, meta.canonical_url) for i in collection.items]
            self._mark_in_sun(session["items"])
            session["page"].update({"categories": collection.categories, "skipped": collection.skipped,
                                    "truncated": collection.truncated, "empty": not collection.items})

    def _fetch_article(self, session: Dict[str, Any], url: str, fetcher: LanternFetcher) -> None:
        item = next(i for i in session["items"] if i["url"] == url)
        _result, page, classification = self._retrieve(url, fetcher)
        if classification.kind == P.KIND_ARTICLE:
            self._apply_article(session, item, page)
        elif classification.kind == P.KIND_COLLECTION:
            collection = P.parse_collection(page, self.settings.max_items_per_collection)
            item.update({"kind": P.KIND_COLLECTION, "status": STATUS_COLLECTION, "state": ITEM_FETCHED,
                         "child_count": len(collection.items), "title": page.meta.title or item.get("title", "")})
        else:
            item["state"] = ITEM_ERROR
            item["kind"] = P.KIND_UNSUPPORTED
            item["error"] = {"code": "lantern_unsupported_page", "message": classification.reason}

    def _expand(self, session: Dict[str, Any], url: str, fetcher: LanternFetcher) -> None:
        parent = next(i for i in session["items"] if i["url"] == url)
        _result, page, classification = self._retrieve(url, fetcher)
        if classification.kind != P.KIND_COLLECTION:
            if classification.kind == P.KIND_ARTICLE:
                self._apply_article(session, parent, page)
                return
            raise ValidationError(classification.reason or "The page is not a collection.")
        collection = P.parse_collection(page, self.settings.max_items_per_collection)
        index = {i["url"]: i for i in session["items"]}
        added: List[Dict[str, Any]] = []
        for child in collection.items:
            place = {"category": child["category"], "subcategory": child["subcategory"]}
            if child["url"] in index:
                existing = index[child["url"]]
                if place not in existing["also_in"]:
                    existing["also_in"].append(place)
                continue
            if len(session["items"]) + len(added) >= self.settings.max_session_items:
                session["page"]["truncated"] = True
                break
            added.append(self._new_item(child, int(parent.get("depth") or 0) + 1, parent["url"]))
        self._mark_in_sun(added)
        session["items"].extend(added)
        parent.update({"kind": P.KIND_COLLECTION, "status": STATUS_COLLECTION, "state": ITEM_EXPANDED,
                       "child_count": len(collection.items), "title": page.meta.title or parent.get("title", "")})

    # -- import ---------------------------------------------------------------------------------
    def import_items(self, user: str, is_admin: bool, session_id: str, selections: List[Dict[str, Any]],
                     confirm: bool, sync: SyncService) -> Dict[str, Any]:
        if confirm is not True:
            raise ValidationError("Import requires explicit confirmation.", {"reason": "not_confirmed"})
        session = self.get(session_id, user, is_admin)
        self._require_ready(session)
        if not isinstance(selections, list) or not selections:
            raise ValidationError("select at least one article to import")
        by_url = {i["url"]: i for i in session["items"]}
        outcomes: List[Dict[str, Any]] = []
        chosen: List[Dict[str, Any]] = []
        for sel in selections:
            url = sel.get("url") if isinstance(sel, dict) else None
            action = sel.get("action", "import") if isinstance(sel, dict) else ""
            item = by_url.get(url) if isinstance(url, str) else None
            if item is None:
                raise ValidationError("an article is not part of this session", {"url": str(url)[:200]})
            outcome = {"url": url, "title": item.get("title", ""), "record_id": item.get("record_id", "")}
            if item.get("state") != ITEM_FETCHED or item.get("kind") != P.KIND_ARTICLE:
                outcomes.append(dict(outcome, outcome="skipped", reason="not_fetched",
                                     message="Fetch and preview the article before importing it."))
                continue
            status = item.get("status")
            if status == STATUS_UNCHANGED:
                outcomes.append(dict(outcome, outcome="skipped", reason="unchanged",
                                     message="Already in SUN and unchanged."))
                continue
            if status == STATUS_UPDATED and action != "update":
                outcomes.append(dict(outcome, outcome="skipped", reason="update_not_confirmed",
                                     message="Already in SUN with different content; select 'update' to apply."))
                continue
            chosen.append(item)
        current = self._existing([i["record_id"] for i in chosen])
        raws: List[Dict[str, Any]] = []
        validator = RecordValidator(lantern_validation_policy())
        found_in = {"url": (session.get("page") or {}).get("url", ""),
                    "title": (session.get("page") or {}).get("title", "")}
        for item in chosen:
            outcome = {"url": item["url"], "title": item.get("title", ""), "record_id": item["record_id"]}
            doc = current.get(content_key(item["record_id"]))
            now_hash = (doc or {}).get("source_hash", "")
            if now_hash != (item.get("sun_hash") or ""):
                if now_hash == (item.get("extraction") or {}).get("content_hash"):
                    item["state"] = ITEM_IMPORTED
                    outcomes.append(dict(outcome, outcome="skipped", reason="already_imported",
                                         message="Another import already applied this version."))
                else:
                    outcomes.append(dict(outcome, outcome="conflict", reason="update_conflict",
                                         message="The article changed in SUN after the preview; fetch it again "
                                                 "to review the latest differences."))
                continue
            raw = decode_raw(self.store.get(C.LANTERN, item.get("stage_key", "")))
            expected = (item.get("extraction") or {}).get("content_hash")
            if raw is None or raw.get("content_hash") != expected or P.content_hash(raw) != expected:
                outcomes.append(dict(outcome, outcome="failed", reason="stage_missing",
                                     message="The staged extraction is missing or does not match the preview; "
                                             "fetch the article again."))
                continue
            vres = validator.validate(raw, len(encode_raw(raw)))
            if not vres.ok:
                outcomes.append(dict(outcome, outcome="failed", reason="invalid",
                                     message="; ".join(f.message for f in vres.errors[:3])))
                continue
            raw["import"] = {"imported_by": user, "imported_at": self.iso_clock(), "session_id": session_id,
                             "found_in": [dict(found_in, category=item.get("category", ""),
                                               subcategory=item.get("subcategory", ""))]
                             + [dict(found_in, **p) for p in item.get("also_in", [])][:10]}
            raws.append(raw)

        job: Optional[Dict[str, Any]] = None
        if raws:
            provider = StagedLanternProvider(raws, session_id)
            manifest_categories = [c.category_id for c in provider.get_manifest().categories]
            job = new_job(user, PROVIDER, manifest_categories, ref=session_id, source="lantern_import")
            job["status"] = "running"
            try:
                sync.enqueue(job)
            except ValidationError as exc:
                raise ConflictError("Another Lantern import is running; try again in a moment.",
                                    {"detail": exc.message})
            job = sync.run(job, provider)
            failures: Dict[str, str] = {}
            for result in job.get("results") or []:
                for err in result.get("errors") or []:
                    rid = err.get("record_id")
                    if rid:
                        failures[rid] = "; ".join(e.get("message", "") for e in err.get("errors") or []) \
                            or err.get("message", "")
                    elif result.get("status") == "failed":
                        for raw in raws:
                            failures.setdefault(raw["id"], err.get("message", "category import failed"))
            stored = self._existing([r["id"] for r in raws])
            for raw in raws:
                item = next(i for i in chosen if i["record_id"] == raw["id"])
                outcome = {"url": item["url"], "title": item.get("title", ""), "record_id": raw["id"]}
                doc = stored.get(content_key(raw["id"]))
                if doc and doc.get("source_hash") == raw["content_hash"] and raw["id"] not in failures:
                    action = "updated" if item.get("status") == STATUS_UPDATED else "imported"
                    item.update({"state": ITEM_IMPORTED, "in_sun": True, "sun_hash": raw["content_hash"],
                                 "import_action": action, "status": STATUS_UNCHANGED})
                    outcomes.append(dict(outcome, outcome=action, content_id="%s:%s" % (PROVIDER, raw["id"])))
                else:
                    outcomes.append(dict(outcome, outcome="failed", reason="import_failed",
                                         message=failures.get(raw["id"], "The import did not store the article.")))
        counts: Dict[str, int] = {"selected": len(selections)}
        for out in outcomes:
            counts[out["outcome"]] = counts.get(out["outcome"], 0) + 1
        session["last_import"] = {"at": self.iso_clock(), "by": user, "job_id": (job or {}).get("job_id", ""),
                                  "job_status": (job or {}).get("status", "not_run"), "counts": counts,
                                  "results": outcomes[:200]}
        self._save(session)
        self.audit.record(user, "content.lantern.imported", "lantern_session", session_id,
                          outcome="success" if not counts.get("failed") and not counts.get("conflict") else "partial",
                          details={"counts": counts, "job_id": (job or {}).get("job_id", ""),
                                   "urls": [o["url"] for o in outcomes if o["outcome"] in ("imported", "updated")][:20]})
        return {"session": session, "result": session["last_import"]}


def preview_usecase(raw: Dict[str, Any]) -> Dict[str, Any]:
    """The canonical use case an import would create, without writing anything."""
    provider = StagedLanternProvider([raw], "preview")
    manifest = provider.get_manifest()
    pcat = manifest.categories[0]
    normalizer = provider.normalizer()
    category = normalizer.normalize_category(pcat, PROVIDER)
    uc = normalizer.normalize(provider.get_use_case(manifest, raw["id"]), category, manifest, "")
    data = dataclasses.asdict(uc)
    data.pop("provider_extras", None)
    return data


class LanternWorker:
    """Background retrieval for Lantern sessions (the only code path that contacts Lantern)."""

    def __init__(self, store: DocumentStore, config: AppConfig, is_leader: Callable[[], Optional[bool]],
                 fetcher_factory: Optional[Callable[[LanternSessionService], LanternFetcher]] = None):
        self.store = store
        self.config = config
        self.is_leader = is_leader
        self.service = LanternSessionService(store, AuditService(store), settings_from_config(config))
        self.fetcher_factory = fetcher_factory or (lambda svc: svc.make_fetcher())

    def run_once(self) -> Dict[str, Any]:
        if self.is_leader() is False:
            return {"action": "skipped", "reason": "not_shc_captain"}
        self.service.recover_interrupted(self.service.settings.worker_time_budget_seconds * 3)
        self.service.cleanup_expired()
        session = self.service.next_queued()
        if session is None:
            return {"action": "idle"}
        result = self.service.process(session, self.fetcher_factory(self.service))
        return dict(result, action="ran")

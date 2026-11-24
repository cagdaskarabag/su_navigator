"""Parse imported SPL, run a bounded preview, and sample required fields.

Imported SPL is never dispatched unless the user requests a preview *and* the
search has no side-effect commands. Field sampling uses a constructed
``search index=… sourcetype=… | head N | fieldsummary`` — not the imported
pipeline (docs/DECISIONS.md D-026, D-027).
"""

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import APP_NAME
from ..audit import AuditService
from ..catalog.detail import key_from_id
from ..content.reindex import StoredNormalizer
from ..content.requirements import INTRINSIC_FIELDS
from ..discovery.spl import RELATIVE_TIME, validate_index_name
from ..errors import NotFoundError, UnsupportedOperation, ValidationError
from ..model.canonical import UseCase
from ..platform.search import SearchClient
from ..readiness.principal import scan_spl
from ..readiness.service import ReadinessService
from ..spl.analysis import analyze
from ..spl.lint import lint_search
from ..spl.parser import high_cost, parse
from ..spl.policy import classify, command_exists, expanded_pipeline
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..storage.repositories import CategoryRepository, ContentRepository
from ..util import utc_now_iso

_SOURCETYPE = re.compile(r"^[\w:.\-]{1,100}$")
_FIELD = re.compile(r"^[\w.\-]{1,100}$")
SAMPLE_MARKER = "sun_sample_marker"


def _review_hint(doc: Dict[str, Any]) -> str:
    """Only unknown commands can be trusted through ``extra_safe_commands``; indirect ones never can."""
    if doc["indirect_commands"] and doc["unknown_commands"]:
        return ("indirect commands (%s) are never previewed and cannot be allowed in ucm.conf; list trusted "
                "read-only add-on commands (%s) in [spl] extra_safe_commands"
                % (", ".join(doc["indirect_commands"]), ", ".join(doc["unknown_commands"])))
    if doc["indirect_commands"]:
        return ("indirect commands run SPL or reach data the search text does not show, so they are never "
                "previewed and cannot be allowed in ucm.conf; an approver can still acknowledge them at deployment")
    return "review the SPL, or list trusted read-only commands in ucm.conf [spl] extra_safe_commands"

class ValidationSettings:
    def __init__(self, earliest: str = "-15m", latest: str = "now", preview_max: int = 50,
                 preview_timeout: int = 30, sample_events: int = 200, sample_timeout: int = 30,
                 max_pairs: int = 3, extra_safe_commands: Sequence[str] = (),
                 sample_window_minutes: int = 60):
        self.extra_safe_commands = tuple(extra_safe_commands)
        self.sample_window_minutes = sample_window_minutes
        self.earliest = earliest
        self.latest = latest
        self.preview_max = preview_max
        self.preview_timeout = preview_timeout
        self.sample_events = sample_events
        self.sample_timeout = sample_timeout
        self.max_pairs = max_pairs


def _count(row: Dict[str, Any]) -> int:
    try:
        return int(float(row.get("count") or 0))
    except (TypeError, ValueError):
        return 0


def _time(value: str, name: str) -> str:
    text = (value or "").strip()
    if not RELATIVE_TIME.match(text):
        raise ValidationError("invalid %s" % name)
    return text


class ValidationService:
    def __init__(self, store: DocumentStore, audit: AuditService, search: SearchClient,
                 settings: Optional[ValidationSettings] = None,
                 readiness: Optional[ReadinessService] = None):
        self.store = store
        self.audit = audit
        self.search = search
        self.settings = settings or ValidationSettings()
        self.readiness = readiness
        self.content = ContentRepository(store)
        self.categories = CategoryRepository(store)

    def get(self, content_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(C.VALIDATION, key_from_id(content_id))

    def parse_only(self, use_case_id: str, actor: str) -> Dict[str, Any]:
        uc = self._load(use_case_id)
        doc = self._parse_use_case(uc)
        self._save(doc, actor, "validation.parsed")
        return doc

    def preview(self, use_case_id: str, actor: str, earliest: str = "", latest: str = "") -> Dict[str, Any]:
        uc = self._load(use_case_id)
        doc = self._parse_use_case(uc)
        if not uc.spl:
            raise ValidationError("this use case has no primary SPL to preview")
        if doc["side_effects"]:
            raise ValidationError(
                "preview refused: search contains side-effect commands (%s)"
                % ", ".join(doc["side_effects"]),
                {"commands": doc["side_effects"]})
        if not doc["parse_ok"]:
            raise ValidationError("preview refused: Splunk could not parse the search",
                                  {"error": doc.get("parse_error")})
        if doc["review_commands"]:
            raise ValidationError(
                "preview refused: search runs commands SUN cannot verify as read-only (%s); %s"
                % (", ".join(doc["review_commands"]), _review_hint(doc)),
                {"code": "review_commands", "indirect": doc["indirect_commands"],
                 "unknown": doc["unknown_commands"]})
        earliest = _time(earliest or self.settings.earliest, "earliest")
        latest = _time(latest or self.settings.latest, "latest")
        from ..spl.parser import parser_candidates
        to_run = (doc.get("normalized") or parser_candidates(uc.spl)[0])
        try:
            result = self.search.preview(
                to_run, timeout=float(self.settings.preview_timeout),
                max_count=self.settings.preview_max, earliest=earliest, latest=latest, app=APP_NAME)
        except UnsupportedOperation as exc:
            doc["preview"] = {
                "ran_at": utc_now_iso(), "ok": False, "event_count": 0, "truncated": False,
                "fields": [], "earliest": earliest, "latest": latest,
                "error": exc.message[:500], "messages": (exc.details or {}).get("messages") or [],
            }
            self._save(doc, actor, "validation.previewed")
            return doc
        fields = []
        if result.rows:
            fields = sorted(k for k in result.rows[0].keys() if k and not k.startswith("$"))[:80]
        doc["preview"] = {
            "ran_at": utc_now_iso(), "ok": True, "event_count": len(result.rows),
            "truncated": result.truncated, "fields": fields,
            "earliest": earliest, "latest": latest,
            "messages": [m.get("text") for m in result.messages][:5],
        }
        self._save(doc, actor, "validation.previewed")
        return doc

    def sample_and_assess(self, use_case_id: str, actor: str) -> Dict[str, Any]:
        uc = self._load(use_case_id)
        doc = self._parse_use_case(uc)
        fields = [r.value for r in uc.requirements if r.type == "field" and _FIELD.match(r.value)
                  and r.value not in INTRINSIC_FIELDS and not r.attributes.get("derived_in_spl")]
        sourcetypes = [r.value for r in uc.requirements if r.type == "sourcetype"]
        doc["field_samples"] = self._sample(fields, sourcetypes) if fields else []
        doc["sampled_at"] = utc_now_iso()
        self._save(doc, actor, "validation.sampled")
        assessed = None
        if self.readiness is not None:
            try:
                assessed = self.readiness.assess_one(uc.content_id, actor)
            except ValidationError:
                assessed = None
        doc["readiness_state"] = None if assessed is None else assessed.get("state")
        doc["readiness_score"] = None if assessed is None else assessed.get("score")
        return doc

    def _parse_use_case(self, uc: UseCase) -> Dict[str, Any]:
        previous = self.store.get(C.VALIDATION, uc.key) or {}
        doc = {
            "_key": uc.key, "doc_schema": DOC_SCHEMA, "content_id": uc.content_id,
            "source_hash": uc.provenance.source_hash, "parsed_at": utc_now_iso(),
            "parse_ok": False, "parse_error": "", "commands": [], "side_effects": [],
            "indirect_commands": [], "unknown_commands": [], "review_commands": [],
            "high_cost": [], "warnings": [], "cim_parse_ok": None, "cim_parse_error": "",
            "access_scan": None, "lint": [], "preview": previous.get("preview"), "field_samples": previous.get("field_samples") or [],
            "sampled_at": previous.get("sampled_at"), "normalized": "",
        }
        if not uc.spl:
            doc["parse_error"] = "no primary SPL"
            doc["warnings"] = ["provider record has no SPL"]
            return doc
        static = analyze(uc.spl)
        doc["warnings"] = list(static.warnings)
        doc["lint"] = lint_search(uc.spl, uc.cim_spl)
        try:
            parsed = parse(self.search, uc.spl, app=APP_NAME)
        except (UnsupportedOperation, ValidationError) as exc:
            doc["parse_error"] = str(exc)
            self._apply_policy(doc, uc.spl, None)
            return doc
        doc["commands"] = parsed.commands
        doc["access_scan"] = scan_spl(uc.spl, expanded_pipeline(parsed) if parsed.ok else "")
        self._apply_policy(doc, uc.spl, parsed)
        doc["high_cost"] = high_cost(parsed.commands)
        if parsed.ok:
            doc["parse_ok"] = True
            doc["normalized"] = parsed.normalized or ""
        else:
            doc["parse_error"] = (parsed.errors[0] if parsed.errors else "parse failed")[:500]
        if uc.cim_spl:
            try:
                cim = parse(self.search, uc.cim_spl, app=APP_NAME)
                doc["cim_parse_ok"] = cim.ok
                if not cim.ok:
                    doc["cim_parse_error"] = (cim.errors[0] if cim.errors else "parse failed")[:500]
            except (UnsupportedOperation, ValidationError) as exc:
                doc["cim_parse_ok"] = False
                doc["cim_parse_error"] = str(exc)
        if doc["side_effects"]:
            doc["warnings"].append("side-effect commands: " + ", ".join(doc["side_effects"]))
        if doc["review_commands"]:
            doc["warnings"].append("commands needing review: " + ", ".join(doc["review_commands"]))
        return doc

    def _apply_policy(self, doc: Dict[str, Any], spl: str, parsed) -> None:
        policy = classify(spl, parsed, self.settings.extra_safe_commands,
                          exists=lambda name: command_exists(self.search, name, APP_NAME))
        doc["side_effects"] = policy.side_effects
        doc["indirect_commands"] = policy.indirect
        doc["unknown_commands"] = policy.unknown
        doc["review_commands"] = policy.review

    def _window(self, last_time: Any) -> Tuple[str, str]:
        """Sample the hour (``sample_window_minutes``) before the pair's newest event seen by
        discovery, so idle sourcetypes are sampled where their events are."""
        try:
            last = int(last_time)
        except (TypeError, ValueError):
            return self.settings.earliest, self.settings.latest
        return str(last - self.settings.sample_window_minutes * 60), str(last + 1)

    def _sample(self, fields: List[str], sourcetypes: List[str]) -> List[Dict[str, Any]]:
        fields = [f for f in fields if _FIELD.match(f) and f != SAMPLE_MARKER]
        pairs: List[Tuple[str, str, Any]] = []
        for st in sourcetypes:
            if not _SOURCETYPE.match(st):
                continue
            for row in self.store.query(
                    C.ENVIRONMENT_SOURCES,
                    {"kind": "pair", "status": "active", "sourcetype": st},
                    sort=[("window_count", -1)], limit=self.settings.max_pairs,
                    fields=["index", "sourcetype", "last_time"]):
                idx = row.get("index") or ""
                try:
                    validate_index_name(idx)
                except ValidationError:
                    continue
                pairs.append((idx, st, row.get("last_time")))
            if len(pairs) >= self.settings.max_pairs:
                break
        if not pairs:
            return [{"field": f, "present": False, "sampled": False, "reason": "no_active_sourcetype"}
                    for f in fields]
        counts: Dict[str, int] = {f: 0 for f in fields}
        observed: Dict[str, Dict[str, Any]] = {}
        complete = truncated = empty = 0
        wanted = " ".join('"%s"' % f for f in fields)
        for index, st, last_time in pairs[: self.settings.max_pairs]:
            spl = '| search index=%s sourcetype="%s" | head %d | eval %s=1 | fields %s %s | fieldsummary maxvals=1' % (
                index, st.replace('"', ""), self.settings.sample_events, SAMPLE_MARKER, SAMPLE_MARKER, wanted)
            earliest, latest = self._window(last_time)
            try:
                result = self.search.oneshot(
                    spl, timeout=float(self.settings.sample_timeout), max_count=len(fields) + 2,
                    earliest=earliest, latest=latest)
            except (UnsupportedOperation, ValidationError):
                continue
            events = sum(_count(r) for r in result.rows if r.get("field") == SAMPLE_MARKER)
            if result.truncated:
                truncated += 1
            elif events == 0:
                empty += 1
                continue
            else:
                complete += 1
            for row in result.rows:
                name = str(row.get("field") or "")
                if name not in counts:
                    continue
                n = _count(row)
                counts[name] += n
                # Event values are not kept: uc_validation is readable by every app user (D-044).
                if n and name not in observed:
                    observed[name] = {"index": index, "sourcetype": st, "count": n}
        out = []
        for f in fields:
            hit = observed.get(f)
            if counts[f] == 0 and not complete:
                # Only a complete sample that held events can show a field is absent.
                reason = "sample_truncated" if truncated else ("sample_empty" if empty else "sample_failed")
                out.append({"field": f, "present": False, "sampled": False, "reason": reason})
                continue
            out.append({
                "field": f, "present": counts[f] > 0, "sampled": True, "count": counts[f],
                "index": None if not hit else hit["index"],
                "sourcetype": None if not hit else hit["sourcetype"],
            })
        return out

    def _load(self, use_case_id: str) -> UseCase:
        key = key_from_id(use_case_id)
        stored = self.content.get_content(key)
        if not stored:
            raise NotFoundError("use case not found", {"id": use_case_id})
        uc = StoredNormalizer(self.categories).normalize(stored)
        if uc is None:
            raise NotFoundError("stored content for this use case is unreadable")
        return uc

    def _save(self, doc: Dict[str, Any], actor: str, action: str) -> None:
        self.store.upsert(C.VALIDATION, doc)
        self.audit.record(actor, action, "validation", doc["content_id"],
                          details={"parse_ok": doc.get("parse_ok"),
                                   "side_effects": doc.get("side_effects"),
                                   "sampled": bool(doc.get("sampled_at"))})

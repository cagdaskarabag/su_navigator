"""Run a bounded environment-discovery job and persist the inventory."""

import dataclasses
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..audit import AuditService
from ..errors import UcmError, ValidationError
from ..log import get_logger
from ..platform.search import SearchClient
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..util import epoch_now, new_id, utc_now_iso
from .inventory import SplunkInventory
from .keys import source_key
from .mapping import MappingService
from .populated import WINDOW, PopulatedSettings, check_models, summarize
from .profile import ProfileSettings, run_profile
from .repositories import DiscoveryStateRepository, SourceRepository
from .spl import chunk_indexes, tstats_future, tstats_searches, tstats_volume, validate_index_name, validate_time

log = get_logger(__name__)

JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_PARTIAL, JOB_FAILED = (
    "queued", "running", "succeeded", "partial", "failed")

ADDON_HINTS = ("TA-", "TA_", "Splunk_TA_", "Splunk_SA_", "SA-")


@dataclasses.dataclass
class DiscoverySettings:
    earliest: str = "-7d"
    latest: str = "now"
    include_internal: bool = False
    max_pairs: int = 5000
    search_timeout: int = 120
    job_timeout_seconds: int = 600
    freshness_days: int = 30
    profile: ProfileSettings = dataclasses.field(default_factory=ProfileSettings)
    populated: PopulatedSettings = dataclasses.field(default_factory=PopulatedSettings)


def new_job(requested_by: str, include_internal: Optional[bool] = None, earliest: str = "",
            latest: str = "", source: str = "manual") -> Dict[str, Any]:
    job_id = new_id()
    return {
        "_key": "djob::" + job_id, "doc_type": "discovery_job", "doc_schema": DOC_SCHEMA,
        "job_id": job_id, "source": source, "status": JOB_QUEUED, "requested_by": requested_by,
        "requested_at": utc_now_iso(),
        "include_internal": include_internal, "earliest": earliest, "latest": latest,
        "results": {}, "errors": [], "totals": {},
    }


class DiscoveryService:
    def __init__(self, store: DocumentStore, audit: AuditService, inventory: SplunkInventory,
                 search: SearchClient, settings: Optional[DiscoverySettings] = None,
                 clock: Callable[[], str] = utc_now_iso, now_epoch: Callable[[], float] = epoch_now):
        self.store = store
        self.audit = audit
        self.inventory = inventory
        self.search = search
        self.settings = settings or DiscoverySettings()
        self.clock = clock
        self.now_epoch = now_epoch
        self.sources = SourceRepository(store)
        self.state = DiscoveryStateRepository(store)
        self.mappings = MappingService(store)

    def enqueue(self, job: Dict[str, Any]) -> Dict[str, Any]:
        active = self.state.jobs(JOB_QUEUED, limit=5) + self.state.jobs(JOB_RUNNING, limit=5)
        if active:
            raise ValidationError("a discovery job is already queued or running",
                                  {"job_id": active[0].get("job_id")})
        self.state.save_job(job)
        self.audit.record(job["requested_by"], "discovery.requested", "discovery_job", job["job_id"],
                          details={"include_internal": job.get("include_internal"),
                                   "earliest": job.get("earliest"), "source": job["source"]})
        return job

    def run(self, job: Dict[str, Any]) -> Dict[str, Any]:
        job["status"] = JOB_RUNNING
        job["started_at"] = self.clock()
        self.state.save_job(job)
        try:
            self._run(job)
        except UcmError as exc:
            job["status"] = JOB_FAILED
            job["errors"].append(exc.to_dict())
            log.warning("discovery failed", extra={"job_id": job["job_id"], "code": exc.code})
        except Exception as exc:
            job["status"] = JOB_FAILED
            job["errors"].append({"code": "internal_error", "message": str(exc)})
            log.exception("discovery crashed", extra={"job_id": job["job_id"]})
        job["finished_at"] = self.clock()
        self.state.save_job(job)
        self.state.prune()
        self.audit.record(job["requested_by"], "discovery.completed", "discovery_job", job["job_id"],
                          outcome=job["status"],
                          details={"totals": job.get("totals"), "errors": job["errors"][:5]})
        return job

    def _run(self, job: Dict[str, Any]) -> None:
        include_internal = self.settings.include_internal if job.get("include_internal") is None \
            else bool(job.get("include_internal"))
        earliest = validate_time(job.get("earliest") or self.settings.earliest, "earliest")
        latest = validate_time(job.get("latest") or self.settings.latest, "latest")
        job.update({"include_internal": include_internal, "earliest": earliest, "latest": latest})

        indexes = self.inventory.list_indexes()
        apps = self.inventory.list_apps()
        models = self.inventory.list_datamodels()
        knowledge = self.inventory.list_knowledge_objects()
        version = self.inventory.server_version()

        eligible = [i for i in indexes if _index_eligible(i, include_internal)]
        event_indexes = [i["name"] for i in eligible if i.get("datatype") != "metric"]
        for name in event_indexes:
            validate_index_name(name)

        pairs, truncated, search_errors, searched = self._tstats(event_indexes, earliest, latest)
        freshness = self._freshness(event_indexes, pairs, searched)
        profile = self._profile(job["job_id"])
        populated = check_models(self.search, models, self._referenced_models(), self.settings.populated)
        imported = utc_now_iso()
        now = self.now_epoch()

        docs: List[Dict[str, Any]] = []
        docs.extend(_index_docs(indexes, pairs, now, imported, job["job_id"]))
        docs.extend(_pair_docs(pairs, now, imported, job["job_id"]))
        docs.extend(_app_docs(apps, imported, job["job_id"]))
        docs.extend(_model_docs(models, imported, job["job_id"], populated))
        docs.extend(_knowledge_docs(knowledge, imported, job["job_id"]))
        self.sources.save(docs)

        kept = {d["_key"] for d in docs}
        gone = []
        for row in self.sources.list_active():
            if row["_key"] in kept:
                continue
            # A pair is only "missing" if its index was actually searched and
            # the result set was complete; otherwise absence proves nothing.
            if row.get("kind") == "pair" and (truncated or row.get("index") not in searched):
                continue
            gone.append(row["_key"])
        missing = self.sources.mark_missing(gone, imported) if gone else 0

        auto = {
            "sourcetype": self.mappings.apply_auto("sourcetype",
                                                   sorted({p["sourcetype"] for p in pairs})),
            "index": self.mappings.apply_auto("index", [i["name"] for i in eligible]),
            "datamodel": self.mappings.apply_auto("datamodel",
                                                  [m["name"] for m in models if not m.get("disabled")]),
            "addon": self.mappings.apply_auto("addon", [a["name"] for a in apps if _looks_like_addon(a)]),
        }

        totals = {
            "indexes": len(indexes), "indexes_eligible": len(eligible),
            "pairs": len(pairs), "apps": len(apps), "datamodels": len(models),
            "knowledge_objects": len(knowledge),
            "populated": summarize(populated, self.settings.populated.enabled),
            "missing": missing, "truncated": truncated, "auto_mappings": auto,
            "freshness": freshness,
            "field_profile": profile,
        }
        job["totals"] = totals
        job["results"] = {"eligible_indexes": event_indexes[:200]}
        if search_errors:
            job["errors"].extend(search_errors[:10])
        if truncated or search_errors:
            job["status"] = JOB_PARTIAL
        else:
            job["status"] = JOB_SUCCEEDED

        state = self.state.state()
        state.update({
            "last_attempt_at": imported, "last_attempt_status": job["status"],
            "last_source": job["source"], "include_internal": include_internal,
            "earliest": earliest, "latest": latest, "totals": totals,
            "splunk_version": version,
            "last_completed_at": imported, "last_completed_job_id": job["job_id"],
            "last_completed_status": job["status"],
        })
        if job["status"] == JOB_SUCCEEDED:
            state["last_success_at"] = imported
        self.state.save_state(state)

    def _referenced_models(self) -> List[str]:
        """Data model names catalogue requirements ask for, plus the local names mapped to them."""
        names: set = set()
        try:
            for row in self.store.query(C.CATALOG, {"provider_status": "active"}, fields=["datamodels"]):
                names.update(str(n) for n in row.get("datamodels") or [])
            lowered = {n.lower() for n in names}
            for m in self.store.query(C.SOURCE_MAPPINGS, {"kind": "datamodel"}):
                if str(m.get("canonical_value") or "").lower() in lowered and m.get("value"):
                    names.add(str(m["value"]))
        except Exception as exc:
            log.warning("referenced data models could not be read", extra={"error": str(exc)[:200]})
        return sorted(names)

    def _profile(self, job_id: str) -> Dict[str, Any]:
        try:
            from ..storage.repositories import CategoryRepository
            return run_profile(self.store, self.search, CategoryRepository(self.store), self.settings.profile,
                               job_id)
        except Exception as exc:
            log.warning("field profile failed", extra={"error": str(exc)[:200]})
            return {"enabled": self.settings.profile.enabled, "errors": 1, "sourcetypes": 0, "fields": 0}

    def _freshness(self, indexes: Sequence[str], pairs: List[Dict[str, Any]], searched: set) -> Dict[str, Any]:
        """Add 30-day volume and future-dated counts to ``pairs``; append pairs seen only before the window.

        Pairs found only by the longer pass are kept with ``window_count`` 0 and ``stale_from_start``,
        so a source that stopped before the window reads as stale instead of not found. A failed
        pass changes nothing and is reported in the totals; it never makes the job partial.
        """
        days = int(self.settings.freshness_days or 0)
        out: Dict[str, Any] = {"enabled": days > 0, "days": days, "stale_from_start": 0, "future_dated": 0,
                               "future_only": [], "errors": 0}
        if days <= 0 or not indexes:
            return out
        by_pair = {(p["index"], p["sourcetype"]): p for p in pairs}
        volume: Dict[tuple, Dict[str, Any]] = {}
        future: Dict[tuple, Dict[str, Any]] = {}
        for group in chunk_indexes([i for i in indexes if i in searched]):
            for target, spl in ((volume, tstats_volume(group, days)), (future, tstats_future(group))):
                try:
                    result = self.search.oneshot(spl, timeout=float(self.settings.search_timeout),
                                                 max_count=self.settings.max_pairs)
                except UcmError:
                    out["errors"] += 1
                    continue
                for row in result.rows:
                    parsed = _parse_tstats_row(row)
                    if parsed:
                        target[(parsed["index"], parsed["sourcetype"])] = parsed
        for key, row in volume.items():
            pair = by_pair.get(key)
            if pair is None:
                if len(pairs) >= self.settings.max_pairs:
                    continue
                pair = dict(row, window_count=0, stale_from_start=True)
                pairs.append(pair)
                by_pair[key] = pair
                out["stale_from_start"] += 1
            pair["volume_30d"] = row["window_count"]
        for key, row in future.items():
            pair = by_pair.get(key)
            if pair is None:
                if len(out["future_only"]) < 20:
                    out["future_only"].append({"index": key[0], "sourcetype": key[1], "count": row["window_count"]})
                continue
            pair["future_count"] = row["window_count"]
            pair["future_last_time"] = row["last_time"]
            out["future_dated"] += 1
        return out

    def _tstats(self, indexes: Sequence[str], earliest: str, latest: str):
        pairs: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        truncated = False
        searched: set = set()
        remaining = self.settings.max_pairs
        for group, spl in tstats_searches(indexes, earliest, latest):
            if remaining <= 0:
                truncated = True
                break
            try:
                result = self.search.oneshot(spl, timeout=float(self.settings.search_timeout),
                                             max_count=remaining)
            except UcmError as exc:
                errors.append(dict(exc.to_dict(), indexes=group[:5]))
                continue
            searched.update(group)
            truncated = truncated or result.truncated
            for row in result.rows:
                if len(pairs) >= self.settings.max_pairs:
                    truncated = True
                    break
                parsed = _parse_tstats_row(row)
                if parsed:
                    pairs.append(parsed)
            remaining = self.settings.max_pairs - len(pairs)
        return pairs, truncated, errors, searched


def _index_eligible(index: Dict[str, Any], include_internal: bool) -> bool:
    if index.get("disabled") or not index.get("is_ready"):
        return False
    if index.get("is_internal") and not include_internal:
        return False
    return True


def _looks_like_addon(app: Dict[str, Any]) -> bool:
    name = app.get("name") or ""
    return app.get("visible") or any(name.startswith(p) for p in ADDON_HINTS)


def _parse_tstats_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    index = str(row.get("index") or "")
    sourcetype = str(row.get("sourcetype") or "")
    if not index or not sourcetype:
        return None
    try:
        count = int(float(row.get("count") or 0))
    except (TypeError, ValueError):
        count = 0
    return {
        "index": index, "sourcetype": sourcetype, "window_count": count,
        "first_time": _epoch(row.get("first_time")), "last_time": _epoch(row.get("last_time")),
    }


def _epoch(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _age(last_time: Optional[int], now: float) -> Optional[int]:
    if last_time is None:
        return None
    return max(0, int(now) - int(last_time))


def _index_docs(indexes, pairs, now, imported, job_id) -> List[Dict[str, Any]]:
    window = {}
    last = {}
    volume: Dict[str, int] = {}
    future: Dict[str, int] = {}
    for p in pairs:
        window[p["index"]] = window.get(p["index"], 0) + p["window_count"]
        volume[p["index"]] = volume.get(p["index"], 0) + int(p.get("volume_30d") or 0)
        future[p["index"]] = future.get(p["index"], 0) + int(p.get("future_count") or 0)
        prev = last.get(p["index"])
        if p["last_time"] is not None and (prev is None or p["last_time"] > prev):
            last[p["index"]] = p["last_time"]
    docs = []
    for idx in indexes:
        name = idx["name"]
        last_time = last.get(name) or _iso_to_epoch(idx.get("max_time"))
        docs.append(_doc(
            kind="index", name=name, index=name, sourcetype="",
            extra={"datatype": idx.get("datatype"), "is_internal": idx.get("is_internal"),
                   "disabled": idx.get("disabled"), "is_ready": idx.get("is_ready"),
                   "total_event_count": idx.get("total_event_count"),
                   "min_time": idx.get("min_time"), "max_time": idx.get("max_time"),
                   "volume_30d": volume.get(name, 0), "future_count": future.get(name, 0)},
            window_count=window.get(name, 0), last_time=last_time, now=now,
            imported=imported, job_id=job_id, identity=(name,)))
    return docs


def _pair_docs(pairs, now, imported, job_id) -> List[Dict[str, Any]]:
    docs = []
    for p in pairs:
        docs.append(_doc(
            kind="pair", name="%s / %s" % (p["index"], p["sourcetype"]),
            index=p["index"], sourcetype=p["sourcetype"],
            extra={"volume_30d": p.get("volume_30d"), "future_count": p.get("future_count") or 0,
                   "future_last_time": p.get("future_last_time"),
                   "stale_from_start": bool(p.get("stale_from_start"))},
            window_count=p["window_count"], last_time=p["last_time"], first_time=p["first_time"],
            now=now, imported=imported, job_id=job_id, identity=(p["index"], p["sourcetype"])))
    return docs


def _app_docs(apps, imported, job_id) -> List[Dict[str, Any]]:
    docs = []
    for app in apps:
        if app.get("disabled"):
            continue
        docs.append(_doc(
            kind="app", name=app["name"], index="", sourcetype="",
            extra={"label": app.get("label"), "version": app.get("version"),
                   "package_id": app.get("package_id") or "", "visible": app.get("visible")},
            window_count=0, last_time=None, now=0, imported=imported, job_id=job_id,
            identity=(app["name"],)))
    return docs


def _model_docs(models, imported, job_id, populated=None) -> List[Dict[str, Any]]:
    docs = []
    for model in models:
        if model.get("disabled"):
            continue
        doc = _doc(
            kind="datamodel", name=model["name"], index="", sourcetype="",
            extra={"app": model.get("app"), "display_name": model.get("display_name"),
                   "objects": model.get("objects") or [], "accelerated": model.get("accelerated"),
                   "acceleration_earliest": model.get("acceleration_earliest") or ""},
            window_count=0, last_time=None, now=0, imported=imported, job_id=job_id,
            identity=(model["name"],))
        outcome = (populated or {}).get(model["name"])
        if outcome is not None:
            doc.update({"populated": outcome["populated"], "populated_reason": outcome["reason"],
                        "populated_count": outcome["count"], "populated_window": WINDOW,
                        "populated_at": imported})
            if "summary_count" in outcome:
                doc["summary_count"] = outcome["summary_count"]
        docs.append(doc)
    return docs


def _knowledge_docs(objects, imported, job_id) -> List[Dict[str, Any]]:
    docs: Dict[str, Dict[str, Any]] = {}
    for obj in objects:
        if obj.get("disabled"):
            continue
        doc = _doc(
            kind=obj["kind"], name=obj["name"], index="", sourcetype="",
            extra={"app": obj.get("app"), "sharing": obj.get("sharing"),
                   "lookup_type": obj.get("lookup_type") or None, "definition": obj.get("definition")},
            window_count=0, last_time=None, now=0, imported=imported, job_id=job_id,
            identity=(obj["name"], obj.get("app") or ""))
        docs[doc["_key"]] = doc
    return list(docs.values())


def _doc(kind, name, index, sourcetype, extra, window_count, last_time, now, imported, job_id,
         identity, first_time=None) -> Dict[str, Any]:
    search = " ".join([kind, name, index, sourcetype] + [str(v) for v in extra.values()
                                                         if isinstance(v, str)]).lower()
    doc = {
        "_key": source_key(kind, *identity), "doc_schema": DOC_SCHEMA, "kind": kind, "status": "active",
        "name": name, "index": index, "sourcetype": sourcetype, "window_count": window_count,
        "first_time": first_time, "last_time": last_time, "age_seconds": _age(last_time, now) if now else None,
        "discovered_at": imported, "job_id": job_id, "search_text": search,
        "sort_key": (name or "").lower(),
    }
    doc.update(extra)
    return doc


def _iso_to_epoch(value: str) -> Optional[int]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    text = text.replace("+00:00", "+0000")
    try:
        return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z").timestamp())
    except ValueError:
        return None

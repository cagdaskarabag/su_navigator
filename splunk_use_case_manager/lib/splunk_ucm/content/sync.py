"""Content synchronization (docs/DECISIONS.md D-009, D-010).

Guarantees:
* A category is fetched, validated and normalized completely before any write;
  a failure leaves its previously imported content untouched (last-known-good).
* Unchanged categories (same tree token and normalizer) cost one comparison;
  unchanged records (same blob token) are not downloaded.
* Records that disappear upstream are marked ``withdrawn``, never deleted.
* Only provider-owned collections are written. Customer state is untouched.
"""

import dataclasses
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..audit import AuditService
from ..catalog.summary import STATUS_ACTIVE, STATUS_WITHDRAWN, catalog_summary
from ..errors import ProviderError, SchemaIncompatibleError, UcmError, ValidationError
from ..log import get_logger
from ..model.canonical import Category
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..storage.repositories import (CategoryRepository, ContentRepository, SyncStateRepository, decode_raw,
                                   encode_raw)
from ..util import new_id, utc_now_iso
from .provider import (ContentProvider, Normalizer, ProviderCategory, ProviderManifest,
                       ProviderRecord, RecordListing)
from .validation import RecordValidator, find_duplicates

log = get_logger(__name__)

JOB_QUEUED, JOB_RUNNING, JOB_SUCCEEDED, JOB_PARTIAL, JOB_FAILED = (
    "queued", "running", "succeeded", "partial", "failed")
CAT_OK, CAT_UNCHANGED, CAT_FAILED = "ok", "unchanged", "failed"


@dataclasses.dataclass
class SyncSettings:
    fetch_concurrency: int = 4
    max_invalid_ratio: float = 0.2  # above this a category is treated as a schema problem
    max_errors_reported: int = 25
    job_timeout_seconds: int = 3600


@dataclasses.dataclass
class CategoryResult:
    category_id: str
    category_key: str = ""
    status: str = CAT_OK
    listed: int = 0
    added: int = 0
    updated: int = 0
    renormalized: int = 0
    unchanged: int = 0
    withdrawn: int = 0
    invalid: int = 0
    warnings: int = 0
    errors: List[Dict[str, Any]] = dataclasses.field(default_factory=list)


def schema_major(version: str) -> str:
    return (version or "").split(".", 1)[0]


def new_job(requested_by: str, provider: str, categories: Optional[List[str]], ref: str = "",
            source: str = "manual", allow_schema_change: bool = False, force: bool = False) -> Dict[str, Any]:
    job_id = new_id()
    return {
        "_key": "job::" + job_id, "doc_type": "job", "doc_schema": DOC_SCHEMA, "job_id": job_id,
        "provider": provider, "source": source, "status": JOB_QUEUED, "requested_by": requested_by,
        "requested_at": utc_now_iso(), "categories": categories or [], "ref": ref,
        "allow_schema_change": bool(allow_schema_change), "force": bool(force),
        "results": [], "errors": [], "totals": {},
    }


class SyncService:
    def __init__(self, store: DocumentStore, audit: AuditService,
                 settings: Optional[SyncSettings] = None, clock: Callable[[], str] = utc_now_iso):
        self.store = store
        self.audit = audit
        self.settings = settings or SyncSettings()
        self.clock = clock
        self.content = ContentRepository(store)
        self.categories = CategoryRepository(store)
        self.state = SyncStateRepository(store)

    # -- job lifecycle -----------------------------------------------------
    def enqueue(self, job: Dict[str, Any]) -> Dict[str, Any]:
        active = self.state.jobs(JOB_QUEUED, limit=5) + self.state.jobs(JOB_RUNNING, limit=5)
        for other in active:
            if other.get("provider") == job["provider"]:
                raise ValidationError("a sync job for this provider is already queued or running",
                                      {"job_id": other.get("job_id")})
        self.state.save_job(job)
        self.audit.record(job["requested_by"], "content.sync.requested", "sync_job", job["job_id"],
                          details={"provider": job["provider"], "categories": job["categories"],
                                   "ref": job["ref"], "source": job["source"]})
        return job

    def run(self, job: Dict[str, Any], provider: ContentProvider) -> Dict[str, Any]:
        job["status"] = JOB_RUNNING
        job["started_at"] = self.clock()
        self.state.save_job(job)
        try:
            self._run(job, provider)
        except UcmError as exc:
            job["status"] = JOB_FAILED
            job["errors"].append(exc.to_dict())
            log.warning("sync failed", extra={"job_id": job["job_id"], "code": exc.code, "error": exc.message})
        except Exception as exc:  # unexpected: record and surface, never swallow silently
            job["status"] = JOB_FAILED
            job["errors"].append({"code": "internal_error", "message": str(exc)})
            log.exception("sync crashed", extra={"job_id": job["job_id"]})
        job["finished_at"] = self.clock()
        self.state.save_job(job)
        self.state.prune()
        self.audit.record(job["requested_by"], "content.sync.completed", "sync_job", job["job_id"],
                          outcome=job["status"],
                          details={"totals": job.get("totals"), "errors": job["errors"][:5],
                                   "provider_version": job.get("provider_version"),
                                   "source_ref": job.get("source_ref")})
        return job

    def _run(self, job: Dict[str, Any], provider: ContentProvider) -> None:
        state = self.state.provider_state(job["provider"])
        manifest = provider.get_manifest()
        job.update({"provider_version": manifest.provider_version, "source_ref": manifest.source_ref,
                    "schema_version": manifest.schema_version, "manifest_warnings": manifest.warnings[:10]})

        previous_schema = state.get("schema_version")
        if previous_schema and schema_major(previous_schema) != schema_major(manifest.schema_version) \
                and not job.get("allow_schema_change"):
            raise SchemaIncompatibleError(
                "provider schema major version changed; administrator confirmation required",
                {"previous": previous_schema, "current": manifest.schema_version})

        requested = [str(c) for c in (job.get("categories") or state.get("selected_categories") or [])]
        if not requested:
            raise ValidationError("no categories selected for synchronization")

        validator = provider.validator(manifest)
        normalizer = provider.normalizer()
        results: List[CategoryResult] = []
        for cat_id in requested:
            pcat = manifest.category(cat_id)
            if pcat is None:
                results.append(CategoryResult(cat_id, status=CAT_FAILED, errors=[
                    {"code": "category_not_found", "message": "category not offered by provider"}]))
                continue
            try:
                results.append(self._sync_category(provider, manifest, pcat, validator, normalizer,
                                                   bool(job.get("force"))))
            except UcmError as exc:
                log.warning("category sync failed", extra={"category": cat_id, "code": exc.code})
                results.append(CategoryResult(cat_id, status=CAT_FAILED, errors=[exc.to_dict()]))

        job["results"] = [dataclasses.asdict(r) for r in results]
        totals: Dict[str, int] = {}
        for r in results:
            for field in ("listed", "added", "updated", "renormalized", "unchanged", "withdrawn",
                          "invalid", "warnings"):
                totals[field] = totals.get(field, 0) + getattr(r, field)
        totals["categories_failed"] = sum(1 for r in results if r.status == CAT_FAILED)
        job["totals"] = totals

        failed = totals["categories_failed"]
        job["status"] = JOB_SUCCEEDED if failed == 0 else (JOB_PARTIAL if failed < len(results) else JOB_FAILED)

        selected = list(state.get("selected_categories") or [])
        for r in results:
            if r.status != CAT_FAILED and r.category_id not in selected:
                selected.append(r.category_id)
        state["selected_categories"] = sorted(selected, key=lambda c: int(c) if c.isdigit() else 0)
        state["last_attempt_at"] = self.clock()
        state["last_attempt_status"] = job["status"]
        state["last_source"] = job["source"]
        if job["status"] == JOB_SUCCEEDED:
            state.update({"last_good_ref": manifest.source_ref, "last_good_version": manifest.provider_version,
                          "requested_ref": manifest.requested_ref, "schema_version": manifest.schema_version,
                          "last_success_at": self.clock()})
        elif not state.get("schema_version"):
            state["schema_version"] = manifest.schema_version
        self.state.save_provider_state(state)

    # -- per category ------------------------------------------------------
    def _sync_category(self, provider: ContentProvider, manifest: ProviderManifest, pcat: ProviderCategory,
                       validator: RecordValidator, normalizer: Normalizer, force: bool) -> CategoryResult:
        ccat = normalizer.normalize_category(pcat, provider.provider_id)
        result = CategoryResult(pcat.category_id, ccat.key)
        previous = self.categories.get(ccat.key) or {}
        if (not force and pcat.tree_sha and previous.get("tree_sha") == pcat.tree_sha
                and previous.get("normalizer_version") == normalizer.version
                and previous.get("last_sync_status") in (CAT_OK, CAT_UNCHANGED)):
            result.status = CAT_UNCHANGED
            result.unchanged = int(previous.get("imported_count") or 0)
            result.listed = result.unchanged
            self._save_category(ccat, previous, result, normalizer.version, manifest)
            return result

        listings = provider.list_records(manifest, pcat)
        result.listed = len(listings)
        dupes = find_duplicates(l.record_id for l in listings)
        if dupes:
            raise ValidationError("duplicate record ids in category", {"ids": dupes[:20]})

        known = self.content.known_records(ccat.key)
        key_of = {l.record_id: normalizer.content_key(l.record_id) for l in listings}
        to_fetch: List[RecordListing] = []
        to_renormalize: List[RecordListing] = []
        for listing in listings:
            prior = known.get(key_of[listing.record_id])
            if prior is None or force or not listing.blob_sha or prior.blob_sha != listing.blob_sha:
                to_fetch.append(listing)
            elif prior.normalizer_version != normalizer.version or prior.provider_status != STATUS_ACTIVE:
                to_renormalize.append(listing)
            else:
                result.unchanged += 1

        records, fetch_errors = self._fetch_all(provider, manifest, pcat, to_fetch)
        if fetch_errors:
            result.status = CAT_FAILED
            result.errors = fetch_errors[: self.settings.max_errors_reported]
            self._save_category(ccat, previous, result, previous.get("normalizer_version", ""), manifest,
                                keep_tree=True)
            return result
        for listing in to_renormalize:
            stored = self.content.get_content(key_of[listing.record_id])
            stored_raw = decode_raw(stored)
            if stored_raw is not None:
                records.append(ProviderRecord(
                    provider=provider.provider_id, record_id=listing.record_id, category_id=pcat.category_id,
                    path=listing.path, raw=stored_raw, raw_size=int(stored.get("raw_size") or 0),
                    blob_sha=listing.blob_sha, source_url=(stored.get("provenance") or {}).get("source_url", "")))
            else:
                to_fetch_again, errs = self._fetch_all(provider, manifest, pcat, [listing])
                records.extend(to_fetch_again)
                if errs:
                    result.status = CAT_FAILED
                    result.errors = errs
                    return result

        imported_at = self.clock()
        catalog_docs: List[Dict[str, Any]] = []
        content_docs: List[Dict[str, Any]] = []
        for record in records:
            vres = validator.validate(record.raw, record.raw_size or None)
            result.warnings += len(vres.warnings)
            if not vres.ok or str(record.raw.get("id")) != record.record_id:
                result.invalid += 1
                if len(result.errors) < self.settings.max_errors_reported:
                    errs = [dataclasses.asdict(f) for f in vres.errors[:3]] or [
                        {"code": "id_path_mismatch", "message": "record id does not match its file name"}]
                    result.errors.append({"record_id": record.record_id, "path": record.path, "errors": errs})
                continue
            uc = normalizer.normalize(record, ccat, manifest, imported_at)
            prior = known.get(uc.key)
            if prior is None:
                result.added += 1
            elif prior.blob_sha == record.blob_sha and record.blob_sha:
                result.renormalized += 1
            else:
                result.updated += 1
            catalog_docs.append(catalog_summary(uc))
            content_docs.append(self._content_doc(uc, record, ccat, vres.warnings))

        if listings and result.invalid / float(len(listings)) > self.settings.max_invalid_ratio:
            result.status = CAT_FAILED
            result.errors.insert(0, {"code": "invalid_ratio_exceeded",
                                     "message": "%d of %d records failed validation; category not updated"
                                                % (result.invalid, len(records))})
            self._save_category(ccat, previous, result, previous.get("normalizer_version", ""), manifest,
                                keep_tree=True)
            return result

        self.content.save(catalog_docs, content_docs)
        listed_keys = set(key_of.values())
        gone = [k for k, rec in known.items() if k not in listed_keys and rec.provider_status == STATUS_ACTIVE]
        if gone and not manifest.partial:
            result.withdrawn = self.content.mark_status(gone, STATUS_WITHDRAWN)
        # Rejected records keep their previous version; the category stays partially stale.
        if result.invalid:
            result.status = CAT_OK
        self._save_category(ccat, previous, result, normalizer.version, manifest,
                            keep_tree=bool(result.invalid))
        return result

    def _fetch_all(self, provider: ContentProvider, manifest: ProviderManifest, pcat: ProviderCategory,
                   listings: List[RecordListing]) -> Tuple[List[ProviderRecord], List[Dict[str, Any]]]:
        if not listings:
            return [], []
        records: List[ProviderRecord] = []
        errors: List[Dict[str, Any]] = []

        def fetch(listing: RecordListing):
            try:
                return provider.fetch_record(manifest, pcat, listing), None
            except ProviderError as exc:
                return None, dict(exc.to_dict(), record_id=listing.record_id)

        workers = max(1, min(self.settings.fetch_concurrency, len(listings)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for record, error in pool.map(fetch, listings):
                if error:
                    errors.append(error)
                elif record:
                    records.append(record)
        return records, errors

    def _content_doc(self, uc, record: ProviderRecord, ccat: Category, warnings) -> Dict[str, Any]:
        return {
            "_key": uc.key, "doc_schema": DOC_SCHEMA, "content_id": uc.content_id,
            "provider": uc.provenance.provider, "record_id": uc.provenance.provider_record_id,
            "category_key": ccat.key, "raw_json": encode_raw(record.raw), "raw_size": record.raw_size,
            "provenance": dataclasses.asdict(uc.provenance), "normalizer_version": uc.provenance.normalizer_version,
            "source_hash": uc.provenance.source_hash,
            "validation_warnings": [dataclasses.asdict(w) for w in warnings[:10]],
            "validation_warning_count": len(warnings),
        }

    def _save_category(self, ccat: Category, previous: Dict[str, Any], result: CategoryResult,
                       normalizer_version: str, manifest: ProviderManifest, keep_tree: bool = False) -> None:
        doc = dict(previous)
        doc.update(ccat.to_dict())
        doc.update({
            "_key": ccat.key, "doc_schema": DOC_SCHEMA, "sort_order": int(ccat.category_id)
            if ccat.category_id.isdigit() else 0, "selected": True,
            "last_sync_status": result.status, "last_sync_at": self.clock(),
            "last_sync_errors": result.errors[:5],
        })
        if keep_tree:
            doc["tree_sha"] = previous.get("tree_sha", "")
        if result.status != CAT_FAILED:
            doc["normalizer_version"] = normalizer_version
            doc["provider_version"] = manifest.provider_version
            doc["source_ref"] = manifest.source_ref
            doc["imported_count"] = self.store.count(
                "uc_catalog", {"$and": [{"category_key": ccat.key}, {"provider_status": STATUS_ACTIVE}]})
        self.categories.save(doc)

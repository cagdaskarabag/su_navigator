# Architecture — SUNavigator

## 1. Shape

A single Splunk app (`sunavigator/`) — a modular monolith:

```
Splunk Web (Simple XML 1.1 + app JS)          Background (modular input)
        │  /splunkd/__raw/services/ucm/*              ucm_sync_worker://default
        ▼                                                    │
  bin/ucm_rest.py  (persistent REST handler, caller's token) │
                   (system token only for audit + secrets)  │
        │                                                    │
        ▼                                                    ▼
  lib/splunk_ucm ──────────────── application services ──────────────────
   api/        request routing, input validation, JSON responses
   content/    ContentProvider ABC, FenreJsonProvider, OfflineBundleProvider,
               validation (schema subset + safety), normalizer, SyncService
   catalog/    CatalogQueryService (filters → KV query, paging), detail view
   spl/        static SPL analysis (requirements extraction, safety hints)
   storage/    SplunkdTransport, KVStore client, repositories
   platform/   capability detection (Enterprise/Cloud adapters)
   audit.py    AuditService
   config.py   app configuration (ucm.conf via REST)
   logging     structured JSON log → var/log/splunk/sunavigator.log
        │
        ▼
  KV Store collections (uc_*), storage/passwords (GitHub token)
```

Dependency direction: `api → services → (storage, platform, content providers)`.
Services depend on interfaces (`SplunkdTransport`, `ContentProvider`,
repository classes), never on `splunk.*` modules directly, so everything is
unit-testable outside Splunk. Only `storage/transport.py` imports `splunk.rest`;
the HTTP transport used by tools and live tests is `tools/splunkd_http.py` and is
not packaged.

## 2. Components and status

| # | Service | Module | WP | Status |
|---|---|---|---|---|
| 1 | Content Provider | `content/provider.py`, `content/fenre/provider.py`, `content/bundle.py` | WP1 | Implemented |
| 2 | Content Normalization | `content/fenre/normalizer.py`, `model/canonical.py` | WP1 | Implemented |
| 3 | Content Synchronization | `content/sync.py`, `bin/ucm_sync_worker.py` | WP1 | Implemented |
| 4 | Environment Discovery | `discovery/` | WP2 | Implemented |
| 5 | Data Source Mapping | `discovery/mapping.py` | WP2 | Implemented |
| 6 | Readiness Assessment | `readiness/` | WP3 | Implemented (inventory evidence; field/SPL checks in WP4) |
| 7 | Use Case Selection | `selection/` | WP4 | Implemented |
| 8 | SPL Validation | `spl/parser.py`, `validation/` | WP4 | Implemented |
| 9 | Deployment Manager | `deployment/` | WP5 | Implemented |
| 10 | Framework Mapping | `frameworks/` (registry, coverage, operations) | WP6 | Implemented |
| 11 | Dashboard Templates | `dashboards/` | WP6 | Implemented |
| 12 | Audit | `audit.py` | WP1 | Implemented (retention in WP7) |
| 14 | Maintenance (migrations, retention) | `maintenance/` | WP7 | Implemented |
| 13 | Platform Capability Adapter | `platform/` | WP1 / WP2 | Implemented (captain gate unit-tested; real SHC and Cloud stack not validated) |

## 3. Content flow

```
Provider.get_manifest() ─▶ ProviderManifest(version, commit, schema_version, categories[tree_sha])
SyncService.plan(categories) ─▶ compare tree_sha / blob_sha with uc_categories / uc_content
Provider.iter_records(category, known_hashes) ─▶ ProviderRecord(raw, blob_sha, path, url)
Validator.validate(raw) ─▶ errors / warnings        (rejects never reach storage)
Normalizer.normalize(raw, provenance) ─▶ UseCase    (canonical)
Stage per category ─▶ batch_save uc_content + uc_catalog, upsert uc_categories
Mark disappeared records `withdrawn`; record job in uc_sync_state; audit
```

Imported SPL is data. It is never dispatched by the content subsystem.
Discovery searches are a constructed ``tstats`` template over index names
returned by ``/services/data/indexes`` (D-020, D-021).

Deployment flow (WP5, D-028/D-029): draft (parse) ─▶ submit ─▶ approve (other
user) ─▶ deploy: create or update the saved search **disabled** with the
operator's session ─▶ read back and compare ─▶ `deployed` or `failed` ─▶
enable / disable / rollback (each read back) ─▶ retire (delete). The worker
re-verifies deployed searches periodically.

Readiness flow (WP3): ``EnvironmentSnapshot.load`` (sources + mappings +
discovery state, once per job) ─▶ ``StoredNormalizer`` re-derives each active
use case's requirements from ``uc_content`` ─▶ one evaluator per requirement
type ─▶ ``score`` (weights, veto) ─▶ batch_save ``uc_readiness``. The worker
queues a re-assessment when discovery or content sync completed after the
last assessment (D-024).

## 4. Canonical model (`ucm.usecase/1`)

Python dataclasses in `model/canonical.py`; serialised as plain dicts.

* **identity** — `content_id` (`fenre:UC-1.1.1`), `key` (`fenre_UC-1.1.1`),
  `provider`, `provider_record_id`, `title`, `description`, `provider_version`,
  `source_ref` (commit), `source_url`, `source_hash` (sha256 of canonical JSON),
  `source_blob_sha`, `source_schema`, `imported_at`, `normalizer_version`.
* **classification** — `domains[]` (canonical enum), `category_key`,
  `category_name`, `subcategory`, `tags[]`, `criticality`, `difficulty`,
  `business_value`, `products[]`, `monitoring_types[]`, `pillar`.
* **requirements[]** — `Requirement(req_id, type, value, level, source,
  confidence, notes)`; types: `data_source, index, sourcetype, field,
  event_condition, freshness, addon, product, cim_model, datamodel_acceleration,
  spl_validity, permission, macro, lookup, version, other`. Plus
  `data_sources_text`, `required_fields[]`, `cim_models[]`, `addons[]`,
  `premium_apps[]`, `splunk_versions[]`, `prerequisite_use_cases[]`.
* **implementation** — `spl`, `cim_spl`, `spl_variants[]`, `macros[]`,
  `lookups[]`, `instructions`, `detailed_instructions`, `visualization`,
  `script_example`, `schedule` (null unless provided).
* **frameworks** — `mappings[]` of `FrameworkMapping(framework, framework_version,
  object_type, object_id)`; `not_applicable_reasons[]`. Version may be `null`
  until WP6 resolves it — UI must show "unversioned", never "undefined".
* **quality** — `review_status`, `spl_status`, `last_reviewed`, `reviewer`,
  `references[]`, `known_false_positives`, `provider_extras{}` (unmapped
  upstream fields kept verbatim).

Customer-owned state (selection, bookmarks, readiness, deployment, local SPL
overrides) lives in **separate collections** keyed by `content_id`; sync never
writes to them.

## 5. KV Store schema

All collections are app-scoped (`nobody` owner) and replicated in SHC.

| Collection | Key | Shared/user | Written by | Contents |
|---|---|---|---|---|
| `uc_catalog` | `fenre_UC-1.1.1` | shared | sync | Canonical summary + filter fields (`domains`, `category_key`, `criticality`, `criticality_rank`, `difficulty`, `sourcetypes`, `indexes`, `datamodels`, `addons`, `addon_ids` (name / Splunkbase id pairs), `mitre_ids`, `provider_status`, `search_text`, `sort_key`). ~1–2 KB. |
| `uc_content` | same | shared | sync | `raw_json` (verbatim record as JSON text; KV Store forbids `$`/`.` in keys, e.g. `$schema`), `provenance`, `normalizer_version`, `source_hash`. ~10–80 KB. |
| `uc_categories` | `fenre_cat-01` | shared | sync | Category metadata, `tree_sha`, `selected`, counts, `last_synced_at`. |
| `uc_sync_state` | `provider::fenre` / `job::<uuid>` | shared | REST (system token), worker | Provider state (pin, last-good commit/version, schema version) and job records (status, counts, errors). Retain last 200 jobs. |
| `uc_audit` | uuid | shared (append) | all services | `time, actor, action, object_type, object_id, outcome, details`. Purged after `[retention] audit_days` (default 365, D-034). |
| `uc_environment_sources` | `src_<kind>_<hash>` | shared | discovery worker | Index, index/sourcetype pair, app (name, label, version, `package_id`) and data-model rows with window counts and data age. Missing sources are marked, never deleted. |
| `uc_source_mappings` | `map_<kind>_<hash>` | shared | discovery worker / REST (system token) | Local and auto mappings. Local rows are never overwritten by discovery. |
| `uc_readiness` | same as `uc_catalog` | shared | readiness worker / REST (system token) | `state`, `score`, `coverage`, `blockers`, `gaps`, `counts`, per-requirement `results[]` (status, code, detail, observed, via_mapping), `engine_version`, `discovery_at`, `source_hash`. ~3 KB. Staleness computed on read. |
| `uc_selections` | `sel_<user>_<content_id>` | per-user | user | Bookmark / select / defer / reject. Sync never writes this collection. |
| `uc_validation` | same as `uc_catalog` | shared | REST (system token) | Parser outcome, side-effects, bounded preview metadata (no event payloads), field samples. |
| `uc_deployments` | `dep_<catalog key>` | shared | REST (system token), worker | Workflow `state`, `revisions[]` (frozen SPL, schedule, parse result, submitter, approver, deploy time), `deployed_revision`, `live` (status, drift, owner, next run), `history[]` (last 100), `version`. |
| `uc_frameworks` | `fw_<id>_<version>` / `active_<id>` | shared | REST (system token) | Imported framework definitions (`ucm.framework/1`) and the active version per framework. Bundled versions are files, not documents. |
| `uc_dashboards` | `dash_<view name>` | shared | REST (system token) | Generated view record: template, params, label, XML hash, created/updated by. |

Accelerated fields (`collections.conf`): `uc_catalog` on `category_key`,
`criticality_rank`, `provider_status`, `sort_key`; `uc_sync_state` on
`doc_type, requested_at`; `uc_audit` on `time`.

Concurrency: sync writes are idempotent upserts by stable key. `enqueue` refuses
a job while another job for the same provider is queued or running; the worker
runs jobs sequentially, and on a search head cluster only the captain runs
them. A stale `running` job older than `job_timeout_seconds` is marked failed.
KV Store has no conditional update, so two workers racing on one job are
prevented by these guards, not by an atomic claim (SHC validation pending).

Upgrades: every document carries `schema_version`; the normalizer version is
stored per content document so a newer app can re-derive catalogue summaries
from `raw_json` without network access (`POST /ucm/catalog/reindex`, WP1).
Catalogue summaries also carry `summary_version`.

App state (`uc_sync_state`, D-033):

| Key | `doc_type` | Contents |
|---|---|---|
| `app::state` | `app_state` | `state_schema`, `applied[]` migration ids, `app_version`, `previous_app_version`, `upgraded_at`, `last_migration`, `last_migration_at` |
| `maintenance::retention` | `retention_state` | `last_run_at`, `totals` (`audit`, `jobs`) of the last purge |
| `deployment::verify` | `deployment_verify` | `last_run_at`, `totals` of the last drift verification |
| `provider::<id>` | `provider` | Provider pin, last good version/commit, schema version |
| `job::`, `djob::`, `rjob::<uuid>` | `job`, `discovery_job`, `readiness_job` | Job records, trimmed to `[retention] job_history` per type |

The background worker runs, in order and one job per run: maintenance
(pending migrations, then retention when due), content sync, discovery,
readiness and deployment verification. All of them are leader-gated (D-035).
Downgrades are not supported (D-033).

## 6. REST API (`/services/ucm/...`)

| Method & path | Capability (role) | Purpose |
|---|---|---|
| `GET ucm/catalog` | read collections | Filtered, paged catalogue (`q, domain, category, criticality, difficulty, sourcetype, mitre, status, quality, review, regulation, sort, offset, count`). |
| `GET ucm/catalog/facets` | read | Review statuses, regulations and quality flags in the active catalogue, with counts. |
| `GET ucm/usecase?id=` | read | Canonical detail (normalized on read) + provenance. |
| `GET ucm/categories` | read | Category list with sync state. |
| `GET ucm/sync` | read | Provider state + recent jobs. |
| `POST ucm/sync` | `ucm_manage_content` | Queue a sync job (`categories`, optional `ref`). |
| `POST ucm/import` | `ucm_manage_content` | Import an offline bundle (JSON body). |
| `POST ucm/catalog/reindex` | `ucm_manage_content` | Re-derive summaries from stored raw records, then duplicate-SPL flags and facets. |
| `GET ucm/provider/manifest` | `ucm_manage_content` | Resolve the remote manifest (optional `ref`) without importing. |
| `GET ucm/platform` | read | Capability report. |
| `GET ucm/audit` | `ucm_manage_content` or `ucm_admin` | Recent audit events (`limit`, `prefix`). |
| `GET ucm/inventory` | read | Filtered, paged environment sources (`kind, status, q, index, sourcetype, stale_hours, sort, offset, count`). |
| `GET ucm/inventory/coverage` | read | Catalogue requirement values vs discovered sources. |
| `GET ucm/discovery` | read | Discovery state and recent jobs. |
| `POST ucm/discovery` | `ucm_run_discovery` | Queue a bounded discovery job (`include_internal`, `earliest`, `latest`). |
| `GET ucm/mappings` | read | Source mappings. |
| `POST ucm/mappings` | `ucm_run_discovery` | Create or update a **local** mapping. |
| `POST ucm/mappings/delete` | `ucm_run_discovery` | Delete a local mapping (auto mappings cannot be deleted). |
| `GET ucm/readiness` | read | Filtered, paged readiness (`state, domain, criticality, category, q, sort, offset, count`). |
| `GET ucm/readiness/summary` | read | Counts by state, most common unmet requirements, jobs, settings. |
| `GET ucm/readiness/usecase?id=` | read | Full readiness document with staleness. Also embedded in `GET ucm/usecase` as `readiness`. |
| `POST ucm/readiness` | `ucm_run_discovery` | Queue a full re-assessment. |
| `POST ucm/readiness/assess` | `ucm_run_discovery` | Assess one use case synchronously (`{"id": ...}`). |
| `GET ucm/selections` | caller | The caller's selections (`intent=bookmark\|select\|defer\|reject\|backlog`). |
| `POST ucm/selections` | caller | Upsert the caller's intent (`id`, `intent`, `notes`, `priority`). |
| `POST ucm/selections/delete` | caller | Remove the caller's selection. |
| `GET ucm/validation?id=` | read | Last parse / preview / field-sample document. |
| `POST ucm/validate` | `ucm_run_discovery` | Parse with `/services/search/parser`, optionally sample fields and re-assess (`sample`). |
| `POST ucm/preview` | `ucm_run_discovery` | Bounded preview of imported SPL; refused when side-effect, indirect-execution or unknown commands are present (D-038). |
| `GET ucm/deployments` | read | Deployments (`state`, `live`, `drift=1`, `summary=1`, paging). |
| `GET ucm/deployment?id=` | read | Deployment document plus `allowed_actions` for the caller. Also embedded in `GET ucm/usecase`. |
| `POST ucm/deployment/draft` | `ucm_run_discovery` or `ucm_deploy` | Create or replace a draft revision (`spl_source`, `custom_spl`, `cron`, `earliest`, `latest`, `schedule_window`, `suppress_period`, `suppress_fields`, `alert_mode`, `severity`, `threshold`, `notes`). |
| `POST ucm/deployment/submit` | `ucm_run_discovery` or `ucm_deploy` | Submit the draft for approval. |
| `POST ucm/deployment/{approve,reject,deploy,enable,disable,rollback,retire}` | `ucm_deploy` | Workflow and saved-search actions (`note`; `override_reason` for enable). |
| `POST ucm/deployment/verify` | `ucm_run_discovery` or `ucm_deploy` | Compare the saved search with its revision. |
| `GET ucm/frameworks` | read | Framework versions (bundled and imported, active flag) and coverage per framework. |
| `GET ucm/frameworks/matrix` | read | ATT&CK matrix (`framework_id`, `version`, `domain`, `operational=1`, `hours`) with remapped and unresolved ids. |
| `GET ucm/frameworks/technique` | read | Use cases for one technique (`id`). |
| `GET ucm/frameworks/controls` | read | Controls of one regulation (`framework`) with best level, `gap` and use cases. |
| `GET ucm/frameworks/navigator` | read | ATT&CK Navigator layer 4.5 (`framework_id`, `version`, `domain`, `operational=1`, `hours`): `layer`, `filename`. |
| `GET ucm/frameworks/clause` | read | Use cases of one clause (`framework`, `clause`) with readiness, deployment and mapping substance. |
| `GET ucm/frameworks/evidence` | read | Deterministic evidence pack (`framework`, optional `clause`, `format=json\|csv`): `content`, `sha256`, `filename`, `meta`. |
| `POST ucm/frameworks/import` | `ucm_manage_content` | Import a `ucm.framework/1` definition (JSON body). |
| `POST ucm/frameworks/activate` | `ucm_manage_content` | Choose the active version (`framework_id`, `version`). |
| `GET ucm/operations` | read (scheduler logs need `_internal`) | Run status of deployed searches (`hours` = 1, 4, 24, 72 or 168). |
| `GET ucm/dashboards` | read | Templates and generated views. |
| `POST ucm/dashboards/preview` | read | Render a template without saving. |
| `POST ucm/dashboards/{create,delete}` | `ucm_deploy` | Write or remove a generated view in this app. |

Writes check an app capability (`authorize.conf`) from the request context in
addition to collection ACLs (defence in depth). Request bodies must be sent as
`Content-Type: application/json`; splunkd rejects other bodies before the
handler runs. Errors are JSON `{"error": {code, message, details}}`.

## 7. Platform adapter

`platform/capabilities.py` probes, with the caller's token: server info
(`server/info`: version, `instance_type` = `cloud` on Splunk Cloud), KV Store
status, the caller's capabilities (`authentication/current-context`), and
configured outbound access. Results are reported to the UI; unsupported
operations return HTTP 409 with a machine-readable reason, never silent failure.

`platform/search.py` (`SearchClient`) is the only path to `search/jobs`. A
oneshot returns at most `max_count` rows, and `truncated` is true only when
more rows existed (D-037). Every evidence producer (discovery, field
sampling, run status) treats an absence inside a truncated result as
unknown, never as proof.

## 8. Security

Full model: `docs/SECURITY.md`.


* Upstream content is untrusted: size limits, JSON-only parsing, schema +
  safety validation, URL scheme allowlist, HTML-escaped rendering, no SPL
  execution in the content subsystem.
* Outbound HTTP only to configured https hosts (allowlist), TLS verified,
  per-response size caps, timeouts, retries with backoff.
* GitHub token (optional) read from `storage/passwords`; never logged or stored
  in conf/KV.
* Audit every import, sync request, sync outcome and configuration change.

## 9. Known limitations

* Total counts use a keys-only KV query and are therefore bounded by
  `max_rows_per_query` (50,000 by default).
* Free-text search is a case-insensitive substring match (all terms must
  match) over a precomputed `search_text` field holding id, title,
  sourcetypes, tags and MITRE ids; descriptions are not searched. No ranking.
* Derived requirements are lexical hypotheses (D-013), not evidence.
* Coverage is computed on read over the whole active catalogue (no cache):
  about 0.5 s per request at 20,000 use cases on a single instance.
* Run status relies on the scheduler log in `_internal`, which most
  non-admin roles cannot search (D-031).

See also `docs/IMPLEMENTATION_PLAN.md` "Validation status" and
`docs/PROJECT_DISCOVERY.md` §6.

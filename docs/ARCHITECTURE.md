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
| 1 | Content Provider | `content/provider.py`, `content/fenre/provider.py`, `content/bundle.py`, `content/escu/` (ESCU offline bundles, D-053), `content/requirements.py` (shared) | WP1 | Implemented |
| 2 | Content Normalization | `content/fenre/normalizer.py`, `model/canonical.py` | WP1 | Implemented |
| 3 | Content Synchronization | `content/sync.py`, `bin/ucm_sync_worker.py` | WP1 | Implemented |
| 4 | Environment Discovery | `discovery/` | WP2 | Implemented |
| 5 | Data Source Mapping | `discovery/mapping.py` | WP2 | Implemented |
| 6 | Readiness Assessment | `readiness/` | WP3 | Implemented (inventory evidence; field/SPL checks in WP4) |
| 7 | Use Case Selection | `selection/` | WP4 | Implemented |
| 8 | SPL Validation | `spl/parser.py`, `spl/lint.py` (advisory lint, D-065), `validation/` | WP4 | Implemented |
| 9 | Deployment Manager | `deployment/` | WP5 | Implemented |
| 10 | Framework Mapping | `frameworks/` (registry, coverage, operations) | WP6 | Implemented |
| 11 | Dashboard Templates | `dashboards/` | WP6 | Implemented |
| 12 | Audit | `audit.py` | WP1 | Implemented (retention in WP7) |
| 14 | Maintenance (migrations, retention) | `maintenance/` | WP7 | Implemented |
| 13 | Platform Capability Adapter | `platform/` | WP1 / WP2 | Implemented (captain gate validated on a local three-member SHC, D-055; Splunk Cloud not validated). `platform/security_content.py` (0.9.1, D-067) reads ES and ESCU presence and the state of ESCU's shipped saved search with the system token, read-only, cached for 60 s; ES-present behaviour is mocked-only and unvalidated. |

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
Discovery searches are constructed ``tstats`` templates: over index names
returned by ``/services/data/indexes`` (D-020, D-021) and, since 0.9.1, one
``| tstats count from datamodel=<model> where earliest=-24h`` per selected data model
(`discovery/populated.py`, D-067, issue #13): bounded by a model cap, a per-search
`max_time`, a total budget and a stop after repeated failures; the outcome is stored as
`populated` on the model's `uc_environment_sources` row and is informational only.

Deployment flow (WP5, D-028/D-029, owner D-051): draft (parse) ─▶ submit ─▶ approve (other
user) ─▶ deploy: create or update the saved search **disabled** with the
system session (owner `ucm_scheduler`, D-051) ─▶ read back and compare ─▶ `deployed` or `failed` ─▶
enable / disable / rollback (each read back) ─▶ retire (delete). The worker
re-verifies deployed searches periodically.

Readiness flow (WP3): ``EnvironmentSnapshot.load`` (sources + mappings +
discovery state, once per job) ─▶ ``StoredNormalizer`` re-derives each active
use case's requirements from ``uc_content`` ─▶ one evaluator per requirement
type ─▶ ``score`` (weights, veto) ─▶ batch_save ``uc_readiness``. The worker
queues a re-assessment when discovery or content sync completed after the
last assessment (D-024).

Recommendation flow (D-060, `readiness/recommend.py`), read-only:
``CoverageService.use_case_levels`` (active catalogue with its deployed level) +
all ``uc_readiness`` keys and states + ``ready`` / ``partially_ready`` rows +
``uc_deployments`` states + the calling user's own ``uc_selections`` ─▶ eligibility
filter ─▶ draft score ─▶ order ─▶ reasons for the top 10 (one ``uc_readiness`` read
each, for the ``cim_model`` result).

```
eligible   = active catalogue entry
             AND uc_readiness row with state ready, or partially_ready with no blockers
             AND level in (catalogue, ready)        # not deployed, enabled or operational
             AND intent of the calling user != reject
draft      = 0.40 * score                           # readiness score, 0-100
           + 0.25 * (criticality_rank / 4 * 100)    # critical 4 ... unknown 0
           + 0.20 * gain * 100                      # gain = |ids not covered| / |ids|, 0 without ids
           + 0.15 * coverage * 100                  # share of scored weight that was decided
covered    = union of mitre_ids of active use cases at level deployed, enabled or operational
order      = (state ready first, -draft, -criticality_rank, -score, content_id)
limit      = 10
```

Empty states, in order: no active catalogue; no readiness rows and no completed
discovery; no readiness rows after discovery; rows exist but none eligible (the
response counts what was left out). The weights are defaults, returned with every
response (`formula`), and are not calibrated against outcomes.

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
| `uc_catalog` | `fenre_UC-1.1.1` | shared | sync | Canonical summary + filter fields (`domains`, `category_key`, `criticality`, `criticality_rank`, `difficulty`, `sourcetypes`, `indexes`, `datamodels`, `addons`, `addon_ids` (name / Splunkbase id pairs), `mitre_ids`, `provider_status`, `search_text`, `sort_key`; since 0.9.0 (summary version 6) `wave`, `analytic_stories` and `data_sources`, which are absent from older summaries; `provider` and the derived `quality_flags` entries `duplicate_spl` and `provider_twin` are used as filters). ~1–2 KB. |
| `uc_content` | same | shared | sync | `raw_json` (verbatim record as JSON text; KV Store forbids `$`/`.` in keys, e.g. `$schema`), `provenance`, `normalizer_version`, `source_hash`. ~10–80 KB. |
| `uc_categories` | `fenre_cat-01` | shared | sync | Category metadata, `tree_sha`, `selected`, counts, `last_synced_at`. |
| `uc_sync_state` | `provider::fenre` / `job::<uuid>` | shared | REST (system token), worker | Provider state (pin, last-good commit/version, schema version) and job records (status, counts, errors). Retain last 200 jobs. |
| `uc_audit` | uuid | shared (append) | all services | `time, actor, action, object_type, object_id, outcome, details`. Purged after `[retention] audit_days` (default 365, D-034). |
| `uc_environment_sources` | `src_<kind>_<hash>` | shared | discovery worker | Index, index/sourcetype pair, app (name, label, version, `package_id`) and data-model rows with window counts and data age; since 0.9.1 data-model rows also carry `populated` (`yes`, `no`, `unverified`), `populated_reason`, `populated_count`, `populated_window` and `populated_at` (additive, D-067). Missing sources are marked, never deleted. |
| `uc_source_mappings` | `map_<kind>_<hash>` | shared | discovery worker / REST (system token) | Local and auto mappings. Local rows are never overwritten by discovery. |
| `uc_readiness` | same as `uc_catalog` | shared | readiness worker / REST (system token) | `state`, `score`, `coverage`, `blockers`, `gaps`, `counts`, per-requirement `results[]` (status, code, detail, observed, via_mapping), `engine_version`, `discovery_at`, `source_hash`. ~3 KB. Staleness computed on read. |
| `uc_selections` | `sel_<user>_<content_id>` | per-user rows, app-shared at KV level (D-061) | user | Bookmark / select / defer / reject. Sync never writes this collection. The API isolates users; the ACL does not. |
| `uc_validation` | same as `uc_catalog` | shared | REST (system token) | Parser outcome, side-effects, advisory lint findings (`lint`, absent before 0.8.9), bounded preview metadata (no event payloads), field samples. |
| `uc_control_fixtures` | `cf_<catalog key>` | shared | REST (system token), import only | Control-test fixture: sourcetype, host, `min_count`, raw positive and negative text, import `batch` (D-054). |
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
prevented by these guards, not by an atomic claim. The captain gate was validated on a local three-member SHC (D-055).

Upgrades: every document carries `schema_version`; the normalizer version is
stored per content document so a newer app can re-derive catalogue summaries
from `raw_json` without network access (`POST /ucm/catalog/reindex`, WP1).
Catalogue summaries also carry `summary_version` (6 since 0.9.0, D-066). A new summary version
is **not** applied by an upgrade: migration 0001 is pinned to `0001_catalog_summary_v5`, and the
migration `0004_catalog_facets_v3` writes only the facets document, which reports
`summary: {version, outdated}`. The operator presses Reindex (`POST /ucm/catalog/reindex`), which
rewrites the summaries, sets the derived flags and stores the facets. Until then a filter on a
field an old summary lacks skips those documents, never errors.

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
| `GET ucm/catalog` | read collections | Filtered, paged catalogue (`q, domain, category, criticality, difficulty, sourcetype, mitre, status, quality, review, regulation, availability, bookmarked, sort, offset, count`). Facet parameters take several comma-separated values (OR within a facet, AND between facets). `availability` is a readiness state or `not_assessed`; `bookmarked=1` uses the caller's own bookmark selections (user from the session). Both are joined by `_key` (D-059). `provider`, `wave`, `story` and `data_source` are `$in` clauses on summary fields, so they take the same join or scan path (D-066); `exclude_quality` is one `quality_flags $ne` clause per flag (`$nin` and `$nor` are invalid on the KV Store). |
| `GET ucm/catalog/facets` | read | Review statuses, regulations, quality flags and counts per domain, category, criticality and difficulty in the active catalogue (stored `catalog::facets` v3, whole-catalogue counts) plus, since 0.9.0, `providers`, `waves`, `analytic_stories`, `data_sources` and `summary: {version, outdated}`. |
| `GET ucm/readiness/recommendations` | read collections | Up to 10 recommended use cases for the calling user (`exclude_quality` leaves out flagged use cases; off by default), with draft-score parts, reasons, flags, the formula and one of four empty states (D-060). Read-only. |
| `GET ucm/usecase?id=` | read | Canonical detail (normalized on read) + provenance. For an ESCU record, since 0.9.1, `escu_handoff`: the shipped stanza's state, schedule, actions, the ES link data, the parallel-copy warning and the coverage note (D-067); `null` for other providers. |
| `GET ucm/categories` | read | Category list with sync state. |
| `GET ucm/sync` | read | Provider state + recent jobs. |
| `POST ucm/sync` | `ucm_manage_content` | Queue a sync job (`categories`, optional `ref`). |
| `POST ucm/import` | `ucm_manage_content` | Import an offline bundle (JSON body). |
| `POST ucm/catalog/reindex` | `ucm_manage_content` | Re-derive summaries from stored raw records, then duplicate-SPL and cross-provider twin flags and facets. |
| `GET ucm/provider/manifest` | `ucm_manage_content` | Resolve the remote manifest (optional `ref`) without importing. |
| `GET ucm/platform` | read | Capability report. Since 0.9.1 also `security_content`: ES and ESCU `state` (`installed`, `disabled`, `not_installed`, `unverified`), version and reason (D-067). |
| `GET ucm/audit` | `ucm_manage_content` or `ucm_admin` | Recent audit events (`limit`, `prefix`). |
| `GET ucm/inventory` | read | Filtered, paged environment sources (`kind, status, q, index, sourcetype, stale_hours, sort, offset, count`). |
| `GET ucm/inventory/coverage` | read | Catalogue requirement values vs discovered sources. |
| `GET ucm/discovery` | read | Discovery state and recent jobs. |
| `POST ucm/discovery` | `ucm_run_discovery` | Queue a bounded discovery job (`include_internal`, `earliest`, `latest`). |
| `GET ucm/mappings` | read | Source mappings. |
| `POST ucm/mappings` | `ucm_run_discovery` | Create or update a **local** mapping. |
| `POST ucm/mappings/delete` | `ucm_run_discovery` | Delete a local mapping (auto mappings cannot be deleted). |
| `GET ucm/readiness` | read | Filtered, paged readiness (`state, domain, criticality, category, q, sort, offset, count`). Each item carries the stored per-status `counts` and `unverified` (shown as requirement results, D-061). |
| `GET ucm/readiness/summary` | read | Counts by state, most common unmet requirements, jobs, settings, and `scheduler` (the scheduled owner's role and index-access summary, D-063). |
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
| `POST ucm/deployment/controltest` | `ucm_deploy` | Replay control fixtures against the deployed search in the test index (D-054). |
| `POST ucm/controltest/import` | `ucm_manage_content` | Import Fenre control-test fixtures (`ucm-control-fixtures/1`) into `uc_control_fixtures` (D-054). |
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
  `max_rows_per_query` (50,000 by default). The catalogue marks a total at the
  bound (`total_capped`) and Administration warns near it; `[catalog] kv_row_limit`
  tells the app the platform value (issue #14, D-065).
* The SPL lint (`spl/lint.py`) is advisory, covers five rules shown wrong on Splunk
  10.2.9, does not expand macros and never changes a gate or score (D-065).
* Free-text search is a case-insensitive substring match (all terms must
  match) over a precomputed `search_text` field holding id, title,
  sourcetypes, tags and MITRE ids; descriptions are not searched. No ranking.
* Derived requirements are lexical hypotheses (D-013), not evidence.
* `populated` (0.9.1) is a snapshot from the last discovery: one 24-hour count per model, not a
  field, tagging or acceleration check, and it never changes a score (D-067, issue #13).
* ES and ESCU state (0.9.1) is read, never written. Everything that needs ES installed is mocked in
  tests and unvalidated (no ES lab, issue #4); SUN deploys plain scheduled searches, not ES
  correlation searches.
* Reindex runs inside one REST call (about 5 ms per use case); there is no background job (draft N-09).
* Coverage is computed on read over the whole active catalogue (no cache):
  about 0.5 s per request at 20,000 use cases on a single instance.
* Catalogue facet counts are global; bookmark / availability / regulation filters
  join by `_key` within `[catalog] max_join_keys` and scan up to 49,999 rows
  otherwise (D-059). Recommendations are an uncalibrated ordering (D-060).
* Run status relies on the scheduler log in `_internal`, which most
  non-admin roles cannot search (D-031).

See also `docs/IMPLEMENTATION_PLAN.md` "Validation status" and
`docs/PROJECT_DISCOVERY.md` §6.

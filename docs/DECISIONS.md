# Decision Log

Each entry: context → decision → consequences. Status is `Accepted` unless noted.
Decisions D-001..D-005 restate the non-negotiable product decisions; the rest were
made during implementation.

## D-001 Modular monolith, single Splunk app
One installable app `sunavigator`. Internal Python package
`splunk_ucm` (in `lib/`) with service modules behind explicit interfaces.

## D-002 Provider-independent canonical model
Upstream JSON is never the internal schema. Providers return `ProviderRecord`
(raw bytes/obj + provenance); a provider-specific normalizer produces the
canonical `UseCase`. See `docs/ARCHITECTURE.md` §4.

## D-003 Evidence-based readiness, guided disabled-first deployment
Unchanged from product requirements. Not implemented in WP1.

## D-004 KV Store for operational state; no filesystem caches
Filesystem caches do not replicate across SHC members (R7). All content, state,
sync history and audit live in KV Store collections owned by this app.

## D-005 Stdlib-only Python, compatible with 3.9–3.13
Splunk 10.2 bundles 3.9 and 3.13; 9.x bundles 3.7/3.9. Cloud vetting and
AppInspect discourage compiled dependencies. All runtime code uses the standard
library plus Splunk-provided modules. Conf files declare
`python.required = 3.9, 3.13` (10.x) and `python.version = python3` (9.x fallback).
*Python 3.7 (Splunk ≤ 9.1) is out of scope.*

## D-006 Fenre transport: git sidecars at a pinned commit
**Context.** Pages serves only manifests/thin indexes; full detail exists in
`content/**/UC-*.json` (source of truth per upstream ADR-0007) and in unversioned
abbreviated helpers (`/api/cat-N.json`) that upstream says not to build on.
**Decision.** Resolve the configured ref (branch, tag, or SHA) to a commit SHA,
walk `content/` via the git trees API, download sidecars from
`raw.githubusercontent.com` at that commit, and verify each file's git blob SHA.
**Consequences.** Exact incremental sync by tree/blob SHA; reproducible pins;
integrity check without signatures. Depends on a layout outside the `/api/v1`
contract (risk R1) — paths are configuration.

## D-007 Validate against the schema of the same commit; tolerant consumer
Validation uses `schemas/uc.schema.json` fetched at the pinned commit (bundled
1.11.0 copy is the fallback, offline). Findings are classified:
* **error** — record rejected: not an object, missing/invalid `id`/`title`,
  wrong type on a field the normalizer consumes, oversize record or SPL, NUL
  bytes in SPL, duplicate id, id not matching its file name.
* **warning** — record accepted: unknown properties (upstream additive changes),
  enum values not in the schema (upstream tolerant-consumer rule), other schema
  keyword violations on fields not consumed, and non-http(s) reference URLs
  (88 upstream records use repository-relative links; they are never rendered
  as links, see D-018).
A schema `version` major change blocks sync for that provider until an
administrator confirms (prevents silent mis-normalization).

## D-008 Store the raw record once; canonical summary for search
`uc_content` holds the verbatim upstream record + provenance; the canonical
detail is produced by the versioned normalizer on read. `uc_catalog` holds a
compact canonical summary with all filterable fields. Avoids duplicating ~200 MB
of text and allows re-normalisation after normalizer upgrades without refetching.

## D-009 Category-level, last-known-good sync
A category is fetched, validated and staged completely before any write. A
fetch or validation failure leaves the previous content of that category
untouched; the job ends `partial`/`failed`; provider state (`last_good_ref`)
only advances when all requested categories succeed.
*Correction (T-09).* The write phase is not atomic: KV Store has no
transactions, and `batch_save` writes in chunks. Content is written before the
catalogue, and the category's `tree_sha` only advances after a successful
write. If a write fails part-way, the category is marked failed and some
records may already carry new content; the catalogue still holds the old blob
SHAs for the rest, so the next sync fetches and rewrites them. Tested with
writes interrupted in either collection (`test_interrupted_write_self_heals_on_next_sync`). Records that disappear upstream are marked
`withdrawn`, never deleted (local state may reference them).

## D-010 Sync runs in a background worker, not in REST requests
REST requests create a sync *job* in `uc_sync_state`; a modular input
(`ucm_sync_worker`) claims and executes queued jobs and scheduled syncs. Keeps
REST latency bounded and works for long category imports. Offline bundle
imports of modest size run inline (they need no network).

## D-011 REST handlers use the caller's session; system token only for audit and secrets
*Amended during WP1.* Persistent REST handler with `passSystemAuth = true`.
Catalogue, content, sync-state and configuration access use the caller's token,
so Splunk enforces collection ACLs (`metadata/default.meta`) and app
capabilities. The system token is used for exactly two things: appending to
`uc_audit` (which ordinary roles cannot write, so users cannot forge or erase
audit entries) and reading the GitHub token from `storage/passwords`. The
background worker runs with the modular-input session key and only executes
jobs whose requester was authorised at enqueue time; the requester is recorded
in the audit log.

## D-012 UI: Simple XML 1.1 + small JS modules
Native Simple XML for count/overview panels (KV lookups via `inputlookup`).
The catalogue/detail view uses one Simple XML dashboard with an HTML panel and
app JS modules calling the app REST API with server-side paging and filtering.
No custom frontend framework or build toolchain in the MVP. Revisit (React via
`@splunk/react-ui`) if the deployment workflow UI outgrows this.

## D-013 Requirements derived from SPL are low/medium confidence
Static analysis extracts `index=`, `sourcetype=`, `datamodel=`, macros
(`` `name` ``), lookups and `inputlookup`. Exact literal values → `medium`;
wildcards/macros → `low`; provider-structured fields (`requiredFields`,
`cimModels`, `splunkbaseApps`) → `high` provenance. Readiness (WP3) must not
treat derived requirements as proof.

## D-014 Monitoring-domain mapping is data, not code
Fenre categories map to canonical domains via a JSON resource
(`fenre/domain_map.json`), overridable per deployment later (WP2 registry).
`splunkPillar=Security` and `securityDomain` add `security`.

## D-015 Modular input spec must declare at least one setting
**Context.** With a spec stanza containing only comments, splunkd 10.2.9 never
registered the `ucm_sync_worker` scheme (no log line, `print-modinput-config`
reported "not initialized"); queued jobs never ran. Moving the app from a
symlink to a real directory did not help.
**Decision.** `README/inputs.conf.spec` declares a real optional setting
(`max_jobs_per_run`, 1..10, default 1), python settings sit on the scheme
stanza `[ucm_sync_worker]`, and the scheme uses `use_single_instance = false`
(one short-lived process per interval). These three changes were made together,
so which one was required is not isolated; the spec setting matches the
pattern of every working Splunk-shipped modular input. Verified live: splunkd logs "Found
external scheme definition ... parameters=max_jobs_per_run" and runs the worker
with python3.13. A KV Store `503` (not ready during startup) ends the run
quietly; the next interval retries.

## D-016 Raw provider records stored as JSON text
**Context.** KV Store rejects documents with `$` or `.` in any key (live:
HTTP 400 "Document may not contain '$' or '.' in keys"). Every Fenre record has
a top-level `$schema`, and upstream keys are untrusted anyway.
**Decision.** `uc_content.raw_json` holds the record as canonical JSON text
(`repositories.encode_raw` / `decode_raw`); nothing upstream-controlled becomes
a KV key. The in-memory test store enforces the same rule so unit tests catch
regressions.

## D-017 Regulation ids come from `obligationRef`
**Context.** In upstream 8.28.0, `compliance[].regulation` mixes registry ids
and display names: 114 distinct strings (for example `NIST-800-53` and
`nist-800-53`, `Cyber Essentials` and `uk-cyber-essentials`) where
`obligationRef` (`<id>@<version>#<clause>`, present on every entry) has 81
consistent ids. Some records list the same obligation twice under both names.
**Decision.** The framework id is `regulation:<id from obligationRef>`, with a
slugified `regulation` as fallback; the original label is kept in
`attributes.regulation_label`. Mappings are de-duplicated on
(regulation, clause, version). Normalizer version bumped to `fenre-1.1.0`,
which re-normalizes stored content on the next sync without downloads
(verified live: 140 records re-normalized, 0 fetched).

## D-018 Partial bundles never withdraw records
**Context.** A bundle built for selected records (`--records`) lists only part
of a category; the category-level sync would have marked every other record
`withdrawn`.
**Decision.** The bundle builder sets `"partial": true` when records are
filtered; `ProviderManifest.partial` disables withdrawal. Full-category
bundles and remote sync keep withdrawal semantics.

## D-019 Packaging constraints from AppInspect
`collections.conf` declares multi-valued fields as `string` (AppInspect allows
only `number`, `bool`, `string` and `time`; with `enforceTypes = false` the KV
Store still stores and matches arrays, verified live). `app.conf` has an `[id]`
stanza; `server.conf` replicates `ucm.conf` on search head clusters. The
packaged app contains no process spawning and no unverified-TLS code; the
splunkd HTTP transport for tools and tests lives in `tools/`. AppInspect
4.4.0 (precert, cloud tags): 0 failures, 0 errors.

## D-020 Metadata via management REST, counts via constructed tstats
**Context.** The WP2 spec named `| rest` for indexes/apps/data models and
`tstats` for index/sourcetype counts. `| rest /services/data/indexes` is a
search wrapping the management endpoint.
**Decision.** Index, app and data-model metadata are read with GET
`/services/data/indexes`, `/services/apps/local` and `/services/data/models`
(verified on Splunk 10.2.9). Event counts use a generating `| tstats count
min(_time) as first_time max(_time) as last_time where (index=a OR index=b)
earliest=-7d latest=now by index, sourcetype` over **validated** index names
from that listing, chunked at 40 indexes, with `max_pairs` and a search
timeout. Imported SPL is never interpolated. `index=*` is not used.
Internal indexes are excluded unless `include_internal` is true. Metric
indexes are recorded from REST but not sent to `tstats`.

## D-021 Discovery jobs run in the existing modular input
Discovery jobs (`doc_type=discovery_job`) are queued like content sync jobs
and executed by `ucm_sync_worker` after the worker is idle of content work.
They use the modular-input session (typically admin) so results reflect that
identity's index permissions; the requester is recorded on the job and in
the audit log. On a search head cluster only the captain runs them (same
leader gate as content sync; SHC still unvalidated).

## D-022 Local mappings are never overwritten by discovery
Auto mappings (`auto_exact` / `auto_heuristic`) match discovered values to
catalogue fields and are labelled medium/low confidence. A mapping with
`origin=local` is left untouched. Auto mappings cannot be deleted; create a
local override instead. Presence of a source is inventory evidence, and not a
readiness score (WP3).

## D-023 Discovery records knowledge objects; absence is only proven by complete searches
Readiness needs macros, lookups and eventtypes (derived from SPL) and the
Splunk version. Discovery therefore also lists `/servicesNS/-/-/admin/macros`,
`data/transforms/lookups`, `data/lookup-table-files`, `saved/eventtypes`
(name, app, sharing) and `server/info` version, and stores **all** enabled apps
(not only add-on-like ones) so premium products and add-ons can be matched.
Fix carried in WP3: an index/sourcetype pair is marked `missing` only if its
index was in a `tstats` chunk that succeeded and the result was not
truncated. Before, a failed chunk would have marked healthy sources missing.

## D-024 Readiness scoring and veto
* Statuses: `met` (1.0), `partial` (0.5, e.g. stale data, add-on below
  minimum version, app-scoped macro), `not_met` (0), `unknown` (0, evaluator
  could not decide), `unverified` (type not checkable from inventory: fields,
  event conditions, permissions, SPL validity other than "no SPL") and
  `not_applicable`.
* Weight = level (critical 3, required 2, recommended 1, informational 0) x
  confidence (high 1.0, medium 0.75, low 0.5), so SPL-derived hypotheses count
  less than provider-structured requirements.
* Score = weighted mean over scored requirements; `unverified` and zero-weight
  requirements are excluded and reported (`unverified` count). Coverage =
  share of scored weight with a decided status (not `unknown`).
* **Veto:** any `critical` requirement `not_met` ⇒ `blocked`, whatever the
  score. A `required` requirement `not_met` prevents `ready`.
* States: `blocked`; `insufficient_evidence` (no scored requirement or
  coverage < `min_coverage`); `ready` (score ≥ 90 and no unmet required);
  `partially_ready` (≥ 50); `not_ready`. Thresholds in `ucm.conf [readiness]`.
* "Ready" means inventory evidence only. The UI states this and shows the
  number of unverified requirements; WP4 adds field sampling and SPL checks.
* Data model presence is "met" for `cim_model` (definition installed);
  populated data is not verified. Acceleration is a separate requirement.

## D-025 Assessment execution, freshness and capability
* Full assessment runs as a job (`doc_type=readiness_job`) in
  `ucm_sync_worker` after content sync and discovery are idle. The environment
  is loaded once per job; ~0.5 ms CPU per use case (16k in ~8 s CPU, measured
  in memory); KV Store I/O dominates.
* `auto_assess` (default on) queues a job when discovery or content sync
  completed after the last assessment; a failed job is not retried until new
  discovery or content arrives.
* Single use cases can be assessed synchronously from the detail page.
* Results record `discovery_at`, `source_hash` and `engine_version`; a read
  flags them `stale` (`newer_discovery`, `content_changed`, `engine_upgraded`).
* Running assessments reuses `ucm_run_discovery` (no new capability):
  assessment reads only app-owned data and dispatches no searches.
* Readiness for withdrawn or removed use cases is deleted at the end of a
  full run.

## D-026 SPL is parsed with Splunk's search/parser; dispatch is opt-in
`POST /services/search/parser?parse_only=true` is the syntax authority
(verified on 10.2.9). A leading `index=` is not a command; candidates tried
in order are the original string then `search ` + original, so
`` `comment(...)` | multisearch `` and `index=... | stats` both parse.
Imported SPL is dispatched only by **preview**, and only after:
* the parser accepted it, and
* neither the parser command list nor the static analyser reports
  side-effect commands (`delete`, `outputlookup`, `collect`, `script`, …).
Preview forces `earliest_time`/`latest_time`, a row limit (D-037) and a timeout.
*Amended in 0.7.2:* validation parses (primary and CIM SPL) with
`app=sunavigator` and preview dispatches through
`/servicesNS/nobody/sunavigator/search/jobs`, the namespace deployment parses
in and the saved search runs in. Before, an app-scoped macro failed to parse
in validation yet parsed at deploy (verified on 10.2.9). The search still runs
as the caller. The Search app's `comment(1)` macro is not exported, and 277
upstream primary searches use it, so the app ships the same no-op
`comment(1)` in `default/macros.conf`, not exported.
Event payloads are not stored; only counts, field names and messages.
A runtime error (missing lookup) is recorded on the validation document
(`preview.ok=false`), not raised as a 5xx.

## D-027 Field sampling uses a constructed fieldsummary, not imported SPL
For each required field, the app runs
`| search index=<validated> sourcetype="<validated>" | head N | fieldsummary`
over at most a few active index/sourcetype pairs from discovery. The
imported pipeline is never used for sampling. Presence updates readiness
(`met` / `not_met`); if no active sourcetype exists the field stays
`unverified`. `spl_validity` is injected at assessment time for use cases
that have primary SPL (not stored in the provider record).

**Amendment (T-06).** The sample is
`| search index=… sourcetype="…" | head N | eval sun_sample_marker=1 | fields sun_sample_marker "<f1>" … | fieldsummary`.
- The time window is the `[validation] sample_window_minutes` (default 60)
  that ends at the newest event discovery recorded for the pair, so a
  sourcetype that last sent data hours ago is sampled where its events are.
  A pair without a recorded last event falls back to `[validation] earliest/latest`.
- `fields` restricts the summary to the requested fields (names validated
  against `[\w.\-]{1,100}`), so the result has at most one row per field and
  cannot be truncated by unrelated fields. `fields` hides `_time` from
  `fieldsummary`; the marker field counts the sampled events instead.
- A field is `not_met` (`sampled_absent`) only when at least one pair returned
  a complete sample that held events. A window with no events gives
  `unverified` / `sample_empty`, like `sample_truncated` and `sample_failed`.
Measured on 10.2.9: an idle test sourcetype three hours old reads
`sample_empty` with the old 15-minute window and `present` with the anchored one.

## D-028 Deployed searches are owned by the deploying user
*Superseded by D-051 (0.7.3+): the owner is `[deployment] scheduled_owner`.*
**Context.** Saved searches created through `/servicesNS/nobody/<app>/saved/searches`
are owned by the caller (verified on 10.2.9). Changing the owner to `nobody`
needs `admin_all_objects` ("You do not have permission to change the owner").
A search owned by `nobody` runs as `splunk-system-user`, which would let an
operator schedule a search with more access than they have.
**Decision.** The saved search is written with the operator's session and
stays owned by them (`sharing = app`). `metadata/default.meta [savedsearches]`
gives `ucm_deployment_operator` and `ucm_admin` write access in this app, and
the role gets `schedule_search` (the `user` role on Splunk 10 does not have
it; without it Splunk rejects `alert.*` arguments). The deployment record
shows the observed owner. An admin can reassign ownership in Splunk.
**Consequences.** A search stops (orphaned) if its owner is removed; the
verifier reports the owner so this is visible. Deployment operators can also
edit saved searches of this app directly in Splunk; such edits are reported
as drift.

## D-029 Deployment workflow: four eyes, frozen SPL, disabled first
* One `uc_deployments` document per use case: workflow `state` of the latest
  revision (`draft → pending_approval → approved → deployed`, plus `rejected`,
  `failed`, `retired`) and the observed saved-search status `live`
  (`absent`, `disabled`, `enabled`, `missing`, `unmanaged`) with drift.
* A revision copies the SPL (primary, CIM or a custom edit) and schedule. The
  approved text is what gets deployed; later upstream changes only raise a
  `content_changed` flag.
* Drafts are parsed with `/services/search/parser`; submit, approve and
  deploy refuse unparsable SPL and side-effect commands (D-026). Deploy
  re-parses.
* The submitter cannot approve their own revision unless
  `allow_self_approval = true`; `require_approval = false` auto-approves on
  submit (recorded as `approval: not_required`).
* *Scope (T-09).* Four eyes applies to the app's workflow. The deployed saved
  search is owned by the deploying operator (D-028), who, like any admin, can
  edit it in Splunk directly. The verifier reports such edits as drift; it
  does not prevent them. Restricting saved-search write access is a
  deployment-level control outside the app.
* Every deploy and rollback writes the search **disabled**; enabling is a
  separate action. Enabling while readiness is in `block_enable_states`
  (default `blocked`) needs an override reason of at least 10 characters,
  which is stored in the audit record.
* After every write the saved search is read back and compared (search hash,
  cron, time window, scheduled, disabled, no alert actions). A mismatch marks
  the deployment `failed` and disables the search.
* The app only modifies saved searches whose description carries its marker
  and content id; an existing search with the same name is never overwritten
  (`name_conflict`).
* Alerts add to Triggered Alerts only (`alert.track`); email, webhook or
  script actions are not configured by the app.
* `uc_deployments` is writable only by `admin`/`sc_admin`; the REST handler
  writes it with the system token after the capability check, so analysts and
  operators cannot forge approvals through the KV REST API (verified live).
  KV Store has no compare-and-swap; a `version` counter re-read before each
  write rejects most concurrent edits.
* The worker re-verifies deployed searches every `verify_interval_minutes`
  (default 60) and audits only changes.

## D-030 Framework definitions are versioned files, not upstream feeds
* Frameworks use a compact format `ucm.framework/1`: tactics, techniques
  (with parent for sub-techniques), `revoked` (old id → replacement) and
  `deprecated` ids. `tools/attack_builder.py` reduces a MITRE STIX bundle to
  this format.
* MITRE ATT&CK Enterprise and ICS 20.1 ship in
  `lib/splunk_ucm/frameworks/data/` with MITRE's attribution. No network
  fetch is needed and nothing is fetched at runtime.
* Content managers (`ucm_manage_content`) can import another version as JSON
  (at most 5 MB, strictly validated) and choose which version is active per
  framework. Imported versions live in `uc_frameworks`, written with the
  system token after the capability check; bundled versions cannot be
  overwritten.
* Catalogue mappings are resolved against the chosen version: revoked ids
  count towards their replacement and are listed as remapped; deprecated and
  unknown ids are listed as unresolved, not counted. A sub-technique mapping
  also counts towards its parent, once per use case.
* Regulations and other frameworks have no bundled control catalogue; their
  coverage is computed from the catalogue's own mappings
  (`framework_controls`, summary version 2).

## D-031 Coverage levels and run status
* Each active use case has one level: `catalogue` < `ready` (readiness state
  `ready`) < `deployed` (deployed revision, search disabled) < `enabled` <
  `operational`. A technique or control takes the best level of its use cases.
* `operational` needs scheduler evidence: a constructed search over
  `index=_internal sourcetype=scheduler` for this app's `SUN - *` searches in
  a chosen window (1 h to 7 d), run with the caller's token. An enabled search
  whose last run succeeded is operational; no runs is `no_runs`; failures or
  skips are `unhealthy`.
* Roles that cannot read `_internal` get `available: false` with a reason
  instead of misleading "no runs": when the scheduler search returns nothing,
  a `tstats count` probe over the last hour checks that `_internal` is
  visible (splunkd always writes to it). Verified live with `ucm_viewer` and
  `ucm_deployment_operator`, which do not search `_internal` by default.

## D-032 Generated dashboards come from fixed templates
* Templates (`domain_overview`, `deployed_searches`) render Simple XML in
  code. Parameters are validated against allowlists (the domain list) and
  every value is XML-escaped; imported text appears only as escaped labels and
  saved-search references (`<search ref>`), never as SPL.
* Views are named `ucm_gen_<template>_<domain|all>`, written to this app with
  the system token by users holding `ucm_deploy`, and carry a "Generated by
  SUNavigator" marker. An existing view without the marker is
  never overwritten (`name_conflict`), and only views recorded in
  `uc_dashboards` can be deleted.
* A static `ucm_domain` dashboard covers the common case without generating
  anything; it reads the app's KV Store lookups.

## D-033 Upgrades run as versioned migrations in the worker
* App state lives in `uc_sync_state` under `app::state`
  (`doc_type: app_state`, `state_schema`, `applied[]`, `app_version`,
  `previous_app_version`, `upgraded_at`, `last_migration`,
  `last_migration_at`).
* `maintenance/migrations.py` holds an ordered list of migrations. Each has
  an id, a check and an apply step; ids are never reused or reordered. The
  worker runs pending migrations before any other job, re-checks each one
  (so a fresh install records it as `not_needed`) and audits it
  (`app.migration`).
* `0001_catalog_summary_v2` re-derives catalogue summaries older than
  `SUMMARY_VERSION` from the stored raw records, without network access.
  Verified live: 0.4.0 package → 0.7.0 package upgraded 164 summaries within
  one worker interval, and `local/ucm.conf` was kept.
* Downgrades are not supported. Splunk drops a KV collection's data when its
  `collections.conf` stanza disappears, so installing a version older than
  the one that introduced a collection loses that collection (observed live
  for `uc_deployments` on 0.4.0). Saved searches written by the app survive
  as unmanaged searches and must be removed or re-adopted by hand.

## D-034 Retention is enforced by the worker
* `[retention]`: `audit_days` (default 365, 0 keeps forever), `job_history`
  (finished jobs kept per type, default 50) and `interval_hours` (default 24).
* Purges delete audit records older than the cutoff with one KV delete query,
  and the oldest finished jobs beyond `job_history` per job type. Queued and
  running jobs are never deleted. Each purge that removes something writes a
  `retention.purged` audit record.
* Services still trim job history at write time (sync 200, discovery and
  readiness 50); these act as upper bounds.

## D-035 Leader election and RBAC review
* All background jobs (maintenance, sync, discovery, readiness, deployment
  verification) run only where `_leader()` is not `False`: a standalone
  search head (member/info returns 404, 503 or 400), or the SHC member whose
  label equals the captain's label. When splunkd cannot answer, the result
  is unknown and the worker runs, so a broken probe never stops a single
  instance; on a cluster this can duplicate a run, which every job tolerates
  (idempotent upserts and per-provider job guards). Covered by unit tests
  with simulated member/captain responses; not validated on a real cluster.
* RBAC review: a unit test calls every POST route as a user without app
  capabilities. All return 403 except the caller-scoped ones (selections and
  dashboard preview). Every GET is open to app users except audit and the
  provider manifest. Collections written for other users (`uc_audit`,
  `uc_deployments`, `uc_frameworks`, `uc_dashboards`) are writable only by
  `admin`/`sc_admin` and written by the handler with the system token.

## D-036 Product name SUNavigator; app ID changes in 0.7.1
* The product is named SUNavigator (short for Splunk use case navigator). The
  app ID, folder and package become `sunavigator`. Splunk treats that as a new
  app, so 0.7.1 is not an in-place upgrade of `splunk_use_case_manager`
  (operator guide §8).
* Internal identifiers keep the `ucm` prefix: `ucm.conf`, `/services/ucm`,
  `UCM_*` variables, the `splunk_ucm` package, `ucm_*` views and `uc_*`
  collections. Renaming them would change REST and config contracts without a
  user-visible benefit.
* Deployed saved searches are named `SUN - <id> - <title>`. Generated
  dashboards and managed markers say SUNavigator. The secret realm follows
  `APP_NAME`.

## D-037 Oneshot result contract: exact limit, explicit truncation
*0.7.2. Supersedes the row-count inference in D-023 and D-026.*
* Measured on 10.2.9: `POST search/jobs exec_mode=oneshot` returns `count`
  rows (default **100**) whatever `max_count` says; `max_count` bounds only
  the events an event search retains; nothing above `[restapi] maxresultrows`
  (50000) is returned. Before 0.7.2 the client sent no `count` and inferred
  truncation from `len(rows) >= max_count`, so results were cut at 100 rows
  and reported complete. Discovery then dropped pairs and marked them
  `missing`, and run status and field sampling were capped the same way.
* `SearchClient` sends `count` and `max_count` as limit + 1 (limit clamped
  below `maxresultrows`), returns at most `limit` rows and sets `truncated`
  only when the extra row arrived. No server-side job statistics are needed.
* Consumers: discovery marks nothing missing after a truncated run (D-023);
  run status reports `truncated` and shows searches without a row as
  `unknown`; field sampling reports a field absent only from a complete
  sample. A truncated or failed sample makes the field `unverified`
  (`sample_truncated`, `sample_failed`). The inventory and coverage views
  show the truncation.

## D-038 SPL execution policy: allowlist, indirect execution, acknowledgment
*0.7.2. Extends D-026 and D-028. Operator decision D3 (a).*
* Every command is classified. **Side-effect** (denylist; adds
  `summaryindex`, `dbxoutput`, `runshellscript`, `deletemodel`, `dump`,
  `crawl`, `outputtelemetry` and `fit … into`): preview, submit and deploy
  refuse, as before. **Indirect** (`map`, `savedsearch`, `loadjob`, `rest`,
  `dbxquery`, `dbxlookup`, `savedsearch:` datasets): runs SPL or reaches data
  the search text does not show. **Unknown**: not on the built-in read-only
  allowlist (custom and add-on commands such as MLTK `apply`).
* Indirect and unknown commands ("review commands") refuse preview. Approval
  needs `acknowledge_commands=true`. The acknowledged list and approver are
  stored on the revision and in the audit record. Without approval
  (`require_approval = false`), the submitter acknowledges at submit. Deploy
  re-parses and refuses when the search now has review commands nobody
  acknowledged, for example after a macro changed.
* Commands are taken from the raw SPL (static analysis sees subsearches) and
  from the pipeline Splunk's parser returns, which has macros expanded,
  including macros inside subsearches. Before 0.7.2 only the parser's top-level
  command names were used, so `outputlookup` in a macro inside a subsearch
  passed the gate (verified on 10.2.9).
* Splunk's parser rejects unknown commands, including those in subsearches. So
  when the whole search parses, an unknown name that only static analysis
  reported is kept only if a one-command probe (`| makeresults | <name>`) does
  not say "Unknown search command". This drops tokenisation artefacts such
  as `$tok|s$` and never drops a command Splunk can run.
* `[spl] extra_safe_commands` in ucm.conf adds trusted read-only commands to
  the allowlist; side-effect and indirect names in it are ignored.
* Readiness: a parsed search with review commands is `partial`
  (`review_commands`) for the SPL-validity requirement, like side effects.
* Measured against the upstream catalogue (19,771 searches, static pass): 128
  flagged. Of those, 42 use `rest`, 12 `map`, 6 `dbxquery` and 14 MLTK `apply`;
  24 `collect` and 18 `fit … into` are side effects.
* Scripted and external lookups execute code through `lookup`. They are out
  of scope here; the lookup definition, not the search, is the control point.

## D-039 Evidence and job collections are written with the system token
*0.7.2. Extends the D-028 pattern to readiness, validation, discovery and jobs.*
* Before 0.7.2, `ucm_analyst` (and `ucm_admin`, `ucm_content_manager` for
  jobs) could write `uc_readiness`, `uc_validation`,
  `uc_environment_sources`, `uc_source_mappings` and `uc_sync_state` directly
  through the KV REST API. That let them lift the readiness gate on enable,
  forge validation evidence or inventory, and enqueue jobs with arbitrary
  parameters for the worker, which runs as the system user.
* These collections are now writable only by `admin` / `sc_admin`. The REST
  handler's `Context` gives the sync, discovery, readiness, validation and
  mapping services the system-token store (`records()`). Every handler that
  writes checks the capability first. Searches (parse, preview, field
  sampling, discovery dispatch) still run with the caller's session, so
  nobody sees data they could not search themselves.
* Workers check each queued job's structure before running it (`storage/jobs.py`:
  type, id/key, requester, source, provider, categories, ref, flags, time
  bounds). A malformed job is failed with `invalid_job` and audited.
* `uc_selections` stays user-writable: it is per-user intent, not evidence.
  Provider collections stay writable by content managers (known limitation in
  SECURITY.md).

## D-040 Fields the search produces are not raw-data requirements
*0.7.3 (T-05, finding F-02). Normalizer `fenre-1.2.0`.*
* Provider `requiredFields` mix raw fields with fields the search creates
  (`eval age_days=…`, `stats count as failures`, `rename src_ip as src`,
  `rex "(?<user>…)"`, `spath output=…`, `lookup … OUTPUT owner`). Sampling raw
  events for created fields reported them missing; in the readiness corpus
  19 of 74 requirements were false `not_met` for this reason alone.
* The static analyser records, per produced name, the first command that
  creates it and whether the name is read earlier (in an earlier command, or
  in the producing command itself, as in `eval user=lower(user)`). Values after
  `=` in search clauses are literals, not reads.
* A required field that is produced and not read before is kept, as
  `informational`, confidence `medium`, attribute `derived_in_spl: <command>`.
  It is not sampled; readiness reports it `not_applicable` (`derived_in_spl`).
  A field read before it is produced stays `required` / `high`: the raw data
  must carry it.
* Static analysis only. Fields created by macros, `inputlookup`, `extract`,
  `kv`, `foreach` or wildcard renames are not recognised and stay required.
* Migration `0002_normalizer_fenre-1.2.0` re-derives catalogue summaries from
  stored raw records (no network). Readiness always re-normalizes stored raw
  records, so the next readiness run uses the new requirements.
* Corpus delta: false `not_met` from derived fields 19 → 0; ready cases
  falsely not ready 9 → 2 (the two OR / IN sourcetype cases, T-07).

## D-041 Alternative sourcetypes in one search clause are an any-of group
*0.7.3 (T-07, finding F-03). Readiness engine `ucm.readiness/2`.*
* An event has one sourcetype, so several positive sourcetype constraints in
  one search clause (`sourcetype=A OR sourcetype=B`, `sourcetype IN (A, B)`,
  also inside `tstats … where`) can only be alternatives. Clauses in
  subsearches, `join`, `append` and `multisearch` are separate: each of their
  sourcetypes is needed (all-of).
* The normalizer gives each member the attribute `any_of: [A, B]`. If a member
  is also the only sourcetype of another clause, it stays required on its own
  and the other members become `recommended` ("alternative to …").
* Scoring collapses a group to its best member (met > partial > unverified >
  unknown > not_applicable > not_met). The others are marked `collapsed` and
  are left out of the score, counts and gaps. A group with no member present is
  one gap, "any of A, B".
* Static analysis only: groups built by macros, eventtypes or tags are not
  recognised. `NOT sourcetype IN (…)` is not detected as negated (existing
  limitation of the analyser).
* Corpus delta: OR / IN cases falsely not ready 2 → 0; every metric is now 0.
  The none-present OR case scores 50 instead of 33 (still `partially_ready`,
  not ready).

## D-042 Scheduling defaults, schedule window and suppression
*0.7.3+ (T-10, finding F-14).*
* New drafts default to `-20m@m` → `-5m@m` instead of `-15m` → `now`. The
  window matches the default 15-minute cron, is snapped to the minute so runs
  do not overlap or leave gaps, and ends 5 minutes ago so events that arrive
  late are still searched.
* Each revision records `schedule_window` (`auto` or 0–1440 minutes, default
  `[deployment] default_schedule_window = auto`) so a busy scheduler delays the
  search instead of skipping it.
* Alerts (`alert_mode = track`) can set suppression: `suppress_period`
  (`30m`, `1h`, `1d`) and optional `suppress_fields` (up to 10 names).
  Written as `alert.suppress`, `alert.suppress.period`, `alert.suppress.fields`.
  Scheduled reports reject suppression. No suppression writes
  `alert.suppress = 0`.
* Revisions record `spl_time_bounds` when the SPL sets `earliest`/`latest`
  itself; the card warns because that overrides the scheduled range. It is a
  warning, not a block.
* Drift checks the new keys only for revisions that have them. Revisions
  frozen before this change keep Splunk's values and show no new drift.
  Splunk keeps period and fields when suppression is off, so they are compared
  only while suppression is on.

## D-043 Which upstream refs a sync may use
*0.7.3+ (T-12, finding F-13).*
* `[provider:fenre] allowed_refs` (default `main`) lists the branch and tag
  names a sync or manifest request may use; `*` is a wildcard. The configured
  `ref` is always allowed when it is a name, so an empty list means "the
  configured ref only".
* A name outside the list is refused by the REST handler and again by the
  provider, with no network request.
* A 40-character commit is accepted only if `GET compare/<allowed>...<sha>`
  returns `identical` or `behind` for one of the listed names without a
  wildcard, i.e. the commit is an ancestor of that branch or tag. Otherwise it
  is refused before any tree or blob is fetched. Wildcard entries cannot
  vouch for a commit: there is no single ref to compare against.
* Rate limiting during the check is reported as rate limiting, not as an
  unreachable commit. Other compare errors (404, size cap) count as "not
  reachable from this ref".
* The Content admin page posts the commit its manifest resolved, so each
  manual sync costs one compare call. Offline bundles are not affected.
* Verified against GitHub: an old `main` commit and tips of merged branches
  are accepted; the tip of an unmerged (diverged) branch is refused.

## D-044 The environment inventory is shared app metadata
*0.7.3+ (T-13, finding F-14, decision D2 = b).*
* Index and sourcetype names, counts, times, installed apps, data models,
  knowledge objects, source mappings, readiness evidence and validation
  results are readable by every user who can open the app, through the views,
  the REST API and the KV collections. They are not filtered by the caller's
  index permissions: discovery runs as the system user.
* Accepted because the app is installed for the people who plan detection
  coverage, and index names already appear in imported SPL. SECURITY.md lists
  exactly what is visible and how to restrict who can open the app.
* Field sampling no longer keeps example values (it kept up to three per
  field, 80 characters each, in `uc_validation` and copied them into readiness
  evidence). Those were event contents, not metadata, and no view showed them.
  Samples keep presence, counts and the index / sourcetype only. Existing
  documents lose the values the next time a use case is sampled.
* Not chosen: option (a), redacting names for viewers. It would need
  per-caller filtering in inventory, readiness, validation and detail
  responses and tighter collection ACLs.

## D-045 Compliance substance and imported fields on the use-case page
*0.7.3+ (T-14, findings F-22 to F-24). Normalizer `fenre-1.3.0`.*
* Regulation mappings keep, per clause: `control_objective`,
  `evidence_artifact`, `assurance_rationale`, `sme_caveat` (each capped at
  4,000 characters), `requires_sme_review` (booleans only) and `clause_url`
  (absolute http/https only; anything else is dropped).
* New canonical fields: `wave` (`crawl`, `walk`, `run`; other values dropped),
  `control_test` (the five schema keys, strings only), `exclusions`,
  `equipment` (also still in `tags`) and `hardware` (free text, not a tag,
  because upstream writes sentences there).
* Every remaining provider field (for example `evidence`,
  `grandmaExplanation`, `owner`, `cost`) is listed verbatim under
  "Other provider fields", rendered as text only.
* The detail view normalizes from the stored raw record on read, so the new
  fields appear without re-downloading. The normalizer bump runs the existing
  reindex migration for catalogue summaries once (verified on the lab: 122
  summaries moved to `fenre-1.3.0`).
* Upstream measurement (16,726 records): every compliance entry has the
  objective, evidence and rationale; 679 of 3,870 have a `clauseUrl`; 3,256
  carry `requires_sme_review`.

## D-046 Content quality flags
*0.7.3+ (T-15, finding F-25). Normalizer `fenre-1.4.0`, catalogue summary v3.*
* Flags are deterministic and derived from the provider record only:
  `unreviewed` (status missing or `draft`), `reviewer_na` (reviewer "N/A"),
  `ai_reviewed` (reviewer names an AI or agent: ai, llm, gpt, copilot, cursor,
  claude, anthropic, openai, gemini, agent-…, auto-generated/drafted, bot),
  `sme_review_pending` (a regulation mapping with `requires_sme_review`),
  `unbounded_index` (the analyser's existing `index=*` / no-index result),
  `es_required` (Enterprise Security in `premiumApps`, unless its note starts
  with "optional"). They are stored in `uc_catalog.quality_flags`, shown as
  badges and filterable (`GET catalog?quality=<flag>`).
* `duplicate_spl` needs the whole catalogue: summaries store a SHA-256 of the
  whitespace-normalized primary SPL (`spl_hash`), and a post-pass after every
  sync, offline import and reindex flags active records sharing a hash.
  Withdrawn records neither count nor keep the flag.
* Upstream measurement (16,726 records): reviewer N/A 161, AI reviewer 304
  (134 distinct strings; reviewer strings without an AI marker such as
  "documentation-only editorial review …" are not flagged), `index=*` 17,
  Enterprise Security listed 3,085, 756 records in 103 duplicate-SPL groups.
* Verified on the lab with 16 category 22 records imported from a bundle: each
  flag filter returned exactly the expected records.
* Not covered: ES dependencies only visible in SPL (notable or risk indexes)
  and near-duplicate SPL.

## D-047 Catalogue search, review and regulation filters, facets
*0.7.3+ (T-16, findings F-26 and F-27). Catalogue summary v4.*
* Search also matches the first 1,500 characters of the description
  (whitespace collapsed), still as a case-insensitive substring over one
  precomputed field per record. The cap keeps summary documents small; terms
  only later in a long description are not found.
* New filters: review status (`GET catalog?review=<status>`, repeatable) and
  regulation (`GET catalog?regulation=<id>`, matching the `regulation:<id>`
  framework tag). Values must match `^[a-z0-9][a-z0-9._-]{0,79}$`; anything
  else is a 400.
* `GET catalog/facets` returns the review statuses, regulations (with labels)
  and quality flags present in the active catalogue, with counts. It is
  computed in the same post-pass as duplicate SPL (after every sync, offline
  import and reindex) and stored in `uc_sync_state` as `catalog::facets`;
  when the document is missing it is computed on request.
* `[expose:ucm_api_catalog]` in `web.conf` allowed only POST, so the
  catalogue page could not reach `catalog/facets` through Splunk Web. It now
  allows GET and POST, and a unit test checks every REST route against the
  `web.conf` expose patterns.
* Verified on the lab (138 records): 26 regulations offered, FedRAMP 4 use
  cases, FedRAMP + verified 3, `q=pipeline` 7 including description matches.

## D-048 Add-on detection: package ids and a verified Splunkbase list
*0.7.3+ (T-17, finding F-19). Readiness engine `ucm.readiness/3`, catalogue summary v5.*
* Investigation: `/services/apps/local` exposes folder name, label, version
  and `details`. `details` is `https://apps.splunk.com/apps/id/<package id>`,
  built from `[package] id` in `app.conf` (verified on 10.2.9 with a renamed
  probe app). No installed-app field carries the numeric Splunkbase id, so
  the static id map cannot be replaced, only extended.
* Discovery stores the package id (`package_id`) for every app. Readiness,
  the use-case "present in environment" overlay and the inventory coverage
  cards now share one matcher (`discovery/apps.py`): folder name, package id
  or label, then a local `addon` mapping. Evidence rows record `matched_by`.
* `SPLUNKBASE_APPS` grew from 5 to 32 ids. Each entry's package id and title
  were read from `https://splunkbase.splunk.com/api/v1/app/<id>/` and kept
  only when the provider's add-on name agrees with the Splunkbase title.
* Upstream measurement (16,726 records, 2,870 add-on references to 65 ids):
  32 ids (2,705 references) agree with Splunkbase. 26 ids (152 references)
  name a different app, for example 4467 "Splunk Connect for Kubernetes" is
  Docker Simple, 4413 "Splunk SOAR" is Puppet Report Viewer, 5680 "Oracle
  Cloud Infrastructure" is a Windows performance app. 7 ids (13 references)
  do not exist. Those references are matched by name only, so an unrelated
  app is never reported as the required add-on.
* The upstream `data/splunkbase-catalog.json` was not used: it omits archived
  apps (29 of the 65 ids) and lists the ES installer rather than
  `SplunkEnterpriseSecuritySuite`.
* No network access at runtime; the list changes only with an app release.

## D-049 Clause-level compliance view and evidence pack
*0.7.3+ (T-18).*
* Chain: regulation → clause → use case → readiness → deployment. Rows join
  the catalogue (active use cases), the mapping substance normalized from
  the stored raw record (mode, assurance, objective, evidence artifact,
  rationale, clause link, SME flag), `uc_readiness` (state, score, evaluated
  time, staleness by the same rules as the readiness API) and
  `uc_deployments` (state, live status, saved search, deployed revision,
  drift). Provenance comes from the stored record.
* A clause is a gap when its best use-case level is below "data ready".
  The clause list (`frameworks/controls`) and the pack compute gaps from the
  same KV documents; a unit test recomputes them from raw collection queries.
* Determinism: rows are sorted by natural clause order, framework version
  and use-case id; JSON uses sorted keys and fixed separators; CSV uses a
  fixed column list and CRLF line ends. No wall-clock time is included, so
  the same state yields the same bytes and SHA-256 (verified on the lab:
  the downloaded file hashes to the value the page reports).
* Long text is capped at 4,000 characters per cell, the normalizer's own
  cap. CSV cells that a spreadsheet would treat as a formula get a leading
  apostrophe.
* Readable by every app user (D-044): the pack contains catalogue,
  readiness and deployment state that the views already show. It is a read,
  so it is not audited.
* Cost: about 0.45 s in memory for NIST 800-53 upstream (1,194 use cases,
  1,214 rows, 116 clauses, 0.9 MB CSV). Content is read in batches of 200;
  a regulation with more than 5,000 use cases is refused with a hint to
  export per clause.
* Not covered: clauses that no imported use case maps to (no bundled clause
  catalogue), and attestation or sign-off workflow.

## D-050 ATT&CK Navigator layer export
*0.7.3+ (T-24).*
* `GET frameworks/navigator` turns the coverage matrix into a Navigator layer
  (format 4.5, Navigator 5.1.0, `versions.attack` = the major version of the
  selected definition, `enterprise-attack` or `ics-attack`). Only techniques
  with a level are listed, sorted by id; score = level rank (1 = in
  catalogue), colour = the coverage page colour, comment = counts per level.
  Techniques are listed without a tactic, so a technique in several tactics
  is coloured in each.
* "Running successfully" is a level (and legend entry) only when run status
  is requested and available.
* Verified: the lab layer (41 techniques) loads in the public ATT&CK
  Navigator with no console errors and the expected colours.

## D-051 Deployed searches are owned by a dedicated scheduler account
*0.7.3+ (T-20). Supersedes D-028 for writes and ownership.*
* Operator direct edit was possible on the lab: a `ucm_deployment_operator`
  user could edit and delete a search the app had deployed, because the app
  ACL granted that role write access. The roadmap's acceptance was "operator
  direct edit refused".
* Writes now go through the REST handler's system token after its capability
  check (as the worker already did). `metadata/default.meta [savedsearches]`
  no longer grants `ucm_deployment_operator` write, and
  `ucm_deployment_operator` no longer gets `schedule_search`.
* Each write reassigns the owner to `[deployment] scheduled_owner` with
  `POST .../saved/searches/<name>/acl` (`owner`, `sharing=app`). The owner
  must hold `ucm_scheduler` (`importRoles = user`, `schedule_search`).
  Writes are refused until it is set. Drift reports an owner that differs.
* Why a dedicated account and not `nobody`: a search owned by `nobody` runs
  as `splunk-system-user` (D-028), which has far more rights than any
  operator. The scheduler account runs searches with the rights of one
  reviewed role. Alternatives considered: keeping the operator as owner
  (operators could then edit their own searches through the ACL they were
  given, and the system token would still have to create them).
* Verified on the lab (10.2.9): before the change the operator edited and
  deleted an app search (200). After it, edit returned 403 and delete was
  refused for a new search; the owner was changed to the scheduler account
  and the scheduler account can read its own search. The live lifecycle test
  asserts the owner, the 403 on edit, and that delete is not allowed.
* Not covered: an admin can still edit or reassign the searches (admins own
  Splunk), and the scheduler account's index access is whatever its role
  grants. Removing the scheduler account orphans its searches; `verify`
  reports the owner.

## D-052 Deterministic export of deployed revisions
*0.7.3+ (T-25).*
* Output: `savedsearches.conf` text plus a JSON manifest, built from the
  deployed revision of each deployment (approved by a reviewer, deployed at
  least once). Each stanza uses the same settings as the deploy path, with
  `disabled = 1` and the app's managed-search description. Stanzas sort by name;
  no export time is recorded; the same records always give the same bytes
  (unit-tested for order independence and live-state independence; live test
  checks the same bytes on two fetches).
* Why this shape: git-based review and diff without giving the export a second
  deployment path. The user commits the file; the app remains the only writer
  to Splunk. A zip or a Splunk package was not chosen because a zip needs a
  binary transport for one text file and the package would imply an owner the
  file cannot carry.
* `ucm.conf` writer and reader (`splunk_ucm/conf.py`) are stdlib. The writer
  refuses values that would not read back unchanged (a line ending in a
  backslash, a carriage return, leading or trailing whitespace on a line),
  so such use cases are listed as skipped instead of being written wrongly.
  Whitespace per SPL line is normalised; the manifest flags it.
* Audit: each export writes `deployment.export` with the count, skipped list and
  SHA-256 of the file.
* Web exposure: `default/web.conf` exposes `ucm/deployments/export` explicitly
  (the `ucm/deployment/*` pattern does not cover it).

## D-054 Control tests replay Fenre fixtures against the deployed search
*0.7.3+ (T-23).*
* Input: `samples/UC-<id>/positive.log` and `negative.log`, built with
  `tools/ucm_cli.py build-control-fixtures --samples <dir>` (94 use cases in the
  Fenre tree on 2026-11). The bundle (`ucm-control-fixtures/1`) is uploaded with
  `POST ucm/controltest/import` (content-manager capability). It is stored in
  `uc_control_fixtures` (admin write). A re-import replaces the fixtures of that
  provider; the `batch` hash decides what is stale.
* Action: `deployment/controltest` (deploy capability) runs on the **deployed**
  revision, not on the draft. The result is stored on the deployment as
  `control_test` and audited as `deployment.controltest`. It does not change
  workflow state or the saved search.
* Run: each fixture event is sent to `services/receivers/simple` in
  `[controltest] index` (default `ucm_controltest`) with the manifest sourcetype,
  host and a per-run `source` marker. The SPL's index filter is rewritten to
  `index=<test> source="<marker>"`. The positive run needs `expected.min_count`
  rows, the negative run needs none. Events that are not all searchable in time
  make the result inconclusive, not failed.
* Event boundaries: blank-line blocks when the file uses them, otherwise one
  line per event. All 94 samples meet their `min_count` under this rule.
* Time: the sample timestamps are fixed (April 2026). The search's own
  `earliest=`/`latest=` terms are removed from the test copy and the test window
  (`-10y` to `+1d`) is used. The logic is tested, not the production window.
* Refused without a run: searches that cannot be scoped to the test index
  (`tstats`, `datamodel`, `from`, `rest`, `mstats`, `map`, `savedsearch`,
  negated or list index filters, a `source=` filter, no index) and deployed
  searches with side effects. These report `not_runnable`. A search that errors
  on the test index is `inconclusive`.
* Why not HEC or a time-bounded search: the HEC token and port were not usable
  on the lab (HEC on 8088 unreachable; the token was rejected on 8089). The raw
  receiver cannot set event time, so each run is isolated by its marker, not by a
  time window. Events accumulate in the test index; retention is an operator
  setting.
* Lab result (Splunk 10.2.9, 2026-11-24): `fenre:UC-9.1.2` passed (2 rows for
  the positive fixture, the negative fixture is absent). `fenre:UC-1.1.1` failed:
  0 rows for 3 `cpu` events. The SPL filters `cpu=all` and computes
  `cpu_load_percent`, which the sample lines do not contain. The verdict is
  correct for the content as written; the sample and the SPL disagree on the
  data shape.
* Not covered: the verdict does not prove alerting, suppression, or the
  schedule. Only the 2 deployed use cases above were run on the lab; the
  remaining 92 fixtures were imported and not deployed.

## D-055 SHC captain detection on Splunk 10.2.9
*0.7.3+ (T-19).*
* Finding: on Splunk 10.2.9, `GET shcluster/member/info` no longer returns a
  `label`. `PlatformProbe.is_shc_captain()` returned `None` on every member, and
  `_leader()` treats `None` as "run". So every member ran the sync, discovery,
  readiness, maintenance and deployment-verify jobs, which are meant for the
  captain only (D-035).
* Fix: the member's name is `server/info` `serverName` when `member/info` has no
  label. SHC members must have unique server names, so the comparison with
  `captain/info` `label` is exact. Old splunkd builds that do return a label
  keep the old path.
* Validation (local three-member SHC, see T-19 below): captain `True`, members
  `False`, `False` after the fix; `None` on all three before it.
* Unknown still runs the job. That is deliberate for standalone instances and
  for splunkd errors, which keeps single instances working.

### T-19 SHC validation on this VM (lab only)
* Topology: three Splunk 10.2.9 copies of the lab install (`/opt/sh1`..`/opt/sh3`,
  ports 8100/8200/8300 web, 8189/8289/8389 management, 9887-9889 replication,
  8491/8591/8691 KV Store), one SHC `shc_sun`, replication factor 3, no deployer.
  The app was copied into each member (identical code, no deployer push).
* Results: the cluster formed with captain `sh1` and KV Store `ready` on all
  three. App REST answered on every member. An offline import on `sh1` was
  visible in the catalogue on `sh2` and `sh3`. A deployment drafted and
  submitted on `sh2`, approved on `sh3` and deployed on `sh2` appeared as a
  disabled saved search owned by `ucm_scheduler` on all three. A control test
  passed on `sh2` and `sh3`.
* Not validated: Splunk Cloud (no environment); a deployer-managed bundle push;
  real indexer peers (the members searched only their own indexes); scheduled
  execution of deployed searches across members; ESCU on the cluster.
* Blocked by the environment: none for the local SHC. The first attempt used the
  lab's default kvstore and appserver ports, which clash on one host; the copies
  use distinct ports.

## D-053 ESCU as an offline-bundle provider
*0.7.3+ (T-22).*
* Source: the Splunk ES Content Update package (`DA-ESS-ContentUpdate`, 6.11.1
  on the lab, 2,230 correlation searches, 16 deprecated). The package is conf
  files only, so the parser is stdlib (`splunk_ucm/conf.py`). No YAML.
* Shape: a `ucm-content-bundle` v1 (`provider = escu`), so the existing import,
  validation, withdrawal and reindex paths handle it. No remote transport: the
  release is fetched by the operator and built with
  `tools/ucm_cli.py build-escu-bundle` (directory or `.tar.gz`, read in memory,
  never extracted, size-capped). Splunkbase downloads need login (404
  anonymously), so the GitHub release asset is the documented source.
* Identity: `content_id = escu:UC-<detection_id>` (UUID). The content id regex
  accepts UUIDs now; the record id pattern for `escu` is a UUID.
* Categories: fixed ids (1 endpoint, 2 network, 3 threat, 4 identity,
  5 access, 6 audit, 7 unassigned) so keys stay stable across releases.
* Requirements: the derivation moved from the Fenre normalizer into
  `content/requirements.py` (no behaviour change; Fenre tests unchanged) so
  both providers use one implementation.
* Discovery: `DA-ESS-ContentUpdate` (Splunkbase 3449, title "Splunk ES Content
  Update") was added to the verified Splunkbase list (D-048).
* Validation: ESCU records go through the same validator (schema subset,
  id pattern, title, SPL size). Full package on the lab: 2,214 records, 0
  invalid, 0 warnings; reimport unchanged.
* Not covered: ESCU's own macro definitions are not imported (the installed
  ESCU app provides them); drilldowns, risk scores and the `fbd` finding-group
  settings are kept only as raw data in the stored record; `cis20`, `nist`,
  `cve` and kill-chain phases are kept in `provider_extras`, not mapped to a
  framework (no ATT&CK-style registry for them in the app).

## D-056 Usability: select-all, glossary and static-asset cache busting
*0.8.0.*
* Select all: the Content Administration category list gets a tri-state header
  checkbox, Select all / Deselect all and a count (`ucm.selectAll`). It only
  changes the checkboxes it was given and never a disabled one. It does not touch
  the separate "Re-download all records" and "Allow schema" options, so selecting
  categories cannot trigger a forced re-download.
* Glossary: one set of texts (`READINESS_HELP`, `STATUS_HELP`) in `ucm_common.js`
  feeds tooltips and legends on the Readiness and use-case pages. The wording
  follows `readiness/scoring.py` and `evaluators.py`; `unverified` is "not checked
  yet", "left out of score and coverage", and explicitly not "data is absent". A
  unit test asserts the glossary keys equal `STATES` and `STATUSES`, so a new
  state cannot ship without an explanation.
* Cache busting (verified on the lab, Splunk 10.2.9): static files are served
  at `/en-US/static/@<splunk build>[.<push>]-<app build>/app/sunavigator/<file>`
  with `Cache-Control: max-age=31536000`. The app build is `app.conf [install]
  build`, so it must be raised in every change that touches `appserver/static`.
  Two traps were found and handled:
  1. The views loaded the shared module with the RequireJS id
     `../app/sunavigator/ucm_common`, which is requested as
     `/static/@<splunk build>/app/sunavigator/ucm_common.js` with no app build.
     That file would stay cached for a year across upgrades while the view
     script (which has the build) changed, so a new view could run against an old
     `ucm_common.js`. `splunk.util.make_url` in the browser does not help: it
     always writes `:0` as the app build. Each view script now derives the module
     URL from the `<link>` of `ucm.css`, which the dashboard XML loads under the
     busted URL, so all three files share one cache key. If the link is missing it
     falls back to the old id. A unit test pins the pattern and the `script` and
     `stylesheet` attributes of every view.
  2. Splunk Web also keeps static files in a server-side cache. After copying
     files into a running instance the old content is still served until a
     restart or `/en-US/_bump` (an operator action; the lab uses restart).
* Observed: with build 2, the script, stylesheet and `ucm_common.js` are all
  requested under `@41bebfa38eb4-2`.
* Browser logic tests: `tests/js` holds dependency-free Node tests with a minimal
  fake DOM and AMD stub (`fake_dom.js`); `tests/unit/test_js_logic.py` runs them
  inside the Python suite and skips when Node is not installed. The fake DOM
  throws on any `innerHTML` use, so the tests also enforce the safe-DOM rule for
  the code they load.

## D-057 Home page as the default landing view
*0.8.1.*
* Decision (OD-1): a new `ucm_home` view is the default landing page;
  `ucm_overview` is unchanged, stays in the nav and is linked from Home. Only
  `nav/default.xml` changes (`default="true"` moves). Static nav, as before.
* Content: a status strip, the six-step journey, a placeholder slot for
  recommendations (filled in a later 0.8.x release), a static user-guide section
  (OD-2) and links to the Domain dashboard for the 13 domains.
* Data: the strip reads existing endpoints only (`catalog`, `sync`, `discovery`,
  `readiness/summary`). No new route, no schema change, no search. Each card
  fails independently, and the "next step" marker is derived only from stored
  results and is withheld while the state it depends on is unknown.
* User guide (OD-2): static and deliberately thin. It says the guide is in
  development and lists the existing views and the topics of
  `docs/OPERATOR_GUIDE.md` in generic terms. It makes no claim about content that
  does not exist yet. The operator guide is not packaged with the app, so the
  page names the file rather than linking to it.
* Domain links: the Domain dashboard takes the form token `domain`
  (`?form.domain=<id>`; `*` is "All domains"). A unit test keeps the Home list
  (ids, labels, order) equal to that dropdown and to `ucm.DOMAINS`.
* Tests: `tests/js/test_home.js` runs the real view against a scripted API in
  the fake DOM (all state combinations, partial failure, links).

## D-058 Interactive search from the use-case page (Alternative A)
*0.8.2 (OD-3).*
* Need: users want to see the output of a detection, not only parse results and
  the bounded preview.
* Alternatives: (A) the browser runs the search with `SearchManager` under the
  user's own permissions; (B) extend the server-side preview (rejected as the
  answer to this need: it is capped and refuses indirect commands by design);
  (C) dispatch from the app under its system token (rejected: it would run user
  clicks with the app's rights and widen what a viewer could reach). A was
  approved, knowing that it bypasses the server-side guard rails.
* What is built (`ucm_usecase.js`, `ucm_common.js`): a "Run this search" card in
  the SPL section with a visible notice, a time range select (15 m, 1 h, 4 h,
  24 h default, 7 d, no all-time and no real-time), **Run search** and **Cancel**
  buttons, a status line and a result table. SearchManager settings:
  `autostart false`, `preview false`, `cache false`, `status_buckets 0`,
  `max_time 120`, `cancelOnUnload true`, `app sunavigator`, and the option
  `tokens false`. The manager is created lazily on click, so nothing is loaded or
  run on page view. Results are fetched with `count 100` and rendered with
  `el()`/`textContent` only; cells are cut at 500 characters; underscore fields
  other than `_time` and `_raw` are hidden. The manager is cancelled and disposed
  on Cancel and on `pagehide`.
* Verified on the lab (Splunk 10.2.9, Chromium): a `$` in the SPL reaches Splunk
  unchanged with `tokens false` (`"a$b$c"`, `"$tok$"`, `"cost$"` came back as
  typed), so Splunk's token substitution does not rewrite imported SPL; a search
  without a leading `search` also runs, and the UI adds `search ` the way
  `spl.parser.parser_candidates` does; `| rest` works under the user; 150 results
  displayed as 100 with "Showing 100 of 150"; Cancel ends the job; a result cell
  containing `<img onerror>` is shown as text and creates no element.
* Guard (UI only): the side-effect list mirrors `analysis.SIDE_EFFECT_COMMANDS`
  and `fit … into`; indirect commands mirror `policy.INDIRECT_COMMANDS`. Tests:
  list equality, and a parity run of the Python and JavaScript command
  extraction over fixture SPL and every SPL-like string in the SPL tests
  (over 100 strings), which fails when either side changes. Macros: allowed only when
  the stored parse of the same `source_hash` is clean, because the browser cannot
  expand macros and a macro could hide `outputlookup`. This is stricter than the
  approved wording on purpose and has a visible reason; it can be relaxed later.
* Capability: the button is disabled with a reason when
  `authentication/current-context` shows no `search` capability. Splunk enforces
  the capability regardless, so a failed lookup leaves the button enabled.
* Consequences, accepted: no app audit (documented in `docs/SECURITY.md`); no
  server-side row cap; results exist only in the page; no export.
* Not done: a custom time range, editing the SPL before running it, running the
  deployed (approved) revision, or saving results.

## D-059 Catalogue facets, bookmarks, readiness availability and KPI cards

*0.8.3 (OD-5, OD-6).*

* Context: the catalogue offered single-value drop-downs, no bookmark filter and
  no way to ask "which use cases can I run here". Readiness lives in `uc_readiness`
  and selections in `uc_selections`, not in `uc_catalog`.
* Decision: filter by readiness without a schema change (Option A, a bounded join
  by key). `CatalogQueryService` reads the keys that match from `uc_readiness`
  (state `$in` the chosen states) and, for `bookmarked=1`, from the caller's own
  `uc_selections` rows with intent `bookmark`. It intersects the sets and sends
  `{"_key": {"$in": [...]}}` together with the other filters, so KV Store still
  sorts, pages and counts. The user comes from `ctx.user` (the session), never
  from a request parameter; a `user=` parameter is ignored (unit test and lab
  check). `not_assessed` is "in the catalogue selection but without a readiness
  row", computed against the same base filter, so withdrawn entries (which have
  no readiness) are not counted as not assessed.
* Measurements (Splunk 10.2.9 lab, KV Store, 44-character keys like
  `escu_UC-<uuid>`):
  * Lab catalogue: 2,357 documents in `uc_catalog` (268 active, 2,089 withdrawn),
    268 readiness rows. `availability=ready` with 111 keys: 0.03 s end to end
    through the app REST endpoint.
  * Key-set limit, direct against a synthetic 20,000-document collection:
    `_key $in` works with 100, 250, 500, 1,000, 1,500, 2,000, 3,000, 5,000 and
    8,000 keys (median 8 ms to 36 ms; request line up to 432 KB), and splunkd
    answers HTTP 414 at 10,000 keys (540 KB). The limit is the URL, since KV
    Store queries are GET requests. In-app (through `splunk.rest`) the `$in` path
    was exercised at 250, 1,000 and 2,000 keys (0.03 to 0.06 s) and the scan path
    at 2,001 and 5,000; a run with `max_join_keys` raised to 5,000 returned
    correctly in 0.04 s but the lab could not show which path served it.
  * Reading all keys: a keys-only query of 20,000 documents takes 0.08 s; 13,306
    keys matching a state query 0.06 s.
  * KV Store refuses `limit` above `max_rows_per_query` (50,000). A first
    version asked for 50,001 in the scan path; the lab caught it and a test with a
    store that enforces the limit now covers it.
* Limits chosen: `[catalog] max_join_keys` default 2,000 (4x below the measured
  8,000, range 1 to 5,000). Above it the service does not fail: it reads the
  matching catalogue keys in order (keys only, at most 49,999), keeps those in
  the allowed set and fetches only the requested page by `_key $in` (at most 101
  keys). Both paths are tested to return the same items, order, total and
  `has_more` for every sort and page. Above 49,999 catalogue rows for one filter
  the request is refused with "narrow the other filters first". Option B (a
  readiness field on `uc_catalog`) was not needed and not built.
* Facet counts are global, not filter-aware. A filter-aware count needs one
  count query per facet value (about 55 for the current facets). Measured on the
  20,000-document collection: 55 counts took 1.8 s (32 ms each) because the
  store counts by reading matching keys. Global counts come from facets stored
  after every sync, import and reindex (`catalog::facets`, now version 2 with
  counts per domain, category, criticality and difficulty); the Availability
  counts come from `readiness/summary`. The page says so in words. A migration
  (`0003_catalog_facets_v2`) writes the new facets once; until then
  `catalog/facets` computes them from a catalogue scan.
* Bookmark semantics: a bookmark is the `bookmark` intent. The collection keeps
  one row per user and use case, so choosing **Select** on a bookmarked use case
  replaces the bookmark. The catalogue offers **Bookmark** only when the user has
  no selection on the row, so it cannot overwrite a select, defer or reject.
* Grouped browse: categories are listed under their first domain with the
  catalogue-wide domain count; a category with several domains appears once.
* KPIs: percentage cards carry their figures and their calculation in text
  (Overview, Readiness, Coverage). Readiness cards are built by one shared
  function so both pages use the same terms. Percentages are of assessed use
  cases, except Assessed (of active catalogue); with no denominator the card
  shows a dash.
* Not done (OD-6): export of any kind. Not done by design: filter-aware counts, a
  Sankey, "bookmark" meaning anything beyond the caller's own intent.

## D-060 Recommended next use cases

*0.8.4 (OD-7).*

* Context: after discovery and assessment a user still has to decide where to
  start. The decision is theirs; the app can only order what it already knows.
* Decision: `GET ucm/readiness/recommendations` (`readiness/recommend.py`),
  read-only and deterministic, with no state and no learning. It returns at most
  10 items, the formula and its weights, the counts it left out, and one of four
  distinct empty states (`no_catalogue`, `no_discovery`, `no_assessment`,
  `none_eligible`).
* Eligibility, in this order: an active entry in `uc_catalog`; a `uc_readiness`
  row; readiness state `ready`, or `partially_ready` with no blockers (blocked,
  not ready and insufficient evidence are never recommended); not rejected by the
  calling user (their own `uc_selections` rows, user from `ctx.user`, never from a
  parameter); not already deployed.
* "Already deployed" is `CoverageService.use_case_levels` itself, so the list and
  the coverage matrix cannot disagree. Checked on the lab and in the code
  (`deployment/service.py`): a deployment document carries a workflow `state`
  (draft, pending_approval, approved, rejected, deployed, failed, retired) and a
  `deployed_revision`. Deploy sets `deployed_revision`; **retire sets it to
  `None`** and removes the saved search; a failed deploy keeps the previous
  `deployed_revision`. The coverage level is *deployed* (or *enabled* when
  `live_status` is `enabled`) exactly when `deployed_revision >= 1`, whatever the
  workflow state. So: enabled or disabled deployed searches are excluded; retired,
  draft, pending approval, approved, rejected and never-deployed use cases are
  eligible, and a draft, pending or approved deployment is shown as a flag. Lab
  data: one retired deployment (`deployed_revision` null), one retired that had
  never been deployed, one pending approval. Note: the flat `live_status` field of
  a retired deployment can still read `disabled` (it is not reset on retire); no
  code in this feature reads it for deployed use cases, `deployed_revision` decides.
* Withdrawn catalogue entries (2,089 on the lab) have no readiness rows and are
  excluded because they are not in the active catalogue.
* Order: `ready` before `partially_ready`, then draft score descending, then
  `criticality_rank` descending, readiness score descending and `content_id`
  ascending. The state tiering is this record's reading of "prefer ready, then
  partially ready with zero blockers".
* Draft score = 0.40 x readiness score + 0.25 x criticality (rank/4 x 100) + 0.20
  x new MITRE gain x 100 + 0.15 x readiness coverage x 100, rounded to two
  decimals. New MITRE gain is the share of the use case's technique ids that are
  not in the set of technique ids of active use cases at deployed level or higher
  (deployed, enabled, operational). Ids are compared as stored: a deployed
  `T1110.001` does not count as covering `T1110` here, although the coverage matrix
  rolls sub-techniques up into their parent. A use case without technique ids has
  gain 0 and its reason says "No MITRE ATT&CK technique mapping is stored". The
  weights are product defaults, not measured; they are returned with every response
  so a later change is visible.
* Selected and deferred use cases stay eligible with a flag and no boost; a
  bookmark is flagged the same way. Rejected ones of other users have no effect and
  nothing about them is returned (unit test: no other user name appears in a
  response).
* Reasons come from stored fields: readiness state, score and coverage, criticality,
  the new technique ids, requirement counts, the unverified count (always stated),
  the first unmet required requirements, and for data models only "Data model
  definition installed (populated data not verified)" when a stored `cim_model`
  result has code `model_present`.
* Not done: weights editable by the user, any use of `uc_selections` of other
  users (for example "popular with your colleagues"), automatic selection, and
  filtering by the user's role or domain interest.

## D-061 Requirement result counts, wording, and selections as shared metadata

*0.8.5 (OD-8).*

* Context: the Readiness table showed one "Not verified" number although the
  assessment stores the count of every status, and some pages described the same
  state in different words. `uc_selections` had never been described as shared
  metadata.
* Decision, display: the Readiness table column "Not verified" became
  "Requirement results" (`ucm.resultBadges`): non-zero stored `counts` as status
  badges with the same labels and hover text as the requirement table. The
  use-case page uses `ucm.resultSummary` for the same sentence in both places it
  printed counts. Rows stored before `counts` existed fall back to `unverified`.
  Nothing is recomputed in the browser.
* Decision, wording: "not assessed" = no stored readiness result for the use case;
  "not verified" = a requirement the inventory cannot check yet, left out of score
  and coverage, never "missing". The out-of-date Overview notice (field and SPL
  checks "in a later release") and the Readiness page description were rewritten
  to say this.
* Decision, OD-8: `uc_selections` is documented as **app-shared metadata**,
  consistent with D2 (D-044). Checked on the lab: a user holding only
  `ucm_viewer` can list every user's rows and create a row for another user
  through `/servicesNS/nobody/sunavigator/storage/collections/data/uc_selections`
  (the test row was deleted). `metadata/default.meta` grants read to all roles and
  write to admin, sc_admin, ucm_admin, ucm_analyst and ucm_viewer. The ACLs were
  **not** changed. The app API only reads and writes the caller's rows, and
  recommendations and bookmark filters use only the caller's rows, so the
  isolation is application-level, not storage-level. A per-user storage boundary
  would need the REST handler to be the only writer, which is a larger change and
  is not made here.
* Consequences: operators are told not to put sensitive text in selection notes.
  No schema change, no new collection, no new route.


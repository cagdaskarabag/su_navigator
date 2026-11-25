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
  sampling) still run with the caller's session, so nobody sees data they
  could not search themselves. Discovery is the exception: the worker runs it
  with the system session, so the inventory is not filtered by the caller's
  index permissions (D-044; corrected in D-062, the earlier text listed
  "discovery dispatch" among the caller-session searches).
* Workers check each queued job's structure before running it (`storage/jobs.py`:
  type, id/key, requester, source, provider, categories, ref, flags, time
  bounds). A malformed job is failed with `invalid_job` and audited.
* `uc_selections` stays user-writable: it is per-user intent, not evidence.
  Provider collections stay writable by content managers (known limitation in
  SECURITY.md). *Superseded by D-062: selections are now written only through
  the REST handler.*

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
  is requested and available. *Relabelled "Ran without error (not a statement
  about data)" by D-063; the level and its meaning are unchanged.*
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
* **Amended by D-064 (0.8.8):** a search that errors on the test data is now
  `content_error`, not `inconclusive`; the window is derived from the fixture
  timestamps instead of the fixed `-10y` to `+1d`; `expected.max_count` and
  `expected.fields` are asserted; the index rewrite touches search clauses only;
  `1.1.1` is explained there (its manifest cannot pass even with the add-on).

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
  settings are **not imported** (D-062 correction: the bundle keeps severity,
  schedule, detection type, analytic stories, data sources and ATT&CK ids, but
  none of the `action.risk.*` or `action.notable.*` parameters other than the
  security domain and severity); `cis20`, `nist`,
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
* *Amended by D-062 (0.8.6):* the guard also reads the search inside `map
  search="..."`, refuses `savedsearch`, `loadjob`, `dbxquery` and the
  `savedsearch:` dataset, and an administrator can switch the feature off.

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
* *Write side superseded by D-062 (0.8.6):* the handler is now the only writer.
  Read access is unchanged.

## D-062 Nested-SPL guard, interactive-search switch and handler-only selection writes

*0.8.6 (assessment of 24 Nov 2026, decisions of the product owner: block hidden SPL, handler-only selections).*

* Context: an independent review and a follow-up check found that `map
  search="... | collect ..."` was classified only as `indirect` (`map`), in the
  Python policy and in the browser guard alike. The server preview refuses every
  indirect command, but the interactive search (D-058) only warned, so a
  poisoned catalogue record could make a click write a lookup, send mail or
  delete, within that user's permissions. D-061 had also shown that any
  `ucm_viewer` could write `uc_selections` rows for another user.
* Decision, nested SPL: the search string of every `map search="..."` is analysed
  with the same policy, recursively up to three levels (`MAX_NESTING`).
  Side-effect commands found inside it are side effects of the whole search
  (`PolicyResult.side_effects`), so preview, submit and deployment refuse
  them. Commands found inside are also listed in `PolicyResult.nested`; indirect
  commands inside it are indirect. `fit … into` and `savedsearch:` inside the
  string count as well. Escapes `\"` and `\\` are undone the way Splunk reads
  them. Allowlist extensions (`extra_safe_commands`) still cannot clear a nested
  finding.
* *Amended by D-068 (0.9.2):* this record and the 0.8.6 text said the guard caught side-effect
  commands in subsearches. It did not when the command was the **first** word of a bracket
  (`appendpipe [ collect ... ]`, `append [ outputlookup ... ]`), of a `map` string without a
  pipe, or of a search sent without `search`/`|`; Splunk 10.2.9 runs all of them. Fixed in both
  guards in 0.9.2.
* Decision, hidden SPL: `PolicyResult.hidden` lists what the page cannot show or
  check: `savedsearch`, `loadjob`, `dbxquery` (`HIDDEN_SPL_COMMANDS`), the
  `savedsearch:` dataset, a `map` whose search is not a readable quoted string
  (`savedsearch=`, an unquoted value), a macro inside a `map` string, and nesting
  deeper than three levels. The interactive search refuses all of them with a
  reason. `rest`, `dbxlookup` and `dbxinputs` stay warnings, and a `map` with a
  readable, clean search only warns. Server side nothing else changes: these
  commands were already indirect, so preview refuses them and approval needs an
  acknowledgment. The stored parse (macros expanded by Splunk) is also consulted:
  an indirect `savedsearch`, `loadjob` or `dbxquery` found there blocks the button.
* Known limit: a side effect nested deeper than three levels is not seen as a
  side effect; the search is reported as hidden, refused in the browser and
  preview, and needs the approver's acknowledgment at deployment like any `map`.
  Macros inside a `map` string are not expanded by Splunk's parser, so they stay
  hidden (blocked in the browser, acknowledged at deployment).
* Measured (no change expected in practice): Fenre `0e21f01` has 12 `map`
  records, none with a nested side effect; 6 contain a macro inside the string
  and 6 use `dbxquery` (hidden, so not offered in the browser). ESCU 6.11.1 has 7
  `map` searches (6 with a macro inside), none with a nested side effect. No
  record changes from allowed to refused for preview or deployment.
* Decision, switch: `[interactive_search] enabled` (default `true`) in
  `ucm.conf`. The use-case detail response carries it as `interactive_search`;
  when it is `false` the page shows a note instead of the button. A missing
  setting keeps the feature on. Removing the `search` capability from a role
  remains the per-role control.
* Decision, refusal hint: the preview refusal no longer suggests
  `extra_safe_commands` for indirect commands, which that list can never clear.
  It names the right remedy per case.
* Decision, selections: `uc_selections` is written only by the REST handler with
  the system token (`Context.selection_service()` uses `records()`), and
  `default.meta` limits KV write to `admin` and `sc_admin`. The handler still
  takes the user only from the session and ignores a `user` parameter. Reads
  stay open to every role so that the caller-scoped filters keep working;
  confidentiality at KV level is unchanged (D-061). No schema change and no
  migration. A site that overrode the ACL in `local.meta` keeps its override.
* Corrections to earlier records: D-039 listed "discovery dispatch" among the
  caller-session searches although discovery runs as the system user (D-044);
  D-053 said risk, drilldown and finding settings are kept as raw data, but the
  bundle does not store them.
* Wording: README, `app.conf` and `app.manifest` no longer claim Splunk Cloud
  support. The package passes AppInspect with the `cloud` tag; runtime on a Cloud
  stack is not validated (issue #3).
* Not done: reading the scheduler account's index access (next sprint), a
  server-side audit of interactive searches, treating `rest` as hidden.

## D-063 Scheduler-principal visibility, scheduled-run proof and the Settings listing

*0.8.7 (assessment of 24 Nov 2026, B-03, B-04, issues #7 and #9).*

* Context: a deployed search runs with the rights of `[deployment] scheduled_owner`
  (D-051). If that account cannot search an index the SPL names, Splunk returns no
  events and no error: the run is logged as `success` with `result_count=0`, so the
  Operations page showed `operational` for a search that never saw data. The readiness
  engine had a `permission` requirement type that always answered `unverified`
  (`not_evaluable`), and an index that discovery had not scanned (internal indexes
  with `[discovery] include_internal = false`) was reported as "index not defined".
* Spike (lab, Splunk 10.2.9, 24 Nov 2026), before any code:
  * With an `admin` session, `GET authentication/users/<owner>` and
    `GET authorization/roles/<role>` return `roles`, `srchIndexesAllowed`,
    `imported_srchIndexesAllowed`, `srchIndexesDisallowed`,
    `imported_srchIndexesDisallowed`, `srchIndexesDefault`, `imported_srchIndexesDefault`,
    `srchFilter` and `imported_srchFilter`. The `imported_*` values are already resolved
    through nested imports, so no recursion is needed.
  * The REST handler's own system token (`passSystemAuth = true`) reads the same data:
    after installing 0.8.7, `GET /services/ucm/readiness/summary` returns the scheduler
    card with `status = ok` for `ucm_scheduler`. The modular input's session key reads
    it too (the readiness worker job stores the principal summary).
  * A user without `admin_all_objects` reads only their own user and roles. A
    `ucm_viewer`-class user got `200` for itself and `403` for `ucm_scheduler`, for
    `authorization/roles/ucm_scheduler` and for `authorization/roles/admin`. The
    scheduler account therefore cannot be read with the caller's token, and the
    handler's system token is required.
  * Measured with throw-away roles and users (all deleted): `*` matches only
    non-internal indexes; `_*` or `_internal` is needed for internal indexes; a pattern
    that starts with `*` (for example `*audit`) never matches an internal index;
    `srchIndexesDisallowed` wins and applies across all of a user's roles; a role that
    imports `user` holds `*` and default `main`; a role with an empty
    `srchIndexesDefault` searching without `index=` sees nothing (no error); setting an
    index in `srchIndexesDisallowed` through REST removes it from the same role's
    `srchIndexesAllowed`; `srchFilter` hides events silently.
* Decision, resolver (`readiness/principal.py`): `read_principal(transport, owner)`
  reads the user and each of the user's roles and merges own and imported allowed,
  disallowed and default patterns and the filters. It never raises. A missing
  owner, an unknown user, a failed read or one unreadable role gives a principal with
  status `no_owner`, `user_not_found` or `unreadable`. `covers(index)` applies the
  rules above (disallowed first, internal indexes need an `_` pattern); wildcard SPL
  patterns (`index=web*`) are expanded against the indexes known from discovery.
* Decision, SPL side (`scan_spl`): the indexes come from the static `analyze` of the SPL
  plus the macro-expanded parse when validation stored one (`access_scan`, bound to the
  source hash). A search with no `index=` is checked against the default indexes. The
  result is `unverified`, never `met`, for `tstats ... from datamodel`, `tag=`,
  `eventtype=`, macros that were not expanded, `index=*`, and `map`, `savedsearch` or
  `loadjob`. A non-empty `srchFilter` adds a warning to the explanation. Only a literal,
  checkable shortfall gives `not_met`; a certain `not_met` is not weakened by a doubt
  about another part of the same search.
* Decision, requirement: every use case with SPL gets a derived requirement
  `permission:scheduler_index_access`, "runs as <owner>: index access", level
  `required` (a gap, not a blocker: the readiness state and the enable gate are separate,
  and the gate is evaluated live against the deployed SPL). Statuses: `met`, `not_met`
  (or `partial` when only some indexes are missing), `unverified`, `not_applicable`
  (no index is read). Each row has a plain explanation and the indexes observed. The
  engine version moved to `ucm.readiness/4` (D-024), so every stored assessment is
  re-run by the next worker cycle; run **Assess** to see it at once.
* Decision, deployment: submit stores `scheduler_access` on the revision and in the audit
  details and never blocks. Enable is gated when the access is `not_met`: it needs an
  override reason of at least 10 characters, the same audited `override_reason` path
  that the readiness gate uses (error code `scheduler_access_gate`, or
  `readiness_gate` if readiness is also blocked). No new capability, route or bypass.
  `unverified` (including a role-read failure) never blocks. The access is read live
  with the handler's system token on each view and each enable; nothing about the roles
  is stored on the deployment.
* Decision, UI: the Overview shows a scheduler card (owner, roles found, internal-index
  access yes or no, default-index count, whether discovery scans internal indexes) from
  `readiness/summary` with no extra request; the use-case page shows the access badge and
  an explanation, and the enable dialog asks for the override reason when the access is
  `not_met`.
* Decision, `include_internal`: X
  default is the one in `ucm.conf.spec`), internal indexes are not scanned. An internal
  index requirement is now `unverified` ("internal indexes are not scanned"), never
  "present" or "missing" and no longer `partial`; a sourcetype not found says so. The
  Inventory and the card state this. This lowers the score of use cases that name only
  an internal index and moves them toward `insufficient_evidence` until discovery scans
  internal indexes; that is the honest reading.
* Decision, issue #7 (B-04): `LiveScheduledRunTest` deploys a custom search as
  `ucm_test_sub_*` (submits) and `ucm_test_apr_*` (approves, four-eyes; the
  submitter's own approval returns 403), enables it with `cron = * * * * *`, waits
  for a real scheduler run and reads `index=_internal sourcetype=scheduler`. Result on
  the lab: `user = ucm_scheduler`, `app = sunavigator`, `status = success`,
  `result_count = 1`, and the saved search is still owned by `ucm_scheduler` with
  sharing `app`. The search is then disabled, retired and the users deleted. Scheduled
  execution as the scheduler account is proven on Splunk Enterprise 10.2.9.
* Decision, Coverage wording: `operational` is now labelled "Ran without error (not a
  statement about data)" everywhere (Coverage, Deployments, Navigator layer comment,
  documentation). The state name in the API stays `operational`. It means the
  scheduler logged `status=success`; as shown above, that includes runs that returned
  nothing. The new access check is the way to find the common cause.
* Finding, issue #9: not a SUN defect. Settings > Searches, reports, and alerts
  requests `servicesNS/<you>/<app>/saved/searches?search=(eai:acl.owner="<you>") AND
  (eai:acl.app="<app>")`: its default **Owner** filter is the signed-in user. Deployed
  searches are owned by `ucm_scheduler`, so they are hidden until the filter is changed
  (captured from Splunk Web 10.2.9 with a headless browser; app `sunavigator`,
  sharing `app`, owner `ucm_scheduler`, disabled). Choosing Owner **All**
  (`servicesNS/-/sunavigator/saved/searches`) or Owner `ucm_scheduler` lists the search.
  Before D-051 the owner was the approver, so the original lab observation was the same
  filter with a different owner. Nothing is changed in how searches are created. The
  use-case page now says to set Owner to All, and the operator guide §9.14 documents it.
* Accepted risks, documented: the check reads roles as they are at the time; a role change
  does not by itself mark stored assessments stale (assess again; the enable gate is
  always live). Macros, data models, tags, event types and `index=*` stay `unverified`.
  `srchFilter`, search-time-window limits (`srchTimeWin`) and per-role quotas are not
  evaluated. A Splunk Cloud or search head cluster stack may restrict role reads: that
  gives `unverified` and does not block (not validated, issues #2 and #3).
* Consequences: the system token now reads `authentication/users/<owner>` and
  `authorization/roles/<role>` (read-only, only for the configured owner;
  `docs/SECURITY.md`). The `readiness/summary` response is visible to every app user and
  carries the owner name, role names and booleans, never index lists. No schema change,
  no migration, no new collection, no new capability, no new route, no new setting.

## D-064 Control-test precision and the 94-fixture campaign
*0.8.8 (B-05, B-06, B-08; issues #5 and #6).*
* Context: D-054 gave a pass/fail from a row count over a fixed 10-year window and
  reported every search error as `inconclusive`. The campaign below ran all 94 Fenre
  fixtures on the lab and showed what that hid: errors indistinguishable from slow
  indexing, a window that made `timechart` fixtures pass on empty buckets or fail with
  "too many rows", events split in the middle of one Windows message, assertions in
  the manifest that were never read, and over-refusals.
* Decision, verdicts. `passed`, `failed`, `not_runnable` and `inconclusive` keep their
  meaning. New **`content_error`**: Splunk ran the search on the test data and reported
  an error (an `ERROR` message on the job, or HTTP 400 from the search endpoint). The
  result carries `phase` (`positive` or `negative`) and the Splunk message in `reason`.
  `inconclusive` is now only for data that was not searchable in time, a timeout, a
  transport failure or a receiver error: states where the search was not judged. Stored
  results are not migrated; a result without `window`, `fields` or `phase` renders as
  before.
* Decision, window. The search window is derived from the timestamps in the fixture's
  first 128 characters per event (Splunk's own look-ahead): `min - 1 h` to `max + 1 h`
  (`ControlTestRunner._replay`, `derive_window`). Formats: ISO 8601 (zone optional),
  splunkd (`MM-DD-YYYY HH:MM:SS.mmm +zzzz`), `YYYY/MM/DD`, Windows (`MM/DD/YYYY
  hh:mm:ss AM`), Snort (`MM/DD/YY-HH:MM:SS`), ctime, and syslog without a year (the
  current year, or the previous one when that would be over a day ahead). A zoneless
  time is read as UTC and the window is padded by **24 h**, not 1 h: splunkd reads it in
  its own zone, which the app cannot see. An event with no parseable time is indexed
  "now", so the end of the window becomes `+1d`; if no event parses the window is the
  old `-10y` to `+1d`. The window is stored on each run (`positive.window`). Settle
  counting still uses the wide window.
* Decision, assertions. `expected.max_count` and `expected.fields` (`name`, `values`,
  `min`, `max`, `regex`) are stored on the fixture (additive keys, same bundle format)
  and asserted on the **positive** run with the semantics of Fenre's
  `run_uc_tests.py`: `values` passes on any overlap; `min`/`max` run over the numeric
  values and fail when none is numeric; `regex` passes on any match; multivalue results
  count each value. A regex longer than 256 characters or with nested repetition is
  refused at import (the fixture is skipped with its reason), as are unknown keys. The
  hand-written YAML reader gained flow lists of scalars, YAML escapes in double quotes
  and block lists of mappings; anything else (anchors, tags, flow mappings, nested or
  multi-line flow lists, tabs) skips the fixture instead of being misread. Control tests
  run at search level `smart` (as Fenre's runner does), so a search that does not end in
  a transforming command returns its extracted fields.
* Decision, scoping. The index rewrite is applied to **search clauses only**: the base
  search, `search` and `where`-free pipeline heads, and the clauses of subsearches. Text
  in `eval`, `where`, `fields`, `rex` and the like, and inside quotes, is never touched.
  Breaker commands are recognised by command position, not by text, so `"map"` or `|REST`
  inside a quoted string no longer refuses a search (`UC-2.6.38` and `UC-5.3.35` were
  refused by D-054 for that reason). Everything D-054 refused is still refused. Two
  refusals were **added** (they only narrow what can run): a macro call (the expansion
  is not visible, so it could read any index; `` `comment` `` is allowed) and the
  breakers `typer`, `eventcount`, `walklex`, `metasearch`, `loadjob`, `history`, `audit`
  and `metadata`. No approval, capability or ACL changed.
* Decision, event boundaries. When the file's first block starts with a timestamp, a
  later blank-line block without one continues the event before it. `UC-1.2.6` is 4
  events (it was 9) and `UC-9.1.2` is 2 (it was 6), which are the `min_count` values in
  their manifests.
* Decision, UI. The use-case page shows `content_error` as its own verdict, the search
  window (and whether it was derived), `max_count`, and one line per field assertion
  with its failures. Administration shows the first error of a failed latest
  synchronization job above the job table (B-08), for example a commit that is not
  allowed. Field sampling no longer asks for `_time`, `host`, `sourcetype` and the other
  `INTRINSIC_FIELDS` (B-08).
* Campaign (B-06). `tools/controltest_campaign.py` sends each fixture to the
  `[controltest]` index with a per-run source marker and runs the SPL from the Fenre
  checkout with the same code the app uses. It deploys nothing and writes no KV row.
  A use case Splunk cannot parse in the app's namespace, or with side effects, is
  `not_runnable` exactly as the deploy step would refuse it. Result on Splunk 10.2.9
  without add-ons, 94 fixtures: **12 passed, 67 failed, 0 content_error, 0 inconclusive,
  15 not_runnable**. Reasons: SUN defect 0 left (see below), missing add-on 1, upstream
  content defect 20, fixture defect 53, not runnable 8, passed 12. Per fixture:
  `docs/upstream/CONTROL_TEST_CAMPAIGN.md`; upstream findings for the product owner:
  `docs/upstream/FENRE_FINDINGS.md` (nothing was filed on the Fenre repository).
* SUN defects found by the campaign and fixed here: (1) a quoted `map`, `REST` or
  `audit` made a search not runnable (2 of the 94); (2) the index rewrite changed
  `eval index=...`; (3) Snort, ctime and `YYYY/MM/DD` times were not read, so the fixed
  window gave a `timechart` "too many rows" error that the old code reported as
  `inconclusive` (`UC-10.2.1`; it is now `content_error` if it recurs); (4) events with
  blank lines inside were split; (5) manifest assertions were ignored.
* Findings that are not SUN's: 64 of the 94 fixtures are 13 generic templates reused
  across different use cases, so their events carry none of the terms or fields the SPL
  needs; 12 base searches use the eval function `match()` as a search term, which
  matches nothing (checked on the lab); 7 searches Splunk rejects (`timechart` with two
  split-by fields in 4, a bad regex, a bad time modifier, bad `match` arguments); manifests
  that assert fields the SPL does not return. Adding the Splunk add-ons and
  `KV_MODE = json` changed no verdict: a run with `KV_MODE = json` on 38 sourcetypes was
  identical per fixture to the run without (Splunk 10.2.9 extracts JSON automatically,
  `AUTO_KV_JSON`). `UC-1.1.1` (issue #6) fails because the events are a multi-line `top`
  table, `cpu_load_percent` is never derived and, with that field emulated, the SPL
  gives one aggregated row whose columns are not the ones the manifest names.
* Limitation, accepted and listed for the product owner: a search that filters on
  `source=` (8 of the 94 SPLs; 6 of them are refused for this reason alone) is `not_runnable`, because the per-run
  marker is the event `source`. Scoping by `_indextime` instead would lift this, at the
  cost of a time-based isolation that two overlapping runs would share; it is not done.
* Limitation: a `timechart` or other time-bucketing search can pass on empty buckets
  (`UC-10.2.1`, `UC-12.1.1`). The row count cannot tell; add `fields` or `min`
  assertions to such a fixture. Placeholder events can pass through `coalesce` defaults
  (`UC-2.6.48`, `2.6.55`, `2.6.76`).
* Cleanup and retention: events from control tests stay in the test index. The
  campaign script's `--delete` removes its own events with `| delete`, which needs the
  `can_delete` role (the app never asks for it). Otherwise set a short retention on the
  test index (`frozenTimePeriodInSecs`) and a size cap (`maxTotalDataSizeMB`); a full
  campaign adds about 300 events per run (308 fixture events in 94 fixtures).
* Consequences: no schema change, no migration, no new capability, route or setting, no
  new dependency; `docs/SECURITY.md` is unchanged because the picture is: new paths only
  add refusals. The build number changed to 10. Python 3.9 compatible, stdlib only.

## D-065 Advisory SPL lint, bounded-total warning and the 0.8.9 documentation pass
*0.8.9 (B-09, B-07 leftovers; issues #8, #13, #14).*
* Context: Splunk accepts SPL that never does what its author meant (an eval function
  in a search clause) and rejects SPL only when it is parsed. The control-test
  campaign (D-064) found both kinds in the Fenre content. The assessment counted 51 and
  54 cases with a text heuristic. A lint that reads the SPL structurally can say so at
  validation time, before a use case reaches the approval step.
* **Advisory only.** The lint adds findings to the validation result and the
  deployment revision. It changes no readiness score, no approval, no deployment gate,
  no SPL refusal and no capability. It never raises: a failure inside it gives an empty
  list. Findings carry `rule`, `severity` (always `warning`), `segment` (the n-th
  command of the top-level pipeline, from 1), `command`, the text found, a message, a
  rewrite and a count. A `map search="..."` string is read as SPL and its findings are
  marked `in_map`.
* **Method.** `spl/lint.py` (stdlib, Python 3.9) uses the quote masking and pipeline
  splitting that the SPL policy uses (`_mask_quotes`, `_split_pipeline`, the `map` string
  extraction). Pieces are command-sized at every bracket level; a piece after a `]`
  keeps the command that owns the subsearch; the first piece of a level is an implicit
  `search` unless its first word is a known command. Quoted text is never inspected, so
  `where match(...)`, `eval x=match(...)` and `if(match(...), ...)` raise nothing (unit
  tests, positive and negative for each rule).
* **Rules, each shown on the lab (Splunk Enterprise 10.2.9, app namespace, with
  `/services/search/parser` and with real searches over two test events):**
  * `L001` an eval function in a search clause. 25 functions were probed (`match`,
    `like`, `cidrmatch`, `isnull`, `isnotnull`, `isnum`, `isint`, `isstr`, `isbool`, `len`,
    `lower`, `upper`, `mvcount`, `mvindex`, `mvfind`, `mvfilter`, `searchmatch`,
    `tonumber`, `tostring`, `substr`, `replace`, `trim`, `ltrim`, `rtrim`, `coalesce`), both as a
    base-search term and after `| search`: each returned 0 rows where the same call in
    `where` returned the matching row, with no error. Under `NOT` four of them
    (`isnum`, `isint`, `isbool`, `searchmatch`) returned every row, so the wrong answer
    can go either way. In `(a=1 OR fn(...))` the call removes the rest of its group
    (F-03, UC-2.6.34). Not flagged: a call after `=`, `<`, `>`, `!` or inside a word
    (`user=*match(x)`), a call in `where`, `eval`, `fields`, `stats`, `if(` and the like,
    and functions outside the 25 (`strftime` was probed in `where` only and is not listed).
  * `L002` `timechart` or `sitimechart` with more than one `by` field. Comma and space
    separated forms, and three fields, were rejected ("The argument ... is invalid");
    one field with options, `where` or `eval` was accepted.
  * `L003` `match`/`like` with 1, 3 or 4 arguments and `cidrmatch` with 1, rejected in
    `where` and `eval` ("The arguments to the function are invalid"); 2 arguments
    accepted. The same call in a search clause is **accepted and never evaluated** (UC-2.6.45),
    so there only `L001` applies (the earlier F-07 wording was wrong, see below).
  * `L004` a regex string for `match` or `replace` that ends in one backslash after
    eval unescaping: an odd number of backslash pairs halves to a lone backslash. 2 and 6
    raw backslashes were rejected ("Regex: \ at end of pattern"), 4 and 8 accepted.
  * `L005` a snap modifier with a count (`-6h@5m`) or `@w8`/`@w9`: `tstats` rejects it
    ("Invalid value ... for time term"), and a plain search selects nothing.
  Rules that were considered and not shipped: anything that needs the data (field
  existence), anything about add-on specific fields, and functions that were not probed on the lab.
* **Corpus measurement** (`tools/spl_lint_corpus.py`, Fenre `0e21f019`: 16,689 records
  with SPL, 19,771 searches counting CIM variants; ESCU 6.11.1: 2,214): 141 Fenre searches
  have findings. `L001` 80 (`match` 61, `like` 12, `lower` 5, `isnotnull` 4, `cidrmatch` 2,
  `isnull` 2, `upper` 1), `L002` 56, `L003` 1 (UC-2.6.44), `L004` 3 searches with 7
  calls (UC-1.2.29, 1.2.66, 1.2.119), `L005` 1 (UC-3.2.1). ESCU: 0. All 61 searches
  flagged by `L002` to `L005` were sent to Splunk's own parser in the app namespace:
  all 61 were rejected, so those four rules had no false positive on this corpus.
  Lists: `docs/upstream/SPL_LINT_CORPUS.md`.
* **Difference from 51 and 54.** The assessment's heuristic reproduces 51 and 54 on
  this commit. The lint finds 61 searches with `match` as a search term (10 more: the call
  sits in a subsearch of `multisearch`, `append` or `join`) and 56 with two split-by
  fields (2 more: UC-15.4.4 and UC-15.5.8 separate the fields with a space). It also
  finds the other eval functions (19 more searches, 80 in all), which the heuristic did
  not look for. Its false-positive rate on `L002` to `L005` is 0 of 61 against Splunk's
  parser; for `L001` the evidence is the probes above, because Splunk gives no error.
* **Where it shows.** The validation result and `GET validation` carry `lint`
  (`validate` also lints the CIM variant, tagged `cim`). The use-case validation card
  lists the findings with a **Dismiss** button that hides one until the page is reloaded
  and stores nothing. The deployment card shows a non-blocking note from the revision's
  `lint`. Both are built with `ucm.el`/text nodes. A validation stored before 0.8.9 has
  no `lint`: the card says "lint has not run" and **Validate** again fills it. No
  migration; the field is optional.
* **Issue #14 (silent 50,000-row bound): implemented as surfacing, not as a limit
  change.** `DocumentStore.count` is a keys-only query, so totals stop at the KV
  Store's `max_rows_per_query`. The catalogue now returns `total_capped`; the page shows
  "50000 or more" and a note. Joined filters that must scan more than the bound refuse
  ("narrow the other filters first") instead of returning a partial set. Administration
  warns from 90 percent of the bound. `[catalog] kv_row_limit` (default 50000, 1000 to
  10,000,000) tells the app the platform value; it does not change the platform. Not done:
  readiness, inventory and coverage counts are not marked at the bound, and the
  join scan is not paged, so the issue stays open for those.
* **Issue #13 (CIM model met without a populated check): not done, plan recorded.**
  Not small: it needs one `tstats` per model through the system-dispatch discovery
  path (`datamodel=X where earliest=-24h`), and for a model that is not accelerated that
  search runs the model's whole constraint search, which can be slow on a large estate; it
  needs a bound and a per-search timeout in the discovery worker, a new additive field on
  the discovery data model document (`populated`: `yes`, `no`, `unverified`), a change in
  `eval_cim_model` and in `recommend.py` (which keys on the code `model_present`), and a
  decision on scoring. Plan: run the check inside the discovery job, cache the answer with
  the discovery data, mark `unverified` (never `no`) when it cannot run, and never block
  on it. Decision needed from the product owner: whether a model that is installed but
  not checked becomes `unverified` (excluded from the score, which moves existing
  readiness scores up or down) or stays `met` with the current wording
  "populated data is not verified". Until then the wording is the only guard.
* **B-07 leftovers.** Already done in 0.8.6 to 0.8.8: the corrections to D-039 and
  D-053 (written in D-062 and in the text of D-039), the README and `app.manifest` Cloud
  wording, the `map` refusal hint, the owner note for D-051. Done here: the operator note that
  `admin`, `sc_admin` and `ucm_admin` can edit deployed searches and that the edit
  shows as drift (D-051), a bundle-split guide for the 50 MB cap (below), the §11 wording
  (the owner is the scheduler account, not the operator who clicked Deploy), a version
  and test-count consistency unit test, and a rewrite of §12 so each item is current,
  appears once and points to its issue (#8).
* **Bundle splitting.** The Fenre `content/` tree is about 193 MiB as bundle JSON.
  Category 25 alone is about 65 MB (6,431 records), category 10 is 31 MB, category 22 is
  26 MB, so the default cap refuses the full corpus and category 25. `build-bundle
  --categories` takes whole categories (four groups of 21 to 40 MiB cover 1 to 24).
  `ucm_cli` cannot cut one category, but `--records` can: three id chunks of 2,200 give
  22 to 23 MB each. Records bundles are partial (`manifest.partial`), so they never withdraw. In a test run, importing the three chunks
  gave 6,431 records and 0 withdrawn. The alternative is `[import] max_bundle_mb` up to 500.
* **Corrections to the Sprint 9 upstream report** (`docs/upstream/FENRE_FINDINGS.md`):
  F-06 said `replace(TargetObject,"\\[^\\]+$","")` has the same defect as
  `"^.*\\"`; on the lab it is valid, only the first is invalid. F-07 listed UC-2.6.45 with
  UC-2.6.44; UC-2.6.45's three-argument `match` is in a search clause, which Splunk
  accepts and never evaluates, so it is an F-03 case only. Nothing was filed upstream.
* Security picture: unchanged. No new route, capability, setting that relaxes anything,
  dependency or collection. The lint only adds findings; the policy still refuses what it
  refused. `docs/SECURITY.md` is not changed. The build number is 11 because the JS and
  CSS changed. Python 3.9 compatible, stdlib only.

## D-066 Provider-aware navigation, twin lineage, quality-aware discovery and the Plan deployment step
*0.9.0 (B-11, B-12, B-13, B-18; assessment W4 and W10).*
* Context: the catalogue holds two providers. ESCU is 2,214 detections; 1,121 of them (51 percent)
  sit in the fixed category "Unassigned" and are therefore hard to find by category. Fenre
  category 10 repeats ESCU searches verbatim: on Fenre `0e21f019` and ESCU 6.11.1, 1,778
  primary-SPL hashes occur in both providers (1,780 Fenre records, 1,778 ESCU records), so a
  user can deploy the same search twice. The use-case page also put the deployment form
  first, before the content a reader needs to judge the use case.
* **B-11 provider-aware navigation.**
  * Provider badge (`Fenre`, `ESCU`) on catalogue rows, the use-case header and the recommended-next
    cards. Provider facet, multi-select, counts from the facets document.
  * Category labels carry the provider (`Fenre · 9. Identity & Access Management`, `ESCU · Endpoint`)
    only when more than one provider is in the catalogue; with one provider the labels are as
    before. ESCU ids are not shown as numbers (they are a fixed list, not a Fenre-style index).
    Category **ids** and the `category` URL parameter are unchanged, so every bookmarked URL works.
  * `analytic_stories` and `data_sources` are new summary fields filled from the ESCU annotation
    (normalizer `escu-1.1.0`). They are facets (top 30 stored per record, top 600 values
    stored per facet; the page shows a find box above 12 values) and filters (`story`,
    `data_source`). They are how ESCU use cases in Unassigned are found: all 1,121 of them carry a
    story. Unassigned records stay visible and filterable (category `escu_cat-unassigned` still
    exists and is listed). A name containing a comma has the comma replaced by a space, because
    `Request.args()` splits a parameter at commas; no name in ESCU 6.11.1 contains one.
  * Facet counts are still computed in the post-pass (`catalog/derived.py`, `FACETS_VERSION 3`) and
    read from `uc_sync_state`; no list query computes a facet. Facets also carry
    `summary: {version, outdated}`.
* **B-12 lineage.** A *twin* is a use case from another provider with the same `spl_hash`
  (SHA-256 of the whitespace-normalised primary SPL, an existing field). The post-pass sets a new
  derived quality flag `provider_twin` next to `duplicate_spl` (both are derived; summary
  rebuilds clear both and the post-pass sets them again). The flag makes "has a twin" a filter
  (`quality=provider_twin`) and a count at no extra cost. The use-case page shows `spl_twins`
  (up to 20, active only, found by an `spl_hash` query; *corrected by D-068:* the field was not declared or indexed in `collections.conf` until 0.9.2, so the query scanned the catalogue) as
  "Same detection in ESCU: <id>" with the title and a deploy-once note ("deploying both creates two
  saved searches"). Links work in both directions and the record is not required to have been
  summarised by 0.9.0: the lookup reads the hash that 0.8.x already stored.
  * **Authority.** `catalog/lineage.py` holds one table: ESCU = "Detection content source",
    Fenre = "Compliance and mapping context". It is a statement about what each provider is
    for, taken from the provider roles, **not** from comparing the two records. The page says that
    the twin test is only that the primary SPL is identical after whitespace is normalised, and that
    title, schedule, severity and compliance mappings can still differ. It does not claim copying,
    origin or equivalence of the whole record. `spl_duplicates` (same provider) keeps its old meaning
    and its own warning.
  * Not done: no merge of twin records, no hiding of a twin, no "deploy once" enforcement. Deploying
    both stays allowed and only warned about. That would be a workflow change.
* **B-13 quality-aware discovery.**
  * `wave` (crawl, walk, run) is a summary field, a facet and a filter. It is Fenre's rollout order;
    ESCU has none, so an ESCU record never matches a wave filter.
  * Quality flags are facets and filters as before. New: `exclude_quality` (hide records that carry a
    flag; nothing is hidden by default) as a "Hide quality flag" facet, and the same option on
    Recommended next (`GET readiness/recommendations?exclude_quality=ai_reviewed,unreviewed`), a
    checkbox that is off by default. Without the parameter the response and the list are as before;
    with it the response adds `exclude_quality` and an `excluded.quality_flagged` count, and a
    list with nothing left is the existing "none eligible" state.
  * `exclude_quality` is a conjunction of `{quality_flags: {$ne: flag}}`, because `$nin` and `$nor`
    are invalid on the KV Store ("The provided query was invalid"; checked on Splunk 10.2.9).
    `$ne` matches an array field that does not contain the value and a document without the field.
  * **Migration (no automatic summary rewrite).** `SUMMARY_VERSION` is 6. Migration 0001 used to
    embed the version in its id, so a bump rebuilt every summary on the first start after an upgrade.
    Its id is now pinned to `0001_catalog_summary_v5`; a 0.9.0 start therefore does **not** rewrite
    the catalogue. The new migration `0004_catalog_facets_v3` writes only the facets document
    (cheap, no catalogue write), which carries `summary.outdated`. The operator presses **Reindex**
    (Content Administration → Catalogue summaries, or `POST catalog/reindex`), which re-derives
    summaries from the stored raw records, with no download.
  * **Degradation before Reindex.** A document summarised before 0.9.0 has no `wave`,
    `analytic_stories` or `data_sources`, so those three filters skip it and never error. The
    catalogue, Overview and Administration show an amber hint ("Reindex needed ...", N of M) while
    `outdated > 0`, and an empty result under a wave/story/data-source filter says why. The provider filter,
    `exclude_quality`, `provider_twin` and the twin links work without Reindex because `provider`,
    `quality_flags` and `spl_hash` exist in the version 5 summary. Existing filter URLs are
    untouched: every parameter that existed keeps its meaning.
  * Invalid input is refused as before (`invalid wave`, `invalid quality flag`, tokens with control
    characters), never a server error.
* **D-059 parity.** Every new filter is part of `build_query` and therefore of both the join
  path (`_key $in`) and the scan path; the parity tests now run the join and scan paths with
  provider, wave, story, data source, `exclude_quality` and `provider_twin`, for every sort and a
  page that is not the first (`tests/unit/test_provider_navigation.py`). The row-limit and
  join-bound behaviour of D-059 and D-065 is unchanged.
* **B-18 Plan deployment.** The selection box, review state and deployment form are still the same
  code with the same permissions, guards and requests; they now sit in one panel after the content
  sections (after References, before Provenance), collapsed by default. A status row above the
  button shows selection, readiness, deployment state, live saved-search state, drift and
  "provider content changed" without expanding, together with the actions the user can take now.
  The button is a real `<button type="button">` with `aria-expanded` and `aria-controls`; the "Your
  selection" and "Plan deployment" jump links and the `#ucm-sec-selection` / `#ucm-sec-deployment`
  hash open it. Nothing about the deployment workflow, allowed actions or REST routes changed.
* **Latency, before (0.8.9) and after (0.9.0).**
  * Lab REST, 270 active use cases (141 Fenre, 129 ESCU), 2,359 documents, median of 9 runs:
    first page 20 ms before and 19 ms after; `domain=security` sorted by criticality 20 and 19;
    `quality=duplicate_spl` 20 and 18; `availability=ready` 27 and 27; `q=powershell` 20 and 20;
    status any, offset 2000: 28 and 28; `catalog/facets` 11 and 11. New filters after, median
    ms: `provider=escu` 20, `wave=crawl` 20, `story` 18, `data_source` 18, `exclude_quality` 20.
  * Synthetic corpus (`tools/perf_catalog.py --escu`, real KV Store, lab documents plus 20,000 and
    47,000 copies, so 22,359 and 49,359 documents, hashes salted so no copy twins a real record),
    median ms before → after, 5 runs. 22,359 documents: first page 89 → 85, `domain` sorted by
    criticality 78 → 78, `mitre` 64 → 64, sourcetype 62 → 63, offset 15,000 100 → 110, page
    without total 34 → 34. 49,359 documents: first page 204 → 177, domain sort 211 → 157,
    mitre 171 → 116, sourcetype 163 → 113, offset 15,000 237 → 198, page without total 92 → 64 (the
    0.8.9 figures were measured with the tool run from a second checkout; the difference at
    49,359 is noise between runs, not an improvement the change should be credited with). New
    filters at 49,359 documents: provider 113, provider plus domain 155, wave 179, story 106, data
    source 114, `exclude_quality` 163, provider plus availability 24.
  * Facets: reading the stored document 8 ms. Recomputing them (one fields scan of the catalogue,
    which now also reads provider, wave, stories and data sources) costs more: 375 → 514 ms at
    22,359 documents and 917 → 1,092 ms at 49,359. The post-pass (derived flags and facets) is
    1,092 → 1,125 ms and 3,006 → 2,303 ms (the larger corpus' 0.8.9 run had one slow write
    batch, max 5,076 ms). The post-pass runs on every sync, import and reindex, never on a list request.
  * Reindex on the lab: 12 s for 2,359 documents (5 ms per document); it is synchronous.
* **Migration verified on the lab.** 0.8.9 with 2,359 documents (270 active) upgraded to 0.9.0:
  the worker applied `0004_catalog_facets_v3` only, all summaries stayed at version 5,
  `summary.outdated` was 270, `wave`, `story` and `data_source` returned 0 results without error,
  `provider`, `exclude_quality` and `quality` filters returned results. After Reindex: all 2,359 at
  version 6, `outdated` 0, waves crawl 130, walk 10, run 1, 52 stories, 79 data sources, and a second
  Reindex left the catalogue identical.
* Risks and limits, stated: twin detection needs the same SPL after whitespace normalisation; a
  rewritten search with the same meaning is not a twin. Authority is a provider-level statement.
  Reindex is synchronous (about 5 ms per use case, about 4 minutes at 49,000) and blocks one REST
  call. Facet values are capped (top 600 stored, 30 per record), and names with a comma lose it.
* Security picture: unchanged. No new route, capability, setting, dependency or collection; no SPL
  refusal, approval control, capability check or ACL was relaxed. All new text is built with
  `ucm.el` and text nodes. Python 3.9 compatible, stdlib only. The build number is 12.

## D-067 ES and ESCU read-only hand-off, and the populated check for CIM data models
*0.9.1 (B-10, W1, W9, N5; issues #4 and #13).*
* Context: ESCU detections are alerts that Enterprise Security (ES) is built to run: their
  stanzas carry `action.notable` and `action.risk`, and ES Content Management enables, tunes
  and groups them. A SUN deployment is a plain scheduled saved search owned by the scheduler
  account (D-051). On an ES search head the two would run side by side and the SUN copy would
  have no notable or risk action. The product has no ES lab, so everything that needs ES to be
  installed is built from documentation and mocks and is stated as unvalidated.
* **Rule that does not move.** SUN does not create ES-managed content, writes nothing into
  another app, and adds no output mode. Alerts stay `es_only` in the sense of D-052 and #4:
  an ES output mode (findings, notable events, risk) is still not built; it needs an ES lab.
  No SPL refusal, approval control (four-eyes, no self-approval), capability check or ACL
  was relaxed, and no bypass was added. The only new policy surface is a read.
* **Detection (read-only, system token).** `platform/security_content.py`:
  `GET /services/apps/local/<app id>` for ES (`SplunkEnterpriseSecuritySuite`; the id and
  releases 8.x were checked on the Splunkbase API, app 263, and the ES 8 documentation; no
  different id was found for ES 8) and for ESCU (`DA-ESS-ContentUpdate`, 6.11.1 on the lab,
  verified). A disabled app is `disabled`, a 404 is `not_installed`, any other read failure
  (403 included) is `unverified` with a reason and is never read as "not installed". The
  reader runs only with the handler's system session (a viewer cannot read other apps) and
  never raises. Reads are cached for 60 seconds in the handler process. No new route: the
  result is `security_content` in `GET platform` and `escu_handoff` in `GET usecase`.
* **Platform card.** Content Administration → Platform has a row "Security content apps"
  ("Enterprise Security 8.x installed; ESCU 6.11.1 installed", "not installed" or
  "unverified (reason)"). The brief called it the Overview platform card; Overview has KPI
  cards and the scheduler card, and the platform capabilities card is in Content
  Administration, so the row is there. Both pages read the same `platform` response.
* **ESCU use-case card.** The saved search ESCU shipped for a record is read with
  `GET /servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/<stanza>`; the stanza name is the
  `stanza` the importer stored in `provider_extras`, else `ESCU - <title> - Rule`. The card
  shows `enabled`, `disabled`, `not_found` or `unverified`, the cron schedule, the time range
  and whether the stanza has the notable and risk actions. Wording by case: ES installed:
  "enable it in ES Content Management"; ESCU without ES: "the shipped search is disabled (or
  enabled) and nothing manages it; SUN can deploy an independent copy"; stanza missing in the
  installed ESCU: say so; ESCU not installed: no shipped search to enable; unreadable: "do not
  assume it is disabled". Cached for 60 seconds per stanza.
* **Deep link.** With ES installed the card links to the ES app's Content Management page,
  built from the app id and the view name `ess_content_management`, as a same-origin URL from
  the current page path (`isSafeHref` still only allows same-app view names, `?`, `#` and
  http(s), so a cross-app link is assembled in the card and refused for any app id that is not
  a plain identifier). The path is not verified on any ES version and the card says so ("the
  exact path varies by ES version"). The ES 8 menu route (Security content, Content
  management) is given in words.
* **Parallel-copy warning.** The Deployment panel shows a non-blocking warning for an ESCU
  use case when ESCU's stanza is enabled or ES is installed. It is text only: Deploy, Enable,
  four-eyes and every gate are the same. The existing acknowledgment is `review_commands`
  only, and no free-text acknowledgment exists, so no new one was added. What is recorded:
  the draft revision carries `parallel_copy` (`warned`, `es_installed`, `escu_enabled`,
  `stanza`, `stanza_state`, `read_at`) and the draft audit event carries the same key; they
  are absent when no warning applied. The approver sees it with the revision.
* **Coverage semantics (Q-3).** "Enabled in ES" and "enabled in ESCU" never count as enabled in
  SUN coverage. Coverage counts searches SUN deployed; the card says so in one sentence and
  Coverage is not changed.
* **What was validated, what was not.** Verified on the lab (Splunk 10.2.9, ESCU 6.11.1, no
  ES): ESCU detection and version, the real stanza state, cron, time range and actions of a real
  ESCU saved search (compared with the REST value), the not-found case, the viewer path
  (the viewer sees the card though cannot read the ESCU app), the draft without a warning. Mocked
  in unit and JS tests only: ES installed (ES 8 version strings, the link, the "enable it in ES"
  wording, the warning with ES), a 403 on the app list, a non-admin caller, unreadable stanza,
  a stanza that appears or disappears between reads. These cases are unvalidated. If ES is
  found to use another app id or another Content Management route, the constants
  `ES_APP_IDS` and `CONTENT_MANAGEMENT_VIEW` are the only places to change.
* **Issue #4.** The issue stays open for the ES output mode. Its decision note is: until an ES
  lab exists SUN hands off to ES Content Management instead of writing ES content; a future
  output mode must not weaken the governed deployment and must be built against a real ES 8.
* **Issue #13, populated check.** Decision on the open question in D-065: a CIM data model that
  is installed stays `met` with code `model_present`, whatever the check finds, so no score and
  no recommendation changes. The check adds a separate `populated` value shown next to it.
  * Where it runs: the discovery job (system dispatch path, same as the pair scan), after the
    model inventory. One search per model: `| tstats count from datamodel=<model> where
    earliest=-24h`, run in the model's own app namespace so app-scoped models are visible.
    The name must be a plain identifier (`[A-Za-z0-9_.-]`, up to 80 characters); no other name
    reaches the search string.
  * Which models: those a catalogue requirement or a local datamodel mapping references, then
    the models of the CIM app (`Splunk_SA_CIM`), by name, up to `populated_max_models` (30).
    Others are `unverified` with the reason `not_referenced`. On the lab, which has no CIM add-on,
    the two internal models are therefore `not_referenced`.
  * Bounds: a per-search time limit (`max_time = populated_timeout_seconds`, 30, the search is
    finalized by Splunk; `timeout` on the oneshot is only the job's time to live, measured), a
    total budget of half the discovery job timeout, and a stop after three consecutive
    failures. A finalized search that counted 0 is `unverified` (`timeout`), never `no`, because
    a partial count of 0 proves nothing; a finalized search that counted more than 0 is `yes`.
  * Result per model: `yes` (count above 0), `no` (the search ran to completion and the count
    is 0) or `unverified` with a reason (`check_disabled`, `not_referenced`, `model_cap`,
    `time_budget`, `timeout`, `search_failed`, `search_unavailable`, `stopped_after_failures`,
    `no_result`, `invalid_name`). Stored additively on the data model document of the
    discovery data (`populated`, `populated_reason`, `populated_count`, `populated_window`,
    `populated_at`) and as `totals.populated` on the job. Documents from before 0.9.1 have none
    of these and read as `unverified` ("predates the check; run discovery again"). No schema
    migration.
  * Shown: a separate chip on the CIM requirement ("populated: yes / no / unverified") with the
    sentence, a line in the readiness explanation and the same sentence in the recommendation
    reasons. `met` still means "the model definition is installed". A model with `no` is still
    `met`; it is a hint that the data is not CIM-tagged or the model is not accelerated.
  * Limits, stated: `yes` means events matched the model's constraints in the last 24 hours at
    discovery time; it does not say the fields a search needs exist, that acceleration is
    current, or that the sourcetype is tagged for the needed dataset. For a model that is not
    accelerated the search runs the model's constraint search, which can be slow; the limits
    above bound the cost. The window is the discovery time, not the assess time.
  * Setting: `[discovery] populated_check` (default `true`), `populated_max_models` (30) and
    `populated_timeout_seconds` (30), in `ucm.conf.spec`, the default `ucm.conf` and the config
    DEFAULTS. With the check off, the models are `unverified` with `check_disabled` and no model
    search runs.
  * Lab result: temporary models, one matching `index=_internal` and one matching a sourcetype
    that does not exist, were `yes` and `no`; a model nothing references was
    `unverified/not_referenced`; with the setting off, `unverified/check_disabled`; readiness for
    the same use case was `met` in both cases with the same score (live tests
    `LivePopulatedTest`). The models and mappings were removed.
* **Housekeeping.** The live macro-probe test now creates a uniquely named lookup and deletes it;
  the leftover `ucm_probe_own` saved search and `sun_live_probe.csv` were removed from the lab.
  **Reindex stays synchronous:** a background job needs a new job document type, a worker
  branch, status and cancel endpoints, polling in the UI and a decision about which token
  writes the catalogue, so it was not simple with the existing job mechanism (a draft is in
  `docs/ISSUES_PENDING.md`).
* Security picture: new system-token reads, all read-only: `apps/local/<ES and ESCU app id>`,
  and `saved/searches/<ESCU stanza>` in the ESCU app namespace (name length-limited, control
  characters refused). The result is visible to every app user (a viewer sees the card), carries
  names, versions and flags and never the stanza's search text. One new search shape in
  discovery (`tstats count from datamodel`) for a validated model name, with a time limit. No
  new route, capability, collection or dependency; no SPL refusal, approval control, capability
  check or ACL was relaxed. Python 3.9 compatible, stdlib only. The build number is 13.

## D-068 Leading command names in the SPL guard, a scheduler role that cannot write, acceleration read from the listing, licence

*0.9.2 (Sprint 13 of the 2026-11 roadmap; research findings N-1, N-2, N-6, N-7, N-8, N-9).*
* Context: an isolated research run on Splunk Enterprise 10.2.9 (2026-11-25) showed that Splunk
  runs the first word of a bracket as a command when it is a command name, and that neither guard
  saw it. `| makeresults count=3 | appendpipe [ collect index=x ]` wrote 3 events (interactive and
  scheduled), `append [ outputlookup f.csv ]` emptied an existing lookup, and `append`,
  `appendcols`, `union`, `join`, `multisearch` and an unpiped `map search="collect ..."` ran
  `collect` too. Splunk's `/services/search/parser` lists only the outer commands
  (`makeresults, eval, appendpipe`), so only the static analysis can see them. A role with only
  `search` and `schedule_search` could write because Splunk's `[default]` stanza grants
  `run_collect`; `ucm_scheduler` imported `user`, which also grants `output_file`, `run_dump`,
  `run_sendalert`. D-062's claim that subsearch side effects were refused was therefore wrong for
  this position.
* **Decision, guard.** `analysis._split_pipeline` marks the first segment of a bracket as `sub`
  (before: `level`, read as an implicit `search`). `_segment_command` resolves the command of every
  segment, and Python and JS share the rule:
  * `sub`: a word followed by a comparison (`delete=1`) stays a search term; otherwise a side-effect,
    indirect or generating command name (`analysis.GENERATING_COMMANDS`) is that command; inside
    `appendpipe [ ... ]` (a subpipeline, `_SUBPIPELINE_HOSTS`) every first word is a command, so an
    unknown one needs review.
  * `level` (start of the search, of a `map` string, of a search sent without `search`/`|`): a
    side-effect or indirect command name is that command; anything else stays `search`.
  * `INDIRECT_COMMANDS` moved to `analysis` (policy re-exports it); the JS guard carries
    `GENERATING_COMMANDS`, checked equal by `GuardListsTest`. `map` is found with the same resolver,
    so `[ map search="..." ]` is analysed as well.
* Evidence: unit tests for every variant run on the lab (`LeadingCommandTest`, uppercase and
  no-space forms, `delete`, `sendalert`, `dump`) and the Python/JS parity corpus extended with them.
  Corpus run (old and new code, static analysis): Fenre `0e21f019` and ESCU 6.11.1, 21,985 primary
  and CIM searches: **0** changes in side effects, indirect, unknown or hidden. 22 searches now list
  `mstats`, `tstats` or `inputlookup` instead of `search` for the first word of a subsearch, which is
  what Splunk runs; their lint findings are unchanged.
* Residual: an add-on command written as the first word of an `append`/`join`/`union` subsearch is
  still read as a search term (the guard cannot know every add-on command). The role below is the
  barrier for that case.
* **Decision, scheduler role.** `role_ucm_scheduler` no longer imports `user`. Measured on the lab:
  a role that imports `user` and sets `run_collect = disabled` / `output_file = disabled` still holds
  both (effective capabilities from `authentication/current-context`) and wrote with
  `appendpipe [ collect ]`. A role without imports that lists `search`, `schedule_search`,
  `get_metadata`, `input_file`, `list_metrics_catalog`, `run_custom_command`, `srchIndexesAllowed = *`,
  `srchIndexesDefault = main` and `run_collect = disabled`, `run_mcollect = disabled` searched normally
  and got "insufficient privileges" for `appendpipe [ collect ]` and `outputlookup`, and "capability
  run_sendalert required" for `sendalert`. That is the shipped role. `run_custom_command` stays because
  add-on commands in approved searches need it; they are reviewed at approval. Internal indexes
  stay excluded as before (`*` never matches them, D-063). `tests/unit/test_scheduler_role.py` and
  the live `LiveSchedulerRoleTest` check it. An operator who extended the role through `user` has to
  add those grants to `ucm_scheduler` directly (operator guide §4).
* **Decision, acceleration.** `GET /services/data/models` on 10.2.9 reports `acceleration` as a
  top-level boolean (and `acceleration.earliest_time`); `eai:data` has no `acceleration` key;
  `datamodel/model/<name>` returns it as a JSON string. Discovery read only a dict inside `eai:data`,
  so every model was `accelerated = false` and `summariesonly=t` requirements were `not_accelerated`.
  `_is_accelerated` now accepts the boolean, the JSON string and the old dict; the model's app is
  taken from `acl.app` first. A trimmed real response is `tests/fixtures/rest/data_models_10_2_9.json`
  (an accelerated temporary model, created and deleted on the lab). Discovery stores
  `acceleration_earliest` with the model. A CIM model in `Splunk_SA_CIM` was not available on the lab;
  the app attribution for it is unverified.
* **Paging (N-7).** Not a server defect: every list caps the page at `[catalog] max_page_size` (100)
  and returns the effective `count`; a client that advanced the offset by the requested 500 read 7
  pages of 100 from 3,271 rows (700) and stopped. Lists now return `next_offset` (the offset of the
  next page, or `null`) next to `has_more`; `tests/unit/test_paging.py`.
* **`spl_hash` (N-6).** D-066 said the twin lookup used an indexed field; `collections.conf` declared
  neither the field nor an index. Both are declared now (`accelerated_fields.by_spl_hash`).
* **Licence (N-8).** The repository and the package carry `LICENSE` (proprietary, all rights reserved,
  the owner's choice pending; equal to the legal position without a file) and
  `THIRD_PARTY_NOTICES.md`: Fenre (MIT; the app ships `uc.schema.json` verbatim, now with Fenre's
  `LICENSE` next to it; test fixtures are verbatim records) and ESCU/`security_content` (Apache
  License 2.0; no ESCU content is shipped; bundles built from an ESCU package keep that licence).
  `app.manifest` names the licence. `LicenceFilesTest` keeps the package copies equal. The product
  research of 2026-11 used other apps for ideas only; nothing of theirs is in the repository.
* Drift (N-9): `ARCHITECTURE.md` now says the first 1,500 characters of the description are
  searched; `config.py` defaults for the deployment time range equal `ucm.conf` (`-20m@m`, `-5m@m`).
* No route, collection or dependency was added; no refusal was relaxed. Python 3.9 compatible,
  stdlib only. The build number is 14.

## D-069 Operational health: dispatch failures, health and schedule advisories, cron jitter

*0.9.3 (Sprint 14 of the 2026-11 roadmap; research findings F-05, F-18).*
* Context: run status (D-031) counted scheduler lines with a `status`. On Splunk 10.2.9 a scheduled
  search that Splunk refuses before it runs writes an `ERROR` line in `sourcetype=scheduler` with
  only `savedsearch_id="<owner>;<app>;<name>"` and `message` (no `savedsearch_name`, no `status`).
  Measured on the lab with two probes owned by `ucm_scheduler`: `| makeresults | collect ...`
  ("Error in 'collect' command: You have insufficient privileges") and a missing lookup ("Could not
  construct lookup"), one line per minute each, nothing else. Both were shown as "no runs". A
  search Splunk's parser rejects (`nosuchcommand`) cannot be saved at all (400), so it never gets
  this far.
* **Decision, health.** `HEALTH_SPL` reads both forms (`savedsearch_name="SUN - *"` in the app, or
  `savedsearch_id="*;sunavigator;SUN - *"`), names the row from either, and counts lines without a
  status as `dispatch_errors` with `last_error` and `last_error_time`; it also returns the last skip
  reason and the p90 and maximum run time. `classify` returns the new status `failing_dispatch`
  when the latest dispatch error is newer than the latest run (or there are errors and no run).
  Coverage's *operational* level keeps requiring `operational`, so a failing search is no longer
  counted there. Advisories are findings with a code, severity, message and evidence
  (`spl/findings.py`, shared with the schedule advice): H001 dispatch errors, H002 skipped ≥ 20%
  of runs, H003 p90 run time above the cron interval, H004 maximum run time above it. They never
  change a status. Evidence: `LiveDispatchHealthTest` (missing lookup, read through `HEALTH_SPL`
  as `failing_dispatch` with H001), unit tests in `test_frameworks.py`; the lab's one healthy
  deployed search still reads `operational` with no advisory.
* **Decision, schedule advice.** Saving a draft stores `schedule_advisories` on the revision
  (`deployment/schedule.py`): S001 every-minute cron, S002 window shorter than the interval (gaps),
  S003 window longer than the interval without suppression (double alerts), S004 `latest=now`
  (late events), S005 interval not derivable. The interval is computed only for minute/hour step
  and list forms; anything else is S005, not a guess. Advice is informational and does not block
  submit or approval.
* **Decision, cron jitter.** `[deployment] cron_jitter = true` (default): a draft that does not set
  `cron` and whose default is `*/N * * * *` gets `o-59/N * * * *`, with `o = sha256(use case key) mod
  N`, so the offset is stable per use case and searches spread over the interval. An explicit cron
  is never changed; existing revisions are not rewritten. Drift checks compare against the stored
  revision, so jittered searches do not report drift.
* Not done: health for searches deployed outside SUNavigator, and alerting on a health change
  (both need a product decision on notification channels).

## D-070 Data evidence beside readiness, 30-day freshness, the environment health panel and the summary check

*0.9.4 (Sprint 15 of the 2026-11 roadmap; research findings F-04, F-06, F-08, F-19 part).*
* Context: readiness answers "is what the content needs installed and configured". It did not say
  whether the data the search reads was ever seen: a use case whose data model is installed but
  empty, or whose sourcetype stopped a month ago, read as ready. Research on the lab also showed
  that a data model can be accelerated with its summary built and still answer `summariesonly=t`
  searches with nothing when the summary is empty (the summary entry does not exist until the first
  build, which the old check never looked at).
* **Decision, data evidence (`readiness/evidence.py`).** A separate dimension, stored with each
  assessment as `data_state` and `data_evidence`: `seen`, `partial`, `none`, `unverified`,
  `not_applicable`. Built from the stored requirement results only (no search). Sourcetype and index
  requirements count as seen when present, missing when not found, stale when partial; a data
  model counts as seen only when its populated check says `yes`, missing when `no`; sampled fields
  count as seen or missing. Informational requirements, collapsed any-of members and non-data
  types are left out. It never changes a readiness state, score or coverage. The engine version is
  `ucm.readiness/5`, so every stored assessment is recomputed once (the worker queues it).
  The recommender leaves out use cases whose data state is `none` (`excluded.no_data_seen`) and
  its reasons say what data it found. Recommender formula `ucm.recommend/2`.
* **Decision, freshness (F-08).** Discovery runs two more bounded tstats passes over the indexes it
  already searched: events per pair over `[discovery] freshness_days` (default 30, `0` disables),
  and events stamped more than five minutes in the future (`earliest=+5m latest=+10y`). A pair seen
  only in the longer window is stored `stale_from_start` with `window_count` 0, so readiness reads
  the source as stale instead of not found. Index and pair documents gain `volume_30d`,
  `future_count`, `future_last_time`. A failed pass is counted in the totals and does not make the
  job partial. The pass adds at most two searches per index group of 40.
* **Decision, summary check (populated.py).** For an accelerated model whose populated check says
  `yes`, discovery runs `| tstats summariesonly=t count ... earliest=-24h` and stores
  `summary_count`. Measured on the lab (10.2.9, a temporary accelerated model created and deleted):
  the summary-only count was 318,485 against 319,119 for the full count, so the summary was built;
  a model whose summary is empty answers 0. The environment health panel reads
  `summary_built`, `summary_partial`, `summary_not_built`, `no_data`, `summary_unverified` or
  `not_accelerated`. A failed summary search leaves the count unset (unverified), never zero.
* **Decision, environment health (`discovery/health.py`, `GET ucm/environment/health`).** A read-only
  panel built from the last discovery: CIM add-on version and accelerated models, data-model summary
  states, CIM index macros (their definition is now stored, only for `cim_*_indexes` macros, and an
  unconstrained one is flagged), enabled indexes without data, sources that stopped before the
  window, future-dated sources, and active sourcetypes that no requirement and no mapping names
  (the review list for unmapped sourcetypes). Every list is capped at 50 and says so. Readable by
  every app user, like the other read routes; it reads no raw events.
* **Decision, field profile (`discovery/profile.py`, collection `uc_field_profile`; F-07).** Discovery
  profiles the fields that active use cases require, one search per sourcetype, against the index that
  holds most of its events in the discovery window. Each search takes the newest `profile_sample_events`
  (default 1000) events of the last 24 hours and counts, per field, the events where the field is
  present and non-blank (fill rate) and where it holds a placeholder (`-`, `N/A`, `0.0.0.0`, ... configurable).
  Only counts, rates and the sample size are stored; no event value leaves the search. Bounds:
  `profile_max_sourcetypes` (busiest first), `profile_max_fields`, `profile_timeout_seconds` per search and
  `profile_budget_seconds` per job; anything beyond a bound is counted as skipped in the job totals
  (`field_profile`). `field_profile = false` turns it off.
* Readiness uses the stored rates as field evidence: a field with a fill rate below 0.5, or a placeholder
  rate above 0.2, is treated as missing data and listed in `missing_fields`. A field that was never
  profiled stays unverified. Readiness reads the last profile; it does not run a search.
* Not done in 0.9.4 (listed as open): the "open in search" link with resolution hints (F-19) and the CIM
  field reference. They need their own review of what the drilldown may run.
* Evidence: `tests/unit/test_data_evidence.py`, `test_freshness.py`, `test_environment_health.py`,
  `test_populated.py` (summary search), `test_field_profile.py`; the lab check above, which ran the
  profile search against `_internal` `splunkd` on Splunk 10.2.9 (`tests/live/test_live_splunk.py`
  `LiveFieldProfileTest`).

## D-071 Licence: Apache License 2.0 for SUNavigator's own code, content and documentation

*0.9.4 (owner decision, 2026-11-25; supersedes the licence statements in D-068 and the Sprint 13 notes).*
* Context: the repository was public with no licence, and the first proposal (a proprietary
  "all rights reserved" licence) did not match the owner's aim: the app should be usable by everyone,
  without limits, including building on it and selling it.
* **Decision.** SUNavigator is released under the Apache License, Version 2.0 (`LICENSE`, the
  unmodified licence text; `NOTICE`, the copyright and third-party attribution). Reasons: it allows
  free use, modification, redistribution and commercial use without requiring derived works to be
  open; it grants patents explicitly; and it is the licence of ESCU, so ESCU-derived bundles
  (`tools/ucm_cli.py build-escu-bundle`) match the outer licence. MIT would also have been acceptable;
  Apache-2.0 was chosen for the patent grant.
* Unchanged: Fenre's use-case content stays under its MIT licence (`content/fenre/LICENSE`), and
  `THIRD_PARTY_NOTICES.md` lists it. The copyright line in `NOTICE` names the contributors and the
  repository, not an individual.
* Consequence: anyone may fork, modify, sell or embed SUNavigator. They must keep the licence and the
  `NOTICE` attribution, and state changes where the licence requires it (Apache-2.0 sections 4 and 5).
  No warranty is given (section 7).
* The repository visibility is public and stays public (owner decision, 2026-11-25).

## D-072 Owner decisions of 2026-11-25: no data lowers the score, macro help, email and webhook actions, Fenre findings stay in the repository

*0.9.5 (owner decisions; they close the open questions in the expanded assessment, section 12).*

* **Decision, an installed but empty data model is `partial` (supersedes the informational wording of D-067 and issue #13).**
  When discovery's populated check found no events in 24 hours, the CIM requirement is `partial` (code
  `model_empty`, weight 0.5) instead of `met`. The explanation and the recommendation reason say the model holds
  no events and tell the operator to check data ingestion: that the sources which feed it are sending, that their
  add-ons tag and normalise events to it, and that the scheduled account can read the indexes. `unverified` and
  `yes` are unchanged. Engine `ucm.readiness/6` recomputes every stored assessment once. The check is a
  24-hour snapshot taken at discovery; a model that is quiet at night reads `no` until the next discovery.
* **Decision, macro help, not macro creation (answers issue #10; Option 1 without a link).** No "Add Macro" button
  and no write path. A macro requirement that is not met or only app-scoped gets a "How to create this macro"
  section with the steps (where to open Search macros, the exact name and argument count, what the definition is,
  sharing, re-run discovery) and a warning that an empty definition would read as met while returning nothing. The
  status badge has a tooltip saying SUNavigator never creates or changes macros. No deep link is built because the
  Splunk Web path is not verified across versions.
* **Decision, email and webhook actions are chosen by the drafter and decided by the approver (answers issue #28).**
  * The draft may carry `actions`: an email (recipients, optional subject and message, link to results) and/or a
    webhook (URL). They are frozen in the revision like the SPL.
  * Destinations are limited by `[actions]` in `ucm.conf`: `email_domains` and `webhook_hosts` (exact or
    `*.example.com`), both empty by default, so nothing can be sent until an administrator names them. `enabled`
    is a master switch, `webhook_allow_http` is false (https only), `max_recipients` is 10, and
    `require_suppression` is true.
  * Rules: actions need the Alert type and a "Suppress repeats for" period (so one condition cannot send on every run);
    results are never attached (`sendresults`, `sendcsv`, `sendpdf` and `inline` are written as 0 and checked for
    drift); script, log-event and every other action kind is refused, not ignored; subject and message are single
    lines; webhook URLs may not carry credentials or fragments.
  * Approval: the approver sees every recipient and URL on the revision, and approving needs
    `acknowledge_actions` (the same mechanism as `acknowledge_commands`). The acknowledgment stores a digest of the
    actions; deploy refuses a revision whose actions changed after it. Without four-eyes
    (`require_approval = false`) the submitter acknowledges. The submitter still cannot approve their own revision.
  * The allowlists are checked again at deploy, enable and rollback, so tightening them stops an old approval.
  * Drift: the frozen actions, recipients, subject and webhook URL are compared with the saved search; a revision
    from before 0.9.5 keeps the old rule (any action is drift). The audit trail records counts, mail domains and
    the webhook host only, never the webhook path, which often carries a token. The revision, the export and the
    saved search do contain the full URL: treat them as secret-bearing.
  * Not built: result attachment, per-recipient approval, templates, and any change to Splunk's mail server.
* **Decision, the Fenre findings (answers issue #20).** The findings F-01 to F-11 stay documented in this repository
  (`docs/upstream/FENRE_FINDINGS.md`, issue #20). They are not sent to the Fenre project by SUNavigator's
  maintainers.
* Open and unchanged: an ES 8 lab (#4, #27) is provided by the owner later; the compliance scope (Sprints 19 and 20)
  and the lab scheduler role follow the recommendations in the assessment (coverage, not assessed compliance; the
  role change is made on the lab only).
* Evidence: `tests/unit/test_actions.py`, `test_populated.py`, `tests/js/test_actions.js`, `test_handoff.js`; the
  lab check on Splunk 10.2.9 (`LiveActionsTest`: draft, refusal without acknowledgment, deploy disabled, the keys read
  back, drift on a changed recipient, removal in a later revision).

## D-073 ESCU depth: enrichment from security_content, event-level data check (Sprint 16)

*0.9.6 (Sprint 16).*

* **Decision, the ESCU bundle may carry facts from `security_content` (answers findings on ESCU depth).**
  * `tools/ucm_cli.py build-escu-bundle --security-content <checkout>` loads a pinned checkout offline (PyYAML is a
    build-machine dependency only; the app never reads YAML) and merges, per detection id, additive fields into the record:
    `status`, `dataSourceDetails`, `supportedTA`, `drilldowns`, `riskEntities`, `tests` (links only), `macroDefinitions`,
    `howToImplement`, `knownFalsePositives`. Every field is length-bounded, links must be `https`, field and value names
    are pattern-checked, and the input record is never modified. A detection without a match is left as it was.
  * The checkout's commit id is appended to the bundle's `source_ref`. The normalizer is `escu-1.2.0`.
  * Nothing is copied from proprietary Splunk apps. `security_content` is Apache-2.0 (THIRD_PARTY_NOTICES.md); SUNavigator
    ships none of it, the bundle is built by the operator, and attack data is never downloaded.
* **Decision, data sources become recommended requirements.** A named data source gives a *sourcetype* requirement
  (confidence medium) and, when it has an event separator, an *event_condition* requirement (confidence low). A macro whose
  definition is exactly `sourcetype=<name>` gives a sourcetype requirement. Recommended, not required: the SPL remains the
  authority on what a search reads.
* **Decision, event-level check (finding F-10).** Discovery checks each distinct (sourcetype, field, value) the active
  catalogue names against the busiest index of the sourcetype: `search index=I sourcetype="S" "VALUE" FIELD="VALUE"
  earliest=-Nd | head 100 | stats count`. The quoted term lets the index narrow events before the field is evaluated.
  Bounds: `event_max_checks` 100, 30 s per search, 300 s in total, window `freshness_days` (7 if 0). Only the count
  is stored (`uc_event_check`). A failed or empty search is counted as an error and stores nothing.
* **Decision, never worse than partial.** Events seen: *met*. Sourcetype present, event type not seen: *partial*
  (`event_not_seen`), because rare events are normal. Sourcetype absent: *unverified*. Not checked (off, beyond the limit):
  *unverified*. Data evidence treats partial as missing, so the data state shows the gap and the recommendation names
  the add-on's input settings to check.
* **Decision, deprecated upstream.** A record whose upstream status is `deprecated` gets the quality flag
  `deprecated_upstream` (hide-able like the others) and a warning on the page. Deprecated detections that ESCU's own
  `.conf` marks are still left out of the bundle, as before.
* **Fix, the field profile never ran (found while building the event check).** `SearchClient.oneshot` accepts only
  generating searches (a leading `|`), and the profile search of 0.9.4 began with `search`, so each profiling search was
  refused, counted as an error and stored nothing. Readiness fell back to the older sample rule, which is why nothing
  looked wrong. Both searches now begin `| search`, and `LiveEventCheckTest` runs the profile and event passes through the
  real search client. After upgrading, run discovery once to fill the field profile.
* Not built: a download of test data or an automatic replay of it; an index-wide event search without a bound; reading
  `security_content` in the app.
* Evidence: `tests/unit/test_escu_enrich.py`, `test_event_checks.py`, `tests/js/test_guidance.js`; on the lab
  (`LiveEventCheckTest`, an enriched ESCU 6.11.1 bundle imported and checked).

## D-074 Brownfield and navigation: graded coverage, data maturity, detections that already run (Sprint 17)

*0.9.7 (Sprint 17).*

* **Decision, graded coverage (finding F-14).** Each technique cell gets a grade: the best single use case on it, its level
  weight times how directly it maps. Level weights: catalogue 0, ready 0.25, deployed 0.5, enabled 0.9, ran without error
  1.0. Match weights: this technique 1.0, through a sub-technique 0.6, through the parent technique 0.4. The best use case,
  not a sum, so many weak detections never add up to a strong one. The counts, the per-level percentages and the D-031
  roll-up are unchanged; the grade is shown beside them (cell tooltip, a *Graded coverage* card, the average over all
  techniques). The weights are SUNavigator's own judgement and are listed on the page, not a Splunk or MITRE measure.
* **Decision, coverage gaps.** The matrix response lists three buckets, first 300 each: data is ready and nothing is
  deployed (the shortest path to coverage), content exists and no use case is ready, and no content in the catalogue.
* **Decision, data maturity is SUNavigator's own scale.** *Raw* (events only), *normalized* (reads a data model),
  *enriched* (also reads a lookup) and *correlated* (reads Enterprise Security data or three or more sourcetypes). It is
  derived from the requirements of a use case, shown as a catalogue facet, and says nothing about Splunk's own definitions.
  A use case that reads no data has no level. Summary version 7 and facets version 4: run **Reindex** once (migration 0005).
* **Decision, catalogue and use-case navigation.** An information strip per provider (version, count, import date), a
  button that copies the address with the current filters, and on a requirement that is not met a specific hint and a
  bounded search (`tstats` or `| search`, built from validated names, opened in Search in a new tab).
* **Decision, detections that already run (finding F-13).** Discovery lists the saved searches the discovery account can
  read in other apps and, for each, computes the hash of its text (the catalogue's `spl_hash`). Candidates are catalogue use
  cases with the same hash (*same search text*), or the same normalised title (`ESCU - ` and ` - Rule` removed) with
  (*same title and technique*) or without (*same title only*) a shared ATT&CK id from the correlation search's
  annotations. The result is a **proposal**; a person with `ucm_run_discovery` accepts one candidate, rejects or resets it.
  * Only the app, name, owner, sharing, enabled and scheduled flags, the hash, technique ids and the candidates are stored
    (`uc_external_matches`). The search text is hashed and dropped, so no role can read another app's search through
    SUNavigator. Searches in SUNavigator's own app are skipped; a search with no candidate is counted, not stored.
  * An accepted match marks the use case *enabled elsewhere* (matrix cell outline, a card, a gap row, a note on the use-case
    page). It never changes `level`: a search SUNavigator did not deploy is not "enabled" in its coverage, because it has no
    revision, approval or drift check. Disabled matches count as matched but not as enabled elsewhere.
  * A decision stands while the search text is unchanged. If the hash changes the proposal is reset and the previous state is
    shown. A search that disappears is marked `missing` and stops counting. A truncated listing never marks anything missing.
  * The listing needs no new role: it is the saved-search endpoint the discovery account already reads. If it is refused,
    matching is skipped and the job is not marked partial. Reading the proposals needs `ucm_run_discovery`; the use-case page
    shows search names only to those holders and counts to everyone.
  * Settings: `[discovery] external_match` (default true), `external_max_searches` (default 20000).
* Not built: an import of another app's SPL, a match by anything but hash, title and technique, counting a foreign search
  towards SUNavigator's levels, and any write to another app's searches.
* Evidence: `tests/unit/test_external_matches.py`, `test_coverage_grading.py`, `test_data_maturity.py`;
  `tests/js/test_external.js`, `test_coverage.js`, `test_catalogue_f20.js`, `test_resolution.js`; on the lab
  (`LiveExternalMatchTest`; a discovery run listed 2436 saved searches and matched 125 to the ESCU bundle by hash).

## D-075 Lifecycle refinements and a tamper-evident audit trail (Sprint 18)

*0.9.8 (Sprint 18).*

* **Decision, the audit trail is a hash chain (finding F-15).** Each audit row carries `prev_hash` (the hash of the row
  written before it) and `hash` (SHA-256 over the row's own fields and `prev_hash`). **Verify audit chain** (Content
  administration, or `GET ucm/audit/verify`, `ucm_admin` or `ucm_manage_content`) re-computes every hash and reports:
  rows whose content changed (*modified*), rows whose predecessor no longer exists (*deleted from the middle*), and places
  where the chain restarts. Rows written before 0.9.8 are counted as *legacy* and are not failures. Two writers that read
  the same head produce a *branch*; branches are counted and are not failures. The oldest chained row may lack a
  predecessor, because the retention purge removes old rows. Each check is itself audited (`audit.verified`).
  * What it cannot do: it cannot see the newest rows being deleted, or the whole collection being rewritten by someone who
    can write it. It is evidence, not prevention. Record the reported `head` somewhere outside Splunk (a ticket, a
    change record) to cover those cases. Reading is paged (5000 rows per request) because the KV Store refuses a query
    for more than 50000 rows; the lab found this on the first live run.
* **Decision, withdraw an approval.** An approved or failed revision that is not yet deployed can be sent back with a note
  of at least 5 characters. The approval and the action acknowledgments are cleared; the revision goes back to
  *pending approval* (or *draft* if no approval was needed). Audited as `deployment.withdraw`.
* **Decision, optional second person to enable.** `[deployment] enable_second_person = true` turns *Enable* into a request
  that a different person confirms within `enable_request_hours` (default 24). The requester can cancel. Off by default.
* **Decision, an override has an end.** Enabling past a blocking readiness state needs a reason (D-050). It now also
  stores who, when and an expiry (`override_days`, default 14, 0 means none). When it expires the app reminds once
  (`deployment.override_expired`) or, with `override_expiry_action = disable`, switches the search off as
  `system:override-expiry`. An override whose gate no longer applies is cleared (`deployment.override_cleared`). The check
  runs in the verification worker and in *Verify all*.
* **Decision, outcomes.** A deployed use case can be marked *needs tuning*, *waiting on data* or *none* with a note. It is
  the owner's statement, not a measurement; it never changes levels or readiness. Retiring clears it.
* **Decision, the Deployments page shows the pipeline.** Counts for draft, pending approval, approved, deployed
  (disabled), enabled, and for needs tuning, waiting on data, override expired, failed and drift. Each is a filter
  (`outcome=`, `override=1`).
* **Decision, revision history and compare.** When the oldest revision is trimmed (`max_revisions`), a stub is kept
  (revision, SPL hash, who created and approved it, times). `GET ucm/deployment/diff` compares two revisions: changed
  settings, an action summary that never shows a webhook path, and a unified diff of the SPL (400 lines at most). If a
  revision is only a stub, the answer says so and lists what remains.
* **Decision, write then verify.** A deployment record is read back after every save; a different version means another
  writer won, and the call fails with `concurrent_update_detected` instead of reporting success.
* Not built: preventing deletion of audit rows (Splunk KV Store has no append-only mode), signing the head, an external
  anchor, and an outcome measured from run results.
* Evidence: `tests/unit/test_audit_chain.py`, `test_lifecycle_refinements.py`, `test_deployment.py`;
  `tests/js/test_lifecycle.js`, `test_admin.js`; on the lab `LiveLifecycleRefinementsTest`.

## D-076 Control catalogues: `ucm.framework/2`, three public NIST catalogues, unmapped controls made visible (Sprint 19)

*0.9.9 (Sprint 19).*

* **Context (finding F-16).** The regulation view lists only clauses that some use case maps to (D-031). A control that
  nobody mapped does not appear at all, so a gap in the standard looks like a smaller standard.
* **Decision, a second definition format.** `ucm.framework/2` (`kind: "controls"`) describes a control framework as a
  list of `{id, title, parent, kind, withdrawn}` in tree order (parents before children), with `regulation_ids` (the
  `regulation:<id>` frameworks of the content provider it applies to) and a `match` rule. `ucm.framework/1` (ATT&CK) is
  unchanged and still validated the same way; the registry accepts both, bundled or imported
  (`POST ucm/frameworks/import`, `ucm_manage_content`). The matrix, navigator and technique endpoints refuse a catalogue
  with a clear error.
* **Decision, the version has a label and a sort key.** `version_label` is text for people ("Rev. 5.2.0", "2.0",
  "Edition ten"); `sort_key` is one to four whole numbers that order versions and form the stored version
  (`[5,2,0]` becomes `5.2.0`). The newest by sort key is active until a content manager chooses another.
* **Decision, bundled catalogues.** NIST SP 800-53 Rev. 5.2.0 (1216 entries, 182 withdrawn), SP 800-171 Rev. 3 (147, 33
  withdrawn) and CSF 2.0 (225, of which 91 are CSF 1.1 subcategories marked withdrawn, leaving the 106 of 2.0), reduced from
  the public OSCAL content at a pinned commit by `tools/control_catalogue_builder.py`. Only identifiers, titles, hierarchy
  and the withdrawn flag are kept; the file records its source URL and the SHA-256 of what was read. Attribution is in
  every file, on the Coverage page and in `THIRD_PARTY_NOTICES.md`. No ISO, CIS or CMMC catalogue is shipped: those are
  not public in a form we may redistribute (CMMC is built on 800-171 and is handled in Sprint 20).
* **Decision, matching.** A mapping `regulation:<id>#<clause>` meets a control when the two have the same canonical
  spelling: with the `nist-800-53` rule `ac-2.1`, `AC-02(01)` and `AC-2(1)` are one control; with `exact` only case and
  spaces are ignored (`3.1.1` is not `03.01.01`; the rule is deliberately narrow because the two numberings differ between
  revisions). The summary of a catalogue row does not store the mapping's version, so matching ignores it: a mapping in an
  older numbering simply does not match.
* **Decision, what is shown.** Every control, with its best level, use cases and a roll-up per ancestor (controls,
  mapped, data ready or better, enabled); totals of controls, mapped, unmapped, ready, deployed and enabled; **controls
  with no mapped use case are listed and filterable**; a withdrawn control is hidden and not counted unless a use case maps
  to it, and the page says how many; clauses a use case maps that match no control are listed under *not in this
  catalogue* and are not counted. A mapped control opens the same use-case list as before.
* **Decision, wording.** "Mapped" is the content provider's mapping. It is not an assessment of the control; that is
  Sprint 20.
* Not built: control text, parameters or guidance; baselines (low, moderate, high); crosswalks between catalogues; a
  catalogue for a regulation whose clauses have no public identifiers.
* Evidence: `tests/unit/test_control_catalogues.py` (22), `tests/js/test_catalogue_controls.js`; on the lab
  (`LiveControlCatalogueTest`). Real upstream mappings sampled (`nist-800-53` `AU-2`, `nist-csf` `DE.CM-04`) match.


## D-077 Assessed state, assessment objectives, POA&M and evidence snapshots (Sprint 20)

*0.10.0 (Sprint 20).*

* **Context.** Until 0.9.9 the app said which controls use cases map to (D-076), never whether a control is met.
  "Mapped" is the content provider's statement; an assessment is a person's.
* **Decision, who may assess.** A new capability `ucm_assess` and a role `ucm_compliance_assessor` (imports
  `ucm_viewer`). `ucm_admin`, `admin` and `sc_admin` have it. Reading assessments, plan items and snapshots needs it too,
  because they contain the organisation's own findings. Everything is written server side with the system token after the
  capability check, and every write is audited.
* **Decision, an assessment is a statement with provenance.** One document per (framework, control) in `uc_assessments`
  with `status` (`implemented`, `partially_implemented`, `planned`, `not_implemented`, `not_applicable`), a mandatory note
  (5 characters, 10 for not applicable), who and when, who assessed first, the catalogue version it was made against, and
  the last 20 changes. After a catalogue upgrade an assessment is flagged *older catalogue version* instead of being
  dropped or silently carried over. Removing one needs a reason and keeps the audit row.
* **Decision, objectives.** SP 800-171 Rev. 3 now carries its 422 assessment objectives (`objectives` on a control, from
  the same NIST OSCAL file). For such a requirement the person records `met`, `not_met` or `not_applicable` per objective
  (not applicable needs 10 characters); the status is derived: every result not met gives not implemented, a mix of met
  and not met gives partially implemented, all met or not applicable (at least one met) gives implemented, all not
  applicable gives not applicable. While some objectives have no result the status is at most partially implemented and the
  requirement is flagged *incomplete*; an objective set back to *not assessed* is removed. The point is that a partly
  assessed requirement is never shown as met. Objective results are stored as a list, because the KV Store refuses a field name that contains a dot (found
  with the in-memory test store and fixed before the first live run).
* **Decision, CMMC Level 2 score.** `cmmc-l2` (110 requirements of 800-171 Rev. 2) is bundled with the point values and
  the partial-credit rules of the DoD assessment methodology v1.2.1 (start 110, floor -203, sum of values 313, cross-checked
  against the methodology's own lists by `tools/cmmc_catalogue_builder.py`). Not assessed counts as not implemented, so the
  score only rises as work is recorded; *best possible* assumes every unassessed requirement will pass. Planned still
  deducts. Only 3.5.3 and 3.13.11 give partial credit. 3.12.4 (system security plan) has value 0 and is a precondition:
  while it is not implemented the page says the assessment cannot be completed. The values come from a Web Archive copy
  of the methodology (the DoD site refused the build machine); the file records the URL and SHA-256.
  *Correction (D-080):* the statement in the first release notes that 32 CFR 170.21 "could not be verified" is withdrawn.
  The eCFR text was fetched and read for Sprint 21; D-080 records what it says and the one informational flag built on it.
* **Decision, POA&M.** `uc_poam` items per control: title, weakness, owner, due date (YYYY-MM-DD), up to 20 milestones,
  state `open`, `in_progress`, `closed`, `risk_accepted`. Closing needs a note, accepting a risk 10 characters. Changing a
  due date needs a note. A closed item is reopened, not edited. Overdue is computed from the date, never stored. A plan
  item does not change the control's status and does not reduce the CMMC deduction.
* **Decision, snapshots.** `uc_assessment_snapshots` holds an immutable canonical JSON of the assessment, the coverage of
  each relevant control and the plan items, with its SHA-256. Reading re-computes the hash and reports a mismatch. The app
  has no way to change or delete a snapshot (200 per framework, 6 MB each). Like the audit chain this is evidence, not
  prevention: someone who can write the KV Store directly can still replace a snapshot together with its hash, so record the
  hash outside Splunk.
* Not built: CMMC conditional status and POA&M eligibility rules (32 CFR 170); assessment objectives for 800-53 and CMMC;
  signing snapshots; deleting snapshots; control text or assessment procedures.
* Evidence: `tests/unit/test_assessment.py` (42), `tests/js/test_assessment_ui.js` (10), `LiveAssessmentTest` on the lab.

## D-078 Platforms without a lab are not validated and not planned

*0.10.0 (documentation; owner decision, 2026-11-25).*

* **Decision.** The owner dropped three validation items because there is no lab environment for them and none will
  be provided: Splunk Cloud (issue #3), a search head cluster with a deployer and indexer peers (issue #2), and
  Splunk Enterprise Security 8 (issues #4 and #27). Issue #18 (scheduler role reads on an SHC and on Splunk Cloud)
  depends on the first two and is dropped with them.
* **What the product says now.** The README support statement, the operator guide (§1 and §12) and the implementation
  plan say that these platforms are not validated and not planned, not "pending". Nothing is removed from the code:
  the cluster-aware leader gate (D-055), the cloud-tag AppInspect pass and the read-only ES and ESCU hand-off (D-067)
  stay as they are, and keep their earlier wording that they were tested without the real platform.
* **ES.** There is no ES output mode (findings, notable events, risk). No test or document in this repository relies
  on ES content, and no premium ES material is stored here.
* **Revisit.** A dropped item is reopened only if a lab for it becomes available. Until then the validation matrix
  shows "not validated" in those columns.
* **Not changed.** No code, schema, route or permission changed. The build number stays 22.

## D-079 Delivery scope: the Sprint 20 limits stay, the 94-fixture re-run is skipped

*0.10.0 (documentation; owner decision, 2026-11-25).*

* **Decision.** 0.10.0 is delivered as built. The four limits listed under D-077 stay as they are and are not
  planned: CMMC conditional status and POA&M eligibility (32 CFR 170), assessment objectives for SP 800-53 and
  CMMC, signing snapshots, and deleting snapshots. The re-run of the 94 control-test fixtures with add-ons
  (issue #23) is skipped.
* **Consequences.** Issue #23 is to be closed as not planned. The campaign results in
  `docs/upstream/CONTROL_TEST_CAMPAIGN.md` stay as the record of the run without add-ons. Issue #31 (CIM field
  reference and field-level checks) stays open as an unscheduled backlog item; it needs `Splunk_SA_CIM` on a lab.
* **Not changed.** No code, schema, route or permission changed. The build number stays 22.

## D-080 Stabilisation: the browser guard fails closed, access gaps and overrides need a second look, refusals are audited (Sprint 21)

*0.11.0 (Sprint 21).*

* **Context.** An independent review of 0.10.0 found six things that were true and one that was not a defect. Nothing in
  this sprint adds a feature; each item closes a gap between what the product says and what it does. Human review of the
  security paths is planned by the owner after the sprints, before 1.0.
* **1. The browser guard refuses what it does not know.** `splPolicy` in `ucm_common.js` returned "allowed" for a command
  that was in neither list. It now returns `unknown`, and `searchGuard` refuses unknown commands unless the server's
  validation (`/spl/validate`, the authoritative `classify()` in `spl/policy.py`) has cleared the search. The five lists in
  the JS (read-only, side-effect, indirect, hidden, generating) are generated from the Python lists by
  `tools/sync_guard_lists.py` (`--check` in the tests), and `test_spl_guard_parity.py` runs every command through both
  implementations. The guard remains a convenience; the server still decides what is offered.
* **2. The scheduler access check is shown where it matters.** Whether the scheduler role can read the indexes of a
  search (D-070) was a report on the readiness page. It is now shown when a request is submitted and in the approval
  dialog. Approving with an access gap needs a reason (`access_gap_reason_required`, audited as
  `approved_with_access_gap`); it does not block, because the approver may know the role is about to change.
* **3. Overriding a gate needs a second person by default.** `[deployment] override_second_person = true`. Enabling a
  search that a gate blocks (D-066, D-070) is requested by one person and confirmed by another, as for
  `enable_second_person`, and the same person cannot do both. Switch it off in `ucm.conf` for a one-person team. The
  default is true because the override is the one deliberate hole in the gates.
* **4. Refused governance requests are audited, with limits.** A refused POST (400, 403, 409) to a governance route
  writes `refused.<route>` to the hash chain (`outcome=refused`, error code, a message shortened to 200 characters
  with any URL query or credentials removed, no body). The limits exist so that refusals cannot flood the chain: a repeat
  of the same (user, route, object, code) inside `refusal_window_seconds` (300) is not written; at most
  `refusal_actor_per_hour` (20) rows per user and `refusal_total_per_hour` (200) in all; the first request over a limit
  writes one `refused.rate_limited` row for that hour and nothing after it. Counting uses one marker row per scope
  and hour. `[audit] refusals = false` turns it off. The Content administration page lists recent refusals.
  A refused row never counts as a change: it is evidence of an attempt, not of an outcome.
* **5. POA&M eligibility, informational only.** 32 CFR 170.21(a)(2): Conditional Level 2 status with a plan needs
  score/110 of at least 0.8, only requirements worth one point on the plan (3.13.11 at three points when encryption is not
  FIPS-validated), none of AC.L2-3.1.20, AC.L2-3.1.22, CA.L2-3.12.4, PE.L2-3.10.3, PE.L2-3.10.4, PE.L2-3.10.5; 170.21(b)
  requires closeout within 180 days. `frameworks/poam_rules.py` computes, for a plan item, whether its control is
  excluded, worth more than a point, or pushes the score under 0.8, and the Coverage page shows a note with the basis
  and "not a CMMC status determination". It never blocks an item and never changes a score. This does **not** build the
  conditional-status feature that D-079 left out; there is still no status, no 180-day clock and no closeout record.
* **6. Upgrade and score wording.** Records written by an older provider normaliser carry no analytic stories or data
  sources, and Reindex cannot add what the record does not hold. The catalogue summary now counts them
  (`normalizer_outdated`, facets version 5, migration `0006_catalog_facets_v5`) and Content administration says to
  import the ESCU bundle again or sync Fenre; the same hint is on the catalogue page. The scored-catalogue response has
  `all_assessed` (every requirement has an answer) and `can_pass` (no precondition requirement, 3.12.4, is
  standing in the way); `complete` stays as a deprecated alias of `all_assessed`, which is what it always meant.
* **Not a defect.** The review's remaining remark about Fenre's SPL (153 lint findings in 16,726 use cases) stays as
  D-072 says: the app does not file anything on the Fenre repository. `tools/fenre_report.py` writes the findings and
  the control-test results as one document and one CSV (`docs/upstream/for-fenre-owner/`) that the owner can hand over.
* **Not built, unchanged from D-079.** CMMC conditional status, objectives for 800-53 and CMMC, snapshot signing and
  deletion, and the 94-fixture re-run.
* **Migration.** `0006_catalog_facets_v5` rebuilds the catalogue summary once. No collection or capability is added.
* Evidence: `tests/unit/test_sprint21.py`, `tests/unit/test_poam_rules.py`, `tests/unit/test_spl_guard_parity.py`,
  `tests/js/test_usecase.js`, `test_admin.js`, `test_assessment_ui.js`, and the live suite on the lab.

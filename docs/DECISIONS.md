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

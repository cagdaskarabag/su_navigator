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

## D-009 Category-level atomic sync, last-known-good
A category is fetched, validated and staged completely before any write. On
failure the previous content of that category is untouched; the job ends
`partial`/`failed`; provider state (`last_good_commit`) only advances when all
requested categories succeed. Records that disappear upstream are marked
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
of a category; the category-atomic sync would have marked every other record
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
as the caller.
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

## D-028 Deployed searches are owned by the deploying user
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

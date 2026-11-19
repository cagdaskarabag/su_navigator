# Decision Log

Each entry: context → decision → consequences. Status is `Accepted` unless noted.
Decisions D-001..D-005 restate the non-negotiable product decisions; the rest were
made during implementation.

## D-001 Modular monolith, single Splunk app
One installable app `splunk_use_case_manager`. Internal Python package
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

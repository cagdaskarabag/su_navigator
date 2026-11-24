# Security model

Status: WP5 (catalogue, discovery, readiness, selection, SPL validation, deployment).

## Trust boundaries

| Boundary | Treatment |
| --- | --- |
| Upstream content (GitHub, offline bundles) | Untrusted. Size-capped, git-blob-SHA verified, schema- and safety-validated, normalized by allowlisted field mapping. Stored as opaque JSON text (`raw_json`). |
| Imported SPL | Displayed only, labelled "untrusted". Never executed by the catalogue or by discovery. SPL analysis is lexical (no search is dispatched). Side-effect commands (`delete`, `outputlookup`, `collect`, ...) are flagged, and so are indirect-execution and unknown commands (D-038). |
| Discovery searches | Only a constructed `tstats` template over index names from `/services/data/indexes`, validated against `^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$`. Relative time window and result cap are required. |
| Interactive search (browser) | Started only by a click on **Run search** on the use-case page. The browser dispatches the SPL through Splunk's search API (`splunkjs/mvc/searchmanager`) with the user's own session: their role, capabilities, index access and search quotas apply, and the app is not involved. This is deliberately outside the preview guard rails (D-058, below). |
| Imported SPL preview | Dispatched only after an explicit user action, a successful parse in the app namespace, a side-effect command gate, and a refusal of indirect-execution (`map`, `savedsearch`, `rest`, ...) and unknown commands (D-038). Time window and `max_count` are forced. Event payloads are not stored. |
| Field sampling | Constructed `| search index=… sourcetype=… \| head N \| eval … \| fields <validated names> \| fieldsummary` over discovered pairs, in a window ending at the pair's newest event. Imported pipelines are not used. Only presence, counts and the index / sourcetype where a field was seen are kept; event values are not stored (D-044). |
| Selections | Per-user KV rows; the handler only reads and writes the caller's `user` field. |
| Deployment | Saved searches are written with the system token after the capability check and owned by `[deployment] scheduled_owner`, a dedicated `ucm_scheduler` account (D-051). Operators cannot edit or delete them in Splunk (verified on the lab). Disabled first, read back and compared, owner included. Only searches carrying the app's marker are modified. No alert actions. Workflow records are written with the system token after the capability check (D-029). |
| Reference links | Rendered as links only when absolute `http(s)`; other values are dropped or shown as plain repository paths. |
| Browser → app API | Splunk Web proxy (`/splunkd/__raw/services/ucm/*`), Splunk session + CSRF form key. All inputs are validated against allowlists; KV queries are built from structured filters, free text is regex-escaped. |
| App → GitHub | HTTPS only, host allowlist (`api.github.com`, `raw.githubusercontent.com` by default, configurable), TLS verification on, optional proxy / CA bundle, response size caps, bounded retries, rate-limit aware. Refs are limited to `allowed_refs`; a commit SHA must be reachable from an allowed ref (GitHub compare API) before any content is fetched (D-043). |

## Capabilities and roles

| Capability | Grants |
| --- | --- |
| *(none)* | Read catalogue, categories, use-case detail, sync status, platform report, inventory, mappings, discovery status. |
| `ucm_manage_content` | Remote sync, provider manifest check, offline import, catalogue reindex, audit read, framework import and activation. |
| `ucm_run_discovery` | Queue discovery jobs; create and delete **local** source mappings; run readiness assessments (full or single). |
| `ucm_deploy` | Approve, reject, deploy, enable, disable, roll back, retire and control-test deployments; create and delete generated dashboards. Drafting and submitting also accept `ucm_run_discovery`. |
| `ucm_admin` | Audit read; app administration in later WPs. |

| Role | Imports | Capabilities |
| --- | --- | --- |
| `ucm_viewer` | `user` | none |
| `ucm_analyst` | `ucm_viewer` | `ucm_run_discovery` |
| `ucm_content_manager` | `ucm_analyst` | `ucm_manage_content` |
| `ucm_deployment_operator` | `ucm_analyst` | `ucm_deploy` |
| `ucm_scheduler` | `user` | `schedule_search`. Owner of deployed searches only; assign it to one account and set `scheduled_owner` (D-051). |
| `ucm_admin` | content manager + deployment operator | all |

`admin` and `sc_admin` receive all app capabilities.

Capabilities are checked server-side in the REST handler for every
state-changing endpoint (verified live: a `ucm_viewer` receives 403 for sync,
import, reindex, manifest and audit). A unit test calls every POST route
without capabilities and expects 403, except the caller-scoped selection
routes and dashboard preview, so a new route without a check fails the build
(D-035).

## Shared environment metadata (D-044)

The inventory is **shared app metadata**: every user who can open the app
sees it, whatever their own index permissions. Discovery and field sampling
run in the background worker as the system user, so they cover every index
the platform can read (`_internal` and other `_` indexes only with
`[discovery] include_internal = true`).

What every app user can read, through the views, the REST API
(`inventory`, `mappings`, `readiness`, `validation`, use-case detail) and
the KV collections:

- Index names, sourcetypes and index / sourcetype pairs, with event counts in
  the discovery window and first / last event times (`uc_environment_sources`).
- Installed apps (name, label, version), data models (objects, acceleration),
  eventtypes, tags, macros and lookups by name and app.
- Source mappings (`uc_source_mappings`).
- Readiness evidence per use case: the matching index / sourcetype / data
  model / field and counts (`uc_readiness`).
- SPL validation results: commands, parse errors, preview event count and time
  range, and per field whether it was seen, how often and in which index /
  sourcetype (`uc_validation`).

What it does not contain: event payloads or field values. Previews return
only counts, and field sampling keeps no values.

If index or sourcetype names are themselves sensitive on a search head,
limit who can open the app: **Apps → Manage Apps → sunavigator →
Permissions**, read for the `ucm_*` roles (plus `admin`, `sc_admin`) instead
of Everyone. Or set it over REST:

```bash
curl -k -u admin https://localhost:8089/servicesNS/nobody/system/apps/local/sunavigator/acl \
  -d sharing=app -d owner=nobody -d perms.write=admin,sc_admin \
  -d perms.read=admin,sc_admin,ucm_viewer,ucm_analyst,ucm_content_manager,ucm_deployment_operator,ucm_admin
```

Verified live on 10.2: a user with only the `user` role then gets no data
from the app's REST API (it answers with a `storage_error`, HTTP 502) and
HTTP 404 from the KV collections, while a `ucm_viewer` still works.
Redacting names per caller was the alternative (D2 option a), not chosen
for 0.7.x.

## Interactive search runs as the user (D-058)

The use-case page can run the displayed SPL from the browser. This is the only
path on which imported SPL is dispatched without the server's guard rails.

What the path is:

* `SearchManager` from `splunkjs/mvc` posts the search to `/services/search/jobs`
  through Splunk Web with the **user's own session**. Splunk applies that user's
  role: the `search` capability, index and app access, search quotas and
  filters. The app's REST handler, its system token and its capabilities are not
  involved, so the search cannot do anything the user could not do in Splunk's
  own Search app.
* The search runs in the app namespace (`sunavigator`) as the user, so macros
  and lookups shared by the app resolve as they do for that user.

What it intentionally does not have, compared with the bounded preview:

* no forced short time window (the user picks 15 minutes to 7 days; time
  modifiers inside the SPL win), no server-side result cap (the browser fetches
  and displays 100 rows; the job itself may produce more), no server-side
  command policy (D-038);
* **no app audit record.** The browser dispatches the search, so the app never
  sees it and cannot write `ucm_audit`. Splunk's own records (job history, the
  `_audit` index) hold the search under the user's name. The app cannot show who
  ran what from this path.
* the results stay in the browser. The app does not receive, store or export
  them (no export feature, OD-6).

Controls that remain, and their limits:

* An explicit click is required; the search never starts on page load.
* The button is disabled, with the reason shown, for SPL that contains a
  side-effect command. The list equals `spl.analysis.SIDE_EFFECT_COMMANDS` plus
  `fit … into`, and the segmentation equals `analysis._split_pipeline`; unit tests
  compare the lists and run both implementations over the fixture SPL.
* SPL with macros is refused until a stored server-side parse of the current
  content (`source_hash` equal) shows that no side-effect command is hidden in
  the expanded pipeline. The parse is stored by the existing
  **Parse and sample fields** action, so a user who never ran it sees a reason,
  not a search.
* Indirect and unknown commands (`map`, `rest`, `savedsearch`, custom
  commands) only produce a warning, because they run with the user's permissions.
* The search is finalised after 120 seconds and cancelled when the user leaves
  the page.
* These checks are a convenience guard, **not a security boundary**: a user can
  run any search in Splunk directly. To switch the feature off for a role, remove
  the Splunk `search` capability from it; the button is then disabled. A
  failure to read the user's capabilities does not enable anything that Splunk
  would not enforce itself.

Residual risks: imported SPL is untrusted content and can be expensive
(`index=*`, subsearches, `join`); a user can consume their own search quota and
see events on screen that they may view in Splunk anyway. There is no app-side
rate limit or audit for this path.

## Catalogue bookmark and availability filters (D-059)

`GET ucm/catalog?bookmarked=1` reads the caller's own `uc_selections` rows
(`user` equal to the session user from `ctx.user`, intent `bookmark`). The
handler takes no user name from the request: a `user=` parameter is ignored,
and a unit test and a lab check with a second user confirm that one user's
bookmarks never appear for another. The availability filter reads readiness
states, which are app-shared metadata (D-044) any app user can already read
through `ucm/readiness`. Neither filter adds a collection, a capability or an
ACL change.

## Control tests write to Splunk (D-054)

A control test sends fixture events to the test index in `[controltest] index`
through `services/receivers/simple`, with the system token, and runs the deployed
SPL as the caller, restricted to that index and a per-run `source` marker. The
receiver call needs the system token because a caller's session cannot write
events; the caller still needs `ucm_deploy`. The index is the only data the test
writes; keep it separate from production indexes and set its retention. Searches
that cannot be restricted to the test index are never run.

## Storage ACLs (`metadata/default.meta`)

- Provider-owned collections (`uc_catalog`, `uc_content`, `uc_categories`):
  readable by all app users, writable by `admin`, `sc_admin`,
  `ucm_content_manager` and `ucm_admin`. Direct KV writes by viewers are
  rejected by splunkd (verified live).
- Evidence and job collections (`uc_sync_state`, `uc_environment_sources`,
  `uc_source_mappings`, `uc_readiness`, `uc_validation`, `uc_control_fixtures`): readable by all app
  users, writable only by `admin` / `sc_admin`. The REST handler writes them
  with the system token after the capability check, and the background worker
  writes discovery and readiness results. Analysts and content managers cannot
  forge readiness, validation evidence, inventory or jobs through the KV REST
  API (D-039; verified live: an analyst gets 403). Workers also check every
  queued job's structure before running it and fail malformed jobs.
- `uc_deployments`: readable by all app users, writable only by `admin` /
  `sc_admin`. The REST handler writes it with the system token after checking
  `ucm_deploy` (or `ucm_run_discovery` for drafts), so approvals cannot be
  forged through the KV REST API (verified live: an operator gets 403).
  Four eyes covers the app's workflow only: the deploying operator owns the
  saved search and can edit it in Splunk directly. Such edits show as drift
  (D-029); restrict saved-search write access if that matters.
- `uc_frameworks` and `uc_dashboards`: readable by all app users, writable
  only by `admin` / `sc_admin`; written by the REST handler with the system
  token after the capability check (verified live: viewer and operator get
  403 on direct writes). Generated views are written to this app with the
  system token, so dashboard creators do not need view-write permissions; the
  app only overwrites or deletes views that carry its marker and have a
  record (D-032).
- `savedsearches` in this app: writable by `admin`, `sc_admin`, `ucm_admin`
  and `ucm_deployment_operator`.
- `uc_audit`: readable by admins and content managers, writable only by
  `admin` / `sc_admin`. The REST handler appends audit records with the
  request's system token (`passSystemAuth = true`), so users cannot forge or
  delete audit entries through the KV REST API.

Known limitations: content managers can write provider-owned collections
directly through the KV REST API, bypassing validation. Those collections are
derived data (rebuildable by sync/reindex) and never hold customer-owned
state.

Run status (D-031) is searched with the caller's token, so it never reveals
scheduler data a user could not search themselves.

Framework definitions imported by content managers are validated strictly
(ids, names, references, size); their text is rendered with `textContent`
only. Dashboard templates escape every value and accept parameters only from
allowlists; imported SPL never appears in a generated dashboard.

Retention (D-034): audit records are purged after `audit_days` (default
365). Set it to 0, or forward audit to an index, where longer retention is
required; the app's structured log
(`var/log/splunk/sunavigator.log`) also carries every audit event
and is indexed into `_internal` by default.

## Secrets

The optional GitHub token is stored in Splunk's credential store
(`storage/passwords`, realm `sunavigator`, name `github_token`) and
read with the system token. It is never written to `.conf` files, KV
collections, logs or API responses, is sent only to the configured API host
(not to the raw-content host), and the CLI reads it from the
`UCM_GITHUB_TOKEN` environment variable rather than from arguments.

## Process and code constraints

- App code uses the Python standard library only. It spawns no processes and
  has no unverified-TLS code path; the HTTP transport used by tools and tests
  lives in `tools/`. CI enforces this with a grep check.
- The background worker (modular input) executes at most one job at a time;
  jobs are leader-gated on search head clusters (captain only).
- Upstream updates never modify customer-owned collections (selections,
  mappings, local SPL, deployment configuration, assessment history). The
  sync engine only writes `uc_catalog`, `uc_content`, `uc_categories` and
  `uc_sync_state`, and withdraws rather than deletes records that disappear
  upstream.

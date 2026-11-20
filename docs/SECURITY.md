# Security model

Status: WP5 (catalogue, discovery, readiness, selection, SPL validation, deployment).

## Trust boundaries

| Boundary | Treatment |
| --- | --- |
| Upstream content (GitHub, offline bundles) | Untrusted. Size-capped, git-blob-SHA verified, schema- and safety-validated, normalized by allowlisted field mapping. Stored as opaque JSON text (`raw_json`). |
| Imported SPL | Displayed only, labelled "untrusted". Never executed by the catalogue or by discovery. SPL analysis is lexical (no search is dispatched). Side-effect commands (`delete`, `outputlookup`, `collect`, ...) are flagged. |
| Discovery searches | Only a constructed `tstats` template over index names from `/services/data/indexes`, validated against `^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$`. Relative time window and result cap are required. |
| Imported SPL preview | Dispatched only after an explicit user action, a successful `/services/search/parser` parse, and a side-effect command gate. Time window and `max_count` are forced. Event payloads are not stored. |
| Field sampling | Constructed `| search index=… sourcetype=… \| head N \| fieldsummary` over discovered pairs. Imported pipelines are not used. |
| Selections | Per-user KV rows; the handler only reads and writes the caller's `user` field. |
| Deployment | Saved searches are written with the operator's session, owned by the operator (D-028), disabled first, read back and compared. Only searches carrying the app's marker are modified. No alert actions. Workflow records are written with the system token after the capability check (D-029). |
| Reference links | Rendered as links only when absolute `http(s)`; other values are dropped or shown as plain repository paths. |
| Browser → app API | Splunk Web proxy (`/splunkd/__raw/services/ucm/*`), Splunk session + CSRF form key. All inputs are validated against allowlists; KV queries are built from structured filters, free text is regex-escaped. |
| App → GitHub | HTTPS only, host allowlist (`api.github.com`, `raw.githubusercontent.com` by default, configurable), TLS verification on, optional proxy / CA bundle, response size caps, bounded retries, rate-limit aware. |

## Capabilities and roles

| Capability | Grants |
| --- | --- |
| *(none)* | Read catalogue, categories, use-case detail, sync status, platform report, inventory, mappings, discovery status. |
| `ucm_manage_content` | Remote sync, provider manifest check, offline import, catalogue reindex, audit read. |
| `ucm_run_discovery` | Queue discovery jobs; create and delete **local** source mappings; run readiness assessments (full or single). |
| `ucm_deploy` | Approve, reject, deploy, enable, disable, roll back and retire deployments. Drafting and submitting also accept `ucm_run_discovery`. |
| `ucm_admin` | Audit read; app administration in later WPs. |

| Role | Imports | Capabilities |
| --- | --- | --- |
| `ucm_viewer` | `user` | none |
| `ucm_analyst` | `ucm_viewer` | `ucm_run_discovery` |
| `ucm_content_manager` | `ucm_analyst` | `ucm_manage_content` |
| `ucm_deployment_operator` | `ucm_analyst` | `ucm_deploy`, `schedule_search` |
| `ucm_admin` | content manager + deployment operator | all |

`admin` and `sc_admin` receive all app capabilities.

Capabilities are checked server-side in the REST handler for every
state-changing endpoint (verified live: a `ucm_viewer` receives 403 for sync,
import, reindex, manifest and audit).

## Storage ACLs (`metadata/default.meta`)

- Provider-owned collections (`uc_catalog`, `uc_content`, `uc_categories`,
  `uc_sync_state`): readable by all app users, writable by `admin`, `sc_admin`,
  `ucm_content_manager` and `ucm_admin`. Direct KV writes by viewers are
  rejected by splunkd (verified live).
- `uc_deployments`: readable by all app users, writable only by `admin` /
  `sc_admin`. The REST handler writes it with the system token after checking
  `ucm_deploy` (or `ucm_run_discovery` for drafts), so approvals cannot be
  forged through the KV REST API (verified live: an operator gets 403).
- `savedsearches` in this app: writable by `admin`, `sc_admin`, `ucm_admin`
  and `ucm_deployment_operator`.
- `uc_audit`: readable by admins and content managers, writable only by
  `admin` / `sc_admin`. The REST handler appends audit records with the
  request's system token (`passSystemAuth = true`), so users cannot forge or
  delete audit entries through the KV REST API.

Known limitations: analysts can write `uc_readiness` directly, which could
lift the readiness gate on enable (the gate is advisory and overridable
anyway; every enable is audited with the readiness state). Content managers can write provider-owned collections
directly through the KV REST API, bypassing validation. Those collections are
derived data (rebuildable by sync/reindex) and never hold customer-owned
state.

## Secrets

The optional GitHub token is stored in Splunk's credential store
(`storage/passwords`, realm `splunk_use_case_manager`, name `github_token`) and
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

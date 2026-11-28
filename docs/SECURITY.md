# Security model

Status: 0.9.1 (catalogue, discovery, readiness, selection, SPL validation, deployment, control tests, ES/ESCU hand-off).

## Trust boundaries

| Boundary | Treatment |
| --- | --- |
| Upstream content (GitHub, offline bundles) | Untrusted. Size-capped, git-blob-SHA verified, schema- and safety-validated, normalized by allowlisted field mapping. Stored as opaque JSON text (`raw_json`). |
| Imported SPL | Displayed only, labelled "untrusted". Never executed by the catalogue or by discovery. SPL analysis is lexical (no search is dispatched). Side-effect commands (`delete`, `outputlookup`, `collect`, ...) are flagged, and so are indirect-execution and unknown commands (D-038). |
| Discovery searches | Only constructed `tstats` templates: over index names from `/services/data/indexes`, validated against `^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$`, and, since 0.9.1, `\| tstats count from datamodel=<model> where earliest=-24h` for a data model name that matches `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$` (D-067). Relative time window, result cap and a per-search time limit are required. |
| Interactive search (browser) | Started only by a click on **Run search** on the use-case page. The browser dispatches the SPL through Splunk's search API (`splunkjs/mvc/searchmanager`) with the user's own session: their role, capabilities, index access and search quotas apply, and the app is not involved. This is deliberately outside the preview guard rails, but refuses side effects (also inside `map`) and hidden SPL (D-058, D-062, below). |
| Imported SPL preview | Dispatched only after an explicit user action, a successful parse in the app namespace, a side-effect command gate, and a refusal of indirect-execution (`map`, `savedsearch`, `rest`, ...) and unknown commands (D-038). Time window and `max_count` are forced. Event payloads are not stored. |
| Field sampling | Constructed `| search index=… sourcetype=… \| head N \| eval … \| fields <validated names> \| fieldsummary` over discovered pairs, in a window ending at the pair's newest event. Imported pipelines are not used. Only presence, counts and the index / sourcetype where a field was seen are kept; event values are not stored (D-044). |
| Selections | Per-user KV rows; the app API only reads and writes the caller's `user` field, with the system token (D-062). KV write is admin-only; read stays open to app roles (D-061, below). |
| Deployment | Saved searches are written with the system token after the capability check and owned by `[deployment] scheduled_owner`, a dedicated `ucm_scheduler` account (D-051). Operators cannot edit or delete them in Splunk (verified on the lab). Disabled first, read back and compared, owner included. Only searches carrying the app's marker are modified. No alert actions. Workflow records are written with the system token after the capability check (D-029). |
| Reference links | Rendered as links only when absolute `http(s)`; other values are dropped or shown as plain repository paths. |
| Browser → app API | Splunk Web proxy (`/splunkd/__raw/services/ucm/*`), Splunk session + CSRF form key. All inputs are validated against allowlists; KV queries are built from structured filters, free text is regex-escaped. |
| App → GitHub | HTTPS only, host allowlist (`api.github.com`, `raw.githubusercontent.com` by default, configurable), TLS verification on, optional proxy / CA bundle, response size caps, bounded retries, rate-limit aware. A redirect is checked against the same allowlist and the HTTPS-only rule before it is followed, and a redirect to another host drops `Authorization`, `Cookie` and `Proxy-Authorization` (0.11.1, issue #49). Refs are limited to `allowed_refs`; a commit SHA must be reachable from an allowed ref (GitHub compare API) before any content is fetched (D-043). |

## Capabilities and roles

| Capability | Grants |
| --- | --- |
| *(none)* | Read catalogue, categories, use-case detail, sync status, platform report, inventory, mappings, discovery status. |
| `ucm_manage_content` | Remote sync, provider manifest check, offline import, catalogue reindex, audit read, framework import and activation. |
| `ucm_run_discovery` | Queue discovery jobs; create and delete **local** source mappings; run readiness assessments (full or single). |
| `ucm_deploy` | Approve, reject, deploy, enable, disable, roll back, retire and control-test deployments; create and delete generated dashboards. Drafting, submitting and **Verify** (a read-only comparison of the live saved search with the approved revision, which records the result and an audit row, at most one per deployment in each `[audit] verify_window_seconds` unless the result changed) also accept `ucm_run_discovery`. |
| `ucm_admin` | Audit read; app administration in later WPs. |

| Role | Imports | Capabilities |
| --- | --- | --- |
| `ucm_viewer` | `user` | none |
| `ucm_analyst` | `ucm_viewer` | `ucm_run_discovery` |
| `ucm_content_manager` | `ucm_analyst` | `ucm_manage_content` |
| `ucm_deployment_operator` | `ucm_analyst` | `ucm_deploy` |
| `ucm_scheduler` | none | `search`, `schedule_search`, `get_metadata`, `input_file`, `list_metrics_catalog`, `run_custom_command`; `run_collect` and `run_mcollect` disabled; no `output_file`, `run_dump`, `run_sendalert`; indexes `*`, default `main` (D-068). Owner of deployed searches only; assign it to one account and set `scheduled_owner` (D-051). |
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
* **Nested SPL (D-062, 0.8.6).** The string of `map search="..."` is analysed the
  same way, up to three levels deep, so `map search="... | collect ..."`,
  `outputlookup`, `sendemail`, `delete` and the rest are side effects of the
  whole search. The server applies the same rule, so preview, submit and
  deployment refuse such a search too.
* **Leading command names (D-068, 0.9.2).** Splunk runs the first word of a
  bracket, of a `map` string and of a search sent without `search`/`|` as a
  command when it is a command name: `appendpipe [ collect ... ]` and
  `append [ outputlookup ... ]` wrote on Splunk 10.2.9, and Splunk's parser does
  not list commands inside brackets. Both guards read a side-effect, indirect or
  generating command name in those positions as that command, and every word that
  opens `appendpipe [ ... ]` (a subpipeline) as a command. Other leading words stay
  search terms; an add-on command written first in a subsearch of `append`, `join`
  or `union` is therefore not seen. The scheduler role is the second barrier: it
  has no capability to write (`docs/OPERATOR_GUIDE.md` §4).
* **Hidden SPL is refused (D-062).** The button stays disabled for `savedsearch`,
  `loadjob`, `dbxquery`, the `savedsearch:` dataset, a `map` whose search cannot
  be read (`savedsearch=`, unquoted), a macro inside a `map` string, and nesting
  deeper than three levels: the page cannot show what would run. The same
  commands were already refused by the preview and need an acknowledgment at
  approval. `rest`, `dbxlookup`, `dbxinputs` and a `map` with a readable, clean
  search still only warn.
* **Switch.** `[interactive_search] enabled = false` in `local/ucm.conf` turns the
  feature off for everyone (the page shows a note). Removing the `search`
  capability from a role remains the per-role control.
* SPL with macros is refused until a stored server-side parse of the current
  content (`source_hash` equal) shows that no side-effect command is hidden in
  the expanded pipeline. The parse is stored by the existing
  **Parse and sample fields** action, so a user who never ran it sees a reason,
  not a search.
* The static split treats a backtick as the start of a macro, so it sees no
  command after an unpaired backtick. Splunk refuses such a search (missing
  closing tick mark), and preview, submit and deployment require Splunk's parse
  (`parse_ok`). A backtick inside a ```` ``` ```` comment usually reads as a macro,
  which sends the search to the server-side parse rule above.
* Scripted and external lookups run code through `lookup`, which is read-only in
  the command lists. The lookup definition in `transforms.conf`, which only an
  admin can install, is the control point (D-038).
* Other indirect and unknown commands (`map` with a clean readable search, `rest`,
  `dbxlookup`, custom commands) only produce a warning, because they run with the
  user's permissions.
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

## Recommendations read only the caller's rejects (D-060)

`GET ucm/readiness/recommendations` excludes use cases the **calling** user
rejected. It queries `uc_selections` with `user = ctx.user`, ignores any `user`
request parameter, returns no selection data of other users, and writes nothing.
A unit test checks that another user's name never appears in a response and that
their rejects have no effect. Readiness, deployments and the catalogue are
app-shared metadata (D-044) already readable by every app user.

## Selections: readable at KV level, written only by the app (D-061, D-062)

`uc_selections` holds each user's bookmark, select, defer and reject intents,
priority and notes. Its ACL (`metadata/default.meta`) gives **read to every role**
(the caller-scoped filters need it), so any user who can reach the app's KV Store
REST endpoints can read every user's rows. Treat it like the shared inventory in
D-044 (decision D2) and keep sensitive text out of selection notes.

**Write (0.8.6, D-062):** KV write is limited to `admin` and `sc_admin`. The REST
handler writes with the system token, takes the user only from the session
(`ctx.user`), never from a parameter, and reads or writes that user's rows only.
In 0.8.5 a user holding only `ucm_viewer` could create a row for another user
(verified on the lab, D-061); after the change the KV endpoint answers 403 for
every app role except the two administrative ones, while the app's own API keeps
working for viewers and analysts. A site that overrides this ACL in `local.meta`
keeps its override.

## The system token reads the scheduler account's roles (D-063)

Since 0.8.7 the REST handler's system token (`passSystemAuth = true`) and the
background worker's session key make two read-only requests, and only for the
account named in `[deployment] scheduled_owner`:

- `GET authentication/users/<scheduled_owner>`: the user's role names;
- `GET authorization/roles/<role>` for each of those roles: `srchIndexesAllowed`,
  `srchIndexesDisallowed`, `srchIndexesDefault`, `srchFilter` and their `imported_*`
  counterparts.

Why the system token: a user without `admin_all_objects` can read only their own
user and roles (a `ucm_viewer`-class user got `403` for `ucm_scheduler`, measured on
10.2.9), so the caller's token cannot answer the question. The calls are read-only,
add no capability and no route, and are not made for any other user. A failure
(permission, network, Cloud restrictions) gives `unverified` and never blocks anything.

What is exposed to app users:

- `GET readiness/summary` (any app role) returns the scheduler card: the owner's name,
  the role names, whether the account can search `_internal`, whether it holds `*`,
  whether a search filter or a disallowed list exists, and how many default indexes
  it has. It never returns index lists, patterns or the filter text.
- The `permission` requirement row in `uc_readiness` (shared metadata, same as the rest
  of the readiness evidence) names the indexes a use case reads that the account cannot
  search; these are index names already visible in the inventory.
- The deployment view and the revision's `scheduler_access` record carry the status, the
  code and a sentence naming the owner, the indexes and the roles.
- Role patterns and filters are not stored anywhere by the app; they are read per
  request.

The enable gate for a search the scheduler cannot read uses the existing audited
override reason (at least 10 characters) and the existing `ucm_deploy` capability. It
adds a refusal; it removes none.

A wildcard index in the SPL (`index=web*`) is checked against every matching index known
from discovery. If the scheduler account can search only some of them, the check reports
**partial** (since 0.12.0) and names the others; the scheduled search would silently skip
them. If it can search none, the result is *not met*.

## The system token reads ES and ESCU state (D-067)

Since 0.9.1 the REST handler's system token makes read-only requests so that the app can say
what Enterprise Security (ES) and the ES Content Update app (ESCU) have on the search head. The
reason for the system token is the same as for D-063: a viewer cannot read other apps.

- `GET apps/local/SplunkEnterpriseSecuritySuite` and `GET apps/local/DA-ESS-ContentUpdate`:
  whether the app is installed and enabled, its version and label.
- `GET servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/<stanza>`: for an ESCU use case,
  the stanza ESCU shipped (`disabled`, `cron_schedule`, the time range and whether the notable
  and risk actions are set). The stanza name is the one the importer stored, capped at 300
  characters, with control characters refused.

Nothing is written, in ES, in ESCU or in any other app. SUN does not create ES-managed content.
The responses are cached for 60 seconds in the handler process. A failure (403, transport,
missing session) gives `unverified` with a reason, never "not installed" and never an
exception.

What is exposed to app users: `GET platform` (`security_content`) and `GET usecase`
(`escu_handoff`, for ESCU records only) return app names, versions, the stanza's name, state,
schedule and two action flags. They never return the stanza's search text. The parallel-copy
warning adds an informational `parallel_copy` object to a draft revision and its audit event.
It is not a gate: the deployment workflow, the four-eyes rule, the capabilities and the ACLs are
unchanged. Behaviour with ES installed is unvalidated (no ES lab); only the ESCU-without-ES case
was checked on a real instance.

## Email and webhook actions (D-072)

Deployed searches can send an email or call a webhook only when all of these hold: an administrator listed the
permitted mail domains or webhook hosts in `[actions]` (both lists are empty by default); the drafter asked for
it in the revision; the approver, who cannot be the submitter, acknowledged the exact recipients and URL; and the
allowlists still permit them at deploy, enable and rollback. Results are never attached, script and every other
action kind are refused, a changed recipient or URL is drift, and a revision whose actions changed after the
acknowledgment is not deployed (digest check). Webhook URLs may carry tokens: the audit trail records only the
host; the revision (visible to deployment users), the export and the saved search hold the full URL.
Residual risk: a permitted webhook host receives a call whenever the alert fires, and the message and subject
may contain Splunk tokens such as `$name$`.

### The browser guard fails closed (D-080)

Before the search is dispatched the page checks it with `searchGuard` (`ucm_common.js`). Since 0.11.0 a command
that is in none of the lists (read-only, side-effect, indirect) is refused unless the server's validation has cleared
the search; the server's `classify()` stays authoritative when it answers. The browser lists are generated from the
Python lists (`tools/sync_guard_lists.py`) and a test compares both implementations on every command. This is a
convenience in front of Splunk's own role checks, not a security boundary: a user who bypasses the page can still run
anything their role allows.

## Refused requests are audited, with limits (D-080)

A refused POST (400, 403, 409) to a governance route writes `refused.<route>` to `uc_audit`: the actor, the route, the
object, the error code and a message cut to 200 characters with URL queries and credentials removed. Request bodies are
never stored. To keep refusals from filling the hash chain: a repeat of the same actor, route, object and code within
`[audit] refusal_window_seconds` is dropped; `refusal_actor_per_hour` and `refusal_total_per_hour` cap the rows, and the
first request over a cap writes a single `refused.rate_limited` row for that hour. `[audit] refusals = false` disables
it. The chain verification treats these rows like any other row.

## Overrides and access gaps need a second look (D-080)

`[deployment] override_second_person` (default true) makes enabling a search that a gate blocks a two-person act: one
requests, another confirms, never the same user. Approving a revision whose search the scheduler role cannot read needs a
written reason and is audited as `approved_with_access_gap`.

## Control tests write to Splunk (D-054)

A control test sends fixture events to the test index in `[controltest] index`
through `services/receivers/simple`, with the system token, and runs the deployed
SPL as the caller, restricted to that index and a per-run `source` marker. The
receiver call needs the system token because a caller's session cannot write
events; the caller still needs `ucm_deploy`. The index is the only data the test
writes; keep it separate from production indexes and set its retention. A search with a clause that names no index (a subsearch, `append` or `join` next to a scoped one) is refused as not runnable instead of running on the caller's default indexes (0.11.1, issue #50). A search with no index clause at all is refused too.

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
- Collections only the app writes and only administrators need to read directly (`uc_field_profile`,
  `uc_event_check`, `uc_external_matches`; since 0.12.2, D-084): readable by `admin`, `sc_admin` and `ucm_admin`
  like `uc_audit`; the API serves their content to the roles with the capability. The assessment collections
  (`uc_assessments`, `uc_poam`, `uc_assessment_snapshots`; retired in 0.14.0, D-086) are read by the administrators only. Before 0.12.2 these
  six had no stanza and inherited the app-wide `read : [ * ]`. Measured live: other roles get 404 from the KV REST and
  the API still answers. A test fails when any collection in `collections.conf` has no stanza.
- `uc_deployments`: readable by all app users, writable only by `admin` /
  `sc_admin`. The REST handler writes it with the system token after checking
  `ucm_deploy` (or `ucm_run_discovery` for drafts), so approvals cannot be
  forged through the KV REST API (verified live: an operator gets 403).
  Four eyes covers the app's workflow. The saved searches the app deploys are owned by the
  scheduler account (D-051), not by the operator, and `ucm_deployment_operator` has no write
  access to them. `admin` and `sc_admin` can still edit them in Splunk, which is intended; such an edit shows as
  drift on the next Verify (D-029) but the app does not record who made it (Splunk's `index=_audit`
  does). Until 0.11.1 `ucm_admin` could edit them too; 0.12.0 removes that right (D-082).
- `uc_frameworks` and `uc_dashboards`: readable by all app users, writable
  only by `admin` / `sc_admin`; written by the REST handler with the system
  token after the capability check (verified live: viewer and operator get
  403 on direct writes). Generated views are written to this app with the
  system token, so dashboard creators do not need view-write permissions; the
  app only overwrites or deletes views that carry its marker and have a
  record (D-032).
- `savedsearches` in this app: writable by `admin` and `sc_admin` only (D-051, D-082).
  Operators cannot edit or delete deployed searches (verified on the lab).
- `uc_audit`: readable by admins and content managers, writable only by
  `admin` / `sc_admin`. The REST handler appends audit records with the
  request's system token (`passSystemAuth = true`), so users cannot forge or
  delete audit entries through the KV REST API.

Known limitations: content managers can write provider-owned collections
directly through the KV REST API, bypassing validation. Those collections are
derived data (rebuildable by sync/reindex) and never hold customer-owned
state.

KV Store has no compare-and-swap. A deployment record carries a `version`
counter that is checked before each write and read back after it, which
rejects most concurrent edits. Two saves of the same record that start from
the same version within the same instant can both pass the version checks. Since 0.12.0 each
save also writes a random token and compares it on read-back, which catches the case where the
other save lands between the write and the read-back; the earlier caller is then told the record
changed. A save whose read-back finishes before the other save writes is still not detected: the
later write wins. Both actions are in `uc_audit`.

Drift covers the search text, owner, cron, time range, schedule window, suppression, the list of actions, email recipients, subject and attachment flags, the webhook URL, `is_scheduled` and `disabled`. Since 0.11.1 it also covers the alert trigger (`alert_type`, `alert_comparator`, `alert_threshold`, `alert.track`, `alert.severity`), the email message and the results-link flag (issue #48); the trigger is compared only for a revision that records an alert mode. After the upgrade, Verify can report new drift on a search deployed earlier, if its trigger or message was edited in Settings; the report names the field.

If writing an audit row fails (for example the KV Store is unavailable), the action
itself still completes. The failure is logged as `audit write failed` in
`$SPLUNK_HOME/var/log/splunk/sunavigator.log`, and the next row links to the last row
that was written, so **Verify audit chain** shows no gap. Alert on that log message.

**Verify audit chain** counts *branches* (two rows that name the same predecessor)
without failing, because two concurrent writers produce one, and lists the rows involved
(since 0.12.0). A row inserted directly
into `uc_audit` that names an existing row as its predecessor looks the same. Only
`admin` and `sc_admin` can write `uc_audit`, and they can rewrite the whole chain
anyway (D-075).

`tools/ucm_cli.py build-escu-bundle` (the offline ESCU bundle builder) runs on the operator's
machine, not in Splunk. Since 0.12.0 it refuses a package file that is a symbolic link (or
sits behind one) and an archive with more than 100,000 members or more than 1 GiB unpacked.
Run it only on packages you downloaded from Splunk. The bundle it writes is validated again when it is imported.

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

## Hardening release 0.12.0 (issue #51, D-082)

Eleven low-severity items from the external code review. None of them gives a role more power than it had; four
remove power or add a refusal.

| Item | What changed |
|---|---|
| 1 | `ucm_admin` no longer writes `[savedsearches]` (`metadata/default.meta`). Only `admin` and `sc_admin` can edit or delete a deployed search in Settings. A `local.meta` from an earlier ACL change can still grant it. |
| 2 | Verify (a deployment) and Verify audit chain write at most one audit row per object in each `[audit] verify_window_seconds` (300), unless the result changed or the audit chain has a problem. `audit/verify` is a POST. |
| 3 | A per-save token narrows the lost-update window (see above). KV Store still has no compare-and-swap. |
| 4 | The `deployment.draft` audit row has `from` (the state the draft replaced, or `none`) and `replaced_draft`. Whether a draft may replace a pending or approved revision without `ucm_deploy` is **not** changed. |
| 5 | A wildcard index the account covers only in part is *partial*; the audit-chain check lists branch rows. |
| 6 | The static SPL split, on the server and in the browser, pairs macros and three-backtick comments and reads an unpaired backtick as an ordinary character, so a later command stays visible. |
| 7 | The offline bundle tool refuses symlinked package files and caps archive members and unpacked size. |
| 8 | A scalar `references` value rejects that record only; an invalid regular expression in an upstream schema makes the provider use the bundled schema. |
| 9 | A control test is refused when `[controltest] index` is `main` or a default search index of the user who runs it. If the roles cannot be read, the check is skipped. |
| 10 | The evidence CSV formula guard ignores leading whitespace. The Fenre report CSV uses the same guard. |
| 11 | `GET selections` clamps `count` to 1 to 500 and `offset` to 0 or more. |

## Patch 0.12.1 (D-083)

| Finding | What changed |
|---|---|
| Splunk's parser runs subsearches | A search with a side-effect command (`outputlookup`, `collect`, `sendemail`, `delete`, `script` ...) inside a `[ ... ]` subsearch is no longer sent to `search/parser`. Before, validation and deployment wrote the lookup or sent the mail during the parse, as the signed-in user (found on Splunk 10.4.3). Not an escalation: the job ran with that user's rights. |
| Still open | A macro whose body holds such a subsearch is expanded by Splunk during the parse and runs. The policy then refuses the use case, but the write has happened. Macros are created by administrators. |
| Correction | The 0.12.0 note that the item 6 live test "runs nothing" was wrong for subsearches; the test now asserts the refusal. |

## Patch 0.12.2 (D-084)

| Finding | What changed |
|---|---|
| Six collections inherited app-wide read | Stanzas in `default.meta` (see Storage ACLs). Confirmed by the external review and fixed; a test covers every collection. |
| `web.conf` `ucm/*` and the narrow stanzas | Probed live (10.2.9): a GET through Splunk Web to a POST-only path (`ucm/poam/update`) gets Splunk Web's own 405 and never reaches the handler. The narrow `expose` stanzas are enforced. The review's claim that they were redundant was wrong. |
| External-match reads | `ExternalMatchService` now uses the app's own store (`ctx.records()`), like the other app-written collections. |
| Reindex | A background job (`uc_sync_state`, key `reindex::current`): `catalog/reindex?background=1` queues, the worker runs, `GET catalog/reindex` reports. Needs `ucm_manage_content`; one job at a time; audited as `content.reindex.queued` and `content.reindex`. |
| Scheduler reach | `ucm_scheduler` keeps `srchIndexesAllowed = *`, now named in the install checklist and the scheduler card. |
| ESCU redistribution | The offline bundle carries the Apache-2.0 notice, a change statement and a non-endorsement line (`notices`). |
| Splunk Security Essentials | The app never reads, stores, bundles or depends on it (D-084); a test fails on any reference in code, configuration or fixtures. |

## Data the app holds (data map)

For a privacy or procurement review. The app has no telemetry and makes no request to any host except the ones below.

| What | Where | Personal data | How long |
|---|---|---|---|
| Audit rows (who did what, when, to which object) | `uc_audit`; the same events in `var/log/splunk/sunavigator.log`, which Splunk indexes into `_internal` | Splunk user name | `[retention] audit_days` (365); the log follows the `_internal` retention |
| Job rows (sync, discovery, readiness, import, reindex) | `uc_sync_state` and the job collections | Name of the user who requested the job | The newest `[retention] job_history` (50) per kind |
| Selections, validation, control-test and deployment revisions | `uc_selections`, `uc_validation`, `uc_deployments` | Names of the user who selected, requested, approved or enabled | Until deleted; no purge |
| Assessments, POA&M items, evidence snapshots (retired in 0.14.0, D-086; nothing writes them) | `uc_assessments`, `uc_poam`, `uc_assessment_snapshots` | Names of the assessor and the creator of a snapshot; free text typed by the assessor | Until deleted; no purge; export with `tools/compliance_export.py` |
| External-match decisions | `uc_external_matches` | Name of the user who decided | Until deleted; no purge |
| Dashboards | `uc_dashboards` | Name of the owner | Until deleted |
| GitHub token (optional) | Splunk `storage/passwords`, realm `sunavigator` | None (a credential) | Until removed |

What leaves the instance: HTTPS requests to the content provider's host (by default `api.github.com` and
`raw.githubusercontent.com`; the optional token is sent as an authorization header) to fetch use-case content and
the schema. The request carries the repository path and the app's user agent, no user name and no record content.
Nothing else is sent. The app talks to the instance's own splunkd for everything else.

Known gaps: there is no per-user erasure function; removing a person's name from selections, deployments or
assessments is a manual KV Store operation, and the audit chain is designed to resist edits. Whether that is
acceptable is for the operator's privacy officer (docs/LEGAL_COMPLIANCE_ANALYSIS.md, L6).

## Retired module: compliance (D-085, D-086)

The assessment, CMMC score, POA&M and evidence-snapshot module was switched off by default in 0.13.0 (D-085) and
retired in 0.14.0 (D-086). The routes, the role `ucm_compliance_assessor`, the capability `ucm_assess`, the `[features]`
switch and the browser code are gone, so no role can reach the module through the REST API or the UI. The
collections `uc_assessments`, `uc_poam` and `uc_assessment_snapshots` are kept, with no writer in the app and the
administrator-only read ACL from 0.12.2. `tools/compliance_export.py` reads them for an administrator and checks each
snapshot's SHA-256. `tests/unit/test_retirement.py` fails if any part of the module comes back. Retirement is not a
security control on the records: someone with `admin_all_objects` can still read the collections directly.

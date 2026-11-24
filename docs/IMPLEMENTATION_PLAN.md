# Implementation Plan

Work packages follow the master specification. Each WP ends with tests, updated
docs and a commit. Status: ✅ done · 🟡 partial · ⬜ not started.

## WP0 — Project foundation ✅
* Workspace/environment inspection → `PROJECT_DISCOVERY.md`.
* App skeleton (`app.conf`, `app.manifest`, nav, metadata, `README/*.spec`).
* Structured logging, configuration (`ucm.conf`), test harness (`unittest`,
  runnable by Splunk's python3.9/3.13), CI workflow, packaging script.

## WP1 — Content provider and catalogue (first vertical slice) ✅
1. Canonical model + requirement model.
2. `ContentProvider` ABC; `FenreJsonProvider` (git trees + raw sidecars, pinned
   commit, blob-SHA verification, retry/backoff, host allowlist, size caps).
3. Schema-subset validator + safety checks (D-007).
4. Fenre normalizer + SPL static analysis for derived requirements (D-013).
5. KV Store repositories; `SyncService` (category-level staging, incremental,
   last-known-good, withdrawn marking, history).
6. Offline bundle provider + `POST ucm/import`; CLI bundle builder.
7. REST API (catalog, detail, categories, sync, manifest, import, reindex,
   platform, audit). Facet counts were deferred (not implemented).
8. Sync worker modular input.
9. UI: Overview, Content Catalogue (server-side filter/paging), Use Case
   detail, Content Administration (sync/import status).
10. Tests: 102 mocked unit tests (validator, schema subset, normalizer, SPL
    analysis, HTTP client, Fenre provider against a fake GitHub, sync engine,
    bundles, catalogue/detail/reindex, KV client, REST routing and
    capabilities, worker), run on Python 3.9, 3.12 and 3.13; 7 opt-in live
    tests against Splunk 10.2.9 (KV Store operator parity, import and read
    paths, RBAC, errors, platform, remote manifest).
11. Tooling: `tools/ucm_cli.py` (build-bundle, validate, manifest),
    `tools/package.sh`, `tools/perf_catalog.py`, CI workflow, AppInspect.

Remaining WP1 gaps (carried forward): facet counts for the filter bar; UI
screens are verified by headless-browser rendering only, with no automated UI
tests; SHC and Splunk Cloud behaviour are unvalidated.

## WP2 — Data discovery ✅
1. Platform adapter probes index/app/datamodel listing and the `search`
   capability (Enterprise vs Cloud reported; Cloud vetting still pending).
2. Bounded discovery jobs: metadata from `/services/data/indexes`,
   `/services/apps/local`, `/services/data/models`; event counts from a
   constructed `tstats` (D-020) with time window, index-name allowlist, chunking
   and `max_pairs`.
3. `uc_environment_sources` (index, pair, app, datamodel) with data age;
   disappeared sources marked `missing`.
4. Mapping registry `uc_source_mappings` with local-over-auto (D-022).
5. Inventory dashboard, coverage vs catalogue, use-case detail overlay
   ("present" / "not seen", not a readiness score).
6. Jobs run in `ucm_sync_worker` (D-021). `ucm_analyst` receives
   `ucm_run_discovery`.

## WP3 — Readiness engine ✅
1. `EnvironmentSnapshot`: sources, mappings and discovery state loaded once
   per job.
2. Evaluators for sourcetype (exact, wildcard, local/auto mapping, staleness,
   no-longer-seen), index, cim_model, datamodel_acceleration, addon (name,
   label, Splunkbase id, minimum version), product (aliases), macro, lookup,
   eventtype (sharing), version, spl_validity ("no SPL"). Fields, event
   conditions, permissions and free-text data sources are `unverified`.
3. Evidence model per requirement: status, code, detail, observed rows,
   mapping used.
4. Weighted score with critical veto and coverage (D-024); `uc_readiness`.
5. Full jobs in the worker with auto re-assessment after discovery or sync;
   synchronous single assessment; staleness on read (D-025).
6. UI: Readiness dashboard (state cards, most common unmet requirements,
   filters, paging), readiness block and per-requirement evidence on the
   use-case page, readiness charts on the Overview.
7. Discovery extended with knowledge objects, Splunk version and all apps;
   fix for false `missing` after failed or truncated searches (D-023).

Gaps carried forward: per-use-case requirement overrides (accept / not
applicable) are not implemented; the catalogue list does not show readiness
yet; SHC and Cloud unvalidated.

## WP4 — Selection and validation ✅
1. Per-user `uc_selections` (bookmark / select / defer / reject); backlog =
   select + defer. Any signed-in user manages their own rows; sync never
   writes them.
2. SPL validation via `/services/search/parser` (D-026), including parser
   candidate prefixes so Fenre `multisearch` and `index=` searches both parse.
3. Bounded preview of imported SPL; side-effect commands are refused; missing
   lookups at runtime are recorded, not thrown as 5xx. No event payloads stored.
4. Field sampling via constructed `fieldsummary` (D-027); readiness evaluators
   for `field` and `spl_validity` consume `uc_validation`.
5. UI: Select on the catalogue, Backlog view, validation + selection cards on
   the use-case page.

Gaps: event-condition sampling still unverified; no shared team backlog;
preview does not open Splunk's Search view.

## WP5 — Deployment engine ✅
1. `uc_deployments` with workflow state, frozen revisions, observed saved-search
   status, drift and history (D-029).
2. State machine draft → pending_approval → approved → deployed, with
   rejected, failed and retired. Four-eyes approval (configurable).
3. Saved searches written with the handler's system session in this app, owned by
   the scheduler account since 0.8.x (D-051; at 0.7.0 by the operator, D-028), always disabled on deploy and rollback; read back and
   compared after each write; name conflicts and unmanaged searches refused.
4. Enable gated on readiness (override reason audited); disable; rollback to
   the previous deployed revision; retire deletes the search.
5. Drift verification on demand and every `verify_interval_minutes` in the
   worker.
6. UI: Deployment card on the use-case page (draft form, actions allowed for
   the caller, drift, history) and a Deployments view.

Gaps at 0.7.0: no alert actions (email, webhook); no bulk deployment; ownership
cannot be moved to a service account by the app. Since 0.8.x deployed searches are
owned by the scheduler account (D-051). Alert actions, bulk deployment and action
profiles are still not built (see WP8, deferred).

## WP6 — Frameworks and dashboards ✅
1. Framework format `ucm.framework/1`, ATT&CK Enterprise and ICS 20.1 bundled,
   STIX builder, import and activation of other versions (D-030).
2. Coverage levels catalogue → ready → deployed → enabled → operational;
   ATT&CK matrix with sub-technique roll-up, revoked remapping and unresolved
   ids; regulation coverage by control (D-031).
3. Run status of deployed searches from the scheduler log, with a clear
   "not available" when the role cannot read `_internal` (D-031).
4. Dashboard templates and generated views with marker and record checks
   (D-032); static Domain dashboard on the KV lookups.
5. UI: Coverage view (matrix, technique drill-down, regulations, run status),
   Generated dashboards view, run-status column on Deployments.
6. Deployment drafts are parsed in the app namespace, so macros that are not
   shared with the app are caught before deploy.

Gaps: regulations have no bundled control catalogue (only mapped controls are
shown); summaries written before 0.6.0 lack `framework_controls` until they
are reindexed (WP7 migration); no PDF export of coverage.

## WP7 — Hardening and release ✅ (0.7.0)
1. RBAC review: every POST route is tested without capabilities (403 except
   caller-scoped routes); read routes checked too (D-035).
2. Leader election: one gate for all background jobs, unit-tested for
   standalone, captain, member and unknown (D-035). Real SHC not available.
3. Upgrades: versioned migrations with an `app::state` record; summary
   reindex migration; live upgrade from the 0.4.0 package to 0.7.0 (D-033).
4. Retention: audit and job-history purges in the worker, `[retention]`
   settings (D-034).
5. Cloud vetting: AppInspect precert with the `cloud`, `private_victoria` and
   `private_classic` tags: 0 failures, 0 errors.
6. Performance at 20k use cases: catalogue queries under 100 ms; coverage
   endpoints about 0.5 s (computed on read).
7. App icons and logos added, which removes the last browser console error.

Not validated here, required before 1.0.0: a real search head cluster
(captain-only jobs, KV replication, generated view replication) and a Splunk
Cloud stack (vetting submission, egress, `sc_admin`).

## WP8 — Navigation, evidence and ES hand-off (0.8.0 to 0.9.1) ✅ (with the deferrals below)

Done, with the decision record:

| Version | Delivered | Record |
|---|---|---|
| 0.8.0 to 0.8.4 | Select-all categories, readiness terms, Home page, use-case summary, interactive "Run this search", multi-value catalogue facets, bookmarks, percentage cards, Recommended next | D-056 to D-060 |
| 0.8.5 to 0.8.6 | Requirement result counts, selections as shared metadata, handler-only selection writes, nested-SPL guard, interactive-search switch, Cloud wording corrected | D-061, D-062 |
| 0.8.7 | Scheduler-account index access check and enable gate, `include_internal` semantics, scheduled run proven as `ucm_scheduler`, Settings listing explained | D-063 (issues #7, #9) |
| 0.8.8 | Control-test precision (`content_error`, window from sample, manifest checks), 94-fixture campaign | D-064 (issues #5, #6) |
| 0.8.9 | Advisory SPL lint, bounded-total warning, documentation pass | D-065 (issues #8, #14 in part) |
| 0.9.0 | Provider-aware navigation, twin lineage, quality-aware discovery, Plan deployment panel | D-066 |
| 0.9.1 | Read-only ES and ESCU hand-off, parallel-copy warning, populated check for CIM data models, release documentation pass | D-067 (issues #4 in part, #13 in part) |

Deferred, each with its reason and its tracking:

| Item | Why deferred | Tracking |
|---|---|---|
| Search head cluster with a deployer and indexer peers | no such lab | issue #2 |
| Splunk Cloud validation and vetting submission | no Cloud stack | issue #3 |
| ES output mode (findings, notable events, risk) | it cannot be built or verified without an ES 8 lab; 0.9.1 only reads and hands off | issue #4, #27 |
| Alert action profiles (email, webhook) | gated by a product decision on safe defaults and by the approval model; deployed searches have no actions | #28 |
| Counts beyond the catalogue marked at the 50,000 bound; join scan paged | the corpora fit today | issue #14, #24 |
| Macro assistance ("Add Macro") | product decision | issue #10 |
| Field and acceleration checks behind `populated`; scoring decision | needs a decision on what a `no` should do | issue #13 |
| Background Reindex | not simple with the existing job mechanism | #25 |
| Browser tests | Node logic tests exist; Splunk Web is checked by hand | issue #15 |

## Validation status (keep current)

"Live" means Splunk Enterprise 10.2.9, single instance, in the development VM.

| Area | Mocked tests | Live single instance | SHC / distributed | Splunk Cloud |
|---|---|---|---|---|
| Validator / normalizer / SPL analysis | ✅ | ✅ full upstream corpus (16,726 records, 0 invalid) via in-memory store | n/a | n/a |
| KV Store client and repositories | ✅ in-memory store with KV key rules | ✅ operator parity test; 20k-document catalogue, every UI query under 100 ms | ⬜ | ⬜ |
| Fenre provider (GitHub) | ✅ fake GitHub with real blob SHAs | ✅ categories 18 and 23 (140 records) synced from commit `3b8024a`; re-sync unchanged; re-normalize without download | ⬜ | ⬜ (egress per stack) |
| Offline bundle import | ✅ | ✅ 24-record demo bundle through REST; idempotent re-import | ⬜ | ⬜ |
| Sync worker (modular input) | ✅ worker logic; leader gate for standalone/captain/member/unknown, every worker skips off-captain | ✅ registered, runs under python3.13, executes queued jobs | ⬜ captain-only election | ⬜ |
| REST handler and RBAC | ✅ router and capability checks | ✅ viewer denied writes (403), direct KV writes denied, JSON errors | ⬜ | ⬜ |
| Dashboards | n/a | ✅ rendered in headless Chrome with live data, no app JS errors | ⬜ | ⬜ |
| Discovery tstats + inventory REST | ✅ fake inventory/search; SPL construction rejects injection | ✅ include_internal job: 31 pairs, 12 indexes, 0 missing; viewer 403 | ⬜ | ⬜ |
| Mapping registry | ✅ local never overwritten | ✅ local create + delete through REST | ⬜ | ⬜ |
| Readiness evaluators, scoring, veto | ✅ per type, thresholds, veto, coverage, staleness, pruning | ✅ 164 use cases auto-assessed after discovery; single assess; viewer 403 | ⬜ | ⬜ |
| Readiness worker | ✅ auto-schedule once per discovery, timeout, captain gate | ✅ queued and ran within one worker interval | ⬜ captain-only election | ⬜ |
| Selection / backlog | ✅ per-user intents, catalogue + backlog UI | ✅ viewer can select; isolated from other users | ⬜ | ⬜ |
| SPL parser + preview + field sample | ✅ parser candidates, side-effect gate, constructed fieldsummary | ✅ 13.1.1 parses; preview records missing lookup; `_time`/`host`/`group`/`name` sampled | ⬜ | ⬜ |
| Deployment workflow and saved searches | ✅ state machine, four eyes, disabled-first, drift, rollback, trim, concurrency, RBAC | ✅ operator drafts and deploys, admin approves, operator owns the search, enable override, external edit detected as drift, rollback restores cron, retire deletes; operator KV write to `uc_deployments` 403 | ⬜ | ⬜ |
| Frameworks, coverage, run status | ✅ builder, validation, versions, matrix roll-up/remap/unresolved, levels, controls, run-status classes and `_internal` probe | ✅ bundled Enterprise/ICS 20.1 served; 227 techniques, revoked T1562 remapped to T1685; admin sees 2 searches operational, viewer and operator get "not available" | ⬜ | ⬜ |
| Generated dashboards | ✅ render escaping/allowlists, create/regenerate/delete, marker conflict | ✅ two views generated and rendered; operator can create/delete, viewer 403, direct KV write 403; `_key` lookups in panels return data | ⬜ | ⬜ |
| Upgrades and migrations | ✅ reindex migration, fresh install, version record, idempotent re-run | ✅ 0.4.0 package → 0.7.0 package: 164 summaries reindexed in one worker run, `local/ucm.conf` kept, app state recorded | ⬜ | ⬜ |
| Retention | ✅ audit cutoff, job history per type, queued jobs kept, interval, audit of purges | ✅ 500-day-old audit record purged by the worker after upgrade | ⬜ | ⬜ |
| RBAC review | ✅ every POST route without capabilities, every GET | ✅ per-feature 403 checks in the live suite | ⬜ | ⬜ |
| Packaging | n/a | ✅ AppInspect 4.4.0 precert (all checks; `cloud`, `private_victoria`, `private_classic` tags): 0 failures, 0 errors | n/a | ⬜ vetting |
| ES / ESCU hand-off (0.9.1) | ✅ mocked app lists and stanza states (ES present, ES disabled, 403, unreadable, non-admin, renamed stanza), name mapping, cache, draft record | ✅ ESCU 6.11.1 without ES: version, real stanza state, schedule, actions, not-found, viewer view | ⬜ | ⬜ |
| ES installed (0.9.1) | ✅ mocked only | ⬜ no ES lab (issue #4) | ⬜ | ⬜ |
| CIM data model populated check (0.9.1) | ✅ yes, no, timeout, failure, cap, budget, setting off, invalid name | ✅ temporary models: yes, no, not referenced, setting off; the lab has no CIM add-on, so no real CIM model was checked | ⬜ | ⬜ |

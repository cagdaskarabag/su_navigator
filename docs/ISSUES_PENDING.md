# Issues: what to close, what stays open, what to file

*Update at 0.9.5 (D-072): #10 is decided (macro help, no Add Macro button), #13 is decided (an empty model is partial), #20 stays documented in this repository and is not sent upstream, and #28 is built (email and webhook actions). Close #10, #13 and #28 after review; keep #20 as the record of the findings.*
*Update at 0.9.6 (D-073): the optional security_content enrichment of the ESCU bundle, the event-level data check and the deprecated-upstream flag are built (Sprint 16). Also fixed: the field profile search was refused by the app's own search guard in 0.9.4 and 0.9.5 and never stored rates; run discovery once after upgrading.*
*Update at 0.9.7 (D-074): graded coverage with gap lists, the data maturity facet, catalogue navigation and the matching of detections that already run in other apps (findings F-13 and F-14) are built (Sprint 17). Sprint 18 follows.*

Status at **0.9.1** (Sprint 12). This file exists because the automation that wrote the code
can read GitHub issues but cannot comment on, edit, close or create them. Everything below is
text to paste. Each statement was checked against the code and the decision records on the
branch that carries this file; the tests named are in the repository.

Repository: `cagdaskarabag/su_navigator`. Issue numbers are the existing ones (#2 to #16).
New issues are drafts `N-01` to `N-13`; the operator guide (§12) and the architecture notes
refer to them by that number until they are filed, and should then be changed to the real
issue number.

Contents: 1. [Close](#1-issues-the-code-resolves-ready-to-close), 2. [Keep open](#2-issues-that-stay-open),
3. [New issues](#3-new-issue-drafts).

---

## 1. Issues the code resolves (ready to close)

Each closing comment says what was wrong, what changed, how it was verified and what remains.
"Remains" always points to an open issue or a draft below, or says nothing remains.

### #5 Run control tests for all 94 fixtures, not only 2

*Resolved by 0.8.8 (D-064).*

Closing comment:

> Closing: all 94 fixtures were run, and the result is committed.
>
> **What was wrong.** The control-test feature had evidence from two use cases only, so it was
> unknown how many of the 94 fixtures were runnable and whether the verdict logic held across
> the variety of Fenre SPL.
>
> **What changed.** `tools/controltest_campaign.py` (lab only, not in the package) runs every
> fixture through the same runner the app uses (`splunk_ucm.deployment.controltest`), with
> `--bisect` row counts per pipeline stage. Findings led to fixes in 0.8.8: a new verdict
> `content_error` (Splunk ran the search and reported an error) separate from `inconclusive`,
> a search window derived from the sample's own timestamps, the manifest's `expected.max_count`
> and `expected.fields` now being applied, the index filter rewritten only in search clauses,
> multi-line samples kept as one event, and field sampling that skips fields every event has.
>
> **How verified.** Lab, Splunk Enterprise 10.2.9, no add-ons, Fenre `0e21f019`, 2026-11-24:
> 12 passed, 67 failed, 15 not runnable, 0 inconclusive, 0 SUN defects. The per-fixture table with
> the reason class and the evidence is `docs/upstream/CONTROL_TEST_CAMPAIGN.md`; raw results are
> `control_test_campaign.results.json` and `control_test_campaign.classification.json`. Unit tests:
> `tests/unit/test_controltest_precision.py`. Retention guidance for the test index is in
> operator guide §6.6a ("Retention") and D-064.
>
> **What remains.** Only 2 use cases were deployed and tested through the app (the campaign used
> the runner directly). 8 searches cannot be scoped (draft N-05), some passes are weak (N-06), the
> run was without add-ons (N-07), and the content defects have not been filed upstream (N-04).

### #6 Control test fails for fenre:UC-1.1.1: sample and SPL disagree (upstream content)

*Resolved: root cause established, recorded as finding F-01 (D-064).*

Closing comment:

> Closing: the cause is known and it is not in SUNavigator.
>
> **What was wrong.** The control test for `fenre:UC-1.1.1` failed with 0 rows.
>
> **Root cause.** Each fixture event is one `top`-style CPU table. The SPL filters `cpu=all` and needs
> `cpu_load_percent`, which only `Splunk_TA_nix` derives. With the add-on's field emulated
> (`EVAL-cpu_load_percent = 100 - pctIdle`, key=value events) the search returns **1** aggregated
> row with `observed_host` and `avg_cpu_percent`, while the manifest expects 3 rows with `host` and
> `pctIdle`. The manifest therefore cannot pass even with the add-on. This is F-01 in
> `docs/upstream/FENRE_FINDINGS.md`, with evidence and a suggested fix (`min_count: 1`, assert the
> search's own columns).
>
> **What changed in SUN.** From 0.8.8 the app reports precise verdicts (`content_error`,
> `inconclusive` only for unsearchable data, the window and manifest checks) and the lab campaign
> classifies every fixture (`docs/upstream/CONTROL_TEST_CAMPAIGN.md`).
>
> **What remains.** Filing the finding with the Fenre project (draft N-04).

### #7 Prove scheduled execution as ucm_scheduler end to end (T-20 follow-up)

*Resolved by 0.8.7 (D-063).*

Closing comment:

> Closing: scheduled execution as `ucm_scheduler` is proven on Splunk Enterprise 10.2.9, and the
> under-privileged case is detected.
>
> **What was wrong.** The first scheduled run after enabling had never been observed, a scheduler
> role without index access would run silently and return nothing, and nothing told the operator.
>
> **What changed.** (1) The live test `LiveScheduledRunTest` deploys a custom search as one user,
> approves it as another (the submitter's own approval returns 403), enables it with a one-minute cron,
> waits for a real run and reads `index=_internal sourcetype=scheduler`: `user = ucm_scheduler`,
> `app = sunavigator`, `status = success`, `result_count = 1`; owner and sharing unchanged afterwards;
> it then disables and retires the search and removes the users (D-063). (2) Every use case now has
> a requirement "runs as <account>: index access" that reads the scheduler account's roles with the
> system token (read-only) and says which indexes it cannot search; enabling a search the account cannot
> read is blocked unless an audited override reason is given. (3) "Operational" is now "Ran without error
> (not a statement about data)". (4) The scheduler account lifecycle is in operator guide §4.
>
> **How verified.** `tests/live/test_live_splunk.py::LiveScheduledRunTest` and
> `LiveSchedulerVisibilityTest`; unit tests for the evaluator and the gate.
>
> **What remains.** Role reads on a search head cluster or Splunk Cloud are unvalidated (drafts N-01 and
> N-02, and issues #2 and #3); a role change does not mark stored assessments stale (N-01).

### #8 Operator guide known limitations are outdated or duplicated

*Resolved by 0.8.9 (D-065) and kept current in 0.9.1.*

Closing comment:

> Closing: section 12 was rewritten and is now checked by a test where it can be.
>
> **What was wrong.** Section 12 of the operator guide contradicted the code (for example it said only
> two control-test cases had been run) and repeated items; version strings were edited by hand.
>
> **What changed.** Section 12 was rewritten so each item is current, appears once and ends with its
> issue number, a draft in `docs/ISSUES_PENDING.md`, or "no issue". `tests/unit/test_release_consistency.py`
> fails when `app.conf` (both version lines), `app.manifest`, `__version__`, the README package names,
> the README unit-test count, the operator guide title, intro, package names, section 12 heading and
> first changelog entry, or the newest decision record disagree on the version.
>
> **How verified.** The test runs in the unit suite and in CI. For 0.9.1 the whole document set was
> re-read (README, operator guide, architecture, security, implementation plan, decisions).
>
> **What remains.** Nothing.

### #9 Deployed searches not listed in Settings > Searches (root cause unknown)

*Resolved by 0.8.7 (D-063): not a defect in SUNavigator.*

Closing comment:

> Closing: the root cause is Splunk Web's default filter, and it is documented.
>
> **What was wrong.** A deployed search was returned by REST but did not show in Settings > Searches,
> reports, and alerts.
>
> **Root cause.** The page requests `servicesNS/<you>/<app>/saved/searches` with `search=(eai:acl.owner="<you>")
> AND (eai:acl.app="<app>")`: its default **Owner** filter is the signed-in user (captured from Splunk Web 10.2.9
> with a headless browser). Deployed searches are owned by `ucm_scheduler` (D-051; before that, by the
> approver, which is why the first observation looked the same), so they are hidden until Owner is set to
> **All** or to `ucm_scheduler`.
>
> **What changed.** Nothing in how searches are created. The use-case page says to set Owner to All, and operator
> guide §9.14 documents the cause and the workaround.
>
> **How verified.** The request was captured from Splunk Web on the lab; the listing with Owner All
> (`servicesNS/-/sunavigator/saved/searches`) shows the search. D-063 records the capture.
>
> **What remains.** Nothing.

### #11 Interactive search runs outside server-side guard rails and audit: required mitigations and review

*Resolved by 0.8.2 and 0.8.6 (D-058, D-062); the residual risks were accepted in the issue.*

Closing comment:

> Closing: every required mitigation is implemented, the security text is written, and what is left was
> accepted explicitly in this issue.
>
> **What changed (0.8.2, D-058; 0.8.6, D-062).** Explicit **Run search** button, never automatic; a visible notice
> that it runs as the user; default range 24 hours with a picker, never all time, stopped after 120 seconds,
> on Cancel or when the page is left; a display cap of 100 rows; the button is disabled with a stated reason for
> side-effect commands (also inside `map search="..."`), for hidden SPL (`savedsearch`, `loadjob`, `dbxquery`,
> a `map` that cannot be read, a macro inside a `map` string, nesting beyond three levels) and when the role lacks
> the `search` capability; for macros it waits for the server-side parse that shows what they expand to; the JS
> command list is tested against the Python policy list; results are rendered with `ucm.el` and text nodes only,
> and nothing is stored. `[interactive_search] enabled = false` removes the feature. The security implications are
> in `docs/SECURITY.md` ("Interactive search runs as the user") and D-058 and D-062.
>
> **How verified.** `tests/js/test_usecase.js` and `tests/unit/test_spl_guard_parity.py` (the Python and JS
> lists agree and the guard is run under Node), unit tests for the nested-SPL guard, a static test that no view
> script uses `innerHTML` (`tests/unit/test_js_logic.py::StaticGuardTest`, 0.9.1), and the lab checks in D-058 and D-062 (Chromium on
> Splunk 10.2.9: a result cell with markup shown as text, 150 results shown as 100, Cancel ends the job).
>
> **What remains (accepted in this issue).** SUN has no audit record of interactive runs (Splunk's own `_audit`
> logs the search under the user's name), and the UI command list is advice, not a boundary. The disabled
> button for a user without the `search` capability is covered by unit tests, not by a lab check (it belongs to
> #15). If an audit or a strict guard becomes necessary, Alternative B in this issue is the fallback.

### #12 uc_selections is readable and writable by all viewers at KV level (OD-8)

*Resolved: the write side was closed in 0.8.6 (D-062); the read side was decided as documented risk (D-061).*

Closing comment:

> Closing: the decision is recorded and the access model is documented; the writable half was removed.
>
> **What was wrong.** Any viewer could read and write every user's `uc_selections` rows through the KV Store REST
> API, bypassing the handler's per-user scoping.
>
> **What changed.** 0.8.5 (D-061) recorded the owner's decision (OD-8): selections are app-shared metadata and
> operators are told not to put anything sensitive in notes. 0.8.6 (D-062) went further than the issue's option 1:
> `metadata/default.meta` now gives `uc_selections` `write : [ admin, sc_admin ]`, and the REST handler writes
> the caller's own rows with the system token after taking the user from the session, so a viewer can no longer
> create, change or delete rows directly. Reading stays open (`read : [ * ]`) because the caller-scoped filters
> need it. `docs/SECURITY.md` ("Selections: readable at KV level, written only by the app") and D-061 and D-062
> state the model.
>
> **How verified.** `tests/unit/test_write_paths.py` (the collection is no longer user-writable) and the live
> `LiveWritePathTest.test_direct_kv_writes_are_refused` (a viewer's direct KV write to `uc_selections` is refused)
> while the UI flows still work (`test_analyst_rest_flows_still_work`; `LiveApiTest`).
>
> **What remains.** Reading other users' rows is still possible at KV level, by decision. If you want read
> isolation (option 2: the handler is the only reader), file it as a new issue; it needs a reworked read path for
> the caller-scoped filters.

*Note for the owner.* The operator guide now says the decision is recorded. If you prefer to keep #12 open as a
reminder of the read side, the guide wording still holds.

### #14 Catalogue and scans are silently bounded by KV max_rows_per_query (partly resolved)

*Resolved for the catalogue by 0.8.9 (D-065); the rest is draft N-08.* Recommendation: close and file N-08, or
keep this issue open and use N-08's body as its new text. Either is accurate.

Closing comment (if closing):

> Closing the catalogue part; the remainder moves to a new issue.
>
> **What was wrong.** Totals and scans stopped at `max_rows_per_query` (50,000) without saying so.
>
> **What changed.** `DocumentStore.count` is keys-only, so the catalogue returns `total_capped` and shows
> "50000 or more" with a note; joins that would have to scan beyond the bound refuse ("narrow the other filters
> first") instead of returning a partial set; Administration warns from 90 percent of the bound;
> `[catalog] kv_row_limit` tells the app the platform value. Operator guide §6.2 and §12 say so.
>
> **How verified.** Unit tests with a store that enforces the limit (`tests/unit/test_kv_bound.py` and the
> provider-navigation parity tests).
>
> **What remains.** Readiness, inventory and coverage counts are not marked at the bound, and the join scan is not
> paged: see the new issue (draft N-08).

---

## 2. Issues that stay open

| # | Title | Status at 0.9.1 | Next step |
|---|---|---|---|
| #2 | Validate SHC with a deployer and indexer peers | A local three-member cluster without deployer or peers was validated (D-055); captain-only jobs fixed. Deployer, peers and rolling restarts untested. | Needs an SHC lab with a deployer and indexers. Include scheduler-role reads (N-02). |
| #3 | Validate on Splunk Cloud | The package passes AppInspect with the cloud tags; runtime on a Cloud stack is unvalidated (managed `limits.conf`, no file access, vetting). | Needs a Cloud stack and the vetting submission. Include N-02. |
| #4 | ES 8 findings/risk output mode | **Not built.** 0.9.1 adds a read-only hand-off instead (D-067): detect ES and ESCU, show the shipped stanza state, hand off to ES Content Management, warn about parallel copies. ES-installed behaviour is mocked-only. | Needs an ES 8 lab. First validate the hand-off (N-11), then design the output mode against a real ES. Post the decision note below. |
| #10 | Decide whether to offer macro assistance (Add Macro) | Unchanged: macros are listed by name; no write path. | Needs the owner's decision (option 0, 1 or 2 in the issue). |
| #13 | Readiness treats an installed CIM data model as met without checking it is populated | **Partly done in 0.9.1 (D-067).** Discovery checks each selected model with `tstats count from datamodel=<m> where earliest=-24h` and stores `populated: yes/no/unverified`; it is shown as a separate chip, in the readiness explanation and in the recommendation reasons. Scores and `met` are unchanged. Setting `[discovery] populated_check`. The lab has no CIM add-on, so only temporary models were checked live. | Needs the owner's decision on scoring (should `no` ever lower a score?); then field presence and acceleration-freshness checks. The issue's first acceptance criterion (installed-only becomes partial) was deliberately not done. Post the status comment below. |
| #14 | Catalogue and scans silently bounded (see §1) | Catalogue part done. | Close and file N-08, or keep open. |
| #15 | Add automated tests for UI JavaScript | Mostly done: `tests/js/` has 11 Node suites with a fake DOM that throws on `innerHTML`, run inside the unit suite when Node exists; 0.9.1 adds a static test over every view script. Not done: a Playwright smoke script, an explicit Node step in CI. | Add the CI step and the optional smoke script, then close. README now documents how to run the tests. |
| #16 | Tracking: open items after T-01..T-25 | Umbrella. | Update the checklist: tick #5, #6, #7, #8, #9, #11, #12 and #14 (catalogue part) once closed; add N-xx links as they are filed. |

Comment to post on **#4** (decision note, D-067):

> Status at 0.9.1. The ES output mode is still not built, because it cannot be built or verified without an ES 8
> lab. 0.9.1 (D-067) adds a read-only hand-off so ES users are not misled: SUN detects Enterprise Security
> (`SplunkEnterpriseSecuritySuite`, checked on the Splunkbase API and the ES 8 documentation) and the ES Content
> Update app (`DA-ESS-ContentUpdate`) with the system token; for an ESCU use case it reads the shipped saved search
> (`ESCU - <name> - Rule`: state, schedule, notable and risk actions) and says "enable it in ES Content Management"
> when ES is installed, or "ESCU is installed without ES; the shipped search is disabled; SUN can deploy an
> independent copy" when it is not; it warns, without blocking, that a SUN deployment is a separate plain
> scheduled search that runs next to an enabled ESCU or ES copy. SUN never creates ES-managed content, never
> writes into another app, and "enabled in ES" never counts as enabled in SUN coverage. Verified on a lab with ESCU
> 6.11.1 and no ES. **All ES-installed behaviour is mocked in tests and unvalidated.** The Content Management link is
> built from the app id and its path is not verified for any ES version. Decision: until an ES lab exists, hand off;
> a future output mode must not weaken the governed deployment (draft, four-eyes, disabled first). Next step: an
> ES 8 lab (draft N-11).

Comment to post on **#13** (status):

> Status at 0.9.1 (D-067). Done: the populated check from the proposed work. The discovery job runs one
> `| tstats count from datamodel=<model> where earliest=-24h` per selected model (models a catalogue requirement
> or a local mapping names, then the CIM add-on's models, up to 30), in the model's own app namespace, with a
> per-search `max_time`, a total budget and a stop after three failures, and stores `populated` (`yes`, `no`,
> `unverified` with a reason code) next to the model. It is shown as a separate chip on the CIM requirement, in the
> readiness explanation and in the recommendation reasons. A model that is installed stays `met`
> (`model_present`); scores, states and the readiness corpus baseline did not change. `[discovery] populated_check
> = false` turns it off. Verified on the lab with temporary models (yes, no, not referenced, off); the lab has no CIM
> add-on. Not done, and why: (1) making installed-only `partial` or `unverified` (the first acceptance criterion)
> changes existing scores and needs your decision; (2) field presence, tagging and acceleration freshness. `yes`
> means events matched the model's constraints in the 24 hours before discovery, nothing more. Please decide
> whether a `no` should lower the score.

---

## 3. New issue drafts (filed)

All thirteen drafts below were filed on 2026-11-24 (the bodies are the text of the issues):

| Draft | Issue |
|---|---|
| N-01 | [#17](https://github.com/cagdaskarabag/su_navigator/issues/17) |
| N-02 | [#18](https://github.com/cagdaskarabag/su_navigator/issues/18) |
| N-03 | [#19](https://github.com/cagdaskarabag/su_navigator/issues/19) |
| N-04 | [#20](https://github.com/cagdaskarabag/su_navigator/issues/20) |
| N-05 | [#21](https://github.com/cagdaskarabag/su_navigator/issues/21) |
| N-06 | [#22](https://github.com/cagdaskarabag/su_navigator/issues/22) |
| N-07 | [#23](https://github.com/cagdaskarabag/su_navigator/issues/23) |
| N-08 | [#24](https://github.com/cagdaskarabag/su_navigator/issues/24) |
| N-09 | [#25](https://github.com/cagdaskarabag/su_navigator/issues/25) |
| N-10 | [#26](https://github.com/cagdaskarabag/su_navigator/issues/26) |
| N-11 | [#27](https://github.com/cagdaskarabag/su_navigator/issues/27) |
| N-12 | [#28](https://github.com/cagdaskarabag/su_navigator/issues/28) |
| N-13 | [#29](https://github.com/cagdaskarabag/su_navigator/issues/29) |


Suggested labels use the repository's existing issue style (type and area in the table of each body). The
repository has no labels today; the "Labels" line is a suggestion.

### N-01 Re-assess readiness when the scheduler account's roles change

*Labels: enhancement, readiness.*

**Title:** Mark stored readiness assessments stale when the scheduler account's role changes

**Body:**

> ## Context
> Since 0.8.7 (D-063) every use case has a requirement "runs as `<scheduler account>`: index access", evaluated
> from the account's roles at assessment time. The roles are read with the system token and nothing is stored
> about them (only the result).
>
> ## Why this is an issue
> If the role gains or loses index access after an assessment, the stored result keeps saying `met` or `not_met`
> until someone presses **Assess** or discovery runs again. The enable gate always reads live, so enabling is safe,
> but the Readiness page, recommendations and availability filters can be wrong in the meantime.
>
> ## Why it is not resolved
> Detecting a role change means either storing a fingerprint of the account's roles and comparing it on every
> read (an extra system-token read per request) or polling in the worker. Neither was justified in 0.8.7, which
> documented the behaviour instead.
>
> ## Proposed approach
> 1. In the worker's periodic pass (no new read path for users), read the scheduler account's roles and index
>    grants, hash them, and store the hash in `uc_sync_state` (existing collection, new key).
> 2. When the hash changes, queue a full assessment (the existing job type) and write an audit event.
> 3. Show "scheduler roles changed, re-assessing" on the Overview scheduler card.
>
> ## Acceptance criteria
> - [ ] Changing the account's `srchIndexesAllowed` on the lab leads to a new assessment within two worker intervals
>   without a button press.
> - [ ] No role patterns or filter text are stored; only a hash.
> - [ ] A failed read leaves the old fingerprint and reports `unverified`.
> - [ ] Operator guide §12 item updated.

### N-02 Scheduler role reads on search head clusters and Splunk Cloud are unvalidated

*Labels: validation, platform.*

**Title:** Validate the scheduler account role reads (`authentication/users`, `authorization/roles`) on an SHC and on Splunk Cloud

**Body:**

> ## Context
> D-063 reads `authentication/users/<owner>` and `authorization/roles/<role>` with the system token. This was
> measured on a single Splunk Enterprise 10.2.9 instance, where a viewer-class user gets 403 and the system token
> succeeds.
>
> ## Why this is an issue
> On a search head cluster the role definitions may live on the deployer or an LDAP/SAML mapping; on Splunk Cloud
> role reads may be restricted. The app reports `unverified` and does not block, but nobody has checked what is
> returned, so the requirement may be `unverified` everywhere on those platforms and the enable gate never fires.
>
> ## Why it is not resolved
> No SHC with a deployer and no Cloud stack are available (see #2 and #3).
>
> ## Proposed approach
> Once a lab exists: run `LiveSchedulerVisibilityTest` and the assess flow, record what each read returns, and
> adjust the evaluator wording for the case where roles are managed outside the instance.
>
> ## Acceptance criteria
> - [ ] The results on an SHC (with a deployer) and on a Cloud stack are recorded in `docs/DECISIONS.md`.
> - [ ] The requirement text names the real reason when the read is restricted.
> - [ ] Operator guide §12 states what was validated.

### N-03 Requirements on internal indexes are `unverified` when `include_internal = false`

*Labels: enhancement, readiness.*

**Title:** Say whether an internal index exists and has data without scanning it by default

**Body:**

> ## Context
> With the default `[discovery] include_internal = false`, discovery does not list `_internal`, `_audit` and other
> `_` indexes (0.8.7, D-063). A use case that reads one gets "not verified (internal indexes are not scanned)",
> never "index not defined". ESCU and Fenre searches that read `_internal` or `_audit` are common.
>
> ## Why this is an issue
> An operator sees many `unverified` requirements that could be `met` with one setting, and the app gives no
> way to see the effect before turning the scan on. The setting is global.
>
> ## Why it is not resolved
> Scanning internal indexes changes discovery cost and what the shared inventory shows (index names are visible
> to every app user, D-044). A decision was taken to keep the default off.
>
> ## Proposed approach
> Evaluate only presence for internal indexes (an `eventcount` or `/services/data/indexes` read, no `tstats`), flag the
> row `internal`, and keep the event-level scan behind the setting. Show the counts that would change.
>
> ## Acceptance criteria
> - [ ] With the default setting a requirement on `_internal` is `met` on presence, with the note that data was not scanned.
> - [ ] No new search over internal indexes runs by default.
> - [ ] Unit and live tests for both settings; operator guide §6.4 and §12 updated.

### N-04 Report the Fenre content findings F-01 to F-11 upstream

*Labels: upstream, content.*

**Title:** File the Fenre content findings from the control-test campaign (F-01 to F-11)

**Body:**

> ## Context
> The 94-fixture campaign (0.8.8, D-064) and the SPL lint corpus run (0.8.9, D-065) found defects in the Fenre
> content (`0e21f019`). They are written up with evidence and a suggested fix in
> `docs/upstream/FENRE_FINDINGS.md` (F-01 to F-11): manifests that cannot pass (F-01, F-02, F-04, F-11), `match()`
> as a search term that never matches (F-03, 12 use cases), a value AWS does not emit (F-05), invalid regex, time
> modifier and `timechart` forms that Splunk rejects (F-06, F-08, F-09), a three-argument `match()` (F-07, corrected
> in D-065) and one generic fixture reused for 64 unrelated use cases (F-10).
>
> ## Why this is an issue
> The defects make 67 of 94 control tests fail and make some use cases deploy SPL that never fires. SUN's lint
> flags what it can, but the fix belongs upstream.
>
> ## Why it is not resolved
> Nothing has been filed on the Fenre repository; the owner has to decide how (one issue per finding, or one
> report) and under whose name.
>
> ## Proposed approach
> File one issue per finding class with the evidence copied from the report (F-07 and F-06 as corrected in D-065),
> link back to the campaign table, and re-run the campaign after each upstream release.
>
> ## Acceptance criteria
> - [ ] Each of F-01 to F-11 has an upstream issue or a written reason it was not filed.
> - [ ] `docs/upstream/FENRE_FINDINGS.md` links the upstream issues.
> - [ ] The campaign is re-run against the fixed content and the table is updated.

### N-05 Control tests cannot scope searches that filter on `source=`

*Labels: enhancement, control tests.*

**Title:** Control tests: support searches that filter on `source=`

**Body:**

> ## Context
> A control test replays the sample events into a test index with a per-run `source` marker and scopes the SPL to
> that index and marker (D-054, D-064). A search that already filters on `source=` cannot be scoped, so the
> verdict is `not_runnable`. In the campaign 8 of the 94 searches could not be scoped (some for `source=`, some for
> a customer lookup or data the rewrite cannot redirect).
>
> ## Why this is an issue
> Those use cases cannot be tested through the app at all, although the filter is part of what the detection
> should be tested for.
>
> ## Why it is not resolved
> The marker is the only isolation between runs in a shared index; replacing the SPL's own `source` filter would
> test a different search. The replay also cannot set the event `source` through the raw receiver.
>
> ## Proposed approach
> Option A: write the events with the `source` the SPL expects into a per-run index (needs index creation, which the
> app does not do). Option B: a clearly labelled "adapted search" verdict that rewrites the `source` term and says
> so. Evaluate both on the lab and record which searches become runnable.
>
> ## Acceptance criteria
> - [ ] The campaign's `not_runnable` count for `source=` searches drops to 0 or each remaining case has a reason.
> - [ ] The result text says when the search was adapted.
> - [ ] No new capability and no relaxed SPL refusal.

### N-06 Weak passes in control tests on empty buckets and defaulted values

*Labels: bug, control tests.*

**Title:** Control tests: do not report a pass when a `timechart` returns empty buckets or `coalesce` supplies the defaults

**Body:**

> ## Context
> The campaign found passes that prove nothing: `timechart` returns rows for empty time buckets (UC-10.2.1,
> UC-12.1.1) and `coalesce` defaults make a search return rows without selecting data (UC-2.6.48, 2.6.55, 2.6.74,
> 2.6.76). The evidence column of the campaign table flags them; the app's verdict is still `passed`.
>
> ## Why this is an issue
> A green result on a search that cannot fail is false assurance, which the product rules forbid ("no unverified
> success claims").
>
> ## Why it is not resolved
> The runner counts rows. Detecting an empty bucket needs a look at the values or a second run on an empty window.
>
> ## Proposed approach
> Run the same search once on an empty window (the negative phase already exists for some searches) and downgrade a
> pass to "weak: the search also returns rows with no matching events"; show it as a distinct verdict.
>
> ## Acceptance criteria
> - [ ] The six use cases above give the weak verdict on the lab.
> - [ ] Strong passes (for example UC-9.1.2) are unchanged.
> - [ ] Operator guide §6.6a explains the verdict.

### N-07 Re-run the control-test campaign with the add-ons installed

*Labels: validation, control tests.*

**Title:** Re-run the 94-fixture campaign on a lab with the add-ons the use cases need

**Body:**

> ## Context
> The 0.8.8 campaign ran on a lab with no add-ons and no props changes. Most failures are classified as fixture or
> content defects, and one as missing add-on or KV_MODE; others may change when `Splunk_TA_nix`, the Windows add-on and
> the CIM add-on exist.
>
> ## Why this is an issue
> Without add-ons the table cannot separate "needs the add-on" from "wrong content", so the upstream report (N-04)
> could over- or under-state defects.
>
> ## Why it is not resolved
> The lab has only ESCU installed; the add-ons were not available offline.
>
> ## Proposed approach
> Install the add-ons named by the use cases (first those in the 94 fixtures), rerun `tools/controltest_campaign.py
> --bisect`, and diff the classification. This also gives the populated check (#13) a real CIM model to run against.
>
> ## Acceptance criteria
> - [ ] A second table with the same columns and the add-on versions is committed.
> - [ ] The classification file records which results changed and why.
> - [ ] The populated check is run against a real CIM model and the result is recorded in D-067's successor.

### N-08 Mark bounded counts beyond the catalogue and page the join scan

*Labels: scalability, enhancement.*

**Title:** Readiness, inventory and coverage counts are silently bounded by `max_rows_per_query`; the join scan is not paged

**Body:**

> ## Context
> 0.8.9 (D-065) made the catalogue total say "50000 or more" and made joins refuse above the bound. Readiness,
> inventory and coverage counts use the same keys-only query and are not marked at the bound; the bookmark,
> availability and regulation joins scan at most 49,999 rows in one query.
>
> ## Why this is an issue
> Combined corpora can reach the bound; derived numbers (coverage, readiness totals, inventory totals) would then be
> wrong without a sign. This is the remainder of #14.
>
> ## Why it is not resolved
> The current corpora (about 16,700 Fenre records plus 2,200 ESCU detections) fit; paging is a broader refactor.
>
> ## Proposed approach
> Return `total_capped` from every count; page the scans that must be complete (facets, duplicate pass, coverage,
> join) with `skip`/`limit` loops; show the limit and catalogue size on the platform card ("max_rows_per_query = N;
> catalogue = M").
>
> ## Acceptance criteria
> - [ ] A unit test with a store that enforces the limit covers readiness, inventory and coverage.
> - [ ] The platform card shows the limit and the size.
> - [ ] No total is shown as exact when it reached the bound.

### N-09 Reindex is synchronous

*Labels: enhancement, catalogue.*

**Title:** Run **Reindex catalogue summaries** as a background job

**Body:**

> ## Context
> `POST catalog/reindex` re-derives every summary inside one REST call: about 5 ms per use case (12 s for 2,359
> documents, about 4 minutes at 49,000). A summary version change (0.9.0) asks every operator to press it.
>
> ## Why this is an issue
> One long REST call can hit proxy or browser timeouts on a large catalogue, blocks a handler thread and shows no
> progress.
>
> ## Why it is not resolved
> Looked at in 0.9.1 and left: it is not a small change with the existing job mechanism. It needs a new job type
> and document, a worker branch (the worker uses its own session and the system token, the handler uses the
> caller's), status and cancel endpoints, polling in Content Administration, an audit event, a decision on whether a
> concurrent sync blocks it, and tests for restart in the middle of a run.
>
> ## Proposed approach
> Model it on the discovery job: queue a `reindex` job (capability `ucm_manage_content`), process in batches of
> 500 with a progress counter, resume from the last key after a restart, and let the page poll.
>
> ## Acceptance criteria
> - [ ] The button queues a job and returns at once; progress is visible.
> - [ ] A worker restart resumes without re-deriving finished summaries.
> - [ ] Running it twice gives the same catalogue (as today).
> - [ ] Latency of other REST calls during a reindex is measured and does not regress.

### N-10 A comma in a facet name is lost

*Labels: bug, catalogue.*

**Title:** Analytic story, data source and other facet values containing a comma cannot be filtered

**Body:**

> ## Context
> Facet filters pass several values as a comma-separated query parameter (D-059, D-066). A value that contains a
> comma (for some ESCU analytic stories and data sources) is split in two or dropped when the facet is stored.
>
> ## Why this is an issue
> Those use cases cannot be found with the story or data-source facet, which is the way to find ESCU use cases in
> the category *Unassigned*.
>
> ## Why it is not resolved
> The URL format is already in users' saved links and the parity tests; a new separator or an escape needs a
> decision so existing links keep their meaning.
>
> ## Proposed approach
> Accept `%2C` as an escaped comma inside a value (and write it that way from the UI), keep the plain comma as a
> separator, and test existing URLs unchanged.
>
> ## Acceptance criteria
> - [ ] A facet value with a comma can be ticked, filtered and bookmarked.
> - [ ] Existing URLs return the same results.
> - [ ] The facet document stores the full name.

### N-11 Validate the ES hand-off on a real Enterprise Security 8 instance

*Labels: validation, ES.*

**Title:** Validate the ES and ESCU hand-off with Enterprise Security installed (prerequisite for #4)

**Body:**

> ## Context
> 0.9.1 (D-067) detects ES and ESCU read-only, shows the state of ESCU's shipped saved search, links to ES Content
> Management and warns about a parallel copy. Only the ESCU-without-ES case ran on a real instance. Everything that
> needs ES installed is covered by mocked app lists and stanza states.
>
> ## Why this is an issue
> Unvalidated claims: the app id `SplunkEnterpriseSecuritySuite` for ES 8 (checked on the Splunkbase API and
> documentation only), the version string, whether the system token can read `apps/local` for it, the stanza
> state when ES manages the ESCU searches (ES may enable or rename them), the Content Management path, and whether the
> wording "enable it in ES Content Management" is right for ES 8.
>
> ## Why it is not resolved
> There is no ES lab.
>
> ## Proposed approach
> On an ES 8 instance: run the platform call and the use-case call for several ESCU detections (enabled and
> disabled in ES), check the link, check a viewer's view, and record the results. Correct `ES_APP_IDS` and
> `CONTENT_MANAGEMENT_VIEW` in `platform/security_content.py` if they differ. Then use this to design the ES
> output mode (#4).
>
> ## Acceptance criteria
> - [ ] A live test for ES installed passes and is committed.
> - [ ] The link opens Content Management on the tested ES versions, or the note says which versions it does not.
> - [ ] The operator guide and `docs/DECISIONS.md` say what was validated.

### N-12 Alert action profiles (email, webhook) for deployed searches

*Labels: feature, deployment.*

**Title:** Alert action profiles for deployed searches (gated)

**Body:**

> ## Context
> Deployed searches have no email, webhook or script actions; the default alert mode only writes to Triggered
> Alerts (README, operator guide §1). Work package 5 listed alert actions as a gap and they were deliberately not
> built.
>
> ## Why this is an issue
> Operators need a notification path to make a deployed detection useful; today they add actions in Settings, which
> the app then reports as drift.
>
> ## Why it is not resolved
> Actions send data out of Splunk and can run code (script actions), so they need governance: who defines a
> profile, who approves it, which destinations are allowed, and how it is audited. None of this was decided. Any
> design must keep four-eyes approval, the disabled-first rule and the no-script rule, and must not add a bypass.
>
> ## Proposed approach
> A small set of named, admin-defined profiles (for example email to a list, webhook to an allowed host) that a
> draft can reference by name; the profile is part of the revision that is approved; script actions stay refused;
> destinations are validated against an allowlist; every use is audited.
>
> ## Acceptance criteria
> - [ ] A decision record names the allowed action types, who may define profiles and how approval works.
> - [ ] A deployed search with a profile does not appear as drift.
> - [ ] Unit and live tests cover refusal of a non-allowlisted destination and a script action.

### N-13 More SPL lint rules, evidence first

*Labels: enhancement, SPL lint.*

**Title:** Extend the SPL lint only with rules shown wrong on a real Splunk

**Body:**

> ## Context
> The lint (0.8.9, D-065) has five rules (`L001` to `L005`), each shown wrong on Splunk 10.2.9 with
> `/services/search/parser` or real searches. Rules that were considered and not shipped needed data, add-on fields
> or functions that were not probed.
>
> ## Why this is an issue
> The corpus run found 141 Fenre searches with findings; other classes of wrong SPL probably exist (for example the
> F-07 and F-06 variants), but a rule without evidence would produce false warnings, which costs trust.
>
> ## Why it is not resolved
> Each rule needs a probe on the lab and a corpus measurement before it ships.
>
> ## Proposed approach
> Pick the candidates from `docs/upstream/SPL_LINT_CORPUS.md` and the campaign's `content_error` results; probe each
> in the app namespace; add a rule only when Splunk's parser rejects it or two test events prove it never matches;
> measure the false-positive rate on the corpus.
>
> ## Acceptance criteria
> - [ ] Each new rule has a positive and a negative unit test, a lab probe recorded in `docs/DECISIONS.md`, and a corpus
>   measurement with 0 false positives against the parser where Splunk rejects the SPL.
> - [ ] The lint stays advisory: no score, approval, gate or refusal changes.

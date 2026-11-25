# SUNavigator user guide

This guide is for a security or monitoring engineer who knows Splunk and has never seen SUNavigator. It describes SUNavigator 0.11.0 as it behaved on a local Splunk Enterprise 10.4.3 (macOS). The app was validated by its authors on Splunk 10.2.x, so everything here is marked as seen on 10.4.3. Where I could not check something, the text says "Not verified on this Splunk".

Screenshots show the demo data used for this guide: use case content from the Fenre catalogue, a few synthetic events in the indexes `os`, `sun_demo` and `ucm_controltest`, and nine test users whose names start with `sunguide_`. The demo setup is described in [the appendix](#appendix-demo-walkthrough).

Feedback is welcome: use the [SUNavigator feedback form](https://github.com/cagdaskarabag/su_navigator/issues/new?template=feedback.yml). What works, what does not and what is planned is in [FEATURE_STATUS.md](FEATURE_STATUS.md).

Contents

1. [What SUNavigator is and what it is not](#what-sunavigator-is)
2. [Ten-minute quick start](#quick-start)
3. [Ideas you need first (glossary)](#glossary)
4. One chapter per page: [Home](#page-home), [Overview](#page-overview), [Content Catalogue](#page-catalogue), [use case page](#page-use-case), [Data Inventory](#page-data-inventory), [Readiness](#page-readiness), [Backlog](#page-backlog), [Deployments](#page-deployments), [Control tests](#page-control-tests), [Coverage](#page-coverage), [Dashboards](#page-dashboards), [Content Administration](#page-content-administration)
5. Task chapters: [find use cases that fit my data](#task-find-use-cases-for-my-data), [understand why a use case is not ready](#task-understand-why-a-use-case-is-not-ready), [deploy as a team of one](#task-deploy-as-a-team-of-one), [deploy as a team of two](#task-deploy-as-two-people), [handle a blocked enable](#task-handle-a-blocked-enable), [tune a noisy search](#task-tune-a-noisy-search), [prove a search works with a control test](#task-control-test), [see my MITRE coverage](#task-see-mitre-coverage), [record an assessment and a POA&M item](#task-record-an-assessment-and-poam-item), [take an evidence snapshot](#task-take-an-evidence-snapshot), [give a colleague read-only access](#task-give-read-only-access), [verify the audit trail](#task-verify-the-audit-trail), [move a catalogue into an air-gapped Splunk](#task-air-gapped)
6. [Roles and permissions](#roles-and-permissions)
7. [Settings an administrator may change](#settings)
8. [Troubleshooting](#troubleshooting)
9. [Limits and what the app does not do](#limits)
10. [Appendix: sample data generator and demo walkthrough](#appendix-demo-walkthrough)

---

## What SUNavigator is
<a id="what-sunavigator-is"></a>

SUNavigator is a Splunk app that helps you decide which monitoring use cases to run and then deploys them safely.

- It imports a catalogue of use cases (today: the Fenre catalogue) into the app's own KV Store.
- It looks at your Splunk (indexes, sourcetypes, add-ons, data models) and tells you which use cases your data can support.
- It writes the ones you choose as saved searches. They are created disabled, and by default a second person must approve them before deployment.
- It shows which MITRE ATT&CK techniques, regulations and control catalogues the deployed use cases cover.
- It is not a SIEM content pack, not a certification tool and not proof that a search returns results. Readiness is evidence, not a guarantee. See [limits](#limits).

Who does what. The app uses seven Splunk roles. Each role grants one or two app capabilities. The table shows what I verified in [roles and permissions](#roles-and-permissions).

| Role | What it is for |
|---|---|
| `ucm_viewer` | Read the catalogue, inventory, readiness, deployments and coverage |
| `ucm_analyst` | Viewer, plus run discovery, validate SPL, assess readiness, start a draft |
| `ucm_content_manager` | Analyst, plus synchronize, import and reindex content, and verify the audit chain |
| `ucm_deployment_operator` | Analyst, plus submit, approve, deploy, enable, roll back and retire deployments |
| `ucm_compliance_assessor` | Viewer, plus record assessments, plan items (POA&M) and evidence snapshots |
| `ucm_scheduler` | The account that owns and runs the deployed saved searches. Nobody signs in as this role |
| `ucm_admin` | All of the above |

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Ten-minute quick start
<a id="quick-start"></a>

Start here when the app is installed and content is loaded. Installation is out of scope: see [`docs/OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md). In this walkthrough the catalogue holds 401 use cases from the Fenre provider, version 8.28.0 (categories 1 and 9).

1. Open Splunk, then Apps, then **SUNavigator**.

   ![The Splunk Apps launcher with the SUNavigator tile](images/02-splunk-launcher.png)

2. **Home** shows where things stand and the six steps from content to monitoring. If the Catalogue box shows 0 use cases, go to **Administration** and synchronize or import content first ([chapter](#page-content-administration)).

   ![Home with the state boxes and the six steps](images/user-guide/02-home.png)

3. Open **Data Inventory** and click **Run discovery**. This reads which indexes and sourcetypes have data. It takes a few seconds to minutes ([chapter](#page-data-inventory)).
4. Open **Readiness**. If a stored result is missing, use **Re-assess all**. Each use case gets a state and a score ([chapter](#page-readiness)).
5. Open **Content Catalogue**, filter by Availability or search for what you want to monitor, and open a use case ([chapter](#page-catalogue)).
6. On the use case page, read **Requirements and readiness**, then click **Plan deployment**. Choose **Select**, fill in the schedule, and click **Save draft**, then **Submit for approval** ([task](#task-deploy-as-two-people)).
7. A second person with the deployment role opens the same use case, clicks **Approve**, then **Deploy (disabled)**.
8. Either person clicks **Enable**. The saved search now runs on its schedule. Look at it in **Settings > Searches, reports, and alerts**, and at **Triggered Alerts** when it fires.

If you work alone, see [deploy as a team of one](#task-deploy-as-a-team-of-one).

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Ideas you need first
<a id="glossary"></a>

| Term | Meaning | Where you see it |
|---|---|---|
| Use case | One monitoring idea with its search (SPL), requirements, mappings and guidance | Catalogue, use case page |
| Provider | The source of use cases. Today `Fenre`. Content is stored locally after a sync or import | Catalogue column, Administration |
| Requirement | Something a use case needs: an add-on, an index, a sourcetype, a data model, a field, a lookup, a permission, a valid search | Use case page, Requirements |
| Readiness state | `ready`, `partially ready`, `not ready`, `blocked`, `insufficient evidence`. A judgement from the checks that could be made | Readiness, use case page |
| Score | 0 to 100. Requirements are weighted by level and confidence; not verified requirements are left out | Readiness |
| Data seen | Whether the events, populated data models and fields the use case reads were observed. It does not change state or score | Readiness, Overview |
| Populated | A data model that has events in the discovery window | Use case page, Inventory |
| Availability | Catalogue filter that groups use cases by how ready they are against your data | Catalogue |
| Four-eyes | Submitter and approver must be different people (`allow_self_approval = false`) | Use case page |
| Disabled-first | Deploy and rollback write the saved search disabled; enabling is a separate audited step | Use case page, Deployments |
| Override | An audited reason that lets you enable despite a gate (for example the scheduler account cannot read an index). Expires after 14 days by default | Enable dialog |
| Access gap | The scheduler account cannot search an index the use case reads, so a scheduled run would return nothing and still report success | Use case page, Overview |
| Drift | The saved search in Splunk no longer matches what the app deployed | Deployments, use case page |
| Outcome | Your judgement after deployment: `Needs tuning` or `Waiting on data` | Use case page, Deployments |
| Coverage: mapped, covered, gap | Mapped: a use case is linked to a technique or control. Covered: that use case is also data ready, deployed or enabled. Gap: nothing mapped or nothing deployed | Coverage |
| Control catalogue | A list of controls (NIST CSF, SP 800-53, SP 800-171, CMMC Level 2) | Coverage |
| Assessment | Your recorded status for one control (Implemented, Partially implemented, Planned, Not implemented, Not applicable) | Coverage |
| POA&M | Plan of action and milestones: a plan item for a weak control | Coverage |
| Snapshot | A saved, hashed copy of an assessment you can download and check later | Coverage |

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Home
<a id="page-home"></a>

**What it answers.** What is the state of content, discovery and readiness, and what should I do next?

**How to read it.**

- *Where things stand*: Catalogue (use case count, last sync, content version), Last discovery (index and sourcetype pairs found), Readiness (counts per state). These come from the app's stored state, not from a live search. Hover a state to see its rule.
- *From content to monitoring*: six steps (Get content, Discover, Assess, Choose, Validate and deploy, Monitor) each with the page that does it. The highlighted step is the first one without a result.
- *Recommended next*: up to 10 use cases. The draft score is 40% readiness score + 25% criticality + 20% new MITRE coverage + 15% requirement coverage. The text says the weights are a starting point, not measured. Ready use cases come before partially ready ones. **Why this use case** shows the breakdown. The checkbox "Leave out AI-reviewed and unreviewed use cases" narrows the list. Nothing is selected or deployed for you.

![Home: the Recommended next list with the draft score](images/user-guide/03-home-recommended-next.png)

**Common mistakes.** Treating the recommended list as an instruction. It ranks stored results; it does not know your priorities.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Overview
<a id="page-overview"></a>

**What it answers.** How much of the catalogue can I run, and is the scheduler account set up properly?

**Key figures** (each has a one-line rule under it):

- *Assessed*: use cases with a stored readiness result divided by active use cases.
- *Ready*: ready divided by assessed. Not verified requirements are left out.
- *Ready or partially ready*, *Not ready, blocked or insufficient evidence*.
- *Data seen*: assessed use cases whose data evidence is seen. Readiness says the content can run; data seen says its data was observed.
- *Deployed*: deployments in the deployed state; "enabled" is how many of those have an enabled saved search at the last check.

**Scheduler account card.** Shows whether a scheduled owner is configured (here `sunguide_scheduler`), the roles it holds, whether it can search internal indexes (`_internal`, `_audit`), and the default indexes. The card warns that a deployed search reading `_internal` or `_audit` would run as this account, return no events and still report success, unless the role has `_*` (or the index name) in `srchIndexesAllowed`. `*` does not include internal indexes.

Below are charts: use cases by domain, by criticality, readiness by state, ready use cases by domain, and a Validation and deployment section.

![Overview with key figures and the scheduler account card](images/user-guide/04-overview.png)

**Common mistakes.** Reading "Ready 8%" as a poor result. It reflects how many use cases match the data in this Splunk, not how good the catalogue is.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Content Catalogue
<a id="page-catalogue"></a>

**What it answers.** Which use cases exist, and which fit my needs?

**Layout.** A summary line (for example "401 active use cases. Fenre 8.28.0: 401, imported ...") then filters, then a table. Filtering and paging run on the server, one page at a time. Counts next to each filter value are for the whole catalogue, not for the other filters you chose.

**Filters.** Text SEARCH, SOURCETYPE (EXACT), MITRE ATT&CK ID, SORT (ID, Criticality, Title, Recently imported), Only my bookmarks, and facets: Provider, Domain, Category, Maturity wave, Data maturity, Criticality, Difficulty, Availability, Review status, Quality flag, Hide quality flag, Regulation, Analytic story, Data source. Facets allow several values at once. **Copy link to this view** copies a link to the current view. *Not verified on this Splunk:* that the link restores every filter.

![Catalogue with its filters and the first use cases](images/user-guide/05-catalogue.png)

![Catalogue after searching for SSH](images/user-guide/06-catalogue-search.png)

![The Availability filter opened with counts per value](images/user-guide/07-catalogue-availability-filter.png)

![Catalogue with an Availability value applied](images/user-guide/08-catalogue-filter-applied.png)

**Table columns.** ID, Use case (with a short description), Domains, Category, Criticality, Difficulty, Sourcetypes (from SPL), MITRE, Review and quality (badges such as `draft`, `unreviewed`, `AI reviewer`), Your selection (**Bookmark** and **Select**).

**Bookmark and Select.** Bookmark marks a use case for you only and does not appear in the Backlog. Select puts it in your Backlog. Both are stored per user and are not changed by a content sync.

**Common mistakes.** Treating review badges as a verdict on readiness. They describe the provider's review of the content, not your environment.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Use case page
<a id="page-use-case"></a>

**What it answers.** What does this use case do, can I run it here, and how do I deploy it?

**Top.** Title, provider, id (`fenre:UC-1.1.8`), criticality, difficulty, domains, review badges, the path (provider > category > subcategory) and catalogue version. A **Jump to** line links to Requirements and readiness, SPL and search, Your selection and Plan deployment. Four cards summarize Requirements, Readiness, Deployment and Your selection.

![Use case page top with four summary cards](images/user-guide/09-usecase-top.png)

**Requirements and readiness.** Shows the readiness state and score, a **Re-assess now** button and a **Data** line. Requirements are grouped (Not Met, Not Verified, Met, N/A) with Type, Requirement, Level, Source, Confidence, Status and Evidence. Each unmet requirement has a **What to check** hint. Requirements come from the provider record or are derived from its SPL; derived ones have lower confidence and weight. A footer states "Readiness is inventory and validation evidence, not a guarantee that the search returns results."

![Requirements and readiness with grouped requirement results](images/user-guide/10-usecase-requirements.png)

**SPL and search.** The primary search (and a CIM search when available), with a **Copy** button.

![The SPL and search section](images/user-guide/11-usecase-spl.png)

**Parse and sample fields.** Asks Splunk to parse the SPL and samples the fields over a short window. A bounded preview forces a short time window and a result cap. Searches with delete, outputlookup, collect, script or similar commands are refused, and so are searches with map, savedsearch, rest or commands outside the app's read-only list. Field requirements show "Field has not been sampled. Run validation on this use case." until you run it.

![SPL validation after Parse and sample fields](images/user-guide/12-usecase-validation.png)

**Run this search.** An interactive search that runs in your browser, as your own Splunk user, through Splunk's search API. The panel warns that it runs outside SUNavigator's guard rails: the bounded-preview rules do not apply, the app cannot audit it and Splunk records it under your account. Nothing runs until you click **Run search**. Choose a time range (Last 15 minutes up to Last 7 days); it is ignored if the SPL sets its own `earliest` or `latest`. The search stops after 120 seconds or when you leave the page, and only the first 100 rows are shown. Results are shown on the page only. Searches with side-effect commands (also inside a map search) or with SPL the page cannot show (`savedsearch`, `loadjob`, `dbxquery`) are not offered. *Not verified on this Splunk*: the refusal itself, because no use case in the imported categories (1 and 9) has a side-effect command in its primary search.

![The Run this search panel](images/user-guide/13-usecase-run-search-form.png)

![Results of a run in the browser](images/user-guide/14-usecase-run-search-result.png)

**Plan deployment.** Opens the selection and deployment controls ([task](#task-deploy-as-two-people)). The card lists *Actions not available to you right now* with the reason for each.

**Common mistakes.**

- Clicking **Run search** to "test" a deployment. It runs as you, not as the scheduler account, so it can succeed while the scheduled run returns nothing (see [access gap](#task-handle-a-blocked-enable)).
- Reading Data seen as readiness. They are separate.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Data Inventory
<a id="page-data-inventory"></a>

**What it answers.** What data does this Splunk actually have?

**Discovery.** Shows the last success and last attempt time, the window (default `-7d` to now) and whether internal indexes are included (default no). **Run discovery** runs a constructed `tstats` over the indexes the management API lists. Imported SPL is never searched. Internal indexes are listed without counts unless "Include internal indexes" is ticked; readiness then shows requirements on internal indexes as not verified, never as present or missing. A history table shows each run with Pairs, Indexes, Missing and Errors.

Discovery runs under the app's system session. Splunk role restrictions of the person who clicks the button do not limit what is listed: I tested with a user limited to three indexes and the inventory still listed all of them. Do not treat the inventory as a per-user view.

![Inventory before the first discovery run](images/user-guide/16-inventory-before-discovery.png)

![Inventory after discovery](images/user-guide/15-inventory-top.png)

**Tables.** Per kind (sourcetype, index, datamodel, addon) the page shows how many catalogue values are present (for example "15 of 207 catalogue values present"), the first missing ones, and data age. Further sections: Environment health, CIM add-on, Data model summaries, CIM index macros, Indexes without data, Stopped before the window (sources whose newest event is older than the window), Future time stamps, and Sourcetypes no use case names. "Populated" means a data model has events; "data seen" is the readiness-level result of those observations.

![Inventory tables: sourcetypes and indexes with data age](images/user-guide/17-inventory-sourcetypes.png)

**Source mappings.** Discovery maps names it finds to canonical catalogue names automatically (origin `auto_exact`, confidence `medium`). Auto matches are not readiness evidence. You can add a **local mapping** (kind, discovered value, canonical value, note). Local mappings are never overwritten by discovery and show origin `local`, confidence `high`. In the demo I mapped the index `sun_demo` to the canonical name `wineventlog`, then deleted it. **Delete** acts at once, without a confirmation dialog.

![Source mappings form and automatic mappings](images/user-guide/18-inventory-source-mappings.png)

![A local mapping filled in](images/user-guide/19-inventory-mapping-form.png)

![The local mapping after saving](images/user-guide/20-inventory-mapping-saved.png)

**Common mistakes.**

- Pushing synthetic Windows events with the source `WinEventLog:Security`. Stock Splunk props rename the sourcetype to `WinEventLog`, so use cases that ask for `WinEventLog:Security` do not find it. Use a different source name (the generator uses `demo:winsec`).
- Expecting a new index to appear in readiness before running discovery and then **Re-assess all**.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Readiness
<a id="page-readiness"></a>

**What it answers.** For each use case, can it run on this data, and how sure are we?

**Key figures** repeat the Overview figures. **State cards** show counts for Ready, Partially ready, Not ready, Blocked and Insufficient evidence. The *Assessment* box shows the last assessment time, the discovery it was based on, and thresholds (here `ready ≥ 90, partial ≥ 50, min coverage 50%`). **Re-assess all** recomputes every use case from the latest discovery.

**States.**

- *Ready*: no blockers, score at or above the ready threshold and enough coverage.
- *Partially ready*: score at or above the partial threshold.
- *Not ready*: below that.
- *Blocked*: an unmet critical requirement.
- *Insufficient evidence*: not enough checks could be made.
- In this walkthrough Blocked was 0, so I have no Blocked screenshot. *Not verified on this Splunk*: the look of a Blocked use case card.

**Requirement statuses.** `met`, `partial`, `not met`, `unknown`, `not verified`, `n/a`. Not verified means the check could not be made yet (for example a field not sampled, or an internal index when discovery skips internal indexes). It is not the same as missing and it is left out of the score.

**Most common unmet requirements** lists required requirements that were checked and not met, with the number of use cases affected (for example an add-on that 40 use cases need). It is a quick way to see which add-on or sourcetype would unlock the most content.

**List.** Filters: search, state, data (seen, partial, none, unverified, not applicable), domain, criticality, sort. Each row opens the use case.

![Readiness key figures and state counts](images/user-guide/21-readiness.png)

![Readiness list with filters and the most common unmet requirements](images/user-guide/22-readiness-list.png)

**Readiness cards.** The card on a use case shows state, score, coverage, the evidence list and when it was evaluated.

![Readiness card of a Ready use case](images/user-guide/23-readiness-card-ready.png)

![Readiness card of a Partially ready use case](images/user-guide/24-readiness-card-partial.png)

![Readiness card of a Not ready use case](images/user-guide/25-readiness-card-not-ready.png)

![Readiness card where the data evidence is not current](images/user-guide/26-readiness-card-stale-data.png)

**What changes the score.** A new discovery followed by a re-assessment, installing an add-on, ingesting data, parsing the SPL (which lifts not verified field requirements), and adding a local mapping. **What never changes it:** selecting, bookmarking, deploying or enabling a use case; the review badges; and Data seen, which is reported separately.

**Common mistakes.** Treating Ready as proof. The page itself says a state is a judgement from the checks that could be made, not a guarantee that data is present.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Backlog
<a id="page-backlog"></a>

**What it answers.** What have I selected or deferred?

Lists the use cases you selected or deferred. Bookmarks are not listed. Selection is per user and is never overwritten by a content sync. The empty state says "Your backlog is empty. Open a use case from the catalogue and choose Select or Defer." The selection panel on a use case page offers **Select**, **Bookmark**, **Defer**, **Reject** and **Clear**.

![Backlog with nothing selected](images/user-guide/27-backlog-empty.png)

![Backlog with selected and deferred use cases](images/user-guide/28-backlog.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Deployments
<a id="page-deployments"></a>

**What it answers.** Which use cases did this app deploy as saved searches, in what state, and has anything drifted?

**Pipeline counts.** Draft, Pending approval, Approved, Deployed (disabled), Enabled. **Needs attention:** Needs tuning, Waiting on data, Override expired, Failed, Drift or missing. Then a table with Use case, Workflow state, Saved search status, Runs (24 h), Revision (`latest 2, deployed 1`), Updated (UTC) with the actor, and Last error. Filters: workflow state (`draft`, `pending approval`, `approved`, `rejected`, `deployed`, `failed`, `retired`) and saved-search status (`enabled`, `disabled`, `missing`, `unmanaged`, `absent`). **Export deployed revisions** downloads the revisions.

![Deployments page with pipeline counts](images/user-guide/46-deployments-page.png)

![Deployments page listing all workflow states](images/user-guide/67-deployments-page-all.png)

**Workflow states.** draft, pending approval, approved, deployed, retired (also rejected and failed). A deployment is created disabled. The saved search status is separate: `disabled` or `enabled` after deployment, `absent` before deployment or after retirement.

**Drift.** I changed the cron schedule of the saved search in Splunk as an admin. After **Verify now** the card showed "Drift detected" with `cron_schedule expected */5 * * * *, observed */10 * * * *` and a drift badge on the plan. The background worker also checks drift (`verify_interval_minutes`, default 60).

![Drift detected on a deployed use case](images/user-guide/50-drift-detected.png)

**New revision and rollback.** **Start a new revision** edits the search or schedule. Deploying a new revision writes it disabled again. **Roll back** returns to an earlier revision and also writes disabled. Both are audited.

![Start a new revision](images/user-guide/51-new-revision-form.png)

![Revision 2 deployed](images/user-guide/52-deployed-revision-2.png)

![The roll back dialog](images/user-guide/53-rollback-dialog.png)

![After rollback](images/user-guide/54-rolled-back.png)

**Withdraw an approval.** Allowed for an approved revision that is not yet deployed. In my run the deployment went back to `pending approval` and the Approve action was offered again.

![Withdraw approval dialog](images/user-guide/62-withdraw-approval-dialog.png)

![After withdrawing the approval the deployment is pending approval again](images/user-guide/63-approval-withdrawn.png)

**Retire.** After retiring, the saved search status is `absent` and the history stays.

![The retire dialog](images/user-guide/64-retire-dialog.png)

![A retired deployment](images/user-guide/65-retired.png)

![Deployment history with actor and time](images/user-guide/66-deployment-history.png)

**Common mistakes.** Editing the saved search in Splunk instead of creating a revision. The next verify reports drift. Expecting **Enable** to happen on deploy: it never does.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Control tests
<a id="page-control-tests"></a>

**What it answers.** Does the deployed search fire on a known-bad sample?

A control test replays a fixture (sample events for one use case) into the index `ucm_controltest`, runs the deployed search over the fixture's time window, and compares the result with what the fixture expects. The card shows `passed` or `failed` with the reasons, the revision tested, the test index, the search window and who ran it.

Fixtures come from the Fenre sample files. I built one file with `python3 tools/ucm_cli.py build-control-fixtures --samples <fenre>/samples --output fixtures.json` and imported it as the content manager (94 fixtures). I found no button for the import in the app, so I sent it to `POST /services/ucm/controltest/import` from the browser session. Not verified on this Splunk: whether another import path exists in the UI.

![Control test result on the use case page](images/user-guide/47-control-test-result.png)

![Control test details card](images/user-guide/48-control-test-card.png)

In my run the control test for UC-1.1.8 returned `failed`: "positive run returned 0 rows, expected at least 5; field src: no value matched regex `^(10|172|192)\.`". The tested search window came from the fixture timestamps (April 2026), and the fixture hosts are synthetic. Treat a failed test as a question about the search or the fixture, not as proof the deployment is wrong. I report it as a finding.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Coverage
<a id="page-coverage"></a>

**What it answers.** Which techniques, regulations and controls do my use cases cover, and what is missing?

**Top.** Choose a framework (MITRE ATT&CK Enterprise or ICS) and a domain. Counters: In catalogue, Data ready, Deployed, Enabled. A switch adds run status. **Graded coverage** colours each technique by how far the use cases mapped to it have progressed. **Export ATT&CK Navigator layer** downloads a layer file.

![Coverage top](images/user-guide/68-coverage-top.png)

![The MITRE ATT&CK matrix coloured by coverage](images/user-guide/69-coverage-mitre-matrix.png)

![Coverage gaps and mappings that need review](images/user-guide/70-coverage-gaps.png)

**Mapped, covered, gap.** *Mapped* means a use case is linked to the technique or control in the catalogue data. It says nothing about your data. *Covered* adds data ready, deployed or enabled. A *gap* is a technique or control with no mapped use case, or with mapped use cases that are not deployed. **Mappings that need review** lists mappings the app is unsure about.

**Other frameworks and regulations.** A table of regulations with how many use cases map to each.

![Regulations](images/user-guide/71-coverage-regulations.png)

**Control catalogues.** NIST Cybersecurity Framework, SP 800-53, SP 800-171 and CMMC 2.0 Level 2, each with an active version. Counters: Controls, With a mapped use case, Without any mapped use case, Data ready or better, Deployed or better, Enabled, and assessment counts. **No mapped use case** filters the unmapped controls. Open a control family to see its controls.

![Control catalogues](images/user-guide/72-control-catalogues.png)

![A control family opened](images/user-guide/73-control-family-open.png)

For assessments, plan items and snapshots see the tasks [record an assessment](#task-record-an-assessment-and-poam-item) and [take an evidence snapshot](#task-take-an-evidence-snapshot).

**What the app does not do.** It does not certify anything. The CMMC score and the plan-item note are information only. The page says: "Information only: this is not a CMMC status determination." See [limits](#limits).

**Common mistakes.** Reading "covered" as "assessed". Coverage comes from deployed content. An assessment is a statement you record.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Dashboards
<a id="page-dashboards"></a>

**What it answers.** Can I get a dashboard for a domain or for the searches deployed by the app?

**Domain dashboard** (`ucm_domain`): choose a domain (here Security) to see Active use cases, Data ready, Enabled searches, Readiness by state, Use cases by criticality, a "Ready but not deployed" table and the Deployments table. It reads the app's KV Store lookups.

![Domain dashboard for Security](images/user-guide/82-domain-dashboard.png)

**Generated dashboards** (`Dashboards` page). Choose a template (*Domain overview* or *Deployed searches*) and for the first, a domain. **Preview** shows the Simple XML that would be written. **Create or regenerate** writes the dashboard into the app, marked as generated. The list shows the name, view id (for example `ucm_gen_domain_overview_security`), template and who updated it last, with **Regenerate** and **Delete**. Creating or removing needs the deployment capability. Delete asks "Delete dashboard? The generated view ... is deleted."

![Preview of the generated Simple XML](images/user-guide/83-dashboard-preview.png)

![The generated dashboard listed with Regenerate and Delete](images/user-guide/84-dashboard-created.png)

![The generated Security overview dashboard](images/user-guide/85-generated-dashboard.png)

![Two generated dashboards](images/user-guide/86-two-generated-dashboards.png)

![Delete dashboard confirmation](images/user-guide/87-dashboard-delete-confirm.png)

I created, regenerated and deleted both. The app's `local/data/ui/views` folder was empty afterwards.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Content Administration
<a id="page-content-administration"></a>

**What it answers.** Is the content current, and how do I update it?

**Fenre provider card.** Configured ref, Allowed refs, Remote sync (available), Last good version, commit and source, Schema version, Last success and last attempt, Selected categories. **Platform card.** Splunk version and capability checks: kvstore, remote content sync, offline import, manage content, run discovery, index/app/datamodel listing, adhoc search and a security content apps line. For a user without the right capability a row shows `unavailable` with the capability name.

![Provider card and platform card](images/user-guide/88-admin-provider-platform.png)

**Catalogue summaries.** Says whether all summaries are current (version 7). **Reindex catalogue summaries** re-derives the searchable summaries and facets from stored records, without any download. Run it after an upgrade that adds filters. The dialog says it takes about 5 seconds per 1,000 use cases and that selections, readiness and deployments are not changed. It needs the `ucm_content_manager` role.

![Catalogue summaries and Reindex](images/user-guide/89-admin-catalogue-summaries.png)

![Reindex confirmation](images/user-guide/92-admin-reindex-confirm.png)

**Remote synchronization.** A version pin field (optional) takes a branch or tag, or a commit on one. **Check provider for categories** lists the upstream categories with Upstream use cases, Imported locally and Last sync (25 categories here; 2 selected). Tick categories and synchronize. Selecting categories does not re-download records; that is the separate sync option.

![Remote synchronization and offline import](images/user-guide/90-admin-sync-import.png)

![Check provider for categories](images/user-guide/91-admin-check-provider.png)

**Offline import.** **Import bundle** takes a `ucm-content-bundle` built with `tools/ucm_cli.py build-bundle`. Every record is verified against its git blob hash, validated and normalized like a remote sync. See [the air-gapped task](#task-air-gapped).

**History.** The *Synchronization and import history* table shows each job with Source, Status, Requested by, Version, Commit, Added, Updated, Re-normalized, Unchanged, Withdrawn, Invalid, Errors. In this walkthrough: one manual sync, 401 added, 0 invalid.

**Content audit trail** and **Verify audit chain** ([task](#task-verify-the-audit-trail)). **Refused requests** lists governance requests that were refused.

The Platform card also shows a line about Splunk Enterprise Security and ESCU presence. It is a read-only check; the app states that behaviour with Enterprise Security installed is unvalidated.

**Common mistakes.** Running a remote sync on a Splunk that cannot reach GitHub. See [troubleshooting](#troubleshooting).

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Task: find use cases that fit my data
<a id="task-find-use-cases-for-my-data"></a>

1. **Data Inventory > Run discovery.** Wait for success.
2. **Readiness > Re-assess all.**
3. **Content Catalogue:** use the *Availability* filter and the *Data maturity* filter, or sort by Criticality. Add a domain or MITRE ID to narrow.
4. Open a result and read **Requirements and readiness**. The unmet requirement hints say what to install or map.
5. For a shortlist, open **Home** and read *Recommended next*.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: understand why a use case is not ready
<a id="task-understand-why-a-use-case-is-not-ready"></a>

1. Open the use case and read the Requirements and readiness section.
2. Open the **Not Met** group. Each row names the requirement, level (required, recommended, informational), source (provider structured or derived SPL), confidence and evidence. Example: "No installed app matches this add-on by name, label or Splunkbase id." with the hint "Install this add-on from Splunkbase, or map the requirement to the add-on you use."
3. Open **Not Verified**. These cost nothing in the score; click **Parse and sample fields** to check fields.
4. If you use a different add-on, add a **local mapping** in the Inventory and **Re-assess now**.

![Requirements and readiness with grouped requirement results](images/user-guide/10-usecase-requirements.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: deploy as a team of one
<a id="task-deploy-as-a-team-of-one"></a>

By default a second person must approve (`require_approval = true`, `allow_self_approval = false`). With one person you have three choices; I verified the refusal and not the changed settings.

- Use two accounts with the `ucm_deployment_operator` role (what I did).
- Set `allow_self_approval = true` in `local/ucm.conf`. *Not verified on this Splunk.*
- Set `require_approval = false`. *Not verified on this Splunk.*

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: deploy as two people
<a id="task-deploy-as-two-people"></a>

Roles: operator A (`sunguide_operator`) and operator B (`sunguide_operator2`), both `ucm_deployment_operator`. The scheduler owner (`sunguide_scheduler`, role `ucm_scheduler`) is configured in `local/ucm.conf` as `[deployment] scheduled_owner`. See [the access gap task](#task-handle-a-blocked-enable) for why the scheduler account matters.

1. **A:** open the use case, click **Plan deployment**, and click **Select**.

   ![Plan deployment panel with the empty draft form](images/user-guide/31-deploy-form.png)

2. **A:** fill in cron (for example `*/5 * * * *`), earliest and latest (`-15m@m`, `@m`), schedule window, alert actions and severity. Click **Save draft**. The saved draft shows the parser result and the plan: "Revision 1: primary SPL, cron ..., alert, severity high, results > 0. Parsed by Splunk."

   ![Draft form filled in](images/user-guide/32-deploy-form-filled.png)

   ![Draft saved](images/user-guide/33-deploy-draft-saved.png)

3. **A:** click **Submit for approval**. The state becomes `pending approval`.

   ![Pending approval](images/user-guide/34-deploy-pending-approval.png)

4. **A** cannot approve. The *Actions not available to you right now* list says: "Needs the ucm_deploy capability and a person other than the one who submitted it (self-approval is off)."

   ![Self-approval is refused](images/user-guide/35-deploy-self-approval-refusal.png)

5. **B:** open the same use case.

   ![A second operator sees the pending deployment](images/user-guide/36-deploy-pending-as-approver.png)

6. **B:** click **Approve**, give a reason in the dialog and confirm.

   ![The approve dialog](images/user-guide/37-approve-dialog.png)

   ![Approved](images/user-guide/38-deploy-approved.png)

7. Click **Deploy (disabled)**. The saved search `SUN - 1.1.8 - SSH Brute-Force Detection` appears, owned by `sunguide_scheduler`, disabled.

   ![Deployed, disabled](images/user-guide/39-deploy-deployed-disabled.png)

8. In Splunk, **Settings > Searches, reports, and alerts**, set Owner to *All* to see it. The page only lists your own searches by default.

   ![The disabled saved search in Splunk Settings](images/user-guide/40-splunk-settings-searches.png)

9. Click **Enable**.

   ![The enable dialog](images/user-guide/41-enable-dialog.png)

   ![Enabled](images/user-guide/42-deploy-enabled.png)

10. Push matching events (the generator's `burst` mode sends 30 failed SSH logins). When the search fires, it appears in **Activity > Triggered Alerts** and the app shows run status.

    ![Triggered Alerts](images/user-guide/43-triggered-alerts.png)

    ![Triggered Alerts list entry](images/user-guide/45-triggered-alerts-list.png)

    ![Run status in the app](images/user-guide/44-deploy-run-status.png)

Alert actions: email and webhook were not exercised because this Splunk has no SMTP server or webhook target. *Not verified on this Splunk.* The default alert mode was used.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: handle a blocked enable
<a id="task-handle-a-blocked-enable"></a>

Two things can stop an enable: readiness `blocked` (setting `block_enable_states`, default `blocked`) and an *access gap*, where the scheduler account cannot read an index the search uses. The use case page says on every use case: "Enabling is blocked while readiness is blocked (an override is audited)." It appears even on a Partially ready use case where nothing is blocked.

I produced an access gap on purpose: I gave `sunguide_scheduler` an extra role that disallows the index `os`, then restored it. I did not reproduce a *blocked readiness* gate because no use case was blocked here. *Not verified on this Splunk:* the blocked-readiness gate itself.

1. When submitting, the app warns: "The scheduler account cannot see this search's data. `sunguide_scheduler` cannot search `os` (os: disallowed by 'os'; roles: ...). Grant the index to the role or the search will run blind. You can submit it, but the approver will be told, and enabling will need an override reason. Consider fixing the account's index access first." Choose **Submit anyway** or fix the role.

   ![Access gap warning on submit](images/user-guide/55-access-gap-dialog.png)

2. The approver sees the same note.

   ![Approval with an access gap](images/user-guide/56-approve-with-access-gap.png)

3. **Enable** opens *Override the enable gate*. Enter a reason of at least 10 characters. The override is audited and expires after 14 days; you are reminded then.

   ![Override the enable gate](images/user-guide/57-enable-override-dialog.png)

4. With `override_second_person = true` (the default), the override becomes an enable request that a second person must confirm within 24 hours.

   ![Enable request pending](images/user-guide/58-enable-request-pending.png)

   ![The second person sees the request](images/user-guide/59-enable-confirm-by-second-person.png)

   ![Confirm dialog](images/user-guide/60-enable-confirm-dialog.png)

5. After confirmation the search is enabled with the override recorded.

   ![Enabled with an override](images/user-guide/61-enabled-with-override.png)

The better fix is to grant the index to the scheduler role. A role limited to `os` that the app does not know about still returns "success" with no events.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: tune a noisy search
<a id="task-tune-a-noisy-search"></a>

1. Open the deployed use case. In *Outcome after deployment* choose **Needs tuning** (it runs but results nobody can act on) or **Waiting on data** (deployed but the data it needs is not there).
2. Enter a note of at least 5 characters and click **Save outcome**. The Deployments page counts it under *Needs attention*.
3. Change the threshold through **Start a new revision**, then approve and deploy again.

![Recording the outcome Needs tuning](images/user-guide/49-outcome-needs-tuning.png)

Without a note the app says: "an outcome needs a note saying why (at least 5 characters)".

![Saving an outcome without a note is refused](images/user-guide/95-error-outcome-needs-note.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: prove a search works with a control test
<a id="task-control-test"></a>

1. A content manager imports fixtures ([Control tests](#page-control-tests)).
2. Open the deployed use case and click **Run control test**.
3. Read the result card: it lists each expectation that did not hold.

![Control test result](images/user-guide/47-control-test-result.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: see what MITRE techniques I cover
<a id="task-see-mitre-coverage"></a>

1. Open **Coverage**, pick **MITRE ATT&CK Enterprise**.
2. Use the domain selector and the counters to compare *In catalogue*, *Data ready*, *Deployed* and *Enabled*.
3. Use **Coverage gaps** for techniques without any mapped use case, and **Mappings that need review**.
4. **Export ATT&CK Navigator layer** writes a file you can open in the MITRE Navigator. *Not verified on this Splunk:* opening the file in Navigator.

![MITRE matrix](images/user-guide/69-coverage-mitre-matrix.png)

![Coverage gaps](images/user-guide/70-coverage-gaps.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: record an assessment and a POA&M item
<a id="task-record-an-assessment-and-poam-item"></a>

You need the `ucm_assess` capability (role `ucm_compliance_assessor`).

1. **Coverage > Control catalogues > CMMC 2.0 Level 2.** Open a family and open a control.
2. Choose a status (Implemented, Partially implemented, Planned, Not implemented, Not applicable), add a note and click **Save assessment**.

   ![The assessment form](images/user-guide/74-assessment-form.png)

   ![The assessment form filled in](images/user-guide/75-assessment-form-filled.png)

3. The score (CMMC scoring) updates. I recorded IA.L2-3.5.3 Implemented, IA.L2-3.5.2 Partially implemented and IA.L2-3.5.4 Not implemented, and the score moved from -203 to -198 of 110.

   ![CMMC score after three assessments](images/user-guide/76-cmmc-score-after-assessing.png)

4. Under **Plan of action and milestones**, click **Add a plan item**. Enter control id, title, what is weak, owner, due date and milestones (one per line; a date at the start gives that milestone a due date). Click **Add plan item**. A plan item records how and when a weakness will be fixed. It does not change the control's status.

   ![The plan item form filled in](images/user-guide/77-poam-form-filled.png)

5. The list shows state `Open` with actions **Start**, **Close**, **Accept risk**. The section header shows the eligibility note: "32 CFR 170.21(a)(2) and (b). Closeout must be within 180 days of the status date. Information only: this is not a CMMC status determination." and the score threshold (needs at least 0.80 for a plan of action for Conditional Level 2 status; the score was -1.80).

   ![A plan item with the eligibility note](images/user-guide/78-poam-item-eligibility.png)

SP 800-171 Rev. 3 per-objective results: *Not verified on this Splunk.* I recorded assessments for CMMC controls only.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: take an evidence snapshot
<a id="task-take-an-evidence-snapshot"></a>

1. On **Coverage**, click **Take a snapshot** and give an optional label.

   ![Take a snapshot dialog](images/user-guide/79-snapshot-dialog.png)

2. The snapshot appears under *Evidence snapshots*.

   ![The list of snapshots](images/user-guide/80-snapshot-list.png)

3. Click **Download** to get a JSON file. The page recomputes the SHA-256 and says "Integrity check passed" with the hash. Record the hash somewhere outside Splunk.

   ![Download shows Integrity check passed](images/user-guide/81-snapshot-integrity-check.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: give a colleague read-only access
<a id="task-give-read-only-access"></a>

1. In Splunk, **Settings > Users > New user**. Assign the role `ucm_viewer` only.
2. They sign in and open SUNavigator.
3. The menu is the same as everyone's. Actions are refused when used (see [roles](#roles-and-permissions)).

   ![Deployments page as a viewer](images/user-guide/29-deployments-viewer.png)

   ![Use case deployment panel as a viewer](images/user-guide/30-usecase-deployment-viewer.png)

Note that `ucm_viewer` inherits the Splunk `user` role, so it can run searches in Splunk itself.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: verify the audit trail
<a id="task-verify-the-audit-trail"></a>

1. **Administration** as a content manager or admin. Scroll to *Content audit trail*.
2. Click **Verify audit chain**. The message in this run was "The audit chain is intact. 76 of 76 rows are chained. Head ... Record it outside Splunk to also detect removal of the newest rows." Each row carries a hash of itself and of the row before it, so editing a row or removing one from the middle is detected. Removing the newest rows is not detected unless you recorded the head hash.
3. *Refused requests* lists governance requests that were refused, with user, route, object, code and message. Repeats are written once per window (`[audit] refusal_window_seconds = 300`) and each user has an hourly limit.

![Audit trail, chain verification and refused requests](images/user-guide/93-admin-audit-chain-verified.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

## Task: move a catalogue into an air-gapped Splunk
<a id="task-air-gapped"></a>

On a connected machine run `python3 tools/ucm_cli.py build-bundle ...` to produce a `ucm-content-bundle` file. On the air-gapped Splunk, **Administration > Import bundle**, choose the file. Maximum size is `[import] max_bundle_mb` (default 50). *Not verified on this Splunk:* a successful import of a real bundle. I verified only the refusals: a 51 MB body returned `bundle exceeds size limit` and a non-JSON body returned `bundle is not valid UTF-8 JSON`.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Roles and permissions
<a id="roles-and-permissions"></a>

I signed in as one user per role, read each page, and called seven API routes from each session. The routes test a capability without changing data: they return 403 when the capability is missing and 400 (missing id or body) when it is present. This table is what the app did on this Splunk.

| Ability | viewer | analyst | content manager | operator | assessor | scheduler | admin |
|---|---|---|---|---|---|---|---|
| See every page and the catalogue | yes | yes | yes | yes | yes | yes | yes |
| Bookmark, select, defer | yes | yes | yes | yes | yes | yes | yes |
| Run discovery, validate SPL, preview, start a draft | no | yes | yes | yes | no | no | yes |
| Fetch the provider manifest, sync, import, reindex | no | no | yes | no | no | no | yes |
| Save an assessment, plan item, snapshot | no | no | no | no | yes | no | yes |
| Enable, approve, deploy (`ucm_deploy`) | no | no | no | yes | no | no | yes |
| Verify the audit chain | no | no | yes | no | no | no | yes |

Notes from the run:

- The menu is identical for all roles: Home, Overview, Content Catalogue, Data Inventory, Readiness, Backlog, Deployments, Coverage, Dashboards, Administration. A viewer sees no limited menu.
- Buttons are also shown to roles that cannot use them. A viewer sees **Run discovery**, **Save local mapping**, **Import bundle**, **Reindex catalogue summaries** and **Check provider for categories**. I clicked **Check provider for categories** as a viewer: the API answered 403 `missing capability ucm_manage_content` and the page said "The provider could not be reached." I did not click the other buttons as a viewer; the API refused the equivalent calls with 403.
- Refusal message format: `missing capability ucm_manage_content`; for drafts `missing capability ucm_deploy or ucm_run_discovery`; for the audit chain `missing capability ucm_admin`, although a content manager is allowed to verify it.
- The analyst can start a draft but cannot enable, approve or deploy.
- `ucm_scheduler` has only Splunk search and schedule capabilities and no app capabilities.
- The Dashboards page offered **Preview** and **Create or regenerate** to every role. Creating needs the deployment capability. I created dashboards as an operator only; the refusal for other roles is *Not verified on this Splunk*.

![A viewer clicks Check provider: the page says the provider could not be reached](images/user-guide/94-viewer-refused-check-provider.png)

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Settings an administrator may change
<a id="settings"></a>

Settings live in `local/ucm.conf` in the app (never edit `default`). The full list is in `README/ucm.conf.spec`. Only what I tried is described as verified.

| Setting | Default | What it does | Seen |
|---|---|---|---|
| `[deployment] scheduled_owner` | empty | The account that owns deployed saved searches. Without it Overview says "No scheduled owner is configured" | Set to `sunguide_scheduler`. After editing the file by hand the app kept the old answer until `POST /services/configs/conf-ucm/_reload`; no restart was needed |
| `[deployment] allow_self_approval` | false | Lets the submitter approve | Default behaviour seen (refused). Changing it: not verified |
| `[deployment] override_second_person` | true | An override needs a second person | Default behaviour seen |
| `[deployment] override_days` | 14 | Override lifetime | Dialog says 14 days |
| `[deployment] block_enable_states` | blocked | Readiness states that block enabling | Not changed; not verified |
| `[audit] refusals`, `refusal_window_seconds` | true, 300 | Writes refused requests to the audit trail | Seen in the Refused requests table |
| `[interactive_search] enabled` | true | Offers **Run search** on use case pages | Seen enabled; disabling not verified |
| `[import] max_bundle_mb` | 50 | Largest offline bundle | The limit message quoted the 52428800 bytes |
| `[controltest] index` | `ucm_controltest` | Index for control test fixtures | Seen |

After changing `local/ucm.conf`, reload with the `_reload` endpoint above or restart Splunk.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Troubleshooting
<a id="troubleshooting"></a>

| Symptom | Cause | Fix | Exact message |
|---|---|---|---|
| Overview says no scheduled owner after you set it | The app cached the old config | `POST /services/configs/conf-ucm/_reload` or restart | "No scheduled owner is configured" |
| A viewer clicks **Check provider for categories** and sees a provider error | The request was refused for lack of permission; the page reports it as a provider problem | Use a content manager account | Page: "The provider could not be reached." API: `missing capability ucm_manage_content` |
| Sync with a bad ref | The ref is not in `allowed_refs` | Use an allowed ref (default `main`) or add it to `allowed_refs` | `ref is not in allowed_refs` (details list `allowed_refs`) |
| Sync with a ref containing odd characters | Refs may use letters, digits and `. _ / -` only | Correct the ref | `invalid ref` |
| Import is too large | Larger than `max_bundle_mb` | Raise the limit or split the bundle | `bundle exceeds size limit` (limit_bytes 52428800) |
| Import is not a bundle | The file is not valid UTF-8 JSON | Build it with `build-bundle` | `bundle is not valid UTF-8 JSON` |
| Save outcome refused | Note shorter than 5 characters | Write a reason | "an outcome needs a note saying why (at least 5 characters)" |
| Approve refused | You submitted it | Ask another operator | "Needs the ucm_deploy capability and a person other than the one who submitted it (self-approval is off)." |
| Enable refused because the scheduler cannot read the index | Access gap | Grant the index to the scheduler role, or enter an override | "The scheduler account cannot see this search's data" |
| Deployed search runs but never fires | Scheduler account has no access, or the data is missing | Check Overview's scheduler card and the Inventory | Run status shows no events |
| Synthetic Windows events not found by use cases | Splunk renamed the sourcetype `WinEventLog:Security` to `WinEventLog` | Use another source name for test data | - |
| KV Store not ready | The app cannot read its collections | Check `splunk show kvstore-status` as an admin. *Not verified on this Splunk:* I did not break the KV Store, so I could not check the exact message | - |
| Platform card shows kvstore as unknown | The caller cannot read `kvstore/status` | Check as an admin | "kvstore/status not readable by caller" (seen as content manager and viewer) |
| Search with a side-effect command | Use case SPL has `outputlookup`, `collect`, `delete` etc. | The preview and the run panel refuse | *Not verified on this Splunk*: no shipped use case in the imported categories triggers it |

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Limits
<a id="limits"></a>

Known small defects found while writing this guide are filed as issues: a refused **Check provider for categories** is reported as "could not be reached" (#34), the audit-chain refusal names only `ucm_admin` (#35), buttons are shown to roles that cannot use them (#36), the Platform card shows kvstore as unknown to some roles (#37), the enable note is shown on every use case (#38), deleting a local mapping has no confirmation (#39), and control-test fixtures can be imported only through the REST API (#40). The full feature list is in [FEATURE_STATUS.md](FEATURE_STATUS.md).

- No Enterprise Security output mode. The Platform card says behaviour with ES installed is unvalidated (no ES lab).
- Not validated on Splunk Cloud or on a search head cluster. This guide covers a single Splunk Enterprise instance.
- Not a CMMC status tool and not a certification tool. Scores and notes are information only.
- Searches are advice, not proof. Readiness says what could be checked. A deployed search can run and return nothing.
- Inventory is not per user: discovery runs under the app's system session.
- Email and webhook alert actions, SP 800-171 Rev. 3 objective results, a Blocked use case, side-effect refusals, a real bundle import and a KV Store outage were not verified.
- Remote sync was run once, for categories 1 and 9. Other categories were not imported.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

---

## Appendix: demo walkthrough
<a id="appendix-demo-walkthrough"></a>

This reproduces the screenshots. Use a test Splunk, not a production one.

1. Install the app and load content (categories 1 and 9).
2. Create indexes `os`, `sun_demo` and `ucm_controltest`.
3. Create users `sunguide_viewer`, `sunguide_analyst`, `sunguide_content`, `sunguide_operator`, `sunguide_operator2`, `sunguide_assessor`, `sunguide_scheduler`, `sunguide_admin` with the roles in the [roles table](#what-sunavigator-is). Give each a random password and keep the passwords out of git.
4. Set `[deployment] scheduled_owner = sunguide_scheduler` in `local/ucm.conf`, then reload.
5. Generate data with [`docs/user-guide-assets/sun_demo_generator.py`](user-guide-assets/sun_demo_generator.py): `base` writes linux_secure, cpu, vmstat, a stale df source, Windows security events (source `demo:winsec`), auditd and syslog; `burst` sends 30 failed SSH logins from the documentation address 203.0.113.50.
6. Run discovery and re-assess all.
7. Follow the deploy task with UC-1.1.8 (SSH brute force) and UC-1.1.9 (denied sudo).

Cleanup on the test Splunk, when you are done:

- Delete the users `sunguide_*` and the temporary roles you created (Settings, Users and Settings, Roles).
- Disable and delete the saved searches named `SUN - ...` that the walkthrough deployed (retire them in the app first).
- Delete the indexes `sun_demo` and `ucm_controltest`, and the index `os` if you created it only for this walkthrough. Deleting an index deletes its data.
- Remove the line `scheduled_owner` from `local/ucm.conf` and reload.

Verified on: SUNavigator 0.11.0, Splunk Enterprise 10.4.3, 2026-11-25

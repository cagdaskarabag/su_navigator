# SUNavigator 0.11.0: feature status

**Beta.** Release: [v0.11.0](https://github.com/cagdaskarabag/su_navigator/releases/tag/v0.11.0), build 23. The code is frozen for this beta; the open work is in [ROADMAP.md](ROADMAP.md).
Validated on Splunk Enterprise 10.2.9, single instance. Splunk Cloud, search head clusters with a deployer, and
Splunk Enterprise Security 8 are **not validated and not planned** (D-078).

A full walkthrough of every page, by role, was also run on Splunk Enterprise 10.4.3 (macOS, arm64) and is written up in
[USER_GUIDE.md](USER_GUIDE.md). It worked, with the small defects below. The live test suite has not been run on 10.4.x (issue #42).

This page is the feature list for feedback. Each item links to the decision record (`docs/DECISIONS.md`), the
operator guide (`docs/OPERATOR_GUIDE.md`) or an issue. Every "working" line was checked on the lab, and every
"not working" line is a limit the project already knows about. Feedback on either kind is welcome.

Legend: **Working** = built and checked on the lab. **Built, limited** = works, with a limit that matters to some users.
**Not working / not built** = missing or known to be wrong. **Nice to have** = backlog, not promised.

## Working

| Area | What works | Reference |
|---|---|---|
| Content | Sync of the Fenre catalogue from GitHub (pinned ref), offline bundle import, ESCU bundle import | §5 |
| Catalogue | Search, multi-select facets with counts, criticality, difficulty, MITRE, provider, wave, maturity, data source, quality flags, bookmarks, availability filter | D-059, D-066, D-074 |
| Use-case page | Description, SPL, requirements, readiness card, MITRE and regulation mapping, provider and twin links | §6.2 |
| SPL lint | Five rules, each shown wrong on Splunk 10.2.9; advice only, changes no gate | D-065, §6.2b |
| Interactive search | Runs the SPL in the browser with the user's own rights; refuses commands it cannot show | D-058, §6.2a |
| Discovery | Indexes, sourcetypes, apps, data models; populated check for data models | §6.3, D-063 |
| Readiness | Deterministic requirement checks, states and score, evidence list, staleness, scheduler access check | §6.4, D-069 to D-070 |
| Backlog and recommendations | Per-user selections, recommended next, exclusions | §6.5 |
| Deployment | Draft, validate, submit, approve, deploy as a disabled saved search, enable, disable, rollback, retire | §6.6, D-051 |
| Four-eyes | Submitter cannot approve by default; enable can need a second person; overrides expire | D-075, §6.6 |
| Drift | Edits to a deployed search in Splunk are detected by Verify; the app does not repair them | §4, D-051 |
| Control tests | A fixture is replayed through a deployed search on a test index; verdicts pass, fail, content error, not runnable | §6.6a, D-054, D-064 |
| Coverage | MITRE ATT&CK matrix and regulatory coverage with gap lists | §6.7, D-074 |
| Control catalogues | NIST SP 800-53 Rev. 5.2.0, SP 800-171 Rev. 3, CSF 2.0; unmapped controls visible | D-076 |
| Assessments | Status per control with who, when and why; per-objective results for SP 800-171 Rev. 3; history | D-077 |
| CMMC Level 2 score | DoD methodology v1.2.1 scoring (110 at best, -203 at worst), best possible score | D-077 |
| POA&M | Plan items with owner, due date, milestones, closing and risk acceptance; overdue flag | D-077 |
| POA&M eligibility note | Information only, from 32 CFR 170.21; never blocks an item or changes a score | D-080 |
| Evidence snapshots | Frozen assessment with SHA-256; download checks the hash | D-077 |
| Audit trail | Hash-chained audit rows; "Verify audit chain" reports edited or missing rows | D-075 |
| Refused requests | Refused governance requests are recorded under rate limits; listed on Content administration | D-080 |
| Dashboards | Domain dashboards and generated dashboards, create, regenerate, delete | §6.8 |
| Roles | Viewer, analyst, content manager, deployment operator, assessor, scheduler, admin; denied actions return 403 | §4 |
| Packaging | AppInspect `cloud` tag: 0 errors, 0 failures (4 warnings) | D-019 |
| Tests | 1074 unit tests and Node tests of the browser code; lab live suite 78 tests OK, 2 skipped | `docs/IMPLEMENTATION_PLAN.md` |

## Built, limited

| Area | Limit | Reference |
|---|---|---|
| Browser search guard | Refuses commands it does not know, but is a convenience in front of Splunk's role checks, not a security boundary | D-080, `docs/SECURITY.md` |
| Scheduler access | Checks index access only: not search filters, time limits, quotas, macros, data models, or `index=*`; those are shown as not verified | §12, D-063 |
| Scheduler role changes | Stored readiness is not marked stale when the role changes; press Assess | §12, issue #17 |
| Counts | Catalogue total stops at the KV Store row limit (50,000); readiness, inventory and coverage counts are not marked when they reach it | §12, issues #14, #24 |
| Reindex | Synchronous; blocks one REST call | §12, issue #25 |
| Facets | Facet values containing a comma are lost; values are capped at 600 stored | §12, issue #26 |
| Control tests | Cannot scope searches that filter on `source=` (8 Fenre searches); a pass on an empty `timechart` can be weak | §6.6a, issues #21, #22 |
| Control tests and Fenre | 12 Fenre searches use `match()` as a search term and never match; reported in `docs/upstream/for-fenre-owner/` | D-072, D-080 |
| Fenre content | 153 SPL lint findings in 141 searches of Fenre `0e21f019`; the app does not file them upstream | `docs/upstream/for-fenre-owner/` |
| Email and webhook actions | Built in 0.9.5, covered by tests; check the live behaviour in your own environment before relying on it | D-072, issue #28 (closed) |
| Recommendations | Ordering heuristic with uncalibrated starting weights | §12 |
| Free-text search | Substring match over a precomputed field; first 1,500 characters of the description | §12 |
| Readiness and data | A data model counts as met when installed; `populated` is a snapshot; fields and acceleration are not checked | §6.4, issue #31 |
| Internal indexes | Requirements on internal indexes stay unverified unless `[discovery] include_internal = true` | issue #19 |
| Browser tests | Node logic tests exist; Splunk Web is checked by hand | issue #15 |
| Install | Splunk Web upload can time out; use the CLI install | §3.2 |

## Known small defects

Found while writing the user guide. None changes data or exposes anything; all are wording or layout.

| Item | Reference |
|---|---|
| A refused **Check provider for categories** says "The provider could not be reached" | issue #34 |
| The audit-chain refusal names only `ucm_admin`, though `ucm_manage_content` also may verify | issue #35 |
| Buttons are shown to roles that cannot use them (the server refuses them) | issue #36 |
| The Platform card shows kvstore as unknown to roles that cannot read it | issue #37 |
| The enable note ("blocked while readiness is blocked") appears on every use case | issue #38 |
| Deleting a local source mapping has no confirmation | issue #39 |
| **Run search** stays disabled after a search returns zero rows. Workaround: Cancel | issue #43 |
| The POA&M banner says the threshold is met when the system security plan is missing (the value `can_pass` is correct) | issue #45 |
| The product name contains a Splunk trademark in app metadata and the export header (docs and README are fixed) | issue #44 |
| Refusal audit limits (20 per user and 200 per instance per hour) are not in the security review checklist | issue #46 |
| **Verify** does not report edits to the alert trigger (threshold, tracking, severity) or the email message | issue #48 |
| Outbound HTTP follows redirects without re-checking the host allowlist and forwards the provider token | issue #49 |
| Control-test scoping: a subsearch or append clause without an index runs on the default indexes | issue #50 |
| One use case's control-test fixture fails (UC-1.1.8); it is a known content finding in the Fenre corpus | `docs/upstream/FENRE_FINDINGS.md`, F-02 |
| Unconfirmed: Splunk Web and the management API stopped answering for about six minutes during a discovery run on 10.4.3; cause unknown | issue #41 |

## Not working / not built

| Item | Why | Reference |
|---|---|---|
| Splunk Cloud | No lab. Not validated and not planned | D-078, issue #3 (closed) |
| Search head cluster with a deployer and indexer peers | No lab. Not validated and not planned | D-078, issue #2 (closed) |
| Enterprise Security 8 output (findings, risk) | Not implemented; ES-installed behaviour is mocked only | D-078, issues #4, #27 (closed) |
| CMMC conditional status | Not built: no status, no 180-day clock, no closeout record | D-079, D-080 |
| Assessment objectives for SP 800-53 and CMMC | No verified machine-readable source in the pinned content | D-079 |
| Signed snapshots | Needs a key custody and rotation decision | D-079 |
| Deleting snapshots | Left out on purpose so evidence cannot be removed from the app | D-079 |
| CIM field reference and field-level checks | Needs `Splunk_SA_CIM` on a lab | issue #31 |
| Add Macro button | Decided: a help section instead | D-072, issue #10 (closed) |

## Nice to have (backlog, not promised)

| Item | Why it matters | Reference |
|---|---|---|
| How-to help inside the app (the user guide exists; the in-app panels do not) | New users have to leave Splunk to learn the pages | [IN_APP_HELP_PLAN.md](IN_APP_HELP_PLAN.md) |
| Import control for control-test fixtures on Administration (REST only today) | People without REST access | issue #40 |
| Run the live suite on Splunk 10.4.x | Confirms the walkthrough result | issue #42 |
| Browser tests for the UI | Catch Splunk Web regressions automatically | issue #15 |
| Re-assess readiness when scheduler roles change | Stale results after a role change | issue #17 |
| Say whether an internal index has data, without a full scan | Better internal-index results | issue #19 |
| Counts beyond the KV bound, paged join scan | Large catalogues | issue #24 |
| Background Reindex | Large catalogues | issue #25 |
| Facet values with commas | Some provider facet names | issue #26 |
| More SPL lint rules, only with lab evidence | Catch more broken Fenre searches | issue #29 |
| Re-run the 94 control-test fixtures with add-ons | Skipped for now (D-079); issue #23 is to be closed as not planned | D-079 |

## What we want feedback on

- Which pages you used, and which you could not work out without help.
- Whether the deployment and approval flow matches how your team works.
- Whether the readiness result matches what you know about your data.
- Whether the compliance pages (coverage, control catalogues, assessments, POA&M) answer a question you have.
- Anything in the "Not working" or "Nice to have" lists that blocks you.

Use the **SUNavigator feedback** issue form. Include the SUNavigator version, your Splunk version and the role you
used. Do not include real index names, host names, IP addresses, user names, or data.

# Final report: Sprints 13 to 21 (0.9.2 to 0.11.0)

*Status at 0.11.0, build 23, 2026-11-25. Everything below was checked against `main` and the lab results
recorded in `docs/IMPLEMENTATION_PLAN.md`.*

## 1. State of the repository

| Item | State |
|---|---|
| `main` | version 0.11.0, build 23 (`app.conf` and `app.manifest` agree); every remote feature branch is merged |
| Unit tests | 1074 passed (mocked, plus Node tests of the browser modules) |
| Lab live suite | 78 tests OK, 2 skipped, Splunk Enterprise 10.2.9, single instance |
| AppInspect (`cloud` tag, precert) | 0 errors, 0 failures, 4 warnings |
| Release tag | `v0.11.0` (`v0.10.0` before it; earlier tags stop at `v0.7.3`, and `0.8.0` to `0.9.9` were not tagged) |
| Licence | Apache License 2.0 for SUNavigator's own code, content and documentation (D-071); third-party notices in `THIRD_PARTY_NOTICES.md` |

The README version badge showed `0.9.x` after the 0.10.0 release because it was a hand-written static badge that no
test looked at. It now follows the app version (`0.11.x`), and `tests/unit/test_release_consistency.py` fails when the badge and
`app.conf` disagree on major and minor version.

## 2. What was delivered

One row per release; the decision record has the reasoning, the operator guide (`What changed in 0.9.x to 0.11`)
has the instructions. The same table is in `docs/IMPLEMENTATION_PLAN.md` (WP9).

| Version | Delivered | Record |
|---|---|---|
| 0.9.2 | SPL guard classifies the first word of a bracket, scheduler role cannot write, acceleration read from the listing | D-068 |
| 0.9.3 | Dispatch failures in run status, health advisories, schedule advice, cron jitter | D-069 |
| 0.9.4 | Data seen state, 30-day freshness, environment health, summary check, field profile; Apache-2.0 | D-070, D-071 |
| 0.9.5 | Owner decisions: empty model is partial, macro help, email and webhook actions, Fenre findings in the repository | D-072 |
| 0.9.6 | ESCU depth: `security_content` enrichment, event-level data check, deprecated flag | D-073 |
| 0.9.7 | Detections already running, graded coverage and gap lists, data maturity facet | D-074 |
| 0.9.8 | Audit hash chain with verification, withdraw approval, second-person enable, override expiry, outcomes | D-075 |
| 0.9.9 | NIST SP 800-53 Rev. 5.2.0, SP 800-171 Rev. 3 and CSF 2.0 catalogues; unmapped controls visible | D-076 |
| 0.10.0 | Assessed state, assessment objectives, CMMC Level 2 score, POA&M, evidence snapshots | D-077 |
| 0.11.0 | Stabilisation: fail-closed browser guard, access gap and override second look, audited refusals, POA&M eligibility note, upgrade notice | D-080 |

## 2a. Sprint 21 in short (0.11.0, D-080)

An independent review of 0.10.0 raised seven points. Six were fixed and one is a hand-over: the browser guard fails
closed (parity test with the server lists), the scheduler access gap is shown at submit and approval, overriding a gate
needs a second person by default, refused governance requests are audited under rate limits, POA&M items carry an
informational 32 CFR 170.21 note, and an upgrade notice and the `all_assessed`/`can_pass` score fields were added. The
review's remark about Fenre's SPL is a report for the owner to send (`docs/upstream/for-fenre-owner/`), not a filing.
The live suite found one defect in the new code (refusal rows hid the specific reason of a conflict, so two different
refusals were treated as one); it is fixed and tested. A human review of the security paths before 1.0 is the owner's.

## 3. What was not done, and why

| Item | Why | Where it stands |
|---|---|---|
| CMMC conditional status and POA&M eligibility (32 CFR 170) | It is a legal-weight certification claim. The app records coverage and assessments, not certification, and a status would carry legal weight. The eCFR text of 170.21 was read for 0.11.0 and an informational eligibility note on POA&M items was built from it (D-080); the conditional status, the 180-day clock and the closeout record were not. | Status left as is; not planned (D-079). Eligibility note: built, D-080 |
| Assessment objectives for SP 800-53 and CMMC | The pinned NIST OSCAL content carries objectives only for SP 800-171 Rev. 3. The 800-53A and 800-171A Rev. 2 objectives exist as PDF and spreadsheet; transcribing them by hand risks errors in compliance data. | Left as is; not planned (D-079) |
| Signing snapshots | Needs a decision on key custody and rotation; Splunk has no key store for it. The SHA-256 of each snapshot, recorded outside Splunk, covers part of the need. | Left as is; not planned (D-079) |
| Deleting snapshots | Left out on purpose, so evidence cannot be removed from the app. Retention would need an export-then-delete design. | Left as is; not planned (D-079) |
| CIM field reference, field presence, acceleration freshness | Needs a lab with `Splunk_SA_CIM` and a populated, accelerated model; the lab has neither. | Issue #31, unscheduled backlog |
| Re-run of the 94 control-test fixtures with add-ons | The fixtures name add-ons the lab does not have (see section 5). | Skipped (D-079); issue #23 is still to be closed as not planned |
| Splunk Cloud, SHC with a deployer, ES 8 | No lab, and none will be provided (D-078). | Dropped; issues #2, #3, #4, #18, #27 (closed) |

## 4. GitHub issues

Closed and verified closed as completed: #5, #6, #7, #8, #9, #10, #11, #12, #13, #14, #28. Their closing
notes are in `docs/ISSUES_PENDING.md` (the integration that wrote this code can read issues and create them, but
cannot comment on, edit or close them).

Closed by the owner as not planned: #2, #3, #4, #18, #27 (D-078). Closed as invalid: #30 (a stray test issue created while probing the integration). #16 (tracking) is closed; #33 replaces it. Still to close as not planned: #23 (D-079).

Open and kept:

| Issue | What it is | Next step |
|---|---|---|
| #15 | Browser tests | Owner decision: Node logic tests exist, Splunk Web is checked by hand |
| #32 | Human review of the security paths before 1.0 | Owner task, after the sprints |
| #33 | Status and roadmap at 0.11.0 | Tracking; replaces #16 |
| #17 | Mark readiness stale when scheduler roles change | Backlog |
| #19 | Say whether an internal index has data without scanning it | Backlog |
| #20 | Fenre findings F-01 to F-11 | Owner decision: not filed by the app (D-072); the report for the owner to send is in `docs/upstream/for-fenre-owner/`; close once it is handed over |
| #21 | Control tests: `source=` searches | Owner decision |
| #22 | Control tests: empty `timechart` buckets passing | Backlog |
| #24 | Counts bounded by `max_rows_per_query` | Backlog |
| #25 | Reindex as a background job | Backlog |
| #26 | Facet values containing a comma | Owner decision |
| #29 | Extend the SPL lint only with rules shown wrong on a real Splunk | Backlog |
| #31 | CIM field reference and field-level checks (remainder of #13) | Unscheduled; needs `Splunk_SA_CIM` on a lab |

## 5. What the lab would need for #31 (and #23, which is skipped)

The lab has only the ES Content Update app. The add-ons are free Splunkbase downloads; they must not be added to
this repository. Of the 94 fixtures, 61 use `citrix:*` sourcetypes, 10 use `WinEventLog`, 3 `uberAgent:*` and 2
`aws:cloudtrail`; the other 18 are a mix of `cpu`, `linux_secure`, `snort:alert`, `iis`, `azure:consume:export`,
`github:webhook`, `splunkd` and fixtures without a sourcetype. The campaign already names `Splunk_TA_nix`, `Splunk_TA_windows` and
`Splunk_TA_paloalto` as missing.

| Step | Add-ons | Unlocks |
|---|---|---|
| 1 | `Splunk_SA_CIM` (Splunk Common Information Model) | #31 and the CIM parts of #23 |
| 2 | `Splunk_TA_windows`, `Splunk_TA_nix` | `WinEventLog`, `cpu` and `linux_secure` fixtures; tagged data for #31 |
| 3 | `Splunk_TA_aws`, `Splunk_TA_paloalto` | `aws:cloudtrail`, `pan:threat` fixtures |
| 4 | The Citrix add-ons for the `citrix:*` sourcetypes | 61 fixtures; names to be confirmed per fixture |

Steps 1 and 2 would be enough to start #31. #23 is skipped (D-079); steps 3 and 4 only matter for it.

## 6. Platforms not validated

Splunk Cloud, a search head cluster with a deployer and indexer peers, and Splunk Enterprise Security 8 are not
validated and not planned (D-078). The README support statement and operator guide §12 say so.

## 7. After the release

- A walkthrough of every page, by role, was run on Splunk Enterprise 10.4.3 (macOS) by a second operator and is published as [USER_GUIDE.md](USER_GUIDE.md) with 94 screenshots. Product names that are not part of this project were removed from three of them.
- It found small wording and layout defects (issues #34 to #41) and one unexplained outage of Splunk Web (#41, unconfirmed). Nothing changed data. None is scheduled; the feature list is [FEATURE_STATUS.md](FEATURE_STATUS.md).
- The app is not being changed until feedback has been collected. The next release adds how-to help inside the app: [IN_APP_HELP_PLAN.md](IN_APP_HELP_PLAN.md).
- Beta review (26 Nov 2026): the code is frozen for this beta. Open work, in priority order, is in [ROADMAP.md](ROADMAP.md): zero-row Run search (#43), the trademark in the product name (#44), the POA&M banner (#45), the security review (#32, #46) and the repository settings in #47.

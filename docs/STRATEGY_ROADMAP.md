# Strategy roadmap: focus on the detection-readiness and governance wedge

Status: proposal of 28 Nov 2026 for the maintainer's decision. Nothing here is built. It does not replace
[ROADMAP.md](ROADMAP.md), which holds the issue-level backlog; this document decides what the backlog is *for*.
Phases are ordered by dependency and decision gates, not by dates.

Inputs: an external product and architecture review of 0.12.1 (Antigravity, 28 Nov 2026), the decisions log
(D-065 to D-083) and a check of the review's claims against the code (section 1).

## 0. The wedge

> **Before a detection runs: is the data there, can the scheduler read it, does the search work on sample events,
> and who approved it. After it runs: has it drifted.**

Everything on this list is the product: content intake (ESCU, Fenre, offline bundles), discovery, readiness, SPL
validation, disabled-first deployment with four-eyes approval, drift verification, control tests, and the ATT&CK
view of what is covered. Everything else is a candidate to freeze, hide or extract.

Two calls where I differ from the review:

* **Control tests (replay testing) stay.** They are the "does it work on sample events" step, which the review's own
  value proposition depends on. The review lists replay testing as bloat and, a page later, as differentiation.
* **ATT&CK and control mapping stay as a lens on detections.** What goes is recording assessments, scoring
  CMMC/800-171, tracking POA&M items and keeping evidence snapshots.

## 1. What the review got right, what it got wrong, what is unverified

Checked against `main` at `65d00a9` on 28 Nov 2026.

| Claim | Verdict | Evidence and consequence |
|---|---|---|
| Six collections have no `default.meta` stanza and inherit `read : [ * ]` (`uc_assessments`, `uc_poam`, `uc_assessment_snapshots`, `uc_field_profile`, `uc_event_check`, `uc_external_matches`) | **True. Fixed in 0.12.2.** | `[]` in `default.meta` grants read to everyone; 14 of 20 collections have their own stanza. Any signed-in user can read assessment and POA&M records through the KV Store REST API, past the `ucm_assess` gate in `api/app.py`. Medium severity. Fixed with a stanza each and a test that every collection in `collections.conf` has one; measured live (a viewer, analyst or assessor gets 404 from the KV REST, the API still answers). |
| `[role_ucm_scheduler]` ships `srchIndexesAllowed = *` | **True, and a decision (S3: keep, name it). Done in 0.12.2.** | It is the account that runs deployed searches, so it needs index reach; readiness already checks it (`readiness/principal.py`) and refuses blind runs. Decide: keep `*` and say so in the install checklist, or ship narrow and let the readiness check force a grant. The install checklist (operator guide 3.5a) and the scheduler card now say so. |
| `app.manifest` says `developmentStatus: Alpha` | **True. Fixed in 0.12.2** (Beta). | One line. |
| `web.conf` `ucm/*` GET, POST makes the narrower `expose` stanzas pointless | **False (probed live on 10.2.9, 28 Nov 2026).** | A GET through Splunk Web to the POST-only `ucm/poam/update` returns Splunk Web's own 405 page and never reaches the handler, so the narrow `expose` stanzas are enforced. The review's inference came from reading `ucm/*` alone. No change. |
| Scope creep into GRC | **True, smaller in code than in claims.** | `frameworks/` is 1,675 of 17,947 Python lines (9%), `ucm_coverage.js` 907 of 5,571 JS lines (16%), `dashboards/` 253 lines. The cost is not size: it is claim surface (CMMC scoring, POA&M, "evidence"), the legal weight D-077 already tried to disclaim, a role, three collections, and a share of the operator guide. Pruning removes risk and reading load, not half the product. |
| Splunk Cloud, SHC deployer and ES are unvalidated | **True, and deliberate.** | D-078 dropped them because there is no lab, not because they were overlooked. Building labs is not available to a single maintainer. The realistic route is the handover to the Splunk team, who have them: section 3, phase 4. |
| `api/app.py` is a 1,086-line router; large vanilla-JS files | **True.** | Worth doing after pruning, which deletes some of that code first. |
| Non-atomic KV writes can branch the audit chain | **Known.** | Documented in `SECURITY.md`; 0.12.0 added the save token and `audit/verify` lists branches. KV Store has no compare-and-swap, so this stays a documented limit. |
| Reindex is synchronous | **Known. Done in 0.12.2.** | #25: the page queues a worker job and polls. |
| 10.4.3 stall during discovery | **Known, not reproduced.** | #41. The 27 Nov live run on 10.4.3 did not show it. |

## 2. Principles for the next releases

1. **Hide before deleting.** The beta exists to learn which parts people use (ROADMAP.md). Pruning on opinion
   throws that away. Put the compliance pages behind a setting, default off, look at use, then extract or retire.
2. **Measure, do not guess.** Add a usage census: a script that counts audit rows by module on one instance and
   prints counts only (no users, no content). Peers run it and paste the output.
3. **No new compliance features, no new frameworks, no new scoring.** Corrections to what exists are fine.
4. **A claim needs a lab.** Anything the app says works on ES, SHC or Splunk Cloud must have been run there.
   Until then the docs say "not validated", as they do now.
5. **Legal gate before distribution.** Nothing derived from ESCU or SSE is published or bundled until the
   analysis in [LEGAL_COMPLIANCE_ANALYSIS.md](LEGAL_COMPLIANCE_ANALYSIS.md) has an answer for that use.

### 2.1 Decisions needed from the maintainer

| # | Decision | Recommendation |
|---|---|---|
| S1 | Does the compliance suite (assessments, POA&M, snapshots, CMMC score) stay in this app? | Hide behind `[features] compliance = false` in 0.13, run the census, then extract to a separate app or retire. Do not delete yet. |
| S2 | Dashboard generation | Freeze (253 lines, no maintenance cost). Decide with the census. |
| S3 | Scheduler default `*` | Keep, but make the install checklist and the first-run banner name it, and keep the readiness refusal. Shipping narrow breaks every first deployment for the sake of a default an administrator has to review anyway. |
| S4 | What to hand the Splunk team | The app plus a dossier (phase 4): what is validated, what is not, an acceptance test per topology. |
| S5 | Who may use the SSE content | Nobody until the legal analysis answers. SSE is not touched by any code today. |

## 3. Phases

### Phase 0: decide, no code (now)

* Record S1 to S5 as decisions (D-084 when the first of them is built).
* Start the legal analysis (workstream L, below). It does not block the beta, because the app ships no ESCU or SSE
  content, but it blocks phases 4 and 5 and any public bundle.
* Ask the Splunk team, informally, which of ES, SHC with deployer and Splunk Cloud they can test on and what they
  would accept as an acceptance test. That answer decides how much of phase 4 is ours.

### Phase 1: 0.12.2, the confirmed rough edges (small, one release)

* `default.meta` stanzas for the six collections, readable only by the roles that already read them through the API;
  a unit test that fails if a collection has no stanza.
* Live probe of the `web.conf` method question; narrow `ucm/*` or delete the redundant stanzas, whichever the
  result says.
* `developmentStatus` to Beta.
* Scheduler default: the S3 outcome, documented in the install checklist.
* Background Reindex (#25), so the one synchronous long call goes away.
* Try to reproduce #41 on 10.4.3 with discovery running under load; if it does not reproduce, close it with the
  evidence.
* Usage census script (`tools/usage_census.py`), counts only.

### Phase 2: 0.13, prune to the wedge

*Status: built in 0.13.0 (D-085): the flag, the server refusal, the UI hiding, the front-page wording. Dashboards stay as they are (S2, frozen). The gate below is the maintainer's.*

* `[features] compliance` (default off): hides the assessment, POA&M and snapshot pages and their routes (the server
  must refuse them too, not only the UI), and the `ucm_compliance_assessor` role stays defined but inert.
  ATT&CK coverage and control mapping stay on.
* Dashboards: frozen, hidden with the same switch unless the census shows use.
* Remove marketing and README claims about CMMC and POA&M from the front page; keep the detail in the guide with the
  existing "not an audit" wording.
* Gate: run the census on the peers' instances. If nobody used the compliance pages, extract them (phase 2b). If
  people did, extract anyway but keep the data export so they can move.

### Phase 2b: extraction (after the gate)

* Move `frameworks/assessment*`, `poam*`, `evidence*`, their pages, routes, collections and role into a separate
  optional app that talks to this one only through its REST API (mappings and readiness read-only). Stop
  shipping the NIST and CMMC data files in the core app (about 245 KB of the control catalogues); keep the ATT&CK
  file.
* Core keeps: catalogue, discovery, readiness, validation, deployment, drift, control tests, ATT&CK view.

### Phase 3: make the core easy to hand over

* Split `api/app.py` into domain routers (catalogue, discovery, deployment, admin) with the same route table;
  `test_every_route_is_reachable_through_splunk_web` is the safety net.
* Split `ucm_usecase.js` along the page's cards (requirements, validation, deployment, control test), no framework
  change. Role-aware controls (#36) belong here.
* Human review of the security paths (#32) on the pruned code.

### Phase 4: the enterprise paths

Splunk Enterprise on one instance is validated. The three the review names are not. What can be done without a lab:
write down what the app does today in each, and make the acceptance test portable.

| Topology | Today | What this phase produces |
|---|---|---|
| ESCU without ES | Validated (D-067): reads ESCU state, hands off, never writes in ES or ESCU. | Nothing to add. |
| Enterprise Security | Not validated. | A design note: what an ES-aware deployment would write (correlation search stanza, notable and risk actions) and what SUN must refuse to touch; a test plan for the Splunk team. |
| SHC with deployer | Validated on a three-member cluster without deployer (D-055). | The deployer path on paper: where `local/` writes go, what the deployer pushes, which of our writes survive a push; a test plan. |
| Splunk Cloud | Not validated. | A gap list against Cloud constraints (no file access, vetting, ACS install, `[expose]` and role handling), AppInspect `cloud` tag already runs in CI. |

Deliverable: `docs/HANDOVER_DOSSIER.md` with the validated matrix and the live suite as the acceptance test
(`tests/live`), with markers so each topology's tests can be selected.

### Phase 5: only if the Splunk team adopts it

* UI modernisation (Dashboard Studio or `@splunk/react-ui`). Not before: it is the largest change with the least
  evidence that users need it.

## 4. Workstream L: legal and compliance analysis

Runs in parallel from phase 0. Detail, the verified facts and the open questions are in
[LEGAL_COMPLIANCE_ANALYSIS.md](LEGAL_COMPLIANCE_ANALYSIS.md). The shape:

| Step | Output | Blocks |
|---|---|---|
| L1 Inbound licence inventory (done as a first pass, needs counsel's check) | Table of every third-party source, its licence and how SUN uses it | L2 |
| L2 Usage-mode analysis for ESCU and SSE: read at run time, store a local copy, transform, bundle, redistribute | A yes, no or ask-Splunk per mode | Any public bundle, Splunkbase listing |
| L3 Splunk General Terms and developer-licence question (clause on software that interoperates with an Offering) | Written answer from counsel or the Splunk team | Public distribution beyond peers, handover terms |
| L4 Ownership and employment | Whether the maintainer may assign or license the work, under which terms, before handing it to Splunk | The handover |
| L5 Claims and marking | Wording review of compliance claims, trademarks, the not-endorsed notice | Public announcement |
| L6 Data protection | A one-page data map (what is stored, where, outbound calls) | Splunkbase listing |

## 5. What I recommend doing first

1. Phase 1 as release 0.12.2, because the KV ACL finding is real and cheap.
2. The usage census in the same release, so phase 2 has data.
3. The legal analysis in parallel; its first outputs (L1, L2 for ESCU) need only reading, not building.
4. Ask the Splunk team the lab question (phase 0). If they say yes, phase 4 shrinks to the dossier.

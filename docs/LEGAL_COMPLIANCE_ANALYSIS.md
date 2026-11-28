# Legal and compliance analysis: using ESCU, SSE and other third-party content

Status: first pass of 28 Nov 2026. **This is a work plan and a record of facts checked against primary sources. It
is not legal advice and it reaches no legal conclusion.** Where a question needs a lawyer or the licensor, it is
listed in section 6 and marked as open. Nothing in the app changes because of this document.

Purpose: before SUNavigator is listed publicly, ships a prebuilt content bundle, or is handed to the Splunk team, the
maintainer needs to know what it may do with Splunk's detection content (ES Content Update, Splunk Security
Essentials) and with the other third-party material it contains or reads. Strategy context:
[STRATEGY_ROADMAP.md](STRATEGY_ROADMAP.md), workstream L.

## 1. How the app uses third-party material today

| Mode | What it means | ESCU | SSE | Others |
|---|---|---|---|---|
| **A. Run time read** | The app reads content the operator already has installed, through the Splunk REST API, with the system token | Yes: saved searches and state of `DA-ESS-ContentUpdate` (D-067), for the hand-off view and external matching | **No** | CIM data model definitions (read for the populated check) |
| **B. Local copy** | The app stores a normalised copy in its own KV Store on the operator's instance | Yes, when the operator imports an ESCU bundle (`uc_content`, `uc_catalog`) | No | Fenre records; ATT&CK |
| **C. Bundle build** | `tools/ucm_cli.py build-escu-bundle` reads an ESCU package on the operator's machine and writes a `ucm-content-bundle` JSON | Yes, by the operator on their own machine | No | n/a |
| **D. Ship in the repository or package** | The app's own package or repository contains the material | **No ESCU content.** The fixtures in `tests/fixtures/escu/` are written for SUNavigator (`THIRD_PARTY_NOTICES.md` section 2) | **No** | Fenre schema (MIT) and sample records, ATT&CK data, NIST control catalogues, CMMC mapping |
| **E. Redistribute a built bundle** | Someone hands a bundle built in C to a third party, or SUN publishes one | Not done by the project; possible by users | No | n/a |

Two facts follow from the code and are worth stating plainly:

* In every mode the ESCU detections come from a package the operator already holds. The project itself distributes
  none (mode D) and publishes no bundle (mode E).
* SSE is not read, stored, bundled or shipped by any code. It appears only as a "UX reference" in
  `docs/PROJECT_DISCOVERY.md`. So the SSE question is about a **future** decision, not about something to repair.

## 2. Facts checked against primary sources (28 Nov 2026)

| Fact | Source | Result |
|---|---|---|
| The `splunk/security_content` repository is licensed under Apache-2.0 | `LICENSE` and README "License" section on GitHub, `develop` branch | Apache License 2.0 |
| The Splunkbase listing for **Splunk ES Content Update** (app 3449) states its licence | Splunkbase API `license_name`, `license_url` | Apache License Version 2.0 |
| The installed package `DA-ESS-ContentUpdate` 6.11.1 carries a licence file | Inspection of the package on the lab (`README/`, `default/`, `lookups/`, `static/`, `metadata/`) | **No LICENSE or NOTICE file in the package.** The licence rests on the Splunkbase listing and the GitHub repository. |
| The Splunkbase listing for **Splunk Security Essentials** (app 3435) states its licence | Splunkbase API | **Splunk General Terms** (not an open-source licence) |
| The Splunkbase listing for **Splunk Common Information Model** (app 1621) | Splunkbase API | Splunk General Terms |
| SSE source is public on GitHub | `github.com/splunk/security-essentials` | **404.** There is no public SSE repository under that name. |
| Splunk General Terms restrict use of an "Offering" | Text of the public terms page, section 1 "Your Use Rights and Limits" and section 13 | Excerpts in 3.3. The version read is the one served on 28 Nov 2026; the effective date was not captured. |

The ESCU result is clean: the licence is stated by the licensor in two places and matches what `NOTICE` and
`THIRD_PARTY_NOTICES.md` already say. The SSE and CIM result is different in kind: they are covered by Splunk's
commercial terms, which are not open-source licences and do not grant copying or redistribution rights by themselves.

## 3. Analysis by source

### 3.1 ESCU (Apache-2.0)

What the licence generally allows, subject to its conditions: use, copy, modify, distribute and sublicense, including
in a derived work, and a patent grant from the contributor. The conditions a bundle redistributor has to meet are the
ones in section 4 of the licence: give recipients a copy of the licence; keep copyright, patent, trademark and
attribution notices; state prominently that files were changed; carry over a `NOTICE` if the work has one. The licence
grants no trademark rights.

Where this touches SUN:

| Question | Why it matters | Status |
|---|---|---|
| Does a `ucm-content-bundle` built from ESCU carry the licence, Splunk's notices and a statement that the content was normalised? | Section 4 conditions apply to any redistribution of the bundle. **Checked: it does not.** `build_bundle` (`content/escu/package.py`) writes `format`, `provider`, `provider_version`, `source_ref`, `schema`, `categories` and `records`, with no licence text, no notice and no change statement. The only notice is in `THIRD_PARTY_NOTICES.md`, which a recipient of a bundle file does not receive. | **Gap, needs a code change** (L2a) |
| Is the ESCU package, as distributed by Splunkbase, covered by the Apache-2.0 grant including its lookups (`lookups/*.csv`)? | The listing says Apache-2.0 for the whole app; the lookups may contain data derived from other sources. | Open, ask the licensor if a lookup is ever bundled; today none is |
| Do ESCU descriptions quote third-party text (vendor advisories, CVE descriptions, blog posts) that Splunk does not own? | Apache-2.0 grants only what Splunk can grant. | Open, spot check |
| Test data (`attack_data`) | Separate repository and licence; SUN downloads none of it (`THIRD_PARTY_NOTICES.md`). | Closed as long as that stays true |
| Running ESCU content without ES | The licence of ESCU does not depend on an ES licence, but the content is written for ES. | Open, counsel's view |
| Trademarks "Splunk", "ESCU" | Nominative use only; `NOTICE` already says SUN is independent and not endorsed by Splunk. | Reviewed in L5 |

### 3.2 SSE (Splunk General Terms)

Nothing in the project uses SSE. The questions apply if someone proposes to:

1. read SSE's own content (its detection and mapping data) at run time from the operator's SSE installation,
2. copy it into SUN's KV Store (mode B), or
3. build a bundle from it (mode C) or ship anything derived from it (modes D, E).

For 2 and 3 the General Terms, not an open-source licence, define what is allowed, and the public terms say a customer
may not "modify, translate or create derivative works based on any Offering" or "resell, sublicense, rent the use of,
transfer or distribute any Offering" (section 1). Whether SSE's content counts as the "Offering", as "Documentation" or
as separately licensed content, and whether an operator's own installation licence permits a local, derived copy, is
not decided by me. **Recommendation: no SSE-derived content in any mode until the licensor answers.** Because the
maintainer intends to hand the app to the Splunk team, the simplest route is for the owner of SSE to decide, which
costs nothing in the meantime.

### 3.3 The General Terms and an app that integrates with Splunk

A separate point, easy to miss. Section 1 of the public General Terms also excludes the right to "access or use an
Offering to develop, test, troubleshoot, support, or market any software or service that competes with any Offering,
or that integrates, interoperates with, or constitutes an extension of any Offering and that you use or intend to use for
a commercial purpose". SUNavigator is an extension of Splunk Enterprise. It is released under Apache-2.0 without a
fee, so whether the clause is engaged depends on what "commercial purpose" covers, on which licence the maintainer's
Splunk instances run under, and on whether the Splunk Developer Program or an employee arrangement has other terms.
I read an excerpt from a public page; I did not review the terms that apply to the maintainer's instances. **Open:
this needs the person who knows the applicable agreement, and counsel.** It is in this document because it bears on
public distribution and on the handover.

### 3.4 The other third-party material

| Material | Licence or status | Where it is | Notes |
|---|---|---|---|
| Fenre use cases | MIT (copyright notice and licence text must accompany copies) | schema shipped in the app with licence; sample records only in `tests/` | Keep the licence file next to every copy; the repository's own `docs/upstream/` quotes Fenre SPL in findings, which is a copy and should carry the notice |
| MITRE ATT&CK | MITRE's terms of use: free use with the copyright notice and licence retained | `frameworks/data/mitre_attack_enterprise-20.1.json`, with an attribution key | Check the attribution is shown in the UI, not only in the file |
| NIST SP 800-53, 800-171, CSF, OSCAL catalogues | U.S. Government work, not subject to copyright in the United States; NIST asks for attribution | `frameworks/data/controls/` (about 245 KB) | Foreign-copyright status and the attribution request are for L1. Would leave the core app if the compliance suite is extracted (STRATEGY_ROADMAP phase 2b) |
| CMMC Level 2 mapping | DoD publication; the scoring and POA&M rules touch 32 CFR 170 | `cmmc-l2-2.0.json` (`poam_rules.py` was removed in 0.14.0) | D-077 already decided the app records coverage, not certification. A wording review is L5 |
| Splunk CIM (data models) | Splunk General Terms | read at run time for the populated check | Mode A only; nothing copied |
| Splunk, ES, ESCU, SSE, MITRE, NIST, CMMC names | Trademarks of their owners | UI and documentation | Nominative use; `NOTICE` carries the Splunk notice |

## 4. Compliance questions beyond licences

| Area | Question | Where the answer lives |
|---|---|---|
| Ownership and employment (L4) | The maintainer is employed by a company that owns Splunk. Who owns the code written outside working hours, under which agreement can it be licensed under Apache-2.0 and later handed over, and is outside work disclosed or approved? | Employer's policies and counsel; not a technical question. **Do this before the handover.** |
| Copyright holder | `NOTICE` says "the SUNavigator contributors". If anyone besides the maintainer has contributed, a contribution policy (DCO or CLA) is needed for a handover. | `git shortlog`, `CONTRIBUTING.md` |
| Compliance claims (L5) | Until 0.13.0 the app computed a CMMC score, POA&M items and evidence snapshots. 0.14.0 retired them (D-086); the records are kept. Claims about "evidence" or "compliance" carry legal weight (D-077). | Resolved mostly by STRATEGY_ROADMAP phase 2; wording review for what remains |
| Data protection (L6) | What personal data does the app hold (user names in the audit log, assessment authors), where, for how long, and what leaves the instance (outbound requests to GitHub and the provider hosts)? | A one-page data map from `docs/SECURITY.md` section on data; the app has no telemetry |
| Security disclosure | Vulnerability reporting route exists; private vulnerability reporting is a repository setting (#47). | ROADMAP.md |
| Export controls | The app contains no encryption of its own; it uses SHA-256 hashing. Counsel to confirm nothing further is needed. | L5 |
| Splunkbase listing | Splunkbase requires an app licence statement, AppInspect results and acceptance of its developer terms. | A later step; AppInspect is clean today (0 failures, 0 errors on 0.12.1) |

## 5. Work plan

| Step | Task | Output | Needs |
|---|---|---|---|
| L1 | Complete the inbound licence inventory: every file under `sunavigator/` and every dependency, with licence and origin | `THIRD_PARTY_NOTICES.md` reconciled, plus a machine-checked list in CI that fails on a new unlisted data file | Code |
| L2a | Make the ESCU bundle builder write the Apache-2.0 notice: a `license` block (name, URL, copyright holder), the source package and version, and a statement that the records were normalised by SUNavigator; the importer ignores it | The change and a unit test on the bundle header. The gap itself is verified (3.1) | Code |
| L2b | Decide the allowed modes for ESCU (A to E) in writing | A short table in this document, signed off by counsel | Counsel |
| L2c | Spot check ESCU descriptions and lookups for third-party text | A list of fields the app copies, and whether any is third-party | Code and reading |
| L3 | The General Terms question in 3.3 | A written answer | The maintainer, counsel, the Splunk team |
| L4 | Ownership and employment | A written position before the handover | The maintainer, counsel |
| L5 | Review of public wording: README, UI strings, compliance claims, trademark use | A reviewed text and a list of changes | Counsel, code for changes |
| L6 | Data map | One page in `docs/SECURITY.md` | Code |
| L7 | SSE decision | A yes, no or ask-Splunk per mode in 3.2 | The Splunk team |

What I can do without anyone else: L1, L2a, L2c, L6. What needs a person: L2b, L3, L4, L5, L7.

## 6. Questions for counsel and for the Splunk team

1. May an operator build a bundle from their licensed installation of ESCU and store a normalised copy in a
   third-party app, under Apache-2.0 alone, with no further Splunk terms?
2. If a bundle is shared, what exactly must it carry (licence, notices, a statement of changes), and does the build
   tool meet it?
3. Does the Apache-2.0 grant on the Splunkbase listing cover the whole package, lookups included?
4. For SSE (General Terms): may an app read SSE content at run time from the customer's own installation? May it keep
   a local derived copy? May anything be bundled or shipped?
5. Does section 1 of the General Terms, on software that integrates with or extends an Offering for a commercial
   purpose, apply to developing and testing an Apache-2.0 app on Splunk Enterprise, and under which licence do the
   maintainer's instances run?
6. Under which terms can the maintainer license the work and hand it to the Splunk team (ownership, employment,
   outside-activity approval, contributor agreements)?
7. Which statements in the README and the compliance pages would you ask to change before a public listing?

## 7. What changes in the project if the answers are cautious

| If the answer is | Then |
|---|---|
| ESCU modes A to C allowed, E needs notices | Keep as is; add the change notice and test (L2a) |
| ESCU bundles may not be shared | Keep building them locally only; document it |
| SSE not allowed | Nothing to remove. Record the decision so nobody adds SSE ingestion |
| SSE allowed by the Splunk team on handover | Add it as a content provider in the Splunk-owned repository, not before |
| The General Terms clause applies | Move development to a Splunk-licensed developer instance; the handover becomes the main route |
| Outside work needs approval | Get it before the handover; the repository history shows when work was done |

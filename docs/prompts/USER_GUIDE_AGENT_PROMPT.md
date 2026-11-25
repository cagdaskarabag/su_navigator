# Prompt: install SUNavigator on a local Splunk, use it, and write the user guide with screenshots

Paste everything below the line into an agent that runs on the machine where Splunk Enterprise is installed
(a local Cursor agent or similar, with shell access and a headless browser). Before you start, set the variables in
section 1 in the agent's shell, and write the deny list described in section 3 to a file outside any repository.

---

## 0. Your task in one paragraph

You are the first real user of SUNavigator 0.11.0, a Splunk app that imports a use case catalogue (Fenre), compares each
use case with the data in this Splunk, scores readiness, lets people deploy the searches as disabled saved searches under
a four-eyes approval, and tracks coverage against MITRE ATT&CK and regulatory control catalogues. Install it from the
GitHub release, use every page the way a new user would, and produce (a) a detailed user guide for people who have never
seen the app and (b) screenshots of every important screen, ready to commit to the repository. Everything you write must
be true because you did it, not because a document said so. The existing `docs/OPERATOR_GUIDE.md` is an installer and
administrator reference that may be out of date in places: use it to find your way, and report every place where the app
and the guide disagree.

When the guide is finished, the project owner will add "how to use" help inside the app (like the help pages in Splunk
Security Essentials). Your guide, your screenshot manifest and your list of confusing places are the input for that.

## 1. Environment and secrets

Discover, do not assume: operating system, `SPLUNK_HOME`, Splunk version (the app is validated on Splunk Enterprise
10.2.x only), whether KV Store is `ready`, Python 3 and Node availability, outbound HTTPS to github.com, and which
headless browser you can use for screenshots (Playwright with Chromium is preferred; install it into a virtual
environment in a scratch directory, not globally).

Expected environment variables, set by the owner before you start. If one is missing, stop and say which.

```
SPLUNK_HOME            e.g. /opt/splunk or C:\Program Files\Splunk
SPLUNK_ADMIN_USER      an existing Splunk admin
SPLUNK_ADMIN_PASSWORD  its password
SPLUNK_WEB_URL         e.g. http://localhost:8000
SPLUNK_MGMT_URL        e.g. https://localhost:8089
```

Secret rules, without exception:
- Never write a password, token or API key into a file in any git repository, a screenshot, a log you keep, the guide or
  the report. Passwords for the test users you create are generated randomly, kept only in a file under
  `~/sun-guide-work/secrets/` (mode 600) and never printed in the final answer.
- Never put a secret on a command line (it lands in the process list). Use environment variables or stdin.
- Do not store the admin password in the browser session you use for screenshots longer than needed.

## 2. What you may and may not do

You may: download and install the app; create and delete test users and roles prefixed `sunguide_`; create the indexes
`sun_demo` and `ucm_controltest`; push synthetic events into them; create saved searches, alerts and dashboards through the
app; create the throw-away scheduler account the app needs; change the app's own `local/ucm.conf` (record every change in
the report); restart Splunk.

You may not: change, delete or re-index any existing index, input, app, user, role, saved search, lookup or
configuration that you did not create; install Splunk Enterprise Security or any premium app; send data outside this
machine (the only outbound traffic allowed is GitHub for the app download and the catalogue sync); modify the
application code of SUNavigator (if you find a defect, describe it, do not fix it); push to the `main` branch.

If a step would break one of these rules, stop and ask the owner. If something fails, diagnose it and record what you
saw. A failure you hit as a new user is valuable material for the guide's troubleshooting chapter.

## 3. The screenshots will be published: privacy rules

The owner's real Splunk data and machine must not appear anywhere you publish. This is the most important rule.

1. Before you take any screenshot, write a deny list to `~/sun-guide-work/secrets/deny.txt`, one case-insensitive string
   per line: this machine's hostname and FQDN, the OS user name, every IP address and domain name of this machine and its
   network, the names of every pre-existing index, sourcetype, host, source, user and app that is not part of a stock
   Splunk install, any email address you find, and anything else the owner tells you. Do not echo the contents of this
   file into the guide, the report or the chat.
2. All screenshots come from the demo data you create (index `sun_demo`) and the users you create. To make sure the
   inventory shows only demo data, run discovery as a test user whose role has `srchIndexesAllowed = sun_demo;ucm_controltest`
   (and no other index) and check that the Data Inventory page lists no other index. If the app lists real indexes
   anyway, tell the owner and do not screenshot Inventory, Readiness or Overview until the inventory is clean. Real data
   may be used privately to check that the app behaves, but no detail of it (names, values, counts) goes into the guide
   or the report.
3. Before a screenshot is saved, read the page's text (DOM text, not OCR) and refuse to save the image if any deny list
   string occurs in it. Run the same check over every committed image with OCR if Tesseract is available, and over the
   Markdown text. The browser's address bar, bookmarks, tabs and the OS desktop never appear: capture the page area only.
4. Use the generic display name `Alex Analyst`, `Olivia Operator`, `Adam Admin` and so on for the users you create (user
   names `sunguide_analyst`, `sunguide_operator`, and so on). Splunk's top bar shows the logged in user: make sure it shows
   one of these, never the owner's account.
5. Do not use any Splunk Enterprise Security or premium content in any screenshot or text.

## 4. Phase 1: install

1. Download the release, check its checksum and install it with the CLI (Splunk Web upload often times out at 30 s):

   ```
   https://github.com/cagdaskarabag/su_navigator/releases/download/v0.11.0/sunavigator-0.11.0.tar.gz
   sha256  242d573b70037e29eadb4f02448abe62f6bcd12a648267c3d96f8ea252d678dd
   $SPLUNK_HOME/bin/splunk install app sunavigator-0.11.0.tar.gz -auth ...   (see OPERATOR_GUIDE section 3)
   $SPLUNK_HOME/bin/splunk restart
   ```

   If the app is already installed, say so and ask whether to upgrade or to use a clean copy.
2. Check KV Store is `ready`. Check the app appears in the launcher.
3. Follow the operator guide section 4 for the scheduler account (`ucm_scheduler` role and the `scheduled_owner` user).
   Record exactly what a new administrator has to do and where the guide is unclear.
4. Create the test users, one per role, each with a random password (section 1):
   `sunguide_viewer` (`ucm_viewer`), `sunguide_analyst` (`ucm_analyst`), `sunguide_content` (`ucm_content_manager`),
   `sunguide_operator` (`ucm_deployment_operator`), `sunguide_operator2` (`ucm_deployment_operator`, the second person
   for four-eyes), `sunguide_assessor` (`ucm_compliance_assessor`), `sunguide_admin` (`ucm_admin`) and
   `sunguide_demo` (a role that can search only `sun_demo` and `ucm_controltest`, used for discovery; it needs the roles
   required to use the app as well). Splunk's built-in `user` role is the base for the searching roles.
5. Take your first screenshots: launcher tile, first page after opening the app.

Take notes as you go, including every wrong turn. A new user will make the same ones.

## 5. Phase 2: content

1. Load the Fenre catalogue as the content manager, with remote sync from GitHub (operator guide section 5.1). The full
   catalogue has about 16,700 use cases and may take a long time; if the sync can be limited to some categories, choose
   categories that match the demo data (for example 9 and 10, or whatever your demo sourcetypes need). Record how long
   it took and what the progress screen shows. If sync is not possible, use the offline bundle path (section 5.2).
2. Do not import the ESCU bundle unless Splunk's Enterprise Security Content Update is already installed here and is
   free of anything the owner marked private. The default is to skip it. State in the report that you skipped it.
3. Read the Content administration page and screenshot sync status, import and the catalogue summary.

## 6. Phase 3: demo data

Create `sun_demo` and `ucm_controltest` (the control-test index, operator guide section 6.6a). Write a small generator
(keep it in `~/sun-guide-work/`, plain Python, no dependencies) that pushes synthetic events for the last 24 hours with
HTTP Event Collector or `splunk add oneshot` and realistic sourcetypes and fields.

Choose the sourcetypes by looking at the catalogue: find the use cases whose requirements you can satisfy, and design the
data so the app has something to say in each state:
- a few use cases that become Ready (all required sourcetypes and fields present, data fresh);
- a few that are Partially ready (a field or a CIM model missing);
- a few that are Blocked or Not ready (a sourcetype that does not exist);
- one use case whose search will really fire on the demo data (for example failed logins above a threshold), so that a
  deployed alert can trigger and show up in Triggered Alerts;
- data of different freshness: one sourcetype whose newest event is more than 24 hours old.

Fenre's repository has sample events for 94 use cases (`samples/`); `tools/ucm_cli.py build-control-fixtures` in the
SUNavigator repository turns them into control-test fixtures. Use them for the control-test chapter. Clone the
repository to `~/sun-guide-work/su_navigator` (read-only use) to get the tools.

Document the demo data: which sourcetypes, which fields, and why. The user guide may include a short "try it with sample
data" appendix with the generator, as long as it contains nothing that identifies the owner.

## 7. Phase 4: use the app, role by role, and capture everything

Work through the journeys below in a real browser (viewport 1440 x 900, device scale factor 1, light theme, English). After
each step ask yourself what a person who has never seen the app would not understand, and write that down. Use the user
that matches the journey.

A. Orientation (viewer). Home, Overview, what each menu item is for, what a viewer cannot do and what the app says when
   you try.
B. Find content (analyst). Catalogue: search, facets (multi-select, counts), domain, criticality, MITRE, provider,
   wave and maturity facets, quality flags, bookmark, availability filter. The use case page: description, SPL, the
   interactive search ("Run search": time range, results, what it is not), requirements, lint findings, readiness
   card, ATT&CK and regulation mapping, provider and twin links.
C. Know your data (analyst or demo user). Run discovery. Data Inventory: indexes, sourcetypes, freshness, field
   profile, data models, what "populated" and "data seen" mean. Local source mappings.
D. Readiness. Assess one use case and all; states and score; why a use case is Partial or Blocked; the evidence list;
   stale evidence; what changes the score and what never does.
E. Plan. Backlog, selections, recommended next (Top 10), exclusions.
F. Deploy with four eyes. Draft as `sunguide_operator` (cron, time range, schedule window, alert actions such as an
   email or webhook if you can make that safe locally), validate (parser result, lint, side-effect commands, access
   check), submit; approve as `sunguide_operator2`; show the self-approval refusal; show approval with a scheduler access
   gap (create a role case to produce it, operator guide section 4) and the reason it needs; deploy (disabled saved
   search appears in Settings, Searches); enable, including the request and second-person confirmation when a gate
   blocks and an override; let the search run and fire (push matching events), then show the result in Triggered Alerts
   and in the app (run status, outcomes: needs tuning, waiting on data); control test with a fixture; drift (edit the
   saved search in Splunk as admin, then Verify); rollback; withdraw an approval; retire. Capture the deployment
   history and the audit entries.
G. Coverage and compliance. MITRE matrix, regulatory coverage, control catalogues (NIST 800-53, 800-171, CSF 2.0, CMMC
   Level 2): what "mapped" means, gap lists, unmapped controls; as `sunguide_assessor`: record an assessment, per-objective
   results for SP 800-171 Rev. 3, the CMMC score, a POA&M item and its eligibility note, an evidence snapshot and its
   SHA-256 check. State plainly in the guide what the app does not do (it is not a certification tool).
H. Dashboards. Domain dashboards and generated dashboards: create, regenerate, delete.
I. Administration (content manager and admin). Sync, import, reindex and the older-record notice, provider manifest,
   Verify audit chain, the refused-requests table (cause one refusal as a viewer), settings that matter
   (`ucm.conf`: `allow_self_approval`, `override_second_person`, `[audit]`, `[interactive_search]`).
J. Roles. For each role: log in, list what the menu and buttons offer, and what the app says when something is
   refused. Produce a table of role against ability that you verified, not copied.
K. When things go wrong. Reproduce at least these and record the exact message: KV Store not ready (do not break the
   production KV Store; read the message from the guide and report whether it is accurate), blocked enable, search with
   a side-effect command, an index the scheduler role cannot read, a sync that fails because of a bad ref, an import
   that is too large.

Screenshot rules:
- Fixed viewport, same theme, same zoom. Wait for loading spinners to finish; never save a screenshot of a loading state.
- One idea per image. Crop to the page content or to the dialog when the page is long, but keep the page title visible
  at least once per page. Take dialogs with the page behind them.
- File names: `docs/images/user-guide/NN-short-name.png`, numbered in guide order, lower case, no spaces. Keep each
  file under 400 KB (use `oxipng`, `pngquant` or Pillow quantisation if needed; the whole set under 20 MB).
- Optional but welcome: a thin red rectangle (2 px) around the control the text talks about, drawn by injecting a CSS
  outline before the capture, not by editing the image. Do not blur anything: if something has to be hidden the
  screenshot is wrong, retake it with clean data.
- The minimum set: launcher; home; overview; catalogue list; catalogue with facets applied; availability filter; use
  case page top, SPL and "Run search" result, requirements, lint finding; inventory and a discovery run; readiness list
  and readiness card (one Ready, one Partial, one Blocked); backlog and recommendations; draft form; validation; submitted
  (pending); approve dialog; self-approval refusal; access-gap reason dialog; deployed (disabled); enable request and
  confirm; the saved search in Splunk Settings; a fired alert in Triggered Alerts; run status and outcome; control test
  result; drift; rollback; coverage MITRE; coverage regulations; control catalogue with unmapped controls; assessment
  dialog; CMMC score; POA&M item with the eligibility note; snapshot; domain dashboard; generated dashboard; Content
  administration (sync, import, summary, audit verify, refused requests); a viewer's limited menu; two or three error
  messages.
- Also write `docs/images/user-guide/manifest.json`: for every image the file name, the page (view name and URL path
  without host), the role used, one sentence of what it shows, and the guide section that uses it.

## 8. Deliverable 1: `docs/USER_GUIDE.md`

Write for a security or monitoring engineer who knows Splunk but has never seen this app. Plain, specific, no marketing
words, short sentences, active voice, product terms as the app shows them (copy button labels and messages exactly).
Match the tone of `docs/OPERATOR_GUIDE.md`. Structure:

1. What SUNavigator is and what it is not (five lines). Who does what: roles in one table.
2. Ten-minute quick start: install is out of scope (link to the operator guide), start at "the app is installed and
   content is loaded": find a use case, check readiness, deploy it disabled, get it approved, enable it, see it run.
3. Ideas you need first, as a glossary: use case, provider, requirement, readiness states and score, data seen,
   populated, availability, four-eyes, disabled-first, override, access gap, drift, outcome, coverage (mapped, covered,
   gap), control catalogue, assessment, POA&M, snapshot. One or two sentences each, with the screen where you see it.
4. One chapter per page of the app (Home, Overview, Catalogue, use case page, Data Inventory, Readiness, Backlog,
   Deployments, Control tests, Coverage, Dashboards, Content administration): what the page answers, how to read it
   (every column and badge), what you can do, screenshots, the mistakes people make.
5. Task chapters ("How do I ..."): at least find the use cases that fit my data; understand why a use case is not ready;
   deploy a search safely as a team of one and as a team of two; handle a blocked enable; tune a noisy search; prove a
   deployed search works with a control test; see what MITRE techniques I cover; record a CIS/NIST/CMMC assessment and
   a POA&M item; take an evidence snapshot and check it later; give a colleague read-only access; verify the audit
   trail; move a catalogue into an air-gapped Splunk.
6. Roles and permissions: the verified table from journey J.
7. Settings an administrator may change and what each does (only the ones you tried).
8. Troubleshooting: symptom, cause, fix, exact message, from journey K and from your own wrong turns.
9. Limits and what the app does not do (be honest: no ES output mode, no Splunk Cloud or SHC validation, not a CMMC
   status tool, searches are advice not proof).
10. Appendix: sample data generator and the demo walkthrough that reproduces the screenshots.

Every statement that describes behaviour must be something you saw. Where you could not check it, write "Not verified
on this Splunk" in the text, do not guess. Each chapter ends with a line `Verified on: SUNavigator 0.11.0, Splunk
Enterprise <version>, <date>`. Link screenshots with relative paths and meaningful alt text (what the picture shows, not
"screenshot"). Keep headings stable and in lower-case kebab-case anchors, because the in-app help will link to them.

## 9. Deliverable 2: `docs/USER_GUIDE_RUN_REPORT.md`

Short, factual, for the owner. Sections:
- Environment (Splunk version, OS family, no host names), install time, sync time, what you skipped.
- Every difference between the app and `docs/OPERATOR_GUIDE.md` (page, what the guide says, what happened).
- Defects found: title, steps, expected, actual, severity (blocks use, wrong result, cosmetic), role. Do not fix them.
- Confusing places in the UI: text that needed explaining, labels you misread, missing empty states, anything that would
  need a tooltip or a help link. For each, propose where in-app help should sit (page and element) and the guide
  anchor it should link to.
- Missing or hard-to-find help: terms the app uses without explanation.
- What you changed on this Splunk and how to undo it (users, roles, indexes, saved searches, config), as a list of
  commands the owner can run. Offer a cleanup script at `~/sun-guide-work/cleanup.sh`; do not run it without asking.
- Verification: the privacy checks you ran (DOM text and OCR against the deny list, results: zero matches), image
  count and total size, and a list of guide sections marked "Not verified".

## 10. Git and hand-over

- Clone `https://github.com/cagdaskarabag/su_navigator` into `~/sun-guide-work/su_navigator`. Create the branch
  `docs/user-guide` from `main`. Commit only `docs/USER_GUIDE.md`, `docs/USER_GUIDE_RUN_REPORT.md` and
  `docs/images/user-guide/`. Do not commit anything from `~/sun-guide-work/secrets/`, the generator is committed only if it
  contains no identifying data (put it under `docs/user-guide-assets/` then). Do not touch application code, tests or
  other docs, except to add a link to the guide from the README docs table if the owner agrees.
- Run `cd tests && python3 -m unittest discover -s unit -t .` to be sure the documentation checks still pass.
- Push the branch. Never push to `main`. If you have no push access, produce the same tree in a zip file and say where it
  is.
- In your final message give: the branch name, the list of files, the number and size of images, the most important five
  findings from the report, and anything you want the owner to decide. Do not include secrets or deny-list contents.

## 11. How to work

- Plan first: write the journey list and the screenshot list into `~/sun-guide-work/plan.md` and tick items off.
- Work in order: install, content, data, then journeys A to K. Do not start writing the guide before you have used the
  feature. Write each chapter right after its journey, while the details are fresh, then edit for consistency at the end.
- Re-read your finished guide as a new user would and follow it step by step once on a clean browser session. Fix what
  fails.
- If a journey needs something you cannot do safely (a real SMTP server, for example), use the safe alternative, say so in
  the guide, and mark the part as not verified.
- Stop and ask the owner when: a secret or variable is missing, the inventory shows real data after the demo user's role
  restriction, a step could affect existing data, or the app reports an error you cannot get past after a fair attempt.

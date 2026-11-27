# Roadmap

Status: 0.11.0 beta. The application code is frozen for this beta: fixes listed below ship only with a later release, and
the maintainer decides what goes in. Every item links to its issue. Nothing here is a promise of a date.

What the beta is for: finding out which parts people use (readiness and governed deployment, or the compliance pages),
and what breaks on their Splunk. Feedback goes through the [feedback form](https://github.com/cagdaskarabag/su_navigator/issues/new?template=feedback.yml).

## Before the beta is announced (maintainer)

These are repository settings and documentation. Tracked in [#47](https://github.com/cagdaskarabag/su_navigator/issues/47).

- Enable private vulnerability reporting (Settings, Security). `.github/SECURITY.md` already points reporters to it.
- Create the `feedback` label used by the feedback form.
- Set the repository description to "SUNavigator: a use-case navigator for Splunk Enterprise".
- Decide whether release `v0.11.0` stays the latest release or is marked as a pre-release for the beta.
- Add the feedback link to the release notes.

## Proposed order after the external code review

An external code review of the application code (16 bundles, every finding checked against the code) found three defects and eleven low-severity hardening items. The code stays frozen until the maintainer decides otherwise. This is the order proposed for when it does.

1. **Now, no code.** Finish the maintainer checklist ([#47](https://github.com/cagdaskarabag/su_navigator/issues/47)). Decide about the Fenre files with the content owner ([#20](https://github.com/cagdaskarabag/su_navigator/issues/20)). Announce the beta with the notices already in the README.
2. **Patch release 0.11.1: the three confirmed defects.** [#49](https://github.com/cagdaskarabag/su_navigator/issues/49) (redirects and the token), [#48](https://github.com/cagdaskarabag/su_navigator/issues/48) (drift coverage), [#50](https://github.com/cagdaskarabag/su_navigator/issues/50) (control-test scoping). Each is a change to one or two functions with unit tests. Add the user-visible fixes that are already small and understood: [#43](https://github.com/cagdaskarabag/su_navigator/issues/43), [#45](https://github.com/cagdaskarabag/su_navigator/issues/45), and [#44](https://github.com/cagdaskarabag/su_navigator/issues/44) with the matching `NOTICE` change. Run the live suite on Splunk 10.4.x ([#42](https://github.com/cagdaskarabag/su_navigator/issues/42)) before tagging.
3. **Human security review on the 0.11.1 code** ([#32](https://github.com/cagdaskarabag/su_navigator/issues/32)). Review the fixed code, so the checklist does not describe code that is about to change. The external review makes this shorter: the confirmed and rejected findings are written down.
4. **Hardening release.** The eleven items in [#51](https://github.com/cagdaskarabag/su_navigator/issues/51). The first three (the `ucm_admin` write right, throttled audit rows, the save token) are the most useful. Most of the rest are a few lines each.
5. **After beta feedback.** The usability and scale items below, in the order the feedback asks for them.

What the review did not cover: the tests, the documentation and the data files; the Splunk platform itself; and behaviour on a live system. It is a reading of the code. It does not replace #32.

## Known defects (next release, needs a code change)

| Item | Issue | Notes |
|---|---|---|
| Outbound HTTP follows redirects past the host allowlist and forwards the token | [#49](https://github.com/cagdaskarabag/su_navigator/issues/49) | Found in the external code review and reproduced locally. With the default GitHub hosts the risk is low; higher for a custom provider host. |
| Control-test scoping: a subsearch or append clause without an index runs on the default indexes | [#50](https://github.com/cagdaskarabag/su_navigator/issues/50) | Found in the external code review and confirmed. The caller already has these rights, so the risk is to test validity. Keep the test index separate from production. |
| Drift check misses the alert trigger and email message settings | [#48](https://github.com/cagdaskarabag/su_navigator/issues/48) | Found in the external code review. An edit to `alert.track` or `alert_threshold` in Settings is not reported by Verify. |
| Run search stays disabled after a zero-row result | [#43](https://github.com/cagdaskarabag/su_navigator/issues/43) | Workaround: Cancel. Most Fenre searches are alert conditions, so this is the common outcome. |
| Product name and metadata contain a Splunk trademark | [#44](https://github.com/cagdaskarabag/su_navigator/issues/44) | README, repository description and the trademark notice are already fixed in the docs. `app.conf`, `app.manifest` and the export header need a release. |
| POA&M banner says the threshold is met without the system security plan | [#45](https://github.com/cagdaskarabag/su_navigator/issues/45) | Wording only. The API already returns the right value. |
| Web and API unresponsive during a discovery run on 10.4.3 | [#41](https://github.com/cagdaskarabag/su_navigator/issues/41) | Not reproduced. Needs a report with logs. |
| Wrong or misleading wording and layout (provider message, audit-chain refusal, enable note, kvstore "unknown") | [#34](https://github.com/cagdaskarabag/su_navigator/issues/34), [#35](https://github.com/cagdaskarabag/su_navigator/issues/35), [#38](https://github.com/cagdaskarabag/su_navigator/issues/38), [#37](https://github.com/cagdaskarabag/su_navigator/issues/37) | Cosmetic. |

## Security

- Hardening candidates from the external code review: [#51](https://github.com/cagdaskarabag/su_navigator/issues/51).
- Complete the human review of the security paths. It is open in [#32](https://github.com/cagdaskarabag/su_navigator/issues/32), with the refusal-audit limits added in [#46](https://github.com/cagdaskarabag/su_navigator/issues/46).
- A public beta is reasonable while #32 is open, as long as the beta label is clear (see the README).

## Usability (after beta feedback)

- Hide or disable controls a role cannot use ([#36](https://github.com/cagdaskarabag/su_navigator/issues/36)). The server already refuses them; this is about the screen.
- Confirmation before deleting a local source mapping ([#39](https://github.com/cagdaskarabag/su_navigator/issues/39)).
- Control-test fixture import control on Administration ([#40](https://github.com/cagdaskarabag/su_navigator/issues/40)).
- In-app help: [IN_APP_HELP_PLAN.md](IN_APP_HELP_PLAN.md). Build only if feedback shows people get lost.

## Scale and reliability

- Background Reindex ([#25](https://github.com/cagdaskarabag/su_navigator/issues/25)). Reindex is synchronous; it works on the lab but is fragile behind proxies and with large catalogues.
- Counts above the KV bound ([#24](https://github.com/cagdaskarabag/su_navigator/issues/24)).

## Coverage and validation

- Run the live suite on Splunk 10.4.x ([#42](https://github.com/cagdaskarabag/su_navigator/issues/42)).
- Splunk Cloud validation ([#3](https://github.com/cagdaskarabag/su_navigator/issues/3)). Needs a trial stack.
- Search head cluster with a deployer ([#2](https://github.com/cagdaskarabag/su_navigator/issues/2)). Needs a lab.
- Re-run the control-test campaign with the add-ons installed ([#23](https://github.com/cagdaskarabag/su_navigator/issues/23)). Not planned (D-079).
- Read the CIM field reference ([#31](https://github.com/cagdaskarabag/su_navigator/issues/31)).

## Upstream content

- The Fenre findings (F-01 to F-11) are in `docs/upstream/`. Whether they are shared with the content owner, and whether the files stay in this public repository, is being decided with the owner ([#20](https://github.com/cagdaskarabag/su_navigator/issues/20)).

## Not planned without evidence of demand

- ES 8 output mode ([#4](https://github.com/cagdaskarabag/su_navigator/issues/4)). Needs an ES 8 lab (D-078).
- CMMC conditional status, assessment objectives and signed snapshots (D-079).
- More compliance frameworks.
- AI-generated SPL.
- A second round of feature work before the beta feedback is read.

## Documentation housekeeping

- Move the "Since 0.x" history in the README into a changelog.
- Keep `docs/FEATURE_STATUS.md` in step with each issue above.

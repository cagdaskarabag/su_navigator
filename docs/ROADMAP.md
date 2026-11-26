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

## Known defects (next release, needs a code change)

| Item | Issue | Notes |
|---|---|---|
| Run search stays disabled after a zero-row result | [#43](https://github.com/cagdaskarabag/su_navigator/issues/43) | Workaround: Cancel. Most Fenre searches are alert conditions, so this is the common outcome. |
| Product name and metadata contain a Splunk trademark | [#44](https://github.com/cagdaskarabag/su_navigator/issues/44) | README, repository description and the trademark notice are already fixed in the docs. `app.conf`, `app.manifest` and the export header need a release. |
| POA&M banner says the threshold is met without the system security plan | [#45](https://github.com/cagdaskarabag/su_navigator/issues/45) | Wording only. The API already returns the right value. |
| Web and API unresponsive during a discovery run on 10.4.3 | [#41](https://github.com/cagdaskarabag/su_navigator/issues/41) | Not reproduced. Needs a report with logs. |
| Wrong or misleading wording and layout (provider message, audit-chain refusal, enable note, kvstore "unknown") | [#34](https://github.com/cagdaskarabag/su_navigator/issues/34), [#35](https://github.com/cagdaskarabag/su_navigator/issues/35), [#38](https://github.com/cagdaskarabag/su_navigator/issues/38), [#37](https://github.com/cagdaskarabag/su_navigator/issues/37) | Cosmetic. |

## Security

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

# In-app help plan

Status: plan only. Nothing here is implemented; the owner decided to stop changing the app until feedback has been collected. The plan is the starting point for the next release, which adds "how to use" help inside the app.

Source: the walkthrough in [USER_GUIDE.md](USER_GUIDE.md) (Splunk 10.4.3, 94 screenshots in `images/user-guide/`, described in `images/user-guide/manifest.json`).

## Where help should sit

| Page | What a first-time user needs on the page | Guide section |
| --- | --- | --- |
| Home | The path: find use cases, check readiness, deploy | Ten-minute quick start, Home |
| Overview | What the cards mean; why "No scheduled owner is configured" blocks deployment | Overview |
| Content Catalogue | What a category and a record are; what the readiness chips mean; how filters combine | Content Catalogue |
| Use case page | Readiness verdicts and reasons; what Enable does and why it can be blocked; what Run search does (120 s limit) | Use case page, Task: handle a blocked enable |
| Data Inventory | What discovery reads and writes; what a local mapping is; that Delete has no confirmation yet (#39) | Data Inventory |
| Readiness, Backlog | How a verdict is built; what the backlog orders | Readiness, Backlog |
| Deployments | Disabled by default; retire and rollback; the scheduled owner | Deployments, Task: deploy as two people |
| Control tests | What a fixture is; import is REST only (#40) | Control tests |
| Coverage | MITRE coverage and its limits | Coverage |
| Dashboards | Create versus regenerate | Dashboards |
| Content Administration | Roles each action needs; provider check; reindex; audit verify; why some values show unknown to non-admin roles (#37) | Content Administration, Roles and permissions |

## Terms to explain on first use

Readiness (Ready, Partially ready, Blocked, Unknown), local mapping, source category, normalizer, provider, control test, fixture, scheduled owner, deployment revision, retire, rollback, audit chain.

## Form

One "How to use this page" panel per page, closed by default, remembered per user, with a link to the matching section of the guide on GitHub. No new dependencies, no new endpoints. Screenshots stay in the repository and are not bundled in the app package.

## Not in scope

Changing behaviour. The defects found in the walkthrough are tracked as issues #34 to #40 and are separate from the help.

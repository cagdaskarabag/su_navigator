# SUNavigator

SUNavigator (short for **Splunk use case navigator**) is a Splunk app for
Enterprise and Cloud to discover, assess, select, validate and deploy
monitoring use cases. Content comes from pluggable providers; the first
is the [Fenre monitoring use-case catalogue](https://github.com/fenre/splunk-monitoring-use-cases)
(MIT).

**Status: 0.7.1.** Content ingestion, catalogue, discovery, readiness,
selection, SPL validation, guided deployment, coverage and generated
dashboards. 0.7.1 renames the application from "Splunk Use Case Manager"
to SUNavigator; see the operator guide for the upgrade path.

- **Install, use and troubleshooting:** [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md)
- Work packages and validation: [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)

![SUNavigator overview dashboard on a lab instance (synthetic sample data)](docs/images/03-overview.png)

The screenshots in the operator guide come from a lab instance with synthetic
sample events, not from production data.

## What works today

- Remote sync from GitHub pinned to an immutable commit, with per-record
  git-blob-SHA verification, incremental updates (tree/blob SHA), category-atomic
  writes with last-known-good fallback, withdrawal of removed records and a
  schema-major-change guard.
- Offline bundle import for air-gapped environments
  (`tools/ucm_cli.py build-bundle`), using the same validation path.
- Provider-independent canonical model with labelled, confidence-rated
  requirements derived from provider fields and lexical SPL analysis.
- Server-side filtered and paged catalogue, use-case detail, content
  administration, overview and a data-inventory dashboard (counts and data
  age from a bounded `tstats`, never from imported SPL).
- Source-mapping registry: local mappings are never overwritten by discovery.
- Readiness assessment: one evaluator per requirement type with stored
  evidence, weighted score, and a veto when a critical requirement is unmet.
  Field presence and SPL parse results become evidence after validation.
- Per-user selection and backlog. Bounded SPL preview (no side-effect
  commands) and field sampling via a constructed `fieldsummary`.
- Guided deployment: draft, four-eyes approval, saved search written
  disabled, read back and checked, enable gated on readiness, rollback,
  retire and drift detection.
- Coverage: MITRE ATT&CK Enterprise and ICS 20.1 matrices (bundled, other
  versions importable) and regulation controls, by level from catalogue to
  running successfully; run status of deployed searches from the scheduler
  log.
- Domain dashboard and dashboards generated from fixed templates.
- Upgrade migrations and retention purges (audit, job history) in the
  background worker; leader-gated on search head clusters.

Not yet validated on a search head cluster or a Splunk Cloud stack; see
`docs/IMPLEMENTATION_PLAN.md`, "Validation status".
- Capability-based access control and an audit trail.

## Layout

| Path | Contents |
| --- | --- |
| `sunavigator/` | The Splunk app (the only thing that is packaged). |
| `sunavigator/lib/splunk_ucm/` | Python services (stdlib only, Python 3.9 and 3.13). |
| `tools/` | Operator CLI, bundle builder, packaging, dev deploy, perf check. |
| `tests/unit/` | Mocked tests: no Splunk, no network. |
| `tests/live/` | Tests against a real Splunk instance (opt-in). |
| `docs/` | Operator guide, discovery, architecture, decisions, plan, security. |

## Install (development)

```bash
./tools/package.sh                       # dist/sunavigator-<version>.tar.gz
# or, for a local dev instance:
SPLUNK_HOME=/opt/splunk ./tools/dev_deploy.sh --restart
```

Then open **SUNavigator → Administration**, check the manifest, select
categories and synchronize, or import an offline bundle. Full steps,
roles, configuration and troubleshooting (including Splunk Web install
timeouts and macOS KV Store certificate trust) are in
[docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md).

Optional GitHub token (raises the API rate limit). It is stored in Splunk's
credential store, never in configuration files:

```bash
curl -k -u admin https://localhost:8089/servicesNS/nobody/sunavigator/storage/passwords \
  -d name=github_token -d realm=sunavigator --data-urlencode password@-
```

## Offline bundles

```bash
git clone https://github.com/fenre/splunk-monitoring-use-cases /tmp/fenre
python3 tools/ucm_cli.py validate --repo /tmp/fenre --categories 9,10
python3 tools/ucm_cli.py build-bundle --repo /tmp/fenre --categories 9,10 --output bundle.json
```

A bundle built with `--records` is marked partial and never withdraws
records it does not list.

## Upgrades

Versions from 0.7.1 on use the app ID `sunavigator`. Upgrading from
`splunk_use_case_manager` (0.7.0 and earlier) is a new app, not an in-place
upgrade: retire deployments, remove the old app, then install SUNavigator.
Within one worker interval (60 s) the background worker applies pending
migrations and records the version in `uc_sync_state` key `app::state`.
Downgrades are not supported. See the operator guide, section 8.

## Tests

```bash
cd tests
python3 -m unittest discover -s unit -t .            # mocked
UCM_LIVE_SPLUNK=1 UCM_SPLUNK_PASSWORD=... UCM_SPLUNK_VERIFY_TLS=0 \
  python3 -m unittest discover -s live -t .          # real Splunk (+ UCM_LIVE_REMOTE=1 for GitHub)
```

Test fixtures in `tests/fixtures/fenre/` are verbatim upstream files used
under the MIT licence (see the README there).

## Security

See [docs/SECURITY.md](docs/SECURITY.md). In short: upstream content is
untrusted, imported SPL is never executed, nothing is enabled or deployed
automatically, and secrets live only in Splunk's credential store.

## Third-party content

`sunavigator/lib/splunk_ucm/frameworks/data/` contains reduced
copies of MITRE ATT&CK® Enterprise and ICS 20.1 (ids, names, tactic
membership, revocations). © The MITRE Corporation. Reproduced and distributed
with the permission of The MITRE Corporation under the
[ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

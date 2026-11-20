# Splunk Use Case Manager

A Splunk app (Enterprise and Cloud) to discover, assess, select, validate and
deploy monitoring use cases. Content comes from pluggable providers; the first
is the [Fenre monitoring use-case catalogue](https://github.com/fenre/splunk-monitoring-use-cases)
(MIT).

**Status: WP3, content ingestion, searchable catalogue, environment
discovery and readiness assessment.** Selection, SPL validation and
deployment are not implemented yet. See
[docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

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
  Field and SPL checks are reported as "not verified" until WP4.
- Capability-based access control and an audit trail.

## Layout

| Path | Contents |
| --- | --- |
| `splunk_use_case_manager/` | The Splunk app (the only thing that is packaged). |
| `splunk_use_case_manager/lib/splunk_ucm/` | Python services (stdlib only, Python 3.9 and 3.13). |
| `tools/` | Operator CLI, bundle builder, packaging, dev deploy, perf check. |
| `tests/unit/` | Mocked tests: no Splunk, no network. |
| `tests/live/` | Tests against a real Splunk instance (opt-in). |
| `docs/` | Discovery, architecture, decisions, plan, security. |

## Install (development)

```bash
./tools/package.sh                       # dist/splunk_use_case_manager-<version>.tar.gz
# or, for a local dev instance:
SPLUNK_HOME=/opt/splunk ./tools/dev_deploy.sh --restart
```

Then open **Use Case Manager → Administration**, check the manifest, select
categories and synchronize, or import an offline bundle.

Optional GitHub token (raises the API rate limit). It is stored in Splunk's
credential store, never in configuration files:

```bash
curl -k -u admin https://localhost:8089/servicesNS/nobody/splunk_use_case_manager/storage/passwords \
  -d name=github_token -d realm=splunk_use_case_manager --data-urlencode password@-
```

## Offline bundles

```bash
git clone https://github.com/fenre/splunk-monitoring-use-cases /tmp/fenre
python3 tools/ucm_cli.py validate --repo /tmp/fenre --categories 9,10
python3 tools/ucm_cli.py build-bundle --repo /tmp/fenre --categories 9,10 --output bundle.json
```

A bundle built with `--records` is marked partial and never withdraws
records it does not list.

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

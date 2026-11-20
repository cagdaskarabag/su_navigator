# Project Discovery — SUNavigator

Status: Phase Zero complete (2026-11-19). Update this document whenever an
assumption recorded here is confirmed or disproved.

## 1. Workspace findings

| Question | Finding |
|---|---|
| Existing Splunk app in workspace? | No. The workspace (`/agent`) was empty; this project starts from scratch. |
| Existing source/config? | None. |
| Git | Initialised locally on `main`. **No remote is configured**; pushing requires the owner to create a repository. |
| Design screenshots / reference assets | None supplied. UI follows Splunk Web conventions (Simple XML + app CSS). |
| Internet access | Yes (github.com, api.github.com, raw.githubusercontent.com, fenre.github.io, download.splunk.com all reachable). |

## 2. Splunk development environment

| Item | Finding |
|---|---|
| Splunk installed? | Not initially. **Splunk Enterprise 10.2.9 (build 41bebfa38eb4)** was installed at `/opt/splunk` as a single-instance trial for this project. |
| Bundled Python | `python3.9` (3.9.25) and `python3.13` (3.13.11). `server.conf [general] python.version = force_python3`. |
| Python selection | `restmap.conf` / `inputs.conf` spec in 10.2 marks `python.version` **deprecated** in favour of `python.required = <list>` (`3.9`, `3.13`). |
| KV Store | Enabled, `wiredTiger`, status `ready`, standalone captain. |
| Verified KV query operators (live) | `$regex` (with `(?i)` and `$options`), array-contains equality, `$in`, `$and`, `$or`, `$gte`, `sort=field:-1`, `skip`, `limit`, `fields`. **No count operator** — totals require a keys-only query. |
| `batch_save` path | `storage/collections/data/<collection>/batch_save` (not `.../batch_save/<collection>`). |
| Splunk Python SDK | Not bundled for app use. In-process `splunk.rest.simpleRequest` and `splunk.persistconn.application.PersistentServerConnectionApplication` are available. |
| Distributed / SHC / Cloud | **Not available.** Only a single-instance Enterprise is testable here. Every Cloud/SHC statement in this repository is design-level until validated (see §6). |

### Target platform assumptions (conservative)

* Splunk Enterprise **9.2+** and **10.x**; Splunk Cloud Platform (Victoria experience).
* Python source must be valid for **3.9 through 3.13** (no `match`, no runtime `X | Y`
  unions, no 3.10+ stdlib APIs). Unit tests are executed under both Splunk-bundled
  interpreters.
* Only the Python standard library plus Splunk-provided modules are used at runtime.
  No compiled dependencies (Cloud vetting, AppInspect, cross-platform).

## 3. Upstream content provider (Fenre)

Repository: <https://github.com/fenre/splunk-monitoring-use-cases> (MIT licence).
Inspected at commit `3b8024a8cf2e` (2026-11-16), `VERSION` = `8.28.0`.
Latest GitHub *release* is `v8.25.0`; tags observed: `v8.25.0`, `v8.24.0`, `v8.23.0`, `v8.7.0`.
**Release tags lag `VERSION`** — version pinning must accept tags *and* commit SHAs.

### 3.1 Source of truth

* ADR-0007 (accepted): each use case is a JSON sidecar at
  `content/cat-NN-slug/UC-X.Y.Z.json`, validated against `schemas/uc.schema.json`.
* Each category directory has `_category.json` (id, name, slug, description,
  subcategories, quickStart, useCaseCount).
* ADR-0016: UC identifiers are permanent and never reused (stable keys are safe).
* 25 categories, **16,726** use cases. Median sidecar 10 KB, max 84 KB, total 192 MB.
  Largest category: `cat-25-personal-hobbyist-monitoring` (6,431 UCs); OT/ICS is
  `cat-14-iot-operational-technology-ot` (252).

### 3.2 Schema (`schemas/uc.schema.json`)

* `$schema` draft 2020-12, `version` **1.11.0**, `x-stability: stable`,
  `additionalProperties: false`, required: `id`, `title`.
* Keywords used: `type, enum, minLength, maxLength, items, pattern, properties,
  additionalProperties, required, format (uri, date), minItems, uniqueItems,
  minimum, oneOf, not`. No `$ref`. → A stdlib validator for this subset is feasible.
* Field presence across the corpus (selected): `spl` 16,689; `cimModels` 16,689;
  `mitreAttack` 5,076 (433 values are `N/A (<reason>)`); `requiredFields` **2,227**;
  `splunkbaseApps` 2,429; `cimSpl` 3,082; `splVariants` 16; `status` 4,288.
* **There is no structured sourcetype/index field on a UC.** Sourcetypes and
  indexes appear in free-text `dataSources` and inside `spl`. Upstream derives
  `/api/v1/recommender/sourcetype-index.json` (5,591 sourcetypes → UC ids).
  ⇒ Readiness requirements must be *derived* from SPL with explicit confidence.
* `mitreAttack` pattern: `^(T\d{4}(\.\d{3})?|TA\d{4}|N/A \(.+\))$`. No ATT&CK version
  on the UC; `/api/v1/mitre/techniques.json` lists 918 techniques with `domain`
  (`enterprise`/`ics`/…) but the framework version must be resolved separately (WP6).

### 3.3 Published HTTP surfaces (verified live on fenre.github.io)

| Path | Status | Notes |
|---|---|---|
| `/api/v1/manifest.json` | 200 | `apiVersion`, `catalogueVersion` (8.28.0), counts, endpoints, deprecations, `successor`. **Versioned contract** (docs/api-versioning.md: additive-only within v1). |
| `/api/v1/recommender/uc-thin.json` | 200, 14.6 MB | Compact records for all UCs; not full detail. |
| `/api/v1/recommender/sourcetype-index.json` | 200 | sourcetype → UC ids. |
| `/api/v1/mitre/techniques.json` | 200 | ATT&CK technique list. |
| `/api/cat-N.json` | 200 | Full per-category payload, **abbreviated keys, unversioned helper — upstream says not for downstream products**. |
| `/catalog.json` | 200, 171 MB | Too large; abbreviated keys. |
| `/api/v1/compliance/ucs/UC-1.1.1.json` | 404 | Only exists for compliance UCs. |
| `/content/...` | 404 | Sidecars are **not** served by Pages. |

GitHub surfaces (verified):

* `GET api.github.com/repos/{o}/{r}/git/trees/{ref}?recursive=1` → 200, 19,873
  entries, `truncated: false`, includes per-file **git blob SHA** and size.
* `raw.githubusercontent.com/{o}/{r}/{ref}/content/<cat>/UC-X.Y.Z.json` → 200 for tags.
* Unauthenticated GitHub REST API limit: 60 requests/hour (raw content is not
  counted against it).

### 3.4 Provider design consequence

The provider reads **schema-validated sidecars from git at a pinned commit**:
category tree SHAs and blob SHAs give exact, cheap change detection (incremental
sync) and content integrity (blob SHA is recomputed locally). The Pages
`/api/v1/manifest.json` is used only as an optional version signal. All paths are
provider configuration, not code constants.

## 4. Splunk Security Essentials (reference only)

SSE is used as a UX reference (catalogue, data inventory, ATT&CK matrix). No SSE
source code was inspected or copied.

## 5. Identified risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | Sidecar layout is not part of upstream's formal `/api/v1` contract. | Provider breakage on restructure. | Paths are configurable; tree walk fails loudly; last-known-good content retained; offline bundles; future transport adapter for an API surface. |
| R2 | No structured data-source requirements upstream. | Readiness requires SPL/text inference. | Derived requirements carry `source=derived_spl` and `confidence`; never treated as high confidence; admin mappings override (WP2). |
| R3 | `additionalProperties: false` + additive upstream evolution. | A newer upstream field fails validation against an older schema. | Validate against the schema **from the same commit**; unknown-property findings are warnings (tolerant consumer); safety checks are hard errors. |
| R4 | GitHub API rate limit (60/h). | Large syncs fail. | ≤ 2 + N(categories) API calls per sync; raw downloads not rate-limited; optional token from `storage/passwords`; backoff honours `Retry-After`/reset. |
| R5 | Splunk Cloud outbound internet usually blocked. | Remote sync unavailable. | Capability detection; offline bundle import via UI/REST; CLI bundle builder. |
| R6 | KV Store payload size (16.7k × ~10–80 KB). | ~200 MB in `uc_content`. | Category-level selective import; raw record stored once, canonical derived on read; catalogue summary kept small. |
| R7 | SHC: filesystem caches do not replicate. | Inconsistent members. | All state in KV Store (replicated in SHC). No filesystem cache. |
| R8 | Only single-instance Enterprise testable here. | Cloud/SHC claims unverified. | Mark as awaiting validation; capability adapter reports unsupported operations. |

## 6. Unresolved questions / validation backlog

1. Splunk Cloud: is the persistent Python REST handler (`passSystemAuth=true`,
   D-011) and the modular-input worker accepted by Cloud vetting? AppInspect
   4.4.0 cloud tags pass locally; a real vetting submission has not been made.
2. Splunk Cloud: does the customer stack allow egress to `api.github.com` and
   `raw.githubusercontent.com`? (Per-stack; detected at runtime.)
3. SHC: modular-input sync worker must run on one member only — validate
   captain-only execution strategy (WP7).
4. Upstream: will Fenre publish full per-UC detail under `/api/v1`? If so, add a
   second transport behind the same provider.
5. MITRE ATT&CK version used by upstream crosswalks (WP6).

## 7. Findings during WP1 implementation (verified on Splunk 10.2.9)

| Finding | Evidence | Handling |
|---|---|---|
| A modular input whose spec stanza has no settings was never registered. | No `ucm_sync_worker` lines in `splunkd.log`; registered after adding a setting (see D-015). | D-015 |
| KV Store rejects `$` or `.` in document keys at any depth. | HTTP 400 on `batch_save` of raw records (`$schema`). | D-016 |
| KV Store answers `503` for a short time after splunkd starts. | Worker crash on first run after restart. | Worker treats 503 as "retry next interval". |
| splunkd rejects POST bodies that are not URL-encoded unless `Content-Type: application/json` is set. | `Unparsable URI-encoded request data` (400) before the handler runs. | UI and tools always send JSON content type. |
| Splunk Web proxy POSTs need `X-Splunk-Form-Key` **and** `X-Requested-With: XMLHttpRequest`. | 401 "CSRF validation failed" without them. | `ucm_common.js` sends both. |
| `collections.conf` `field.* = array` fails AppInspect. | `check_collections_conf_for_specified_name_field_type`. | D-019 |
| Upstream `compliance[].regulation` is inconsistent (114 strings, 81 ids). | Corpus scan of 8.28.0. | D-017 |
| Upstream records use repository-relative reference links (88 records). | Full-corpus validation run. | Warning; shown as repository paths. |


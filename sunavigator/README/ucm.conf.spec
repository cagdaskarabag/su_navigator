[provider:<provider_id>]
enabled = <boolean>
* Whether the provider is offered in the UI.
remote_sync_enabled = <boolean>
* Set to false on stacks without outbound internet access; offline import remains available.
owner = <string>
repo = <string>
ref = <string>
* Branch, tag or 40-character commit SHA to synchronize. Pin a tag or SHA for reproducible content.
allowed_refs = <comma-separated list>
* Branch and tag names a sync or manifest request may use. "*" is a wildcard
* (for example release/*, v*). The configured ref is always allowed when it is a
* name; an empty list means the configured ref only. A 40-character commit SHA
* is accepted only if the GitHub compare API shows it is reachable from one of
* the listed names without a wildcard; otherwise it is rejected before any
* content is fetched. Default main.
api_base = <url>
raw_base = <url>
content_root = <relative path>
schema_path = <relative path>
version_path = <relative path>
allowed_hosts = <comma-separated host list>
* Outbound host allowlist. Empty means the hosts of api_base and raw_base.
fetch_concurrency = <integer 1-16>
timeout = <seconds>
max_attempts = <integer>
proxy_url = <url>
* Optional HTTPS proxy.
ca_bundle = <path>
* Optional CA bundle file for TLS verification.

[sync]
schedule_interval_hours = <integer>
* 0 disables scheduled synchronization.
job_timeout_seconds = <integer>
max_invalid_ratio = <float 0-1>
* A category whose invalid-record ratio exceeds this value is not updated.

[import]
max_bundle_mb = <integer>

[controltest]
index = <string>
* Dedicated test index for post-deploy control tests (D-054). Create it on the
  Splunk instance first; the app never creates indexes. Default ucm_controltest.
* A control test is refused when this index is main, or is a default search index of the user who runs it.

[catalog]
max_page_size = <integer>
max_join_keys = <integer>
* Longest key list the catalogue sends to the KV Store when the availability or bookmark
  filter joins readiness or selections. Longer lists are filtered inside the app instead.
  Measured limit 8000 keys of 44 characters; default 2000, range 1-5000.
kv_row_limit = <integer>
* The value of limits.conf [kvstore] max_rows_per_query on this deployment. The KV Store returns
  at most this many rows per query, so a catalogue total at this number is a lower bound and
  Administration warns when the catalogue approaches it. Filters that join readiness or bookmarks
  refuse above this number minus one. It does not change the platform limit. Default 50000.

[discovery]
earliest = <relative-time>
* Relative earliest bound for the discovery tstats (e.g. -7d, -24h). Default -7d.
latest = <relative-time>
* Relative latest bound. Default now.
include_internal = <boolean>
* Include Splunk internal indexes (_internal, _audit, ...). Default false.
* When false, internal indexes are not scanned: a requirement on one is reported as
* not verified (never present or missing). Scanning them also does not give the
* scheduler account access to them; that is a role setting (see [deployment]
* scheduled_owner and docs/OPERATOR_GUIDE.md).
max_pairs = <integer>
* Maximum index/sourcetype pairs stored per job.
search_timeout_seconds = <integer>
job_timeout_seconds = <integer>
schedule_interval_hours = <integer>
* 0 disables scheduled discovery.
freshness_days = <integer 0-365>
* Discovery also counts events per index and sourcetype over this many days and the events time-stamped more than five minutes in the future (two tstats searches per index group). A pair seen in that period but not in the discovery window is kept as stale instead of not found. 0 disables. Default 30. D-070.
field_profile = <boolean>
* Profile field fill and placeholder rates for the fields the active catalogue
* requires, one search per sourcetype over the last 24 hours (D-070). Readiness
* uses the stored rates to tell a present field from an empty one. Default true.
profile_max_sourcetypes = <integer 0-200>
* Sourcetypes profiled per job, most used by the catalogue first. Default 20.
profile_max_fields = <integer 1-200>
* Fields profiled per sourcetype. Default 60.
profile_sample_events = <integer 100-10000>
* Events sampled per sourcetype (head of the 24-hour window). Default 1000.
profile_timeout_seconds = <integer 10-600>
* Timeout for each profile search. Default 60.
profile_budget_seconds = <integer 30-3600>
* Total time one job may spend profiling. Remaining sourcetypes are reported as skipped. Default 300.
profile_placeholders = <comma-separated strings>
* Values treated as placeholders (for example "-", "N/A") when computing placeholder rates.
* Empty uses the built-in list: -, N/A, n/a, null, NULL, unknown, none, 0.0.0.0.
event_check = <boolean>
* For each event type a detection reads (for example eventName=DescribeImageScanFindings in aws:cloudtrail), run one bounded search to see whether events of that type exist, over freshness_days (7 if 0). Only a count is stored (D-073). Default true.
event_max_checks = <integer 0-1000>
* Event types checked per job, most used by the catalogue first. Default 100.
event_timeout_seconds = <integer 5-300>
* Timeout for each event check. Default 30.
external_match = <boolean>
* List saved searches in other apps and propose which catalogue use cases they already implement (D-074). Only names and a hash of the search text are stored; the search text is never kept. Default true.
external_max_searches = <integer 100-100000>
* Saved searches considered per job. Default 20000.
event_budget_seconds = <integer 30-3600>
* Total time one job may spend on event checks. Remaining checks are reported as skipped. Default 300.
populated_check = <boolean>
* Check whether installed data models hold events (issue #13). For each selected model
* discovery runs one `| tstats count from datamodel=<model> where earliest=-24h` with the
* discovery account's token and stores populated = yes, no or unverified next to the model.
* Models that catalogue requirements reference (and their mapped local names) are checked
* first, then the models of Splunk_SA_CIM. The value is informational: it never changes a
* readiness status, score or state. Default true; false records "unverified" for every
* model and runs no search.
populated_max_models = <integer 1-100>
* Cap on models checked per discovery job; the rest are recorded as unverified
* (reason model_cap). Default 30.
populated_timeout_seconds = <integer 5-300>
* Time limit of each check (sent to splunkd as max_time and as the request timeout). A search
* that does not finish is recorded as unverified (reason timeout), never as "no". The checks of
* one job also share a budget of half of job_timeout_seconds. Default 30.

[readiness]
auto_assess = <boolean>
* Re-assess all use cases after each completed discovery run or content sync. Default true.
stale_hours = <integer>
* A sourcetype whose newest event is older than this is "partial" (stale). Default 24.
ready_threshold = <integer 1-100>
* Minimum score for "ready" (also requires no unmet required or critical requirement). Default 90.
partial_threshold = <integer 0-100>
* Minimum score for "partially_ready". Default 50.
min_coverage = <float 0-1>
* Minimum share of scored requirement weight with a decided status; below it the state is
* "insufficient_evidence". Default 0.5.
job_timeout_seconds = <integer>

[validation]
earliest = <relative-time>
* Forced earliest bound for preview, and for field sampling of a pair discovery
* recorded no last event time for. Default -15m.
latest = <relative-time>
preview_max_events = <integer>
preview_timeout_seconds = <integer>
sample_events = <integer>
* Events read per index/sourcetype pair for fieldsummary. Default 200.
sample_timeout_seconds = <integer>
sample_window_minutes = <integer 1-10080>
* Field sampling reads the window of this length that ends at the newest event discovery
* saw for each index/sourcetype pair, so idle sourcetypes are sampled where their events
* are. A window with no events leaves fields unverified rather than absent. Default 60.

[interactive_search]
enabled = <boolean>
* Offers the "Run this search" box on a use case page. The search runs in the browser through
* Splunk's search API as the signed-in user, outside the server's bounded preview (D-058).
* Set to false to switch it off for everyone; the page then shows a note instead of the button.
* Searches with side-effect commands (also inside a map search) or that run SPL the page cannot
* show (savedsearch, loadjob, dbxquery, macros inside a map string) are never offered (D-062). Default true.

[spl]
extra_safe_commands = <comma-separated command names>
* Commands you trust to be read-only, in addition to SUN's built-in allowlist
* (for example custom or add-on search commands such as an MLTK "apply").
* Commands outside the allowlist block preview and need an approver's acknowledgment.
* Side-effect commands (outputlookup, collect, sendemail, ...) and indirect-execution
* commands (map, savedsearch, loadjob, rest, dbxquery, ...) are ignored here. Default empty.

[deployment]
require_approval = <boolean>
* A submitted revision must be approved by a user with ucm_deploy before it can be deployed. Default true.
allow_self_approval = <boolean>
* Allow the submitter to approve their own revision. Default false (four-eyes principle).
block_enable_states = <comma-separated readiness states>
* Enabling a deployed search whose readiness is in this list requires an override reason. Default blocked.
enable_second_person = <boolean>
* Enabling needs a request and a confirmation by two different people. Default false. D-075.
override_second_person = <boolean>
* Enabling past a gate (readiness state or scheduler access) needs a request and a confirmation by two different people, even when enable_second_person is false. allow_self_approval lets one person do both. Default true. D-080.
enable_request_hours = <integer 1-720>
* How long an enable request stays open. Default 24.
override_days = <integer 0-365>
* How long an override (enabling past a blocking readiness state) lasts. 0 means no expiry. Default 14.
override_expiry_action = remind|disable
* What the verification worker does when an override expires: record one reminder, or also disable the search. Default remind.
default_cron = <five-field cron>
* Schedule proposed for new drafts. Default */15 * * * *.
default_earliest = <relative-time>
default_latest = <relative-time>
* Time range proposed for new drafts. Default -20m@m to -5m@m: a 15-minute window
* that matches the default cron and leaves 5 minutes for late-arriving events.
default_schedule_window = auto|<integer 0-1440>
* schedule_window proposed for new drafts, so the scheduler can delay the search
* under load instead of skipping it. Default auto.
default_alert_mode = none|track
* track: an alert that adds to Triggered Alerts when results exceed the threshold; no external actions.
* none: a scheduled report. Default track.
scheduled_owner = <string>
* Name of the account that owns every deployed saved search. It must hold the ucm_scheduler role (or any role with schedule_search and the indexes the searches read). Required before any deploy, enable, disable, rollback or retire; the app refuses those actions without it. Default empty. D-051.
max_revisions = <integer 2-100>
* Revisions kept per deployment. The deployed and previous deployed revisions are always kept. Default 20.
verify_interval_minutes = <integer>
* The worker compares deployed saved searches with their revision at this interval. 0 disables. Default 60.
cron_jitter = <boolean>
* When a draft uses the default cron and it has the form */N * * * *, start the search at a minute offset derived from the use case (for example 7-59/15), so deployed searches do not all start at the same minute. An explicit cron is never changed. Default true. D-069.

[actions]
enabled = <boolean>
* Master switch for email and webhook alert actions on deployed searches (D-072). Default true.
* Nothing can be sent until the two lists below name permitted destinations.
email_domains = <comma-separated domains>
* Mail domains a recipient may belong to, for example example.com or *.example.com. Empty (default) means no
* email action can be drafted, approved or deployed.
webhook_hosts = <comma-separated hostnames>
* Hosts a webhook URL may point to, for example hooks.example.com or *.example.com. Empty (default) means no
* webhook action. Entries are matched against the URL's host name only.
webhook_allow_http = <boolean>
* Allow http:// webhook URLs. Default false: https only.
max_recipients = <integer 1-50>
* Recipients allowed on one email action. Default 10.
require_suppression = <boolean>
* Require 'Suppress repeats for' on any search with an action, so one condition does not send a message on
* every run. Default true.

[audit]
refusals = <boolean>
* Write an audit row (refused.<route>, outcome refused) when a governance request is refused: deployment,
* catalogue import and administration routes; client errors 400, 403 and 409 only. Default true. D-080.
refusal_window_seconds = <integer 0-3600>
* The same refusal (same user, route, object and error code) is written once per this many seconds. Default 300.
refusal_actor_per_hour = <integer 1-1000>
* Most refusal rows one user writes per hour. The first one over writes a single refused.rate_limited row. Default 20.
refusal_total_per_hour = <integer 1-100000>
* Most refusal rows written per hour by all users together. Default 200.
verify_window_seconds = <integer 0-3600>
* Verify (a deployment, or the audit chain) writes at most one audit row per object per this many seconds, unless the result changed or the audit chain has a problem. 0 writes a row on every call. Default 300.

[retention]
audit_days = <integer 0-3650>
* Audit records older than this are deleted by the background worker. 0 keeps them forever. Default 365.
job_history = <integer 10-200>
* Finished jobs kept per job type (sync, discovery, readiness). Queued and running jobs are never deleted.
* Services also trim at write time (sync 200, discovery and readiness 50), so those are upper bounds. Default 50.
interval_hours = <integer 0-720>
* How often the purge runs. 0 disables purging. Default 24.

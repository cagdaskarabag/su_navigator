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

[catalog]
max_page_size = <integer>

[discovery]
earliest = <relative-time>
* Relative earliest bound for the discovery tstats (e.g. -7d, -24h). Default -7d.
latest = <relative-time>
* Relative latest bound. Default now.
include_internal = <boolean>
* Include Splunk internal indexes (_internal, _audit, ...). Default false.
max_pairs = <integer>
* Maximum index/sourcetype pairs stored per job.
search_timeout_seconds = <integer>
job_timeout_seconds = <integer>
schedule_interval_hours = <integer>
* 0 disables scheduled discovery.

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

[retention]
audit_days = <integer 0-3650>
* Audit records older than this are deleted by the background worker. 0 keeps them forever. Default 365.
job_history = <integer 10-200>
* Finished jobs kept per job type (sync, discovery, readiness). Queued and running jobs are never deleted.
* Services also trim at write time (sync 200, discovery and readiness 50), so those are upper bounds. Default 50.
interval_hours = <integer 0-720>
* How often the purge runs. 0 disables purging. Default 24.

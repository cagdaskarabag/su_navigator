[provider:<provider_id>]
enabled = <boolean>
* Whether the provider is offered in the UI.
remote_sync_enabled = <boolean>
* Set to false on stacks without outbound internet access; offline import remains available.
owner = <string>
repo = <string>
ref = <string>
* Branch, tag or 40-character commit SHA to synchronize. Pin a tag or SHA for reproducible content.
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

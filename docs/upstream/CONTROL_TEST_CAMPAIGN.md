# Control-test campaign: all 94 Fenre fixtures (SUNavigator 0.8.8)

Decision record: [D-064](../DECISIONS.md). Upstream findings for the product owner:
[FENRE_FINDINGS.md](FENRE_FINDINGS.md). Issues: #5 and #6.

| | |
|---|---|
| Run | 2026-11-24, `tools/controltest_campaign.py --bisect` (raw data: `control_test_campaign.results.json`, classes and evidence: `control_test_campaign.classification.json`) |
| Splunk | Enterprise 10.2.9, single instance, **no add-ons**, no props changes |
| Content | Fenre `main` at `0e21f019` (2026-11-23): `content/` for the SPL, `samples/` for the 94 fixtures |
| Code | `splunk_ucm.deployment.controltest` of 0.8.8: the same runner the app uses for **Run control test** (scoping, derived window, assertions, verdicts) |
| Data | events go to the `[controltest]` index (`ucm_controltest`) with a per-run `source` marker; the SPL is scoped to that index and marker |
| Left behind | no saved search, no KV row, no role or user; this sprint's events were removed from the test index afterwards (see the end of this file) |

What the script does that the app does not: it takes the SPL from the Fenre checkout
instead of a deployed revision, and it applies the deployment gate first (Splunk must
parse the search in the app's namespace and it must not have side effects), so a use
case the app would refuse to deploy is `not_runnable` with the parser's message. With
`--bisect` it also counts rows after each pipeline stage of a search that did not pass,
which is how the "where it stopped" evidence below was found.

Reason classes:

| Class | Meaning |
|---|---|
| SUN defect | SUNavigator gave a wrong verdict. None remain; those found were fixed in 0.8.8 (below). |
| missing add-on or KV_MODE | The data needs an add-on's field extraction or a props setting that the lab does not have. |
| upstream content defect | The SPL itself is wrong (Splunk rejects it, or a term never matches). |
| fixture defect | The sample events or the manifest do not fit the SPL. |
| not runnable | The control test cannot scope the search to the test index, or it needs something the lab does not have (a customer lookup). |
| passed | Verdict `passed`. |

When a fixture has an SPL defect and a fixture defect, the class is the SPL defect; the
evidence names both.

## Summary

| Verdict | Fixtures |
|---|---|
| passed | 12 |
| failed | 67 |
| content_error | 0 |
| inconclusive | 0 |
| not_runnable | 15 |
| **total** | **94** |

| Reason class | Fixtures |
|---|---|
| SUN defect | 0 |
| missing add-on or KV_MODE | 1 |
| upstream content defect | 20 |
| fixture defect | 53 |
| not runnable | 8 |
| passed | 12 |

## Per fixture

| UC | Verdict | Reason class | Evidence |
|---|---|---|---|
| UC-1.1.1 | failed | fixture defect | Events are one multi-line `top`-style CPU table per event. Without Splunk_TA_nix `cpu_load_percent` is never derived, so stage 1 (`cpu=all`) returns 0 rows. Lab experiment with the field emulated by a temporary `EVAL-cpu_load_percent = 100 - pctIdle` and key=value events: the SPL returns 1 aggregated row (by observed_host), not the 3 rows the manifest expects, and its output has `observed_host` and `avg_cpu_percent`, not the manifest fields `host` and `pctIdle`. The manifest cannot pass even with the add-on. See FENRE_FINDINGS F-01. |
| UC-1.1.8 | failed | fixture defect | All 7 failed-password events are from one source (10.99.0.42) inside one 5-minute bin: the SPL aggregates them to 1 row with attempts=7, below its `attempts > 10` threshold, and the manifest expects at least 5 rows. See FENRE_FINDINGS F-02. |
| UC-1.2.4 | not_runnable | not runnable | The SPL calls `lookup windows_service_failure_policy.csv`, a customer-maintained lookup that does not exist on the lab, so Splunk cannot construct it. Also filters on `source=`. |
| UC-1.2.6 | not_runnable | not runnable | The SPL filters on `source=`; the control test uses `source` as its per-run marker, so the search cannot be scoped (D-064, product-owner item). |
| UC-1.2.29 | not_runnable | upstream content defect | Splunk rejects the SPL: `Regex: \ at end of pattern` in `replace(TargetObject,"^.*\\",...)`: the doubled backslash reaches the regex as one. Also filters on `source=`. See FENRE_FINDINGS F-06. |
| UC-2.6.28 | not_runnable | not runnable | The SPL filters on `source=`; the control test uses `source` as its per-run marker, so the search cannot be scoped (D-064, product-owner item). |
| UC-2.6.29 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-2.6.34, UC-2.6.46); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=xd sourcetype="citrix:monitor:odata" (ODataEntity=MachineCatalog OR entity_type=MachineCatalog OR Name=*)`). |
| UC-2.6.30 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 14 other fixtures (UC-2.6.31, UC-2.6.32, UC-2.6.33, UC-2.6.35 and 10 more); it is a generic template, not data for this search. |
| UC-2.6.31 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.32, UC-2.6.33, UC-2.6.35 and 10 more); it is a generic template, not data for this search. |
| UC-2.6.32 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.33, UC-2.6.35 and 10 more); it is a generic template, not data for this search. |
| UC-2.6.33 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.35 and 10 more); it is a generic template, not data for this search. |
| UC-2.6.34 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 2 other fixtures (UC-2.6.29, UC-2.6.46); it is a generic template, not data for this search. |
| UC-2.6.35 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. |
| UC-2.6.36 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 2 other fixtures (UC-2.6.39, UC-2.6.52); it is a generic template, not data for this search. |
| UC-2.6.37 | failed | fixture defect | The event body is shared with 1 other fixture (UC-2.6.77); it is a generic template, not data for this search. The base search matches the 2 events, then `where loss_pct>2 OR latency_ms>150 OR fallback=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.38 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 4 other fixtures (UC-2.6.40, UC-2.6.41, UC-2.6.43, UC-2.6.54); it is a generic template, not data for this search. |
| UC-2.6.39 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 2 other fixtures (UC-2.6.36, UC-2.6.52); it is a generic template, not data for this search. |
| UC-2.6.40 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 4 other fixtures (UC-2.6.38, UC-2.6.41, UC-2.6.43, UC-2.6.54); it is a generic template, not data for this search. |
| UC-2.6.41 | not_runnable | not runnable | The SPL filters on `source=`; the control test uses `source` as its per-run marker, so the search cannot be scoped (D-064, product-owner item). |
| UC-2.6.42 | failed | fixture defect | The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=windows sourcetype="WinEventLog:Security" (EventCode=4688 OR EventCode=4702)`). |
| UC-2.6.43 | not_runnable | not runnable | The SPL filters on `source=`; the control test uses `source` as its per-run marker, so the search cannot be scoped (D-064, product-owner item). |
| UC-2.6.44 | not_runnable | upstream content defect | Splunk rejects the SPL: "The arguments to the 'match' function are invalid" in a `where` clause. See FENRE_FINDINGS F-07. |
| UC-2.6.45 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). No fixture event matches the pattern either. The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. |
| UC-2.6.46 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-2.6.29, UC-2.6.34); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=xd sourcetype="citrix:monitor:odata" odata_resource="Machines"`). |
| UC-2.6.47 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=xd sourcetype="citrix:broker:events" (event_type="SessionConnection" OR event_type="ConnectionLogon" OR event_type="SessionInfo")`). |
| UC-2.6.48 | passed | passed | Weak pass: the row comes from `coalesce` defaults (`app` = Unknown, `actor` = unknown); the placeholder events carry none of the fields the SPL reads. |
| UC-2.6.49 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=xd sourcetype="citrix:broker:events" (event_type="SessionState" OR event_type="SessionDisconnect" OR event_type="SessionLogoff")`). |
| UC-2.6.50 | passed | passed | Row count, field and negative assertions hold. |
| UC-2.6.51 | not_runnable | not runnable | The SPL filters on `source=`; the control test uses `source` as its per-run marker, so the search cannot be scoped (D-064, product-owner item). |
| UC-2.6.52 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-2.6.36, UC-2.6.39); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=xd sourcetype="citrix:vda:events" (event_type="AgentInfo" OR event_type="Registration" OR event_type="Heartbeat")`). |
| UC-2.6.53 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search matches the 3 events, then `where event_type IN ("DesktopAssignmentChange", "MachineAssignment", "EntitlementChange") OR match(_raw, "(?i)` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.54 | not_runnable | not runnable | The SPL filters on `source=`; the control test uses `source` as its per-run marker, so the search cannot be scoped (D-064, product-owner item). |
| UC-2.6.55 | passed | passed | Weak pass: the row holds only default values (`driver_version` = unknown, `license_state` = unknown, `vgpu` = Unknown). |
| UC-2.6.56 | failed | fixture defect | The base search matches the 2 events, then `stats latest(st) as status, latest(sev) as impact, latest(_time) as last_update by comp, region` leaves 0 rows; the events carry no `region`. |
| UC-2.6.57 | failed | fixture defect | The base search matches the 2 events, then `stats latest(cpu) as cpu_pct, latest(alert_state) as alert_state, latest(cloud_registration) as registration, ` leaves 0 rows; the events carry no `connector_id`, `resource_location`. |
| UC-2.6.58 | not_runnable | upstream content defect | Splunk rejects the SPL: `timechart` takes one split-by field; this one has two (`by reason, user_principal`). See FENRE_FINDINGS F-09. |
| UC-2.6.59 | failed | fixture defect | The event body is shared with 1 other fixture (UC-2.6.58); it is a generic template, not data for this search. The base search matches the 2 events, then `where risk>=70 OR like(rtype, "%exfil%") OR like(rtype, "%anomal%auth%") OR like(rtype, "%insider%")` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.60 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-2.6.62, UC-2.6.76); it is a generic template, not data for this search. The base search matches the 2 events, then `where like(err, "%cert%") OR like(err, "%signature%") OR like(err, "%nameid%") OR like(err, "%audience%") OR l` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.61 | failed | fixture defect | The event body is shared with 1 other fixture (UC-10.6.198); it is a generic template, not data for this search. The base search matches the 12 events, then `stats count by host, user, path, stun, udp_block, nat_type, ver` leaves 0 rows; the events carry no `path`, `stun`, `udp_block`, `nat_type`, `ver`. |
| UC-2.6.62 | not_runnable | upstream content defect | Splunk rejects the SPL: `timechart` takes one split-by field; this one has two (`by issue, store_name`). See FENRE_FINDINGS F-09. |
| UC-2.6.63 | failed | fixture defect | The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=cloud sourcetype="azure:consume:export" (resource_type="*compute*" OR resource_type="*virtual*")`). |
| UC-2.6.64 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.65, UC-2.6.66, UC-2.6.68, UC-2.6.69); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=xd sourcetype="citrix:endpoint:enrollment" outcome!="success"`). |
| UC-2.6.65 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.64, UC-2.6.66, UC-2.6.68, UC-2.6.69); it is a generic template, not data for this search. The base search matches the 2 events, then `stats values(device_id) as sample_devices, latest(os_patch_level) as patch_level, count as events by user_id, ` leaves 0 rows; the events carry no `user_id`, `reason`. |
| UC-2.6.66 | not_runnable | upstream content defect | Splunk rejects the SPL: `timechart` takes one split-by field; this one has two (`by cat, plat`). See FENRE_FINDINGS F-09. |
| UC-2.6.67 | passed | passed | Row count, field and negative assertions hold. |
| UC-2.6.68 | not_runnable | upstream content defect | Splunk rejects the SPL: `timechart` takes one split-by field; this one has two (`by action, outcome`). See FENRE_FINDINGS F-09. |
| UC-2.6.69 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.64, UC-2.6.65, UC-2.6.66, UC-2.6.68); it is a generic template, not data for this search. The base search matches the 2 events, then `where blocked>50 OR back>1000 OR db_pct>90 OR (isnotnull(cert_days) AND cert_days<=30)` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.70 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.71, UC-2.6.72, UC-2.6.73, UC-2.6.74); it is a generic template, not data for this search. The base search matches the 2 events, then `stats min(zone_ok) as min_zone, max(backlog) as max_backlog, min(conn_ok) as min_connector, values(hosting_mod` leaves 0 rows; the events carry no `zone_id`. |
| UC-2.6.71 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.70, UC-2.6.72, UC-2.6.73, UC-2.6.74); it is a generic template, not data for this search. The base search matches the 2 events, then `stats count as hits, sum(eval(action="block")) as blocks, sum(eval(action="warn")) as warns, sum(is_fp) as fp_` leaves 0 rows; the events carry no `policy_id`, `user`. |
| UC-2.6.72 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.70, UC-2.6.71, UC-2.6.73, UC-2.6.74); it is a generic template, not data for this search. The base search matches the 2 events, then `stats sum(b) as tot_bytes, sum(bulk) as bulk_events, sum(is_link) as link_creates, sum(eval(off_hours=1 AND is` leaves 0 rows; the events carry no `user`, `client_ip`. |
| UC-2.6.73 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-2.6.70, UC-2.6.71, UC-2.6.72, UC-2.6.74); it is a generic template, not data for this search. The base search matches the 2 events, then `where auth_fails>10 OR rate_hits>0 OR job_errors>0` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.74 | passed | passed | Weak pass: aggregates the placeholder (`actions` = download, `users` = 0); the events carry no user. |
| UC-2.6.75 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=xd (sourcetype="citrix:broker:events" event_type="SessionLogon" OR sourcetype="uberAgent:Logon:LogonDetail" OR sourcetype="citrix:hdx:connect")`). |
| UC-2.6.76 | passed | passed | Weak pass: the row holds only default values (`dev`, `os`, `ver` = unknown). |
| UC-2.6.77 | failed | fixture defect | The event body is shared with 1 other fixture (UC-2.6.37); it is a generic template, not data for this search. The base search matches the 2 events, then `where med_start>10000 OR med_ica>100 OR hang_ev>0` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.78 | failed | fixture defect | The base search matches the 2 events, then `where risk_disk=1 OR max_lag>300 OR down_ev=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-2.6.79 | failed | fixture defect | The base search matches the 2 events, then `stats count as n, sum(ok) as okc, sum(bfail) as blks, median(rtt) as medrtt, values(cat) as cats by _time, use` leaves 0 rows; the events carry no `user`, `app`. |
| UC-3.2.1 | not_runnable | upstream content defect | Splunk rejects the SPL: `earliest=-6h@5m` is not a valid time modifier in `tstats` (no snap to 5 minutes). See FENRE_FINDINGS F-08. |
| UC-4.1.1 | failed | upstream content defect | The SPL filters `errorCode="Client.UnauthorizedAccess"`, which AWS does not emit (the code is `Client.UnauthorizedOperation`, which the manifest itself lists), so the third fixture event is not selected: 2 rows, 3 expected. The `table` also drops `errorCode`, which the manifest asserts. See FENRE_FINDINGS F-05. |
| UC-4.1.2 | failed | fixture defect | The SPL ends in `table _time userIdentity.arn eventName sourceIPAddress awsRegion`; the manifest asserts `userIdentity.type`, which the search does not return. Rows are returned (2 of 2). |
| UC-5.1.1 | failed | fixture defect | The SPL keeps only `count > 3` groups; the 7 events give one qualifying group (Gi1/0/24 down, 4 times), the manifest expects 3 rows. |
| UC-5.2.3 | failed | missing add-on or KV_MODE | The events are `pan:threat` CSV lines; `severity`, `src`, `dest` and `threat_name` come from Splunk_TA_paloalto field extractions, which the lab does not have, so `severity="critical" OR severity="high"` matches nothing. |
| UC-5.3.23 | failed | upstream content defect | The base search uses the eval function `match()` as a search term; Splunk does not evaluate it there and the clause matches no event, even an OR branch that would (lab check: the same events return with `\| where match(...)` and none without the `where`). The event body is shared with 10 other fixtures (UC-5.3.24, UC-5.3.25, UC-5.3.26, UC-5.3.27 and 6 more); it is a generic template, not data for this search. |
| UC-5.3.24 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.25, UC-5.3.26, UC-5.3.27 and 6 more); it is a generic template, not data for this search. The base search matches the 2 events, then `stats count as hits, values(violation) as violation_types, dc(url) as unique_urls, latest(host) as adc by poli` leaves 0 rows; the events carry no `policy_name`, `_time`. |
| UC-5.3.25 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.26, UC-5.3.27 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=netscaler (sourcetype="citrix:netscaler:appflow" OR sourcetype="citrix:netscaler:syslog") ("bot" OR "BOT" OR captcha OR "reputation")`). |
| UC-5.3.26 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.27 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler sourcetype="citrix:netscaler:syslog" (nFactor OR "login schema" OR AAA OR SAML OR "factor" OR IdP OR "assertion" OR "epa") ( "failed" `). |
| UC-5.3.27 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler (sourcetype="citrix:netscaler:syslog" OR sourcetype="citrix:netscaler:perf") ("surge" OR "spillover" OR "max client" OR maxclient OR "`). |
| UC-5.3.28 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-5.3.30, UC-5.3.31); it is a generic template, not data for this search. The base search matches the 2 events, then `stats avg(cps) as tps, avg(reuse_pct) as avg_reuse, avg(p95_latency_ms) as p95_ms by _time, host, lbvserver` leaves 0 rows; the events carry no `lbvserver`. |
| UC-5.3.29 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search matches the 3 events, then `where client_rtt>0 OR server_rtt>0` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-5.3.30 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-5.3.28, UC-5.3.31); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler sourcetype="citrix:netscaler:perf" ("ic_cache" OR "ico_" OR cache_hits OR cache_misses)`). |
| UC-5.3.31 | failed | fixture defect | The event body is shared with 2 other fixtures (UC-5.3.28, UC-5.3.30); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler sourcetype="citrix:netscaler:perf" ("compress" OR comp_ OR gzip OR deflate)`). |
| UC-5.3.32 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler (sourcetype="citrix:netscaler:syslog" OR sourcetype="citrix:netscaler:snmp") (ADNS OR "dns" OR nameserver OR NXDOMAIN OR SERVFAIL OR D`). |
| UC-5.3.33 | failed | fixture defect | The base search matches the 2 events, then `stats max(part_cpu) as max_cpu, max(part_mem) as max_mem, sum(alarm) as alarm_events, values(host) as hosts by` leaves 0 rows; the events carry no `sdx_name`, `partition_id`. |
| UC-5.3.34 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler sourcetype="citrix:netscaler:syslog" ("cluster" OR CLIP OR CCO OR NSYNC OR "quorum" OR "propagat" OR "split-brain" OR "split brain" OR`). |
| UC-5.3.35 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler sourcetype="citrix:netscaler:syslog" ("audit" OR NITRO OR "nsconfig" OR "cmd" OR "set " OR "add " OR "rm " OR "save ns config" OR "Com`). |
| UC-5.3.36 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 3 events: they lack the terms or fields it filters on (`index=netscaler (sourcetype="citrix:netscaler:syslog" OR sourcetype="citrix:netscaler:appflow") ("API" OR "openapi" OR swagger OR "json" OR "xml" OR t`). |
| UC-5.3.37 | failed | fixture defect | The event body is shared with 10 other fixtures (UC-5.3.23, UC-5.3.24, UC-5.3.25, UC-5.3.26 and 6 more); it is a generic template, not data for this search. The base search returns 0 of the 2 events: they lack the terms or fields it filters on (`index=netscaler (sourcetype="citrix:netscaler:syslog" OR sourcetype="citrix:netscaler:perf") ("pooled" OR "license pool" OR vCPU OR throughput OR enti`). |
| UC-5.3.38 | passed | passed | Row count, field and negative assertions hold. |
| UC-5.3.39 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-5.3.38, UC-5.3.40, UC-5.3.41, UC-5.3.42); it is a generic template, not data for this search. The base search matches the 2 events, then `where total_drops>0 OR dec_events>1000` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-5.3.40 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-5.3.38, UC-5.3.39, UC-5.3.41, UC-5.3.42); it is a generic template, not data for this search. The base search matches the 2 events, then `stats max(uin) as max_in, max(uout) as max_out, max(mbytes) as max_meter, sum(fo) as failover by _time, site_i` leaves 0 rows; the events carry no `link_id`, `role`, `state`. |
| UC-5.3.41 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-5.3.38, UC-5.3.39, UC-5.3.40, UC-5.3.42); it is a generic template, not data for this search. The base search matches the 2 events, then `stats latest(role) as cur_role, latest(tstate) as tun, sum(vtrans) as vrrp_events by _time, site_id, group_id` leaves 0 rows; the events carry no `group_id`. |
| UC-5.3.42 | failed | fixture defect | The event body is shared with 4 other fixtures (UC-5.3.38, UC-5.3.39, UC-5.3.40, UC-5.3.41); it is a generic template, not data for this search. The base search matches the 2 events, then `stats count as jobs, sum(ok) as okc, sum(fail) as failc, sum(nreach) as reach_fails, dc(target_appliance) as a` leaves 0 rows; the events carry no `change_set`. |
| UC-5.4.8 | passed | passed | Row count, field and negative assertions hold. |
| UC-9.1.2 | failed | fixture defect | Passes the row count (2 of 2). The SPL ends in `table _time, Account_Name, CallerComputerName`; the manifest asserts `EventCode`, which the search does not return. `Account_Name` is a Splunk_TA_windows extraction, absent in the lab. See FENRE_FINDINGS F-04. |
| UC-10.2.1 | passed | passed | Weak pass: `timechart ... by priority` returns one empty hourly row per bucket (49 rows, only a `NULL` series, because nothing extracts `priority` from the Snort line without an add-on); min_count 5 is met by empty buckets. |
| UC-10.6.194 | passed | passed | Row count, field and negative assertions hold. |
| UC-10.6.195 | passed | passed | Row count, field and negative assertions hold. |
| UC-10.6.196 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search matches the 3 events, then `where km_s=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-10.6.197 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search matches the 3 events, then `where priv=1 AND off=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-10.6.198 | failed | fixture defect | The event body is shared with 1 other fixture (UC-2.6.61); it is a generic template, not data for this search. The base search matches the 12 events, then `where wm_fail=1 OR cap_fail=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-10.6.199 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search matches the 3 events, then `where denied=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-10.6.200 | failed | fixture defect | The event body is shared with 14 other fixtures (UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33 and 10 more); it is a generic template, not data for this search. The base search matches the 3 events, then `where off=1 OR longsess=1` leaves 0 rows because the placeholder lacks the values it tests. |
| UC-12.1.1 | passed | passed | Weak pass: the GitHub JSON has its timestamp past the first 128 characters, so the 3 events are indexed at the current time and the 10-year fallback window makes `timechart span=1d` return 1000 empty rows (the row cap). |
| UC-13.1.15 | not_runnable | not runnable | The SPL starts with `multisearch` over `_internal` and uses `tstats` and `inputlookup`; their data cannot be redirected to the test index. |

## SUN defects found and fixed in this sprint

These came out of earlier campaign runs, before the numbers above.

| Found | Effect before | Fix (D-064) |
|---|---|---|
| A quoted `map`, `REST` or `audit` in a regex counted as a command | UC-2.6.38 and UC-5.3.35 `not_runnable` (D-054 code refused 12 of 94 SPLs before running; these 2 were wrong) | breakers are matched by command position on a quote-masked copy |
| The index rewrite changed `eval index=...` and any other `index=` text | wrong or broken test copy | rewrite touches search clauses only |
| Snort, ctime and `YYYY/MM/DD` timestamps were not read | UC-10.2.1: fixed 10-year window, `timechart` error "too many (>50000) rows", reported `inconclusive` | formats added; the window follows the events; a search error is `content_error` |
| A blank line inside an event split it | UC-1.2.6 sent 9 events (4 in the manifest), UC-9.1.2 sent 6 (2) | a block without a time continues the event |
| `expected.fields` and `max_count` were ignored | a fixture passed whatever the search returned | asserted, with Fenre's semantics |

## Reading the results

* `failed` with `0 rows` and a base search that matches nothing is almost always the
  fixture or the search, not the app. The evidence column says which, and where the
  rows stop.
* A pass is weak when the search can return rows without selecting data: `timechart`
  (UC-10.2.1, UC-12.1.1) and `coalesce` defaults (UC-2.6.48, 2.6.55, 2.6.74, 2.6.76). The
  evidence column says so for each.
* The campaign proves the verdict logic and the search/fixture agreement. It does not
  prove alerting, suppression or the schedule.

## Reproducing

```
UCM_SPLUNK_PASSWORD=... UCM_SPLUNK_VERIFY_TLS=0 \
  python3 tools/controltest_campaign.py --fenre <fenre checkout> --bisect --output results.json
python3 tools/controltest_campaign.py --report results.json --classification classification.json
```

`--static` checks scoping and window derivation without Splunk. `--delete` removes this
run's events with `| delete` (needs the `can_delete` role). The password is read from
the environment only.

## Cleanup

Each full run adds the 308 fixture events to the test index. After the campaign, the
sprint's own runs (all campaign runs, bisect copies, experiments and live tests, 1,775
events) were removed with `| delete` on `source="ucm-ct-*"`, using a temporary
`can_delete` role on the lab's `admin` that was reverted at once. `| delete` hides events;
it does not free disk. Five older events from the D-054 probes (`source` `probe` and
`ucm-probe-*`) were left. Operators who run control tests regularly should set a short
retention on the test index instead (D-064).

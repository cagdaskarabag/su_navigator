# Fenre content findings from the control-test campaign

Status: report for the product owner. **Nothing has been filed on the Fenre repository.**
This file is the working list; each entry has the evidence and a suggested fix, so an
issue can be written from it.

* Source: Fenre `main` at `0e21f019` (2026-11-23), `content/` and `samples/` (94 fixtures).
* Method: `tools/controltest_campaign.py` (SUNavigator 0.8.8, decision D-064) ran each
  fixture's events through the use case's own SPL on a lab with Splunk Enterprise 10.2.9
  and **no add-ons**. Per-fixture results, with the evidence for each verdict, are in
  [CONTROL_TEST_CAMPAIGN.md](CONTROL_TEST_CAMPAIGN.md).
* Reading the entries: "the search" is the SPL in Fenre's content. A defect is listed here
  only when it holds without any add-on, or when it was shown to hold with the add-on's
  fields emulated. Findings that need an add-on or a customer lookup are in the last
  section and are not defects.
* Splunk's `search` command does not evaluate eval functions; `match()` works in `where`
  and `eval` only (F-03 shows this on the lab).

| ID | Use cases | Defect | Kind |
|---|---|---|---|
| F-01 | UC-1.1.1 | Manifest cannot pass: the SPL returns one aggregated row with other column names | manifest vs SPL |
| F-02 | UC-1.1.8 | Fixture is below the SPL's own threshold, `min_count` is unreachable | fixture vs SPL |
| F-03 | UC-2.6.30, 31, 32, 33, 34, 35, 36, 38, 39, 40, 45, UC-5.3.23 | `match()` used as a search term, never matches | SPL |
| F-04 | UC-9.1.2, UC-4.1.2 | Manifest asserts a field the final `table` drops | manifest vs SPL |
| F-05 | UC-4.1.1 | SPL filters a value AWS does not emit; manifest disagrees | SPL |
| F-06 | UC-1.2.29 | Eval string `"\\"` is not a valid regex; Splunk rejects the search | SPL |
| F-07 | UC-2.6.44, UC-2.6.45 | `match()` called with three arguments | SPL |
| F-08 | UC-3.2.1 | `earliest=-6h@5m` is not a valid time modifier | SPL |
| F-09 | UC-2.6.58, 62, 66, 68 | `timechart` with two split-by fields; Splunk rejects the search | SPL |
| F-10 | 64 fixtures in 13 groups | One generic event template reused for unrelated use cases | fixtures |
| F-11 | UC-5.1.1 | Fixture gives one qualifying group; manifest expects three rows | fixture vs SPL |

---

## F-01 UC-1.1.1 "Sustained Linux CPU Utilization Above 90 Percent" (issue #6)

* Symptom: `failed`, 0 rows for 3 `cpu` events; 2 field assertions fail.
* Evidence, without the add-on: each fixture event is one `top`-style table
  (`cpu pctUser pctNice ... pctIdle` header, then `all`, `cpu0`, ... rows). The SPL
  filters `cpu=all` and needs `cpu_load_percent`, which nothing derives without
  `Splunk_TA_nix` (its field extraction). Stage-by-stage row counts are 0 from the base
  search on.
* Evidence, with the add-on's fields emulated: a temporary
  `EVAL-cpu_load_percent = 100 - pctIdle` on sourcetype `cpu` and key=value events
  (`cpu=all pctIdle=2.34 pctUser=85.12`, three of them). The SPL then returns **1** row
  (`stats ... by observed_host`, then `where avg_cpu_percent>90`), not the 3 the manifest
  expects (`min_count: 3`). Its columns are `observed_host`, `sample_count`,
  `avg_cpu_percent`, ...; the manifest asserts `host` (values `linux-prod-01`) and
  `pctIdle` (`max: 10`), neither of which the search returns. Lab, 2026-11-24;
  the temporary props were removed afterwards.
* Conclusion: not a SUNavigator defect and not only a missing add-on. The manifest's
  `expected` block describes raw events, not the search's output.
* Suggested fix: `min_count: 1`; assert the search's own columns
  (`observed_host` values `["linux-prod-01"]`, `avg_cpu_percent` `min: 90`). Say in the
  notes which add-on fields the SPL depends on (`cpu_load_percent`).

## F-02 UC-1.1.8 "SSH Brute-Force Detection"

* Symptom: `failed`, 0 rows; `min_count: 5`; `src` must match `^(10|172|192)\.`.
* Evidence: all 7 events index and match (7 rows after the base search, `rex`, `where`
  and `bin`). `stats ... by _time src host` gives **one** row (src `10.99.0.42`,
  `attempts=7`), and `where attempts > 10` removes it. The fixture has fewer failures than
  the search's threshold, and one source can produce at most one row per 5-minute bin, so
  `min_count: 5` cannot be met by this data.
* Suggested fix: at least 11 failed-password events from one source inside one 5-minute
  window, and `min_count: 1`.

## F-03 `match()` as a search term (12 use cases)

* Use cases: UC-2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36, 2.6.38, 2.6.39,
  2.6.40, 2.6.45, UC-5.3.23.
* Example (UC-2.6.30): `index=xd (sourcetype="citrix:broker:events" event_type=Provisioning*
  OR match(_raw, "(?i)identity|prep|snapshot|MCS|Provision")) OR (...)`. UC-2.6.39 has
  `| search match(_raw, "...")`.
* Evidence: lab check on Splunk 10.2.9 with two events in the test index, one containing
  "identity": `<base> | where match(_raw, "(?i)identity|MCS")` returns 1 row;
  `<base> match(_raw, "(?i)identity|MCS")`, `<base> (match(...) OR event_type=Foo)` and
  `<base> | search match(...)` return 0. No error is shown. The term also removes the
  rest of its group: with JSON events carrying `"ODataEntity": "Machines"`,
  `ODataEntity=Machine*` returns 2 and `(ODataEntity=Machine* OR match(_raw, "(?i)drain"))`
  returns 0 (UC-2.6.34 has exactly that clause). The search silently matches nothing in
  production.
* In 11 of the 12, none of the fixture events would match the pattern either (see F-10),
  so both defects have to be fixed.
* Suggested fix: move the test into `| where match(_raw, "...")` (or use a wildcarded
  term), and give the fixture events that contain it.

## F-04 Manifest asserts a field the final `table` drops (UC-9.1.2, UC-4.1.2)

* UC-9.1.2: SPL ends `| table _time, Account_Name, CallerComputerName`; manifest asserts
  `EventCode` values `["4740"]`. Rows are returned (2 of 2) and the row count passes; the
  field assertion fails: the rows have only `_time` on the lab (the Windows add-on extracts
  `Account_Name`; `EventCode` is not in the table at all).
* UC-4.1.2: SPL ends `| table _time userIdentity.arn eventName sourceIPAddress awsRegion`;
  manifest asserts `userIdentity.type` values `["Root"]`. Rows are returned (2 of 2).
* Suggested fix: assert a column the search returns (`CallerComputerName`,
  `userIdentity.arn`), or add the field to `table`.

## F-05 UC-4.1.1 "Unauthorized API Calls"

* Symptom: 2 rows, `min_count: 3`.
* Evidence: the SPL selects `errorCode="AccessDenied" OR errorCode="UnauthorizedAccess"
  OR errorCode="Client.UnauthorizedAccess"`. The manifest lists
  `AccessDenied`, `UnauthorizedAccess` and `Client.UnauthorizedOperation`, and the third
  fixture event carries the last one. AWS emits `Client.UnauthorizedOperation`, so the SPL
  value is wrong and misses real events as well as the fixture. The final `table` also
  drops `errorCode`, which the manifest asserts.
* Suggested fix: `errorCode="Client.UnauthorizedOperation"` in the SPL; add `errorCode` to
  the `table` or assert another column.

## F-06 UC-1.2.29 "Registry Run Key Modification (Persistence)"

* Symptom: Splunk refuses the search: `Error in 'EvalCommand': Regex: \ at end of pattern`.
* Evidence: the SPL has `replace(TargetObject,"^.*\\","")`. In an eval string `\\` is one
  backslash, so the regex ends in a lone backslash. The same applies to
  `replace(TargetObject,"\\[^\\]+$","")`. SUNavigator cannot deploy the search.
* Suggested fix: `"^.*\\\\"` and `"\\\\[^\\\\]+$"` (a regex backslash needs four in an
  eval string). The search also filters on `source=`, which the control test cannot scope
  (see the last section).

## F-07 `match()` with three arguments (UC-2.6.44, UC-2.6.45)

* UC-2.6.44: `| where match(VolumeName, "Cache|WCD|MCS|WriteCache|PVS|Differencing", "i")
  OR 1=1`. Splunk: "The arguments to the 'match' function are invalid."; the search cannot
  be deployed. UC-2.6.45 has `match(_raw, "(power.?on|start|registration|boot)", "i")`
  (and also F-03).
* Suggested fix: `match(x, "(?i)...")`. In UC-2.6.44 the `OR 1=1` makes the `where` keep
  everything; drop it or the `match`.

## F-08 UC-3.2.1 "Kubernetes pod restarts" (tstats)

* Symptom: Splunk refuses the search: `Error in 'TsidxStats': Invalid value "-6h@5m" for
  time term 'earliest'`.
* Evidence: `tstats ... WHERE ... earliest=-6h@5m latest=now ...`. A snap-to unit cannot
  carry a multiple.
* Suggested fix: `earliest=-6h@m` (or `-6h`), and bin to 5 minutes with `span=5m`.

## F-09 `timechart` with two split-by fields (UC-2.6.58, 2.6.62, 2.6.66, 2.6.68)

* Splunk refuses the search: `Error in 'timechart' command: The argument '<field>' is
  invalid.` The searches have `timechart span=1h count by reason, user_principal`,
  `... count by issue, store_name`, `... count by cat, plat`, `... count by action,
  outcome`. `timechart` takes one split-by field.
* Suggested fix: `bin _time span=1h | stats count by _time, reason, user_principal`, or
  combine the two fields into one before `timechart`.

## F-10 Generic fixtures reused across unrelated use cases (64 of 94 fixtures)

* Evidence: the first positive event of 64 fixtures is byte-identical, apart from
  `sourcetype` and `host`, to that of at least one other fixture. There are 13 such
  groups. Their searches filter on different terms, fields and values, so the events do
  not contain what the SPL needs (stage-by-stage counts show 0 rows at the base search or
  at the first `where`/`stats`). Of the 64, 41 fail for this reason alone, 16 also have an
  SPL defect (F-03 in 12, F-09 in 4), 3 cannot be scoped because they filter on `source=`,
  and 4 pass. Another 6 single fixtures (UC-2.6.42, 2.6.56, 2.6.57, 2.6.63, 2.6.78,
  2.6.79) are one-off placeholders of the same kind (`"msg": "synthetic Citrix ..."` and
  similar) that fail the same way.

| Fixtures | First event (start) | Use cases |
|---|---|---|
| 15 | `04/24/2026 08:15:00 AM EventType=LogonFailed MachineName=XD-VDA-00 UserName=jdoe ...` | UC-2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.35, 2.6.45, 2.6.47, 2.6.48, 2.6.49, 2.6.53, 2.6.75, UC-10.6.196, 10.6.197, 10.6.199, 10.6.200 |
| 11 | `Apr 24 08:15:00 citrix-lab-01 04/24/2026:08:15:00 GMT ... APPFW APPFW 123: CEF:0\|Citrix\|NetScaler...` | UC-5.3.23, 5.3.24, 5.3.25, 5.3.26, 5.3.27, 5.3.29, 5.3.32, 5.3.34, 5.3.35, 5.3.36, 5.3.37 |
| 5 | `04/24/2026 08:15:00 AM EventCode=1000 Source=Citrix ComputerName=citrix-lab-01 Message="Citrix service error: ...` | UC-2.6.38, 2.6.40, 2.6.41, 2.6.43, 2.6.54 |
| 5 | `{"_time": ..., "enrollment": "error", ...}` | UC-2.6.64, 2.6.65, 2.6.66, 2.6.68, 2.6.69 |
| 5 | `{"_time": ..., "actor": "u@ex.com", "action": "Download", "result": "fail", ...}` | UC-2.6.70, 2.6.71, 2.6.72, 2.6.73, 2.6.74 |
| 5 | `{"_time": ..., "site_id": "site-a", "path_name": "MPLS1", "loss_pct": 5.0, ...}` | UC-5.3.38, 5.3.39, 5.3.40, 5.3.41, 5.3.42 |
| 3 | `{"_time": ..., "ODataEntity": "Machines", ..."machine_name": "mcs-0", ...}` | UC-2.6.29, 2.6.34, 2.6.46 |
| 3 | `04/24/2026 08:15:00 AM EventType=ServiceRestart MachineName=XD-VDA-01 service=CtxCVdb ...` | UC-2.6.36, 2.6.39, 2.6.52 |
| 3 | `{"_time": ..., "user": "u1", "login_result": "fail", ...}` | UC-2.6.60, 2.6.62, 2.6.76 |
| 3 | `{"_time": ..., "appliance": "citrix-lab-01", "vserver": "vs-citrix-443", "rtt": 400, ...}` | UC-5.3.28, 5.3.30, 5.3.31 |
| 2 | `{"_time": ..., "user": "u1", "direction": "upload", "policy_result": "Block", ...}` | UC-2.6.61, UC-10.6.198 |
| 2 | `{"_time": ..., "proc_name": "winlogon", "unexpected_reboot": 1, ...}` | UC-2.6.37, 2.6.77 |
| 2 | `{"_time": ..., "risk_level": 80, ...}` | UC-2.6.58, 2.6.59 |

* Four fixtures pass only because of `coalesce` defaults (`unknown`, `Unknown`):
  UC-2.6.48, 2.6.55, 2.6.74, 2.6.76. A pass there says nothing about the data.
* Field names in some fixtures are not the ones the SPL reads: `EventType` against
  `event_type` (field names are case-sensitive), `machine_name` against `Name`,
  `ODataEntity` against `odata_resource`, `UserName` against `user`.
* Suggested fix: write the events of each fixture from the search's own filter terms and
  group-by fields (the ones named in its `stats ... by` and `where`), and set `min_count`
  to what the search's aggregation produces.

## F-11 UC-5.1.1 "Interface flapping"

* Symptom: 1 row, `min_count: 3`.
* Evidence: 7 events; the SPL ends `stats count by host, interface, state | where count > 3`
  and only `GigabitEthernet1/0/24` down (4 events) qualifies. The manifest expects 3 rows.
* Suggested fix: `min_count: 1`, or three interfaces with more than three events each.

---

## Not upstream defects (listed so they are not reported as such)

| UC | Verdict | Why |
|---|---|---|
| UC-5.2.3 | failed | `pan:threat` events are CSV; `severity`, `src`, `dest` come from `Splunk_TA_paloalto`, absent in the lab. Fails until the add-on is installed. |
| UC-1.2.4 | not_runnable | The SPL uses the lookup `windows_service_failure_policy.csv`, which the customer maintains; it does not exist on the lab. |
| UC-13.1.15 | not_runnable | Starts with `multisearch` over `_internal` and uses `tstats` and `inputlookup`; their data cannot be redirected to the test index. |
| UC-1.2.6, 2.6.28, 2.6.41, 2.6.43, 2.6.51, 2.6.54 | not_runnable | The SPL filters on `source=`; SUNavigator uses `source` as its per-run marker, so these cannot be scoped. A SUNavigator limitation, not Fenre's (D-064). |
| UC-10.2.1, UC-12.1.1 | passed (weak) | `timechart` returns empty buckets, which meet `min_count` without any data selected. Add assertions in the manifest. |

## What the lab showed about add-ons and `KV_MODE`

A second campaign run with `KV_MODE = json` on 38 sourcetypes gave the same verdict for
every fixture as the run without it: Splunk 10.2.9 extracts JSON events automatically
(`AUTO_KV_JSON`). The missing add-on matters only for key=value and CSV sourcetypes
(UC-1.1.1, UC-5.2.3, UC-9.1.2 columns), not for the JSON fixtures.

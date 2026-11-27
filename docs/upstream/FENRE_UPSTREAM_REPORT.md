# Fenre `splunk-monitoring-use-cases`: verified SPL and fixture defects

Prepared for the repository owner. Everything below was reproduced on a clean Splunk instance by running
Fenre's own content and fixtures. Each finding has the evidence, a self-contained reproduction and a suggested fix,
so it can be turned into an issue directly.

## 1. Summary

| | |
|---|---|
| Fenre revision tested | `main` at `0e21f01992` (2026-11-23): `content/` for the SPL, `samples/` for the 94 fixtures |
| Splunk | Enterprise 10.4.3, single instance (an independent earlier run on 10.2.9 gave the same results) |
| Method | Searches checked with Splunk's own search parser (`/services/search/parser`). Fixtures ingested into a throw-away index and the use case SPL run against them. Assertions evaluated with the same semantics as `scripts/run_uc_tests.py`. |
| Scope | 94 fixtures, plus the SPL of all 16,689 records (19,771 searches including `cimSpl`) |

What was found, in order of impact:

| ID | Use cases | Defect | Splunk behaviour |
|---|---|---|---|
| A | 80 use cases (12 with fixtures) | An eval function (`match`, `like`, `lower`, `isnotnull`, ...) is used as a search term | Accepted, **silently matches nothing** |
| B | 56 use cases | `timechart` with two split-by fields | Search rejected |
| C | UC-1.2.29, 1.2.66, 1.2.119 | Backslash escaping in `replace()` / `match()` regex | Search rejected |
| D | UC-2.6.44 | `match()` with three arguments in `where` | Search rejected |
| E | UC-3.2.1 | `earliest=-6h@5m` | Search rejected |
| F | UC-4.1.1 | Wrong AWS error code in the SPL (`Client.UnauthorizedAccess`) | Misses real events |
| G | 64 of 94 fixtures | One generic event reused across unrelated use cases | Fixtures cannot exercise the search |
| H | UC-1.1.1, 1.1.8, 5.1.1, 4.1.1, 4.1.2, 9.1.2 | Manifest cannot be satisfied by the search or fixture | Fixture test fails |

Fixture test outcome with the current content (positive fixtures only): 10 pass, 75 fail, 1 fails with a search error
(UC-1.2.4, missing lookup) and 8 are rejected by the parser. Of the 10 that pass, 4 (UC-2.6.48, 2.6.55, 2.6.74, 2.6.76) pass only because of
`coalesce` defaults and prove nothing about the data.

Findings A, B, C, D and E are deterministic and can be found without any fixture, so a parser check in CI would catch
them (see section 5).

---

## 2. Search defects (the SPL itself is wrong)

### A. Eval function used as a search term (80 use cases)

An eval function such as `match()` is only valid inside `eval`, `where` or `fieldformat`. Placed in the base search
or after `| search`, Splunk accepts the text, never evaluates it, and the clause matches no event. No error is shown.
Because the clause sits inside an `OR` group, **the whole group stops matching**.

Published example, UC-2.6.34:

```
index=xd (sourcetype="citrix:monitor:odata" (ODataEntity=Machine* OR match(_raw, "(?i)Maintenance|drain|suspend")))
```

Reproduction without any data (Splunk 10.4.3):

```
| makeresults | eval _raw="identity disk fail" | search match(_raw,"(?i)identity")
  -> 0 rows
| makeresults | eval _raw="identity disk fail" | where match(_raw,"(?i)identity")
  -> 1 row
| makeresults | eval _raw="identity disk fail", event_type="Foo" | search event_type=Foo
  -> 1 row
| makeresults | eval _raw="identity disk fail", event_type="Foo" | search (event_type=Foo OR match(_raw,"(?i)zzz"))
  -> 0 rows   (the working OR branch is lost as well)
| makeresults | eval msg="alpha" | search like(msg,"%alp%")        -> 0 rows
| makeresults | eval msg="alpha" | where  like(msg,"%alp%")        -> 1 row
```

The same holds for the other eval functions against indexed events: `like`, `lower`, `isnull`, `isnotnull`,
`cidrmatch`, `upper`.

Effect on a real use case (UC-2.6.34). One event that the use case is meant to detect, indexed in
`citrix:monitor:odata`: `{"ODataEntity":"Machines","MachineName":"vda1","InMaintenanceMode":"true","delivery_group":"dg1"}`.

| Search | Result |
|---|---|
| as published | 0 rows |
| `match()` moved to `\| where like(ODataEntity,"Machine%") OR match(_raw,"(?i)Maintenance\|drain\|suspend")` | rows returned |

UC-2.6.39 (`| search match(_raw, "...")`) behaves the same: 0 rows as published, 1 row with `| where match(...)`.

Count across the corpus: 80 use cases. By function: `match` 61, `like` 12, `lower` 5, `isnotnull` 4, `cidrmatch` 2,
`isnull` 2, `upper` 1 (some searches use more than one). 61 is higher than a text search for `match(` in the first
segment gives (51), because ten more carry the call inside a subsearch (`multisearch`, `append`, `join`).

Affected use cases:

UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33, UC-2.6.34, UC-2.6.35, UC-2.6.36, UC-2.6.38, UC-2.6.39, UC-2.6.40, UC-2.6.41, UC-2.6.42, UC-2.6.45, UC-2.6.51, UC-2.7.3, UC-2.8.11, UC-2.9.7, UC-2.9.12, UC-3.1.1, UC-3.1.2, UC-3.3.14, UC-5.2.43, UC-5.2.44, UC-5.2.45, UC-5.3.23, UC-5.4.35, UC-5.7.14, UC-5.7.18, UC-5.14.43, UC-7.1.52, UC-7.1.64, UC-7.1.81, UC-7.5.22, UC-9.2.12, UC-9.3.16, UC-9.5.4, UC-9.5.12, UC-10.11.102, UC-10.12.20, UC-10.13.11, UC-12.7.14, UC-13.1.2, UC-13.1.8, UC-13.1.12, UC-13.1.27, UC-13.2.7, UC-13.2.8, UC-13.2.16, UC-13.5.7, UC-13.5.12, UC-13.7.6, UC-14.6.20, UC-16.1.21, UC-18.2.3, UC-18.2.4, UC-18.2.11, UC-18.2.12, UC-18.2.13, UC-19.1.31, UC-21.1.8, UC-21.8.7, UC-21.10.1, UC-22.2.50, UC-22.2.51, UC-22.2.52, UC-22.2.53, UC-22.2.56, UC-22.5.7, UC-22.6.9, UC-22.9.4, UC-22.11.63, UC-22.13.47, UC-22.13.58, UC-22.14.53, UC-22.15.16, UC-22.15.42, UC-22.15.44, UC-22.27.28, UC-22.31.3, UC-23.4.1

Suggested fix: move the test into `| where` (or `| eval` plus `| where`), or use a wildcarded search term. Where
a fixture exists, give it events that actually contain the pattern: for 11 of the 12 use cases that have a fixture
(UC-2.6.30, 31, 32, 33, 34, 35, 36, 38, 39, 40, 45), no fixture event matches the pattern; UC-5.3.23 is the exception.

### B. `timechart` with two split-by fields (56 use cases)

`timechart` accepts exactly one `by` field. Splunk rejects the search:

```
Error in 'timechart' command: The argument 'user_principal' is invalid.
```

Reproduction (parser):

```
| makeresults | eval a=1,b=2 | timechart span=1h count by a, b     -> rejected
| makeresults | eval a=1,b=2 | timechart span=1h count by a b      -> rejected
| makeresults | eval a=1,b=2 | timechart span=1h count by a        -> accepted
sitimechart behaves the same
```

I extracted every `timechart` / `sitimechart` segment of the corpus and sent it to the parser on its own: exactly
56 use cases are rejected. The four with fixtures:

| UC | Segment |
|---|---|
| 2.6.58 | `timechart span=1h count by reason, user_principal` |
| 2.6.62 | `timechart span=5m count by issue, store_name` |
| 2.6.66 | `timechart span=1h count by cat, plat` |
| 2.6.68 | `timechart span=1h count by action, outcome` |

Some use cases separate the fields with a space (UC-15.4.4, UC-15.5.8: `by pdu_name outlet`); that is rejected the
same way. (For UC-7.1.24, another error comes first and hides this one in the parser output; the isolated
`timechart` segment is rejected too.)

Suggested fix: `| bin _time span=1h | stats count by _time, <f1>, <f2>` (verified to parse), or combine the two fields
into one before `timechart`.

All 56:

UC-2.6.58, UC-2.6.62, UC-2.6.66, UC-2.6.68, UC-6.1.22, UC-6.1.23, UC-6.1.27, UC-6.1.54, UC-6.1.77, UC-6.2.47, UC-6.4.12, UC-6.4.13, UC-6.4.15, UC-7.1.24, UC-7.2.16, UC-7.3.1, UC-7.3.9, UC-7.3.12, UC-7.3.16, UC-7.4.2, UC-7.4.11, UC-7.4.15, UC-7.4.17, UC-7.4.19, UC-7.4.20, UC-7.4.21, UC-7.5.6, UC-8.1.16, UC-8.1.75, UC-8.2.6, UC-8.2.11, UC-8.2.12, UC-8.2.13, UC-8.2.18, UC-8.3.1, UC-8.3.2, UC-8.3.11, UC-8.3.13, UC-8.3.15, UC-8.4.11, UC-8.4.17, UC-8.4.22, UC-8.4.31, UC-8.4.32, UC-8.4.37, UC-8.5.31, UC-8.5.37, UC-8.6.31, UC-13.1.16, UC-13.1.40, UC-13.2.36, UC-15.4.4, UC-15.5.8, UC-20.1.9, UC-20.2.17, UC-22.15.43

### C. Backslash escaping in regex arguments (UC-1.2.29, UC-1.2.66, UC-1.2.119)

In an eval string `\\` is one backslash, so `"^.*\\"` reaches the regex engine as `^.*\`, a pattern that ends in a lone
backslash.

```
UC-1.2.29, UC-1.2.119:  replace(TargetObject,"^.*\\","")
Error in 'EvalCommand': Regex: \ at end of pattern
```

Reproduction:

```
| makeresults | eval t="a", x=replace(t,"^.*\\","")        -> rejected
| makeresults | eval t="a", x=replace(t,"\\[^\\]+$","")    -> accepted (the second call in the same searches is fine)
| makeresults | eval t="a", x=replace(t,"^.*\\\\","")      -> accepted
```

The fix is verified functionally: `replace("HKLM\Software\...\Run\evil.exe","^.*\\\\","")` returns `evil.exe`.

UC-1.2.66 is the same class with a different symptom: `match(target_filename,"^.:\\users\\[^\\]+\\appdata\\...")`
unescapes to `\users`, and Splunk rejects it with `PCRE2 does not support \F, \L, \l, \N{name}, \U, or \u`.
To match a literal backslash, the regex needs `\\` and the eval string therefore needs four (`\\\\`): `\\\\users` for a literal `\users`.

Note that the `cimSpl` variants of UC-1.2.29 and UC-1.2.119 parse; only the `spl` field is affected.

### D. `match()` with three arguments (UC-2.6.44)

```
| where match(VolumeName, "Cache|WCD|MCS|WriteCache|PVS|Differencing", "i") OR 1=1
Error in 'where' command: The arguments to the 'match' function are invalid.
```

`match` takes two arguments in `where` and `eval`. Use `match(VolumeName, "(?i)Cache|WCD|...")`. The `OR 1=1` makes the
`where` keep every row; remove it or the `match`. UC-2.6.45 also uses a three-argument `match`, but inside a search
clause, where Splunk accepts and ignores it, so that use case is only an instance of finding A.

### E. Invalid time modifier (UC-3.2.1)

```
| tstats latest(Value) AS restart_cumulative WHERE ... earliest=-6h@5m latest=now ...
Error in 'TsidxStats': Invalid value "-6h@5m" for time term 'earliest'
```

A snap-to unit cannot carry a multiplier. Verified on Splunk 10.4.3:

| Modifier | Parser |
|---|---|
| `-6h@5m` | rejected |
| `-6h@m` | accepted (73 five-minute bins returned) |
| `-6h`, `-6h@h` | accepted |

A plain (non-tstats) search with `earliest=-6h@5m` is accepted by the parser but fails when run with the same
`Invalid value` error on 10.4.3. Suggested fix: `earliest=-6h@m` (or `-6h`), keeping `span=5m`.

### F. UC-4.1.1 filters an error code AWS does not emit

```
index=aws sourcetype="aws:cloudtrail" errorCode="AccessDenied" OR errorCode="UnauthorizedAccess" OR errorCode="Client.UnauthorizedAccess"
| table _time userIdentity.arn eventName sourceIPAddress awsRegion
```

AWS emits `Client.UnauthorizedOperation`, which the manifest itself lists and the third fixture event carries. With
the published SPL the fixture returns 2 rows (3 expected); with `errorCode="Client.UnauthorizedOperation"` it returns
3. The final `table` also drops `errorCode`, which the manifest asserts (see H).

---

## 3. Fixture and manifest defects

### G. One event template reused across unrelated use cases (64 of 94 fixtures)

The first positive event of 64 fixtures is identical, apart from `sourcetype` and `host`, to that of at least one other
fixture. There are 13 groups. The searches filter on different terms, fields and values, so the events do not contain
what the SPL needs: stage-by-stage row counts show 0 rows at the base search or at the first `where`/`stats`.

| Fixtures | Use cases |
|---|---|
| 15 | UC-2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.35, 2.6.45, 2.6.47, 2.6.48, 2.6.49, 2.6.53, 2.6.75, UC-10.6.196, 10.6.197, 10.6.199, 10.6.200 |
| 11 | UC-5.3.23, 5.3.24, 5.3.25, 5.3.26, 5.3.27, 5.3.29, 5.3.32, 5.3.34, 5.3.35, 5.3.36, 5.3.37 |
| 5 | UC-2.6.38, 2.6.40, 2.6.41, 2.6.43, 2.6.54 |
| 5 | UC-2.6.64, 2.6.65, 2.6.66, 2.6.68, 2.6.69 |
| 5 | UC-2.6.70, 2.6.71, 2.6.72, 2.6.73, 2.6.74 |
| 5 | UC-5.3.38, 5.3.39, 5.3.40, 5.3.41, 5.3.42 |
| 3 | UC-2.6.29, 2.6.34, 2.6.46 |
| 3 | UC-2.6.36, 2.6.39, 2.6.52 |
| 3 | UC-2.6.60, 2.6.62, 2.6.76 |
| 3 | UC-5.3.28, 5.3.30, 5.3.31 |
| 2 | UC-2.6.37, 2.6.77 |
| 2 | UC-2.6.58, 2.6.59 |
| 2 | UC-2.6.61, UC-10.6.198 |

Six more single fixtures (UC-2.6.42, 2.6.56, 2.6.57, 2.6.63, 2.6.78, 2.6.79) are one-off placeholders of the same
kind (`"msg": "synthetic Citrix ..."`) and fail the same way.

Field names in some fixtures are not the ones the SPL reads: `EventType` against `event_type` (field names are
case-sensitive), `machine_name` against `Name`, `ODataEntity` against `odata_resource`, `UserName` against `user`.

Four fixtures pass only because of `coalesce` defaults and give no signal: UC-2.6.48 (`app=Unknown, actor=unknown`),
UC-2.6.55 (`driver_version=unknown`), UC-2.6.74 (`users=0`), UC-2.6.76 (`dev/os/ver=unknown`). UC-10.2.1 and
UC-12.1.1 pass or can pass on empty `timechart` buckets (UC-10.2.1 returned 5,436 rows, all in an empty `NULL`
series). UC-12.1.1 events are indexed at the ingest time because the event timestamp is beyond the first 128
characters.

Suggested fix: write each fixture from the search's own filter terms and group-by fields (those named in its
`stats ... by` and `where`), and set `min_count` to what the search's aggregation produces. Where a test can pass on
defaults, assert on a value the data must supply.

### H. Manifests that the search or fixture cannot satisfy

**UC-1.1.1** (Sustained Linux CPU Utilization Above 90 Percent). Each fixture event is one multi-line `top`-style
table (`cpu pctUser ... pctIdle` header, then `all`, `cpu0`, ...). The SPL filters `cpu=all` and needs
`cpu_load_percent`, which nothing derives without `Splunk_TA_nix`; the stage counts are 0 from the first stage.
Even with the add-on's field emulated (key=value events and `cpu_load_percent = 100 - pctIdle`), the search returns
**one** aggregated row by `observed_host` (`avg_cpu_percent` 96.65), not the three the manifest expects, and its
columns are `observed_host`, `avg_cpu_percent`, `min_cpu_percent`, `max_cpu_percent`, `sample_count`, ... The
manifest asserts `host` and `pctIdle`, which the search does not return.
Suggested manifest: `min_count: 1`; `observed_host` values `["linux-prod-01"]`; `avg_cpu_percent` `min: 90`
(verified to pass). Say in the notes that the SPL depends on `cpu_load_percent`.

**UC-1.1.8** (SSH Brute-Force Detection). The seven failed-password events index and match, but
`stats ... by _time src host` after `bin _time span=5m` gives a single row (`attempts=7`) and `where attempts > 10`
removes it. Stage rows: 7, 7, 7, 7, 1, 0. One source can produce at most one row per 5-minute bin, so `min_count: 5`
cannot be met. With 11 failed-password events from one source in one 5-minute window the search returns 1 row
(with 10 events it returns none). Suggested: 11 or more events and `min_count: 1`.

**UC-5.1.1** (Interface flapping). The SPL ends `stats count by host, interface, state | where count > 3`. Only
`GigabitEthernet1/0/24` down (4 events) qualifies, so 1 row, not 3. Suggested: `min_count: 1`, or three interfaces
with more than three events each.

**UC-4.1.1**: see F (3 rows needed; `errorCode` dropped by `table`).

**UC-4.1.2**. The SPL ends `table _time userIdentity.arn eventName sourceIPAddress awsRegion`; the manifest asserts
`userIdentity.type`. Two rows are returned, but the column is not in the output. Assert `userIdentity.arn`, or add
`userIdentity.type` to the `table`.

**UC-9.1.2**. The SPL ends `table _time, Account_Name, CallerComputerName`; the manifest asserts `EventCode`, which
the table does not contain. Adding `EventCode` to the table makes the assertion pass. (Verified on a Splunk that has
`Splunk_TA_windows`: the rows still show only `_time`, so `Account_Name` and `CallerComputerName` do not come out
of this fixture either.)

---

## 4. Additional observation, needs the maintainers' judgement

Splunk_TA_windows contains the transform `ta-windows-fix-sourcetype`, which rewrites an incoming
`sourcetype=WinEventLog:Security` to `sourcetype=WinEventLog`; the event keeps `source=WinEventLog:Security`. On an
instance with the add-on, a search that filters `sourcetype="WinEventLog:Security"` (or `:System`) therefore selects
nothing. Observed here: the fixture for UC-2.6.50 returns 0 rows and UC-9.1.2 returns 0 rows with the published
`sourcetype` filter, and rows once the filter is `source="WinEventLog:Security"`.
A native Windows forwarder input also sets `sourcetype=WinEventLog` with the channel in `source`. 158 use cases
filter on `sourcetype="WinEventLog:..."`. I only verified this against the fixtures, not against a live forwarder, so
please treat it as a question rather than a confirmed defect.

---

## 5. Suggested CI check

All of A to E can be caught without data, with Splunk's parser, plus a lint for A (which the parser does not report):

* Send each `spl` and `cimSpl` to `POST /services/search/parser` with `parse_only=true` (the search must start with
  `search` or `|`). This rejects B, C, D and E. About a quarter of the corpus is rejected for unrelated reasons
  (macros and data models that are not installed), so filter on the error text:
  `The argument '...' is invalid` (timechart), `Regex: \ at end of pattern`, `The arguments to the '...' function are
  invalid`, `Invalid value "..." for time term`.
* For A: flag an eval function name (`match`, `like`, `lower`, `upper`, `isnull`, `isnotnull`, `cidrmatch`) followed by
  `(` in the first segment, in a `| search` segment, or inside a subsearch, outside quotes and outside
  `eval`/`where`/`stats`.
* In the fixture runner, report the number of rows returned by the base search so that placeholder fixtures show up.

## 6. How this was checked

* Searches: Splunk's search parser, in the `search` app namespace, for every `spl` and `cimSpl` in `content/`.
* Silent-failure probes (A): `makeresults` repros above and indexed test events, comparing the same condition as a
  search term and in `where`.
* Fixtures: each `positive.log` ingested into a dedicated index with the manifest's `sourcetype`, `host` and `source`;
  the search run with the index rewritten, inline `earliest`/`latest` removed, and the window opened to cover the
  events; results checked with the `min_count`/`values`/`regex`/`min`/`max` semantics from `scripts/run_uc_tests.py`.
  Row counts after each pipe stage were taken for every failing fixture and agree with the independent campaign for
  66 of the 75 failures; the other nine are use cases that filter on `source=` (outside the scope of the other tool)
  and the two TA-related cases in section 4.
* The corpus counts (A: 80 use cases, 61 of them with `match`; B: 56) were reproduced by an independent detector,
  not only by the tool that first reported them.

Out of scope for upstream (environment, not defects): UC-1.2.4 uses the customer-maintained lookup
`windows_service_failure_policy.csv`; UC-5.2.3 needs `Splunk_TA_paloalto` for `severity`, `src`, `dest`;
UC-13.1.15 is a multi-source search over `_internal`/`tstats`/`inputlookup`.

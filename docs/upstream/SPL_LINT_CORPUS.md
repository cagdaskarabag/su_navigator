# SPL lint over the Fenre and ESCU corpora (SUNavigator 0.8.9, D-065)

Status: working data for the product owner. **Nothing has been filed on the Fenre repository.**

* Source: Fenre `main` at `0e21f019` (16,689 records with SPL, 19,771 searches counting the CIM variants) and the ESCU
  package `DA-ESS-ContentUpdate` 6.11.1 (2,214 detections).
* Method: `python3 tools/spl_lint_corpus.py --fenre <checkout> --escu <package> --ids --output findings.json`. Every use
  case goes through the app's own provider and normalizer, then `splunk_ucm.spl.lint`. A search counts once per rule.
* Every rule fires only for a construct shown to be wrong on Splunk Enterprise 10.2.9 (evidence in D-065). The 61 searches
  flagged by `L002` to `L005` (56 + 1 + 3 + 1) were also sent to Splunk's own parser in the app's namespace on the lab
  (`/services/search/parser`): **all 61 were rejected**. `L001` is silent in the parser (Splunk accepts the search and
  returns nothing), so it is shown by the probes in D-065 instead.

| Rule | Meaning | Fenre searches | ESCU searches |
|---|---|---|---|
| L001 | eval function used as a search term (never evaluated) | 80 | 0 |
| L002 | `timechart`/`sitimechart` with more than one `by` field (Splunk rejects) | 56 | 0 |
| L003 | `match`/`like`/`cidrmatch` with the wrong number of arguments in an eval-style command (Splunk rejects) | 1 | 0 |
| L004 | regex for `match`/`replace` ending in one backslash after eval unescaping (Splunk rejects) | 3 | 0 |
| L005 | time modifier snapping to a number of units, `-6h@5m` (`tstats` rejects, a plain search selects nothing) | 1 | 0 |
| L006 | regex for `match`/`replace` with `\u`, `\U`, `\l`, `\L` or `\F` after eval unescaping (0.12.1; UC-1.2.29 and UC-1.2.66, both already flagged by L004, so no new searches) | 2 | 0 |

141 of the 19,771 Fenre searches have at least one finding; none of the ESCU searches has one.

`L001` by function (Fenre): `match` 61, `like` 12, `lower` 5, `isnotnull` 4, `cidrmatch` 2, `isnull` 2, `upper` 1.

## Difference from the assessment's counts (51 and 54)

The assessment counted with a text heuristic: `match(` in the first segment or in a `| search` segment, and
`timechart ... by a, b` with a comma. That heuristic gives 51 and 54 on this commit (reproduced). The lint is stricter
about structure and wider about forms, so its numbers are higher:

* `match` as a search term: **61** searches (not 51). The 10 more carry the call inside a subsearch (`multisearch`,
  `append` or `join`): UC-13.1.2, 13.1.8, 13.1.12, 13.2.7, 13.2.8, 13.5.7, 13.5.12, 13.7.6, 19.1.31, 3.3.14. The other eval
  functions used as search terms (`like`, `lower`, `isnotnull`, `cidrmatch`, `isnull`, `upper`) add 19 more searches, so
  `L001` is 80 searches in all.
* `timechart` with two split-by fields: **56** searches (not 54). UC-15.4.4 and UC-15.5.8 separate the fields with a space
  (`by pdu_name outlet`), which Splunk rejects in the same way as a comma (lab, 10.2.9).

## L001 eval function used as a search term

UC-2.6.30, UC-2.6.31, UC-2.6.32, UC-2.6.33, UC-2.6.34, UC-2.6.35, UC-2.6.36, UC-2.6.38, UC-2.6.39, UC-2.6.40, UC-2.6.41, UC-2.6.42, UC-2.6.45, UC-2.6.51, UC-2.7.3, UC-2.8.11, UC-2.9.7, UC-2.9.12, UC-3.1.1, UC-3.1.2, UC-3.3.14, UC-5.2.43, UC-5.2.44, UC-5.2.45, UC-5.3.23, UC-5.4.35, UC-5.7.14, UC-5.7.18, UC-5.14.43, UC-7.1.52, UC-7.1.64, UC-7.1.81, UC-7.5.22, UC-9.2.12, UC-9.3.16, UC-9.5.4, UC-9.5.12, UC-10.11.102, UC-10.12.20, UC-10.13.11, UC-12.7.14, UC-13.1.2, UC-13.1.8, UC-13.1.12, UC-13.1.27, UC-13.2.7, UC-13.2.8, UC-13.2.16, UC-13.5.7, UC-13.5.12, UC-13.7.6, UC-14.6.20, UC-16.1.21, UC-18.2.3, UC-18.2.4, UC-18.2.11, UC-18.2.12, UC-18.2.13, UC-19.1.31, UC-21.1.8, UC-21.8.7, UC-21.10.1, UC-22.2.50, UC-22.2.51, UC-22.2.52, UC-22.2.53, UC-22.2.56, UC-22.5.7, UC-22.6.9, UC-22.9.4, UC-22.11.63, UC-22.13.47, UC-22.13.58, UC-22.14.53, UC-22.15.16, UC-22.15.42, UC-22.15.44, UC-22.27.28, UC-22.31.3, UC-23.4.1

## L002 `timechart` with more than one split-by field

UC-2.6.58, UC-2.6.62, UC-2.6.66, UC-2.6.68, UC-6.1.22, UC-6.1.23, UC-6.1.27, UC-6.1.54, UC-6.1.77, UC-6.2.47, UC-6.4.12, UC-6.4.13, UC-6.4.15, UC-7.1.24, UC-7.2.16, UC-7.3.1, UC-7.3.9, UC-7.3.12, UC-7.3.16, UC-7.4.2, UC-7.4.11, UC-7.4.15, UC-7.4.17, UC-7.4.19, UC-7.4.20, UC-7.4.21, UC-7.5.6, UC-8.1.16, UC-8.1.75, UC-8.2.6, UC-8.2.11, UC-8.2.12, UC-8.2.13, UC-8.2.18, UC-8.3.1, UC-8.3.2, UC-8.3.11, UC-8.3.13, UC-8.3.15, UC-8.4.11, UC-8.4.17, UC-8.4.22, UC-8.4.31, UC-8.4.32, UC-8.4.37, UC-8.5.31, UC-8.5.37, UC-8.6.31, UC-13.1.16, UC-13.1.40, UC-13.2.36, UC-15.4.4, UC-15.5.8, UC-20.1.9, UC-20.2.17, UC-22.15.43

## L003 wrong argument count

UC-2.6.44

## L004 regex ending in a single backslash

UC-1.2.29, UC-1.2.66, UC-1.2.119 (7 calls in 3 searches).

## L005 invalid snap-to modifier

UC-3.2.1

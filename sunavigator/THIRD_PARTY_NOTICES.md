# Third-party notices

SUNavigator itself is licensed under the Apache License 2.0 (see `LICENSE` and `NOTICE`). The material below is third-party and keeps its own licence.

## 1. Fenre Splunk Monitoring Use Cases (MIT)

Source: <https://github.com/fenre/splunk-monitoring-use-cases>. Copyright (c) 2026 Fredrik Lima Sudmann.

What SUNavigator contains:

| Path | What | Shipped in the app package |
|---|---|---|
| `sunavigator/lib/splunk_ucm/content/fenre/uc.schema.json` | the use-case JSON schema, verbatim, fetched at the pinned commit (D-012) | yes |
| `tests/fixtures/fenre/content/` | sample use-case records, byte-identical to upstream (`tests/fixtures/fenre/README.md`) | no |

Use-case content that an operator imports from Fenre at run time is Fenre's, under the same licence. SUNavigator
reads it, normalises it and stores it in the KV Store; it does not change the upstream records.

Licence text (also in `tests/fixtures/fenre/LICENSE` and `sunavigator/lib/splunk_ucm/content/fenre/LICENSE`):

```
MIT License

Copyright (c) 2026 Fredrik Lima Sudmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 2. Splunk ES Content Update and `security_content` (Apache License 2.0)

Source: the ES Content Update app (`DA-ESS-ContentUpdate`) and <https://github.com/splunk/security_content>,
Copyright Splunk Inc., licensed under the Apache License, Version 2.0
(<https://www.apache.org/licenses/LICENSE-2.0>).

What SUNavigator contains: **no ESCU content**. The ESCU provider (`sunavigator/lib/splunk_ucm/content/escu/`) is
SUNavigator code that reads an ESCU package the operator supplies; the test fixtures in `tests/fixtures/escu/` are
written for SUNavigator (version `6.11.1-fixture`) and are not copies of ESCU files. Offline bundles built with
`tools/ucm_cli.py build-escu-bundle` contain ESCU detections and remain under the Apache
License 2.0; when you redistribute such a bundle, include that licence and keep Splunk's notices. With
`--security-content` the build also reads a checkout of the `security_content` repository on the build machine and
adds facts from it (data sources, supported add-ons and their Splunkbase links, drilldowns, risk entities, links to
test data, macro definitions, status). Those fields are Splunk's, under the same licence. SUNavigator ships none of
them and downloads none of the test data.

## 3. NIST control catalogues (public, U.S. Government work)

Source: the OSCAL content of the National Institute of Standards and Technology,
<https://github.com/usnistgov/oscal-content>, at commit `f0de6d8d8c059d374f15e0ae07508d82e370fc1d`.

| Path | What | Shipped in the app package |
|---|---|---|
| `sunavigator/lib/splunk_ucm/frameworks/data/controls/nist-800-53-5.2.0.json` | SP 800-53 Rev. 5.2.0: identifiers, titles, hierarchy, withdrawn flag | yes |
| `sunavigator/lib/splunk_ucm/frameworks/data/controls/nist-800-171-3.json` | SP 800-171 Rev. 3: the same fields | yes |
| `sunavigator/lib/splunk_ucm/frameworks/data/controls/nist-csf-2.0.json` | Cybersecurity Framework 2.0: the same fields, plus the one-sentence subcategory statement as its title | yes |
| `tools/control_catalogue_builder.py` | reduces an OSCAL catalogue to those fields; each file records the source URL and the SHA-256 of what was read | no |

NIST publications are works of the U.S. Government and are not subject to copyright in the United States; NIST asks that
they be attributed. No control text, guidance or assessment procedure is copied. Each file carries its attribution, and the
Coverage page shows it. SUNavigator is not endorsed by NIST, and a use case mapped to a control is not an assessment.

## 4. MITRE ATT&CK

`sunavigator/lib/splunk_ucm/frameworks/data/mitre_attack_*.json` are reduced copies of MITRE ATT&CK (identifiers, names,
tactic membership). MITRE ATT&CK®. © The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation, under <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>. Each
file carries this attribution.

## 5. Other applications studied

The 2026-11 product research looked at other Splunk apps (Security Essentials, Compliance Essentials, DataSense
Navigator, DIA, DDA, TrackUC, SA-DetectionInsights, Attack Path Intelligence and others). Several are
proprietary or all rights reserved. SUNavigator takes **ideas only** from them: no code, SPL, lookups, text, data or
images were copied, and nothing from them is in this repository.

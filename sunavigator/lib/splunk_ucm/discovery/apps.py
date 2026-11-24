"""Identify installed Splunk apps for add-on and premium-product requirements.

Installed apps expose their folder name, label and `[package] id` (splunkd
reports the latter as the `details` URL ``.../apps/id/<package id>``). None of
them carries the numeric Splunkbase id that provider records use, so ids are
resolved through ``SPLUNKBASE_APPS``.
"""

import re
from typing import Any, Dict, List, Tuple

# Splunkbase id -> (package id, Splunkbase title). Every pair was read from
# https://splunkbase.splunk.com/api/v1/app/<id>/ (`appid`, `title`). Ids whose
# provider name disagrees with the Splunkbase title are left out on purpose:
# matching them would report an unrelated app as the required add-on.
SPLUNKBASE_APPS: Dict[int, Tuple[str, str]] = {
    263: ("SplunkEnterpriseSecuritySuite", "Splunk Enterprise Security"),
    742: ("Splunk_TA_windows", "Splunk Add-on for Microsoft Windows"),
    833: ("Splunk_TA_nix", "Splunk Add-on for Unix and Linux"),
    1620: ("Splunk_TA_cisco-asa", "Splunk Add-on for Cisco ASA"),
    1621: ("Splunk_SA_CIM", "Splunk Common Information Model (CIM)"),
    1710: ("Splunk_TA_nessus", "Splunk Add-on for Tenable"),
    1809: ("splunk_app_stream", "Splunk App for Stream"),
    1876: ("Splunk_TA_aws", "Splunk Add-on for Amazon Web Services (AWS)"),
    1928: ("Splunk_TA_snow", "Splunk Add-on for ServiceNow"),
    2686: ("splunk_app_db_connect", "Splunk DB Connect"),
    2757: ("Splunk_TA_paloalto", "Palo Alto Networks Add-on for Splunk"),
    2806: ("Splunk_TA_okta", "Splunk Add-on for Okta"),
    2846: ("Splunk_TA_fortinet_fortigate", "Fortinet FortiGate Add-On for Splunk"),
    2890: ("Splunk_ML_Toolkit", "Splunk AI Toolkit"),
    2891: ("Splunk_TA_cyberark", "Splunk Add-on for CyberArk"),
    3088: ("Splunk_TA_google-cloudplatform", "Splunk Add-on for Google Cloud Platform"),
    3110: ("Splunk_TA_microsoft-cloudservices", "Splunk Add-on for Microsoft Cloud Services"),
    3215: ("splunk_TA_vmware", "Splunk Add-on for VMware"),
    3757: ("TA-MS-AAD", "Splunk Add on for Microsoft Azure"),
    4055: ("splunk_ta_o365", "Splunk Add-on for Microsoft Office 365"),
    4060: ("TA-tenable", "Tenable Add-On for Splunk"),
    5089: ("a9423324-b66a-11ea-8c1e-0281150c11dc", "Splunk Add-on for VMware Metrics"),
    5180: ("splunk-app-ar", "Splunk Operational Technology Intelligence (OTI)"),
    5580: ("Splunk_TA_cisco_meraki", "Cisco Meraki Add-on for Splunk"),
    5602: ("SA-VMWIndex-inframon", "Splunk Add-on for VMware Metrics Indexes"),
    5603: ("Splunk_TA_esxilogs", "Splunk Add-on for VMware ESXi Logs"),
    5640: ("SA-VMWIndex", "Splunk Add-on for VMware Indexes"),
    5641: ("TA-VMW-FieldExtractions", "Splunk Add-on for VMware Extractions"),
    5709: ("Splunk_TA_microsoft_sysmon", "Splunk Add-on for Sysmon"),
    5748: ("TA-cisco_cybervision", "Cisco Cyber Vision Splunk Add On"),
    6207: ("Splunk_TA_MS_Security", "Splunk Add-on for Microsoft Security"),
    6905: ("TA-nozomi-networks-universal-add-on", "Nozomi Networks Universal Add-on"),
}

PRODUCT_APPS = {
    "splunk enterprise security": ["SplunkEnterpriseSecuritySuite"],
    "enterprise security": ["SplunkEnterpriseSecuritySuite"],
    "splunk es": ["SplunkEnterpriseSecuritySuite"],
    "splunk it service intelligence": ["itsi", "SA-ITOA"],
    "splunk itsi": ["itsi", "SA-ITOA"],
    "itsi": ["itsi", "SA-ITOA"],
}

_DETAILS_RE = re.compile(r"^https://[a-z0-9.-]+/apps/id/([A-Za-z0-9_.-]{1,100})/?$")


def package_id(details: Any) -> str:
    """The `[package] id` splunkd embeds in an app's `details` URL, or ''."""
    m = _DETAILS_RE.match(str(details or "").strip())
    return m.group(1) if m else ""


def app_candidates(req: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(name, how) pairs to look up, in order; `how` says what produced the name."""
    value = (req.get("value") or "").strip()
    sb = (req.get("attributes") or {}).get("splunkbase_id")
    out: List[Tuple[str, str]] = []
    if isinstance(sb, int) and not isinstance(sb, bool) and sb in SPLUNKBASE_APPS:
        pkg, title = SPLUNKBASE_APPS[sb]
        out += [(pkg, "splunkbase_id"), (title, "splunkbase_id")]
    if value:
        out.append((value, "name"))
    out.extend((name, "product") for name in PRODUCT_APPS.get(value.lower(), []))
    return out


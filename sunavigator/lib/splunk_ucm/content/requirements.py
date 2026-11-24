"""Technical requirements derived from a canonical use case (shared by providers).

Requirements come from the SPL (static analysis) and from provider-structured
fields. Pure functions: the same use case and analysis always give the same list.
"""

import re
from typing import List, Optional, Set

from ..model.canonical import Requirement, UseCase
from ..spl.analysis import SplAnalysis

# Search-time fields present on every event; never a meaningful data requirement.
INTRINSIC_FIELDS = {"_time", "_indextime", "_raw", "source", "sourcetype", "host", "index",
                     "splunk_server", "linecount", "punct", "eventtype", "tag"}
SUMMARIES_ONLY = re.compile(r"summariesonly\s*=\s*(t|true|1)\b", re.IGNORECASE)


def req_id(req_type: str, value: str) -> str:
    return "%s:%s" % (req_type, value)


def derive_requirements(uc: UseCase, primary: Optional[SplAnalysis], cim_spl: str) -> List[Requirement]:
    reqs: List[Requirement] = []
    seen: Set[str] = set()

    def add(req: Requirement) -> None:
        if req.req_id not in seen:
            seen.add(req.req_id)
            reqs.append(req)

    if primary is not None:
        for v in primary.sourcetypes:
            if v.negated:
                continue
            note = "extracted from SPL" + (" (wildcard)" if v.wildcard else "")
            group = next((g for g in primary.sourcetype_groups if v.value in g), None)
            level, attrs = "required", {}
            if group and v.value not in primary.sole_sourcetypes:
                sole = [g for g in group if g in primary.sole_sourcetypes]
                if sole:
                    level, note = "recommended", note + "; alternative to " + ", ".join(sole)
                else:
                    attrs = {"any_of": group}
                    note += "; any of " + ", ".join(group)
            add(Requirement(req_id("sourcetype", v.value), "sourcetype", v.value, level,
                            "derived_spl", "low" if v.wildcard else "medium", note, attrs))
        for v in primary.indexes:
            if v.negated:
                continue
            # Upstream index names are deployment-local examples, not contracts.
            add(Requirement(req_id("index", v.value), "index", v.value, "informational",
                            "derived_spl", "low", "index in provider SPL is an example"))
        for dm in primary.datamodels:
            add(Requirement(req_id("cim_model", dm.split(".")[0]), "cim_model", dm.split(".")[0],
                            "required", "derived_spl", "medium", "data model referenced by SPL",
                            {"dataset": dm}))
        if primary.datamodels and SUMMARIES_ONLY.search(uc.spl):
            add(Requirement(req_id("datamodel_acceleration", primary.datamodels[0].split(".")[0]),
                            "datamodel_acceleration", primary.datamodels[0].split(".")[0],
                            "required", "derived_spl", "medium", "SPL uses summariesonly=t"))
        for name in primary.macros:
            add(Requirement(req_id("macro", name), "macro", name, "required", "derived_spl", "medium"))
        for name in primary.lookups:
            add(Requirement(req_id("lookup", name), "lookup", name, "required", "derived_spl", "medium"))
        for name in primary.eventtypes:
            add(Requirement(req_id("other", "eventtype=" + name), "other", "eventtype=" + name,
                            "required", "derived_spl", "medium", "eventtype referenced by SPL"))

    produced = primary.produced_fields if primary is not None else {}
    for field in uc.required_fields:
        made = produced.get(field)
        if made and not made["read_before"] and field not in INTRINSIC_FIELDS:
            # Created by the search itself; raw events are not expected to carry it.
            add(Requirement(req_id("field", field), "field", field, "informational", "provider_structured",
                            "medium", "derived_in_spl: produced by %s" % made["command"],
                            {"derived_in_spl": made["command"]}))
            continue
        level = "informational" if field in INTRINSIC_FIELDS else "required"
        add(Requirement(req_id("field", field), "field", field, level, "provider_structured", "high"))
    uses_dm = primary is not None and bool(primary.datamodels)
    for model in uc.cim_models:
        add(Requirement(req_id("cim_model", model), "cim_model", model,
                        "required" if uses_dm else "recommended", "provider_structured", "high",
                        "" if uses_dm else "used by the CIM variant (cimSpl)"))
    for addon in uc.addons:
        level = "required" if addon.role in ("primary", "data-source") else "recommended"
        if addon.role == "premium":
            level = "required"
        add(Requirement(req_id("addon", str(addon.splunkbase_id or addon.name)), "addon", addon.name,
                        level, "provider_structured", "high", addon.role,
                        {"splunkbase_id": addon.splunkbase_id, "min_version": addon.min_version}))
    for name in uc.premium_apps:
        add(Requirement(req_id("product", name), "product", name, "required", "provider_structured", "high"))
    if uc.splunk_versions:
        add(Requirement(req_id("version", "splunk"), "version", ",".join(uc.splunk_versions),
                        "informational", "provider_structured", "high", "validated Splunk versions"))
    for prereq in uc.prerequisite_use_cases:
        add(Requirement(req_id("other", "prerequisite=" + prereq), "other", "prerequisite=" + prereq,
                        "recommended", "provider_structured", "high", "prerequisite use case"))
    if not uc.spl and not cim_spl:
        add(Requirement(req_id("spl_validity", "missing"), "spl_validity", "missing", "critical",
                        "provider_structured", "high", "provider record has no SPL"))
    return reqs

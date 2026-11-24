"""Fenre sidecar (uc.schema.json 1.x) → canonical ``ucm.usecase/1``.

Deterministic: the same raw record, category and manifest produce the same
canonical object (``imported_at`` aside). Every upstream field is either mapped
or preserved verbatim in ``provider_extras``.
"""

import json
import os
import posixpath
import re
from typing import Any, Dict, List, Optional, Set

from ...model.canonical import (CRITICALITY_RANK, DIFFICULTIES, DOMAINS, AddonRef, Category,
                                FrameworkMapping, Provenance, Reference, Requirement, SplVariant,
                                UseCase)
from ...spl.analysis import SplAnalysis, analyze
from ...util import dedupe, safe_key, sha256_json
from ..provider import Normalizer, ProviderCategory, ProviderManifest, ProviderRecord
from ..validation import FieldContract, ValidationPolicy, is_safe_url

NORMALIZER_VERSION = "fenre-1.2.0"
PROVIDER = "fenre"

_DOMAIN_MAP_PATH = os.path.join(os.path.dirname(__file__), "domain_map.json")
_MITRE_TECHNIQUE = re.compile(r"^T(\d{4})(\.\d{3})?$")
_MITRE_TACTIC = re.compile(r"^TA\d{4}$")
_MITRE_NA = re.compile(r"^N/A \((.+)\)$")
_REGULATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# Search-time fields present on every event; never a meaningful data requirement.
_INTRINSIC_FIELDS = {"_time", "_indextime", "_raw", "source", "sourcetype", "host", "index",
                     "splunk_server", "linecount", "punct", "eventtype", "tag"}
_SUMMARIES_ONLY = re.compile(r"summariesonly\s*=\s*(t|true|1)\b", re.IGNORECASE)

# Fields mapped into canonical attributes; everything else goes to provider_extras.
_MAPPED = {
    "$schema", "id", "title", "description", "value", "criticality", "difficulty",
    "monitoringType", "splunkPillar", "subcategory", "securityDomain", "equipment",
    "detectionType", "industry", "products", "dataSources", "app", "splunkbaseApps",
    "premiumApps", "splunkVersions", "prerequisiteUseCases", "requiredFields", "cimModels",
    "dataModelAcceleration", "spl", "cimSpl", "splVariants", "implementation",
    "detailedImplementation", "visualization", "scriptExample", "mitreAttack", "compliance",
    "status", "splStatus", "lastReviewed", "reviewer", "references", "knownFalsePositives",
}

CONSUMED_FIELDS = (
    FieldContract("description", "string"), FieldContract("value", "string"),
    FieldContract("criticality", "string"), FieldContract("difficulty", "string"),
    FieldContract("monitoringType", "array", "string"), FieldContract("splunkPillar", "string"),
    FieldContract("subcategory", "string"), FieldContract("securityDomain", "string"),
    FieldContract("equipment", "array", "string"), FieldContract("products", "array", "string"),
    FieldContract("dataSources", "string"), FieldContract("app", "string"),
    FieldContract("splunkbaseApps", "array", "object"), FieldContract("premiumApps", "array"),
    FieldContract("splunkVersions", "array", "string"),
    FieldContract("prerequisiteUseCases", "array", "string"),
    FieldContract("requiredFields", "array", "string"), FieldContract("cimModels", "array", "string"),
    FieldContract("dataModelAcceleration", "string"), FieldContract("spl", "string"),
    FieldContract("cimSpl", "string"), FieldContract("splVariants", "array", "object"),
    FieldContract("implementation", "string"), FieldContract("detailedImplementation", "string"),
    FieldContract("visualization", "string"), FieldContract("scriptExample", "string"),
    FieldContract("mitreAttack", "array", "string"), FieldContract("compliance", "array", "object"),
    FieldContract("status", "string"), FieldContract("splStatus", "string"),
    FieldContract("lastReviewed", "string"), FieldContract("reviewer", "string"),
    FieldContract("references", "array", "object"), FieldContract("knownFalsePositives", "string"),
)


def fenre_validation_policy(max_record_bytes: int = 512 * 1024) -> ValidationPolicy:
    return ValidationPolicy(max_record_bytes=max_record_bytes, consumed=CONSUMED_FIELDS)


def load_domain_map(path: str = _DOMAIN_MAP_PATH) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _strs(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return dedupe(v.strip() for v in value if isinstance(v, str) and v.strip())


def _resolve_repo_path(record_path: str, link: str) -> str:
    """Resolve a link relative to the repository; '' if it escapes the root.

    Upstream uses both record-relative (``../cat-17-.../UC-17.1.71.json``) and
    repository-root-relative (``docs/guides/x.md``) links.
    """
    link = link.split("#", 1)[0].split("?", 1)[0]
    if not link or link.startswith("/"):
        return ""
    base = posixpath.dirname(record_path) if link.startswith(".") else ""
    resolved = posixpath.normpath(posixpath.join(base, link))
    if resolved.startswith("..") or resolved.startswith("/"):
        return ""
    return resolved


def _req_id(req_type: str, value: str) -> str:
    return "%s:%s" % (req_type, value)


def _regulation_id(item: Dict[str, Any]) -> str:
    """Stable regulation id. Upstream ``regulation`` mixes ids and display names
    ("NIST-800-53", "nist-800-53", "Cyber Essentials"); ``obligationRef``
    (``<id>@<version>#<clause>``) carries the registry id consistently."""
    ref = _s(item.get("obligationRef"))
    if "@" in ref and _REGULATION_ID.match(ref.split("@", 1)[0]):
        return ref.split("@", 1)[0]
    return re.sub(r"[^a-z0-9]+", "-", _s(item.get("regulation")).lower()).strip("-") or "unknown"


def category_key(category_id: str) -> str:
    return safe_key(PROVIDER, "cat-%02d" % int(category_id))


def content_key(record_id: str) -> str:
    return safe_key(PROVIDER, "UC-" + record_id)


class FenreNormalizer(Normalizer):
    version = NORMALIZER_VERSION

    def __init__(self, domain_map: Optional[Dict[str, Any]] = None):
        self.domain_map = domain_map or load_domain_map()

    def content_key(self, record_id: str) -> str:
        return content_key(record_id)

    def normalize_category(self, category: ProviderCategory, provider: str = PROVIDER) -> Category:
        meta = category.metadata or {}
        subs = []
        for sub in meta.get("subcategories") or []:
            if isinstance(sub, dict) and isinstance(sub.get("id"), str):
                subs.append({"id": sub["id"], "name": _s(sub.get("name")),
                             "use_case_count": sub.get("useCaseCount")
                             if isinstance(sub.get("useCaseCount"), int) else None})
        return Category(
            key=category_key(category.category_id), provider=provider,
            category_id=category.category_id, name=category.name, slug=category.slug,
            description=_s(meta.get("description")),
            domains=list(self.domain_map.get("categories", {}).get(category.category_id, ["other"])),
            subcategories=subs, upstream_count=category.upstream_count, tree_sha=category.tree_sha)

    def normalize(self, record: ProviderRecord, category: Category,
                  manifest: ProviderManifest, imported_at: str) -> UseCase:
        raw = record.raw
        rid = str(raw["id"])
        spl = _s(raw.get("spl"))
        cim_spl = _s(raw.get("cimSpl"))
        analyses = [analyze(q) for q in (spl, cim_spl) if q]
        primary: Optional[SplAnalysis] = analyses[0] if spl and analyses else None

        provenance = Provenance(
            provider=PROVIDER, provider_record_id=rid, provider_version=manifest.provider_version,
            source_ref=manifest.source_ref, source_url=record.source_url, source_path=record.path,
            source_hash=sha256_json(raw), source_blob_sha=record.blob_sha,
            source_schema="uc.schema.json@%s" % manifest.schema_version,
            imported_at=imported_at, normalizer_version=self.version)

        criticality = _s(raw.get("criticality")).lower()
        difficulty = _s(raw.get("difficulty")).lower()
        mappings, na_reasons = self._frameworks(raw)
        uc = UseCase(
            content_id="%s:UC-%s" % (PROVIDER, rid), key=content_key(rid), title=_s(raw.get("title")),
            provenance=provenance, description=_s(raw.get("description")),
            domains=self._domains(raw, category),
            category_key=category.key, category_name=category.name,
            subcategory=self._subcategory(raw, rid, category),
            tags=dedupe(_strs(raw.get("equipment")) + ([_s(raw["industry"])] if _s(raw.get("industry")) else [])
                        + ([_s(raw["detectionType"])] if _s(raw.get("detectionType")) else [])),
            criticality=criticality if criticality in CRITICALITY_RANK else "unknown",
            difficulty=difficulty if difficulty in DIFFICULTIES else "unknown",
            business_value=_s(raw.get("value")),
            products=_strs(raw.get("products")) or ["splunk-platform"],
            monitoring_types=_strs(raw.get("monitoringType")), pillar=_s(raw.get("splunkPillar")),
            data_sources_text=_s(raw.get("dataSources")),
            required_fields=_strs(raw.get("requiredFields")), cim_models=_strs(raw.get("cimModels")),
            datamodel_acceleration_text=_s(raw.get("dataModelAcceleration")),
            addons=self._addons(raw), addons_text=_s(raw.get("app")),
            premium_apps=self._premium(raw), splunk_versions=_strs(raw.get("splunkVersions")),
            prerequisite_use_cases=["%s:%s" % (PROVIDER, p) for p in _strs(raw.get("prerequisiteUseCases"))],
            spl=spl, cim_spl=cim_spl, spl_variants=self._variants(raw),
            macros=dedupe(m for a in analyses for m in a.macros),
            lookups=dedupe(lk for a in analyses for lk in a.lookups),
            instructions=_s(raw.get("implementation")),
            detailed_instructions=_s(raw.get("detailedImplementation")),
            visualization=_s(raw.get("visualization")), script_example=_s(raw.get("scriptExample")),
            framework_mappings=mappings, framework_na_reasons=na_reasons,
            review_status=_s(raw.get("status")) or "unknown", spl_status=_s(raw.get("splStatus")),
            last_reviewed=_s(raw.get("lastReviewed")), reviewer=_s(raw.get("reviewer")),
            references=self._references(raw, record.path), known_false_positives=_s(raw.get("knownFalsePositives")),
            provider_extras={k: v for k, v in raw.items() if k not in _MAPPED},
        )
        uc.requirements = self._requirements(uc, primary, cim_spl)
        return uc

    # -- helpers -----------------------------------------------------------
    def _domains(self, raw: Dict[str, Any], category: Category) -> List[str]:
        found: Set[str] = set(category.domains or ["other"])
        pillar = self.domain_map.get("pillar", {}).get(_s(raw.get("splunkPillar")))
        if pillar:
            found.add(pillar)
        sec = _s(raw.get("securityDomain"))
        if sec:
            found.add("security")
            mapped = self.domain_map.get("security_domain", {}).get(sec)
            if mapped:
                found.add(mapped)
        if len(found) > 1:
            found.discard("other")
        return [d for d in DOMAINS if d in found]

    @staticmethod
    def _subcategory(raw: Dict[str, Any], rid: str, category: Category) -> str:
        sub_id = _s(raw.get("subcategory")).split("#", 1)[0] or ".".join(rid.split(".")[:2])
        for sub in category.subcategories:
            if sub.get("id") == sub_id:
                return sub.get("name") or sub_id
        return sub_id

    @staticmethod
    def _addons(raw: Dict[str, Any]) -> List[AddonRef]:
        out = []
        for app in raw.get("splunkbaseApps") or []:
            if not isinstance(app, dict) or not _s(app.get("name")):
                continue
            app_id = app.get("id") if isinstance(app.get("id"), int) else None
            url = _s(app.get("url"))
            out.append(AddonRef(name=_s(app.get("name")), splunkbase_id=app_id,
                                min_version=_s(app.get("minVersion")), role=_s(app.get("role")),
                                url=url if is_safe_url(url) else ""))
        return out

    @staticmethod
    def _premium(raw: Dict[str, Any]) -> List[str]:
        names = []
        for item in raw.get("premiumApps") or []:
            if isinstance(item, str):
                names.append(item.strip())
            elif isinstance(item, dict) and _s(item.get("name")):
                names.append(_s(item.get("name")))
        return dedupe(n for n in names if n)

    @staticmethod
    def _variants(raw: Dict[str, Any]) -> List[SplVariant]:
        out = []
        for v in raw.get("splVariants") or []:
            if isinstance(v, dict) and _s(v.get("model")) and _s(v.get("spl")):
                out.append(SplVariant(model=_s(v["model"]), spl=_s(v["spl"]),
                                      sourcetypes=_strs(v.get("sourcetypes")),
                                      cim_spl=_s(v.get("cimSpl")),
                                      addon_id=v.get("splunkbaseAppId")
                                      if isinstance(v.get("splunkbaseAppId"), int) else None))
        return out

    @staticmethod
    def _references(raw: Dict[str, Any], record_path: str) -> List[Reference]:
        out = []
        for ref in raw.get("references") or []:
            if not isinstance(ref, dict):
                continue
            url = _s(ref.get("url"))
            title, retrieved = _s(ref.get("title")), _s(ref.get("retrieved"))
            if is_safe_url(url):
                out.append(Reference(url=url, title=title, retrieved=retrieved))
            elif url and ":" not in url.split("/", 1)[0]:
                repo_path = _resolve_repo_path(record_path, url)
                if repo_path:
                    out.append(Reference(url="", title=title, retrieved=retrieved, repo_path=repo_path))
        return out

    @staticmethod
    def _frameworks(raw: Dict[str, Any]):
        mappings: List[FrameworkMapping] = []
        na: List[str] = []
        for value in _strs(raw.get("mitreAttack")):
            tech = _MITRE_TECHNIQUE.match(value)
            if tech:
                # ATT&CK ICS technique ids are T08xx; Enterprise ids are T1xxx.
                domain = "ics" if tech.group(1).startswith("0") else "enterprise"
                mappings.append(FrameworkMapping(
                    framework="mitre_attack", object_id=value,
                    object_type="sub-technique" if tech.group(2) else "technique", domain=domain))
            elif _MITRE_TACTIC.match(value):
                mappings.append(FrameworkMapping(framework="mitre_attack", object_id=value,
                                                 object_type="tactic"))
            else:
                match = _MITRE_NA.match(value)
                na.append(match.group(1) if match else value)
        seen = set()
        for item in raw.get("compliance") or []:
            if not isinstance(item, dict) or not _s(item.get("regulation")) or not _s(item.get("clause")):
                continue
            reg_id = _regulation_id(item)
            version = _s(item.get("version")) or None
            ident = (reg_id, _s(item["clause"]), version)
            if ident in seen:
                continue
            seen.add(ident)
            attributes = {k: item[k] for k in ("mode", "assurance", "obligationRef")
                          if isinstance(item.get(k), (str, bool))}
            attributes["regulation_label"] = _s(item["regulation"])
            mappings.append(FrameworkMapping(
                framework="regulation:" + reg_id, object_id=_s(item["clause"]),
                object_type="control", framework_version=version, attributes=attributes))
        return mappings, na

    def _requirements(self, uc: UseCase, primary: Optional[SplAnalysis], cim_spl: str) -> List[Requirement]:
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
                add(Requirement(_req_id("sourcetype", v.value), "sourcetype", v.value, "required",
                                "derived_spl", "low" if v.wildcard else "medium",
                                "extracted from SPL" + (" (wildcard)" if v.wildcard else "")))
            for v in primary.indexes:
                if v.negated:
                    continue
                # Upstream index names are deployment-local examples, not contracts.
                add(Requirement(_req_id("index", v.value), "index", v.value, "informational",
                                "derived_spl", "low", "index in provider SPL is an example"))
            for dm in primary.datamodels:
                add(Requirement(_req_id("cim_model", dm.split(".")[0]), "cim_model", dm.split(".")[0],
                                "required", "derived_spl", "medium", "data model referenced by SPL",
                                {"dataset": dm}))
            if primary.datamodels and _SUMMARIES_ONLY.search(uc.spl):
                add(Requirement(_req_id("datamodel_acceleration", primary.datamodels[0].split(".")[0]),
                                "datamodel_acceleration", primary.datamodels[0].split(".")[0],
                                "required", "derived_spl", "medium", "SPL uses summariesonly=t"))
            for name in primary.macros:
                add(Requirement(_req_id("macro", name), "macro", name, "required", "derived_spl", "medium"))
            for name in primary.lookups:
                add(Requirement(_req_id("lookup", name), "lookup", name, "required", "derived_spl", "medium"))
            for name in primary.eventtypes:
                add(Requirement(_req_id("other", "eventtype=" + name), "other", "eventtype=" + name,
                                "required", "derived_spl", "medium", "eventtype referenced by SPL"))

        produced = primary.produced_fields if primary is not None else {}
        for field in uc.required_fields:
            made = produced.get(field)
            if made and not made["read_before"] and field not in _INTRINSIC_FIELDS:
                # Created by the search itself; raw events are not expected to carry it.
                add(Requirement(_req_id("field", field), "field", field, "informational", "provider_structured",
                                "medium", "derived_in_spl: produced by %s" % made["command"],
                                {"derived_in_spl": made["command"]}))
                continue
            level = "informational" if field in _INTRINSIC_FIELDS else "required"
            add(Requirement(_req_id("field", field), "field", field, level, "provider_structured", "high"))
        uses_dm = primary is not None and bool(primary.datamodels)
        for model in uc.cim_models:
            add(Requirement(_req_id("cim_model", model), "cim_model", model,
                            "required" if uses_dm else "recommended", "provider_structured", "high",
                            "" if uses_dm else "used by the CIM variant (cimSpl)"))
        for addon in uc.addons:
            level = "required" if addon.role in ("primary", "data-source") else "recommended"
            if addon.role == "premium":
                level = "required"
            add(Requirement(_req_id("addon", str(addon.splunkbase_id or addon.name)), "addon", addon.name,
                            level, "provider_structured", "high", addon.role,
                            {"splunkbase_id": addon.splunkbase_id, "min_version": addon.min_version}))
        for name in uc.premium_apps:
            add(Requirement(_req_id("product", name), "product", name, "required", "provider_structured", "high"))
        if uc.splunk_versions:
            add(Requirement(_req_id("version", "splunk"), "version", ",".join(uc.splunk_versions),
                            "informational", "provider_structured", "high", "validated Splunk versions"))
        for prereq in uc.prerequisite_use_cases:
            add(Requirement(_req_id("other", "prerequisite=" + prereq), "other", "prerequisite=" + prereq,
                            "recommended", "provider_structured", "high", "prerequisite use case"))
        if not uc.spl and not cim_spl:
            add(Requirement(_req_id("spl_validity", "missing"), "spl_validity", "missing", "critical",
                            "provider_structured", "high", "provider record has no SPL"))
        return reqs

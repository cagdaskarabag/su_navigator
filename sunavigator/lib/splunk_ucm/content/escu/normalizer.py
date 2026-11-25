"""ESCU detections (Splunk Enterprise Security Content Update) → canonical ``ucm.usecase/1`` (T-22, D-053).

Records come from ``package.build_bundle`` as ``ucm-content-bundle`` v1 entries,
one JSON document per correlation search. Deterministic: the same raw record,
category and manifest give the same canonical object (``imported_at`` aside).
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from ...catalog.quality import ordered as ordered_flags
from ...model.canonical import DOMAINS, Category, FrameworkMapping, Provenance, UseCase
from ...spl.analysis import SplAnalysis, analyze
from ...util import dedupe, safe_key, sha256_json
from ..provider import Normalizer, ProviderCategory, ProviderManifest, ProviderRecord
from ...model.canonical import Requirement
from ..requirements import derive_requirements, req_id
from .enrich import macro_sourcetype
from ..validation import FieldContract, ValidationPolicy

PROVIDER = "escu"
NORMALIZER_VERSION = "escu-1.2.0"
_MITRE_TECHNIQUE = re.compile(r"^T(\d{4})(\.\d{3})?$")
ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
SCHEMA_VERSION = "1.0"
PRODUCT = "Splunk Enterprise Security"

# (category_id, slug, name, canonical domains). Ids are fixed so re-imports keep category keys.
CATEGORIES: Tuple[Tuple[str, str, str, Tuple[str, ...]], ...] = (
    ("1", "endpoint", "Endpoint", ("endpoint",)),
    ("2", "network", "Network", ("network",)),
    ("3", "threat", "Threat", ("security",)),
    ("4", "identity", "Identity", ("identity",)),
    ("5", "access", "Access", ("identity",)),
    ("6", "audit", "Audit", ("observability",)),
    ("7", "unassigned", "Unassigned", ("other",)),
)
CATEGORY_BY_SLUG = {slug: (cid, name, domains) for cid, slug, name, domains in CATEGORIES}
_CRITICALITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

CONSUMED_FIELDS = (
    FieldContract("stanza", "string"), FieldContract("description", "string"),
    FieldContract("search", "string"), FieldContract("securityDomain", "string"),
    FieldContract("severity", "string"), FieldContract("detectionType", "string"),
    FieldContract("type", "string"), FieldContract("analyticStories", "array", "string"),
    FieldContract("dataSources", "array", "string"), FieldContract("mitreAttack", "array", "string"),
    FieldContract("cis20", "array", "string"), FieldContract("nist", "array", "string"),
    FieldContract("cve", "array", "string"), FieldContract("killChainPhases", "array", "string"),
    FieldContract("schedule", "object"), FieldContract("status", "string"),
    FieldContract("dataSourceDetails", "array", "object"), FieldContract("supportedTA", "array", "object"),
    FieldContract("drilldowns", "array", "object"), FieldContract("riskEntities", "array", "object"),
    FieldContract("tests", "array", "object"), FieldContract("macroDefinitions", "object"),
    FieldContract("howToImplement", "string"), FieldContract("knownFalsePositives", "string"),
)

ESCU_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ESCU correlation search record (ucm escu record)",
    "version": SCHEMA_VERSION,
    "type": "object",
    "required": ["id", "title", "search"],
    "properties": {
        "id": {"type": "string"}, "title": {"type": "string"}, "search": {"type": "string"},
        "description": {"type": "string"}, "stanza": {"type": "string"},
        "securityDomain": {"type": "string"}, "severity": {"type": "string"},
        "detectionType": {"type": "string"}, "type": {"type": "string"},
        "analyticStories": {"type": "array", "items": {"type": "string"}},
        "dataSources": {"type": "array", "items": {"type": "string"}},
        "mitreAttack": {"type": "array", "items": {"type": "string"}},
        "schedule": {"type": "object"},
        "status": {"type": "string", "enum": ["production", "experimental", "deprecated"]},
        "dataSourceDetails": {"type": "array", "items": {"type": "object"}},
        "supportedTA": {"type": "array", "items": {"type": "object"}},
        "drilldowns": {"type": "array", "items": {"type": "object"}},
        "riskEntities": {"type": "array", "items": {"type": "object"}},
        "tests": {"type": "array", "items": {"type": "object"}},
        "macroDefinitions": {"type": "object"},
        "howToImplement": {"type": "string"}, "knownFalsePositives": {"type": "string"},
    },
}


def escu_validation_policy(max_record_bytes: int = 512 * 1024) -> ValidationPolicy:
    return ValidationPolicy(id_field="id", id_pattern=ID_PATTERN, title_field="title",
                            max_record_bytes=max_record_bytes, spl_fields=("search",), url_fields=(),
                            consumed=CONSUMED_FIELDS)


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _strs(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return dedupe(v.strip() for v in value if isinstance(v, str) and v.strip())


def content_key(record_id: str) -> str:
    return safe_key(PROVIDER, "UC-" + record_id)


class EscuNormalizer(Normalizer):
    version = NORMALIZER_VERSION

    def content_key(self, record_id: str) -> str:
        return content_key(record_id)

    def normalize_category(self, category: ProviderCategory, provider: str = PROVIDER) -> Category:
        meta = category.metadata or {}
        slug = category.slug or category.path.rsplit("/", 1)[-1]
        _, _, domains = CATEGORY_BY_SLUG.get(slug, CATEGORY_BY_SLUG["unassigned"])
        return Category(
            key=safe_key(PROVIDER, "cat-" + slug), provider=provider, category_id=category.category_id,
            name=category.name, slug=slug, description=_s(meta.get("description")),
            domains=[d for d in DOMAINS if d in domains], subcategories=[],
            upstream_count=category.upstream_count, tree_sha=category.tree_sha)

    def normalize(self, record: ProviderRecord, category: Category,
                  manifest: ProviderManifest, imported_at: str) -> UseCase:
        raw = record.raw
        rid = _s(raw["id"])
        spl = _s(raw.get("search"))
        analysis: Optional[SplAnalysis] = analyze(spl) if spl else None
        stories = _strs(raw.get("analyticStories"))
        provenance = Provenance(
            provider=PROVIDER, provider_record_id=rid, provider_version=manifest.provider_version,
            source_ref=manifest.source_ref, source_url=record.source_url, source_path=record.path,
            source_hash=sha256_json(raw), source_blob_sha=record.blob_sha,
            source_schema="escu-record@%s" % SCHEMA_VERSION, imported_at=imported_at,
            normalizer_version=self.version)
        schedule = raw.get("schedule") if isinstance(raw.get("schedule"), dict) else None
        uc = UseCase(
            content_id="%s:UC-%s" % (PROVIDER, rid), key=content_key(rid), title=_s(raw.get("title")),
            provenance=provenance, description=_s(raw.get("description")),
            domains=list(category.domains), category_key=category.key, category_name=category.name,
            subcategory=stories[0] if stories else "", tags=stories, analytic_stories=stories,
            data_sources=_strs(raw.get("dataSources")),
            criticality=_CRITICALITY.get(_s(raw.get("severity")).lower(), "unknown"),
            products=[PRODUCT], monitoring_types=[t for t in [_s(raw.get("type"))] if t],
            data_sources_text=", ".join(_strs(raw.get("dataSources"))),
            spl=spl, macros=list(analysis.macros) if analysis else [],
            lookups=list(analysis.lookups) if analysis else [],
            schedule=schedule, review_status="released", reviewer="Splunk Threat Research Team",
            framework_mappings=self._frameworks(raw),
            provider_extras={"stanza": _s(raw.get("stanza")), "detectionVersion": raw.get("detectionVersion"),
                             "publishTime": raw.get("publishTime"), "enabled": raw.get("enabled"),
                             "detectionType": _s(raw.get("detectionType")), "cis20": _strs(raw.get("cis20")),
                             "nist": _strs(raw.get("nist")), "cve": _strs(raw.get("cve")),
                             "killChainPhases": _strs(raw.get("killChainPhases")),
                             "securityDomain": _s(raw.get("securityDomain")),
                             **self._extras(raw)},
        )
        uc.instructions = _s(raw.get("howToImplement"))
        uc.known_false_positives = _s(raw.get("knownFalsePositives"))
        uc.requirements = derive_requirements(uc, analysis, "")
        self._data_requirements(uc, raw)
        flags = ["unbounded_index"] if analysis is not None and analysis.unbounded_index else []
        if _s(raw.get("status")) == "deprecated":
            flags.append("deprecated_upstream")
        uc.quality_flags = ordered_flags(flags)
        return uc

    @staticmethod
    def _extras(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Optional security_content fields (Sprint 16); absent from records built without it."""
        out: Dict[str, Any] = {}
        for key in ("status", "howToImplement", "knownFalsePositives"):
            if _s(raw.get(key)):
                out[key] = _s(raw[key])
        for key in ("supportedTA", "dataSourceDetails", "drilldowns", "riskEntities", "tests"):
            if isinstance(raw.get(key), list) and raw[key]:
                out[key] = [v for v in raw[key] if isinstance(v, dict)]
        if isinstance(raw.get("macroDefinitions"), dict) and raw["macroDefinitions"]:
            out["macroDefinitions"] = {k: v for k, v in raw["macroDefinitions"].items()
                                       if isinstance(k, str) and isinstance(v, str)}
        return out

    @staticmethod
    def _data_requirements(uc: UseCase, raw: Dict[str, Any]) -> None:
        """Sourcetypes and event types the data sources and macro definitions name (recommended, not required)."""
        have = {r.req_id for r in uc.requirements}

        def add(req: Requirement) -> None:
            if req.req_id not in have:
                have.add(req.req_id)
                uc.requirements.append(req)

        for src in raw.get("dataSourceDetails") or []:
            if not isinstance(src, dict):
                continue
            sourcetype = _s(src.get("sourcetype"))
            if not sourcetype:
                continue
            add(Requirement(req_id("sourcetype", sourcetype), "sourcetype", sourcetype, "recommended",
                            "provider_structured", "medium", "data source: %s" % _s(src.get("name"))))
            field, value = _s(src.get("separator")), _s(src.get("separatorValue"))
            if field and value:
                add(Requirement(req_id("event_condition", "%s|%s=%s" % (sourcetype, field, value)),
                                "event_condition", "%s=%s" % (field, value), "recommended", "provider_structured",
                                "low", "events of this type in %s (data source: %s)" % (sourcetype, _s(src.get("name"))),
                                {"sourcetype": sourcetype, "field": field, "value": value}))
        definitions = raw.get("macroDefinitions") if isinstance(raw.get("macroDefinitions"), dict) else {}
        for name in sorted(definitions):
            sourcetype = macro_sourcetype(definitions[name]) if isinstance(definitions[name], str) else ""
            if sourcetype:
                add(Requirement(req_id("sourcetype", sourcetype), "sourcetype", sourcetype, "recommended",
                                "provider_structured", "medium", "macro `%s` is defined as sourcetype=%s" % (name, sourcetype)))

    @staticmethod
    def _frameworks(raw: Dict[str, Any]) -> List[FrameworkMapping]:
        out = []
        for value in _strs(raw.get("mitreAttack")):
            tech = _MITRE_TECHNIQUE.match(value)
            if not tech:
                continue
            out.append(FrameworkMapping(
                framework="mitre_attack", object_id=value,
                object_type="sub-technique" if tech.group(2) else "technique",
                domain="ics" if tech.group(1).startswith("0") else "enterprise"))
        return out

"""Lantern article extraction (``sun.lantern.article/1``) -> canonical ``ucm.usecase/1``.

Deterministic like the Fenre normalizer: the stored raw extraction always
rebuilds the same use case, so readiness, validation, deployment and reindex
work on Lantern content through the shared ``normalizer_for`` path.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Set

from ...model.canonical import (DOMAINS, AddonRef, Category, FrameworkMapping, Provenance, Reference,
                                Requirement, SplVariant, UseCase)
from ...spl.analysis import analyze
from ...util import dedupe, safe_key
from ..provider import Normalizer, ProviderCategory, ProviderManifest, ProviderRecord
from ..validation import FieldContract, ValidationPolicy
from .urls import path_segments, segment_label

PROVIDER = "lantern"
NORMALIZER_VERSION = "lantern-1.0.0"
ID_PATTERN = r"^LN-[0-9a-f]{20}$"

_DOMAIN_MAP_PATH = os.path.join(os.path.dirname(__file__), "domain_map.json")
_MITRE_TECHNIQUE = re.compile(r"^T(\d{4})(\.\d{3})?$")
# Product names that readiness can verify through PRODUCT_APPS.
_VERIFIABLE_PRODUCTS = {"splunk enterprise security", "enterprise security", "splunk es",
                        "splunk it service intelligence", "splunk itsi", "itsi"}

CONSUMED_FIELDS = (
    FieldContract("source_url", "string"), FieldContract("description", "string"),
    FieldContract("business_value", "string"), FieldContract("breadcrumbs", "array", "object"),
    FieldContract("section_path", "array", "string"), FieldContract("tags", "array", "string"),
    FieldContract("classifications", "object"), FieldContract("products", "array", "string"),
    FieldContract("addons", "array", "object"), FieldContract("data_sources", "array", "string"),
    FieldContract("prerequisites", "array", "string"), FieldContract("implementation", "string"),
    FieldContract("spl_blocks", "array", "object"), FieldContract("dashboards", "array", "object"),
    FieldContract("related_articles", "array", "object"), FieldContract("resources", "array", "object"),
    FieldContract("mitre", "array", "string"), FieldContract("blocks", "array", "object"),
    FieldContract("content_hash", "string"), FieldContract("extraction", "object"),
)


def lantern_validation_policy(max_record_bytes: int = 1024 * 1024) -> ValidationPolicy:
    return ValidationPolicy(id_pattern=ID_PATTERN, max_record_bytes=max_record_bytes, spl_fields=(),
                            url_fields=("resources", "related_articles"), consumed=CONSUMED_FIELDS)


def load_domain_map(path: str = _DOMAIN_MAP_PATH) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _strs(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def _objs(value: Any) -> List[Dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _req_id(req_type: str, value: str) -> str:
    return "%s:%s" % (req_type, value)


def content_key(record_id: str) -> str:
    return safe_key(PROVIDER, record_id)


def section_slug(raw: Dict[str, Any]) -> str:
    segments = path_segments(_s(raw.get("source_url")))
    top = segments[0] if len(segments) > 1 else "General"
    return re.sub(r"[^a-z0-9]+", "-", top.lower()).strip("-")[:60] or "general"


def section_segment(raw: Dict[str, Any]) -> str:
    segments = path_segments(_s(raw.get("source_url")))
    return segments[0] if len(segments) > 1 else "General"


def section_name(raw: Dict[str, Any]) -> str:
    crumbs = _objs(raw.get("breadcrumbs"))
    if crumbs and _s(crumbs[0].get("title")):
        return _s(crumbs[0].get("title"))
    return segment_label(section_segment(raw))


def category_key(slug: str) -> str:
    return safe_key(PROVIDER, "cat-" + slug)


class LanternNormalizer(Normalizer):
    version = NORMALIZER_VERSION

    def __init__(self, domain_map: Optional[Dict[str, Any]] = None):
        self.domain_map = domain_map or load_domain_map()

    def content_key(self, record_id: str) -> str:
        return content_key(record_id)

    def section_domains(self, segment: str) -> List[str]:
        return list(self.domain_map.get("sections", {}).get(segment, ["other"]))

    def normalize_category(self, category: ProviderCategory, provider: str = PROVIDER) -> Category:
        meta = category.metadata or {}
        return Category(
            key=category_key(category.category_id), provider=provider, category_id=category.category_id,
            name="Splunk Lantern: " + category.name, slug=category.slug,
            description=_s(meta.get("description")) or "Articles imported from Splunk Lantern.",
            domains=self.section_domains(_s(meta.get("segment"))), upstream_count=None,
            tree_sha=category.tree_sha)

    def normalize(self, record: ProviderRecord, category: Category,
                  manifest: ProviderManifest, imported_at: str) -> UseCase:
        raw = record.raw
        rid = str(raw["id"])
        blocks = [b for b in _objs(raw.get("spl_blocks")) if _s(b.get("spl"))]
        primary = _s(blocks[0]["spl"]) if len(blocks) == 1 else ""
        variants = []
        if len(blocks) > 1:
            for idx, block in enumerate(blocks, 1):
                section = _s(block.get("section")).split(" > ")[-1] if _s(block.get("section")) else ""
                analysis = analyze(_s(block["spl"]))
                variants.append(SplVariant(
                    model=("Search %d: %s" % (idx, section)) if section else "Search %d" % idx,
                    spl=_s(block["spl"]),
                    sourcetypes=[v.value for v in analysis.sourcetypes if not v.negated]))
        analyses = [analyze(_s(b["spl"])) for b in blocks]
        extraction = raw.get("extraction") if isinstance(raw.get("extraction"), dict) else {}
        import_info = raw.get("import") if isinstance(raw.get("import"), dict) else {}
        source_url = _s(raw.get("source_url"))
        content_hash = _s(raw.get("content_hash"))

        provenance = Provenance(
            provider=PROVIDER, provider_record_id=rid, provider_version=_s(raw.get("extraction_version")),
            source_ref=content_hash[:12], source_url=source_url,
            source_path="/" + "/".join(path_segments(source_url)), source_hash=content_hash,
            source_blob_sha=record.blob_sha or content_hash, source_schema=_s(raw.get("schema")),
            imported_at=imported_at, normalizer_version=self.version)

        section_path = _strs(raw.get("section_path"))
        subcategory = section_path[1] if len(section_path) > 1 else ""
        mitre = [m for m in _strs(raw.get("mitre")) if _MITRE_TECHNIQUE.match(m)]
        mappings = [FrameworkMapping(framework="mitre_attack", object_id=m,
                                     object_type="sub-technique" if "." in m else "technique",
                                     domain="ics" if m[1] == "0" else "enterprise",
                                     attributes={"source": "derived_text"}) for m in mitre]
        retrieved = _s(raw.get("retrieved_at"))[:10]
        references = [Reference(url=source_url, title="Original article on Splunk Lantern", retrieved=retrieved)]
        for item in _objs(raw.get("related_articles")) + _objs(raw.get("resources")):
            if _s(item.get("url")).startswith("https://"):
                references.append(Reference(url=_s(item["url"]), title=_s(item.get("title")), retrieved=retrieved))

        uc = UseCase(
            content_id="%s:%s" % (PROVIDER, rid), key=content_key(rid), title=_s(raw.get("title")),
            provenance=provenance, description=_s(raw.get("description")),
            domains=self._domains(raw, category), category_key=category.key, category_name=category.name,
            subcategory=subcategory,
            tags=dedupe(_strs(raw.get("tags"))),
            criticality="unknown", difficulty="unknown",
            business_value=_s(raw.get("business_value")),
            products=_strs(raw.get("products")),
            data_sources_text="\n".join(_strs(raw.get("data_sources"))),
            addons=self._addons(raw), addons_text="",
            spl=primary, cim_spl="", spl_variants=variants,
            macros=dedupe(m for a in analyses for m in a.macros),
            lookups=dedupe(lk for a in analyses for lk in a.lookups),
            instructions=_s(raw.get("implementation")),
            detailed_instructions="",
            visualization="\n".join(_s(d.get("title")) for d in _objs(raw.get("dashboards")) if _s(d.get("title"))),
            framework_mappings=mappings, framework_na_reasons=[],
            review_status="unknown", spl_status="extracted" if blocks else "none",
            last_reviewed=_s(raw.get("modified")), reviewer="",
            references=references, known_false_positives="",
            provider_extras={"lantern": {
                "source_title": _s(raw.get("title")),
                "source_url": source_url,
                "source_retrieved_at": _s(raw.get("retrieved_at")),
                "source_content_hash": content_hash,
                "source_last_updated": _s(raw.get("modified")),
                "source_published": _s(raw.get("published")),
                "extraction_version": _s(raw.get("extraction_version")),
                "extraction_confidence": _s(extraction.get("confidence")) or "low",
                "extraction_score": extraction.get("score"),
                "needs_review": bool(extraction.get("needs_review")),
                "warnings": _strs(extraction.get("warnings")),
                "imported_by": _s(import_info.get("imported_by")),
                "imported_at": _s(import_info.get("imported_at")),
                "found_in": _objs(import_info.get("found_in")),
                "page_type": _s(raw.get("page_type")),
                "article_type": _s(raw.get("article_type")),
                "authors": _s(raw.get("authors")),
                "breadcrumbs": _objs(raw.get("breadcrumbs")),
                "section_path": section_path,
                "classifications": raw.get("classifications") if isinstance(raw.get("classifications"), dict) else {},
                "prerequisites": _strs(raw.get("prerequisites")),
                "data_sources": _strs(raw.get("data_sources")),
                "dashboards": _objs(raw.get("dashboards")),
                "related_articles": _objs(raw.get("related_articles")),
                "resources": _objs(raw.get("resources")),
                "internal_links": _objs(raw.get("internal_links")),
                "spl_blocks": blocks,
                "code_block_count": raw.get("code_block_count", 0),
                "blocks": _objs(raw.get("blocks")),
            }},
        )
        uc.requirements = self._requirements(raw, analyses)
        return uc

    def _domains(self, raw: Dict[str, Any], category: Category) -> List[str]:
        found: Set[str] = set(category.domains or self.section_domains(section_segment(raw)))
        text = " %s %s %s " % (_s(raw.get("title")), " ".join(_strs(raw.get("products"))),
                               " ".join(_strs(raw.get("data_sources"))))
        text = text.lower()
        for domain, words in self.domain_map.get("keywords", {}).items():
            if domain in DOMAINS and any(w in text for w in words):
                found.add(domain)
        if len(found) > 1:
            found.discard("other")
        return sorted(found) or ["other"]

    @staticmethod
    def _addons(raw: Dict[str, Any]) -> List[AddonRef]:
        out: List[AddonRef] = []
        seen: Set[str] = set()
        for item in _objs(raw.get("addons")):
            name = _s(item.get("name"))
            sb = _s(item.get("splunkbase_id"))
            ident = sb or name.lower()
            if not name or ident in seen:
                continue
            seen.add(ident)
            out.append(AddonRef(name=name, splunkbase_id=int(sb) if sb.isdigit() else None,
                                role=_s(item.get("role")), url=_s(item.get("url"))))
        return out

    def _requirements(self, raw: Dict[str, Any], analyses: List[Any]) -> List[Requirement]:
        reqs: List[Requirement] = []
        seen: Set[str] = set()

        def add(req: Requirement) -> None:
            if req.req_id not in seen:
                seen.add(req.req_id)
                reqs.append(req)

        # Several searches in one article are alternatives or steps, so their
        # data needs are weaker evidence than a single primary search.
        spl_conf = "medium" if len(analyses) == 1 else "low"
        for analysis in analyses:
            for v in analysis.sourcetypes:
                if not v.negated:
                    add(Requirement(_req_id("sourcetype", v.value), "sourcetype", v.value, "required",
                                    "derived_spl", "low" if v.wildcard else spl_conf,
                                    "extracted from the article's SPL"))
            for v in analysis.indexes:
                if not v.negated and not v.wildcard:
                    add(Requirement(_req_id("index", v.value), "index", v.value, "informational",
                                    "derived_spl", "low", "index named in the article's SPL"))
            for dm in analysis.datamodels:
                model = dm.split(".")[0]
                add(Requirement(_req_id("cim_model", model), "cim_model", model, "required", "derived_spl",
                                spl_conf))
            for name in analysis.macros:
                add(Requirement(_req_id("macro", name), "macro", name, "required", "derived_spl", spl_conf))
            for name in analysis.lookups:
                add(Requirement(_req_id("lookup", name), "lookup", name, "required", "derived_spl", spl_conf))
        for text in _strs(raw.get("data_sources"))[:30]:
            add(Requirement(_req_id("data_source", text[:200]), "data_source", text[:200], "required",
                            "derived_text", "medium", "listed in the article's data section"))
        for item in _objs(raw.get("addons")):
            name = _s(item.get("name"))
            if not name:
                continue
            structured = _s(item.get("source")) == "classification"
            level = "required" if _s(item.get("role")) == "primary" else "recommended"
            sb = _s(item.get("splunkbase_id"))
            add(Requirement(_req_id("addon", sb or name), "addon", name, level,
                            "provider_structured" if structured else "derived_text",
                            "high" if structured else "medium",
                            "article classification" if structured else "linked from the article",
                            {"splunkbase_id": int(sb)} if sb.isdigit() else {}))
        applies_to = {v.lower() for v in _strs((raw.get("classifications") or {}).get("Applies To"))}
        for name in _strs(raw.get("products")):
            if name.lower() in _VERIFIABLE_PRODUCTS:
                structured = name.lower() in applies_to
                add(Requirement(_req_id("product", name), "product", name, "required",
                                "provider_structured" if structured else "derived_text",
                                "high" if structured else "medium"))
        return reqs

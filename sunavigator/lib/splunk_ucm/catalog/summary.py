"""Projection of a canonical use case into the searchable ``uc_catalog`` document."""

from typing import Any, Dict

from ..model.canonical import CRITICALITY_RANK, UseCase
from ..storage.collections import DOC_SCHEMA
from ..util import dedupe, truncate

STATUS_ACTIVE = "active"
STATUS_WITHDRAWN = "withdrawn"


def sort_key_for(record_id: str) -> str:
    """Zero-padded numeric key so ``1.2.10`` sorts after ``1.2.9``."""
    parts = []
    for part in record_id.split("."):
        parts.append(part.zfill(6) if part.isdigit() else part)
    return ".".join(parts)


# Bump when catalog_summary gains or changes fields; the upgrade migration
# re-derives older summaries from stored raw records (no network).
SUMMARY_VERSION = 2


def catalog_summary(uc: UseCase) -> Dict[str, Any]:
    sourcetypes = [r.value for r in uc.requirements if r.type == "sourcetype"]
    for variant in uc.spl_variants:
        sourcetypes.extend(variant.sourcetypes)
    sourcetypes = dedupe(sourcetypes)
    datamodels = dedupe(r.value for r in uc.requirements if r.type == "cim_model")
    indexes = [r.value for r in uc.requirements if r.type == "index"]
    mitre = [m.object_id for m in uc.framework_mappings if m.framework == "mitre_attack"]
    frameworks = dedupe(m.framework for m in uc.framework_mappings)
    controls = dedupe("%s#%s" % (m.framework, m.object_id) for m in uc.framework_mappings
                      if m.framework != "mitre_attack" and m.object_id)[:300]
    addons = dedupe(a.name for a in uc.addons)
    search_text = " ".join([uc.provenance.provider_record_id, uc.content_id, uc.title,
                            " ".join(sourcetypes), " ".join(uc.tags), " ".join(mitre)]).lower()
    return {
        "_key": uc.key,
        "doc_schema": DOC_SCHEMA,
        "summary_version": SUMMARY_VERSION,
        "content_id": uc.content_id,
        "provider": uc.provenance.provider,
        "record_id": uc.provenance.provider_record_id,
        "title": uc.title,
        "summary": truncate(uc.description or uc.business_value, 300),
        "domains": uc.domains,
        "category_key": uc.category_key,
        "category_name": uc.category_name,
        "subcategory": uc.subcategory,
        "criticality": uc.criticality,
        "criticality_rank": CRITICALITY_RANK.get(uc.criticality, 0),
        "difficulty": uc.difficulty,
        "monitoring_types": uc.monitoring_types,
        "pillar": uc.pillar,
        "products": uc.products,
        "tags": uc.tags,
        "sourcetypes": sourcetypes,
        "indexes": indexes,
        "datamodels": datamodels,
        "addons": addons,
        "premium_apps": uc.premium_apps,
        "mitre_ids": mitre,
        "frameworks": frameworks,
        "framework_controls": controls,
        "has_spl": bool(uc.spl or uc.cim_spl),
        "requirement_count": len(uc.requirements),
        "review_status": uc.review_status,
        "provider_status": STATUS_ACTIVE,
        "provider_version": uc.provenance.provider_version,
        "source_ref": uc.provenance.source_ref,
        "source_hash": uc.provenance.source_hash,
        "source_blob_sha": uc.provenance.source_blob_sha,
        "normalizer_version": uc.provenance.normalizer_version,
        "imported_at": uc.provenance.imported_at,
        "sort_key": sort_key_for(uc.provenance.provider_record_id),
        "search_text": search_text,
    }

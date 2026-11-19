"""Provider-independent canonical content model (``ucm.usecase/1``).

Provider-owned content only. Customer-owned state (selection, readiness,
deployment, local overrides) is deliberately absent and lives in separate
collections keyed by ``content_id``.
"""

import dataclasses
from typing import Any, Dict, List, Optional

USECASE_SCHEMA = "ucm.usecase/1"
CATEGORY_SCHEMA = "ucm.category/1"

DOMAINS = (
    "security", "infrastructure", "network", "application", "database", "cloud",
    "endpoint", "identity", "ot_ics", "observability", "compliance", "business", "other",
)
CRITICALITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
DIFFICULTIES = ("beginner", "intermediate", "advanced", "expert", "unknown")

REQUIREMENT_TYPES = (
    "data_source", "index", "sourcetype", "field", "event_condition", "freshness",
    "addon", "product", "cim_model", "datamodel_acceleration", "spl_validity",
    "permission", "macro", "lookup", "version", "other",
)
REQUIREMENT_LEVELS = ("critical", "required", "recommended", "informational")
# provider_structured: an explicit structured field in the provider record.
# derived_spl: extracted from SPL by static analysis.
# derived_text: extracted from free text.
REQUIREMENT_SOURCES = ("provider_structured", "derived_spl", "derived_text", "local")
CONFIDENCE = ("high", "medium", "low")


@dataclasses.dataclass
class Requirement:
    req_id: str
    type: str
    value: str
    level: str = "required"
    source: str = "provider_structured"
    confidence: str = "high"
    notes: str = ""
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in REQUIREMENT_TYPES:
            raise ValueError("unknown requirement type: %s" % self.type)
        if self.level not in REQUIREMENT_LEVELS:
            raise ValueError("unknown requirement level: %s" % self.level)
        if self.source not in REQUIREMENT_SOURCES:
            raise ValueError("unknown requirement source: %s" % self.source)
        if self.confidence not in CONFIDENCE:
            raise ValueError("unknown confidence: %s" % self.confidence)


@dataclasses.dataclass
class FrameworkMapping:
    framework: str  # e.g. "mitre_attack"
    object_id: str  # e.g. "T1078.004"
    object_type: str  # tactic | technique | sub-technique | control | requirement
    framework_version: Optional[str] = None
    domain: Optional[str] = None  # enterprise | ics | mobile (resolved in WP6)
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Reference:
    url: str  # absolute http(s) URL or "" when only repo_path is known
    title: str = ""
    retrieved: str = ""
    repo_path: str = ""  # provider-repository-relative path, displayed as text


@dataclasses.dataclass
class AddonRef:
    name: str
    splunkbase_id: Optional[int] = None
    min_version: str = ""
    role: str = ""
    url: str = ""


@dataclasses.dataclass
class SplVariant:
    model: str
    spl: str
    sourcetypes: List[str] = dataclasses.field(default_factory=list)
    cim_spl: str = ""
    addon_id: Optional[int] = None


@dataclasses.dataclass
class Provenance:
    provider: str
    provider_record_id: str
    provider_version: str
    source_ref: str
    source_url: str
    source_path: str
    source_hash: str
    source_blob_sha: str
    source_schema: str
    imported_at: str
    normalizer_version: str


@dataclasses.dataclass
class UseCase:
    content_id: str
    key: str
    title: str
    provenance: Provenance
    description: str = ""
    # classification
    domains: List[str] = dataclasses.field(default_factory=list)
    category_key: str = ""
    category_name: str = ""
    subcategory: str = ""
    tags: List[str] = dataclasses.field(default_factory=list)
    criticality: str = "unknown"
    difficulty: str = "unknown"
    business_value: str = ""
    products: List[str] = dataclasses.field(default_factory=list)
    monitoring_types: List[str] = dataclasses.field(default_factory=list)
    pillar: str = ""
    # technical requirements
    requirements: List[Requirement] = dataclasses.field(default_factory=list)
    data_sources_text: str = ""
    required_fields: List[str] = dataclasses.field(default_factory=list)
    cim_models: List[str] = dataclasses.field(default_factory=list)
    datamodel_acceleration_text: str = ""
    addons: List[AddonRef] = dataclasses.field(default_factory=list)
    addons_text: str = ""
    premium_apps: List[str] = dataclasses.field(default_factory=list)
    splunk_versions: List[str] = dataclasses.field(default_factory=list)
    prerequisite_use_cases: List[str] = dataclasses.field(default_factory=list)
    # implementation
    spl: str = ""
    cim_spl: str = ""
    spl_variants: List[SplVariant] = dataclasses.field(default_factory=list)
    macros: List[str] = dataclasses.field(default_factory=list)
    lookups: List[str] = dataclasses.field(default_factory=list)
    instructions: str = ""
    detailed_instructions: str = ""
    visualization: str = ""
    script_example: str = ""
    schedule: Optional[Dict[str, Any]] = None
    # frameworks
    framework_mappings: List[FrameworkMapping] = dataclasses.field(default_factory=list)
    framework_na_reasons: List[str] = dataclasses.field(default_factory=list)
    # quality and provenance
    review_status: str = "unknown"
    spl_status: str = ""
    last_reviewed: str = ""
    reviewer: str = ""
    references: List[Reference] = dataclasses.field(default_factory=list)
    known_false_positives: str = ""
    provider_extras: Dict[str, Any] = dataclasses.field(default_factory=dict)
    schema_version: str = USECASE_SCHEMA

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def requirement_values(self, req_type: str) -> List[str]:
        return [r.value for r in self.requirements if r.type == req_type]


@dataclasses.dataclass
class Category:
    key: str
    provider: str
    category_id: str
    name: str
    slug: str = ""
    description: str = ""
    domains: List[str] = dataclasses.field(default_factory=list)
    subcategories: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    upstream_count: Optional[int] = None
    tree_sha: str = ""
    schema_version: str = CATEGORY_SCHEMA

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

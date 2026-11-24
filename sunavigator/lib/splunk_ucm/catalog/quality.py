"""Content quality signals shown as badges and usable as catalogue filters (D-046).

Per-record flags are derived by the normalizer. ``duplicate_spl`` and ``provider_twin`` need the
whole catalogue and are set by :func:`splunk_ucm.catalog.derived.refresh_derived`.
"""

import hashlib
import re
from typing import List

QUALITY_FLAGS = {
    "unreviewed": "No review status, or draft",
    "reviewer_na": "Reviewer recorded as N/A",
    "ai_reviewed": "Reviewer is an automated or AI agent",
    "sme_review_pending": "Compliance mapping awaits SME review",
    "unbounded_index": "Primary SPL searches index=* or no index",
    "es_required": "Requires Splunk Enterprise Security",
    "duplicate_spl": "Primary SPL is identical to another use case",
    "provider_twin": "Primary SPL is identical to a use case from another provider",
}
FLAG_ORDER = tuple(QUALITY_FLAGS)
# Flags that need the whole catalogue; the post-pass sets and clears exactly these.
DERIVED_FLAGS = ("duplicate_spl", "provider_twin")


def spl_hash(spl: str) -> str:
    text = re.sub(r"\s+", " ", spl or "").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def ordered(flags) -> List[str]:
    present = set(flags)
    return [f for f in FLAG_ORDER if f in present]

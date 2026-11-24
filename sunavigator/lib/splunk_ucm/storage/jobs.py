"""Structural checks on queued jobs before a worker runs them (docs/DECISIONS.md D-039).

Only the REST handler (with the system token, after its capability check) and
the workers enqueue jobs; ``uc_sync_state`` is admin-write only. These checks
are defence in depth against a record written some other way.
"""

import re
from typing import Any, Dict, Optional

from ..discovery.spl import RELATIVE_TIME

_JOB_ID = re.compile(r"^[0-9a-f]{32}$")
_CATEGORY = re.compile(r"^[\w.\-]{1,100}$")
_REF = re.compile(r"^[\w./\-]{0,200}$")
_SOURCES = ("manual", "schedule", "auto", "offline_bundle")
_KINDS = {"job": ("job::", ("fenre",)), "discovery_job": ("djob::", ()), "readiness_job": ("rjob::", ())}


def reject(job: Dict[str, Any], problem: str) -> Dict[str, Any]:
    job["status"] = "failed"
    errors = job.get("errors") if isinstance(job.get("errors"), list) else []
    errors.append({"code": "invalid_job", "message": "job rejected: %s" % problem})
    job["errors"] = errors
    return job


def job_problem(job: Dict[str, Any]) -> Optional[str]:
    """Return why ``job`` must not run, or None."""
    kind = job.get("doc_type")
    if kind not in _KINDS:
        return "unknown job type"
    prefix, providers = _KINDS[kind]
    job_id = job.get("job_id")
    if not isinstance(job_id, str) or not _JOB_ID.match(job_id) or job.get("_key") != prefix + job_id:
        return "malformed job id"
    requested_by = job.get("requested_by")
    if not isinstance(requested_by, str) or not requested_by or len(requested_by) > 256:
        return "malformed requested_by"
    if job.get("source") not in _SOURCES:
        return "unknown job source"
    if kind == "job":
        if job.get("provider") not in providers:
            return "unknown provider"
        cats = job.get("categories")
        if not isinstance(cats, list) or len(cats) > 100 or not all(
                isinstance(c, str) and _CATEGORY.match(c) for c in cats):
            return "malformed categories"
        if not isinstance(job.get("ref", ""), str) or not _REF.match(job.get("ref", "")):
            return "malformed ref"
        if not all(isinstance(job.get(k, False), bool) for k in ("allow_schema_change", "force")):
            return "malformed flags"
    elif kind == "discovery_job":
        if job.get("include_internal") not in (None, True, False):
            return "malformed include_internal"
        for k in ("earliest", "latest"):
            value = job.get(k, "")
            if not isinstance(value, str) or (value and not RELATIVE_TIME.match(value)):
                return "malformed %s" % k
    return None

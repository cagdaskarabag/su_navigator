"""Build an offline ``ucm-content-bundle`` from an ESCU content package (T-22, D-053).

Accepts the extracted ``DA-ESS-ContentUpdate`` directory or its ``.tar.gz``
release archive. Archives are read in memory member by member; nothing is
extracted to disk and only the three ``default/*.conf`` files are read.

Output is deterministic: the same package always gives the same bytes (no
build time, records sorted by category and detection id). Detections marked
deprecated, and records without a detection id, are left out and counted in
the report.
"""

import collections
import hashlib
import io
import json
import os
import tarfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from ...errors import ValidationError
from ...util import git_blob_sha
from .. import bundle as bundle_format
from ...conf import parse as parse_conf
from .normalizer import CATEGORIES, CATEGORY_BY_SLUG, ESCU_SCHEMA, PROVIDER

MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100000
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
_FILES = ("default/savedsearches.conf", "default/analyticstories.conf", "default/app.conf",
          "default/content-version.conf")
_SEVERITY_TEXT = {"informational", "low", "medium", "high", "critical"}


def _inside(root: str, full: str) -> bool:
    root = os.path.realpath(root)
    return os.path.realpath(full).startswith(root + os.sep)


def _read_directory(path: str) -> Dict[str, bytes]:
    out = {}
    for rel in _FILES:
        full = os.path.join(path, *rel.split("/"))
        if os.path.lexists(full) and (os.path.islink(full) or not _inside(path, full)):
            raise ValidationError("package file is a symbolic link or lies outside the package directory",
                                  {"file": rel})
        if os.path.isfile(full):
            if os.path.getsize(full) > MAX_MEMBER_BYTES:
                raise ValidationError("package file is too large", {"file": rel})
            with open(full, "rb") as handle:
                out[rel] = handle.read()
    return out


def _read_archive(path: str) -> Tuple[Dict[str, bytes], bytes]:
    if os.path.getsize(path) > MAX_ARCHIVE_BYTES:
        raise ValidationError("package archive is too large", {"limit_bytes": MAX_ARCHIVE_BYTES})
    with open(path, "rb") as handle:
        raw = handle.read()
    out: Dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            members = 0
            unpacked = 0
            for member in archive:
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    raise ValidationError("package archive has too many members", {"limit": MAX_ARCHIVE_MEMBERS})
                if not member.isfile():
                    continue
                unpacked += member.size
                if unpacked > MAX_UNPACKED_BYTES:
                    raise ValidationError("package archive unpacks to too much data", {"limit_bytes": MAX_UNPACKED_BYTES})
                parts = member.name.split("/")
                if ".." in parts or member.name.startswith("/"):
                    continue
                for rel in _FILES:
                    if member.name == rel or member.name.endswith("/" + rel):
                        if member.size > MAX_MEMBER_BYTES:
                            raise ValidationError("package file is too large", {"file": rel})
                        out.setdefault(rel, archive.extractfile(member).read())
    except tarfile.TarError as exc:
        raise ValidationError("package is not a readable tar archive") from exc
    return out, hashlib.sha256(raw).hexdigest()


def read_package(source: str) -> Dict[str, Any]:
    if not os.path.exists(source):
        raise ValidationError("package path does not exist", {"path": source})
    if os.path.isdir(source):
        files = _read_directory(source)
        digest = hashlib.sha256(files.get("default/savedsearches.conf", b"")).hexdigest()
        ref = "local:" + digest
    else:
        files, digest = _read_archive(source)
        ref = "escu-package:sha256:" + digest
    if "default/savedsearches.conf" not in files:
        raise ValidationError("package has no default/savedsearches.conf")
    return {"files": {k: v.decode("utf-8") for k, v in files.items()}, "source_ref": ref}


def _json(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except ValueError:
        return default


def _list(value: Any) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def _title(stanza: str) -> str:
    title = stanza
    if title.startswith("ESCU - "):
        title = title[len("ESCU - "):]
    if title.endswith(" - Rule"):
        title = title[:-len(" - Rule")]
    return title.strip()


def _version(files: Dict[str, str]) -> str:
    for name, section, key in (("default/content-version.conf", "content-version", "version"),
                               ("default/app.conf", "launcher", "version")):
        for stanza, settings in parse_conf(files.get(name, "")):
            if stanza == section and settings.get(key):
                return settings[key]
    return "unknown"


def _record(stanza: str, settings: Dict[str, str], domain_slug: str) -> Tuple[Optional[Dict[str, Any]], str]:
    meta = _json(settings.get("action.correlationsearch.metadata"), {})
    if not isinstance(meta, dict) or not isinstance(meta.get("detection_id"), str):
        return None, "no_detection_id"
    if str(meta.get("deprecated", "0")).lower() in ("1", "true"):
        return None, "deprecated"
    ann = _json(settings.get("action.correlationsearch.annotations"), {})
    if not isinstance(ann, dict):
        ann = {}
    severity = settings.get("action.notable.param.severity", "")
    raw = {
        "id": meta["detection_id"].strip(),
        "title": _title(stanza),
        "stanza": stanza,
        "description": settings.get("description", "").strip(),
        "search": settings.get("search", "").strip(),
        "enabled": settings.get("action.correlationsearch.enabled") == "1",
        "detectionVersion": meta.get("detection_version"),
        "publishTime": meta.get("publish_time"),
        "detectionType": settings.get("action.correlationsearch.detection_type", ""),
        "type": (ann.get("type") or "") if isinstance(ann.get("type"), str) else "",
        "securityDomain": domain_slug if domain_slug != "unassigned" else "",
        "severity": severity if severity in _SEVERITY_TEXT else "",
        "analyticStories": _list(ann.get("analytic_story")),
        "dataSources": _list(ann.get("data_source")),
        "mitreAttack": _list(ann.get("mitre_attack")),
        "cis20": _list(ann.get("cis20")),
        "nist": _list(ann.get("nist")),
        "cve": _list(ann.get("cve")),
        "killChainPhases": _list(ann.get("kill_chain_phases")),
        "schedule": {k: settings[s] for k, s in (("cron", "cron_schedule"), ("earliest", "dispatch.earliest_time"),
                                                 ("latest", "dispatch.latest_time"),
                                                 ("window", "schedule_window")) if s in settings},
    }
    return raw, ""


_APACHE_URL = "https://www.apache.org/licenses/LICENSE-2.0"
_APP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))


def _license_text() -> str:
    """The Apache-2.0 text shipped with the app (``LICENSE`` in the app root), or "" when it is not there."""
    try:
        with open(os.path.join(_APP_ROOT, "LICENSE"), encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def bundle_notices(provider_version: str, enriched: bool) -> Dict[str, Any]:
    """What Apache-2.0 section 4 asks a redistributor of ESCU content to carry (docs/LEGAL_COMPLIANCE_ANALYSIS.md, L2a)."""
    components = [{"component": "Splunk ES Content Update (DA-ESS-ContentUpdate) %s" % provider_version,
                   "copyright": "Copyright Splunk Inc.", "license": "Apache-2.0", "license_url": _APACHE_URL}]
    if enriched:
        components.append({"component": "splunk/security_content (https://github.com/splunk/security_content)",
                           "copyright": "Copyright Splunk Inc.", "license": "Apache-2.0", "license_url": _APACHE_URL})
    return {
        "components": components,
        "changes": "SUNavigator read the saved searches and metadata of this package and rewrote them into the "
                   "ucm-content-bundle format: fields were renamed, normalised and merged, and the detection text "
                   "was otherwise kept. These records are not the files Splunk published.",
        "not_endorsed": "SUNavigator is an independent project. It is not made, sponsored or endorsed by Splunk. "
                        "Splunk is a trademark of Splunk LLC.",
        "license_text": _license_text(),
    }


def build_bundle(source: str, enricher: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
                 extra_ref: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """``enricher`` adds optional fields to each record (see ``enrich.py``); ``extra_ref`` is appended to ``source_ref``."""
    package = read_package(source)
    files = package["files"]
    stanzas = parse_conf(files["default/savedsearches.conf"])
    skipped: collections.Counter = collections.Counter()
    records: Dict[Tuple[str, str], Dict[str, Any]] = {}
    seen_ids = set()
    for stanza, settings in stanzas:
        if stanza == "default" or "action.correlationsearch.label" not in settings:
            continue
        domain = settings.get("action.notable.param.security_domain", "").strip()
        slug = domain if domain in CATEGORY_BY_SLUG else "unassigned"
        raw, reason = _record(stanza, settings, slug)
        if raw is None:
            skipped[reason] += 1
            continue
        if raw["id"] in seen_ids:
            skipped["duplicate_detection_id"] += 1
            continue
        seen_ids.add(raw["id"])
        if enricher is not None:
            raw = enricher(raw)
        content = json.dumps(raw, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        cat_id = CATEGORY_BY_SLUG[slug][0]
        records[(cat_id, raw["id"])] = {
            "category_id": cat_id, "record_id": raw["id"], "path": "detections/%s/%s.json" % (slug, raw["id"]),
            "blob_sha": git_blob_sha(content.encode("utf-8")), "content": content,
        }
    ordered = [records[key] for key in sorted(records)]
    counts = collections.Counter(r["category_id"] for r in ordered)
    categories = []
    for cid, slug, name, _ in CATEGORIES:
        if not counts[cid]:
            continue
        note = ("Detections in the %s domain." % name.lower() if slug != "unassigned"
                else "Detections without a notable security domain.")
        categories.append({"category_id": cid, "slug": slug, "path": "detections/" + slug,
                           "metadata": {"name": name, "description": note, "useCaseCount": counts[cid]}})
    bundle = {
        "format": bundle_format.BUNDLE_FORMAT, "format_version": bundle_format.BUNDLE_VERSION,
        "provider": PROVIDER, "provider_version": _version(files),
        "source_ref": package["source_ref"] + (("+" + extra_ref) if extra_ref else ""),
        "schema": ESCU_SCHEMA, "categories": categories, "records": ordered,
    }
    bundle["notices"] = bundle_notices(bundle["provider_version"], bool(extra_ref))
    report = {"provider_version": bundle["provider_version"], "source_ref": bundle["source_ref"],
              "stanzas": len(stanzas), "records": len(ordered), "skipped": dict(sorted(skipped.items())),
              "categories": {c["slug"]: c["metadata"]["useCaseCount"] for c in categories}}
    return bundle, report

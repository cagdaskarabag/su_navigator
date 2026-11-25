"""Offline loader for a ``security_content`` checkout (https://github.com/splunk/security_content, Apache-2.0).

Needs PyYAML, which is a build-machine dependency only: the app never reads YAML. The checkout should be
pinned to one commit; its id is recorded in the bundle's ``source_ref``.
"""

import glob
import os
import subprocess
from typing import Any, Callable, Dict, Tuple


def _yaml():
    try:
        import yaml
    except ImportError:
        raise SystemExit("PyYAML is required to read security_content: pip install pyyaml")
    return yaml


def _load_dir(yaml, pattern: str, key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for path in sorted(glob.glob(pattern, recursive=True)):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get(key), str):
            out[doc[key]] = doc
    return out


def commit_of(root: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def load(root: str) -> Tuple[Callable[[Dict[str, Any]], Dict[str, Any]], Dict[str, Any]]:
    """(enricher, report) for a checkout. Records are matched by detection id."""
    from splunk_ucm.content.escu.enrich import enrich

    if not os.path.isdir(os.path.join(root, "detections")):
        raise SystemExit("%s does not look like a security_content checkout (no detections/)" % root)
    yaml = _yaml()
    detections = _load_dir(yaml, os.path.join(root, "detections", "**", "*.yml"), "id")
    sources = _load_dir(yaml, os.path.join(root, "data_sources", "*.yml"), "name")
    macros = _load_dir(yaml, os.path.join(root, "macros", "*.yml"), "name")
    report: Dict[str, Any] = {"detections": len(detections), "data_sources": len(sources), "macros": len(macros),
                              "matched": 0, "unmatched": 0, "commit": commit_of(root)}

    def enricher(raw: Dict[str, Any]) -> Dict[str, Any]:
        detection = detections.get(raw.get("id"))
        report["matched" if detection else "unmatched"] += 1
        return enrich(raw, detection, sources, macros)

    return enricher, report

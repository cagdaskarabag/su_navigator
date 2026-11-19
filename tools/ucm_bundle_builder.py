"""Build ``ucm-content-bundle`` v1 files from a local Fenre-layout checkout.

Runs outside Splunk (administrator workstation / CI). Not shipped in the app
package, which must not spawn processes.
"""

import hashlib
import json
import os
import re
import subprocess  # nosec - fixed git invocation on an operator-supplied directory
import sys
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                "splunk_use_case_manager", "lib"))

from splunk_ucm.content.bundle import BUNDLE_FORMAT, BUNDLE_VERSION  # noqa: E402
from splunk_ucm.errors import ValidationError  # noqa: E402
from splunk_ucm.util import git_blob_sha, utc_now_iso  # noqa: E402

_CATEGORY_DIR = re.compile(r"^cat-(\d{1,3})-[a-z0-9-]+$")
_RECORD_FILE = re.compile(r"^UC-(\d+\.\d+\.\d+)\.json$")


def _git_head(repo_dir: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", repo_dir, "rev-parse", "HEAD"], capture_output=True,  # nosec
                             text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = out.stdout.strip()
    return sha if re.match(r"^[0-9a-f]{40}$", sha) else None


def build_bundle_from_directory(repo_dir: str, category_ids: Optional[Sequence[str]] = None,
                                provider: str = "fenre", content_root: str = "content",
                                schema_path: str = "schemas/uc.schema.json",
                                version_path: str = "VERSION",
                                record_ids: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    root = os.path.join(repo_dir, content_root)
    if not os.path.isdir(root):
        raise ValidationError("content root not found", {"path": root})
    wanted = {str(int(c)) for c in category_ids} if category_ids else None
    wanted_records = set(record_ids) if record_ids else None
    categories: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    listing_hash = hashlib.sha256()
    for name in sorted(os.listdir(root)):
        match = _CATEGORY_DIR.match(name)
        if not match or not os.path.isdir(os.path.join(root, name)):
            continue
        cat_id = str(int(match.group(1)))
        if wanted is not None and cat_id not in wanted:
            continue
        cat_dir = os.path.join(root, name)
        meta: Dict[str, Any] = {}
        meta_path = os.path.join(cat_dir, "_category.json")
        if os.path.isfile(meta_path):
            with open(meta_path, "r", encoding="utf-8") as handle:
                meta = json.load(handle)
        cat_records = []
        for fname in sorted(os.listdir(cat_dir)):
            rmatch = _RECORD_FILE.match(fname)
            if not rmatch or (wanted_records is not None and rmatch.group(1) not in wanted_records):
                continue
            with open(os.path.join(cat_dir, fname), "rb") as handle:
                body = handle.read()
            sha = git_blob_sha(body)
            listing_hash.update(sha.encode("ascii"))
            cat_records.append({"category_id": cat_id, "record_id": rmatch.group(1),
                                "path": "%s/%s/%s" % (content_root, name, fname), "blob_sha": sha,
                                "content": body.decode("utf-8")})
        if wanted_records is not None and not cat_records:
            continue
        categories.append({"category_id": cat_id, "slug": name, "path": "%s/%s" % (content_root, name),
                           "metadata": meta})
        records.extend(cat_records)
    if not categories:
        raise ValidationError("no matching categories found")
    schema = None
    spath = os.path.join(repo_dir, schema_path)
    if os.path.isfile(spath):
        with open(spath, "r", encoding="utf-8") as handle:
            schema = json.load(handle)
    version = "unknown"
    vpath = os.path.join(repo_dir, version_path)
    if os.path.isfile(vpath):
        with open(vpath, "r", encoding="utf-8") as handle:
            version = handle.read().strip()[:40]
    head = _git_head(repo_dir) if wanted_records is None else None
    return {
        "format": BUNDLE_FORMAT, "format_version": BUNDLE_VERSION, "provider": provider,
        "provider_version": version, "source_ref": head or "local:" + listing_hash.hexdigest(),
        "created_at": utc_now_iso(), "partial": wanted_records is not None, "schema": schema, "categories": categories, "records": records,
    }

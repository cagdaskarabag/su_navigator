"""Fenre "Splunk Monitoring Use Cases" provider (git sidecar transport).

Verified layout (docs/PROJECT_DISCOVERY.md §3):
``<content_root>/cat-NN-slug/_category.json`` and
``<content_root>/cat-NN-slug/UC-X.Y.Z.json`` validated by
``schemas/uc.schema.json``; catalogue version in ``VERSION``.

Transport (docs/DECISIONS.md D-006): resolve ``ref`` → commit SHA via the
GitHub REST API, walk trees by SHA, download blobs from the raw host at the
commit, and verify each blob's git SHA locally.
"""

import dataclasses
import fnmatch
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from ...errors import IntegrityError, NotFoundError, ProviderError, RateLimitedError, ValidationError
from ...log import get_logger
from ...util import git_blob_sha, utc_now_iso
from ..http import HttpConfig, HttpFetcher
from ..provider import (ContentProvider, Normalizer, ProviderCategory, ProviderManifest,
                        ProviderRecord, RecordListing)
from ..jsonschema_subset import SchemaValidator
from ..validation import RecordValidator
from .normalizer import FenreNormalizer, fenre_validation_policy

log = get_logger(__name__)

PROVIDER_ID = "fenre"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")
_REF_PATTERN_RE = re.compile(r"^[A-Za-z0-9._/\-*]{1,200}$")
_CATEGORY_DIR = re.compile(r"^cat-(\d{1,3})-[a-z0-9-]+$")
_RECORD_FILE = re.compile(r"^UC-(\d+\.\d+\.\d+)\.json$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")

BUNDLED_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "uc.schema.json")


@dataclasses.dataclass
class FenreConfig:
    owner: str = "fenre"
    repo: str = "splunk-monitoring-use-cases"
    ref: str = "main"
    api_base: str = "https://api.github.com"
    raw_base: str = "https://raw.githubusercontent.com"
    content_root: str = "content"
    schema_path: str = "schemas/uc.schema.json"
    version_path: str = "VERSION"
    category_file: str = "_category.json"
    max_record_bytes: int = 512 * 1024
    max_tree_bytes: int = 16 * 1024 * 1024
    fetch_concurrency: int = 4
    token: str = ""
    allowed_refs: Tuple[str, ...] = ("main",)

    def validate(self) -> None:
        for name in ("owner", "repo"):
            if not re.match(r"^[A-Za-z0-9_.-]{1,100}$", getattr(self, name)):
                raise ProviderError("invalid %s" % name)
        if not _REF_RE.match(self.ref) or ".." in self.ref:
            raise ProviderError("invalid ref")
        for pattern in self.allowed_refs:
            if not _REF_PATTERN_RE.match(pattern) or ".." in pattern:
                raise ProviderError("invalid allowed_refs entry", {"entry": pattern[:200]})
        for name in ("content_root", "schema_path", "version_path", "category_file"):
            value = getattr(self, name)
            if not value or value.startswith("/") or ".." in value.split("/"):
                raise ProviderError("invalid path setting %s" % name)
        if not 1 <= self.fetch_concurrency <= 16:
            raise ProviderError("fetch_concurrency must be 1..16")


def is_commit_sha(ref: str) -> bool:
    return bool(_SHA_RE.match(ref or ""))


def parse_allowed_refs(value: str, configured_ref: str = "") -> Tuple[str, ...]:
    """Branch and tag names (``*`` wildcards allowed) a sync may use.

    The configured ref is always allowed when it is a name. An empty list
    therefore means "the configured ref only".
    """
    out = [v.strip() for v in str(value or "").split(",") if v.strip()]
    if configured_ref and not is_commit_sha(configured_ref) and configured_ref not in out:
        out.append(configured_ref)
    return tuple(out)


def check_ref_name(ref: str, allowed_refs: Tuple[str, ...]) -> None:
    """Reject a branch or tag outside ``allowed_refs`` without any network access.

    Commit SHAs pass here; :meth:`FenreJsonProvider.verify_ref` checks that
    they are reachable from an allowed ref.
    """
    if is_commit_sha(ref):
        return
    if not any(fnmatch.fnmatchcase(ref, pattern) for pattern in allowed_refs):
        raise ValidationError("ref is not in allowed_refs", {"ref": ref[:200], "allowed_refs": list(allowed_refs)})


def load_bundled_schema() -> Dict[str, Any]:
    with open(BUNDLED_SCHEMA_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


class FenreJsonProvider(ContentProvider):
    provider_id = PROVIDER_ID

    def __init__(self, config: FenreConfig, fetcher: Optional[HttpFetcher] = None,
                 http_config: Optional[HttpConfig] = None):
        config.validate()
        self.config = config
        if fetcher is None:
            hosts = [_host(config.api_base), _host(config.raw_base)]
            fetcher = HttpFetcher(http_config or HttpConfig(allowed_hosts=hosts))
        self.fetcher = fetcher
        self._normalizer = FenreNormalizer()

    # -- GitHub primitives -------------------------------------------------
    def _api_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.config.token:
            headers["Authorization"] = "Bearer " + self.config.token
        return headers

    def _api_json(self, path: str, max_bytes: Optional[int] = None) -> Any:
        url = "%s/repos/%s/%s/%s" % (self.config.api_base.rstrip("/"), quote(self.config.owner),
                                     quote(self.config.repo), path)
        resp = self.fetcher.get(url, self._api_headers(), max_bytes)
        try:
            return json.loads(resp.body.decode("utf-8"))
        except ValueError as exc:
            raise ProviderError("invalid JSON from provider API", {"url": url}) from exc

    def raw_url(self, commit: str, path: str) -> str:
        return "%s/%s/%s/%s/%s" % (self.config.raw_base.rstrip("/"), quote(self.config.owner),
                                   quote(self.config.repo), commit, quote(path))

    def _raw(self, commit: str, path: str, max_bytes: Optional[int] = None) -> bytes:
        return self.fetcher.get(self.raw_url(commit, path), None, max_bytes).body

    def _tree(self, sha: str) -> List[Dict[str, Any]]:
        if not _SHA_RE.match(sha):
            raise ProviderError("invalid tree sha")
        data = self._api_json("git/trees/" + sha, self.config.max_tree_bytes)
        if not isinstance(data, dict) or not isinstance(data.get("tree"), list):
            raise ProviderError("unexpected tree response")
        if data.get("truncated"):
            raise ProviderError("tree listing truncated by provider", {"sha": sha})
        return data["tree"]

    def verify_ref(self) -> Optional[str]:
        """Apply the ref policy before any content is fetched.

        Returns the allowed ref a pinned commit was found on, or None for a
        branch or tag name.
        """
        ref = self.config.ref
        check_ref_name(ref, self.config.allowed_refs)
        if not is_commit_sha(ref):
            return None
        for base in self.config.allowed_refs:
            if "*" in base or not _REF_RE.match(base):
                continue
            try:
                data = self._api_json("compare/%s...%s?per_page=1" % (quote(base, safe=""), ref), 8 * 1024 * 1024)
            except RateLimitedError:
                raise
            except ProviderError:
                continue
            # "behind": the pinned commit is an ancestor of the allowed ref.
            if isinstance(data, dict) and data.get("status") in ("identical", "behind"):
                return base
        raise ValidationError("commit is not reachable from an allowed ref",
                              {"ref": ref, "allowed_refs": list(self.config.allowed_refs)})

    def resolve_commit(self) -> Tuple[str, str]:
        """Return ``(commit_sha, root_tree_sha)`` for the configured ref."""
        reachable_from = self.verify_ref()
        if reachable_from:
            log.info("pinned commit verified", extra={"ref": self.config.ref, "reachable_from": reachable_from})
        data = self._api_json("commits/" + quote(self.config.ref, safe=""), 4 * 1024 * 1024)
        sha = data.get("sha") if isinstance(data, dict) else None
        tree = ((data.get("commit") or {}).get("tree") or {}).get("sha") if isinstance(data, dict) else None
        if not isinstance(sha, str) or not _SHA_RE.match(sha):
            raise ProviderError("could not resolve ref", {"ref": self.config.ref})
        if not isinstance(tree, str) or not _SHA_RE.match(tree):
            raise ProviderError("commit has no tree", {"commit": sha})
        return sha, tree

    def _subtree(self, root_sha: str, path: str) -> str:
        sha = root_sha
        for part in path.strip("/").split("/"):
            entry = next((e for e in self._tree(sha) if e.get("path") == part and e.get("type") == "tree"), None)
            if entry is None:
                raise ProviderError("content path not found in repository", {"path": path})
            sha = entry["sha"]
        return sha

    # -- ContentProvider ---------------------------------------------------
    def get_manifest(self) -> ProviderManifest:
        warnings: List[str] = []
        commit, root_tree = self.resolve_commit()
        content_sha = self._subtree(root_tree, self.config.content_root)

        version = self._raw(commit, self.config.version_path, 1024).decode("utf-8", "replace").strip()
        if not _VERSION_RE.match(version):
            warnings.append("unrecognised catalogue version %r" % version[:40])
            version = "unknown"

        schema: Optional[Dict[str, Any]]
        try:
            schema = json.loads(self._raw(commit, self.config.schema_path, 2 * 1024 * 1024))
            if not isinstance(schema, dict):
                raise ValueError("schema is not an object")
            bad = SchemaValidator(schema).invalid_patterns
            if bad:
                raise ValueError("it has a pattern that is not a valid regular expression: %s" % bad[0])
        except (ProviderError, ValueError, TypeError, RecursionError) as exc:
            warnings.append("upstream schema unavailable (%s); using bundled schema" % exc)
            schema = load_bundled_schema()
        schema_version = str(schema.get("version", "unknown"))

        cats: List[ProviderCategory] = []
        for entry in self._tree(content_sha):
            name = entry.get("path", "")
            match = _CATEGORY_DIR.match(name)
            if entry.get("type") != "tree" or not match:
                continue
            cats.append(ProviderCategory(
                category_id=str(int(match.group(1))), name=name, slug=name,
                path="%s/%s" % (self.config.content_root.strip("/"), name), tree_sha=entry["sha"]))
        if not cats:
            raise ProviderError("no categories found under content root")

        def load_meta(cat: ProviderCategory) -> None:
            try:
                meta = json.loads(self._raw(commit, cat.path + "/" + self.config.category_file, 1024 * 1024))
            except (ProviderError, ValueError) as exc:
                warnings.append("category metadata unavailable for %s (%s)" % (cat.slug, exc))
                return
            if isinstance(meta, dict):
                cat.metadata = meta
                if isinstance(meta.get("name"), str) and meta["name"].strip():
                    cat.name = meta["name"].strip()
                count = meta.get("useCaseCount")
                cat.upstream_count = count if isinstance(count, int) else None

        with ThreadPoolExecutor(max_workers=self.config.fetch_concurrency) as pool:
            list(pool.map(load_meta, cats))
        cats.sort(key=lambda c: int(c.category_id))
        return ProviderManifest(
            provider=PROVIDER_ID, provider_version=version, source_ref=commit,
            requested_ref=self.config.ref, schema=schema, schema_version=schema_version,
            categories=cats, retrieved_at=utc_now_iso(), warnings=warnings)

    def list_records(self, manifest: ProviderManifest,
                     category: ProviderCategory) -> List[RecordListing]:
        out = []
        for entry in self._tree(category.tree_sha):
            match = _RECORD_FILE.match(entry.get("path", ""))
            if entry.get("type") != "blob" or not match:
                continue
            out.append(RecordListing(record_id=match.group(1),
                                     path="%s/%s" % (category.path, entry["path"]),
                                     blob_sha=entry.get("sha", ""), size=entry.get("size")))
        return out

    def fetch_record(self, manifest: ProviderManifest, category: ProviderCategory,
                     listing: RecordListing) -> ProviderRecord:
        if listing.size is not None and listing.size > self.config.max_record_bytes:
            raise IntegrityError("record exceeds size limit", {"path": listing.path})
        body = self._raw(manifest.source_ref, listing.path, self.config.max_record_bytes)
        actual = git_blob_sha(body)
        if listing.blob_sha and actual != listing.blob_sha:
            raise IntegrityError("blob hash mismatch", {"path": listing.path,
                                                        "expected": listing.blob_sha, "actual": actual})
        try:
            raw = json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise IntegrityError("record is not valid JSON", {"path": listing.path}) from exc
        return ProviderRecord(provider=PROVIDER_ID, record_id=listing.record_id,
                              category_id=category.category_id, path=listing.path, raw=raw,
                              raw_size=len(body), blob_sha=actual,
                              source_url=self.raw_url(manifest.source_ref, listing.path))

    def get_use_case(self, manifest: ProviderManifest, record_id: str) -> ProviderRecord:
        cat = manifest.category(record_id.split(".", 1)[0])
        if cat is None:
            raise NotFoundError("category not found for record", {"record_id": record_id})
        for listing in self.list_records(manifest, cat):
            if listing.record_id == record_id:
                return self.fetch_record(manifest, cat, listing)
        raise NotFoundError("record not found", {"record_id": record_id})

    def normalizer(self) -> Normalizer:
        return self._normalizer

    def validator(self, manifest: ProviderManifest) -> RecordValidator:
        return RecordValidator(fenre_validation_policy(self.config.max_record_bytes), manifest.schema)


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()

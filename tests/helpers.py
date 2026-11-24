"""Shared test helpers. Everything here is a test double: no Splunk, no network."""

import copy
import hashlib
import json
import os
import sys
from typing import Dict, List, Optional
from urllib.parse import unquote, urlparse

os.environ.setdefault("UCM_LOG_LEVEL", "CRITICAL")
os.environ.pop("SPLUNK_HOME", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "sunavigator", "lib")
TOOLS = os.path.join(ROOT, "tools")
for _p in (LIB, TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

FIXTURE_REPO = os.path.join(ROOT, "tests", "fixtures", "fenre")

from splunk_ucm.content.http import HttpResponse  # noqa: E402
from splunk_ucm.errors import ProviderError  # noqa: E402
from splunk_ucm.util import git_blob_sha  # noqa: E402

OWNER, REPO = "fenre", "splunk-monitoring-use-cases"
API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"


def load_fixture_record(record_id: str) -> Dict:
    for dirpath, _dirs, files in os.walk(os.path.join(FIXTURE_REPO, "content")):
        name = "UC-%s.json" % record_id
        if name in files:
            with open(os.path.join(dirpath, name), "r", encoding="utf-8") as handle:
                return json.load(handle)
    raise KeyError(record_id)


def fixture_files() -> Dict[str, bytes]:
    """All fixture repository files keyed by repo-relative path."""
    out = {}
    for dirpath, _dirs, files in os.walk(FIXTURE_REPO):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, FIXTURE_REPO).replace(os.sep, "/")
            if rel in ("README.md", "LICENSE"):
                continue
            with open(full, "rb") as handle:
                out[rel] = handle.read()
    return out


def fixture_bundle(record_ids=None, category_ids=None) -> Dict:
    from ucm_bundle_builder import build_bundle_from_directory
    return copy.deepcopy(build_bundle_from_directory(FIXTURE_REPO, category_ids, record_ids=record_ids))


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()  # nosec - test identifiers only


class FakeGitHub:
    """Serves a mutable in-memory repository through the HttpFetcher interface.

    Tree SHAs are content-derived (any change below a tree changes its SHA) and
    blob SHAs are real git blob SHAs, matching GitHub's behaviour closely
    enough for provider and sync tests.
    """

    def __init__(self, files: Optional[Dict[str, bytes]] = None):
        self.files: Dict[str, bytes] = dict(files if files is not None else fixture_files())
        self.tampered: Dict[str, bytes] = {}
        self.fail_paths = set()
        self.truncate_trees = False
        self.requests = []
        self._trees: Dict[str, list] = {}
        self._commit = ""
        self._root = ""
        self.history: List[str] = []
        self.diverged = set()

    # -- repository mutation ----------------------------------------------
    def put(self, path: str, data) -> None:
        self.files[path] = data if isinstance(data, bytes) else json.dumps(data, indent=2).encode("utf-8")

    def delete(self, path: str) -> None:
        self.files.pop(path, None)

    def _build(self) -> None:
        self._trees = {}

        def build_dir(prefix: str) -> str:
            entries = []
            children = set()
            for path in self.files:
                if prefix and not path.startswith(prefix + "/"):
                    continue
                rest = path[len(prefix) + 1:] if prefix else path
                children.add(rest.split("/", 1)[0] if "/" in rest else ("\0" + rest))
            for child in sorted(children):
                if child.startswith("\0"):
                    name = child[1:]
                    body = self.files[(prefix + "/" if prefix else "") + name]
                    entries.append({"path": name, "type": "blob", "sha": git_blob_sha(body), "size": len(body)})
                else:
                    sub = build_dir((prefix + "/" if prefix else "") + child)
                    entries.append({"path": child, "type": "tree", "sha": sub})
            sha = _sha1(json.dumps(entries, sort_keys=True))
            self._trees[sha] = entries
            return sha

        self._root = build_dir("")
        self._commit = _sha1("commit:" + self._root)
        if self._commit not in self.history:
            self.history.append(self._commit)

    @property
    def commit(self) -> str:
        self._build()
        return self._commit

    # -- HttpFetcher interface ---------------------------------------------
    def get(self, url, headers=None, max_bytes=None):
        self.requests.append(url)
        parsed = urlparse(url)
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        path = unquote(parsed.path)
        if base == API:
            self._build()
            prefix = "/repos/%s/%s/" % (OWNER, REPO)
            assert path.startswith(prefix), path
            rest = path[len(prefix):]
            if rest.startswith("compare/"):
                base, head = rest[len("compare/"):].split("...", 1)
                if base != "main" or (head not in self.history and head not in self.diverged):
                    raise ProviderError("HTTP 404 from provider", {"url": url, "status": 404})
                status = ("identical" if head == self._commit else
                          "diverged" if head in self.diverged else "behind")
                return self._json({"status": status, "ahead_by": 0, "commits": [], "files": []})
            if rest.startswith("commits/"):
                return self._json({"sha": self._commit, "commit": {"tree": {"sha": self._root}}})
            if rest.startswith("git/trees/"):
                sha = rest[len("git/trees/"):]
                if sha not in self._trees:
                    raise ProviderError("HTTP 404 from provider", {"url": url, "status": 404})
                return self._json({"sha": sha, "tree": self._trees[sha], "truncated": self.truncate_trees})
            raise AssertionError("unexpected API path " + rest)
        if base == RAW:
            prefix = "/%s/%s/" % (OWNER, REPO)
            assert path.startswith(prefix), path
            _ref, repo_path = path[len(prefix):].split("/", 1)
            if repo_path in self.fail_paths:
                raise ProviderError("provider unreachable after retries", {"url": url})
            if repo_path in self.tampered:
                return HttpResponse(200, {}, self.tampered[repo_path], url)
            if repo_path not in self.files:
                raise ProviderError("HTTP 404 from provider", {"url": url, "status": 404})
            body = self.files[repo_path]
            if max_bytes and len(body) > max_bytes:
                raise ProviderError("response exceeds size limit", {"url": url})
            return HttpResponse(200, {}, body, url)
        raise AssertionError("unexpected host " + base)

    @staticmethod
    def _json(obj):
        return HttpResponse(200, {}, json.dumps(obj).encode("utf-8"), "")


def fenre_provider(github: FakeGitHub, ref: str = "main", **overrides):
    from splunk_ucm.content.fenre.provider import FenreConfig, FenreJsonProvider
    cfg = FenreConfig(ref=ref, fetch_concurrency=2, **overrides)
    return FenreJsonProvider(cfg, fetcher=github)


def record_path(record_id: str, files: Dict[str, bytes]) -> str:
    suffix = "/UC-%s.json" % record_id
    return next(p for p in files if p.endswith(suffix))

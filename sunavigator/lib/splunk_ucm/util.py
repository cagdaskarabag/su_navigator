"""Small, dependency-free helpers (hashing, time, canonical JSON)."""

import datetime
import hashlib
import json
import re
import uuid
from typing import Any, Iterable, Iterator, List, Sequence, TypeVar

T = TypeVar("T")

_KEY_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for content hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_blob_sha(data: bytes) -> str:
    """SHA-1 object id git assigns to a blob with this content."""
    header = ("blob %d\0" % len(data)).encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # nosec - git object id, not security hash


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def utc_now_iso() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch_now() -> float:
    return utc_now().timestamp()


def new_id() -> str:
    return uuid.uuid4().hex


def safe_key(*parts: str) -> str:
    """Build a KV Store ``_key`` from parts; only ``[A-Za-z0-9._-]`` survive."""
    return "_".join(_KEY_SAFE.sub("-", p) for p in parts if p)


def chunked(items: Sequence[T], size: int) -> Iterator[List[T]]:
    for i in range(0, len(items), size):
        yield list(items[i:i + size])


def dedupe(items: Iterable[T]) -> List[T]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def truncate(text: str, limit: int) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "\u2026"


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]

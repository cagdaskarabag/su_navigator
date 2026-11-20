"""Stable KV keys for environment sources and mappings.

Sourcetype names contain ``:`` and other characters that are awkward in
``_key`` values, so the identifying fields are stored as data and the key is a
short hash of ``kind`` + identity.
"""

from ..util import sha256_text


def source_key(kind: str, *parts: str) -> str:
    return "src_%s_%s" % (kind, sha256_text("\0".join(parts))[:20])


def mapping_key(kind: str, value: str) -> str:
    return "map_%s_%s" % (kind, sha256_text(value)[:20])

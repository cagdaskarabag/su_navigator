"""Document-store interface with KV Store and in-memory implementations.

The in-memory store implements the subset of KV Store query semantics the
application relies on (verified against a live KV Store, see
docs/PROJECT_DISCOVERY.md §2) so services are testable without Splunk.
"""

import abc
import copy
import json
import re
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

from .. import APP_NAME
from ..errors import StorageError
from .transport import SplunkdTransport

Sort = Sequence[Tuple[str, int]]  # (field, 1 | -1)


class DocumentStore(abc.ABC):
    @abc.abstractmethod
    def get(self, collection: str, key: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def query(self, collection: str, query: Optional[Dict[str, Any]] = None, sort: Sort = (),
              skip: int = 0, limit: int = 0, fields: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def batch_save(self, collection: str, docs: List[Dict[str, Any]]) -> List[str]:
        """Upsert documents by ``_key``."""

    @abc.abstractmethod
    def delete(self, collection: str, key: str) -> None:
        ...

    @abc.abstractmethod
    def delete_query(self, collection: str, query: Dict[str, Any]) -> None:
        ...

    def upsert(self, collection: str, doc: Dict[str, Any]) -> str:
        return self.batch_save(collection, [doc])[0]

    def count(self, collection: str, query: Optional[Dict[str, Any]] = None) -> int:
        return len(self.query(collection, query, fields=["_key"]))


class KVStore(DocumentStore):
    """Splunk KV Store via REST (``storage/collections/data``)."""

    def __init__(self, transport: SplunkdTransport, app: str = APP_NAME, owner: str = "nobody",
                 max_batch_docs: int = 500, max_batch_bytes: int = 8 * 1024 * 1024):
        self.t = transport
        self.base = "/servicesNS/%s/%s/storage/collections/data" % (quote(owner), quote(app))
        self.max_batch_docs = max_batch_docs
        self.max_batch_bytes = max_batch_bytes

    def _path(self, collection: str, key: Optional[str] = None) -> str:
        path = "%s/%s" % (self.base, quote(collection, safe=""))
        if key is not None:
            path += "/" + quote(key, safe="")
        return path

    def get(self, collection, key):
        status, body = self.t.request("GET", self._path(collection, key), {"output_mode": "json"})
        if status == 404:
            return None
        if status != 200:
            raise StorageError("KV get failed", status, {"collection": collection})
        return json.loads(body.decode("utf-8"))

    def query(self, collection, query=None, sort=(), skip=0, limit=0, fields=None):
        params: Dict[str, Any] = {"output_mode": "json"}
        if query:
            params["query"] = json.dumps(query)
        if sort:
            params["sort"] = ",".join("%s:%d" % (f, d) for f, d in sort)
        if skip:
            params["skip"] = int(skip)
        if limit:
            params["limit"] = int(limit)
        if fields:
            params["fields"] = ",".join(fields)
        result = self.t.json("GET", self._path(collection), params)
        return result if isinstance(result, list) else []

    def batch_save(self, collection, docs):
        keys: List[str] = []
        batch: List[Dict[str, Any]] = []
        size = 0
        for doc in docs:
            doc_size = len(json.dumps(doc))
            if batch and (len(batch) >= self.max_batch_docs or size + doc_size > self.max_batch_bytes):
                keys.extend(self._save(collection, batch))
                batch, size = [], 0
            batch.append(doc)
            size += doc_size
        if batch:
            keys.extend(self._save(collection, batch))
        return keys

    def _save(self, collection: str, batch: List[Dict[str, Any]]) -> List[str]:
        result = self.t.json("POST", self._path(collection) + "/batch_save", json_body=batch)
        return list(result or [])

    def delete(self, collection, key):
        status, _ = self.t.request("DELETE", self._path(collection, key))
        if status not in (200, 404):
            raise StorageError("KV delete failed", status, {"collection": collection})

    def delete_query(self, collection, query):
        if not query:
            raise StorageError("refusing to delete without a query")
        status, _ = self.t.request("DELETE", self._path(collection), {"query": json.dumps(query)})
        if status not in (200, 404):
            raise StorageError("KV delete failed", status, {"collection": collection})


def _match_value(doc_value: Any, cond: Any) -> bool:
    if isinstance(cond, dict) and any(k.startswith("$") for k in cond):
        for op, arg in cond.items():
            if op == "$in":
                vals = doc_value if isinstance(doc_value, list) else [doc_value]
                if not any(v in arg for v in vals):
                    return False
            elif op == "$nin":
                vals = doc_value if isinstance(doc_value, list) else [doc_value]
                if any(v in arg for v in vals):
                    return False
            elif op == "$ne":
                if _match_value(doc_value, arg):
                    return False
            elif op == "$regex":
                flags = re.IGNORECASE if "i" in cond.get("$options", "") else 0
                vals = doc_value if isinstance(doc_value, list) else [doc_value]
                if not any(isinstance(v, str) and re.search(arg, v, flags) for v in vals):
                    return False
            elif op == "$options":
                continue
            elif op in ("$gt", "$gte", "$lt", "$lte"):
                if doc_value is None or isinstance(doc_value, (list, dict)):
                    return False
                try:
                    ok = {"$gt": doc_value > arg, "$gte": doc_value >= arg,
                          "$lt": doc_value < arg, "$lte": doc_value <= arg}[op]
                except TypeError:
                    return False
                if not ok:
                    return False
            else:
                raise StorageError("unsupported operator in memory store: %s" % op)
        return True
    if isinstance(doc_value, list) and not isinstance(cond, list):
        return cond in doc_value
    return doc_value == cond


def matches(doc: Dict[str, Any], query: Optional[Dict[str, Any]]) -> bool:
    if not query:
        return True
    for key, cond in query.items():
        if key == "$and":
            if not all(matches(doc, q) for q in cond):
                return False
        elif key == "$or":
            if not any(matches(doc, q) for q in cond):
                return False
        elif not _match_value(doc.get(key), cond):
            return False
    return True


def _illegal_key(value: Any) -> Optional[str]:
    """Mirror KV Store's rejection of ``$`` or ``.`` in document keys at any depth."""
    if isinstance(value, dict):
        for k, v in value.items():
            if "$" in k or "." in k:
                return k
            found = _illegal_key(v)
            if found:
                return found
    elif isinstance(value, list):
        for v in value:
            found = _illegal_key(v)
            if found:
                return found
    return None


class InMemoryStore(DocumentStore):
    def __init__(self) -> None:
        self.collections: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._seq = 0

    def _coll(self, name: str) -> Dict[str, Dict[str, Any]]:
        return self.collections.setdefault(name, {})

    def get(self, collection, key):
        doc = self._coll(collection).get(key)
        return copy.deepcopy(doc) if doc is not None else None

    def query(self, collection, query=None, sort=(), skip=0, limit=0, fields=None):
        docs = [d for d in self._coll(collection).values() if matches(d, query)]
        for field, direction in reversed(list(sort)):
            docs.sort(key=lambda d: (d.get(field) is None, d.get(field)), reverse=direction < 0)
        docs = docs[skip:]
        if limit:
            docs = docs[:limit]
        if fields:
            keep = set(fields) | {"_key"}
            docs = [{k: v for k, v in d.items() if k in keep} for d in docs]
        return copy.deepcopy(docs)

    def batch_save(self, collection, docs):
        keys = []
        for doc in docs:
            bad = _illegal_key(doc)
            if bad:
                raise StorageError("splunkd returned HTTP 400", 400,
                                   {"body": "Document may not contain '$' or '.' in keys (%s)" % bad})
        with self._lock:
            coll = self._coll(collection)
            for doc in docs:
                doc = copy.deepcopy(doc)
                if "_key" not in doc:
                    self._seq += 1
                    doc["_key"] = "auto%08d" % self._seq
                coll[doc["_key"]] = doc
                keys.append(doc["_key"])
        return keys

    def delete(self, collection, key):
        self._coll(collection).pop(key, None)

    def delete_query(self, collection, query):
        if not query:
            raise StorageError("refusing to delete without a query")
        coll = self._coll(collection)
        for key in [k for k, d in coll.items() if matches(d, query)]:
            coll.pop(key, None)

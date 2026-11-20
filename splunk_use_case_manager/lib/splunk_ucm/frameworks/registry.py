"""Versioned framework definitions (generic model, D-030).

A definition (``ucm.framework/1``) lists tactics (columns) and techniques
(objects, optionally with a parent) for one framework version. Definitions
come from files bundled with the app (``frameworks/data``, MITRE ATT&CK
Enterprise and ICS) or are imported by a content manager; both are read-only
reference data. The selected version per framework is stored in
``uc_frameworks`` (default: newest available).
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ..errors import NotFoundError, ValidationError
from ..storage import collections as C
from ..storage.collections import DOC_SCHEMA
from ..storage.kvstore import DocumentStore
from ..util import safe_key, sha256_json, utc_now_iso

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
FORMAT = "ucm.framework/1"
_FW_ID = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_VERSION = re.compile(r"^\d{1,4}(\.\d{1,4}){0,3}$")
_OBJ_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,31}$")
MAX_OBJECTS = 5000
MAX_BYTES = 5 * 1024 * 1024


def version_key(version: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValidationError("%s must be a non-empty string of at most %d characters" % (name, limit))
    return value.strip()


def validate_definition(doc: Any) -> Dict[str, Any]:
    """Return a cleaned copy containing only known fields; raise on anything malformed."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValidationError("definition must be a JSON object with format %s" % FORMAT)
    fw_id = str(doc.get("framework_id") or "")
    if not _FW_ID.match(fw_id):
        raise ValidationError("invalid framework_id")
    version = str(doc.get("version") or "")
    if not _VERSION.match(version):
        raise ValidationError("version must be numeric, e.g. 20.1")
    tactics_in = doc.get("tactics")
    techniques_in = doc.get("techniques")
    if not isinstance(tactics_in, list) or not isinstance(techniques_in, list):
        raise ValidationError("tactics and techniques must be lists")
    if not tactics_in or len(tactics_in) > 100 or len(techniques_in) > MAX_OBJECTS:
        raise ValidationError("definition has too many or no tactics/techniques")
    tactics = []
    tactic_ids = set()
    for t in tactics_in:
        if not isinstance(t, dict) or not _OBJ_ID.match(str(t.get("id") or "")):
            raise ValidationError("invalid tactic")
        if t["id"] in tactic_ids:
            raise ValidationError("duplicate tactic %s" % t["id"])
        tactic_ids.add(t["id"])
        tactics.append({"id": t["id"], "name": _text(t.get("name"), "tactic name", 200),
                        "shortname": str(t.get("shortname") or "")[:100]})
    techniques = []
    seen = set()
    for t in techniques_in:
        if not isinstance(t, dict) or not _OBJ_ID.match(str(t.get("id") or "")):
            raise ValidationError("invalid technique")
        if t["id"] in seen:
            raise ValidationError("duplicate technique %s" % t["id"])
        seen.add(t["id"])
        tacs = t.get("tactics") or []
        if not isinstance(tacs, list) or any(x not in tactic_ids for x in tacs):
            raise ValidationError("technique %s references an unknown tactic" % t["id"])
        parent = t.get("parent")
        if parent is not None and not _OBJ_ID.match(str(parent)):
            raise ValidationError("invalid parent for %s" % t["id"])
        platforms = [str(p)[:40] for p in (t.get("platforms") or []) if isinstance(p, str)][:12]
        techniques.append({"id": t["id"], "name": _text(t.get("name"), "technique name", 300),
                           "tactics": list(tacs), "parent": parent, "platforms": platforms})
    for t in techniques:
        if t["parent"] and t["parent"] not in seen:
            raise ValidationError("technique %s has an unknown parent %s" % (t["id"], t["parent"]))
    revoked = doc.get("revoked") or {}
    if not isinstance(revoked, dict) or not all(_OBJ_ID.match(str(k)) and _OBJ_ID.match(str(v))
                                                for k, v in revoked.items()):
        raise ValidationError("invalid revoked map")
    deprecated = doc.get("deprecated") or []
    if not isinstance(deprecated, list) or not all(_OBJ_ID.match(str(x)) for x in deprecated):
        raise ValidationError("invalid deprecated list")
    return {
        "format": FORMAT, "framework": str(doc.get("framework") or fw_id)[:64], "framework_id": fw_id,
        "domain": str(doc.get("domain") or "")[:32], "name": _text(doc.get("name"), "name", 200),
        "version": version, "modified": str(doc.get("modified") or "")[:40],
        "source": str(doc.get("source") or "")[:500], "source_sha256": str(doc.get("source_sha256") or "")[:64],
        "attribution": str(doc.get("attribution") or "")[:1000], "tactics": tactics, "techniques": techniques,
        "revoked": {str(k): str(v) for k, v in revoked.items()}, "deprecated": [str(x) for x in deprecated],
    }


def definition_key(framework_id: str, version: str) -> str:
    return safe_key("fw", framework_id, version)


def _summary(defn: Dict[str, Any], origin: str) -> Dict[str, Any]:
    return {"framework_id": defn["framework_id"], "framework": defn["framework"], "domain": defn["domain"],
            "name": defn["name"], "version": defn["version"], "modified": defn.get("modified", ""),
            "origin": origin, "tactics": len(defn["tactics"]), "techniques": len(defn["techniques"]),
            "attribution": defn.get("attribution", "")}


class FrameworkRegistry:
    _bundled_cache: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None

    def __init__(self, store: DocumentStore, data_dir: str = DATA_DIR):
        self.store = store
        self.data_dir = data_dir

    def bundled(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        if self.data_dir != DATA_DIR or FrameworkRegistry._bundled_cache is None:
            out: Dict[Tuple[str, str], Dict[str, Any]] = {}
            for name in sorted(os.listdir(self.data_dir)) if os.path.isdir(self.data_dir) else []:
                if not name.endswith(".json"):
                    continue
                with open(os.path.join(self.data_dir, name), "r", encoding="utf-8") as handle:
                    defn = validate_definition(json.load(handle))
                out[(defn["framework_id"], defn["version"])] = defn
            if self.data_dir != DATA_DIR:
                return out
            FrameworkRegistry._bundled_cache = out
        return FrameworkRegistry._bundled_cache

    def list(self) -> List[Dict[str, Any]]:
        items = {k: _summary(v, "bundled") for k, v in self.bundled().items()}
        for doc in self.store.query(C.FRAMEWORKS, {"doc_type": "definition"},
                                    fields=["framework_id", "version", "summary"]):
            key = (doc.get("framework_id"), doc.get("version"))
            if key not in items and doc.get("summary"):
                items[key] = doc["summary"]
        active = self.active_versions()
        out = []
        for key in sorted(items, key=lambda k: (k[0], version_key(k[1]))):
            item = dict(items[key])
            item["active"] = active.get(key[0]) == key[1]
            out.append(item)
        return out

    def versions(self, framework_id: str) -> List[str]:
        return sorted({v for (f, v) in self.bundled() if f == framework_id} |
                      {d.get("version") for d in self.store.query(
                          C.FRAMEWORKS, {"doc_type": "definition", "framework_id": framework_id},
                          fields=["version"])}, key=version_key)

    def active_versions(self) -> Dict[str, str]:
        chosen = {d["framework_id"]: d["version"] for d in self.store.query(
            C.FRAMEWORKS, {"doc_type": "active"}, fields=["framework_id", "version"])
            if d.get("framework_id") and d.get("version")}
        ids = {f for (f, _) in self.bundled()} | {d.get("framework_id") for d in self.store.query(
            C.FRAMEWORKS, {"doc_type": "definition"}, fields=["framework_id"])}
        out = {}
        for fw in ids:
            versions = self.versions(fw)
            if not versions:
                continue
            out[fw] = chosen[fw] if chosen.get(fw) in versions else versions[-1]
        return out

    def get(self, framework_id: str, version: str = "") -> Dict[str, Any]:
        version = version or self.active_versions().get(framework_id, "")
        if not version:
            raise NotFoundError("unknown framework", {"framework_id": framework_id})
        defn = self.bundled().get((framework_id, version))
        if defn is not None:
            return defn
        doc = self.store.get(C.FRAMEWORKS, definition_key(framework_id, version))
        if not doc or not doc.get("definition_json"):
            raise NotFoundError("framework version not found", {"framework_id": framework_id, "version": version})
        return json.loads(doc["definition_json"])

    def import_definition(self, raw: bytes, actor: str) -> Dict[str, Any]:
        if len(raw) > MAX_BYTES:
            raise ValidationError("definition is larger than %d bytes" % MAX_BYTES)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ValidationError("definition is not valid JSON")
        defn = validate_definition(parsed)
        if (defn["framework_id"], defn["version"]) in self.bundled():
            raise ValidationError("this framework version is bundled with the app")
        summary = _summary(defn, "imported")
        self.store.upsert(C.FRAMEWORKS, {
            "_key": definition_key(defn["framework_id"], defn["version"]), "doc_schema": DOC_SCHEMA,
            "doc_type": "definition", "framework_id": defn["framework_id"], "version": defn["version"],
            "summary": summary, "definition_json": json.dumps(defn, separators=(",", ":")),
            "sha256": sha256_json(defn), "imported_by": actor, "imported_at": utc_now_iso()})
        return summary

    def activate(self, framework_id: str, version: str, actor: str) -> Dict[str, Any]:
        if version not in self.versions(framework_id):
            raise NotFoundError("framework version not found", {"framework_id": framework_id, "version": version})
        self.store.upsert(C.FRAMEWORKS, {"_key": safe_key("active", framework_id), "doc_schema": DOC_SCHEMA,
                                         "doc_type": "active", "framework_id": framework_id,
                                         "version": version, "set_by": actor, "set_at": utc_now_iso()})
        return {"framework_id": framework_id, "version": version}

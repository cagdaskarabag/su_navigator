"""Platform capability detection (Enterprise vs Cloud, SHC, KV Store, RBAC).

Every probe records *how* the answer was obtained. A capability that could not
be determined is ``unknown`` — never assumed available.
"""

import dataclasses
from typing import Any, Dict, List, Optional

from ..errors import StorageError
from ..storage.transport import SplunkdTransport

AVAILABLE, UNAVAILABLE, UNKNOWN = "available", "unavailable", "unknown"


@dataclasses.dataclass
class Capability:
    name: str
    status: str
    evidence: str
    details: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class PlatformReport:
    platform: str  # enterprise | cloud | unknown
    version: str
    server_roles: List[str]
    shc_member: bool
    capabilities: List[Capability]
    user: str
    user_capabilities: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def status(self, name: str) -> str:
        for cap in self.capabilities:
            if cap.name == name:
                return cap.status
        return UNKNOWN


def _first_content(data: Any) -> Dict[str, Any]:
    entries = (data or {}).get("entry") or []
    return (entries[0].get("content") or {}) if entries else {}


class PlatformProbe:
    def __init__(self, transport: SplunkdTransport):
        self.t = transport

    def server_info(self) -> Dict[str, Any]:
        return _first_content(self.t.json("GET", "/services/server/info"))

    def current_context(self) -> Dict[str, Any]:
        return _first_content(self.t.json("GET", "/services/authentication/current-context"))

    def user_capabilities(self) -> List[str]:
        try:
            return list(self.current_context().get("capabilities") or [])
        except StorageError:
            return []

    def is_shc_member(self) -> Optional[bool]:
        try:
            status, _ = self.t.request("GET", "/services/shcluster/member/info", {"output_mode": "json"})
        except StorageError:
            return None
        if status == 200:
            return True
        if status in (404, 503, 400):
            return False
        return None

    def is_shc_captain(self) -> Optional[bool]:
        try:
            member = self.t.json("GET", "/services/shcluster/member/info")
            captain = self.t.json("GET", "/services/shcluster/captain/info")
        except StorageError:
            return None
        member_label = _first_content(member).get("label")
        captain_label = _first_content(captain).get("label")
        if not member_label or not captain_label:
            return None
        return member_label == captain_label

    def report(self, remote_sync_enabled: bool) -> PlatformReport:
        caps: List[Capability] = []
        try:
            info = self.server_info()
        except StorageError as exc:
            info = {}
            caps.append(Capability("server_info", UNKNOWN, "server/info failed", {"status": exc.status}))
        instance_type = str(info.get("instance_type", "")).lower()
        platform = "cloud" if instance_type == "cloud" else ("enterprise" if info else "unknown")
        roles = [str(r) for r in info.get("server_roles") or []]

        try:
            kv = _first_content(self.t.json("GET", "/services/kvstore/status"))
            current = kv.get("current") or {}
            kv_status = current.get("status", "unknown")
            caps.append(Capability("kvstore", AVAILABLE if kv_status == "ready" else UNAVAILABLE,
                                   "kvstore/status", {"status": kv_status,
                                                      "replication": current.get("replicationStatus")}))
        except StorageError as exc:
            caps.append(Capability("kvstore", UNKNOWN, "kvstore/status not readable by caller",
                                   {"status": exc.status}))

        try:
            ctx = self.current_context()
            user = str(ctx.get("username", ""))
            user_caps = sorted(ctx.get("capabilities") or [])
        except StorageError:
            user, user_caps = "", []

        caps.append(Capability(
            "remote_content_sync", AVAILABLE if remote_sync_enabled else UNAVAILABLE,
            "ucm.conf remote_sync_enabled; egress is verified only by an actual sync",
            {"egress_verified": False}))
        caps.append(Capability("offline_import", AVAILABLE, "always supported (no network required)"))
        caps.append(Capability("manage_content", AVAILABLE if "ucm_manage_content" in user_caps else UNAVAILABLE,
                               "caller capability ucm_manage_content"))
        caps.append(Capability("run_discovery", AVAILABLE if "ucm_run_discovery" in user_caps else UNAVAILABLE,
                               "caller capability ucm_run_discovery"))
        for name, path in (("index_listing", "/services/data/indexes"),
                           ("app_listing", "/services/apps/local"),
                           ("datamodel_listing", "/services/data/models")):
            try:
                self.t.json("GET", path, {"count": "1"})
                caps.append(Capability(name, AVAILABLE, path))
            except StorageError as exc:
                status = UNAVAILABLE if exc.status in (403, 404, 402) else UNKNOWN
                caps.append(Capability(name, status, path, {"status": exc.status}))
        caps.append(Capability(
            "adhoc_search", AVAILABLE if "search" in user_caps else UNAVAILABLE,
            "caller capability search (tstats is attempted only when a discovery job runs)"))
        shc = self.is_shc_member()
        return PlatformReport(platform=platform, version=str(info.get("version", "")), server_roles=roles,
                              shc_member=bool(shc), capabilities=caps, user=user, user_capabilities=user_caps)

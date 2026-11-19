"""Secret retrieval from Splunk's ``storage/passwords`` (encrypted at rest)."""

from typing import Optional
from urllib.parse import quote

from . import APP_NAME
from .errors import StorageError
from .storage.transport import SplunkdTransport

REALM = APP_NAME


def get_secret(transport: SplunkdTransport, name: str, app: str = APP_NAME) -> Optional[str]:
    entity = quote("%s:%s:" % (REALM, name), safe="")
    path = "/servicesNS/nobody/%s/storage/passwords/%s" % (quote(app), entity)
    try:
        data = transport.json("GET", path)
    except StorageError as exc:
        if exc.status in (403, 404):
            return None
        raise
    for entry in (data or {}).get("entry", []):
        value = (entry.get("content") or {}).get("clear_password")
        if isinstance(value, str) and value:
            return value
    return None

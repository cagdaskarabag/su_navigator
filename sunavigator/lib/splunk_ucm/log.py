"""Structured JSON logging.

Inside Splunk, records go to ``$SPLUNK_HOME/var/log/splunk/<app>.log`` which
splunkd indexes into ``_internal`` automatically. Outside Splunk (tests, CLI)
records go to stderr.
"""

import json
import logging
import logging.handlers
import os
from typing import Any, Dict

from . import APP_NAME

_CONFIGURED = False
_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _log_path() -> str:
    home = os.environ.get("SPLUNK_HOME")
    if not home:
        return ""
    return os.path.join(home, "var", "log", "splunk", APP_NAME + ".log")


def get_logger(name: str) -> logging.Logger:
    global _CONFIGURED
    root = logging.getLogger("splunk_ucm")
    if not _CONFIGURED:
        path = _log_path()
        if path and os.path.isdir(os.path.dirname(path)):
            handler: logging.Handler = logging.handlers.RotatingFileHandler(
                path, maxBytes=25 * 1024 * 1024, backupCount=5)
        else:
            handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        root.addHandler(handler)
        root.setLevel(os.environ.get("UCM_LOG_LEVEL", "INFO").upper())
        root.propagate = False
        _CONFIGURED = True
    if name.startswith("splunk_ucm"):
        return logging.getLogger(name)
    return root.getChild(name)


def set_level(level: str) -> None:
    logging.getLogger("splunk_ucm").setLevel(level.upper())

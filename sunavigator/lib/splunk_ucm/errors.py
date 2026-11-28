"""Exception hierarchy shared by all services.

Every exception carries a stable machine-readable ``code`` so REST responses
and audit records can report failures without leaking internals.
"""

from typing import Any, Dict, Optional


class UcmError(Exception):
    code = "ucm_error"
    http_status = 500

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


class ValidationError(UcmError):
    code = "validation_error"
    http_status = 400


class NotFoundError(UcmError):
    code = "not_found"
    http_status = 404


class FeatureDisabled(UcmError):
    """The route belongs to an optional module that the administrator has not turned on."""

    code = "feature_disabled"
    http_status = 404


class PermissionDenied(UcmError):
    code = "permission_denied"
    http_status = 403


class ConflictError(UcmError):
    code = "conflict"
    http_status = 409


class UnsupportedOperation(UcmError):
    """The current platform or configuration does not support the operation."""

    code = "unsupported"
    http_status = 409


class ProviderError(UcmError):
    """A content provider could not deliver content."""

    code = "provider_error"
    http_status = 502


class RateLimitedError(ProviderError):
    code = "provider_rate_limited"

    def __init__(self, message: str, reset_epoch: Optional[float] = None, **kw: Any):
        super().__init__(message, kw.get("details"))
        self.reset_epoch = reset_epoch


class IntegrityError(ProviderError):
    code = "integrity_error"


class SchemaIncompatibleError(ProviderError):
    code = "schema_incompatible"


class StorageError(UcmError):
    code = "storage_error"
    http_status = 502

    def __init__(self, message: str, status: Optional[int] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.status = status

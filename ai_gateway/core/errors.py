"""
Typed gateway errors (D-41).

Execution routes answer every refusal with the closed
:class:`~ai_sdk_m8.schemas.AiError` body: a ``code``, an opaque per-request
``request_id`` and, where it applies, ``retry_after_seconds`` (mirrored in
``Retry-After``). Nothing else — no exception text, no header, no body
excerpt — reaches the caller.
"""

from __future__ import annotations

import secrets

from ai_sdk_m8.schemas import AiError, AiErrorCode, ProviderStatusClass
from ai_sdk_m8.schemas.errors import ProviderMetadata
from fastapi import Request
from fastapi.responses import JSONResponse

#: HTTP status of each code when a route does not choose another.
DEFAULT_STATUS: dict[AiErrorCode, int] = {
    AiErrorCode.UNAUTHORIZED: 401,
    AiErrorCode.CONTEXT_MISSING: 401,
    AiErrorCode.CONTEXT_INVALID: 401,
    AiErrorCode.CONTEXT_EXPIRED: 401,
    AiErrorCode.CONTEXT_REPLAYED: 401,
    AiErrorCode.FORBIDDEN_SCOPE: 403,
    AiErrorCode.DATA_CLASS_DENIED: 403,
    AiErrorCode.BOUNDARY_DENIED: 403,
    AiErrorCode.PROFILE_UNKNOWN: 404,
    AiErrorCode.CAPABILITY_UNSUPPORTED: 422,
    AiErrorCode.EXECUTION_IDENTITY_CHANGED: 409,
    AiErrorCode.REQUEST_TOO_LARGE: 413,
    AiErrorCode.QUOTA_EXCEEDED: 429,
    AiErrorCode.RATE_LIMITED: 429,
    AiErrorCode.CREDENTIAL_UNAVAILABLE: 503,
    AiErrorCode.PROVIDER_UNREACHABLE: 502,
    AiErrorCode.PROVIDER_REJECTED: 502,
    AiErrorCode.RESPONSE_TOO_LARGE: 502,
    AiErrorCode.TIMEOUT: 504,
    AiErrorCode.BREAKER_OPEN: 503,
    AiErrorCode.CLOCK_SKEW_EXCEEDED: 503,
    AiErrorCode.CAPACITY_EXHAUSTED: 503,
    AiErrorCode.RESTORE_DETECTED: 503,
}


def new_request_id() -> str:
    """An opaque, unguessable request id (``[A-Za-z0-9_-]{22}``)."""
    return secrets.token_urlsafe(16)


class GatewayError(Exception):
    """A typed refusal; its message is the code alone."""

    def __init__(
        self,
        code: AiErrorCode,
        *,
        status_code: int | None = None,
        retry_after_seconds: int | None = None,
        provider_status_class: ProviderStatusClass | None = None,
        provider_metadata: ProviderMetadata | None = None,
    ) -> None:
        self.code = code
        self.status_code = status_code or DEFAULT_STATUS[code]
        self.retry_after_seconds = retry_after_seconds
        self.provider_status_class = provider_status_class
        self.provider_metadata = provider_metadata
        super().__init__(code.value)


def error_response(error: GatewayError) -> JSONResponse:
    """The ``AiError`` answer of ``error``."""
    body = AiError(
        code=error.code,
        request_id=new_request_id(),
        retry_after_seconds=error.retry_after_seconds,
        provider_status_class=error.provider_status_class,
        provider_metadata=error.provider_metadata,
    )
    headers = {}
    if error.retry_after_seconds is not None:
        headers["Retry-After"] = str(error.retry_after_seconds)
    return JSONResponse(
        body.model_dump(mode="json", exclude_none=True),
        status_code=error.status_code,
        headers=headers,
    )


async def gateway_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """FastAPI exception handler for :class:`GatewayError`."""
    assert isinstance(exc, GatewayError)  # nosec B101 - registered for this type
    return error_response(exc)


__all__ = [
    "DEFAULT_STATUS",
    "GatewayError",
    "error_response",
    "gateway_error_handler",
    "new_request_id",
]

"""
Refusals of the management controllers.

A controller raises one of these with a fixed, operator-readable detail; the
handler answers ``{"detail": …}`` with the error's status, the shape
``fastapi-m8``'s tier denials already use. A detail never carries a secret,
and never says whether a row exists in a scope the caller cannot see.
"""

from __future__ import annotations

from typing import ClassVar

from fastapi import Request
from fastapi.responses import JSONResponse


class ManagementError(Exception):
    """A refused management request; ``detail`` is safe to return."""

    status_code: ClassVar[int] = 400

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class NotFound(ManagementError):
    """No such row, or none the caller may see."""

    status_code = 404


class Conflict(ManagementError):
    """The change contradicts the row's state (frozen, duplicate, in use)."""

    status_code = 409


class Invalid(ManagementError):
    """The request is well-formed but its values are refused."""

    status_code = 422


class Forbidden(ManagementError):
    """The caller's tier or the deployment's configuration refuses the action."""

    status_code = 403


class TooManyRequests(ManagementError):
    """A per-principal rate limit is spent; retry after ``retry_after``."""

    status_code = 429

    def __init__(self, detail: str, retry_after: int) -> None:
        super().__init__(detail)
        self.retry_after = retry_after


async def management_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """FastAPI exception handler for :class:`ManagementError`."""
    assert isinstance(exc, ManagementError)  # nosec B101 - registered for this type
    headers = {}
    if isinstance(exc, TooManyRequests):
        headers["Retry-After"] = str(exc.retry_after)
    return JSONResponse(
        {"detail": exc.detail}, status_code=exc.status_code, headers=headers
    )


__all__ = [
    "Conflict",
    "Forbidden",
    "Invalid",
    "ManagementError",
    "NotFound",
    "TooManyRequests",
    "management_error_handler",
]

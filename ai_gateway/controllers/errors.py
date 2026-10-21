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


async def management_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """FastAPI exception handler for :class:`ManagementError`."""
    assert isinstance(exc, ManagementError)  # nosec B101 - registered for this type
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


__all__ = [
    "Conflict",
    "Invalid",
    "ManagementError",
    "NotFound",
    "management_error_handler",
]

"""
The mandatory dependency of every execution route.

An execution route authorizes a provider call from a signed job context
presented by an authenticated service client — never from a user JWT. Every
execution route is registered on a router built by :func:`build_execution_router`,
which attaches :func:`require_job_context` to the whole router so no route can
be added without it.

Every execution route also refuses to run while the application and
database clocks disagree by more than ``AI_MAX_CLOCK_SKEW_SECONDS``: every
lease and deadline is a database-clock predicate, so a skewed process answers
the typed ``503 clock_skew_exceeded`` instead (D-24).

Current state: the job-context verifier does not exist yet, so
:func:`require_job_context` **fails closed** — every request is refused with
``401 context_invalid``, whatever it carries. It never reads the
``Authorization`` header, so a user JWT cannot reach an execution route. The
verifying implementation replaces its body; the router factory stays.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

#: Header carrying the compact signed job context.
JOB_CONTEXT_HEADER = "X-AI-Job-Context"

#: Typed refusal code; the token is never echoed.
CONTEXT_INVALID = "context_invalid"


def require_job_context(request: Request) -> None:
    """
    Refuse the request: no job context can be verified yet.

    Parameters
    ----------
    request
        The incoming request. Only its job-context header would be consulted;
        the ``Authorization`` header is never read here.

    Raises
    ------
    HTTPException
        Always ``401`` with the ``context_invalid`` code.

    """
    del request
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": CONTEXT_INVALID},
    )


def require_clock_within_bound() -> None:
    """Refuse execution while the clock skew exceeds its bound (D-24)."""
    from ai_gateway.core.deps import clock  # noqa: PLC0415 - built once at import

    clock.require_within_bound()


def build_execution_router(**kwargs: Any) -> APIRouter:
    """
    Return a router whose every route runs the execution guards.

    The clock-skew guard runs first, then :func:`require_job_context`.

    Parameters
    ----------
    **kwargs
        Forwarded to :class:`fastapi.APIRouter`, except ``dependencies``, which
        this factory owns.

    Returns
    -------
    APIRouter
        The guarded router.

    Raises
    ------
    TypeError
        If ``dependencies`` is passed, since the guard must not be replaced or
        reordered by a caller.

    """
    if "dependencies" in kwargs:
        raise TypeError("execution routers own their dependencies")
    return APIRouter(
        dependencies=[
            Depends(require_clock_within_bound),
            Depends(require_job_context),
        ],
        **kwargs,
    )

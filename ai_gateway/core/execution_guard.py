"""The mandatory dependency of every execution route.

An execution route authorizes a provider call from a signed job context
presented by an authenticated service client — never from a user JWT. Every
execution route is registered on a router built by :func:`build_execution_router`,
which attaches :func:`require_job_context` to the whole router so no route can
be added without it.

Scaffold state: the job-context verifier and the service-client guard do not
exist yet, so this dependency **fails closed** — every request is refused with
``401 context_invalid``, whatever it carries. It never reads the
``Authorization`` header, so a user JWT cannot reach an execution route. The
verifying implementation replaces the body of :func:`require_job_context`; the
router factory and the refusal shape stay.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

#: Header carrying the compact signed job context.
JOB_CONTEXT_HEADER = "X-AI-Job-Context"

#: Typed refusal code; the token is never echoed.
CONTEXT_INVALID = "context_invalid"


def require_job_context(request: Request) -> None:
    """Refuse the request: no job context can be verified yet.

    Args:
        request: The incoming request. Only its job-context header would be
            consulted; the ``Authorization`` header is never read here.

    Raises:
        HTTPException: Always ``401`` with the ``context_invalid`` code.
    """
    del request
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": CONTEXT_INVALID},
    )


def build_execution_router(**kwargs: Any) -> APIRouter:
    """Return a router whose every route depends on :func:`require_job_context`.

    Args:
        **kwargs: Forwarded to :class:`fastapi.APIRouter`, except
            ``dependencies``, which this factory owns.

    Returns:
        The guarded router.

    Raises:
        TypeError: If ``dependencies`` is passed, since the guard must not be
            replaced or reordered by a caller.
    """
    if "dependencies" in kwargs:
        raise TypeError("execution routers own their dependencies")
    return APIRouter(dependencies=[Depends(require_job_context)], **kwargs)

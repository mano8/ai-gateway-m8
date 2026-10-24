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
the typed ``503 clock_skew_exceeded`` instead (D-24). It refuses with ``503
restore_detected`` while its database is behind the spool's high-water or a
restore is held (:mod:`~ai_gateway.core.restore_state`); the reservation
transaction re-checks the hold.

:func:`require_job_context`, in order:

1. takes the route's capability from the SDK route table
   (:data:`ROUTE_CAPABILITIES`); a route outside it is refused, so a new
   route cannot run before its capability is declared;
2. authenticates the service client through the ``fastapi-m8`` guard bound to
   ``AI_SERVICE_CLIENTS`` with that capability's ``execute:`` scope (R-07):
   ``401 unauthorized`` for a missing, unknown or wrong credential, ``403
   forbidden_scope`` for a client without the scope;
3. verifies ``X-AI-Job-Context`` (C-03): ``401 context_missing`` when absent,
   otherwise ``context_invalid`` / ``context_expired``.

It returns the :class:`~ai_gateway.core.job_context.JobContextPrincipal`;
an endpoint receives the same, computed once, through :data:`JobContextDep`.
The handler binds the request's profile and redeems the context inside the
transaction that records the execution. The ``Authorization`` header is
never read, so a user JWT cannot reach an execution route.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, Final

from ai_sdk_m8.client import routes
from ai_sdk_m8.schemas import AiErrorCode, Capability
from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from fastapi_m8 import INTERNAL_CLIENT_HEADER, INTERNAL_TOKEN_HEADER

from .errors import GatewayError
from .job_context import JobContextPrincipal
from .restore_state import assert_not_held

#: Header carrying the compact signed job context.
JOB_CONTEXT_HEADER = "X-AI-Job-Context"

#: The capability of each execution route, from the SDK route table (C-02).
ROUTE_CAPABILITIES: Final[dict[str, Capability]] = {
    routes.EXECUTE_OCR.path: Capability.OCR,
    routes.EXECUTE_OCR_DISPATCH.path: Capability.OCR,
    routes.EXECUTE_EMBED.path: Capability.EMBEDDING,
    routes.EXECUTE_RERANK.path: Capability.RERANK,
    routes.EXECUTE_STRUCTURED_OUTPUT.path: Capability.STRUCTURED_OUTPUT,
}


def route_capability(request: Request) -> Capability:
    """The capability the matched route executes; refuse an undeclared route."""
    route = request.scope.get("route")
    path = getattr(route, "path", "")
    for template, capability in ROUTE_CAPABILITIES.items():
        if path.endswith(f"/{template}"):
            return capability
    raise GatewayError(AiErrorCode.CONTEXT_INVALID)


def authenticate_service_client(
    guard: Callable[[Request], str], request: Request
) -> str:
    """Run a ``fastapi-m8`` service-client guard; answer its refusal typed."""
    try:
        return guard(request)
    except HTTPException as exc:
        code = (
            AiErrorCode.FORBIDDEN_SCOPE
            if exc.status_code == status.HTTP_403_FORBIDDEN
            else AiErrorCode.UNAUTHORIZED
        )
        raise GatewayError(code) from None


def require_job_context(request: Request) -> JobContextPrincipal:
    """
    Authenticate the service client and verify its job context.

    Parameters
    ----------
    request
        The incoming request. Only the service-client and job-context
        headers are read; the ``Authorization`` header never is.

    Returns
    -------
    JobContextPrincipal
        The verified context, bound to its presenter and the route's
        capability; not yet redeemed.

    Raises
    ------
    GatewayError
        Every refusal, typed (see the module docstring).

    """
    from ai_gateway.core.deps import (  # noqa: PLC0415 - built once at import
        execution_client_guards,
        job_contexts,
    )

    capability = route_capability(request)
    client_id = authenticate_service_client(
        execution_client_guards[capability], request
    )
    return job_contexts.verify(
        request.headers.get(JOB_CONTEXT_HEADER),
        presenter=client_id,
        capability=capability,
    )


#: The service-client scheme, for the OpenAPI document only (``auto_error``
#: off: it never refuses — the guards above do). One scheme, because an
#: OpenAPI requirement per header would read as alternatives.
SERVICE_CLIENT_SCHEME: Final = APIKeyHeader(
    name=INTERNAL_CLIENT_HEADER,
    scheme_name="ServiceClient",
    description=(
        f"A registered service client: {INTERNAL_CLIENT_HEADER} with its "
        f"{INTERNAL_TOKEN_HEADER}, and the signed job context in "
        f"{JOB_CONTEXT_HEADER}. A user JWT is never accepted."
    ),
    auto_error=False,
)


#: The verified job context of an execution request.
JobContextDep = Annotated[JobContextPrincipal, Depends(require_job_context)]


def require_clock_within_bound() -> None:
    """Refuse execution while the clock skew exceeds its bound (D-24)."""
    from ai_gateway.core.deps import clock  # noqa: PLC0415 - built once at import

    clock.require_within_bound()


def require_restore_clear() -> None:
    """Refuse execution while the database is behind its high-water or held."""
    from ai_gateway.core.deps import db_engine, settings  # noqa: PLC0415

    with db_engine.connect() as connection:
        assert_not_held(connection, settings.AI_OCR_SPOOL_DIR, budgeted=False)


def build_execution_router(
    *, gate: Callable[[], None] | None = None, **kwargs: Any
) -> APIRouter:
    """
    Return a router whose every route runs the execution guards.

    The clock-skew guard runs first, then the restore guard, then
    :func:`require_job_context`.

    Parameters
    ----------
    gate
        An optional dependency run before both guards — a route family that
        is not served answers before any credential is read.
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
    guards = [
        Depends(require_clock_within_bound),
        Depends(require_restore_clear),
        Depends(require_job_context),
    ]
    if gate is not None:
        guards.insert(0, Depends(gate))
    return APIRouter(dependencies=[*guards, Security(SERVICE_CLIENT_SCHEME)], **kwargs)


__all__ = [
    "SERVICE_CLIENT_SCHEME",
    "JOB_CONTEXT_HEADER",
    "ROUTE_CAPABILITIES",
    "JobContextDep",
    "authenticate_service_client",
    "build_execution_router",
    "require_clock_within_bound",
    "require_job_context",
    "require_restore_clear",
    "route_capability",
]

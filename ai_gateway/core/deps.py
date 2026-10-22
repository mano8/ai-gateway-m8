"""
Build-once site for auth and database dependencies.

Import ``auth``, ``engine``, the tier dependencies and ``SessionDep`` from here.
Never call ``build_auth_deps`` or ``create_db_engine`` a second time.

User authentication applies to management routes only (D-05): the reader,
writer, admin and superuser tiers, each on fastapi-m8's fresh-revocation path,
so a token revoked inside the positive-cache window is refused there. No
API-key principal is wired: no gateway route accepts one.

Execution routes depend on :mod:`ai_gateway.core.execution_guard` instead and
never accept a user JWT: a service client authenticated by the ``fastapi-m8``
guard over ``AI_SERVICE_CLIENTS``, with the capability's ``execute:`` scope
(R-07), presents a signed job context the verifier below checks (C-03).
"""

from collections.abc import Callable
from typing import Annotated

from ai_sdk_m8.schemas import V1_CAPABILITIES, Capability
from fastapi import Depends, Request
from sqlmodel import Session

from fastapi_m8 import (
    AuthDeps,
    DbEngine,
    UserModel,
    build_auth_deps,
    build_service_client_guard,
    create_db_engine,
)

from ai_gateway.controllers.resolution import ResolutionPolicy
from ai_gateway.credentials.factory import build_credential_store
from ai_gateway.execution.limits import ExecutionLimits
from ai_gateway.execution.service import ExecutionService
from ai_gateway.providers.breaker import breakers
from ai_gateway.providers.http import ClientFactory, ClientLimits
from ai_gateway.providers.registry import ADAPTERS

from .clock import ClockSkewMonitor
from .config import settings
from .job_context import InstallationAudience, JobContextVerifier
from .service_clients import PROFILES_READ, execute_scope
from .ssrf import DestinationPolicy
from .utc_session import pin_utc_session

# Single instances shared across the entire process.
auth: AuthDeps = build_auth_deps(settings)
engine: DbEngine = create_db_engine(settings)
# Every PostgreSQL session this engine opens runs in UTC.
pin_utc_session(engine._engine)
# Application–database clock skew, checked by /health and every execution.
clock = ClockSkewMonitor(lambda: engine._engine, settings.AI_MAX_CLOCK_SKEW_SECONDS)

CurrentUser = auth.CurrentUser
get_current_user = auth.get_current_user
get_current_active_reader = auth.get_current_active_reader
get_current_active_writer = auth.get_current_active_writer
get_current_active_admin = auth.get_current_active_admin
get_current_active_superuser = auth.get_current_active_superuser
#: Superuser-only management (SUPERADMIN role and ``is_superuser``, D-05).
require_superuser = get_current_active_superuser

CurrentReader = Annotated[UserModel, Depends(get_current_active_reader)]
CurrentWriter = Annotated[UserModel, Depends(get_current_active_writer)]
CurrentAdmin = Annotated[UserModel, Depends(get_current_active_admin)]
CurrentSuperuser = Annotated[UserModel, Depends(require_superuser)]

get_db = engine.session_dep
SessionDep = Annotated[Session, Depends(get_db)]
#: The SQLAlchemy engine controllers open Core transactions on.
db_engine = engine._engine
#: The provider destination posture every ``base_url`` write is checked against.
destination_policy = DestinationPolicy.from_settings(settings)
#: The configured credential store (C-06); the only path to credential material.
credential_store = build_credential_store(settings, engine._engine)
#: Builds the client of each provider call (D-20), on the process's breakers.
provider_clients = ClientFactory(
    destination_policy, ClientLimits.from_settings(settings), breakers
)
#: The execution core (D-24): the one path from a verified context to a provider.
execution_service = ExecutionService(
    engine._engine,
    credential_store,
    provider_clients,
    ADAPTERS,
    policy=lambda: ResolutionPolicy.from_settings(settings),
    limits=lambda: ExecutionLimits.from_settings(settings),
    breakers=breakers,
)

#: One service-client guard per capability, each requiring ``execute:<cap>``.
execution_client_guards: dict[Capability, Callable[[Request], str]] = {
    capability: build_service_client_guard(
        settings.service_clients.registry,
        required_scopes={execute_scope(capability)},
    )
    for capability in V1_CAPABILITIES
}
#: Service clients that read profiles without a user token (``T18``).
profiles_read_guard = build_service_client_guard(
    settings.service_clients.registry, required_scopes={PROFILES_READ}
)
#: Job-context verification against the registered issuer keys (C-03).
job_contexts = JobContextVerifier(
    settings.service_clients,
    audience=InstallationAudience(lambda: engine._engine),
    max_ttl_seconds=settings.AI_JOB_CONTEXT_MAX_TTL_SECONDS,
    skew_seconds=settings.AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS,
    dispatch_ttl_seconds=settings.AI_DISPATCH_CONTEXT_TTL_SECONDS,
)

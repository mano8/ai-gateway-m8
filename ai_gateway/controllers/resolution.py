"""
Which model, provider and credential serve an execution (C-04, D-08).

Called by the reservation (``T27``) inside the transaction that records the
result on the execution row, so the destination checked is the destination
dispatched.

**Precedence (C-04).** The user binding, then the tenant binding, then the
global one. The user binding consulted is the one whose ``(tenant_id,
owner_user_id)`` equal the **signed** context's ``(tenant_id, user_id)``, so
a context without ``user_id`` never consults one and a user's binding never
serves another tenant's context (N-07). A scope with no binding falls
through. A scope **with** a binding does not, unless the binding says
``fall_through`` — and then only when its credential is unavailable:
disabled, invalid, deleted, awaiting re-confirmation or re-provisioning,
throttled, or a user binding while ``AI_USER_BYOK_ENABLED`` is false (A-3).
Each fall-through is audited. Otherwise the binding fails closed:
``credential_unavailable``, or ``rate_limited`` with ``Retry-After`` while
throttled — before any provider request.

**Destination policy (D-08), applied to the candidate actually resolved.**
``rerank`` reaches ``local`` providers only, hard-wired (``boundary_denied``);
a signed ``allowed_boundaries`` must contain the provider's boundary
(``boundary_denied``); the data class must allow the destination —
``local``, the context's own BYOK (a tenant or user credential, which by the
precedence above is always the context's own), or a platform credential —
(``data_class_denied``); on the database backends a ``restricted`` OCR context
never reaches an ``external`` provider unless the restore residual was
accepted by a recorded human decision. A refusal here is terminal: a denied
candidate is never a reason to try the next scope (N-06).

A disabled profile, model or provider stops resolution too (terminal).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from ai_sdk_m8.jobcontext import JobContextPayload
from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    DataClass,
    ProviderBoundary,
)
from ai_sdk_m8.schemas.management import (
    CredentialStatus,
    OnUnavailable,
    ScopeType,
)

from ai_gateway.core.errors import GatewayError
from ai_gateway.core.identities import embedding_space_id
from ai_gateway.core.policy import DataClassPolicy, Destination
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_binding,
    ai_profile_revision,
    ai_provider,
)

from .audit import Actor, AuditedTransaction
from .registry import Row
from .scopes import GLOBAL, Scope

_SYSTEM = Actor("system")


@dataclass(frozen=True)
class ExecutionRequest:
    """What a verified job context asks for."""

    profile_key: str
    capability: Capability
    data_class: DataClass
    tenant_id: str | None = None
    user_id: str | None = None
    allowed_boundaries: tuple[ProviderBoundary, ...] | None = None

    @classmethod
    def from_context(cls, payload: JobContextPayload) -> ExecutionRequest:
        """The request a verified context signs."""
        return cls(
            profile_key=payload.profile_key,
            capability=payload.capability,
            data_class=payload.data_class,
            tenant_id=payload.tenant_id,
            user_id=payload.user_id,
            allowed_boundaries=payload.allowed_boundaries,
        )


@dataclass(frozen=True)
class ResolutionPolicy:
    """The deployment settings resolution depends on."""

    data_classes: DataClassPolicy
    user_byok_enabled: bool
    database_backend: bool
    restricted_ocr_residual_accepted: bool = False

    @classmethod
    def from_settings(cls, settings: Any) -> ResolutionPolicy:
        """From gateway ``Settings``, read at call time."""
        return cls(
            data_classes=settings.data_class_policy,
            user_byok_enabled=settings.user_byok_enabled,
            database_backend=settings.AI_CREDENTIAL_STORAGE_BACKEND == "database",
            restricted_ocr_residual_accepted=bool(
                settings.AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED
            ),
        )


@dataclass(frozen=True)
class Resolution:
    """The destination an execution records and the adapter may use, only."""

    binding_id: uuid.UUID
    scope_type: ScopeType
    profile_id: uuid.UUID
    profile_revision: int
    model_id: uuid.UUID
    provider_id: uuid.UUID
    provider_type: str
    boundary: ProviderBoundary
    destination: Destination
    credential_id: uuid.UUID | None
    credential_version: int | None
    execution_identity: str
    embedding_space_id: str | None


class _Unavailable(Exception):
    """The candidate's credential cannot serve; ``error`` if it fails closed."""

    def __init__(self, error: GatewayError, reason: str) -> None:
        self.error = error
        self.reason = reason


def _uuid(value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def candidate_scopes(request: ExecutionRequest) -> list[Scope]:
    """The scopes to consult, in C-04 order, from the signed claims only."""
    tenant, user = _uuid(request.tenant_id), _uuid(request.user_id)
    scopes: list[Scope] = []
    tenant_usable = request.tenant_id is None or tenant is not None
    if user is not None and tenant_usable:
        scopes.append(Scope(ScopeType.USER, tenant_id=tenant, owner_user_id=user))
    if tenant is not None:
        scopes.append(Scope(ScopeType.TENANT, tenant_id=tenant))
    scopes.append(GLOBAL)
    return scopes


def _profile(connection: sa.Connection, request: ExecutionRequest) -> Row:
    profile = (
        connection.execute(
            sa.select(
                ai_profile.c.id,
                ai_profile.c.capability,
                ai_profile.c.enabled,
                ai_profile.c.current_revision,
                ai_profile_revision.c.execution_config_hash,
            )
            .join(
                ai_profile_revision,
                sa.and_(
                    ai_profile_revision.c.profile_id == ai_profile.c.id,
                    ai_profile_revision.c.revision == ai_profile.c.current_revision,
                ),
            )
            .where(ai_profile.c.profile_key == request.profile_key)
        )
        .mappings()
        .first()
    )
    if profile is None or not profile["enabled"]:
        raise GatewayError(AiErrorCode.PROFILE_UNKNOWN)
    if profile["capability"] != request.capability.value:
        raise GatewayError(AiErrorCode.CAPABILITY_UNSUPPORTED)
    return profile


def _binding(
    connection: sa.Connection, profile_id: uuid.UUID, scope: Scope
) -> Row | None:
    b, m, p, c = ai_profile_binding, ai_model, ai_provider, ai_credential
    statement = (
        sa.select(
            b.c.id.label("binding_id"),
            b.c.on_unavailable,
            m.c.id.label("model_id"),
            m.c.enabled.label("model_enabled"),
            m.c.capabilities,
            m.c.external_model_id,
            m.c.model_revision,
            m.c.dimensions,
            m.c.execution_identity,
            p.c.id.label("provider_id"),
            p.c.enabled.label("provider_enabled"),
            p.c.provider_type,
            p.c.boundary,
            c.c.id.label("credential_id"),
            c.c.status.label("credential_status"),
            c.c.current_version,
            (c.c.throttled_until > sa.func.now()).label("throttled"),
            sa.func.ceil(
                sa.func.extract("epoch", c.c.throttled_until - sa.func.now())
            ).label("throttle_seconds"),
        )
        .join(m, m.c.id == b.c.model_id)
        .join(p, p.c.id == m.c.provider_id)
        .outerjoin(c, c.c.id == b.c.credential_id)
        .where(b.c.profile_id == profile_id, scope.where(b))
    )
    return connection.execute(statement).mappings().first()


def _check_available(row: Row, scope: Scope, policy: ResolutionPolicy) -> None:
    """Raise :class:`_Unavailable` when the candidate's credential cannot serve."""
    unavailable = GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)
    if scope.scope_type is ScopeType.USER and not policy.user_byok_enabled:
        raise _Unavailable(unavailable, "user_byok_disabled")
    if row["credential_id"] is None:
        return
    if row["credential_status"] != CredentialStatus.ACTIVE.value:
        raise _Unavailable(unavailable, f"credential_{row['credential_status']}")
    if row["throttled"]:
        retry = max(1, int(row["throttle_seconds"]))
        throttled = GatewayError(AiErrorCode.RATE_LIMITED, retry_after_seconds=retry)
        raise _Unavailable(throttled, "credential_throttled")


def _destination(row: Row, scope: Scope) -> Destination:
    if row["boundary"] == ProviderBoundary.LOCAL.value:
        return Destination.LOCAL
    if row["credential_id"] is not None and scope.scope_type is not ScopeType.GLOBAL:
        return Destination.EXTERNAL_BYOK
    return Destination.EXTERNAL_PLATFORM


def _check_serviceable(row: Row, request: ExecutionRequest) -> None:
    """The model and provider are enabled and the model has the capability."""
    if not (row["model_enabled"] and row["provider_enabled"]):
        raise GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)
    if request.capability.value not in row["capabilities"]:
        raise GatewayError(AiErrorCode.CAPABILITY_UNSUPPORTED)


def _check_boundary(row: Row, request: ExecutionRequest) -> ProviderBoundary:
    """``rerank`` is local-only (hard-wired); a signed claim must hold the boundary."""
    boundary = ProviderBoundary(row["boundary"])
    if (
        request.capability is Capability.RERANK
        and boundary is not ProviderBoundary.LOCAL
    ):
        raise GatewayError(AiErrorCode.BOUNDARY_DENIED)
    allowed = request.allowed_boundaries
    if allowed is not None and boundary not in allowed:
        raise GatewayError(AiErrorCode.BOUNDARY_DENIED)
    return boundary


def _check_data_class(
    boundary: ProviderBoundary,
    destination: Destination,
    request: ExecutionRequest,
    policy: ResolutionPolicy,
) -> None:
    """The D-08 table, then the restricted-OCR restore residual."""
    if not policy.data_classes.allows(request.data_class, destination):
        raise GatewayError(AiErrorCode.DATA_CLASS_DENIED)
    restore_residual = (
        request.capability is Capability.OCR
        and request.data_class is DataClass.RESTRICTED
        and boundary is ProviderBoundary.EXTERNAL
        and policy.database_backend
        and not policy.restricted_ocr_residual_accepted
    )
    if restore_residual:
        raise GatewayError(AiErrorCode.DATA_CLASS_DENIED)


def _check_destination(
    row: Row, scope: Scope, request: ExecutionRequest, policy: ResolutionPolicy
) -> Destination:
    """D-08 on the resolved candidate; every refusal is terminal (N-06)."""
    _check_serviceable(row, request)
    boundary = _check_boundary(row, request)
    destination = _destination(row, scope)
    _check_data_class(boundary, destination, request, policy)
    return destination


def _resolution(
    row: Row, scope: Scope, profile: Row, destination: Destination
) -> Resolution:
    space = None
    if Capability(profile["capability"]) is Capability.EMBEDDING:
        space = embedding_space_id(
            row["provider_id"],
            row["external_model_id"],
            row["model_revision"],
            row["dimensions"],
            profile["execution_config_hash"],
        )
    has_key = row["credential_id"] is not None
    return Resolution(
        binding_id=row["binding_id"],
        scope_type=scope.scope_type,
        profile_id=profile["id"],
        profile_revision=profile["current_revision"],
        model_id=row["model_id"],
        provider_id=row["provider_id"],
        provider_type=row["provider_type"],
        boundary=ProviderBoundary(row["boundary"]),
        destination=destination,
        credential_id=row["credential_id"],
        credential_version=row["current_version"] if has_key else None,
        execution_identity=row["execution_identity"],
        embedding_space_id=space,
    )


def resolve(
    tx: AuditedTransaction, request: ExecutionRequest, policy: ResolutionPolicy
) -> Resolution:
    """Resolve ``request`` to the one destination it may use, or refuse."""
    profile = _profile(tx.connection, request)
    for scope in candidate_scopes(request):
        row = _binding(tx.connection, profile["id"], scope)
        if row is None:
            continue
        try:
            _check_available(row, scope, policy)
        except _Unavailable as unavailable:
            # A global binding never holds fall_through (refused at creation);
            # if one did, the loop would end in profile_unknown, still closed.
            if row["on_unavailable"] != OnUnavailable.FALL_THROUGH.value:
                raise unavailable.error from None
            metadata = {**scope.audit(), "profile_key": request.profile_key}
            tx.admin(
                _SYSTEM,
                "binding.fall_through",
                "binding",
                row["binding_id"],
                {**metadata, "reason": unavailable.reason},
            )
            continue
        destination = _check_destination(row, scope, request, policy)
        return _resolution(row, scope, profile, destination)
    raise GatewayError(AiErrorCode.PROFILE_UNKNOWN)


__all__ = [
    "ExecutionRequest",
    "Resolution",
    "ResolutionPolicy",
    "candidate_scopes",
    "resolve",
]

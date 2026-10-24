"""
The reservation transaction (D-24 *Execution sequence*, step 2).

One transaction, in this order, and nothing else:

1. the destination, by C-04 precedence with D-08 and the destination policy
   applied to the candidate actually resolved
   (:func:`~ai_gateway.controllers.resolution.resolve`);
2. the model's and the provider's first use, stamped with
   ``UPDATE … SET first_used_at = now() WHERE … AND first_used_at IS NULL`` —
   which locks (and, through the T16 triggers, freezes) the row only on its
   first use, so a first reservation and an admin edit serialize while later
   reservations never contend for the row;
3. the model's frozen identity, re-read **after** the stamp, so the identity
   recorded is the one the row now keeps; a model disabled, flagged or
   stripped of the capability meanwhile is refused;
4. the execution-identity pin, when the request carries one;
5. the job context's ``(iss, jti)`` redemption, ``exp`` asserted on the
   database clock;
6. the fixed admission units, reserved against every scope the **signed**
   context names — ``client`` always, ``tenant`` and ``user`` when present —
   with ``UPDATE … WHERE reserved + used + :units <= :budget``, on the UTC
   budget day of the database clock;
7. one rate-window admission per principal and the client's occupancy slot;
8. the ``pending`` row, recording the scope ids, units, budget day,
   ``reservation_expires_at``, the resolved provider, boundary, model,
   profile revision and credential version, and the context's ``exp``.

**OCR** (``:dispatch``, D-44) does not create a row: step 8 is the CAS
``spooled → pending`` of the row phase 1 created, under the **spool
binding** — the dispatch context's ``spool_id`` is the row id, and its
``iss``, ``azp`` (the presenting client), ``job_ref``, ``attempt``,
``profile_key``, ``tenant_id``, ``user_id``, ``input_sha256``,
``input_bytes`` and ``ocr_options_hash`` equal the recorded ones, the spool
unexpired — else ``context_invalid``, the row untouched. The run's rate
admission and occupancy slot were taken at ``receiving`` and are carried,
never re-acquired (step 7 is skipped); the budget units are reserved here.
The dispatch context's own ``data_class`` is recorded, as the class the
policy evaluated.

A refusal anywhere rolls the whole transaction back: no row, no units, no
window, no slot, and the ``jti`` is not burned. Nothing after this
transaction re-resolves a binding, a model or a profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Final
from uuid import UUID, uuid4

import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability
from pydantic import JsonValue
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.controllers.audit import audited_transaction
from ai_gateway.controllers.resolution import (
    ExecutionRequest,
    Resolution,
    ResolutionPolicy,
    resolve,
)
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.metrics import QUOTA_REJECTIONS
from ai_gateway.core.restore_state import assert_not_held
from ai_gateway.core.identities import embedding_space_id
from ai_gateway.core.job_context import JobContextPrincipal
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import (
    ai_client_occupancy,
    ai_execution,
    ai_rate_window,
    ai_usage,
)
from ai_gateway.db_models.registry import ai_model, ai_profile_revision, ai_provider

from .jobs import Admission
from .limits import ExecutionLimits

_UTC_NOW: Final = sa.func.timezone("UTC", sa.func.now())

#: The UTC budget day of the database clock.
_BUDGET_DAY: Final = sa.cast(_UTC_NOW, sa.Date)

#: Seconds until the current UTC budget day ends.
_SECONDS_TO_NEXT_DAY: Final = sa.func.ceil(
    sa.func.extract(
        "epoch",
        sa.func.date_trunc("day", _UTC_NOW) + timedelta(days=1) - _UTC_NOW,
    )
)

#: Seconds left in the current rate window (a UTC minute).
_SECONDS_TO_NEXT_MINUTE: Final = sa.func.ceil(
    60 - sa.func.extract("second", sa.func.now())
)


@dataclass(frozen=True)
class Scope:
    """One accounting scope of an execution, keyed by a signed identifier."""

    scope_type: str
    scope_id: str
    daily_units: int | None

    @property
    def principal_key(self) -> str:
        """The rate-window key of this scope (``client:<id>``, …)."""
        return f"{self.scope_type}:{self.scope_id}"


def scopes_of(principal: JobContextPrincipal, limits: ExecutionLimits) -> list[Scope]:
    """``client`` always, then ``tenant`` and ``user`` when the context signs them."""
    payload = principal.payload
    scopes = [Scope("client", principal.client_id, limits.client_daily_units)]
    if payload.tenant_id is not None:
        scopes.append(Scope("tenant", payload.tenant_id, limits.tenant_daily_units))
    if payload.user_id is not None:
        scopes.append(Scope("user", payload.user_id, limits.user_daily_units))
    return scopes


@dataclass(frozen=True)
class Reservation:
    """A ``pending`` execution: what it reserved and the destination it recorded."""

    execution_id: UUID
    resolution: Resolution
    execution_identity: str
    embedding_space_id: str | None
    units: int
    client_id: str


@dataclass(frozen=True)
class _Frozen:
    execution_identity: str
    embedding_space_id: str | None
    config: dict[str, JsonValue]


def _stamp_first_use(connection: Connection, resolution: Resolution) -> None:
    for table, row_id in (
        (ai_model, resolution.model_id),
        (ai_provider, resolution.provider_id),
    ):
        connection.execute(
            sa.update(table)
            .where(table.c.id == row_id, table.c.first_used_at.is_(None))
            .values(first_used_at=sa.func.now())
        )


def _freeze(
    connection: Connection, resolution: Resolution, capability: Capability
) -> _Frozen:
    """Stamp first use, then read the identity the stamp froze."""
    _stamp_first_use(connection, resolution)
    model = (
        connection.execute(
            sa.select(ai_model).where(ai_model.c.id == resolution.model_id)
        )
        .mappings()
        .one()
    )
    if not model["enabled"] or model["flagged_at"] is not None:
        raise GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)
    if capability.value not in model["capabilities"]:
        raise GatewayError(AiErrorCode.CAPABILITY_UNSUPPORTED)
    revision = (
        connection.execute(
            sa.select(
                ai_profile_revision.c.execution_config,
                ai_profile_revision.c.execution_config_hash,
            ).where(
                ai_profile_revision.c.profile_id == resolution.profile_id,
                ai_profile_revision.c.revision == resolution.profile_revision,
            )
        )
        .mappings()
        .one()
    )
    space = None
    if capability is Capability.EMBEDDING:
        space = embedding_space_id(
            resolution.provider_id,
            model["external_model_id"],
            model["model_revision"],
            model["dimensions"],
            revision["execution_config_hash"],
        )
    return _Frozen(
        model["execution_identity"], space, dict(revision["execution_config"])
    )


def _reserve_units(connection: Connection, scope: Scope, day: date, units: int) -> None:
    key = sa.and_(
        ai_usage.c.scope_type == scope.scope_type,
        ai_usage.c.scope_id == scope.scope_id,
        ai_usage.c.day == day,
    )
    connection.execute(
        pg_insert(ai_usage)
        .values(scope_type=scope.scope_type, scope_id=scope.scope_id, day=day)
        .on_conflict_do_nothing()
    )
    statement = (
        sa.update(ai_usage).where(key).values(reserved=ai_usage.c.reserved + units)
    )
    if scope.daily_units is not None:
        statement = statement.where(
            ai_usage.c.reserved + ai_usage.c.used + units <= scope.daily_units
        )
    if connection.execute(statement.returning(ai_usage.c.day)).first() is None:
        QUOTA_REJECTIONS.labels(scope_type=scope.scope_type).inc()
        retry = int(connection.execute(sa.select(_SECONDS_TO_NEXT_DAY)).scalar_one())
        raise GatewayError(
            AiErrorCode.QUOTA_EXCEEDED, retry_after_seconds=max(1, retry)
        )


def _admit(connection: Connection, scope: Scope, limit: int | None) -> None:
    """Charge one admission in the scope's current rate window."""
    table = ai_rate_window
    statement = (
        pg_insert(table)
        .values(
            principal_key=scope.principal_key,
            window_start=sa.func.date_trunc("minute", sa.func.now()),
            count=1,
        )
        .on_conflict_do_update(
            index_elements=[table.c.principal_key, table.c.window_start],
            set_={"count": table.c.count + 1},
            where=None if limit is None else table.c.count < limit,
        )
        .returning(table.c.count)
    )
    if connection.execute(statement).first() is None:
        retry = int(connection.execute(sa.select(_SECONDS_TO_NEXT_MINUTE)).scalar_one())
        raise GatewayError(AiErrorCode.RATE_LIMITED, retry_after_seconds=max(1, retry))


def occupy(connection: Connection, client_id: str, cap: int | None) -> None:
    """Take one of the client's in-flight slots (D-24), or refuse."""
    table = ai_client_occupancy
    connection.execute(
        pg_insert(table)
        .values(client_id=client_id, occupied=0)
        .on_conflict_do_nothing()
    )
    statement = (
        sa.update(table)
        .where(table.c.client_id == client_id)
        .values(occupied=table.c.occupied + 1)
    )
    if cap is not None:
        statement = statement.where(table.c.occupied < cap)
    if connection.execute(statement.returning(table.c.occupied)).first() is None:
        raise GatewayError(AiErrorCode.RATE_LIMITED, retry_after_seconds=1)


def admit(
    connection: Connection,
    client_id: str,
    scopes: list[Scope],
    limits: ExecutionLimits,
) -> None:
    """The row-creation charges: one rate-window admission per scope, one slot."""
    for scope in scopes:
        _admit(connection, scope, limits.rate_per_minute)
    occupy(connection, client_id, limits.max_inflight_per_client)


def _pending_values(
    principal: JobContextPrincipal,
    job: Admission,
    resolution: Resolution,
    frozen: _Frozen,
    units: int,
    day: date,
    ttl_seconds: int,
) -> dict[str, object]:
    payload = principal.payload
    return {
        "status": ExecutionStatus.PENDING.value,
        "capability": job.capability.value,
        "profile_key": payload.profile_key,
        "data_class": payload.data_class.value,
        "client_scope_id": principal.client_id,
        "tenant_scope_id": payload.tenant_id,
        "user_scope_id": payload.user_id,
        "jti": payload.jti,
        "issuer": payload.iss,
        "azp": payload.azp,
        "job_ref": payload.job_ref,
        "attempt": payload.attempt,
        "reserved_units": units,
        "reservation_day": day,
        "reservation_expires_at": sa.func.now() + timedelta(seconds=ttl_seconds),
        "resolved_provider_id": resolution.provider_id,
        "resolved_boundary": resolution.boundary.value,
        "resolved_model_id": resolution.model_id,
        "resolved_profile_id": resolution.profile_id,
        "resolved_profile_revision": resolution.profile_revision,
        "resolved_credential_id": resolution.credential_id,
        "resolved_credential_version": resolution.credential_version,
        "context_exp": datetime.fromtimestamp(payload.exp, UTC),
        "execution_identity": frozen.execution_identity,
        "embedding_space_id": frozen.embedding_space_id,
    }


#: What the dispatch reservation writes on a ``spooled`` row; the binding
#: columns are immutable (T16) and asserted equal instead.
_DISPATCH_COLUMNS: Final = frozenset(
    {
        "status",
        "data_class",
        "reserved_units",
        "reservation_day",
        "reservation_expires_at",
        "resolved_provider_id",
        "resolved_boundary",
        "resolved_model_id",
        "resolved_profile_id",
        "resolved_profile_revision",
        "resolved_credential_id",
        "resolved_credential_version",
        "context_exp",
        "execution_identity",
        "embedding_space_id",
    }
)


def _bind_spool(
    connection: Connection, principal: JobContextPrincipal, values: dict[str, object]
) -> UUID:
    """``spooled → pending`` under the D-44 spool binding; the row id."""
    payload = principal.payload
    if payload.spool_id is None:
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)
    e = ai_execution
    bound = connection.execute(
        sa.update(e)
        .where(
            e.c.id == UUID(payload.spool_id),
            e.c.status == ExecutionStatus.SPOOLED.value,
            e.c.capability == Capability.OCR.value,
            e.c.spool_expires_at > sa.func.now(),
            e.c.client_scope_id == principal.client_id,
            e.c.issuer == payload.iss,
            e.c.azp == payload.azp,
            e.c.job_ref == payload.job_ref,
            e.c.attempt == payload.attempt,
            e.c.profile_key == payload.profile_key,
            e.c.tenant_scope_id.is_not_distinct_from(payload.tenant_id),
            e.c.user_scope_id.is_not_distinct_from(payload.user_id),
            e.c.input_sha256 == payload.input_sha256,
            e.c.input_bytes == payload.input_bytes,
            e.c.ocr_options_hash == payload.ocr_options_hash,
        )
        .values(
            **{k: v for k, v in values.items() if k in _DISPATCH_COLUMNS},
            updated_at=sa.func.now(),
        )
        .returning(e.c.id)
    ).first()
    if bound is None:
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)
    execution_id: UUID = bound[0]
    return execution_id


def _budgeted(scopes: list[Scope]) -> bool:
    """Whether the admission reserves daily-budget units (the restore budget hold)."""
    return any(scope.daily_units is not None for scope in scopes)


def reserve(
    engine: Engine,
    principal: JobContextPrincipal,
    job: Admission,
    *,
    policy: ResolutionPolicy,
    limits: ExecutionLimits,
) -> Reservation:
    """Run the reservation transaction; a ``pending`` row, or a typed refusal."""
    execution_id = uuid4()
    scopes = scopes_of(principal, limits)
    with audited_transaction(engine) as tx:
        connection = tx.connection
        assert_not_held(connection, None, budgeted=_budgeted(scopes))
        resolution = resolve(
            tx, ExecutionRequest.from_context(principal.payload), policy
        )
        frozen = _freeze(connection, resolution, job.capability)
        pin = job.expected_identity
        if pin is not None and pin != frozen.execution_identity:
            raise GatewayError(AiErrorCode.EXECUTION_IDENTITY_CHANGED)
        units = job.units(frozen.config)
        principal.redeem(connection)
        day = connection.execute(sa.select(_BUDGET_DAY)).scalar_one()
        for scope in scopes:
            _reserve_units(connection, scope, day, units)
        values = _pending_values(
            principal,
            job,
            resolution,
            frozen,
            units,
            day,
            limits.reservation_ttl_seconds,
        )
        if job.capability is Capability.OCR:
            execution_id = _bind_spool(connection, principal, values)
        else:
            admit(connection, principal.client_id, scopes, limits)
            connection.execute(
                sa.insert(ai_execution).values(id=execution_id, **values)
            )
    return Reservation(
        execution_id=execution_id,
        resolution=resolution,
        execution_identity=frozen.execution_identity,
        embedding_space_id=frozen.embedding_space_id,
        units=units,
        client_id=principal.client_id,
    )


__all__ = [
    "Reservation",
    "Scope",
    "admit",
    "occupy",
    "reserve",
    "scopes_of",
]

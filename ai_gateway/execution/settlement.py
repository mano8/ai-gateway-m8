"""
Every transition of the D-24 table, for handlers and sweepers alike.

Each transition is one compare-and-set ``UPDATE … WHERE status = :from``, so
it happens at most once whoever attempts it; every terminal transition, in
the same transaction:

* settles the admission units from the **recorded** scope ids and budget
  day, never current configuration — a charged outcome (``ok``, ``failed``,
  ``charged_uncertain``) moves exactly ``reserved_units`` from ``reserved``
  to ``used``, a refund (``released``, ``abandoned``) only drops the
  reservation;
* releases the client's occupancy slot exactly once
  (``occupancy_released_at``).

The **marker** moves ``pending → dispatching`` before any provider I/O,
re-asserting everything the reservation recorded: the reservation and the
context unexpired on the database clock, the provider enabled with its
recorded boundary, the model enabled and unflagged, the profile enabled at
the recorded revision, and the recorded version still the current version
of an active, unthrottled credential of the recorded provider. Zero rows
means no provider call.

Refunds exist only for established pre-dispatch outcomes: ``pending →
released``, and ``dispatching → released`` only while ``first_byte_sent_at``
is null (the schema refuses it otherwise). The sweepers act by stored status
only: ``pending`` past ``reservation_expires_at`` → ``abandoned``;
``dispatching`` past ``dispatch_deadline_at`` + grace → ``charged_uncertain``
— never refunded.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Final
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, IdentityAssurance, ProviderUsage
from pydantic import JsonValue
from sqlalchemy import Connection, Engine, RowMapping

from ai_gateway.controllers.audit import Actor, AuditedTransaction
from ai_gateway.core.errors import GatewayError
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import ai_client_occupancy, ai_execution, ai_usage
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_revision,
    ai_provider,
)
from ai_gateway.providers.base import ModelRef
from ai_gateway.providers.cooldown import apply_cooldown
from ai_gateway.providers.errors import Incident
from ai_gateway.providers.http import ProviderEndpoint

_E = ai_execution
_SYSTEM = Actor("system")

#: Rows one sweep transaction settles.
SWEEP_BATCH: Final = 100

_SCOPE_COLUMNS: Final = (
    ("client", _E.c.client_scope_id),
    ("tenant", _E.c.tenant_scope_id),
    ("user", _E.c.user_scope_id),
)


@dataclass(frozen=True)
class Marked:
    """What the marker returned: the frozen destination and the time left."""

    endpoint: ProviderEndpoint
    model: ModelRef
    config: Mapping[str, JsonValue]
    identity_assurance: IdentityAssurance
    remaining_seconds: float


def _credential_still_current() -> sa.ColumnElement[bool]:
    c = ai_credential
    current = sa.exists().where(
        c.c.id == _E.c.resolved_credential_id,
        c.c.current_version == _E.c.resolved_credential_version,
        c.c.status == "active",
        c.c.provider_id == _E.c.resolved_provider_id,
        sa.or_(c.c.throttled_until.is_(None), c.c.throttled_until <= sa.func.now()),
    )
    return sa.or_(_E.c.resolved_credential_id.is_(None), current)


def _marker_predicates() -> list[sa.ColumnElement[bool]]:
    p, m, pr, rv = ai_provider, ai_model, ai_profile, ai_profile_revision
    return [
        _E.c.status == ExecutionStatus.PENDING.value,
        _E.c.reservation_expires_at > sa.func.now(),
        _E.c.context_exp > sa.func.now(),
        p.c.id == _E.c.resolved_provider_id,
        p.c.enabled.is_(True),
        p.c.boundary == _E.c.resolved_boundary,
        m.c.id == _E.c.resolved_model_id,
        m.c.enabled.is_(True),
        m.c.flagged_at.is_(None),
        pr.c.id == _E.c.resolved_profile_id,
        pr.c.enabled.is_(True),
        pr.c.current_revision == _E.c.resolved_profile_revision,
        rv.c.profile_id == _E.c.resolved_profile_id,
        rv.c.revision == _E.c.resolved_profile_revision,
        _credential_still_current(),
    ]


def _marked(row: RowMapping) -> Marked:
    endpoint = ProviderEndpoint.from_row(
        {
            "id": row["provider_id"],
            "provider_type": row["provider_type"],
            "base_url": row["base_url"],
            "boundary": row["boundary"],
            "auth_type": row["auth_type"],
            "auth_header_name": row["auth_header_name"],
        }
    )
    model = ModelRef(
        model_id=row["model_id"],
        external_model_id=row["external_model_id"],
        dimensions=row["dimensions"],
        max_output_tokens=row["max_output_tokens"],
        model_revision=row["model_revision"],
    )
    return Marked(
        endpoint=endpoint,
        model=model,
        config=dict(row["execution_config"]),
        identity_assurance=IdentityAssurance(row["identity_assurance"]),
        remaining_seconds=float(row["remaining"]),
    )


def mark_dispatching(
    engine: Engine, execution_id: UUID, *, total_deadline_seconds: int
) -> Marked | None:
    """
    The marker: ``pending → dispatching`` under every step-(4) predicate.

    Commits ``dispatched_at`` and ``dispatch_deadline_at`` before any provider
    I/O and returns the frozen endpoint, model and revision configuration,
    with the seconds left until the stored deadline. ``None`` when no row
    matched: no provider call may follow.
    """
    p, m, rv = ai_provider, ai_model, ai_profile_revision
    statement = (
        sa.update(_E)
        .where(_E.c.id == execution_id, *_marker_predicates())
        .values(
            status=ExecutionStatus.DISPATCHING.value,
            dispatched_at=sa.func.now(),
            dispatch_deadline_at=sa.func.now()
            + timedelta(seconds=total_deadline_seconds),
            updated_at=sa.func.now(),
        )
        .returning(
            sa.func.extract(
                "epoch", _E.c.dispatch_deadline_at - sa.func.clock_timestamp()
            ).label("remaining"),
            p.c.id.label("provider_id"),
            p.c.provider_type,
            p.c.base_url,
            p.c.boundary,
            p.c.auth_type,
            p.c.auth_header_name,
            m.c.id.label("model_id"),
            m.c.external_model_id,
            m.c.dimensions,
            m.c.max_output_tokens,
            m.c.model_revision,
            m.c.identity_assurance,
            rv.c.execution_config,
        )
    )
    with engine.begin() as connection:
        row = connection.execute(statement).mappings().first()
    return None if row is None else _marked(row)


def record_first_byte(engine: Engine, execution_id: UUID) -> bool:
    """
    Persist ``first_byte_sent_at`` before the first request byte (D-24).

    Only while the row is ``dispatching`` inside its stored deadline: a row a
    sweeper settled, or whose deadline passed, gets no byte. Set once.
    """
    with engine.begin() as connection:
        row = connection.execute(
            sa.update(_E)
            .where(
                _E.c.id == execution_id,
                _E.c.status == ExecutionStatus.DISPATCHING.value,
                _E.c.first_byte_sent_at.is_(None),
                _E.c.dispatch_deadline_at > sa.func.now(),
            )
            .values(first_byte_sent_at=sa.func.now(), updated_at=sa.func.now())
            .returning(_E.c.id)
        ).first()
    return row is not None


def _settle_units(connection: Connection, row: RowMapping, *, charge: bool) -> None:
    units = row["reserved_units"]
    if units is None:
        return
    for scope_type, column in _SCOPE_COLUMNS:
        scope_id = row[column.name]
        if scope_id is None:
            continue
        values: dict[str, object] = {"reserved": ai_usage.c.reserved - units}
        if charge:
            values["used"] = ai_usage.c.used + units
        connection.execute(
            sa.update(ai_usage)
            .where(
                ai_usage.c.scope_type == scope_type,
                ai_usage.c.scope_id == scope_id,
                ai_usage.c.day == row["reservation_day"],
            )
            .values(**values)
        )


def vacate(connection: Connection, client_id: str) -> None:
    """Return one of the client's occupancy slots (the terminal transition's)."""
    table = ai_client_occupancy
    connection.execute(
        sa.update(table)
        .where(table.c.client_id == client_id)
        .values(occupied=table.c.occupied - 1)
    )


def close(
    connection: Connection,
    where: sa.ColumnElement[bool],
    *,
    status: ExecutionStatus,
    error: AiErrorCode | None = None,
    values: Mapping[str, object] | None = None,
) -> list[UUID]:
    """
    Move every row matching ``where`` to the terminal ``status``.

    Settles each row's units from its recorded scopes and day and vacates its
    slot, in the caller's transaction; returns the ids moved.
    """
    charge = status in (
        ExecutionStatus.OK,
        ExecutionStatus.FAILED,
        ExecutionStatus.CHARGED_UNCERTAIN,
    )
    rows = (
        connection.execute(
            sa.update(_E)
            .where(where)
            .values(
                status=status.value,
                error_class=None if error is None else error.value,
                settled_at=sa.func.now(),
                occupancy_released_at=sa.func.now(),
                updated_at=sa.func.now(),
                **dict(values or {}),
            )
            .returning(
                _E.c.id,
                _E.c.reserved_units,
                _E.c.reservation_day,
                *(column for _, column in _SCOPE_COLUMNS),
            )
        )
        .mappings()
        .all()
    )
    for row in rows:
        _settle_units(connection, row, charge=charge)
        vacate(connection, row["client_scope_id"])
    return [row["id"] for row in rows]


def release(
    engine: Engine,
    execution_id: UUID,
    error: AiErrorCode,
    *,
    dispatched: bool = False,
) -> bool:
    """
    Refund an established pre-dispatch outcome.

    ``pending → released``, or with ``dispatched`` ``dispatching → released``
    while no request byte was recorded. ``False`` when another actor already
    settled the row.
    """
    where = sa.and_(_E.c.id == execution_id)
    if dispatched:
        where = sa.and_(
            where,
            _E.c.status == ExecutionStatus.DISPATCHING.value,
            _E.c.first_byte_sent_at.is_(None),
        )
    else:
        where = sa.and_(where, _E.c.status == ExecutionStatus.PENDING.value)
    with engine.begin() as connection:
        return bool(
            close(connection, where, status=ExecutionStatus.RELEASED, error=error)
        )


def settle(
    engine: Engine,
    execution_id: UUID,
    status: ExecutionStatus,
    *,
    error: AiErrorCode | None = None,
    usage: ProviderUsage | None = None,
    cooldown: tuple[UUID, int] | None = None,
    incident: tuple[Incident, UUID] | None = None,
) -> bool:
    """
    Settle a dispatched row as ``ok``, ``failed`` or ``charged_uncertain``.

    One ``UPDATE … WHERE status = 'dispatching'``: a late answer after a
    sweeper settled the row changes nothing. A provider 429's cooldown is
    applied to the credential, and an incident audited against the recorded
    model, whatever the row's state.
    """
    where = sa.and_(
        _E.c.id == execution_id, _E.c.status == ExecutionStatus.DISPATCHING.value
    )
    values = {}
    if usage is not None:
        values["provider_usage"] = usage.model_dump(mode="json", exclude_none=True)
    with engine.begin() as connection:
        audit = AuditedTransaction(connection)
        if cooldown is not None:
            apply_cooldown(connection, *cooldown)
        if incident is not None:
            reason, model_id = incident
            audit.admin(
                _SYSTEM,
                "model.incident",
                "model",
                model_id,
                {"incident": reason.value, "execution_id": str(execution_id)},
            )
        settled = bool(
            close(connection, where, status=status, error=error, values=values)
        )
    audit.emit()
    return settled


def _due(
    status: ExecutionStatus,
    expired: sa.ColumnElement[bool],
    fence: sa.ColumnElement[bool] | None,
    limit: int,
) -> sa.ColumnElement[bool]:
    candidates = (
        sa.select(_E.c.id)
        .where(_E.c.status == status.value, expired)
        .order_by(_E.c.created_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    where = sa.and_(
        _E.c.id.in_(candidates.scalar_subquery()), _E.c.status == status.value
    )
    return where if fence is None else sa.and_(where, fence)


def sweep_expired_pending(
    engine: Engine,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = SWEEP_BATCH,
) -> list[UUID]:
    """``pending`` past ``reservation_expires_at`` → ``abandoned`` (released)."""
    expired = _E.c.reservation_expires_at < sa.func.now()
    with engine.begin() as connection:
        return close(
            connection,
            _due(ExecutionStatus.PENDING, expired, fence, limit),
            status=ExecutionStatus.ABANDONED,
            error=AiErrorCode.TIMEOUT,
        )


def sweep_stale_dispatching(
    engine: Engine,
    *,
    grace_seconds: int,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = SWEEP_BATCH,
) -> list[UUID]:
    """``dispatching`` past ``dispatch_deadline_at`` + grace → ``charged_uncertain``."""
    expired = (
        _E.c.dispatch_deadline_at + timedelta(seconds=grace_seconds) < sa.func.now()
    )
    with engine.begin() as connection:
        return close(
            connection,
            _due(ExecutionStatus.DISPATCHING, expired, fence, limit),
            status=ExecutionStatus.CHARGED_UNCERTAIN,
            error=AiErrorCode.TIMEOUT,
        )


def diagnose(engine: Engine, execution_id: UUID) -> GatewayError:
    """Why a marker matched no row, as the caller's typed refusal."""
    c = ai_credential
    statement = (
        sa.select(
            (_E.c.context_exp <= sa.func.now()).label("context_expired"),
            (_E.c.reservation_expires_at <= sa.func.now()).label("reservation_expired"),
            (c.c.throttled_until > sa.func.now()).label("throttled"),
            sa.func.ceil(
                sa.func.extract("epoch", c.c.throttled_until - sa.func.now())
            ).label("throttle_seconds"),
        )
        .select_from(_E)
        .outerjoin(c, c.c.id == _E.c.resolved_credential_id)
        .where(_E.c.id == execution_id)
    )
    with engine.connect() as connection:
        row = connection.execute(statement).mappings().one()
    if row["context_expired"]:
        return GatewayError(AiErrorCode.CONTEXT_EXPIRED)
    if row["reservation_expired"]:
        return GatewayError(AiErrorCode.TIMEOUT)
    if row["throttled"]:
        return GatewayError(
            AiErrorCode.RATE_LIMITED,
            retry_after_seconds=max(1, int(row["throttle_seconds"])),
        )
    return GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)


__all__ = [
    "SWEEP_BATCH",
    "Marked",
    "close",
    "diagnose",
    "mark_dispatching",
    "record_first_byte",
    "release",
    "settle",
    "sweep_expired_pending",
    "sweep_stale_dispatching",
    "vacate",
]

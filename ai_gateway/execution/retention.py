"""
Retention and reconciliation of the accounting rows (``T33``, S-13).

The runtime never deletes a row because it is old: an ``ai_execution`` row is
removed only when a **positive eligibility predicate** holds — every other
owner of the row (the ledger, the client's occupancy slot, the spool
reservation, the remote-artifact rows that reference it) has finished with it.
Settlement, unlink and remote deletion happen first, in the sweepers; this
module never substitutes for stalled work, so a row whose cleanup keeps
failing simply stays.

``ai_usage`` days are removed only when no ``ai_execution`` row of any status
still carries the day as its ``reservation_day``.

:func:`reconcile` is the superuser's evidence-recording closure of a
``charged_uncertain`` row; only a reconciled row becomes eligible.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine

from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.core import metrics
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import ai_execution, ai_usage
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact

from .settlement import SWEEP_BATCH

_E = ai_execution
_A = ai_provider_remote_artifact

#: The UTC budget day of the database clock.
_BUDGET_DAY: Final = sa.cast(sa.func.timezone("UTC", sa.func.now()), sa.Date)

#: Statuses a row may be removed in; ``charged_uncertain`` only once reconciled.
_REMOVABLE: Final = tuple(
    s.value
    for s in (
        ExecutionStatus.OK,
        ExecutionStatus.FAILED,
        ExecutionStatus.RELEASED,
        ExecutionStatus.ABANDONED,
    )
)

#: The audit tables the runtime exports a size for (and never prunes).
AUDIT_TABLES: Final = ("ai_credential_audit", "ai_admin_audit")


def eligible(retention_days: int) -> sa.ColumnElement[bool]:
    """The positive predicate: ``True`` only for a row nothing else needs."""
    return sa.and_(
        sa.or_(
            _E.c.status.in_(_REMOVABLE),
            sa.and_(
                _E.c.status == ExecutionStatus.CHARGED_UNCERTAIN.value,
                _E.c.reconciled_at.is_not(None),
            ),
        ),
        _E.c.cleanup_pending.is_(False),
        _E.c.spool_bytes_reserved.is_(None),
        _E.c.occupancy_released_at.is_not(None),
        ~sa.exists().where(_A.c.execution_id == _E.c.id),
        sa.or_(_E.c.reservation_day.is_(None), _E.c.reservation_day < _BUDGET_DAY),
        _E.c.updated_at < sa.func.now() - timedelta(days=retention_days),
    )


def collect_executions(
    engine: Engine,
    retention_days: int,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = SWEEP_BATCH,
) -> int:
    """Delete up to ``limit`` eligible ``ai_execution`` rows; the count."""
    where = eligible(retention_days)
    if fence is not None:
        where = sa.and_(where, fence)
    picked = (
        sa.select(_E.c.id).where(where).limit(limit).with_for_update(skip_locked=True)
    )
    with engine.begin() as connection:
        return int(
            connection.execute(
                # Re-checked in the DELETE: a row that changed after the pick stays.
                sa.delete(_E).where(_E.c.id.in_(picked.scalar_subquery()), where)
            ).rowcount
        )


def collect_usage(
    engine: Engine,
    retention_days: int,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = SWEEP_BATCH,
) -> int:
    """Delete up to ``limit`` old ``ai_usage`` days no execution still carries."""
    u = ai_usage
    where = sa.and_(
        u.c.day < _BUDGET_DAY - retention_days,
        ~sa.exists().where(_E.c.reservation_day == u.c.day),
    )
    if fence is not None:
        where = sa.and_(where, fence)
    picked = (
        sa.select(u.c.scope_type, u.c.scope_id, u.c.day)
        .where(where)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    with engine.begin() as connection:
        return int(
            connection.execute(
                sa.delete(u).where(
                    sa.tuple_(u.c.scope_type, u.c.scope_id, u.c.day).in_(picked),
                    where,
                )
            ).rowcount
        )


def reconcile(engine: Engine, execution_id: UUID, actor: Actor, evidence: str) -> bool:
    """
    Close one ``charged_uncertain`` row as reconciled, with audited evidence.

    The charge stays; only ``reconciled_at`` is set, which is what makes the
    row eligible for retention. ``False`` when no unreconciled
    ``charged_uncertain`` row has that id.
    """
    with audited_transaction(engine) as tx:
        row = tx.connection.execute(
            sa.update(_E)
            .where(
                _E.c.id == execution_id,
                _E.c.status == ExecutionStatus.CHARGED_UNCERTAIN.value,
                _E.c.reconciled_at.is_(None),
            )
            .values(reconciled_at=sa.func.now(), updated_at=sa.func.now())
            .returning(_E.c.reserved_units, _E.c.capability)
        ).first()
        if row is None:
            return False
        tx.admin(
            actor,
            "execution.reconcile",
            "execution",
            execution_id,
            {"reserved_units": row[0], "capability": row[1], "evidence": evidence},
        )
    return True


def observe_audit_table_bytes(engine: Engine) -> dict[str, int]:
    """Export ``ai_audit_table_bytes{table}``; the runtime only measures."""
    sizes: dict[str, int] = {}
    with engine.connect() as connection:
        for table in AUDIT_TABLES:
            size = int(
                connection.execute(
                    sa.select(sa.func.pg_total_relation_size(sa.literal(table)))
                ).scalar_one()
            )
            metrics.AUDIT_TABLE_BYTES.labels(table=table).set(size)
            sizes[table] = size
    return sizes


__all__ = [
    "AUDIT_TABLES",
    "collect_executions",
    "collect_usage",
    "eligible",
    "observe_audit_table_bytes",
    "reconcile",
]

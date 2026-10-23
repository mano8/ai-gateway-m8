"""
The sweepers (``T32``, D-24, D-45): settle by stored status, then clean.

Each job is one bounded pass the scheduler runs under its lease (``T33a``
passes the fence); every settlement is a CAS on the stored status through
:func:`~.settlement.close`, so it returns the client's occupancy slot exactly
once and stamps ``occupancy_released_at``:

* :func:`sweep_contexts` — ``ai_job_context_use`` rows past ``exp`` on the
  database clock (a row is only needed while its context could still be
  redeemed);
* :func:`sweep_spools` — ``receiving`` past ``spool_lease_until`` and
  ``spooled`` past ``spool_expires_at`` → ``abandoned``; the ``pending`` and
  ``dispatching`` sweepers are :mod:`.settlement`'s (``abandoned``, and
  ``charged_uncertain`` — never refunded);
* :func:`clean_spools` — terminal rows still ``cleanup_pending`` through the
  D-45 cleaner (a held lock defers, never releases);
* :func:`collect_orphans` — files the protocol left behind a crash: a lock
  whose reservation was already released (the crash between the release
  commit and the lock unlink), and files whose row is absent; each under
  ``LOCK_EX|LOCK_NB``, a live holder deferring it;
* :func:`spool_repair` — the audited superuser release of a row whose lock
  vanished while its reservation is held (``spool_lock_missing``), which
  the protocol cannot produce outside tampering or a restore.
"""

from __future__ import annotations

import fcntl
import logging
import os
import uuid
from collections import Counter as Tally
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode
from sqlalchemy import Engine

from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.core.job_context import JOB_CONTEXTS
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import ai_execution, ai_job_context_use

from . import spool
from .settlement import SWEEP_BATCH, close
from .spool import SpoolLayout

logger = logging.getLogger(__name__)

_E = ai_execution
_U = ai_job_context_use


def sweep_contexts(engine: Engine, *, limit: int = SWEEP_BATCH) -> int:
    """Delete context rows whose ``exp`` passed on the database clock."""
    expired = sa.select(_U.c.iss, _U.c.jti).where(_U.c.exp < sa.func.now()).limit(limit)
    with engine.begin() as connection:
        deleted = connection.execute(
            sa.delete(_U).where(sa.tuple_(_U.c.iss, _U.c.jti).in_(expired))
        ).rowcount
    JOB_CONTEXTS.labels(event="swept").inc(deleted)
    return int(deleted)


def sweep_spools(
    engine: Engine,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = SWEEP_BATCH,
) -> list[UUID]:
    """Abandon uploads past their lease and spools past their TTL."""
    due = sa.or_(
        sa.and_(
            _E.c.status == ExecutionStatus.RECEIVING.value,
            _E.c.spool_lease_until < sa.func.now(),
        ),
        sa.and_(
            _E.c.status == ExecutionStatus.SPOOLED.value,
            _E.c.spool_expires_at < sa.func.now(),
        ),
    )
    if fence is not None:
        due = sa.and_(due, fence)
    picked = (
        sa.select(_E.c.id).where(due).limit(limit).with_for_update(skip_locked=True)
    )
    with engine.begin() as connection:
        return close(
            connection,
            _E.c.id.in_(picked.scalar_subquery()),
            status=ExecutionStatus.ABANDONED,
            error=AiErrorCode.TIMEOUT,
        )


def clean_spools(
    layout: SpoolLayout, engine: Engine, *, limit: int = SWEEP_BATCH
) -> dict[str, int]:
    """Run the cleaner on terminal rows still holding a reservation."""
    with engine.connect() as connection:
        ids = list(
            connection.execute(
                sa.select(_E.c.id)
                .where(_E.c.cleanup_pending.is_(True))
                .order_by(_E.c.updated_at)
                .limit(limit)
            ).scalars()
        )
    outcomes = Tally(spool.clean(layout, engine, execution_id) for execution_id in ids)
    return {outcome.value: count for outcome, count in outcomes.items()}


def _spool_id(name: str) -> UUID | None:
    try:
        return uuid.UUID(name)
    except ValueError:
        return None


def _retired(engine: Engine, execution_id: UUID) -> bool:
    """No row, or a row whose reservation is already released."""
    with engine.connect() as connection:
        row = connection.execute(
            sa.select(_E.c.cleanup_pending, _E.c.spool_bytes_reserved).where(
                _E.c.id == execution_id
            )
        ).first()
    return row is None or (not row[0] and row[1] is None)


def _collect(layout: SpoolLayout, execution_id: UUID) -> bool:
    """Remove a retired spool's files under ``LOCK_EX``; ``False`` if held."""
    lock_path = layout.lock(execution_id)
    try:
        fd = spool.open_lock(lock_path, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    try:
        layout.data(execution_id).unlink(missing_ok=True)
        if fd is not None:
            lock_path.unlink(missing_ok=True)
    finally:
        if fd is not None:
            os.close(fd)
    return True


def collect_orphans(layout: SpoolLayout, engine: Engine) -> list[UUID]:
    """The spools a crash left behind a released or absent row."""
    names = {p.name for p in layout.root.iterdir() if p.is_file()}
    if layout.locks.is_dir():
        names |= {p.name for p in layout.locks.iterdir() if p.is_file()}
    collected: list[UUID] = []
    for execution_id in filter(None, map(_spool_id, sorted(names))):
        if _retired(engine, execution_id) and _collect(layout, execution_id):
            collected.append(execution_id)
    return collected


def spool_repair(
    engine: Engine, execution_id: UUID, actor: Actor, evidence: str
) -> bool:
    """
    Release the reservation of a row whose lock file vanished (audited).

    Only for a terminal ``cleanup_pending`` row with ``spool_file_created``
    and no lock file — the ``spool_lock_missing`` alert — after the operator
    confirmed no process holds its data file.
    """
    with audited_transaction(engine) as tx:
        row = tx.connection.execute(
            sa.select(_E.c.spool_bytes_reserved)
            .where(
                _E.c.id == execution_id,
                _E.c.cleanup_pending.is_(True),
                _E.c.spool_file_created.is_(True),
            )
            .with_for_update()
        ).first()
        if row is None:
            return False
        spool.release_reservation(tx.connection, execution_id, row[0])
        tx.admin(
            actor,
            "spool.repair",
            "execution",
            execution_id,
            {"spool_bytes_reserved": row[0], "evidence": evidence},
        )
    return True


__all__ = [
    "clean_spools",
    "collect_orphans",
    "spool_repair",
    "sweep_contexts",
    "sweep_spools",
]

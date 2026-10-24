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
* :func:`prune_rate_windows` — ``ai_rate_window`` rows older than two
  windows (no admission reads them again);
* :func:`repair_occupancy` — each client's in-flight counter recounted from
  its live rows (``occupancy_released_at IS NULL``) **under the counter
  row's** ``FOR UPDATE`` **lock with a fresh statement**: an admission or a
  settlement that touched the counter first is waited for and then counted;
  one that touches it after waits and applies its ±1 to the repaired value.
  A snapshot count followed by an unlocked overwrite would lose one;
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
from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.core.job_context import JOB_CONTEXTS
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import (
    ai_client_occupancy,
    ai_execution,
    ai_job_context_use,
    ai_rate_window,
)

from . import spool
from .settlement import SWEEP_BATCH, close
from .spool import SpoolLayout

logger = logging.getLogger(__name__)

_E = ai_execution
_U = ai_job_context_use
_W = ai_rate_window
_O = ai_client_occupancy

#: A rate window is one minute; rows older than two windows are pruned.
RATE_WINDOW: timedelta = timedelta(minutes=1)


def _fenced(
    where: sa.ColumnElement[bool], fence: sa.ColumnElement[bool] | None
) -> sa.ColumnElement[bool]:
    return where if fence is None else sa.and_(where, fence)


def sweep_contexts(
    engine: Engine,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = SWEEP_BATCH,
) -> int:
    """Delete context rows whose ``exp`` passed on the database clock."""
    expired = sa.select(_U.c.iss, _U.c.jti).where(_U.c.exp < sa.func.now()).limit(limit)
    with engine.begin() as connection:
        deleted = connection.execute(
            sa.delete(_U).where(
                _fenced(sa.tuple_(_U.c.iss, _U.c.jti).in_(expired), fence)
            )
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


def prune_rate_windows(
    engine: Engine, *, fence: sa.ColumnElement[bool] | None = None
) -> int:
    """Delete rate-window rows older than two windows; the count."""
    current = sa.func.date_trunc("minute", sa.func.now())
    with engine.begin() as connection:
        return int(
            connection.execute(
                sa.delete(_W).where(
                    _fenced(_W.c.window_start < current - 2 * RATE_WINDOW, fence)
                )
            ).rowcount
        )


def _live(client_id: str) -> sa.Select[int]:
    return sa.select(sa.func.count()).where(
        _E.c.client_scope_id == client_id, _E.c.occupancy_released_at.is_(None)
    )


def _repair_one(
    connection: Connection,
    client_id: str,
    fence: sa.ColumnElement[bool] | None,
    pause: Callable[[str], None],
) -> int | None:
    """Recount one client under its counter row's lock; the change, if fenced."""
    connection.execute(
        pg_insert(_O).values(client_id=client_id, occupied=0).on_conflict_do_nothing()
    )
    locked = connection.execute(
        sa.select(_O.c.occupied)
        .where(_fenced(_O.c.client_id == client_id, fence))
        .with_for_update()
    ).first()
    if locked is None:
        return None  # the lease moved on: change nothing
    pause("locked")
    # A fresh statement, after the lock: it sees every committed ±1.
    live = int(connection.execute(_live(client_id)).scalar_one())
    pause("counted")
    connection.execute(
        sa.update(_O).where(_O.c.client_id == client_id).values(occupied=live)
    )
    return live - int(locked[0])


def repair_occupancy(
    engine: Engine,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    pause: Callable[[str], None] = lambda _step: None,
) -> dict[str, int]:
    """
    Recount every client's in-flight counter from its live rows.

    Returns the clients whose counter changed and by how much. ``pause`` is
    a test seam called after the lock and after the count.
    """
    with engine.connect() as connection:
        clients = set(connection.execute(sa.select(_O.c.client_id)).scalars())
        clients |= set(
            connection.execute(
                sa.select(_E.c.client_scope_id)
                .where(_E.c.occupancy_released_at.is_(None))
                .distinct()
            ).scalars()
        )
    changed: dict[str, int] = {}
    for client_id in sorted(clients):
        with engine.begin() as connection:
            delta = _repair_one(connection, client_id, fence, pause)
        if delta:
            logger.warning("occupancy.repaired client_id=%s delta=%d", client_id, delta)
            changed[client_id] = delta
    return changed


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
    "prune_rate_windows",
    "repair_occupancy",
    "spool_repair",
    "sweep_contexts",
    "sweep_spools",
]

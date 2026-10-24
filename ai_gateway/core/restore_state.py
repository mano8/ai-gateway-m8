"""
Restore detection and the execution hold (D-42, D-43, D-45).

**High-water.** The scheduler draws ``nextval('ai_db_epoch')`` and writes the
value to ``/spool/.state/db-highwater`` (atomic replace, never lowered). A
sequence lives in the database, so a snapshot restore rewinds it while the
file on the spool volume keeps the later value: a process that reads a
database epoch **below** the file's knows its database is behind and refuses
execution with ``restore_detected`` until ``restore-ratify`` re-baselines the
file. Without a spool directory there is no file and no detection by this
path; ``restore-reconcile`` still holds execution.

**Hold.** While ``ai_restore_state`` records a restore that is not ratified,
every reservation refuses with ``restore_detected``. After ratification the
**budget hold** keeps refusing budgeted admissions with ``quota_exceeded``
until the next UTC day: the restored ``ai_usage`` rows undercount what was
spent after the snapshot, and V1 offers no reconstruction (``T1``).

Both checks run in the reservation transaction; the high-water check also
runs as a route guard, before any credential is read.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode
from sqlalchemy import Connection, Engine

from ai_gateway.db_models.installation import ai_restore_state

from .errors import GatewayError

_R = ai_restore_state

#: Directory, under the spool, of the files that outlive an ``ai_db`` restore.
STATE_DIR: Final = ".state"
HIGHWATER_FILE: Final = "db-highwater"
EVENTS_FILE: Final = "restore-events"

#: ``Retry-After`` while a restore is held: the operator has to act.
HOLD_RETRY_SECONDS: Final = 60

_EPOCH: Final = sa.text(
    "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM ai_db_epoch"
)


def state_dir(spool_root: Path) -> Path:
    """``/spool/.state``."""
    return spool_root / STATE_DIR


def database_epoch(connection: Connection) -> int:
    """The last epoch drawn from ``ai_db_epoch`` (``0`` before the first)."""
    return int(connection.execute(_EPOCH).scalar_one())


def read_highwater(spool_root: Path) -> int | None:
    """The recorded high-water, or ``None`` before the first write."""
    try:
        text = (state_dir(spool_root) / HIGHWATER_FILE).read_text("ascii")
    except FileNotFoundError:
        return None
    return int(text.strip())


def _replace(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (``0600``, fsynced, renamed)."""
    path.parent.mkdir(mode=0o700, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, text.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)


def write_highwater(engine: Engine, spool_root: Path) -> int | None:
    """
    Raise the high-water to a fresh epoch; ``None`` while the database is behind.

    The file is never lowered here: a database behind it is a restore that
    only ``restore-ratify`` (:func:`rebaseline`) may settle.
    """
    recorded = read_highwater(spool_root)
    with engine.begin() as connection:
        if recorded is not None and database_epoch(connection) < recorded:
            return None
        value = int(
            connection.execute(sa.select(sa.func.nextval("ai_db_epoch"))).scalar_one()
        )
    # Not behind, so a fresh ``nextval`` is above the recorded value.
    _replace(state_dir(spool_root) / HIGHWATER_FILE, f"{value}\n")
    return value


def rebaseline(engine: Engine, spool_root: Path) -> int:
    """Set the high-water to a fresh epoch of this database, even below the old one."""
    with engine.begin() as connection:
        value = int(
            connection.execute(sa.select(sa.func.nextval("ai_db_epoch"))).scalar_one()
        )
    _replace(state_dir(spool_root) / HIGHWATER_FILE, f"{value}\n")
    return value


def database_behind(connection: Connection, spool_root: Path | None) -> bool:
    """Whether this database's epoch is below the spool's high-water."""
    if spool_root is None:
        return False
    recorded = read_highwater(spool_root)
    return recorded is not None and database_epoch(connection) < recorded


def append_event(spool_root: Path | None, event: dict[str, object]) -> None:
    """Append one restore event to ``/spool/.state/restore-events`` (JSON line)."""
    if spool_root is None:
        return
    directory = state_dir(spool_root)
    directory.mkdir(mode=0o700, exist_ok=True)
    line = json.dumps(
        {"at": datetime.now(UTC).isoformat(), **event}, sort_keys=True, default=str
    )
    fd = os.open(
        directory / EVENTS_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(fd, f"{line}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def in_restore() -> sa.ColumnElement[bool]:
    """A restore was entered and not yet ratified."""
    return sa.and_(_R.c.detected_at.is_not(None), _R.c.ratified_at.is_(None))


def in_restore_exists() -> sa.ColumnElement[bool]:
    """:func:`in_restore` as a predicate any statement can carry."""
    return sa.exists().where(in_restore())


def assert_not_held(
    connection: Connection, spool_root: Path | None, *, budgeted: bool
) -> None:
    """
    Refuse execution while a restore is detected, held or budget-held.

    ``budgeted`` is whether the admission reserves daily-budget units.
    """
    if database_behind(connection, spool_root):
        raise GatewayError(
            AiErrorCode.RESTORE_DETECTED, retry_after_seconds=HOLD_RETRY_SECONDS
        )
    row = connection.execute(
        sa.select(
            in_restore().label("held"),
            sa.func.ceil(
                sa.func.extract("epoch", _R.c.budget_hold_until - sa.func.now())
            ).label("budget_seconds"),
        )
    ).first()
    if row is None:
        return
    if row.held:
        raise GatewayError(
            AiErrorCode.RESTORE_DETECTED, retry_after_seconds=HOLD_RETRY_SECONDS
        )
    if budgeted and row.budget_seconds is not None and row.budget_seconds > 0:
        raise GatewayError(
            AiErrorCode.QUOTA_EXCEEDED, retry_after_seconds=int(row.budget_seconds)
        )


__all__ = [
    "EVENTS_FILE",
    "HIGHWATER_FILE",
    "HOLD_RETRY_SECONDS",
    "STATE_DIR",
    "append_event",
    "assert_not_held",
    "database_behind",
    "database_epoch",
    "in_restore",
    "in_restore_exists",
    "read_highwater",
    "rebaseline",
    "state_dir",
    "write_highwater",
]

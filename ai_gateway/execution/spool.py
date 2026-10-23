"""
The OCR spool's file protocol (D-45) — the only code that opens its files.

``L`` = ``<spool>/.locks/<execution_id>`` (the lock, whose identity outlives
the data), ``D`` = ``<spool>/<execution_id>`` (the document). No data
descriptor is ever opened outside a held, re-validated lock:

* **Receiver** (:class:`Receiver`): create ``L`` with ``O_CREAT|O_EXCL`` —
  the only place it is created — take ``LOCK_SH``, **then** the lease CAS
  setting ``spool_file_created`` (zero rows: unlink ``L``, no ``D``, no
  byte); create ``D`` with ``O_CREAT|O_EXCL``; write while the lease holds
  and never past the signed ``input_bytes``; commit ``receiving → spooled``;
  close ``D``; then release ``L``.
* **Reader** (:class:`SpoolReader`, the ``:dispatch`` side): open ``L``
  without ``O_CREAT`` (absent: the spool is retired), take ``LOCK_SH``,
  re-validate that the lock is current (``st_nlink ≥ 1`` and the path still
  names the same inode), re-read the row, and only then open ``D``; the lock
  is held for the whole upstream read and ``D`` is closed first.
* **Cleaner** (:func:`clean`): run after the row's terminal transition
  (``cleanup_pending``); take ``LOCK_EX|LOCK_NB`` the same way — a live
  holder keeps its blocks and the reservation stays charged until a later
  try; under the lock unlink ``D``, release the reservation exactly once
  (``WHERE cleanup_pending``) together with the ``ai_spool_capacity``
  decrement, then unlink ``L``. With ``L`` absent: never created → release
  directly; created and the reservation still held → impossible under the
  protocol, so the capacity stays charged and ``spool_lock_missing`` is
  alerted for ``spool-repair`` (``T32``).

The receiving row, its lease and its capacity reservation are
:mod:`.ocr`'s, created before any file.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import logging
import os
import stat
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode
from sqlalchemy import Engine

from ai_gateway.core.errors import GatewayError
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import ai_execution, ai_spool_capacity

logger = logging.getLogger(__name__)

_E = ai_execution
_CREATE: Final = os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
#: Bytes read from ``D`` per upstream chunk.
READ_CHUNK: Final = 64 * 1024


class Cleaned(StrEnum):
    """What one :func:`clean` attempt did."""

    RELEASED = "released"
    BUSY = "busy"
    LOCK_MISSING = "lock_missing"
    NOTHING = "nothing"


@dataclass(frozen=True)
class SpoolLayout:
    """The paths of one spool directory."""

    root: Path

    @property
    def locks(self) -> Path:
        return self.root / ".locks"

    def lock(self, execution_id: UUID) -> Path:
        return self.locks / str(execution_id)

    def data(self, execution_id: UUID) -> Path:
        return self.root / str(execution_id)

    def allocation_unit(self) -> int:
        """The filesystem's allocation unit (``statvfs`` ``f_frsize``)."""
        return int(os.statvfs(self.root).f_frsize)


def reserved_size(input_bytes: int, unit: int) -> int:
    """``input_bytes`` rounded up to the allocation unit (A-4)."""
    return -(-input_bytes // unit) * unit


def capacity_exhausted() -> GatewayError:
    """The typed 503 of a full spool, before any byte is written."""
    return GatewayError(AiErrorCode.CAPACITY_EXHAUSTED, retry_after_seconds=1)


def _current(fd: int, path: Path) -> bool:
    """The held lock is still the one the path names (not a retired inode)."""
    held = os.fstat(fd)
    try:
        named = os.stat(path)
    except FileNotFoundError:
        return False
    return held.st_nlink >= 1 and (held.st_dev, held.st_ino) == (
        named.st_dev,
        named.st_ino,
    )


def _open_existing_lock(path: Path, operation: int) -> int | None:
    """Open ``L`` without creating it and lock it; ``None`` when retired."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        fcntl.flock(fd, operation)
    except BlockingIOError:
        os.close(fd)
        raise
    if not _current(fd, path):
        os.close(fd)
        return None
    return fd


# --- the receiver ---------------------------------------------------------------------


class Receiver:
    """Writes one document into the spool under the receiving row's lease."""

    def __init__(
        self,
        layout: SpoolLayout,
        engine: Engine,
        execution_id: UUID,
        *,
        input_bytes: int,
        lease_deadline: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._layout = layout
        self._engine = engine
        self._id = execution_id
        self._limit = input_bytes
        self._deadline = lease_deadline
        self._clock = clock
        self._lock_fd: int | None = None
        self._data_fd: int | None = None
        self._digest = hashlib.sha256()
        self.written = 0

    def open(self) -> None:
        """Create and lock ``L``, claim the lease, then create ``D``."""
        self._layout.locks.mkdir(mode=0o700, exist_ok=True)
        self._lock_fd = os.open(
            self._layout.lock(self._id), _CREATE | os.O_RDONLY, 0o600
        )
        fcntl.flock(self._lock_fd, fcntl.LOCK_SH)
        with self._engine.begin() as connection:
            claimed = connection.execute(
                sa.update(_E)
                .where(
                    _E.c.id == self._id,
                    _E.c.status == ExecutionStatus.RECEIVING.value,
                    _E.c.spool_lease_until > sa.func.now(),
                )
                .values(spool_file_created=True, updated_at=sa.func.now())
                .returning(_E.c.id)
            ).first()
        if claimed is None:
            os.unlink(self._layout.lock(self._id))
            self._release_lock()
            raise GatewayError(AiErrorCode.TIMEOUT)
        self._data_fd = os.open(
            self._layout.data(self._id), _CREATE | os.O_WRONLY, 0o600
        )

    def write(self, chunk: bytes) -> None:
        """Append ``chunk``; never past the signed size or the lease."""
        assert self._data_fd is not None  # nosec B101 - after open()
        if self._clock() >= self._deadline:
            raise GatewayError(AiErrorCode.TIMEOUT)
        if self.written + len(chunk) > self._limit:
            # The body no longer matches its signed claims: nothing past them.
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)
        view = memoryview(chunk)
        try:
            while view:
                view = view[os.write(self._data_fd, view) :]
        except OSError as exc:
            if exc.errno in (errno.ENOSPC, errno.EDQUOT):
                raise capacity_exhausted() from None
            raise
        self._digest.update(chunk)
        self.written += len(chunk)

    @property
    def sha256(self) -> str:
        """The hex digest of the bytes written."""
        return self._digest.hexdigest()

    def commit(self, ttl_seconds: int) -> datetime:
        """``receiving → spooled`` by CAS; the spool's ``expires_at``."""
        assert self._data_fd is not None  # nosec B101 - after open()
        os.fsync(self._data_fd)
        with self._engine.begin() as connection:
            row = connection.execute(
                sa.update(_E)
                .where(
                    _E.c.id == self._id,
                    _E.c.status == ExecutionStatus.RECEIVING.value,
                    _E.c.spool_lease_until > sa.func.now(),
                )
                .values(
                    status=ExecutionStatus.SPOOLED.value,
                    spool_expires_at=sa.func.now() + timedelta(seconds=ttl_seconds),
                    updated_at=sa.func.now(),
                )
                .returning(_E.c.spool_expires_at)
            ).first()
        if row is None:
            raise GatewayError(AiErrorCode.TIMEOUT)
        self.close()
        expires_at: datetime = row[0]
        return expires_at

    def close(self) -> None:
        """Close ``D``, then release ``L`` (never the other order)."""
        if self._data_fd is not None:
            os.close(self._data_fd)
            self._data_fd = None
        self._release_lock()

    def _release_lock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)  # closing the descriptor releases the lock
            self._lock_fd = None


# --- the reader -------------------------------------------------------------------------


class SpoolReader:
    """The ``:dispatch`` side: a verified spool read under ``LOCK_SH``."""

    def __init__(self, layout: SpoolLayout, engine: Engine, execution_id: UUID) -> None:
        self._layout = layout
        self._engine = engine
        self._id = execution_id
        self._lock_fd: int | None = None
        self._data_fd: int | None = None
        self._size = 0

    def open(self, input_bytes: int) -> None:
        """Lock, re-validate, re-read the row, then open ``D``; else retired."""
        self._lock_fd = _open_existing_lock(self._layout.lock(self._id), fcntl.LOCK_SH)
        if self._lock_fd is None:
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)
        with self._engine.connect() as connection:
            live = connection.execute(
                sa.select(_E.c.id).where(
                    _E.c.id == self._id,
                    _E.c.status == ExecutionStatus.SPOOLED.value,
                    _E.c.spool_file_created.is_(True),
                    _E.c.cleanup_pending.is_(False),
                )
            ).first()
        if live is None:
            self.close()
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)
        self._data_fd = os.open(self._layout.data(self._id), os.O_RDONLY | os.O_CLOEXEC)
        info = os.fstat(self._data_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != input_bytes:
            self.close()
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)
        self._size = info.st_size

    @property
    def size(self) -> int:
        """The verified size."""
        return self._size

    def _pread(self, offset: int, length: int) -> bytes:
        assert self._data_fd is not None  # nosec B101 - after open()
        return os.pread(self._data_fd, length, offset)

    async def chunks(self) -> AsyncIterator[bytes]:
        """The document, in order, read while the lock is held."""
        offset = 0
        while offset < self._size:
            chunk = await asyncio.to_thread(self._pread, offset, READ_CHUNK)
            if not chunk:
                return
            offset += len(chunk)
            yield chunk

    async def read(self) -> bytes:
        """The whole document (only below the inline threshold)."""
        return b"".join([chunk async for chunk in self.chunks()])

    def close(self) -> None:
        """Close ``D``, then release ``L``."""
        if self._data_fd is not None:
            os.close(self._data_fd)
            self._data_fd = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None


# --- the cleaner ----------------------------------------------------------------------


def _release(engine: Engine, execution_id: UUID) -> bool:
    """The exactly-once release: ``cleanup_pending`` off, capacity returned."""
    with engine.begin() as connection:
        row = connection.execute(
            sa.select(_E.c.spool_bytes_reserved)
            .where(_E.c.id == execution_id, _E.c.cleanup_pending.is_(True))
            .with_for_update()
        ).first()
        if row is None:
            return False
        connection.execute(
            sa.update(_E)
            .where(_E.c.id == execution_id)
            .values(
                cleanup_pending=False,
                spool_bytes_reserved=None,
                updated_at=sa.func.now(),
            )
        )
        connection.execute(
            sa.update(ai_spool_capacity).values(
                reserved_bytes=ai_spool_capacity.c.reserved_bytes - (row[0] or 0)
            )
        )
    return True


def _row(engine: Engine, execution_id: UUID) -> tuple[bool, bool] | None:
    """``(cleanup_pending, spool_file_created)`` of the row, if any."""
    with engine.connect() as connection:
        row = connection.execute(
            sa.select(_E.c.cleanup_pending, _E.c.spool_file_created).where(
                _E.c.id == execution_id
            )
        ).first()
    return None if row is None else (bool(row[0]), bool(row[1]))


def clean(layout: SpoolLayout, engine: Engine, execution_id: UUID) -> Cleaned:
    """Remove a terminal row's spool and release its reservation, once."""
    row = _row(engine, execution_id)
    if row is None or not row[0]:
        return Cleaned.NOTHING
    file_created = row[1]
    lock_path = layout.lock(execution_id)
    try:
        fd = _open_existing_lock(lock_path, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return Cleaned.BUSY  # a live holder still owns the blocks
    if fd is None:
        if file_created:
            logger.warning("spool_lock_missing execution_id=%s", execution_id)
            return Cleaned.LOCK_MISSING
        _release(engine, execution_id)
        return Cleaned.RELEASED
    try:
        layout.data(execution_id).unlink(missing_ok=True)
        _release(engine, execution_id)
        lock_path.unlink(missing_ok=True)
    finally:
        os.close(fd)
    return Cleaned.RELEASED


__all__ = [
    "READ_CHUNK",
    "Cleaned",
    "Receiver",
    "SpoolLayout",
    "SpoolReader",
    "capacity_exhausted",
    "clean",
    "reserved_size",
]

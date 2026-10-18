"""
Pin every PostgreSQL session this service opens to UTC.

sqlmodel maps a plain ``datetime`` field to ``UTCDateTime``, which binds an
*aware* UTC value, and PostgreSQL casts an aware value into a ``timestamp
without time zone`` column in the session ``TimeZone``. With the session pinned
to UTC that cast is a no-op on every server, whatever its configured zone.
Other dialects bind the UTC wall clock unchanged, so they are left alone.
Applied to the service engine in ``core/deps.py`` and to Alembic's engine in
``alembic/env.py``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine

UTC_SESSION_SQL = "SET TIME ZONE 'UTC'"


def set_session_utc(dbapi_connection: Any, _connection_record: Any) -> None:
    """Set a new DBAPI connection's session zone to UTC, outside any transaction."""
    autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(UTC_SESSION_SQL)
    finally:
        cursor.close()
        dbapi_connection.autocommit = autocommit


def pin_utc_session(engine: Engine) -> Engine:
    """Register :func:`set_session_utc` on *engine* when it speaks PostgreSQL."""
    if engine.dialect.name == "postgresql" and not event.contains(
        engine, "connect", set_session_utc
    ):
        event.listen(engine, "connect", set_session_utc, insert=True)
    return engine

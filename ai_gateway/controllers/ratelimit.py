"""
Per-principal rate limits on credential writes (T20, D-24 rows).

Creating and rotating a credential (and, with ``T25``, validating one) each
charge one admission in ``ai_rate_window`` under the key
``credential-write:<sub>`` — the JWT ``sub``, so one user cannot spend
another's allowance, and never an execution principal's key, so management
never spends execution allowance. The charge commits on its own before the
write runs: a refused or failed write still counts.

C-14 names no setting for this limit, so it is a module constant, as the
sweeper grace is (``T15``).
"""

from __future__ import annotations

from typing import Final

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.db_models.accounting import ai_rate_window

from .errors import TooManyRequests

#: Credential writes one principal may make per UTC minute.
CREDENTIAL_WRITES_PER_MINUTE: Final = 20


def charge_credential_write(
    engine: Engine, subject: str, limit: int = CREDENTIAL_WRITES_PER_MINUTE
) -> None:
    """Count one write for ``subject``; 429 with ``Retry-After`` when spent."""
    table = ai_rate_window
    window = sa.func.date_trunc("minute", sa.func.now())
    statement = (
        pg_insert(table)
        .values(
            principal_key=f"credential-write:{subject}", window_start=window, count=1
        )
        .on_conflict_do_update(
            index_elements=[table.c.principal_key, table.c.window_start],
            set_={"count": table.c.count + 1},
            where=table.c.count < limit,
        )
        .returning(table.c.count)
    )
    # Seconds left in the current UTC minute.
    remaining = sa.select(sa.func.ceil(60 - sa.func.extract("second", sa.func.now())))
    with engine.begin() as connection:
        if connection.execute(statement).first() is not None:
            return
        retry_after = int(connection.execute(remaining).scalar_one())
    raise TooManyRequests("credential write rate limit reached", max(1, retry_after))


__all__ = ["CREDENTIAL_WRITES_PER_MINUTE", "charge_credential_write"]

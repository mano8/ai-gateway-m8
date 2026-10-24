"""Shared column helpers and value sets of the gateway schema (``ai_db``)."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Any

import sqlalchemy as sa
from sqlmodel import SQLModel

#: Every gateway table lives on the one metadata Alembic compares against.
metadata = SQLModel.metadata

TIMESTAMP = sa.DateTime(timezone=True)


class ExecutionStatus(StrEnum):
    """The stored statuses of ``ai_execution`` (D-24 transition table)."""

    RECEIVING = "receiving"
    SPOOLED = "spooled"
    PENDING = "pending"
    DISPATCHING = "dispatching"
    OK = "ok"
    FAILED = "failed"
    CHARGED_UNCERTAIN = "charged_uncertain"
    RELEASED = "released"
    ABANDONED = "abandoned"


#: Statuses that end an execution and release its occupancy slot.
TERMINAL_STATUSES = frozenset(
    {
        ExecutionStatus.OK,
        ExecutionStatus.FAILED,
        ExecutionStatus.CHARGED_UNCERTAIN,
        ExecutionStatus.RELEASED,
        ExecutionStatus.ABANDONED,
    }
)


def sql_list(values: Iterable[Any]) -> str:
    """``'a', 'b'`` for an ``IN (...)`` CHECK; values are fixed vocabularies."""
    return ", ".join(f"'{getattr(v, 'value', v)}'" for v in sorted(values, key=str))


def one_of(column: str, values: Iterable[Any], name: str) -> sa.CheckConstraint:
    """``CHECK (column IN (...))`` named ``name``."""
    return sa.CheckConstraint(f"{column} IN ({sql_list(values)})", name=name)


def created_at() -> sa.Column[Any]:
    """``created_at timestamptz NOT NULL DEFAULT now()``."""
    return sa.Column(
        "created_at", TIMESTAMP, nullable=False, server_default=sa.func.now()
    )


def updated_at() -> sa.Column[Any]:
    """``updated_at timestamptz NOT NULL DEFAULT now()``."""
    return sa.Column(
        "updated_at", TIMESTAMP, nullable=False, server_default=sa.func.now()
    )


def scope_shape_check(name: str) -> sa.CheckConstraint:
    """A row's scope: global has no owner, tenant names a tenant, user a user."""
    return sa.CheckConstraint(
        "(scope_type = 'global' AND tenant_id IS NULL AND owner_user_id IS NULL)"
        " OR (scope_type = 'tenant' AND tenant_id IS NOT NULL AND owner_user_id IS NULL)"
        " OR (scope_type = 'user' AND owner_user_id IS NOT NULL)",
        name=name,
    )


def json_bounded(column: str, name: str, max_bytes: int = 4096) -> sa.CheckConstraint:
    """``CHECK (octet_length(column::text) <= max_bytes)``."""
    return sa.CheckConstraint(f"octet_length({column}::text) <= {max_bytes}", name=name)


__all__ = [
    "TERMINAL_STATUSES",
    "TIMESTAMP",
    "ExecutionStatus",
    "created_at",
    "json_bounded",
    "metadata",
    "one_of",
    "scope_shape_check",
    "sql_list",
    "updated_at",
]

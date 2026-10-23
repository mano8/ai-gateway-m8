"""
``GET /v1/usage`` (``T33``): aggregates only, never a row or an identifier.

Two figures are reported and never merged: **admission units** (what the
gateway reserved and settled against a budget, from ``ai_usage``) and
**provider usage** (what providers reported, from the settled executions;
informational, no bound). A tenant is read through its ``tenant`` scope; the
platform view sums the ``client`` scope, which every execution carries once.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Connection

from ai_gateway.db_models.accounting import ai_execution, ai_usage

_E = ai_execution
_U = ai_usage
_TODAY = sa.cast(sa.func.timezone("UTC", sa.func.now()), sa.Date)

#: Days a report may span.
MAX_DAYS = 90


class AdmissionUnits(BaseModel):
    """Units reserved (in flight) and used (settled) on one day."""

    model_config = ConfigDict(frozen=True)
    reserved: int
    used: int


class ProviderUsageTotals(BaseModel):
    """Provider-reported totals on one day."""

    model_config = ConfigDict(frozen=True)
    input_tokens: int
    output_tokens: int
    pages_processed: int


class UsageDay(BaseModel):
    """One UTC budget day."""

    model_config = ConfigDict(frozen=True)
    day: date
    admission_units: AdmissionUnits
    provider_usage: ProviderUsageTotals


class UsageReport(BaseModel):
    """The report: ``tenant_id`` is ``None`` for the platform view."""

    model_config = ConfigDict(frozen=True)
    tenant_id: UUID | None
    days: list[UsageDay]


def _total(key: str) -> sa.ColumnElement[int]:
    return sa.func.coalesce(
        sa.func.sum(sa.cast(_E.c.provider_usage[key].astext, sa.BigInteger)), 0
    )


def usage_report(
    connection: Connection, tenant_id: UUID | None, days: int
) -> UsageReport:
    """The last ``days`` days of ``tenant_id`` (``None``: the whole platform)."""
    scope_type, scope_id = (
        ("client", None) if tenant_id is None else ("tenant", str(tenant_id))
    )
    since = _TODAY - (days - 1)
    units = sa.select(
        _U.c.day, sa.func.sum(_U.c.reserved), sa.func.sum(_U.c.used)
    ).where(_U.c.scope_type == scope_type, _U.c.day >= since)
    reported = sa.select(
        _E.c.reservation_day,
        _total("input_tokens"),
        _total("output_tokens"),
        _total("pages_processed"),
    ).where(_E.c.reservation_day >= since)
    if scope_id is not None:
        units = units.where(_U.c.scope_id == scope_id)
        reported = reported.where(_E.c.tenant_scope_id == scope_id)
    by_day: dict[date, list[int]] = {}
    for day, reserved, used in connection.execute(units.group_by(_U.c.day)):
        by_day[day] = [int(reserved), int(used), 0, 0, 0]
    for day, tokens_in, tokens_out, pages in connection.execute(
        reported.group_by(_E.c.reservation_day)
    ):
        by_day.setdefault(day, [0, 0, 0, 0, 0])[2:] = [
            int(tokens_in),
            int(tokens_out),
            int(pages),
        ]
    return UsageReport(
        tenant_id=tenant_id,
        days=[
            UsageDay(
                day=day,
                admission_units=AdmissionUnits(reserved=v[0], used=v[1]),
                provider_usage=ProviderUsageTotals(
                    input_tokens=v[2], output_tokens=v[3], pages_processed=v[4]
                ),
            )
            for day, v in sorted(by_day.items())
        ],
    )


__all__ = [
    "MAX_DAYS",
    "AdmissionUnits",
    "ProviderUsageTotals",
    "UsageDay",
    "UsageReport",
    "usage_report",
]

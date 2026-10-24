"""
The admission bounds an execution runs under (D-24, C-14).

Budgets are daily admission units per scope (client, tenant, user), the rate
limit is admissions per principal and UTC minute, and the in-flight cap is
occupancy slots per service client. Outside ``production``/strict an unset
bound is not enforced — the counters are still kept, so a bound configured
later starts from the truth; under ``production``/strict the settings refuse
to boot without each of them (``T27``).
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_gateway.core.config import ADMISSION_SETTINGS, SWEEPER_GRACE_SECONDS


@dataclass(frozen=True)
class ExecutionLimits:
    """Budgets, rate limit, in-flight cap, TTLs and the sweeper grace."""

    client_daily_units: int | None = None
    tenant_daily_units: int | None = None
    user_daily_units: int | None = None
    rate_per_minute: int | None = None
    max_inflight_per_client: int | None = None
    reservation_ttl_seconds: int = 60
    total_deadline_seconds: int = 120
    sweeper_grace_seconds: int = SWEEPER_GRACE_SECONDS

    @classmethod
    def from_settings(cls, settings: object) -> ExecutionLimits:
        """From gateway ``Settings``, read at call time."""

        def value(name: str) -> int | None:
            raw = getattr(settings, name)
            return None if raw is None else int(raw)

        return cls(
            client_daily_units=value("AI_CLIENT_DAILY_BUDGET_UNITS"),
            tenant_daily_units=value("AI_TENANT_DAILY_BUDGET_UNITS"),
            user_daily_units=value("AI_USER_DAILY_BUDGET_UNITS"),
            rate_per_minute=value("AI_RATE_LIMIT_PER_MINUTE"),
            max_inflight_per_client=value("AI_MAX_INFLIGHT_PER_CLIENT"),
            reservation_ttl_seconds=int(
                getattr(settings, "AI_RESERVATION_TTL_SECONDS")
            ),
            total_deadline_seconds=int(
                getattr(settings, "AI_PROVIDER_TOTAL_DEADLINE_SECONDS")
            ),
        )


__all__ = ["ADMISSION_SETTINGS", "ExecutionLimits"]

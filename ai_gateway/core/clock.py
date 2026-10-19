"""
Application–database clock skew (D-24).

Every lease, deadline, expiry and window predicate is evaluated in SQL
against the database clock, but the handler's remaining-time checks also use
the local clock. The gateway therefore measures how far the two disagree and
refuses execution — a typed ``503 clock_skew_exceeded`` — while the skew is
above ``AI_MAX_CLOCK_SKEW_SECONDS``; ``/health`` reports the state as
degraded. A measurement is cached briefly so a burst of requests costs one
query.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ai_sdk_m8.schemas import AiErrorCode
from sqlalchemy import Engine, text

from fastapi_m8 import HealthCheckResult, HealthStatus

from .errors import GatewayError

#: Seconds a skew measurement is reused.
MEASUREMENT_TTL_SECONDS = 5.0

_DB_EPOCH = text("SELECT EXTRACT(EPOCH FROM clock_timestamp())")


@dataclass(frozen=True)
class SkewReading:
    """One measurement: the absolute skew and whether it is within the bound."""

    skew_seconds: float
    within_bound: bool


class ClockSkewMonitor:
    """Measures and caches the application–database clock skew."""

    def __init__(
        self,
        engine: Callable[[], Engine],
        bound_seconds: float,
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine = engine
        self._bound = bound_seconds
        self._wall_clock = wall_clock
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._cached: tuple[float, SkewReading] | None = None

    def measure(self) -> SkewReading:
        """Query the database clock now and compare it with the local clock."""
        with self._engine().connect() as connection:
            before = self._wall_clock()
            database = float(connection.execute(_DB_EPOCH).scalar_one())
            after = self._wall_clock()
        skew = abs(database - (before + after) / 2)
        return SkewReading(skew, skew <= self._bound)

    def reading(self) -> SkewReading:
        """The cached measurement, refreshed after ``MEASUREMENT_TTL_SECONDS``."""
        with self._lock:
            now = self._monotonic()
            if self._cached is None or now - self._cached[0] > MEASUREMENT_TTL_SECONDS:
                self._cached = (now, self.measure())
            return self._cached[1]

    def require_within_bound(self) -> None:
        """Raise the typed 503 when the skew exceeds the bound."""
        if not self.reading().within_bound:
            raise GatewayError(AiErrorCode.CLOCK_SKEW_EXCEEDED, retry_after_seconds=30)

    async def health_check(self) -> HealthCheckResult:
        """``/health`` check: degraded above the bound, failed when unreadable."""
        try:
            reading = self.reading()
        except Exception as exc:
            return HealthCheckResult(
                name="clock_skew", status=HealthStatus.FAIL, error=type(exc).__name__
            )
        return HealthCheckResult(
            name="clock_skew",
            status=HealthStatus.OK if reading.within_bound else HealthStatus.DEGRADED,
            meta={"skew_ms": round(reading.skew_seconds * 1000)},
        )


__all__ = ["MEASUREMENT_TTL_SECONDS", "ClockSkewMonitor", "SkewReading"]

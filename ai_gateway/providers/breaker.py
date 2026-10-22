"""
Per-provider circuit breakers (D-20).

A breaker is keyed by provider and fed **only** by transport failures,
timeouts and 5xx answers. A 401/403 is an outcome of the credential (the
``T25`` counter) and a 429 backs off that credential only, so neither moves
a breaker: one tenant's invalid or throttled key cannot open the breaker for
every other tenant of the same provider.

States: ``closed`` (calls pass), ``open`` (calls are refused before any
connection, for ``reset_seconds``), ``half_open`` (one trial call passes;
its success closes the breaker, its failure opens it again, a neutral
outcome lets the next trial through).

Breaker state lives in the process (documented, not a correctness control:
replicas keep their own; cross-replica state is a named follow-on). The
thresholds are module constants, because C-14 names no setting for them.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from enum import StrEnum
from typing import Final
from uuid import UUID

#: Consecutive failures that open a closed breaker.
FAILURE_THRESHOLD: Final = 5

#: Seconds an open breaker refuses calls before it allows one trial.
RESET_SECONDS: Final = 30.0


class BreakerState(StrEnum):
    """Where a breaker is in its cycle."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """One provider's breaker; safe to share between threads."""

    def __init__(
        self,
        *,
        failure_threshold: int = FAILURE_THRESHOLD,
        reset_seconds: float = RESET_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._threshold = failure_threshold
        self._reset = reset_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at: float | None = None
        self._trial_in_flight = False

    @property
    def state(self) -> BreakerState:
        """The current state; an open breaker past its reset is half-open."""
        with self._lock:
            return self._state()

    def _state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock() - self._opened_at < self._reset:
            return BreakerState.OPEN
        return BreakerState.HALF_OPEN

    def allow(self) -> bool:
        """Whether a call may start; a half-open breaker admits one trial."""
        with self._lock:
            state = self._state()
            if state is BreakerState.CLOSED:
                return True
            if state is BreakerState.OPEN or self._trial_in_flight:
                return False
            self._trial_in_flight = True
            return True

    def success(self) -> None:
        """The provider answered: close the breaker."""
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._trial_in_flight = False

    def failure(self) -> None:
        """A transport failure, a timeout or a 5xx: count it, open on threshold."""
        with self._lock:
            self._failures += 1
            trial = self._trial_in_flight
            self._trial_in_flight = False
            if trial or self._failures >= self._threshold:
                self._opened_at = self._clock()

    def neutral(self) -> None:
        """A credential outcome (401/403/429): no change; free the trial slot."""
        with self._lock:
            self._trial_in_flight = False


class Breakers:
    """The process's breakers, one per provider id."""

    def __init__(self, factory: Callable[[], CircuitBreaker] = CircuitBreaker) -> None:
        self._factory = factory
        self._lock = threading.Lock()
        self._breakers: dict[UUID, CircuitBreaker] = {}

    def for_provider(self, provider_id: UUID) -> CircuitBreaker:
        """The breaker of ``provider_id``, created closed on first use."""
        with self._lock:
            breaker = self._breakers.get(provider_id)
            if breaker is None:
                breaker = self._breakers[provider_id] = self._factory()
            return breaker

    def states(self) -> dict[UUID, BreakerState]:
        """Every known breaker's state, for metrics and health."""
        with self._lock:
            items = list(self._breakers.items())
        return {provider_id: breaker.state for provider_id, breaker in items}


#: The breakers of this process.
breakers = Breakers()


__all__ = [
    "FAILURE_THRESHOLD",
    "RESET_SECONDS",
    "BreakerState",
    "Breakers",
    "CircuitBreaker",
    "breakers",
]

"""
The scheduler loop: lease, check due, run, stamp, heartbeat (D-42).

Each job is polled every ``min(interval, POLL_CAP_SECONDS)`` seconds. A poll
renews or acquires the job's lease; without it the job is another replica's.
With it, the job runs only if the lease row's ``last_success_at`` is older
than its interval — so N replicas run each job **once per interval**, not
once each — and a successful run stamps ``last_success_at`` under the fence.
A failed run is logged and retried at the next poll; ``/health`` sees it
late.

The loop touches a heartbeat file after every pass; ``--healthcheck`` (the
container probe) answers from that file's age alone (:mod:`.heartbeat`).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Final

import sqlalchemy as sa
from sqlalchemy import Engine

from ai_gateway.db_models.installation import ai_scheduler_lease

from .heartbeat import touch
from .jobs import Job, Summary
from .lease import LEASE_TTL_SECONDS, Lease, LeaseKeeper

logger = logging.getLogger(__name__)

_L = ai_scheduler_lease

#: The longest gap between two polls of one job (renews its lease in time).
POLL_CAP_SECONDS: Final = LEASE_TTL_SECONDS // 3

#: Seconds the loop sleeps between passes.
PASS_SECONDS: Final = 1.0


class Scheduler:
    """Runs ``jobs`` under ``keeper``'s leases until stopped."""

    def __init__(
        self,
        engine: Engine,
        keeper: LeaseKeeper,
        jobs: Sequence[Job],
        *,
        heartbeat: Path,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine = engine
        self._keeper = keeper
        self._jobs = list(jobs)
        self._heartbeat = heartbeat
        self._clock = clock
        self._next_poll: dict[str, float] = {}

    def _due(self, lease: Lease, interval_seconds: int) -> bool:
        """No replica succeeded within the interval (read under the lease)."""
        with self._engine.connect() as connection:
            row = connection.execute(
                sa.select(
                    sa.or_(
                        _L.c.last_success_at.is_(None),
                        _L.c.last_success_at
                        <= sa.func.now() - timedelta(seconds=interval_seconds),
                    )
                ).where(_L.c.job == lease.job)
            ).first()
        return row is not None and bool(row[0])

    async def run_job(self, job: Job) -> Summary | None:
        """Poll ``job`` once; its summary if it ran and succeeded."""
        lease = self._keeper.hold(job.name)
        if lease is None or not self._due(lease, job.interval_seconds):
            return None
        try:
            summary = await job.run(lease)
        except Exception:  # one job's failure never stops the others
            logger.exception("scheduler job %s failed", job.name)
            return None
        if not self._keeper.succeeded(lease):
            logger.warning("scheduler job %s lost its lease while running", job.name)
            return None
        logger.info("scheduler job %s %s", job.name, dict(summary))
        return summary

    async def tick(self) -> dict[str, Summary]:
        """One pass over every job whose poll is due; the summaries of those that ran."""
        ran: dict[str, Summary] = {}
        now = self._clock()
        for job in self._jobs:
            if self._next_poll.get(job.name, 0.0) > now:
                continue
            self._next_poll[job.name] = now + min(
                job.interval_seconds, POLL_CAP_SECONDS
            )
            summary = await self.run_job(job)
            if summary is not None:
                ran[job.name] = summary
        touch(self._heartbeat)
        return ran

    async def serve(self, stop: asyncio.Event) -> None:
        """Pass after pass until ``stop`` is set; give the leases up on the way out."""
        try:
            while not stop.is_set():
                await self.tick()
                try:
                    await asyncio.wait_for(stop.wait(), timeout=PASS_SECONDS)
                except TimeoutError:
                    pass
        finally:
            self._keeper.release()


def last_successes(engine: Engine) -> Mapping[str, float | None]:
    """Seconds since each job's last success (``None`` if it never succeeded)."""
    age = sa.func.extract("epoch", sa.func.now() - _L.c.last_success_at)
    with engine.connect() as connection:
        rows = connection.execute(sa.select(_L.c.job, age)).all()
    return {str(job): None if value is None else float(value) for job, value in rows}


__all__ = ["POLL_CAP_SECONDS", "Scheduler", "last_successes"]

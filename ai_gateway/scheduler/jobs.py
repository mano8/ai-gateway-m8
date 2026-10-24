"""
The scheduler's jobs (D-42): each one bounded pass under its own lease.

Every job acts by stored status per the D-24 and D-43 tables, through the
functions that own those transitions, and passes them the lease's fence;
the remote-artifact jobs that reach a provider per row also take per-item
claims. Nothing here re-implements a transition.

========================  ========  ==============================================
job                       interval  work
========================  ========  ==============================================
``settlement``            15 s      ``pending`` / ``dispatching`` / ``receiving``
                                    / ``spooled`` settlement (D-24, D-45)
``contexts``              60 s      context rows past ``exp``
``spool``                 30 s      the D-45 cleaner, restore-mode release,
                                    orphan collection, the high-water write
``remote_artifacts``      30 s      D-43 (c), (g), (h)/(i), (d)/(e)/(f), (j)/(k),
                                    the platform sweep and the status gauge
``restore``               30 s      the ``restore-reconcile`` steps
``rate_windows``          300 s     rate-window rows older than two windows
``occupancy``             300 s     the locked occupancy-counter repair
``model_digests``         900 s     the Ollama digest re-check (``T28``)
``credentials``           3600 s    material destruction of retired versions
``retention``             3600 s    execution and usage retention, audit bytes
========================  ========  ==============================================

The ``spool`` job exists only where ``AI_OCR_SPOOL_DIR`` is configured.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine

from ai_gateway.core import restore_state
from ai_gateway.core.config import SWEEPER_GRACE_SECONDS
from ai_gateway.credentials.destruction import destroy_retired
from ai_gateway.execution import retention, settlement, sweepers
from ai_gateway.execution.artifacts import ArtifactScheduler
from ai_gateway.execution.spool import SpoolLayout
from ai_gateway.restore import RestorePolicy, advance, release_restore_artifacts

from .lease import LEASE_TTL_SECONDS, Lease

#: Seconds between two runs of each job (the module table).
SCHEDULE: Final[Mapping[str, int]] = {
    "settlement": 15,
    "contexts": 60,
    "spool": 30,
    "remote_artifacts": 30,
    "restore": 30,
    "rate_windows": 300,
    "occupancy": 300,
    "model_digests": 900,
    "credentials": 3600,
    "retention": 3600,
}

#: Retention batches one run may take (each ``SWEEP_BATCH`` rows).
RETENTION_BATCHES: Final = 100

Summary = Mapping[str, object]


def late_after(interval_seconds: int) -> int:
    """Seconds after which a job's last success counts as late (``/health``)."""
    return max(3 * interval_seconds, interval_seconds + LEASE_TTL_SECONDS + 60)


def expected_jobs(*, spool: bool) -> dict[str, int]:
    """The jobs a deployment runs and the age at which each is late."""
    return {
        name: late_after(interval)
        for name, interval in SCHEDULE.items()
        if spool or name != "spool"
    }


@dataclass(frozen=True)
class Job:
    """One scheduled job: its lease name, interval and fenced pass."""

    name: str
    interval_seconds: int
    run: Callable[[Lease], Awaitable[Summary]]


class DigestRechecker(Protocol):
    """:class:`~ai_gateway.controllers.model_identity.DigestReader`'s re-check."""

    async def recheck(
        self, *, fence: sa.ColumnElement[bool] | None = None
    ) -> list[UUID]:
        """Flag every digest-pinned model whose listing changed."""


@dataclass(frozen=True)
class JobContext:
    """What the jobs act on; built from ``core.deps`` in the scheduler process."""

    engine: Engine
    artifacts: ArtifactScheduler
    digests: DigestRechecker
    restore: RestorePolicy
    retention_days: int
    spool_root: Path | None


def _settlement(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        fence = lease.fence()
        return {
            "pending": len(settlement.sweep_expired_pending(ctx.engine, fence=fence)),
            "dispatching": len(
                settlement.sweep_stale_dispatching(
                    ctx.engine, grace_seconds=SWEEPER_GRACE_SECONDS, fence=fence
                )
            ),
            "spools": len(sweepers.sweep_spools(ctx.engine, fence=fence)),
        }

    return run


def _contexts(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        return {"swept": sweepers.sweep_contexts(ctx.engine, fence=lease.fence())}

    return run


def _spool(ctx: JobContext, root: Path) -> Callable[[Lease], Awaitable[Summary]]:
    layout = SpoolLayout(root)

    async def run(lease: Lease) -> Summary:
        fence = lease.fence()
        summary: dict[str, object] = {}
        with ctx.engine.connect() as connection:
            restoring = bool(
                connection.execute(
                    sa.select(restore_state.in_restore_exists())
                ).scalar()
            )
        if restoring:  # spools cleaned after the snapshot point are no alert
            summary["restore_released"] = len(
                release_restore_artifacts(layout, ctx.engine, fence=fence)
            )
        summary["cleaned"] = sweepers.clean_spools(layout, ctx.engine)
        summary["orphans"] = len(sweepers.collect_orphans(layout, ctx.engine))
        summary["highwater"] = restore_state.write_highwater(ctx.engine, root)
        return summary

    return run


def _remote_artifacts(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    work = ctx.artifacts

    async def run(lease: Lease) -> Summary:
        fence = lease.fence()
        summary = {
            "expired_uploads": len(work.expire_uploads(fence)),
            "retired_active": len(work.retire_active(fence)),
            "deleted": len(await work.delete_pending(claim=lease)),
            "resolved": len(await work.resolve_unknown(claim=lease)),
            "revisited": len(await work.revisit_parked(claim=lease)),
            "swept": len(await work.sweep()),
        }
        work.refresh_gauge()
        return summary

    return run


def _restore(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        return advance(ctx.engine, ctx.restore, fence=lease.fence())

    return run


def _rate_windows(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        return {"pruned": sweepers.prune_rate_windows(ctx.engine, fence=lease.fence())}

    return run


def _occupancy(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        return {"repaired": sweepers.repair_occupancy(ctx.engine, fence=lease.fence())}

    return run


def _model_digests(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        flagged = await ctx.digests.recheck(fence=lease.fence())
        return {"flagged": [str(model_id) for model_id in flagged]}

    return run


def _credentials(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        return {"destroyed": len(destroy_retired(ctx.engine, fence=lease.fence()))}

    return run


def _drain(
    collect: Callable[..., int], ctx: JobContext, fence: sa.ColumnElement[bool]
) -> int:
    """Run one retention collector batch by batch, up to the per-run cap."""
    total = 0
    for _ in range(RETENTION_BATCHES):
        removed = collect(ctx.engine, ctx.retention_days, fence=fence)
        total += removed
        if removed < settlement.SWEEP_BATCH:
            break
    return total


def _retention(ctx: JobContext) -> Callable[[Lease], Awaitable[Summary]]:
    async def run(lease: Lease) -> Summary:
        fence = lease.fence()
        # Only rows the positive predicate says nothing else needs (T33):
        # settlement, unlink and remote cleanup always come first.
        return {
            "executions": _drain(retention.collect_executions, ctx, fence),
            "usage": _drain(retention.collect_usage, ctx, fence),
            "audit_table_bytes": retention.observe_audit_table_bytes(ctx.engine),
        }

    return run


def build_jobs(ctx: JobContext) -> list[Job]:
    """Every job of this deployment, in the module table's order."""
    runs: dict[str, Callable[[Lease], Awaitable[Summary]]] = {
        "settlement": _settlement(ctx),
        "contexts": _contexts(ctx),
        "remote_artifacts": _remote_artifacts(ctx),
        "restore": _restore(ctx),
        "rate_windows": _rate_windows(ctx),
        "occupancy": _occupancy(ctx),
        "model_digests": _model_digests(ctx),
        "credentials": _credentials(ctx),
        "retention": _retention(ctx),
    }
    if ctx.spool_root is not None:
        runs["spool"] = _spool(ctx, ctx.spool_root)
    return [Job(name, SCHEDULE[name], runs[name]) for name in SCHEDULE if name in runs]


__all__ = [
    "SCHEDULE",
    "DigestRechecker",
    "Job",
    "JobContext",
    "build_jobs",
    "expected_jobs",
    "late_after",
]

"""
Scheduler run-mode (D-42): ``python -m ai_gateway.scheduler``.

The same image as the web service, started by command override as
``ai_gateway_scheduler``. It runs every scheduled gateway job under a fenced
database lease (:mod:`.lease`, :mod:`.jobs`, :mod:`.runner`), lease-safe for
any number of replicas.

Before its first pass it runs the web run-mode's start-up checks
(:mod:`ai_gateway.prestart`): a local spool whose locks exclude, the schema
revision equal to the packaged head, this installation, and every KEK
generation a stored version needs. It runs as ``AI_RUN_MODE=scheduler``, so
it neither requires nor reads the fingerprint key or the OCR receipt seed,
which are mounted on the web service only. It never migrates.

``python -m ai_gateway.scheduler --healthcheck`` is the container probe: it
exits ``0`` only while the loop's heartbeat file (in tmpfs) is fresh.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import socket
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from .runner import Scheduler

logger = logging.getLogger(__name__)

#: The loop's heartbeat, in the container's tmpfs.
HEARTBEAT_FILE: Final = Path(tempfile.gettempdir()) / "ai_gateway_scheduler.heartbeat"


def build_scheduler(heartbeat: Path = HEARTBEAT_FILE) -> Scheduler:
    """The scheduler over this process's ``core.deps`` (built once)."""
    from ai_gateway.core import deps  # noqa: PLC0415 - after the run-mode is set
    from ai_gateway.restore import RestorePolicy  # noqa: PLC0415

    from .jobs import JobContext, build_jobs  # noqa: PLC0415
    from .lease import LeaseKeeper  # noqa: PLC0415
    from .runner import Scheduler  # noqa: PLC0415

    settings = deps.settings
    context = JobContext(
        engine=deps.db_engine,
        artifacts=deps.artifact_scheduler,
        digests=deps.model_digests,
        restore=RestorePolicy.from_settings(settings),
        retention_days=settings.AI_EXECUTION_RETENTION_DAYS,
        spool_root=settings.AI_OCR_SPOOL_DIR,
    )
    keeper = LeaseKeeper(deps.db_engine, f"{socket.gethostname()}:{os.getpid()}")
    return Scheduler(deps.db_engine, keeper, build_jobs(context), heartbeat=heartbeat)


async def _serve(scheduler: Scheduler) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await scheduler.serve(stop)


def main(argv: list[str] | None = None) -> int:
    """Run the scheduler until SIGTERM, or answer the container probe."""
    parser = argparse.ArgumentParser(prog="python -m ai_gateway.scheduler")
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.healthcheck:
        from .heartbeat import healthy  # noqa: PLC0415

        return 0 if healthy(HEARTBEAT_FILE) else 1
    # Before the settings are first read: no fingerprint key, no receipt seed.
    os.environ["AI_RUN_MODE"] = "scheduler"
    from ai_gateway import prestart  # noqa: PLC0415

    if prestart.main() != 0:
        logger.error("ai_gateway scheduler: start-up checks failed; refusing to run")
        return 1
    asyncio.run(_serve(build_scheduler()))
    return 0


__all__ = ["HEARTBEAT_FILE", "build_scheduler", "main"]

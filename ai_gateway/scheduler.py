"""
Scheduler run-mode entrypoint.

The scheduler owns the gateway's background jobs (sweeps, reconciliation,
retention). None is implemented yet, so this entrypoint refuses to run rather
than idle as a process that looks healthy and does nothing.

Run as ``python -m ai_gateway.scheduler``.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def main() -> int:
    """
    Refuse to start: no scheduler job exists yet.

    Returns
    -------
    int
        Exit status ``1``.

    """
    logger.error("ai_gateway scheduler: no job is implemented yet; refusing to run")
    return 1


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

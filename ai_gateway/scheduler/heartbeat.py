"""
The scheduler's heartbeat file and the container probe (D-42).

Imports nothing of the gateway: ``python -m ai_gateway.scheduler
--healthcheck`` answers from the file's age without reading any setting.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Final

#: A heartbeat older than this fails ``--healthcheck``.
HEARTBEAT_MAX_AGE_SECONDS: Final = 120


def touch(path: Path) -> None:
    """Record a live pass: create or refresh ``path``'s modification time."""
    path.touch(mode=0o600, exist_ok=True)
    os.utime(path)


def heartbeat_age(path: Path, now: float | None = None) -> float | None:
    """Seconds since the last pass, or ``None`` without a heartbeat."""
    try:
        modified = path.stat().st_mtime
    except FileNotFoundError:
        return None
    return (time.time() if now is None else now) - modified


def healthy(path: Path, max_age_seconds: int = HEARTBEAT_MAX_AGE_SECONDS) -> bool:
    """The container probe's verdict."""
    age = heartbeat_age(path)
    return age is not None and age <= max_age_seconds


__all__ = ["HEARTBEAT_MAX_AGE_SECONDS", "healthy", "heartbeat_age", "touch"]

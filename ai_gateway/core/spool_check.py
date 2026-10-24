"""
Start-up assertion that the OCR spool is a local block filesystem (D-45).

``flock`` has kernel semantics only on one host and a local filesystem, and
a ``local`` Docker volume driver does not prove one (it also mounts NFS and
CIFS). Every gateway and scheduler process therefore refuses to start unless
the spool directory sits on ``ext4``, ``xfs`` or ``btrfs`` and a lock
self-test shows that a lock held by another process blocks a non-blocking
attempt.
"""

from __future__ import annotations

import fcntl
import os
import select
import subprocess  # nosec B404 - runs this interpreter on a fixed script
import sys
from pathlib import Path
from typing import Final

#: Filesystems the spool may live on.
LOCAL_FILESYSTEMS: Final = frozenset({"ext4", "xfs", "btrfs"})

MOUNTINFO: Final = Path("/proc/self/mountinfo")

#: Seconds the lock self-test waits for its holder process.
HOLDER_START_TIMEOUT_SECONDS: Final = 10.0

# The child holds LOCK_EX on the probe until its stdin closes.
_HOLDER = (
    "import fcntl, os, sys\n"
    "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC)\n"
    "fcntl.flock(fd, fcntl.LOCK_EX)\n"
    "sys.stdout.write('held\\n'); sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)


class SpoolFilesystemError(RuntimeError):
    """The spool is not on a local filesystem or its locks do not exclude."""


def _unescape(field: str) -> str:
    # mountinfo escapes space, tab, newline and backslash as octal.
    return (
        field.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def filesystem_type(path: Path, mountinfo: str | None = None) -> str:
    """The filesystem type of the mount that holds ``path``."""
    resolved = str(path.resolve())
    text = mountinfo if mountinfo is not None else MOUNTINFO.read_text()
    best_point = ""
    best_type = ""
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        fields = left.split()
        if not sep or len(fields) < 5 or not right.split():
            continue
        point = _unescape(fields[4])
        inside = resolved == point or resolved.startswith(point.rstrip("/") + "/")
        if inside and len(point) >= len(best_point):
            best_point, best_type = point, right.split()[0]
    if not best_type:
        raise SpoolFilesystemError("the spool's mount could not be identified")
    return best_type


def lock_self_test(directory: Path) -> None:
    """A ``LOCK_EX`` held by another process must make ``LOCK_NB`` fail."""
    probe = directory / ".locks" / f".selftest-{os.getpid()}"
    probe.parent.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(probe, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    holder = subprocess.Popen(  # nosec B603 - fixed argv, no shell
        [sys.executable, "-c", _HOLDER, str(probe)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None  # nosec B101 - PIPE requested
        ready, _, _ = select.select(
            [holder.stdout], [], [], HOLDER_START_TIMEOUT_SECONDS
        )
        if not ready or holder.stdout.readline().strip() != "held":
            raise SpoolFilesystemError("the lock self-test holder did not start")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        raise SpoolFilesystemError(
            "a lock held by another process did not block: the spool's locks "
            "do not exclude"
        )
    finally:
        holder.kill()
        holder.communicate()
        os.close(fd)
        probe.unlink(missing_ok=True)


def assert_local_spool(directory: Path, mountinfo: str | None = None) -> None:
    """Refuse a spool that is missing, remote or whose locks do not exclude."""
    if not directory.is_dir():
        raise SpoolFilesystemError("AI_OCR_SPOOL_DIR is not a directory")
    kind = filesystem_type(directory, mountinfo)
    if kind not in LOCAL_FILESYSTEMS:
        raise SpoolFilesystemError(
            f"AI_OCR_SPOOL_DIR is on {kind!r}; the spool needs ext4, xfs or btrfs"
        )
    lock_self_test(directory)


__all__ = [
    "LOCAL_FILESYSTEMS",
    "SpoolFilesystemError",
    "assert_local_spool",
    "filesystem_type",
    "lock_self_test",
]

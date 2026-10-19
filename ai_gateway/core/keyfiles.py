"""
Secret key files: read once, mode-checked, never logged (D-23).

Every key the gateway holds — the local KEK and its previous generations,
the fingerprint keys, the OCR receipt seed — comes from a file (a Docker
secret), never from an environment variable. A file is refused unless it is
a regular file with no group or other permission bits. A 32-byte key may be
stored raw or as its 44-character base64 text.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import stat
from pathlib import Path
from typing import Final

#: Length of every symmetric key and Ed25519 seed the gateway loads.
KEY_BYTES: Final = 32

#: Largest key or token file read, in bytes.
_MAX_FILE_BYTES: Final = 4096

#: Permission bits a secret file must not carry.
_UNSAFE_MODE_BITS: Final = stat.S_IRWXG | stat.S_IRWXO


class KeyFileError(ValueError):
    """A key file is missing, unreadable, unsafe or malformed."""


class KeyMaterial:
    """Key bytes whose ``repr`` never shows them."""

    __slots__ = ("_value", "path")

    def __init__(self, value: bytes, path: Path) -> None:
        self._value = value
        self.path = path

    def __repr__(self) -> str:
        return f"KeyMaterial(path={str(self.path)!r}, value=<redacted>)"

    def reveal(self) -> bytes:
        """The raw key bytes."""
        return self._value

    def same_as(self, other: KeyMaterial) -> bool:
        """Constant-time equality of two keys."""
        return hmac.compare_digest(self._value, other._value)

    def version(self, purpose: str) -> str:
        """
        A stable, non-secret label for this key generation.

        It is a truncated hash of the key under a purpose tag, so two
        purposes never share a label and the label reveals nothing usable.
        """
        digest = hashlib.sha256(
            f"m8.ai.{purpose}-version.v1".encode() + b"\x00" + self._value
        ).hexdigest()
        return f"{purpose}-{digest[:16]}"


def _read_secret_file(path: Path, what: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        raise KeyFileError(f"{what} is not readable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise KeyFileError(f"{what} is not a regular file")
        if info.st_mode & _UNSAFE_MODE_BITS:
            raise KeyFileError(f"{what} must not be readable by group or others")
        data = os.read(fd, _MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _MAX_FILE_BYTES:
        raise KeyFileError(f"{what} is too large")
    return data


def load_key_file(path: Path, *, what: str) -> KeyMaterial:
    """
    Load a 32-byte key from ``path``.

    The file holds exactly 32 raw bytes, or the 44-character standard base64
    text of 32 bytes (one trailing newline allowed).
    """
    data = _read_secret_file(path, what)
    if len(data) == KEY_BYTES:
        return KeyMaterial(data, path)
    text = data.removesuffix(b"\n")
    if len(text) == 44:
        try:
            decoded = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) == KEY_BYTES:
            return KeyMaterial(decoded, path)
    raise KeyFileError(f"{what} must hold 32 raw bytes or their base64 text")


def load_secret_text(path: Path, *, what: str) -> str:
    """Load a short secret token (a Vault token, a role or secret id)."""
    data = _read_secret_file(path, what).strip()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise KeyFileError(f"{what} must be ASCII text") from None
    if not text or not text.isprintable() or any(c.isspace() for c in text):
        raise KeyFileError(f"{what} must hold one non-empty token")
    return text


__all__ = [
    "KEY_BYTES",
    "KeyFileError",
    "KeyMaterial",
    "load_key_file",
    "load_secret_text",
]

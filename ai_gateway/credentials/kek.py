"""
Key-encryption-key providers (D-23, R-10).

A provider wraps and unwraps the per-version data keys; it never sees a
credential. ``local`` wraps with AES-256-GCM under a 32-byte key read once
from a mode-checked file (``AI_CREDENTIAL_KEK_FILE``); earlier generations
listed in ``AI_CREDENTIAL_KEK_PREVIOUS_FILES`` unwrap only. Each generation
is named by ``kek_key_version``, a purpose-tagged digest prefix of its key,
so a row says which key it needs without revealing anything about it.
``vault_transit`` is ``T23``'s.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ai_gateway.core.keyfiles import KeyMaterial

#: AES-GCM nonce length.
NONCE_BYTES: Final = 12

#: The non-secret probe ``health`` round-trips.
_PROBE: Final = b"m8.ai.kek-probe.v1"


class KekError(Exception):
    """A key could not be wrapped or unwrapped; the message names no key."""


@dataclass(frozen=True)
class WrappedKey:
    """A wrapped data key and the KEK generation that wrapped it."""

    wrapped_dek: bytes
    wrap_nonce: bytes | None
    key_id: str
    key_version: str


@runtime_checkable
class KekProvider(Protocol):
    """Wraps data keys; ``provider`` is the ``kek_provider`` column value."""

    provider: str

    @property
    def active_version(self) -> str:
        """The generation new wraps use."""

    def generations(self) -> frozenset[str]:
        """Every generation this replica can unwrap."""

    def wrap(self, dek: bytes, aad: bytes) -> WrappedKey:
        """Wrap ``dek`` under the active generation, bound to ``aad``."""

    def unwrap(self, wrapped: WrappedKey, aad: bytes) -> bytes:
        """Unwrap ``wrapped``; :class:`KekError` on any failure."""

    def probe(self) -> None:
        """Round-trip a constant; :class:`KekError` when it fails."""


class LocalKekProvider:
    """AES-256-GCM key wrapping under local key files."""

    provider = "local"
    #: ``kek_key_id`` of every local wrap; the generation is the version.
    key_id = "local"

    def __init__(
        self, active: KeyMaterial, previous: Sequence[KeyMaterial] = ()
    ) -> None:
        self._active = active.version("kek")
        self._keys = {key.version("kek"): key for key in (*previous, active)}

    def __repr__(self) -> str:
        return f"LocalKekProvider(active={self._active!r})"

    @property
    def active_version(self) -> str:
        """The generation new wraps use."""
        return self._active

    def generations(self) -> frozenset[str]:
        """Every configured generation."""
        return frozenset(self._keys)

    def wrap(self, dek: bytes, aad: bytes) -> WrappedKey:
        """Wrap ``dek`` under the active key with a fresh nonce."""
        nonce = os.urandom(NONCE_BYTES)
        key = self._keys[self._active].reveal()
        wrapped = AESGCM(key).encrypt(nonce, dek, aad)
        return WrappedKey(wrapped, nonce, self.key_id, self._active)

    def unwrap(self, wrapped: WrappedKey, aad: bytes) -> bytes:
        """Unwrap with the generation the row names."""
        key = self._keys.get(wrapped.key_version)
        if key is None or wrapped.wrap_nonce is None:
            raise KekError("the KEK generation this row needs is not configured")
        try:
            return AESGCM(key.reveal()).decrypt(
                wrapped.wrap_nonce, wrapped.wrapped_dek, aad
            )
        except (InvalidTag, ValueError):
            raise KekError("the data key does not unwrap") from None

    def probe(self) -> None:
        """Wrap and unwrap the probe under the active key (authenticated)."""
        self.unwrap(self.wrap(_PROBE, _PROBE), _PROBE)


__all__ = ["NONCE_BYTES", "KekError", "KekProvider", "LocalKekProvider", "WrappedKey"]

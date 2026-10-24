"""
The credential-store contract (C-06).

Only the gateway decrypts provider credentials (D-02), and only through a
:class:`CredentialStore`:

* ``store`` / ``replace`` write a new version: under ``SELECT … FOR UPDATE``
  on the credential row, version ``next_version`` is allocated (and
  ``next_version`` advanced) and the pointer ``current_version`` moved. On the
  database backends this is one transaction; the ``vault`` KV backend runs
  C-06's prepare → write → commit protocol instead.
* ``resolve_for_execution(credential_id, version)`` yields the plaintext of
  **exactly** the version an execution row recorded, inside a ``with`` block,
  and only while the credential is ``active`` and that version is current —
  a retired version or any other status is ``credential_unavailable``. It
  never reads a binding.
* ``resolve_for_cleanup(credential_id, version)`` is the separate D-43 entry
  point: it also accepts a retired version and a non-``active`` credential,
  as long as the version's material still exists. It is never used to
  execute.
* ``delete`` is logical (D-43); ``destroy`` clears one version's material
  and keeps its row as a tombstone; ``rewrap`` and ``refingerprint`` move rows
  to the active key generations (D-23).

The plaintext travels only as a :class:`ResolvedSecret`, whose ``repr`` and
``str`` are redacted and whose buffer is overwritten when its ``with``
block ends. That wipe is best effort: a ``str`` built from it by
:meth:`ResolvedSecret.reveal` is an immutable copy Python cannot erase.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID

from ai_sdk_m8.schemas import AiErrorCode
from ai_sdk_m8.schemas.management import ScopeType
from pydantic import SecretStr
from sqlalchemy import Connection

from fastapi_m8 import HealthCheckResult

from ai_gateway.core.errors import GatewayError


class ResolvedSecret:
    """A decrypted credential: redacted when shown, wiped when released."""

    __slots__ = ("_buffer",)

    def __init__(self, plaintext: bytes | bytearray) -> None:
        self._buffer = bytearray(plaintext)

    def __repr__(self) -> str:
        return "ResolvedSecret(<redacted>)"

    __str__ = __repr__

    def reveal(self) -> str:
        """The secret as text, for the one request header that carries it."""
        if not self._buffer:
            raise ValueError("the secret was released")
        return self._buffer.decode("utf-8")

    def wipe(self) -> None:
        """Overwrite the buffer (best effort; copies already made survive)."""
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._buffer.clear()


@contextmanager
def released(secret: ResolvedSecret) -> Iterator[ResolvedSecret]:
    """Yield ``secret`` and wipe it when the block ends, however it ends."""
    try:
        yield secret
    finally:
        secret.wipe()


def credential_unavailable() -> GatewayError:
    """The one refusal of every resolution failure; it names no cause."""
    return GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)


@dataclass(frozen=True)
class CredentialIdentity:
    """The immutable row context a version's envelope is bound to (C-05)."""

    credential_id: UUID
    provider_id: UUID
    scope_type: ScopeType
    tenant_id: UUID | None = None
    owner_user_id: UUID | None = None


@dataclass(frozen=True)
class StoredVersion:
    """The version a write created and its scope-bound fingerprint."""

    version: int
    fingerprint: str
    fingerprint_key_version: str


@dataclass(frozen=True)
class KeyGenerations:
    """Rows per key generation, for ``rewrap --verify`` (D-23 step 5)."""

    kek: dict[str, int]
    fingerprint: dict[str, int]


@runtime_checkable
class CredentialStore(Protocol):
    """C-06: the only way any gateway code reaches credential material."""

    #: ``database`` or ``vault`` — the ``ai_credential.secret_backend`` value.
    backend: str

    def store(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        """Write version 1 of a new credential and make the credential active."""

    def replace(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        """Write the next version and move the pointer onto it."""

    def resolve_for_execution(
        self, credential_id: UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        """The recorded, current version of an active credential."""

    def resolve_for_cleanup(
        self, credential_id: UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        """Any version whose material still exists (D-43 cleanup only)."""

    def fingerprints(
        self, credential: CredentialIdentity, secret: SecretStr
    ) -> dict[str, str]:
        """``secret``'s fingerprint in ``credential``'s scope, per key generation."""

    def duplicate_in_scope(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> bool:
        """Whether another live credential of the scope holds ``secret`` now."""

    def delete(self, connection: Connection, credential_id: UUID) -> None:
        """Mark the credential deleted; its material stays until D-43 allows."""

    def destroy(
        self, connection: Connection, credential_id: UUID, version: int
    ) -> None:
        """Clear one version's material; the row stays as a tombstone."""

    def rewrap(self, connection: Connection) -> int:
        """Re-wrap every row under an older KEK generation; the count."""

    def refingerprint(self, connection: Connection) -> int:
        """Recompute every fingerprint under an older key; the count."""

    def generations(self, connection: Connection) -> KeyGenerations:
        """Rows per KEK and fingerprint-key generation."""

    async def health(self) -> HealthCheckResult:
        """``/health``: the store and its key provider can serve a resolution."""


__all__ = [
    "CredentialIdentity",
    "CredentialStore",
    "KeyGenerations",
    "ResolvedSecret",
    "StoredVersion",
    "credential_unavailable",
    "released",
]

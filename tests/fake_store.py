"""An in-memory :class:`CredentialStore`: the contract with no database (T21)."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from uuid import UUID

from ai_sdk_m8.schemas.management import CredentialStatus
from pydantic import SecretStr
from sqlalchemy import Connection

from ai_gateway.credentials.store import (
    CredentialIdentity,
    KeyGenerations,
    ResolvedSecret,
    StoredVersion,
    credential_unavailable,
    released,
)
from fastapi_m8 import HealthCheckResult


@dataclass
class _Row:
    identity: CredentialIdentity
    status: str = CredentialStatus.PROVISIONING.value
    current_version: int | None = None
    next_version: int = 1
    material: dict[int, bytes | None] = field(default_factory=dict)


class InMemoryCredentialStore:
    """Keeps plaintext in memory; for contract tests only."""

    backend = "memory"

    def __init__(self) -> None:
        self.rows: dict[UUID, _Row] = {}

    def register(self, identity: CredentialIdentity) -> None:
        """The provisioning row a controller inserts before ``store``."""
        self.rows[identity.credential_id] = _Row(identity)

    def _write(
        self, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        row = self.rows[credential.credential_id]
        version = row.next_version
        row.next_version += 1
        row.material[version] = secret.get_secret_value().encode()
        row.current_version = version
        fingerprint = self.fingerprints(credential, secret)["memory-0"]
        return StoredVersion(version, fingerprint, "memory-0")

    def store(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        stored = self._write(credential, secret)
        self.rows[credential.credential_id].status = CredentialStatus.ACTIVE.value
        return stored

    def replace(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        return self._write(credential, secret)

    @contextmanager
    def _resolve(
        self, credential_id: UUID, version: int, *, execution: bool
    ) -> Iterator[ResolvedSecret]:
        row = self.rows.get(credential_id)
        material = None if row is None else row.material.get(version)
        if row is None or material is None:
            raise credential_unavailable()
        if execution and (
            row.status != CredentialStatus.ACTIVE.value
            or row.current_version != version
        ):
            raise credential_unavailable()
        with released(ResolvedSecret(material)) as secret:
            yield secret

    def resolve_for_execution(
        self, credential_id: UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        return self._resolve(credential_id, version, execution=True)

    def resolve_for_cleanup(
        self, credential_id: UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        return self._resolve(credential_id, version, execution=False)

    def fingerprints(
        self, credential: CredentialIdentity, secret: SecretStr
    ) -> dict[str, str]:
        scope = (
            f"{credential.scope_type}|{credential.tenant_id}|{credential.owner_user_id}"
        )
        digest = hashlib.sha256(f"{scope}|{secret.get_secret_value()}".encode())
        return {"memory-0": digest.hexdigest()}

    def duplicate_in_scope(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> bool:
        wanted = self.fingerprints(credential, secret)["memory-0"]
        for other_id, row in self.rows.items():
            current = row.material.get(row.current_version or 0)
            if other_id == credential.credential_id or current is None:
                continue
            if row.status == CredentialStatus.DELETED.value:
                continue
            held = self.fingerprints(row.identity, SecretStr(current.decode()))[
                "memory-0"
            ]
            if held == wanted:
                return True
        return False

    def delete(self, connection: Connection, credential_id: UUID) -> None:
        self.rows[credential_id].status = CredentialStatus.DELETED.value

    def destroy(
        self, connection: Connection, credential_id: UUID, version: int
    ) -> None:
        self.rows[credential_id].material[version] = None

    def rewrap(self, connection: Connection) -> int:
        return 0

    def refingerprint(self, connection: Connection) -> int:
        return 0

    def generations(self, connection: Connection) -> KeyGenerations:
        count = sum(
            1
            for row in self.rows.values()
            for m in row.material.values()
            if m is not None
        )
        return KeyGenerations({"memory-0": count}, {"memory-0": count})

    async def health(self) -> HealthCheckResult:
        return HealthCheckResult.from_bool("credential_store", True)

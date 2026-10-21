"""
``DatabaseCredentialStore``: envelopes in ``ai_db`` (D-23, C-05, C-06).

The default backend (``database`` + ``local`` KEK) and the hardened one
(``database`` + ``vault_transit`` KEK, ``T23``) share this store; only the
:class:`~ai_gateway.credentials.kek.KekProvider` differs.

A write is one transaction: the credential row is locked
(``SELECT … FOR UPDATE``), version ``next_version`` is allocated and
``next_version`` advanced, the version row is inserted with its envelope
and scope-bound fingerprint, and the pointer moved — so two concurrent
rotations serialize into consecutive versions with the pointer on the
later one. A resolution reads exactly the requested version on its own
connection, bounded by ``AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS``, and
answers ``credential_unavailable`` for every failure: a wrong status, a
retired version, missing or destroyed material, a tampered envelope, a KEK
generation that is not configured, a slow database.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Final
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import CredentialStatus, ScopeType
from pydantic import SecretStr
from sqlalchemy import Connection, Engine, RowMapping

from fastapi_m8 import HealthCheckResult, HealthStatus

from ai_gateway.db_models.credentials import ai_credential

# Only this package may import the version table (TID251, ``ruff.toml`` here).
from ai_gateway.db_models.credential_version import ai_credential_version  # noqa: TID251

from .envelope import (
    ALGORITHM,
    Envelope,
    EnvelopeError,
    open_envelope,
    rewrapped,
    seal,
    version_aad,
)
from .fingerprints import FingerprintKeys
from .kek import KekError, KekProvider, WrappedKey
from .store import (
    CredentialIdentity,
    KeyGenerations,
    ResolvedSecret,
    StoredVersion,
    credential_unavailable,
    released,
)

logger = logging.getLogger(__name__)

_C, _V = ai_credential, ai_credential_version

#: Every column that holds a version's material (cleared on destruction).
MATERIAL_COLUMNS: Final = (
    "ciphertext",
    "nonce",
    "wrapped_dek",
    "wrap_nonce",
    "algorithm",
    "kek_provider",
    "kek_key_id",
    "kek_key_version",
    "fingerprint",
    "fingerprint_key_version",
)

#: Rows re-wrapped or re-fingerprinted per transaction.
BATCH: Final = 100


class KeyCoverageError(RuntimeError):
    """Stored rows need a key generation this replica does not hold."""


def identity_of(row: RowMapping | dict[str, Any]) -> CredentialIdentity:
    """The C-05 context of a credential row (or of a joined version row)."""
    return CredentialIdentity(
        credential_id=row["credential_id"] if "credential_id" in row else row["id"],
        provider_id=row["provider_id"],
        scope_type=ScopeType(row["scope_type"]),
        tenant_id=row["tenant_id"],
        owner_user_id=row["owner_user_id"],
    )


def _envelope(row: RowMapping) -> Envelope:
    wrapped = WrappedKey(
        row["wrapped_dek"], row["wrap_nonce"], row["kek_key_id"], row["kek_key_version"]
    )
    return Envelope(row["ciphertext"], row["nonce"], wrapped, row["kek_provider"])


def _live_material() -> sa.ColumnElement[bool]:
    return sa.and_(
        _V.c.ciphertext.is_not(None),
        _V.c.material_committed_at.is_not(None),
        _V.c.material_destroyed_at.is_(None),
        _V.c.material_lost_at.is_(None),
        _V.c.aborted_at.is_(None),
    )


def _versions_with_context() -> sa.Select[Any]:
    return sa.select(
        _V,
        _C.c.provider_id,
        _C.c.scope_type,
        _C.c.tenant_id,
        _C.c.owner_user_id,
        _C.c.status,
        _C.c.current_version,
    ).join(_C, _C.c.id == _V.c.credential_id)


class DatabaseCredentialStore:
    """Envelope-encrypted versions in ``ai_db``."""

    backend = "database"

    def __init__(
        self,
        engine: Engine,
        kek: KekProvider,
        fingerprint_keys: FingerprintKeys,
        *,
        resolve_timeout_seconds: float,
    ) -> None:
        self._engine = engine
        self._kek = kek
        self._fingerprints = fingerprint_keys
        self._timeout_ms = max(1, int(resolve_timeout_seconds * 1000))

    def __repr__(self) -> str:
        return f"DatabaseCredentialStore(kek={self._kek!r})"

    @property
    def kek_version(self) -> str:
        """The KEK generation new versions are wrapped under."""
        return self._kek.active_version

    @property
    def fingerprint_version(self) -> str:
        """The fingerprint-key generation new versions use."""
        return self._fingerprints.active_version

    # --- writes ------------------------------------------------------------

    def _write(
        self,
        connection: Connection,
        credential_id: UUID,
        secret: SecretStr,
        *,
        activate: bool,
    ) -> StoredVersion:
        row = (
            connection.execute(
                sa.select(_C).where(_C.c.id == credential_id).with_for_update()
            )
            .mappings()
            .one()
        )
        version = row["next_version"]
        connection.execute(
            sa.update(_C)
            .where(_C.c.id == credential_id)
            .values(next_version=version + 1)
        )
        fingerprint = self._insert_version(connection, row, version, secret)
        pointer: dict[str, object] = {
            "current_version": version,
            "updated_at": sa.func.now(),
        }
        if activate:
            pointer["status"] = CredentialStatus.ACTIVE.value
        connection.execute(
            sa.update(_C).where(_C.c.id == credential_id).values(**pointer)
        )
        return StoredVersion(version, fingerprint, self._fingerprints.active_version)

    def _insert_version(
        self, connection: Connection, row: RowMapping, version: int, secret: SecretStr
    ) -> str:
        """Insert ``version``'s envelope; its scope-bound fingerprint."""
        identity = identity_of(row)
        plaintext = secret.get_secret_value().encode("utf-8")
        try:
            envelope = seal(plaintext, version_aad(identity, version), self._kek)
        except KekError:
            # A KEK outage (Vault unreachable) refuses the write; never a fallback.
            raise credential_unavailable() from None
        fingerprint = self._fingerprints.compute(identity, plaintext)
        connection.execute(
            sa.insert(_V).values(
                credential_id=row["id"],
                version=version,
                ciphertext=envelope.ciphertext,
                nonce=envelope.nonce,
                wrapped_dek=envelope.wrapped.wrapped_dek,
                wrap_nonce=envelope.wrapped.wrap_nonce,
                algorithm=ALGORITHM,
                kek_provider=envelope.kek_provider,
                kek_key_id=envelope.wrapped.key_id,
                kek_key_version=envelope.wrapped.key_version,
                fingerprint=fingerprint,
                fingerprint_key_version=self._fingerprints.active_version,
                prepare_id=secrets.token_hex(16),
                base_version=row["current_version"],
                material_committed_at=sa.func.now(),
            )
        )
        return fingerprint

    def store(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        """Version 1 of a provisioning credential; the credential becomes active."""
        return self._write(connection, credential.credential_id, secret, activate=True)

    def replace(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> StoredVersion:
        """The next version; the previous one stays decryptable as retired."""
        return self._write(connection, credential.credential_id, secret, activate=False)

    def fingerprints(
        self, credential: CredentialIdentity, secret: SecretStr
    ) -> dict[str, str]:
        """``secret``'s fingerprint in the scope, per configured generation."""
        return self._fingerprints.all(
            credential, secret.get_secret_value().encode("utf-8")
        )

    def duplicate_in_scope(
        self, connection: Connection, credential: CredentialIdentity, secret: SecretStr
    ) -> bool:
        """
        Whether another non-deleted credential of the same scope holds ``secret``
        as its current version.

        Fingerprints are scope-bound, so only this scope's rows can match; the
        check compares under every configured fingerprint generation.
        """
        candidates = self.fingerprints(credential, secret)
        match = sa.or_(
            *(
                sa.and_(
                    _V.c.fingerprint_key_version == version, _V.c.fingerprint == value
                )
                for version, value in candidates.items()
            )
        )
        scope = sa.and_(
            _C.c.scope_type == credential.scope_type.value,
            _C.c.tenant_id.is_not_distinct_from(credential.tenant_id),
            _C.c.owner_user_id.is_not_distinct_from(credential.owner_user_id),
        )
        statement = (
            sa.select(_V.c.credential_id)
            .join(
                _C,
                sa.and_(
                    _C.c.id == _V.c.credential_id, _C.c.current_version == _V.c.version
                ),
            )
            .where(
                scope,
                match,
                _C.c.id != credential.credential_id,
                _C.c.status != CredentialStatus.DELETED.value,
            )
            .limit(1)
        )
        return connection.execute(statement).first() is not None

    def delete(self, connection: Connection, credential_id: UUID) -> None:
        """Logical deletion; the material stays until D-43 allows destruction."""
        connection.execute(
            sa.update(_C)
            .where(
                _C.c.id == credential_id, _C.c.status != CredentialStatus.DELETED.value
            )
            .values(
                status=CredentialStatus.DELETED.value,
                deleted_at=sa.func.now(),
                updated_at=sa.func.now(),
            )
        )

    def destroy(
        self, connection: Connection, credential_id: UUID, version: int
    ) -> None:
        """Clear one version's material; the schema refuses it while needed."""
        connection.execute(
            sa.update(_V)
            .where(
                _V.c.credential_id == credential_id,
                _V.c.version == version,
                _V.c.material_destroyed_at.is_(None),
            )
            .values(
                **{column: None for column in MATERIAL_COLUMNS},
                material_destroyed_at=sa.func.now(),
            )
        )

    # --- resolution -----------------------------------------------------------

    @contextmanager
    def _resolve(
        self, credential_id: UUID, version: int, *, execution: bool
    ) -> Iterator[ResolvedSecret]:
        try:
            plaintext = self._decrypt(credential_id, version, execution=execution)
        except (sa.exc.SQLAlchemyError, EnvelopeError, LookupError) as exc:
            logger.warning(
                "credential.resolution_refused reason=%s execution=%s",
                type(exc).__name__,
                execution,
            )
            raise credential_unavailable() from None
        with released(ResolvedSecret(plaintext)) as secret:
            plaintext[:] = bytes(len(plaintext))
            yield secret

    def _decrypt(
        self, credential_id: UUID, version: int, *, execution: bool
    ) -> bytearray:
        statement = _versions_with_context().where(
            _V.c.credential_id == credential_id,
            _V.c.version == version,
            _live_material(),
        )
        if execution:
            statement = statement.where(
                _C.c.status == CredentialStatus.ACTIVE.value,
                _C.c.current_version == version,
            )
        with self._engine.begin() as connection:
            connection.execute(
                sa.select(
                    sa.func.set_config("statement_timeout", str(self._timeout_ms), True)
                )
            )
            row = connection.execute(statement).mappings().first()
        if row is None:
            raise LookupError("no resolvable version")
        aad = version_aad(identity_of(row), version)
        return open_envelope(_envelope(row), aad, self._kek)

    def resolve_for_execution(
        self, credential_id: UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        """The recorded, current version of an active credential."""
        return self._resolve(credential_id, version, execution=True)

    def resolve_for_cleanup(
        self, credential_id: UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        """Any version whose material still exists (D-43 cleanup only)."""
        return self._resolve(credential_id, version, execution=False)

    # --- key rotation (D-23) --------------------------------------------------

    def _stale(
        self, connection: Connection, column: sa.Column[Any], active: str
    ) -> list[RowMapping]:
        return list(
            connection.execute(
                _versions_with_context()
                .where(
                    _V.c.ciphertext.is_not(None), column.is_not(None), column != active
                )
                .order_by(_V.c.credential_id, _V.c.version)
                .limit(BATCH)
                .with_for_update(of=_V)
            ).mappings()
        )

    def rewrap(self, connection: Connection) -> int:
        """Re-wrap every DEK under an older KEK generation; ciphertext untouched."""
        count = 0
        while rows := self._stale(
            connection, _V.c.kek_key_version, self._kek.active_version
        ):
            for row in rows:
                aad = version_aad(identity_of(row), row["version"])
                wrapped = rewrapped(_envelope(row), aad, self._kek)
                connection.execute(
                    sa.update(_V)
                    .where(
                        _V.c.credential_id == row["credential_id"],
                        _V.c.version == row["version"],
                    )
                    .values(
                        wrapped_dek=wrapped.wrapped_dek,
                        wrap_nonce=wrapped.wrap_nonce,
                        kek_provider=self._kek.provider,
                        kek_key_id=wrapped.key_id,
                        kek_key_version=wrapped.key_version,
                    )
                )
            count += len(rows)
        return count

    def refingerprint(self, connection: Connection) -> int:
        """Recompute every fingerprint under an older key from the plaintext."""
        count = 0
        column = _V.c.fingerprint_key_version
        while rows := self._stale(
            connection, column, self._fingerprints.active_version
        ):
            for row in rows:
                identity = identity_of(row)
                aad = version_aad(identity, row["version"])
                plaintext = open_envelope(_envelope(row), aad, self._kek)
                try:
                    fingerprint = self._fingerprints.compute(identity, bytes(plaintext))
                finally:
                    plaintext[:] = bytes(len(plaintext))
                connection.execute(
                    sa.update(_V)
                    .where(
                        _V.c.credential_id == row["credential_id"],
                        _V.c.version == row["version"],
                    )
                    .values(
                        fingerprint=fingerprint,
                        fingerprint_key_version=self._fingerprints.active_version,
                    )
                )
            count += len(rows)
        return count

    def generations(self, connection: Connection) -> KeyGenerations:
        """Rows per KEK and fingerprint-key generation, material rows only."""

        def counts(column: sa.Column[Any]) -> dict[str, int]:
            rows = connection.execute(
                sa.select(column, sa.func.count())
                .where(_V.c.ciphertext.is_not(None), column.is_not(None))
                .group_by(column)
            )
            return {str(value): int(count) for value, count in rows}

        return KeyGenerations(
            counts(_V.c.kek_key_version), counts(_V.c.fingerprint_key_version)
        )

    def check_coverage(self, connection: Connection) -> None:
        """Refuse to run while a stored row needs a generation not configured."""
        held = self.generations(connection)
        missing_kek = sorted(v for v in held.kek if not self._kek.covers(v))
        missing_fp = sorted(set(held.fingerprint) - self._fingerprints.generations())
        if missing_kek or missing_fp:
            raise KeyCoverageError(
                "stored credential versions need key generations this replica "
                f"does not hold: kek={missing_kek} fingerprint={missing_fp}"
            )

    async def health(self) -> HealthCheckResult:
        """The KEK probe: this replica can wrap and unwrap under its active key."""
        try:
            self._kek.probe()
        except KekError as exc:
            return HealthCheckResult(
                name="credential_store",
                status=HealthStatus.FAIL,
                error=type(exc).__name__,
            )
        return HealthCheckResult(
            name="credential_store",
            status=HealthStatus.OK,
            meta={"backend": self.backend, "kek_provider": self._kek.provider},
        )


__all__ = [
    "BATCH",
    "MATERIAL_COLUMNS",
    "DatabaseCredentialStore",
    "KeyCoverageError",
    "identity_of",
]

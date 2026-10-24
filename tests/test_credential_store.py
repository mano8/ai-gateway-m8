"""
The C-06 contract, run against every credential-store backend (T21).

Each backend joins :data:`BACKENDS`; every test below runs against each of
them, so the resolution rules — exactly the recorded version, only while the
credential is ``active`` and that version current, a separate cleanup path for
retired versions — hold identically on every backend.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass

import pytest
from ai_sdk_m8.schemas import AiErrorCode
from ai_sdk_m8.schemas.management import ScopeType
from pydantic import SecretStr
from sqlalchemy import Connection

from ai_gateway.core import deps
from ai_gateway.core.errors import GatewayError
from ai_gateway.credentials.store import (
    CredentialIdentity,
    CredentialStore,
    ResolvedSecret,
    released,
)
from fake_store import InMemoryCredentialStore
from sqlalchemy import insert, update

from ai_gateway.db_models.credentials import ai_credential
import factories

FIRST = SecretStr("sk-first-0123456789abcdefghijklmnop")
SECOND = SecretStr("sk-second-0123456789abcdefghijklmno")


@dataclass
class Backend:
    """One backend under the contract, with the controller's side of it."""

    store: CredentialStore
    new_credential: Callable[[], CredentialIdentity]
    transaction: Callable[[], AbstractContextManager[Connection]]
    set_status: Callable[[uuid.UUID, str], None]


def _memory() -> Backend:
    store = InMemoryCredentialStore()

    def new_credential() -> CredentialIdentity:
        identity = CredentialIdentity(uuid.uuid4(), uuid.uuid4(), ScopeType.GLOBAL)
        store.register(identity)
        return identity

    def set_status(credential_id: uuid.UUID, status: str) -> None:
        store.rows[credential_id].status = status

    return Backend(store, new_credential, lambda: nullcontext(None), set_status)  # type: ignore[arg-type]


def provisioning_credential(
    scope_type: ScopeType = ScopeType.TENANT,
) -> CredentialIdentity:
    """The provisioning row a controller inserts before ``store``."""
    tenant = uuid.uuid4() if scope_type is not ScopeType.GLOBAL else None
    owner = uuid.uuid4() if scope_type is ScopeType.USER else None
    credential_id = uuid.uuid4()
    with deps.db_engine.begin() as connection:
        provider_id = factories.provider(connection)
        connection.execute(
            insert(ai_credential).values(
                id=credential_id,
                scope_type=scope_type.value,
                tenant_id=tenant,
                owner_user_id=owner,
                provider_id=provider_id,
                name="key",
                status="provisioning",
                secret_backend="database",
            )
        )
    return CredentialIdentity(credential_id, provider_id, scope_type, tenant, owner)


def _database() -> Backend:
    def set_status(credential_id: uuid.UUID, status: str) -> None:
        with deps.db_engine.begin() as connection:
            connection.execute(
                update(ai_credential)
                .where(ai_credential.c.id == credential_id)
                .values(status=status)
            )

    return Backend(
        deps.credential_store,
        provisioning_credential,
        deps.db_engine.begin,
        set_status,
    )


#: Every backend the contract runs against.
BACKENDS: dict[str, Callable[[], Backend]] = {
    "memory": _memory,
    "database+local": _database,
}


@pytest.fixture(params=sorted(BACKENDS))
def backend(request: pytest.FixtureRequest) -> Iterator[Backend]:
    yield BACKENDS[request.param]()


def _stored(backend: Backend, *secrets: SecretStr) -> CredentialIdentity:
    identity = backend.new_credential()
    with backend.transaction() as connection:
        backend.store.store(connection, identity, secrets[0])
    for secret in secrets[1:]:
        with backend.transaction() as connection:
            backend.store.replace(connection, identity, secret)
    return identity


def _unavailable(context: AbstractContextManager[ResolvedSecret]) -> None:
    with pytest.raises(GatewayError) as refused:
        with context:
            pass  # pragma: no cover - the context refuses on entry
    assert refused.value.code is AiErrorCode.CREDENTIAL_UNAVAILABLE


def test_the_backend_implements_the_protocol(backend: Backend) -> None:
    assert isinstance(backend.store, CredentialStore)


def test_a_stored_credential_resolves_its_current_version(backend: Backend) -> None:
    identity = _stored(backend, FIRST)
    with backend.store.resolve_for_execution(identity.credential_id, 1) as secret:
        assert secret.reveal() == FIRST.get_secret_value()
        assert FIRST.get_secret_value() not in repr(secret)
        assert FIRST.get_secret_value() not in str(secret)
    with pytest.raises(ValueError, match="released"):
        secret.reveal()


def test_a_retired_version_resolves_for_cleanup_only(backend: Backend) -> None:
    identity = _stored(backend, FIRST, SECOND)
    _unavailable(backend.store.resolve_for_execution(identity.credential_id, 1))
    with backend.store.resolve_for_cleanup(identity.credential_id, 1) as old:
        assert old.reveal() == FIRST.get_secret_value()
    with backend.store.resolve_for_execution(identity.credential_id, 2) as current:
        assert current.reveal() == SECOND.get_secret_value()


@pytest.mark.parametrize(
    "status", ["disabled", "invalid", "reconfirm_required", "reprovision_required"]
)
def test_a_credential_that_is_not_active_resolves_for_cleanup_only(
    backend: Backend, status: str
) -> None:
    identity = _stored(backend, FIRST)
    backend.set_status(identity.credential_id, status)
    _unavailable(backend.store.resolve_for_execution(identity.credential_id, 1))
    with backend.store.resolve_for_cleanup(identity.credential_id, 1) as secret:
        assert secret.reveal() == FIRST.get_secret_value()


def test_a_deleted_credential_keeps_its_material_for_cleanup(backend: Backend) -> None:
    identity = _stored(backend, FIRST)
    with backend.transaction() as connection:
        backend.store.delete(connection, identity.credential_id)
    _unavailable(backend.store.resolve_for_execution(identity.credential_id, 1))
    with backend.store.resolve_for_cleanup(identity.credential_id, 1) as secret:
        assert secret.reveal() == FIRST.get_secret_value()


def test_a_destroyed_version_resolves_nowhere(backend: Backend) -> None:
    identity = _stored(backend, FIRST, SECOND)
    with backend.transaction() as connection:
        backend.store.destroy(connection, identity.credential_id, 1)
    _unavailable(backend.store.resolve_for_cleanup(identity.credential_id, 1))
    _unavailable(backend.store.resolve_for_execution(identity.credential_id, 1))
    with backend.store.resolve_for_execution(identity.credential_id, 2) as secret:
        assert secret.reveal() == SECOND.get_secret_value()


def test_unknown_credentials_and_versions_are_unavailable(backend: Backend) -> None:
    identity = _stored(backend, FIRST)
    _unavailable(backend.store.resolve_for_execution(uuid.uuid4(), 1))
    _unavailable(backend.store.resolve_for_cleanup(uuid.uuid4(), 1))
    _unavailable(backend.store.resolve_for_execution(identity.credential_id, 7))
    _unavailable(backend.store.resolve_for_cleanup(identity.credential_id, 7))


def test_fingerprints_are_scope_bound(backend: Backend) -> None:
    identity = backend.new_credential()
    other = CredentialIdentity(
        uuid.uuid4(), identity.provider_id, ScopeType.TENANT, tenant_id=uuid.uuid4()
    )
    mine = backend.store.fingerprints(identity, FIRST)
    assert mine == backend.store.fingerprints(identity, FIRST)
    assert set(mine.values()).isdisjoint(
        backend.store.fingerprints(other, FIRST).values()
    )
    assert mine != backend.store.fingerprints(identity, SECOND)


def test_the_health_contract(backend: Backend) -> None:
    import asyncio

    result = asyncio.run(backend.store.health())
    assert (result.name, result.status) == ("credential_store", "ok")


# --- ResolvedSecret ------------------------------------------------------------


def test_a_resolved_secret_is_wiped_even_when_the_block_raises() -> None:
    secret = ResolvedSecret(b"canary-secret")
    with pytest.raises(RuntimeError):
        with released(secret):
            raise RuntimeError("provider call failed")
    with pytest.raises(ValueError):
        secret.reveal()
    assert repr(secret) == str(secret) == "ResolvedSecret(<redacted>)"

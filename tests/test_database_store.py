"""
``DatabaseCredentialStore`` + ``LocalKekProvider`` (T22, D-23, S-01).

The contract rows run in ``test_credential_store.py``; these are the
backend's own: the envelope and its AAD, tampering, the D-23 rolling KEK and
fingerprint-key rotations across two replicas, start-up coverage, a
database dump, disclosure in logs and exceptions, concurrent rotations,
destruction, the resolve timeout, health and the rotation commands.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from ai_sdk_m8.schemas import AiErrorCode
from ai_sdk_m8.schemas.management import ScopeType
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

import pg_harness as pg
from ai_gateway import main, prestart
from ai_gateway.core import deps
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.keyfiles import KeyMaterial
from ai_gateway.credentials import __main__ as cli
from ai_gateway.credentials.database import (
    MATERIAL_COLUMNS,
    DatabaseCredentialStore,
    KeyCoverageError,
)
from ai_gateway.credentials.envelope import (
    Envelope,
    EnvelopeError,
    length_prefixed,
    open_envelope,
    rewrapped,
    version_aad,
)
from ai_gateway.credentials.factory import (
    UnsupportedBackendError,
    build_credential_store,
)
from ai_gateway.credentials.fingerprints import FingerprintKeys
from ai_gateway.credentials.kek import KekError, LocalKekProvider, WrappedKey
from ai_gateway.credentials.store import CredentialIdentity
from ai_gateway.db_models.audit import ai_admin_audit
from ai_gateway.db_models.credential_version import ai_credential_version
from ai_gateway.db_models.credentials import ai_credential
from test_credential_store import provisioning_credential

pytestmark = pytest.mark.usefixtures("clean_db")

CANARY = "sk-canary-" + "Zq7" * 12


def key(name: str = "key") -> KeyMaterial:
    return KeyMaterial(secrets.token_bytes(32), Path(f"/run/secrets/{name}"))


FINGERPRINT = key("fingerprint")


def make_store(
    active: KeyMaterial,
    *previous: KeyMaterial,
    fingerprint: KeyMaterial = FINGERPRINT,
    previous_fingerprint: KeyMaterial | None = None,
    timeout: float = 5.0,
) -> DatabaseCredentialStore:
    return DatabaseCredentialStore(
        deps.db_engine,
        LocalKekProvider(active, previous),
        FingerprintKeys(fingerprint, previous_fingerprint),
        resolve_timeout_seconds=timeout,
    )


def stored(store: DatabaseCredentialStore, secret: str = CANARY) -> CredentialIdentity:
    identity = provisioning_credential()
    with deps.db_engine.begin() as connection:
        store.store(connection, identity, SecretStr(secret))
    return identity


def resolve(
    store: DatabaseCredentialStore, identity: CredentialIdentity, version: int = 1
) -> str:
    with store.resolve_for_execution(identity.credential_id, version) as secret:
        return secret.reveal()


def refused(
    store: DatabaseCredentialStore, identity: CredentialIdentity, version: int = 1
) -> None:
    for resolver in (store.resolve_for_execution, store.resolve_for_cleanup):
        with pytest.raises(GatewayError) as error:
            with resolver(identity.credential_id, version):
                pass  # pragma: no cover - refused on entry
        assert error.value.code is AiErrorCode.CREDENTIAL_UNAVAILABLE


def version_row(identity: CredentialIdentity, version: int = 1) -> dict[str, object]:
    with deps.db_engine.connect() as connection:
        row = (
            connection.execute(
                select(ai_credential_version).where(
                    ai_credential_version.c.credential_id == identity.credential_id,
                    ai_credential_version.c.version == version,
                )
            )
            .mappings()
            .one()
        )
    return dict(row)


def tamper(statement: str, **params: object) -> None:
    """Change a row as the database superuser, with every trigger bypassed."""
    engine = pg.admin_engine(pg.DB_NAME)
    try:
        with engine.connect() as connection:
            connection.execute(text("SET session_replication_role = replica"))
            connection.execute(text(statement), params)
    finally:
        engine.dispose()


@pytest.fixture
def store() -> DatabaseCredentialStore:
    return make_store(key("kek"))


# --- the envelope --------------------------------------------------------------


def test_the_aad_is_length_prefixed_and_unambiguous() -> None:
    assert length_prefixed("ab", "c") != length_prefixed("a", "bc")
    assert length_prefixed(None, "x") == b"\x00\x00\x00\x00\x00\x00\x00\x01x"
    credential = CredentialIdentity(
        uuid.UUID(int=1), uuid.UUID(int=2), ScopeType.TENANT, tenant_id=uuid.UUID(int=3)
    )
    fields = [
        str(uuid.UUID(int=1)),
        "4",
        str(uuid.UUID(int=2)),
        "tenant",
        str(uuid.UUID(int=3)),
    ]
    expected = b"".join(len(f).to_bytes(4, "big") + f.encode() for f in fields) + bytes(
        4
    )
    assert version_aad(credential, 4) == expected


def test_a_stored_version_is_an_envelope(store: DatabaseCredentialStore) -> None:
    identity = stored(store)
    row = version_row(identity)
    assert CANARY.encode() not in row["ciphertext"]  # type: ignore[operator]
    assert len(row["nonce"]) == len(row["wrap_nonce"]) == 12  # type: ignore[arg-type]
    assert (row["algorithm"], row["kek_provider"], row["kek_key_id"]) == (
        "AES-256-GCM",
        "local",
        "local",
    )
    assert row["kek_key_version"] == store.kek_version
    assert row["fingerprint_key_version"] == store.fingerprint_version
    assert row["material_committed_at"] is not None and row["base_version"] is None
    with deps.db_engine.connect() as connection:
        credential = (
            connection.execute(
                select(ai_credential).where(
                    ai_credential.c.id == identity.credential_id
                )
            )
            .mappings()
            .one()
        )
    assert (
        credential["status"],
        credential["current_version"],
        credential["next_version"],
    ) == (
        "active",
        1,
        2,
    )
    assert resolve(store, identity) == CANARY


def test_every_version_has_its_own_dek_and_nonce(
    store: DatabaseCredentialStore,
) -> None:
    identity = stored(store)
    with deps.db_engine.begin() as connection:
        store.replace(connection, identity, SecretStr(CANARY))
    first, second = version_row(identity, 1), version_row(identity, 2)
    for column in ("ciphertext", "nonce", "wrapped_dek", "wrap_nonce"):
        assert first[column] != second[column]
    assert second["base_version"] == 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE ai_credential_version SET ciphertext = substring(ciphertext from 1 "
        "for length(ciphertext) - 1) WHERE credential_id = :a",
        "UPDATE ai_credential_version SET wrapped_dek = "
        "overlay(wrapped_dek placing '\\x00'::bytea from 1 for 1) WHERE credential_id = :a",
        "UPDATE ai_credential SET tenant_id = gen_random_uuid() WHERE id = :a",
        "UPDATE ai_credential_version SET kek_key_version = 'kek-0000000000000000' "
        "WHERE credential_id = :a",
        "UPDATE ai_credential_version SET kek_provider = 'vault_transit' "
        "WHERE credential_id = :a",
        "UPDATE ai_credential_version a SET ciphertext = b.ciphertext, nonce = b.nonce, "
        "wrapped_dek = b.wrapped_dek, wrap_nonce = b.wrap_nonce "
        "FROM ai_credential_version b WHERE a.credential_id = :a AND b.credential_id = :b",
    ],
    ids=[
        "truncated-tag",
        "wrapped-dek",
        "aad-context",
        "unknown-kek",
        "other-provider",
        "swapped-rows",
    ],
)
def test_a_tampered_row_is_unavailable_never_partial(
    store: DatabaseCredentialStore, statement: str
) -> None:
    victim, other = stored(store), stored(store, "sk-other-" + "x" * 30)
    tamper(statement, a=victim.credential_id, b=other.credential_id)
    refused(store, victim)
    assert resolve(store, other) == "sk-other-" + "x" * 30


def test_the_kek_rejects_a_row_without_its_wrap_nonce() -> None:
    kek = LocalKekProvider(key())
    wrapped = kek.wrap(b"d" * 32, b"aad")
    with pytest.raises(KekError):
        kek.unwrap(
            WrappedKey(wrapped.wrapped_dek, None, "local", wrapped.key_version), b"aad"
        )
    envelope = Envelope(b"c", b"n" * 12, wrapped, "local")
    with pytest.raises(EnvelopeError):
        rewrapped(envelope, b"aad", LocalKekProvider(key()))
    with pytest.raises(EnvelopeError):
        open_envelope(envelope, b"other-aad", kek)


# --- D-23 rotations ------------------------------------------------------------


def test_a_rolling_kek_rotation_across_two_replicas_loses_nothing() -> None:
    old, new = key("kek-old"), key("kek-new")
    a = b = make_store(old)
    first = stored(a, "sk-first-" + "1" * 30)
    # (1) the new key is deployed decrypt-only to every replica.
    a, b = make_store(old, new), make_store(old, new)
    second = stored(b, "sk-second-" + "2" * 30)
    # (2) the active key switches replica by replica; writes continue.
    a = make_store(new, old)
    third = stored(a, "sk-third-" + "3" * 30)
    fourth = stored(b, "sk-fourth-" + "4" * 30)
    b = make_store(new, old)
    expected = {first: "1", second: "2", third: "3", fourth: "4"}
    for replica in (a, b):
        for identity, digit in expected.items():
            assert resolve(replica, identity).endswith(digit * 30)
    with deps.db_engine.connect() as connection:
        before = a.generations(connection).kek
        # Removing the old key now refuses to start, naming the generation.
        with pytest.raises(KeyCoverageError, match=old.version("kek")):
            make_store(new).check_coverage(connection)
    assert before == {old.version("kek"): 3, new.version("kek"): 1}
    # (4) rewrap, (5) verify zero old-generation rows.
    with deps.db_engine.begin() as connection:
        assert a.rewrap(connection) == 3
    with deps.db_engine.connect() as connection:
        assert a.generations(connection).kek == {new.version("kek"): 4}
        # (6) the old key leaves the deployment; nothing is lost.
        make_store(new).check_coverage(connection)
    for identity, digit in expected.items():
        assert resolve(make_store(new), identity).endswith(digit * 30)


def test_rewrap_leaves_the_ciphertext_untouched() -> None:
    old, new = key("kek-old"), key("kek-new")
    identity = stored(make_store(old))
    before = version_row(identity)
    with deps.db_engine.begin() as connection:
        make_store(new, old).rewrap(connection)
    after = version_row(identity)
    assert (after["ciphertext"], after["nonce"]) == (
        before["ciphertext"],
        before["nonce"],
    )
    assert after["wrapped_dek"] != before["wrapped_dek"]


def test_a_fingerprint_key_rotation_moves_every_row() -> None:
    kek, old, new = key("kek"), key("fp-old"), key("fp-new")
    identity = stored(make_store(kek, fingerprint=old))
    rotating = make_store(kek, fingerprint=new, previous_fingerprint=old)
    # During the overlap the stored fingerprint still matches.
    candidates = rotating.fingerprints(identity, SecretStr(CANARY))
    assert (
        version_row(identity)["fingerprint"] == candidates[old.version("fingerprint")]
    )
    with deps.db_engine.connect() as connection:
        with pytest.raises(KeyCoverageError, match=old.version("fingerprint")):
            make_store(kek, fingerprint=new).check_coverage(connection)
    with deps.db_engine.begin() as connection:
        assert rotating.refingerprint(connection) == 1
    row = version_row(identity)
    assert row["fingerprint_key_version"] == new.version("fingerprint")
    assert row["fingerprint"] == candidates[new.version("fingerprint")]
    with deps.db_engine.connect() as connection:
        make_store(kek, fingerprint=new).check_coverage(connection)


# --- disclosure ----------------------------------------------------------------


def _dump() -> str:
    engine = pg.owner_engine()
    try:
        with engine.connect() as connection:
            tables = connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            ).scalars()
            return "\n".join(
                row
                for name in list(tables)
                for row in connection.execute(
                    text(f"SELECT row_to_json(t)::text FROM {name} t")  # noqa: S608 - catalog names
                ).scalars()
            )
    finally:
        engine.dispose()


def _forms(value: bytes) -> list[str]:
    return [
        value.decode("latin-1"),
        value.hex(),
        base64.b64encode(value).decode(),
        base64.urlsafe_b64encode(value).decode().rstrip("="),
    ]


def test_a_database_dump_holds_ciphertext_only() -> None:
    kek = key("kek")
    store = make_store(kek)
    identity = stored(store)
    with deps.db_engine.begin() as connection:
        store.replace(connection, identity, SecretStr(CANARY + "-2"))
    dump = _dump()
    assert version_row(identity, 2)["ciphertext"]
    for value in (CANARY.encode(), kek.reveal(), FINGERPRINT.reveal()):
        for form in _forms(value):
            assert form not in dump


def _check_coverage(store: DatabaseCredentialStore) -> None:
    with deps.db_engine.connect() as connection:
        store.check_coverage(connection)


def test_neither_the_kek_nor_the_secret_reaches_a_log_or_an_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    kek = key("kek")
    store = make_store(kek)
    identity = stored(store)
    resolve(store, identity)
    texts = [repr(store), str(store), repr(kek), repr(LocalKekProvider(kek))]
    texts.append(repr(FingerprintKeys(FINGERPRINT)))
    tamper(
        "UPDATE ai_credential_version SET kek_key_version = 'kek-x' WHERE credential_id = :a",
        a=identity.credential_id,
    )
    for attempt in (
        lambda: resolve(store, identity),
        lambda: _check_coverage(store),
        lambda: LocalKekProvider(key()).unwrap(
            LocalKekProvider(kek).wrap(b"d" * 32, b"a"), b"a"
        ),
    ):
        try:
            attempt()
        except Exception as exc:  # noqa: BLE001 - every failure path is inspected
            texts += [str(exc), repr(exc)]
    texts.append(caplog.text)
    joined = "\n".join(texts)
    assert "resolution_refused" in caplog.text
    for value in (CANARY.encode(), kek.reveal(), FINGERPRINT.reveal()):
        for form in _forms(value):
            assert form not in joined


# --- concurrency, destruction, timeout ------------------------------------------


def test_two_concurrent_rotations_serialize_into_consecutive_versions(
    store: DatabaseCredentialStore,
) -> None:
    identity = stored(store)
    barrier = threading.Barrier(2)

    def rotate(secret: str) -> int:
        barrier.wait()
        with deps.db_engine.begin() as connection:
            return store.replace(connection, identity, SecretStr(secret)).version

    with_versions: list[int] = []
    threads = [
        threading.Thread(target=lambda s=s: with_versions.append(rotate(s)))
        for s in ("sk-a-" + "a" * 30, "sk-b-" + "b" * 30)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(with_versions) == [2, 3]
    with deps.db_engine.connect() as connection:
        current = connection.execute(
            select(ai_credential.c.current_version).where(
                ai_credential.c.id == identity.credential_id
            )
        ).scalar_one()
    assert current == 3
    assert resolve(store, identity, 3).startswith(("sk-a-", "sk-b-"))


def test_destroying_a_version_clears_its_material_and_keeps_the_row(
    store: DatabaseCredentialStore,
) -> None:
    identity = stored(store)
    old_ciphertext = version_row(identity)["ciphertext"]
    assert isinstance(old_ciphertext, bytes)
    with deps.db_engine.begin() as connection:
        store.replace(connection, identity, SecretStr(CANARY + "-2"))
    with deps.db_engine.begin() as connection:
        store.destroy(connection, identity.credential_id, 1)
    row = version_row(identity)
    assert all(row[column] is None for column in MATERIAL_COLUMNS)
    assert row["material_destroyed_at"] is not None
    assert old_ciphertext.hex() not in _dump()
    refused(store, identity)
    # The current version of a live credential cannot be destroyed.
    with pytest.raises(IntegrityError):
        with deps.db_engine.begin() as connection:
            store.destroy(connection, identity.credential_id, 2)


def test_a_slow_database_is_unavailable_within_the_resolve_timeout() -> None:
    store = make_store(key("kek"), timeout=0.3)
    identity = stored(store)
    engine = pg.owner_engine()
    try:
        with engine.connect() as holder:
            transaction = holder.begin()
            holder.execute(
                text("LOCK TABLE ai_credential_version IN ACCESS EXCLUSIVE MODE")
            )
            started = time.monotonic()
            refused(store, identity)
            elapsed = time.monotonic() - started
            transaction.rollback()
    finally:
        engine.dispose()
    assert elapsed < 5
    assert resolve(store, identity) == CANARY


# --- health, start-up, construction -----------------------------------------------


class _BrokenKek(LocalKekProvider):
    def probe(self) -> None:
        raise KekError("the KEK probe did not round-trip")


def test_health_reports_the_kek_probe() -> None:
    healthy = asyncio.run(make_store(key()).health())
    assert (healthy.name, healthy.status) == ("credential_store", "ok")
    assert healthy.meta == {"backend": "database", "kek_provider": "local"}
    broken = DatabaseCredentialStore(
        deps.db_engine,
        _BrokenKek(key()),
        FingerprintKeys(key()),
        resolve_timeout_seconds=1,
    )
    result = asyncio.run(broken.health())
    assert (result.status, result.error) == ("fail", "KekError")


def test_start_up_refuses_a_missing_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    stored(make_store(key("kek-elsewhere")))
    with pytest.raises(KeyCoverageError):
        asyncio.run(main.check_credential_keys())
    assert prestart.main() == 1


def test_start_up_passes_with_every_generation_held() -> None:
    stored(deps.credential_store)
    asyncio.run(main.check_credential_keys())
    assert prestart.main() == 0


def test_only_the_database_and_local_kek_are_served() -> None:
    settings = SimpleNamespace(
        AI_CREDENTIAL_STORAGE_BACKEND="vault", AI_CREDENTIAL_KEK_PROVIDER=None
    )
    with pytest.raises(UnsupportedBackendError, match="not served"):
        build_credential_store(settings, deps.db_engine)  # type: ignore[arg-type]
    settings = SimpleNamespace(
        AI_CREDENTIAL_STORAGE_BACKEND="database",
        AI_CREDENTIAL_KEK_PROVIDER="local",
        kek=None,
        fingerprint_key=None,
    )
    with pytest.raises(UnsupportedBackendError, match="needs a KEK"):
        build_credential_store(settings, deps.db_engine)  # type: ignore[arg-type]


# --- the rotation commands ---------------------------------------------------------


def _audit_actions() -> list[str]:
    with deps.db_engine.connect() as connection:
        return list(
            connection.execute(
                select(ai_admin_audit.c.action).order_by(ai_admin_audit.c.id)
            ).scalars()
        )


def test_the_rotation_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    kek, old = key("kek-new"), key("kek-old")
    fp_new = key("fp-new")
    stored(make_store(old))
    monkeypatch.setattr(
        deps,
        "credential_store",
        make_store(kek, old, fingerprint=fp_new, previous_fingerprint=FINGERPRINT),
    )
    assert cli.main(["generations"]) == 0
    assert cli.main(["rewrap", "--verify"]) == 1
    assert cli.main(["refingerprint", "--verify"]) == 1
    assert cli.main(["rewrap"]) == 0
    assert cli.main(["rewrap", "--verify"]) == 0
    assert cli.main(["refingerprint"]) == 0
    assert cli.main(["refingerprint", "--verify"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {"rewrapped": 1} in lines and {"refingerprinted": 1} in lines
    assert lines[-1] == {
        "kek": {kek.version("kek"): 1},
        "fingerprint": {fp_new.version("fingerprint"): 1},
    }
    assert _audit_actions() == ["credentials.rewrap", "credentials.refingerprint"]

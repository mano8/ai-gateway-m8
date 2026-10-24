"""
The ``vault_transit`` KEK provider and its Vault client (T23, D-20, D-23).

A stub Vault is mounted as the session's transport adapter, so the real
``hvac`` and ``requests`` code runs and every request the gateway sends is
recorded: AppRole and token-file authentication, transit encrypt/decrypt
with associated data over AES-GCM per key version, ``lookup-self``. The live
test against ``T87``'s ``vault_transit_m8`` stack is ``T87``'s.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests
from ai_sdk_m8.schemas import AiErrorCode
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr

from ai_gateway.core import deps
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.keyfiles import KeyMaterial
from ai_gateway.credentials.database import DatabaseCredentialStore, KeyCoverageError
from ai_gateway.credentials.factory import build_credential_store
from ai_gateway.credentials.fingerprints import FingerprintKeys
from ai_gateway.credentials.kek import KekError, LocalKekProvider, WrappedKey
from ai_gateway.credentials.vault import (
    VaultAccess,
    VaultTransitKekProvider,
    vault_session,
)
from conftest import write_key_file
from test_credential_store import provisioning_credential

ADDR = "https://vault.test.invalid:8200"
SECRET_ID = "s.secret-id-" + uuid.uuid4().hex
ROLE_ID = "role-" + uuid.uuid4().hex
STATIC_TOKEN = "hvs.static-" + uuid.uuid4().hex


class StubVault(requests.adapters.BaseAdapter):
    """Just enough Vault: auth, ``lookup-self``, transit over AES-GCM."""

    def __init__(self, *, lease: int = 3600) -> None:
        super().__init__()
        self.calls: list[dict[str, Any]] = []
        self.versions: dict[int, bytes] = {1: os.urandom(32)}
        self.tokens: set[str] = {STATIC_TOKEN}
        self.lease = lease
        self.logins = 0
        self.deny_decrypt = False
        self.redirect = False
        self.no_content = False
        self.down = False

    def rotate(self) -> None:
        self.versions[max(self.versions) + 1] = os.urandom(32)

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:  # type: ignore[override]
        body = json.loads(request.body) if request.body else {}
        path = urlsplit(request.url or "").path
        self.calls.append(
            {
                "method": request.method,
                "url": request.url,
                "path": path,
                "body": body,
                **kwargs,
            }
        )
        if self.down:
            raise requests.ConnectionError("vault unreachable")
        if self.redirect:
            return self._answer(
                request, 307, None, {"Location": "https://evil.example/v1/x"}
            )
        if self.no_content:
            return self._answer(request, 204, None)
        if path == "/v1/auth/approle/login":
            return self._login(request, body)
        if request.headers.get("X-Vault-Token") not in self.tokens:
            return self._answer(request, 403, {"errors": ["permission denied"]})
        if path == "/v1/auth/token/lookup-self":
            return self._answer(request, 200, {"data": {"ttl": self.lease}})
        if path == "/v1/transit/encrypt/gateway":
            return self._encrypt(request, body)
        if path == "/v1/transit/decrypt/gateway":
            return self._decrypt(request, body)
        return self._answer(request, 403, {"errors": ["permission denied"]})

    def _login(
        self, request: requests.PreparedRequest, body: dict[str, Any]
    ) -> requests.Response:
        if (body.get("role_id"), body.get("secret_id")) != (ROLE_ID, SECRET_ID):
            return self._answer(request, 400, {"errors": ["invalid role or secret id"]})
        self.logins += 1
        token = f"hvs.approle-{self.logins}"
        self.tokens.add(token)
        return self._answer(
            request,
            200,
            {"auth": {"client_token": token, "lease_duration": self.lease}},
        )

    def _encrypt(
        self, request: requests.PreparedRequest, body: dict[str, Any]
    ) -> requests.Response:
        version = max(self.versions)
        nonce = os.urandom(12)
        aad = base64.b64decode(body["associated_data"])
        sealed = AESGCM(self.versions[version]).encrypt(
            nonce, base64.b64decode(body["plaintext"]), aad
        )
        ciphertext = f"vault:v{version}:" + base64.b64encode(nonce + sealed).decode()
        return self._answer(
            request, 200, {"data": {"ciphertext": ciphertext, "key_version": version}}
        )

    def _decrypt(
        self, request: requests.PreparedRequest, body: dict[str, Any]
    ) -> requests.Response:
        if self.deny_decrypt:
            return self._answer(request, 403, {"errors": ["permission denied"]})
        _, version, encoded = body["ciphertext"].split(":", 2)
        raw = base64.b64decode(encoded)
        aad = base64.b64decode(body["associated_data"])
        try:
            plain = AESGCM(self.versions[int(version[1:])]).decrypt(
                raw[:12], raw[12:], aad
            )
        except InvalidTag:
            return self._answer(
                request, 400, {"errors": ["cipher: message authentication failed"]}
            )
        return self._answer(
            request, 200, {"data": {"plaintext": base64.b64encode(plain).decode()}}
        )

    @staticmethod
    def _answer(
        request: requests.PreparedRequest,
        status: int,
        body: object,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        response = requests.Response()
        response.status_code = status
        response._content = b"" if body is None else json.dumps(body).encode()
        response.headers.update({"Content-Type": "application/json", **(headers or {})})
        response.request = request
        response.url = request.url or ""
        return response

    def close(self) -> None:
        pass


@pytest.fixture
def vault() -> StubVault:
    return StubVault()


def access(
    vault: StubVault,
    method: str = "approle",
    *,
    ca_file: Path | None = None,
    clock: list[float] | None = None,
    token_file: Path | None = None,
) -> VaultAccess:
    def session(ca: Path | None) -> requests.Session:
        built = vault_session(ca)
        built.mount("https://", vault)
        built.mount("http://", vault)
        return built

    ticks = clock if clock is not None else [0.0]
    return VaultAccess(
        ADDR,
        method,
        token_file=token_file or write_key_file("vault-token", STATIC_TOKEN.encode()),
        role_id_file=write_key_file("vault-role", ROLE_ID.encode()),
        secret_id_file=write_key_file("vault-secret", SECRET_ID.encode()),
        ca_file=ca_file,
        timeout_seconds=2,
        session_factory=session,
        monotonic=lambda: ticks[0],
    )


def provider(
    vault: StubVault, method: str = "approle", **kwargs: Any
) -> VaultTransitKekProvider:
    return VaultTransitKekProvider(
        access(vault, method, **kwargs), mount="transit", key="gateway"
    )


# --- wrapping ------------------------------------------------------------------


@pytest.mark.parametrize("method", ["approle", "token_file"])
def test_a_data_key_round_trips_through_transit(vault: StubVault, method: str) -> None:
    kek = provider(vault, method)
    wrapped = kek.wrap(b"d" * 32, b"aad")
    assert wrapped.wrapped_dek.startswith(b"vault:v1:")
    assert (wrapped.wrap_nonce, wrapped.key_id, wrapped.key_version) == (
        None,
        "gateway",
        "transit-v1",
    )
    assert kek.unwrap(wrapped, b"aad") == b"d" * 32
    assert kek.active_version == "transit-v1"
    encrypt = next(c for c in vault.calls if c["path"].endswith("/encrypt/gateway"))
    assert base64.b64decode(encrypt["body"]["associated_data"]) == b"aad"


def test_a_wrapped_key_never_unwraps_for_another_row(vault: StubVault) -> None:
    kek = provider(vault)
    wrapped = kek.wrap(b"d" * 32, b"row-a")
    for bad in (
        lambda: kek.unwrap(wrapped, b"row-b"),
        lambda: kek.unwrap(
            WrappedKey(wrapped.wrapped_dek, None, "other-key", wrapped.key_version),
            b"row-a",
        ),
        lambda: kek.unwrap(
            WrappedKey(wrapped.wrapped_dek, None, "gateway", "kek-0123"), b"row-a"
        ),
    ):
        with pytest.raises(KekError):
            bad()


def test_rewrap_moves_a_key_to_the_latest_version(vault: StubVault) -> None:
    kek = provider(vault)
    old = kek.wrap(b"d" * 32, b"aad")
    vault.rotate()
    new = kek.rewrap(old, b"aad")
    assert (old.key_version, new.key_version) == ("transit-v1", "transit-v2")
    assert kek.unwrap(new, b"aad") == kek.unwrap(old, b"aad") == b"d" * 32
    assert (
        kek.covers("transit-v1")
        and kek.covers("transit-v2")
        and not kek.covers("kek-1")
    )


# --- the client (D-20) ---------------------------------------------------------------


def test_a_redirect_to_another_host_is_never_followed(vault: StubVault) -> None:
    kek = provider(vault)
    kek.probe()
    vault.redirect = True
    with pytest.raises(KekError):
        kek.wrap(b"d" * 32, b"aad")
    assert all("evil.example" not in str(call["url"]) for call in vault.calls)


def test_proxy_variables_are_ignored_and_tls_is_always_verified(
    vault: StubVault, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test.invalid:3128")
    monkeypatch.setenv("https_proxy", "http://proxy.test.invalid:3128")
    provider(vault).probe()
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    provider(vault, ca_file=ca).probe()
    assert vault.calls
    for call in vault.calls:
        assert not call.get("proxies"), call["proxies"]
        assert call["verify"] in (True, str(ca))
    assert vault_session(None).trust_env is False


def test_an_approle_token_is_renewed_before_its_lease_ends(vault: StubVault) -> None:
    clock = [0.0]
    kek = provider(vault, clock=clock)
    kek.probe()
    assert vault.logins == 1
    clock[0] = 3600 * 0.79
    kek.probe()
    assert vault.logins == 1
    clock[0] = 3600 * 0.81
    kek.probe()
    assert vault.logins == 2


def test_a_token_that_expires_mid_run_recovers_by_logging_in_again(
    vault: StubVault,
) -> None:
    kek = provider(vault)
    wrapped = kek.wrap(b"d" * 32, b"aad")
    vault.tokens.clear()
    assert kek.unwrap(wrapped, b"aad") == b"d" * 32
    assert vault.logins == 2


def test_a_rewritten_token_file_is_read_again(vault: StubVault) -> None:
    token_file = write_key_file("vault-token-rotating", STATIC_TOKEN.encode())
    kek = provider(vault, "token_file", token_file=token_file)
    kek.probe()
    vault.tokens = {"hvs.agent-rotated"}
    token_file.write_bytes(b"hvs.agent-rotated")
    kek.probe()
    vault.tokens = set()
    with pytest.raises(KekError):
        kek.probe()


def test_a_missing_or_unreadable_auth_file_refuses(
    vault: StubVault, tmp_path: Path
) -> None:
    no_role = VaultAccess(ADDR, "approle", secret_id_file=write_key_file("s2", b"x"))
    with pytest.raises(KekError, match="not configured"):
        no_role.call(lambda client: client)
    unsafe = tmp_path / "token"
    unsafe.write_text(STATIC_TOKEN)
    unsafe.chmod(0o644)
    with pytest.raises(KekError, match="not readable"):
        VaultAccess(ADDR, "token_file", token_file=unsafe).call(lambda client: client)


def test_a_refused_login_is_unavailable(vault: StubVault) -> None:
    bad = access(vault)
    bad._files["secret"] = write_key_file("wrong-secret", b"s.wrong")
    with pytest.raises(KekError):
        VaultTransitKekProvider(bad, mount="transit", key="gateway").probe()


def test_an_unreachable_vault_is_unavailable_never_a_fallback(vault: StubVault) -> None:
    kek = provider(vault)
    vault.down = True
    with pytest.raises(KekError):
        kek.wrap(b"d" * 32, b"aad")


# --- health and the documented policy -------------------------------------------------


def test_health_needs_lookup_self_encrypt_and_decrypt_only(vault: StubVault) -> None:
    store = transit_store(vault)
    healthy = asyncio.run(store.health())
    assert (healthy.status, healthy.meta) == (
        "ok",
        {"backend": "database", "kek_provider": "vault_transit"},
    )
    paths = {call["path"] for call in vault.calls}
    assert paths <= {
        "/v1/auth/approle/login",
        "/v1/auth/token/lookup-self",
        "/v1/transit/encrypt/gateway",
        "/v1/transit/decrypt/gateway",
    }
    assert not any("/keys/" in path for path in paths)
    vault.deny_decrypt = True  # a policy granting encrypt without decrypt
    failed = asyncio.run(store.health())
    assert (failed.status, failed.error) == ("fail", "KekError")


# --- the database store over transit -----------------------------------------------------


def transit_store(vault: StubVault) -> DatabaseCredentialStore:
    return DatabaseCredentialStore(
        deps.db_engine,
        provider(vault),
        FingerprintKeys(KeyMaterial(os.urandom(32), Path("/run/secrets/fp"))),
        resolve_timeout_seconds=2,
    )


@pytest.mark.usefixtures("clean_db")
def test_the_database_store_over_transit(vault: StubVault) -> None:
    store = transit_store(vault)
    identity = provisioning_credential()
    with deps.db_engine.begin() as connection:
        store.store(connection, identity, SecretStr("sk-transit-" + "t" * 30))
    with store.resolve_for_execution(identity.credential_id, 1) as secret:
        assert secret.reveal() == "sk-transit-" + "t" * 30
    vault.rotate()
    with deps.db_engine.begin() as connection:
        store.replace(connection, identity, SecretStr("sk-transit-2-" + "u" * 30))
        held = store.generations(connection).kek
        assert held == {"transit-v1": 1, "transit-v2": 1}
        store.check_coverage(connection)
        assert store.rewrap(connection) == 1
        assert store.generations(connection).kek == {"transit-v2": 2}
    with store.resolve_for_cleanup(identity.credential_id, 1) as old:
        assert old.reveal() == "sk-transit-" + "t" * 30


@pytest.mark.usefixtures("clean_db")
def test_a_vault_outage_refuses_reads_and_writes(vault: StubVault) -> None:
    store = transit_store(vault)
    identity = provisioning_credential()
    with deps.db_engine.begin() as connection:
        store.store(connection, identity, SecretStr("sk-transit-" + "t" * 30))
    vault.down = True
    with pytest.raises(GatewayError) as read:
        with store.resolve_for_execution(identity.credential_id, 1):
            pass  # pragma: no cover - refused on entry
    # Every connection is closed here: a leaked one would hold the row lock.
    with pytest.raises(GatewayError) as write:
        with deps.db_engine.begin() as connection:
            store.replace(connection, identity, SecretStr("sk-x-" + "x" * 30))
    assert read.value.code is write.value.code is AiErrorCode.CREDENTIAL_UNAVAILABLE


@pytest.mark.usefixtures("clean_db")
def test_local_rows_are_not_covered_by_a_transit_replica(vault: StubVault) -> None:
    local = DatabaseCredentialStore(
        deps.db_engine,
        LocalKekProvider(KeyMaterial(os.urandom(32), Path("/run/secrets/kek"))),
        FingerprintKeys(KeyMaterial(os.urandom(32), Path("/run/secrets/fp"))),
        resolve_timeout_seconds=2,
    )
    identity = provisioning_credential()
    with deps.db_engine.begin() as connection:
        local.store(connection, identity, SecretStr("sk-local-" + "l" * 30))
    with deps.db_engine.connect() as connection, pytest.raises(KeyCoverageError):
        transit_store(vault).check_coverage(connection)


# --- disclosure and construction ---------------------------------------------------------


def test_neither_the_token_nor_the_secret_id_is_ever_shown(
    vault: StubVault, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    kek = provider(vault)
    texts = [repr(kek), repr(kek._access)]
    kek.probe()
    vault.tokens.clear()
    kek.probe()
    vault.down = True
    try:
        kek.probe()
    except KekError as exc:
        texts += [str(exc), repr(exc)]
    joined = "\n".join(texts) + caplog.text
    for secret in (SECRET_ID, ROLE_ID, STATIC_TOKEN, "hvs.approle-1", "hvs.approle-2"):
        assert secret not in joined


def test_the_factory_builds_the_transit_store_without_contacting_vault() -> None:
    settings = SimpleNamespace(
        AI_CREDENTIAL_STORAGE_BACKEND="database",
        AI_CREDENTIAL_KEK_PROVIDER="vault_transit",
        AI_VAULT_ADDR=ADDR,
        AI_VAULT_AUTH_METHOD="approle",
        AI_VAULT_TOKEN_FILE=None,
        AI_VAULT_ROLE_ID_FILE=Path("/run/secrets/role"),
        AI_VAULT_SECRET_ID_FILE=Path("/run/secrets/secret"),
        AI_VAULT_CA_FILE=None,
        AI_VAULT_TRANSIT_MOUNT="transit",
        AI_VAULT_TRANSIT_KEY="gateway",
        AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS=5,
        fingerprint_key=KeyMaterial(os.urandom(32), Path("/run/secrets/fp")),
        previous_fingerprint_key=None,
    )
    store = build_credential_store(settings, deps.db_engine)  # type: ignore[arg-type]
    assert "VaultTransitKekProvider(key='gateway'" in repr(store)


def test_an_answer_without_data_is_unavailable(vault: StubVault) -> None:
    # A 3xx makes requests raise (max_redirects = 0); a 2xx without JSON data
    # comes back as a bare response, and is refused too.
    vault.no_content = True
    with pytest.raises(KekError):
        provider(vault).probe()  # the AppRole login gets a 204
    with pytest.raises(KekError):
        provider(vault, "token_file").wrap(b"d" * 32, b"aad")  # the encrypt


def test_the_active_version_is_probed_when_unknown(vault: StubVault) -> None:
    vault.rotate()
    assert provider(vault).active_version == "transit-v2"


def test_rewrap_refuses_an_envelope_of_another_kek_provider(vault: StubVault) -> None:
    from ai_gateway.credentials.envelope import Envelope, EnvelopeError, rewrapped

    local = LocalKekProvider(KeyMaterial(os.urandom(32), Path("/run/secrets/kek")))
    envelope = Envelope(b"c", b"n" * 12, local.wrap(b"d" * 32, b"aad"), "local")
    with pytest.raises(EnvelopeError):
        rewrapped(envelope, b"aad", provider(vault))

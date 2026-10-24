"""
Live: the Vault transit KEK against the running ``vault_transit_m8`` stack (T23, T87).

Not part of the default run (``pytest.ini`` ignores ``tests/live``). Start the
stack, then, as a user that can read its ``secrets/`` directory (uid 1000 once
the stack has started) and run ``docker compose`` there::

    cd docker_compose/vault_transit_m8 && bash init.sh && docker compose up -d
    AI_GATEWAY_LIVE_STACK_DIR=docker_compose/vault_transit_m8 \\
        python -m pytest tests/live -o addopts="" --confcutdir=tests/live -m live

``--confcutdir`` keeps the unit suite's conftest (and its PostgreSQL harness)
out of this run. The public router is reached at ``AI_GATEWAY_LIVE_PUBLIC_URL``
(default ``https://127.0.0.1:4431``, verified against the stack CA) and the
loopback in-network entrypoint at ``AI_GATEWAY_LIVE_API_URL`` (default
``http://127.0.0.1:18080``).

The policy and token steps use the learning Vault's root token from the
``vault_bootstrap`` volume, through the stack's own ``vault-init`` image; they
restore the documented policy before the test ends.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - fixed docker compose argv
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import httpx
import pytest

pytestmark = pytest.mark.live

STACK: Final = Path(os.environ.get("AI_GATEWAY_LIVE_STACK_DIR", "")).resolve()
PUBLIC: Final = os.environ.get("AI_GATEWAY_LIVE_PUBLIC_URL", "https://127.0.0.1:4431")
API: Final = os.environ.get("AI_GATEWAY_LIVE_API_URL", "http://127.0.0.1:18080")
CANARY: Final = f"sk-live-transit-canary-{uuid.uuid4().hex}"

#: Reads the root token from the learning Vault's bootstrap volume.
_ROOT_TOKEN: Final = (
    'export VAULT_TOKEN="$(grep -o \'"root_token": *"[^"]*"\' '
    '/vault/bootstrap/init.json | sed \'s/.*"\\([^"]*\\)"$/\\1/\')"; '
)
#: The documented policy narrowed to encrypt only.
_ENCRYPT_ONLY: Final = (
    'printf \'path "transit/encrypt/ai-gateway-kek" { capabilities = ["update"] }\\n\''
    " | vault policy write ai-gateway -"
)
_REVOKE: Final = "vault token revoke -mode=path auth/approle/login"


def _secret(name: str) -> str:
    return (STACK / "secrets" / name).read_text("utf-8").strip()


def _compose(*args: str, stdin: str | None = None) -> str:
    result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["docker", "compose", *args],
        cwd=STACK,
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    return result.stdout


def _vault(script: str) -> None:
    _compose(
        "run", "--rm", "-T", "--no-deps", "--entrypoint", "/bin/sh",
        "vault-init", "-c", _ROOT_TOKEN + script,
    )  # fmt: skip


def _sql(statement: str) -> str:
    return _compose(
        "exec", "-T", "m8_db", "sh", "-c",
        "PGPASSWORD=$(cat /run/secrets/postgres_password) "
        "psql -U postgres -d ai_db -At",
        stdin=statement,
    ).strip()  # fmt: skip


def _credential_store() -> dict[str, Any]:
    answer = httpx.get(
        f"{API}/ai/health/",
        headers={"X-Internal-Token": _secret("health_detail_credential")},
        timeout=15,
    )
    checks = {check["name"]: check for check in answer.json()["checks"]}
    store: dict[str, Any] = checks["credential_store"]
    return store


@pytest.fixture(scope="module")
def public() -> Iterator[httpx.Client]:
    if not (STACK / "secrets" / "stack_ca.pem").is_file():
        pytest.skip("AI_GATEWAY_LIVE_STACK_DIR names no initialised vault_transit_m8")
    with httpx.Client(
        base_url=PUBLIC, verify=str(STACK / "secrets" / "stack_ca.pem"), timeout=15
    ) as client:
        yield client


@pytest.fixture(scope="module")
def superuser(public: httpx.Client) -> dict[str, str]:
    answer = public.post(
        "/user/login/access-token",
        data={
            "username": "admin@example.com",
            "password": _secret("issuer_superuser_password"),
        },
    )
    answer.raise_for_status()
    return {"Authorization": f"Bearer {answer.json()['access_token']}"}


def test_health_passes_under_the_documented_policy() -> None:
    store = _credential_store()
    assert store["status"] == "ok"
    assert store["meta"] == {"backend": "database", "kek_provider": "vault_transit"}


def test_a_credential_is_stored_under_the_transit_key(
    public: httpx.Client, superuser: dict[str, str]
) -> None:
    provider = public.post(
        "/ai/v1/admin/providers",
        headers=superuser,
        json={
            "name": f"live-transit-{uuid.uuid4().hex[:8]}",
            "provider_type": "openai_compatible",
            "base_url": "https://api.example.com/v1",
            "auth_type": "bearer",
            "boundary": "external",
        },
    )
    assert provider.status_code == 201, provider.text
    credential = public.post(
        "/ai/v1/me/credentials",
        headers=superuser,
        json={
            "provider_id": provider.json()["id"],
            "name": "live-transit-key",
            "secret": CANARY,
        },
    )
    assert credential.status_code == 201, credential.text
    row = _sql(
        "SELECT kek_provider, kek_key_id, kek_key_version FROM ai_credential_version "
        f"WHERE credential_id = '{uuid.UUID(credential.json()['id'])}';"
    )
    provider_name, key_id, version = row.split("|")
    assert (provider_name, key_id) == ("vault_transit", "ai-gateway-kek")
    assert version.startswith("transit-v")
    dump = _compose(
        "exec", "-T", "m8_db", "sh", "-c",
        "PGPASSWORD=$(cat /run/secrets/postgres_password) pg_dump -U postgres ai_db",
    )  # fmt: skip
    assert CANARY not in dump


def test_revoked_tokens_recover_by_a_fresh_login() -> None:
    _vault(_REVOKE)
    assert _credential_store()["status"] == "ok"


def test_encrypt_without_decrypt_fails_health() -> None:
    try:
        _vault(f"{_ENCRYPT_ONLY} && {_REVOKE}")
        store = _credential_store()
        assert store["status"] == "fail"
        assert store["error"] == "KekError"
    finally:
        _compose("run", "--rm", "-T", "--no-deps", "vault-init")
        _vault(_REVOKE)
    assert _credential_store()["status"] == "ok"


def test_the_approle_policy_reads_no_key_metadata() -> None:
    text = _compose(
        "run", "--rm", "-T", "--no-deps", "--entrypoint", "/bin/sh", "vault-init",
        "-c", _ROOT_TOKEN + "vault policy read ai-gateway",
    )  # fmt: skip
    assert "transit/keys" not in text
    assert "transit/encrypt/ai-gateway-kek" in text
    assert "transit/decrypt/ai-gateway-kek" in text

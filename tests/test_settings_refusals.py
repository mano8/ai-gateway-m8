"""T15: every contradiction the settings can detect is refused at boot."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from ai_sdk_m8.schemas import Capability
from ai_sdk_m8.signed import derive_kid, encode_public_key, public_key_from_seed
from pydantic import ValidationError

from ai_gateway.core.config import (
    ADMISSION_SETTINGS,
    SWEEPER_GRACE_SECONDS,
    Settings,
    describe_validation_error,
)
from ai_gateway.core.policy import DEFAULT_POLICY, Destination
from conftest import ADMISSION_LIMITS, FINGERPRINT_KEY_FILE, KEK_FILE, write_key_file
from fastapi_m8 import ConsumerCredential

Build = Callable[..., Settings]

ISSUER_SEED = bytes(range(32))
ISSUER_PUBLIC = public_key_from_seed(ISSUER_SEED)
ISSUER_KID = derive_kid(ISSUER_PUBLIC)
SECRET_HASH = ConsumerCredential.create("x", "s" * 64).encoded_secret


def client_entry(
    scopes: list[str], keys: dict[str, str] | None = None
) -> dict[str, object]:
    entry: dict[str, object] = {"secret": SECRET_HASH, "scopes": scopes}
    if keys is not None:
        entry["job_context_public_keys"] = keys
    return entry


@pytest.fixture
def build(monkeypatch: pytest.MonkeyPatch) -> Build:
    """Build ``Settings`` from the test environment plus ``overrides``.

    A value of ``None`` removes the variable.
    """

    def _build(**overrides: object) -> Settings:
        for key, value in overrides.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, str(value))
        return Settings(_env_file=None)  # type: ignore[call-arg]

    return _build


def refused(build: Build, match: str, **overrides: object) -> None:
    with pytest.raises(ValidationError, match=match):
        build(**overrides)


def test_the_test_environment_is_valid(build: Build) -> None:
    settings = build()
    assert settings.kek is not None
    assert settings.fingerprint_key is not None
    assert settings.user_byok_enabled is False
    assert settings.capabilities_enabled == frozenset()
    assert settings.data_class_policy.is_default()
    assert settings.job_context_audience == f"ai-gateway/{settings.deployment_id}"
    assert "<redacted>" in repr(settings.kek)
    assert KEK_FILE.read_bytes() not in repr(settings).encode()


# --- storage backend and KEK -------------------------------------------------


@pytest.mark.parametrize(
    "setting",
    [
        "AI_CREDENTIAL_KEK_PROVIDER",
        "AI_CREDENTIAL_KEK_FILE",
        "AI_CREDENTIAL_KEK_PREVIOUS_FILES",
    ],
)
def test_vault_backend_with_any_kek_setting_is_refused(
    build: Build, setting: str
) -> None:
    overrides: dict[str, object] = {
        "AI_CREDENTIAL_STORAGE_BACKEND": "vault",
        "AI_CREDENTIAL_KEK_PROVIDER": None,
        "AI_CREDENTIAL_KEK_FILE": None,
        "AI_VAULT_ADDR": "https://vault:8200",
        "AI_VAULT_AUTH_METHOD": "token_file",
        "AI_VAULT_TOKEN_FILE": write_key_file("vault-token", b"hvs.token"),
        "AI_VAULT_KV_MOUNT": "kv",
        "AI_VAULT_KV_PATH_PREFIX": "ai-gateway",
    }
    build(**overrides)  # the clean vault configuration boots
    overrides[setting] = {"AI_CREDENTIAL_KEK_PROVIDER": "local"}.get(
        setting, str(KEK_FILE)
    )
    refused(build, "takes no KEK setting", **overrides)


def test_vault_backend_needs_its_mount_and_prefix(build: Build) -> None:
    refused(
        build,
        "AI_VAULT_KV_MOUNT, AI_VAULT_KV_PATH_PREFIX must be set",
        AI_CREDENTIAL_STORAGE_BACKEND="vault",
        AI_CREDENTIAL_KEK_PROVIDER=None,
        AI_CREDENTIAL_KEK_FILE=None,
    )


def test_database_backend_needs_a_kek_provider(build: Build) -> None:
    refused(build, "needs AI_CREDENTIAL_KEK_PROVIDER", AI_CREDENTIAL_KEK_PROVIDER=None)


def test_database_backend_needs_a_fingerprint_key(build: Build) -> None:
    refused(
        build,
        "AI_CREDENTIAL_FINGERPRINT_KEY_FILE must be set",
        AI_CREDENTIAL_FINGERPRINT_KEY_FILE=None,
    )


def test_local_kek_needs_its_file(build: Build) -> None:
    refused(build, "AI_CREDENTIAL_KEK_FILE must be set", AI_CREDENTIAL_KEK_FILE=None)


@pytest.mark.parametrize(
    ("content", "mode", "match"),
    [
        (None, 0o640, "group or others"),
        (None, 0o604, "group or others"),
        (b"x" * 31, 0o600, "32 raw bytes"),
        (b"x" * 33, 0o600, "32 raw bytes"),
        (b"!" * 44, 0o600, "32 raw bytes"),
    ],
)
def test_local_kek_file_must_be_safe_and_32_bytes(
    build: Build, content: bytes | None, mode: int, match: str
) -> None:
    path = write_key_file("bad-kek", content, mode)
    refused(build, match, AI_CREDENTIAL_KEK_FILE=path)


def test_unreadable_or_irregular_kek_file(build: Build, tmp_path: Path) -> None:
    refused(build, "not readable", AI_CREDENTIAL_KEK_FILE=tmp_path / "absent")
    directory = tmp_path / "dir"
    directory.mkdir(mode=0o700)
    refused(build, "not a regular file", AI_CREDENTIAL_KEK_FILE=directory)
    big = write_key_file("big", b"x" * 5000)
    refused(build, "too large", AI_CREDENTIAL_KEK_FILE=big)


def test_base64_kek_file_is_accepted(build: Build) -> None:
    raw = bytes(range(100, 132))
    path = write_key_file("b64-kek", base64.b64encode(raw) + b"\n")
    assert build(AI_CREDENTIAL_KEK_FILE=path).kek.reveal() == raw  # type: ignore[union-attr]


def test_previous_kek_files_are_loaded(build: Build) -> None:
    first = write_key_file("prev-1")
    second = write_key_file("prev-2")
    settings = build(AI_CREDENTIAL_KEK_PREVIOUS_FILES=f"{first}, {second}")
    assert [k.path for k in settings.previous_keks] == [first, second]


def test_a_key_reused_across_purposes_is_refused(build: Build) -> None:
    refused(build, "hold the same key", AI_CREDENTIAL_FINGERPRINT_KEY_FILE=KEK_FILE)
    copy = write_key_file("kek-copy", KEK_FILE.read_bytes())
    refused(build, "hold the same key", AI_CREDENTIAL_KEK_PREVIOUS_FILES=copy)


def test_vault_transit_needs_address_auth_mount_and_key(build: Build) -> None:
    base = {
        "AI_CREDENTIAL_KEK_PROVIDER": "vault_transit",
        "AI_CREDENTIAL_KEK_FILE": None,
    }
    refused(build, "AI_VAULT_TRANSIT_MOUNT, AI_VAULT_TRANSIT_KEY", **base)
    base |= {"AI_VAULT_TRANSIT_MOUNT": "transit", "AI_VAULT_TRANSIT_KEY": "ai-kek"}
    refused(build, "AI_VAULT_ADDR, AI_VAULT_AUTH_METHOD must be set", **base)
    base |= {"AI_VAULT_ADDR": "https://vault:8200", "AI_VAULT_AUTH_METHOD": "approle"}
    refused(build, "AI_VAULT_ROLE_ID_FILE, AI_VAULT_SECRET_ID_FILE", **base)
    base |= {
        "AI_VAULT_ROLE_ID_FILE": write_key_file("role-id", b"role-1"),
        "AI_VAULT_SECRET_ID_FILE": write_key_file("secret-id", b"secret-1"),
    }
    assert build(**base).kek is None


def test_vault_transit_refuses_local_kek_files(build: Build) -> None:
    refused(
        build,
        "remove the local KEK files",
        AI_CREDENTIAL_KEK_PROVIDER="vault_transit",
    )


@pytest.mark.parametrize(
    ("address", "match"),
    [
        ("vault:8200", "absolute http or https"),
        ("https://user:pw@vault:8200", "no credentials"),
        ("https://vault:8200/?x=1", "no credentials"),
    ],
)
def test_vault_address_shape(build: Build, address: str, match: str) -> None:
    refused(
        build,
        match,
        AI_CREDENTIAL_KEK_PROVIDER="vault_transit",
        AI_CREDENTIAL_KEK_FILE=None,
        AI_VAULT_TRANSIT_MOUNT="transit",
        AI_VAULT_TRANSIT_KEY="k",
        AI_VAULT_ADDR=address,
        AI_VAULT_AUTH_METHOD="token_file",
        AI_VAULT_TOKEN_FILE=write_key_file("tok", b"t"),
    )


def test_plain_http_vault_is_refused_under_production(build: Build) -> None:
    overrides = {
        "AI_CREDENTIAL_KEK_PROVIDER": "vault_transit",
        "AI_CREDENTIAL_KEK_FILE": None,
        "AI_VAULT_TRANSIT_MOUNT": "transit",
        "AI_VAULT_TRANSIT_KEY": "k",
        "AI_VAULT_ADDR": "http://vault:8200",
        "AI_VAULT_AUTH_METHOD": "token_file",
        "AI_VAULT_TOKEN_FILE": write_key_file("tok2", b"t"),
        "AI_USER_BYOK_ENABLED": "true",
    }
    build(**overrides)  # accepted outside production (learning-only dev Vault)
    refused(build, "must be https", ENVIRONMENT="production", **overrides)
    refused(build, "must be https", STRICT_PRODUCTION_MODE="true", **overrides)


def test_vault_token_file_must_be_a_safe_token(build: Build) -> None:
    refused(
        build,
        "group or others",
        AI_CREDENTIAL_KEK_PROVIDER="vault_transit",
        AI_CREDENTIAL_KEK_FILE=None,
        AI_VAULT_TRANSIT_MOUNT="transit",
        AI_VAULT_TRANSIT_KEY="k",
        AI_VAULT_ADDR="https://vault:8200",
        AI_VAULT_AUTH_METHOD="token_file",
        AI_VAULT_TOKEN_FILE=write_key_file("tok3", b"t", 0o644),
    )
    for content, match in ((b"two words", "one non-empty token"), (b"\xff", "ASCII")):
        refused(
            build,
            match,
            AI_CREDENTIAL_KEK_PROVIDER="vault_transit",
            AI_CREDENTIAL_KEK_FILE=None,
            AI_VAULT_TRANSIT_MOUNT="transit",
            AI_VAULT_TRANSIT_KEY="k",
            AI_VAULT_ADDR="https://vault:8200",
            AI_VAULT_AUTH_METHOD="token_file",
            AI_VAULT_TOKEN_FILE=write_key_file("tok4", content),
        )


# --- placeholders and reuse --------------------------------------------------


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AI_VAULT_ADDR", "changethis"),
        ("AI_DATA_CLASS_POLICY", "CHANGETHIS"),
        ("AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE", "changethis"),
        ("AI_SERVICE_CLIENTS", "changethis"),
    ],
)
def test_a_placeholder_gateway_value_is_refused(
    build: Build, key: str, value: str
) -> None:
    refused(build, "changethis|Insecure default", **{key: value})


def test_a_placeholder_fleet_secret_is_refused(build: Build) -> None:
    refused(build, "Insecure default", PRIVATE_API_SECRET="changethis")


def test_a_reused_secret_is_refused_under_production(build: Build) -> None:
    same = "Reused-Secret-Value-1234567890-abcdef"
    overrides = {
        "PRIVATE_API_SECRET": same,
        "EVENT_SIGNING_KEY": same,
        "AI_USER_BYOK_ENABLED": "true",
    }
    build(**overrides)
    refused(
        build,
        "EVENT_SIGNING_KEY reuses the value of PRIVATE_API_SECRET",
        ENVIRONMENT="production",
        **overrides,
    )


# --- callers, users and policy -----------------------------------------------


def test_user_byok_must_be_explicit_under_production(build: Build) -> None:
    refused(build, "AI_USER_BYOK_ENABLED must be set", ENVIRONMENT="production")
    refused(build, "AI_USER_BYOK_ENABLED must be set", STRICT_PRODUCTION_MODE="true")
    assert build(
        ENVIRONMENT="production", AI_USER_BYOK_ENABLED="true", **ADMISSION_LIMITS
    ).user_byok_enabled
    assert not build(
        ENVIRONMENT="production", AI_USER_BYOK_ENABLED="false", **ADMISSION_LIMITS
    ).user_byok_enabled


@pytest.mark.parametrize("missing", ADMISSION_SETTINGS)
def test_admission_bounds_must_be_set_under_production(
    build: Build, missing: str
) -> None:
    limits: dict[str, object] = {**ADMISSION_LIMITS, missing: None}
    for mode in (
        {"ENVIRONMENT": "production", "STRICT_PRODUCTION_MODE": "false"},
        {"ENVIRONMENT": "local", "STRICT_PRODUCTION_MODE": "true"},
    ):
        refused(
            build,
            f"{missing} must be set under production",
            AI_USER_BYOK_ENABLED="true",
            **mode,
            **limits,
        )
    # Outside production an unset bound is simply not enforced.
    relaxed = build(ENVIRONMENT="local", STRICT_PRODUCTION_MODE="false", **limits)
    assert getattr(relaxed, missing) is None


def test_api_key_introspection_is_refused(build: Build) -> None:
    refused(
        build,
        "API_KEY_INTROSPECTION_ENABLED must stay false",
        API_KEY_INTROSPECTION_ENABLED="true",
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        INTERNAL_CLIENT_ID="ai-gateway",
        PRIVATE_API_SECRET="GatewayTests-Private-Api-Secret-1234",
    )


@pytest.mark.parametrize(
    ("policy", "match"),
    [
        (
            {
                "public": ["local"],
                "internal": ["local"],
                "restricted": ["local", "external_platform"],
            },
            "never let restricted",
        ),
        ({"public": ["local"], "internal": ["local"]}, "exactly public"),
        ({"public": "local", "internal": [], "restricted": []}, "must be a list"),
        (
            {"public": ["anywhere"], "internal": [], "restricted": []},
            "unknown destination",
        ),
        ({"public": ["local", "local"], "internal": [], "restricted": []}, "repeats"),
        ([], "exactly public"),
    ],
)
def test_data_class_policy_refusals(build: Build, policy: object, match: str) -> None:
    refused(build, match, AI_DATA_CLASS_POLICY=json.dumps(policy))
    refused(build, "not valid JSON", AI_DATA_CLASS_POLICY="{")


def test_data_class_policy_default_and_explicit_widening(build: Build) -> None:
    default = build().data_class_policy
    assert dict(default.allowed) == dict(DEFAULT_POLICY)
    assert not default.allows(*_internal_platform())
    widened = build(
        AI_DATA_CLASS_POLICY=json.dumps(
            {
                "public": ["local", "external_byok", "external_platform"],
                "internal": ["local", "external_byok", "external_platform"],
                "restricted": ["local", "external_byok"],
            }
        )
    ).data_class_policy
    assert widened.allows(*_internal_platform())
    assert not widened.is_default()
    assert widened.sha256() != default.sha256()
    assert len(default.sha256()) == 64


def _internal_platform() -> tuple[object, Destination]:
    from ai_sdk_m8.schemas import DataClass

    return DataClass.INTERNAL, Destination.EXTERNAL_PLATFORM


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("embedding,teleport", "unknown capability"),
        ("embedding,embedding", "repeats"),
        ("chat", "no V1 route"),
    ],
)
def test_capability_set_is_closed(build: Build, value: str, match: str) -> None:
    refused(build, match, AI_CAPABILITIES_ENABLED=value)


def test_capability_set_parses(build: Build) -> None:
    assert build(
        AI_CAPABILITIES_ENABLED=" embedding, rerank "
    ).capabilities_enabled == {
        Capability.EMBEDDING,
        Capability.RERANK,
    }


# --- service clients ---------------------------------------------------------


def _clients(**entries: object) -> str:
    return json.dumps(entries)


def test_service_clients_parse(build: Build) -> None:
    settings = build(
        AI_SERVICE_CLIENTS=_clients(
            **{
                "media-service": client_entry(
                    ["execute:embedding", "job-context:issue"],
                    {ISSUER_KID: encode_public_key(ISSUER_PUBLIC)},
                ),
                "media-worker": client_entry(["execute:ocr"]),
            }
        )
    )
    clients = settings.service_clients
    assert clients.issuer_keys("media-service") == {ISSUER_KID: ISSUER_PUBLIC}
    assert clients.issuer_keys("media-worker") == {}
    assert clients.has_scope("media-worker", "execute:ocr")
    assert not clients.has_scope("media-worker", "execute:embedding")
    assert clients.registry.verify("media-worker", "s" * 64) is not None


@pytest.mark.parametrize(
    ("clients", "match"),
    [
        ("{", "not valid JSON"),
        ("[]", "must be a JSON object"),
        (_clients(**{"bad id": client_entry([])}), "not a valid token"),
        (_clients(a={"secret": SECRET_HASH}), "must be an object with secret"),
        (
            _clients(a={"secret": "plaintext-secret", "scopes": []}),
            "never in plaintext",
        ),
        (_clients(a={"secret": "sha256$zz$zz", "scopes": []}), "malformed"),
        (_clients(a=client_entry(["execute:chat"])), "unknown scopes"),
        (_clients(a=client_entry(["execute:ocr", "execute:ocr"])), "repeats a scope"),
        (
            _clients(a=client_entry(["job-context:issue"])),
            "lists no job_context_public_keys",
        ),
        (
            _clients(
                a=client_entry(
                    ["execute:ocr"], {ISSUER_KID: encode_public_key(ISSUER_PUBLIC)}
                )
            ),
            "without job-context:issue",
        ),
        (
            _clients(a=client_entry(["job-context:issue"], {"kid": "AAAA"})),
            "not 32 bytes",
        ),
        (
            _clients(
                a=client_entry(
                    ["job-context:issue"],
                    {"wrong-kid": encode_public_key(ISSUER_PUBLIC)},
                )
            ),
            "not the one its key derives",
        ),
        (
            _clients(
                a=client_entry(
                    ["job-context:issue"],
                    {ISSUER_KID: encode_public_key(ISSUER_PUBLIC)},
                ),
                b=client_entry(
                    ["job-context:issue"],
                    {ISSUER_KID: encode_public_key(ISSUER_PUBLIC)},
                ),
            ),
            "registered under both",
        ),
    ],
)
def test_service_client_refusals(build: Build, clients: str, match: str) -> None:
    refused(build, match, AI_SERVICE_CLIENTS=clients)


# --- receipts ----------------------------------------------------------------


def test_ocr_needs_a_receipt_key_and_a_spool(build: Build, tmp_path: Path) -> None:
    refused(build, "AI_EXECUTION_RECEIPT_KEY_FILE", AI_CAPABILITIES_ENABLED="ocr")
    seed = write_key_file("receipt-seed")
    refused(
        build,
        "needs AI_OCR_SPOOL_DIR",
        AI_CAPABILITIES_ENABLED="ocr",
        AI_EXECUTION_RECEIPT_KEY_FILE=seed,
    )
    settings = build(
        AI_CAPABILITIES_ENABLED="ocr",
        AI_EXECUTION_RECEIPT_KEY_FILE=seed,
        AI_OCR_SPOOL_DIR=tmp_path,
    )
    assert settings.receipt_kid == derive_kid(public_key_from_seed(seed.read_bytes()))
    assert settings.receipt_public_key == public_key_from_seed(seed.read_bytes())


def test_spool_sizing_rule(build: Build, tmp_path: Path) -> None:
    refused(
        build,
        "exceeds AI_OCR_SPOOL_MAX_BYTES",
        AI_CAPABILITIES_ENABLED="ocr",
        AI_EXECUTION_RECEIPT_KEY_FILE=write_key_file("receipt-seed-2"),
        AI_OCR_SPOOL_DIR=tmp_path,
        AI_MAX_CONCURRENT_SPOOLS=4,
        AI_MAX_REQUEST_BYTES=1000,
        AI_OCR_SPOOL_MAX_BYTES=3999,
    )


def test_receipt_kid_must_match_the_seed(build: Build) -> None:
    seed = write_key_file("receipt-seed-3")
    refused(
        build,
        "differs from the kid",
        AI_EXECUTION_RECEIPT_KEY_FILE=seed,
        AI_EXECUTION_RECEIPT_KID="not-the-kid",
    )
    good = derive_kid(public_key_from_seed(seed.read_bytes()))
    assert (
        build(
            AI_EXECUTION_RECEIPT_KEY_FILE=seed, AI_EXECUTION_RECEIPT_KID=good
        ).receipt_kid
        == good
    )
    refused(
        build,
        "without AI_EXECUTION_RECEIPT_KEY_FILE",
        AI_EXECUTION_RECEIPT_KEY_FILE=None,
        AI_EXECUTION_RECEIPT_KID=good,
    )


def test_an_issuer_key_equal_to_the_receipt_key_is_refused(build: Build) -> None:
    seed = write_key_file("receipt-is-issuer", ISSUER_SEED)
    refused(
        build,
        "equals the gateway's receipt key",
        AI_EXECUTION_RECEIPT_KEY_FILE=seed,
        AI_SERVICE_CLIENTS=_clients(
            a=client_entry(
                ["job-context:issue"], {ISSUER_KID: encode_public_key(ISSUER_PUBLIC)}
            )
        ),
    )


def test_receipt_seed_reused_as_a_kek_is_refused(build: Build) -> None:
    refused(
        build, "hold the same key", AI_EXECUTION_RECEIPT_KEY_FILE=FINGERPRINT_KEY_FILE
    )


# --- destinations ------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "ollama",
        "ollama:",
        "ollama:0",
        "ollama:99999",
        "Ollama:11434",
        "10.0.0.5:11434",
        "-x:1",
        "a_b:1",
    ],
)
def test_internal_hosts_must_be_name_port_pairs(build: Build, value: str) -> None:
    refused(
        build,
        "not a lower-case name:port|not a TCP port",
        AI_PROVIDER_ALLOWED_INTERNAL_HOSTS=value,
    )


def test_internal_hosts_parse(build: Build) -> None:
    settings = build(AI_PROVIDER_ALLOWED_INTERNAL_HOSTS="ollama:11434, tei.ai-net:8080")
    assert settings.internal_hosts == {("ollama", 11434), ("tei.ai-net", 8080)}


@pytest.mark.parametrize("value", [",", "443,x", "0"])
def test_external_ports(build: Build, value: str) -> None:
    refused(
        build, "lists no port|not a TCP port", AI_PROVIDER_ALLOWED_EXTERNAL_PORTS=value
    )
    assert build(AI_PROVIDER_ALLOWED_EXTERNAL_PORTS="443, 8443").external_ports == {
        443,
        8443,
    }


# --- timing ------------------------------------------------------------------


def test_dispatch_ttl_above_the_context_ttl_is_refused(build: Build) -> None:
    refused(
        build,
        "AI_DISPATCH_CONTEXT_TTL_SECONDS exceeds",
        AI_DISPATCH_CONTEXT_TTL_SECONDS=901,
        AI_RESERVATION_TTL_SECONDS=2000,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS": 60},
        {"AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS": 30},
        {"AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS": 10, "AI_RESERVATION_TTL_SECONDS": 10},
    ],
)
def test_resolve_timeout_must_be_below_both_ttls(
    build: Build, overrides: dict[str, int]
) -> None:
    refused(build, "must be below both", **overrides)


@pytest.mark.parametrize(
    "key", ["AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS", "AI_MAX_CLOCK_SKEW_SECONDS"]
)
def test_skew_bounds_must_fit_the_sweeper_grace(build: Build, key: str) -> None:
    refused(build, "exceeds the sweeper grace", **{key: SWEEPER_GRACE_SECONDS + 1})
    assert getattr(build(**{key: SWEEPER_GRACE_SECONDS}), key) == SWEEPER_GRACE_SECONDS


def test_credentials_per_scope_must_be_positive(build: Build) -> None:
    refused(build, "AI_MAX_CREDENTIALS_PER_SCOPE", AI_MAX_CREDENTIALS_PER_SCOPE=0)
    refused(build, "AI_MAX_CREDENTIALS_PER_SCOPE", AI_MAX_CREDENTIALS_PER_SCOPE=None)


# --- boot error text ---------------------------------------------------------


def test_boot_errors_never_carry_the_environment(build: Build) -> None:
    secret = "Never-Print-This-Db-Passw0rd!"
    with pytest.raises(ValidationError) as info:
        build(DB_PASSWORD=secret, AI_MAX_CREDENTIALS_PER_SCOPE=0)
    text = describe_validation_error(info.value)
    assert "AI_MAX_CREDENTIALS_PER_SCOPE" in text
    assert secret not in text


def test_key_accessors(build: Build) -> None:
    previous = write_key_file("fp-previous")
    seed = write_key_file("receipt-seed-4")
    settings = build(
        AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE=previous,
        AI_EXECUTION_RECEIPT_KEY_FILE=seed,
    )
    assert settings.previous_fingerprint_key.path == previous  # type: ignore[union-attr]
    assert settings.receipt_seed.reveal() == seed.read_bytes()  # type: ignore[union-attr]
    plain = build(
        AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE=None,
        AI_EXECUTION_RECEIPT_KEY_FILE=None,
    )
    assert plain.receipt_seed is None
    assert plain.receipt_public_key is None
    assert plain.previous_fingerprint_key is None


def test_vault_backend_loads_no_fingerprint_key(build: Build) -> None:
    settings = build(
        AI_CREDENTIAL_STORAGE_BACKEND="vault",
        AI_CREDENTIAL_KEK_PROVIDER=None,
        AI_CREDENTIAL_KEK_FILE=None,
        AI_CREDENTIAL_FINGERPRINT_KEY_FILE=None,
        AI_VAULT_ADDR="https://vault:8200",
        AI_VAULT_AUTH_METHOD="token_file",
        AI_VAULT_TOKEN_FILE=write_key_file("vault-token-2", b"hvs.token"),
        AI_VAULT_KV_MOUNT="kv",
        AI_VAULT_KV_PATH_PREFIX="ai-gateway",
    )
    assert settings.fingerprint_key is None
    assert settings.kek is None


def test_default_policy_json_round_trips(build: Build) -> None:
    from ai_gateway.core.policy import default_policy_json

    assert build(
        AI_DATA_CLASS_POLICY=default_policy_json()
    ).data_class_policy.is_default()

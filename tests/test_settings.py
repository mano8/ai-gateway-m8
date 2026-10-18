"""Settings: metadata, required keys fail fast, unknown keys refused."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_gateway import __version__
from ai_gateway.core import config
from ai_gateway.core.config import Settings, settings

REQUIRED_GATEWAY_KEYS = (
    "AI_DEPLOYMENT_ID",
    "AI_CREDENTIAL_STORAGE_BACKEND",
    "AI_SERVICE_CLIENTS",
    "AI_MAX_CREDENTIALS_PER_SCOPE",
)


def test_service_version_resurfaces_the_package_version() -> None:
    assert settings.SERVICE_VERSION == __version__
    assert settings.CONTRACT_VERSION == "1.0"
    assert settings.CONTRACT_RANGE == ">=1.0.0 <2.0.0"


def test_ratified_defaults() -> None:
    assert settings.AI_JOB_CONTEXT_MAX_TTL_SECONDS == 900
    assert settings.AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS == 5
    assert settings.AI_DISPATCH_CONTEXT_TTL_SECONDS == 30
    assert settings.AI_PROVIDER_ALLOWED_EXTERNAL_PORTS == "443"
    assert settings.AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED is False
    assert settings.AI_CAPABILITIES_ENABLED is None
    assert settings.AI_USER_BYOK_ENABLED is None


@pytest.mark.parametrize("key", REQUIRED_GATEWAY_KEYS)
def test_a_missing_required_key_fails(
    key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(key)
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert key in str(info.value)


def test_an_unknown_key_in_the_env_file_is_refused(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("AI_NOT_A_GATEWAY_KEY=1\n", encoding="utf-8")
    with pytest.raises(
        ValidationError, match="(?is)ai_not_a_gateway_key.*extra_forbidden"
    ):
        Settings(_env_file=env_file)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AI_CREDENTIAL_STORAGE_BACKEND", "filesystem"),
        ("AI_CREDENTIAL_KEK_PROVIDER", "plaintext"),
        ("AI_MAX_CREDENTIALS_PER_SCOPE", "0"),
        ("AI_DEPLOYMENT_ID", "not-a-uuid"),
        ("AI_JOB_CONTEXT_MAX_TTL_SECONDS", "changethis"),
    ],
)
def test_a_mistyped_value_fails(
    key: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(key, value)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_import_fails_fast_on_an_incomplete_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import auth_sdk_m8.utils.paths as paths_mod

    monkeypatch.setattr(paths_mod, "find_dotenv", lambda *_a, **_kw: "")
    monkeypatch.delenv("AI_DEPLOYMENT_ID")
    try:
        with pytest.raises(RuntimeError, match="Configuration validation error"):
            importlib.reload(config)
    finally:
        monkeypatch.undo()
        monkeypatch.setattr(paths_mod, "find_dotenv", lambda *_a, **_kw: "")
        importlib.reload(config)

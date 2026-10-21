"""
The configured credential store (R-10), built once in ``core/deps.py``.

* ``database`` + ``local`` — envelopes in ``ai_db``, data keys wrapped under
  the KEK file (the default);
* ``database`` + ``vault_transit`` — the same envelopes, data keys wrapped by
  a Vault transit key (the recommended hardened mode, ``T23``);
* ``vault`` KV (``T24``) is not served yet: a deployment configured for it
  refuses to start rather than run without a store.
"""

from __future__ import annotations

from sqlalchemy import Engine

from ai_gateway.core.config import Settings

from .database import DatabaseCredentialStore
from .fingerprints import FingerprintKeys
from .kek import KekProvider, LocalKekProvider
from .vault import VaultAccess, VaultTransitKekProvider


class UnsupportedBackendError(RuntimeError):
    """The configured backend has no store in this build."""


def _kek_provider(settings: Settings) -> KekProvider:
    if settings.AI_CREDENTIAL_KEK_PROVIDER == "vault_transit":
        assert settings.AI_VAULT_ADDR is not None  # nosec B101 - required at boot
        assert settings.AI_VAULT_AUTH_METHOD is not None  # nosec B101
        access = VaultAccess(
            settings.AI_VAULT_ADDR,
            settings.AI_VAULT_AUTH_METHOD,
            token_file=settings.AI_VAULT_TOKEN_FILE,
            role_id_file=settings.AI_VAULT_ROLE_ID_FILE,
            secret_id_file=settings.AI_VAULT_SECRET_ID_FILE,
            ca_file=settings.AI_VAULT_CA_FILE,
            timeout_seconds=settings.AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS,
        )
        return VaultTransitKekProvider(
            access,
            mount=str(settings.AI_VAULT_TRANSIT_MOUNT),
            key=str(settings.AI_VAULT_TRANSIT_KEY),
        )
    if settings.kek is None:  # the settings refuse this at boot
        raise UnsupportedBackendError("the local KEK provider needs a KEK file")
    return LocalKekProvider(settings.kek, settings.previous_keks)


def build_credential_store(
    settings: Settings, engine: Engine
) -> DatabaseCredentialStore:
    """The store ``settings`` select; refuse a backend not served yet."""
    if settings.AI_CREDENTIAL_STORAGE_BACKEND != "database":
        raise UnsupportedBackendError(
            "AI_CREDENTIAL_STORAGE_BACKEND=vault is not served by this build"
        )
    fingerprint_key = settings.fingerprint_key
    if fingerprint_key is None:  # the settings refuse this at boot
        raise UnsupportedBackendError("the database backend needs a fingerprint key")
    return DatabaseCredentialStore(
        engine,
        _kek_provider(settings),
        FingerprintKeys(fingerprint_key, settings.previous_fingerprint_key),
        resolve_timeout_seconds=settings.AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS,
    )


__all__ = ["UnsupportedBackendError", "build_credential_store"]

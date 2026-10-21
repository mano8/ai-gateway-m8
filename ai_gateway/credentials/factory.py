"""
The configured credential store (R-10), built once in ``core/deps.py``.

``database`` + ``local`` is served by
:class:`~ai_gateway.credentials.database.DatabaseCredentialStore` over
:class:`~ai_gateway.credentials.kek.LocalKekProvider`. ``database`` +
``vault_transit`` (``T23``) and ``vault`` KV (``T24``) are not served yet: a
deployment configured for them refuses to start rather than run without a
store.
"""

from __future__ import annotations

from sqlalchemy import Engine

from ai_gateway.core.config import Settings

from .database import DatabaseCredentialStore
from .fingerprints import FingerprintKeys
from .kek import LocalKekProvider


class UnsupportedBackendError(RuntimeError):
    """The configured backend has no store in this build."""


def build_credential_store(
    settings: Settings, engine: Engine
) -> DatabaseCredentialStore:
    """The store ``settings`` select; refuse a backend not served yet."""
    backend = settings.AI_CREDENTIAL_STORAGE_BACKEND
    provider = settings.AI_CREDENTIAL_KEK_PROVIDER
    if backend != "database" or provider != "local":
        raise UnsupportedBackendError(
            f"AI_CREDENTIAL_STORAGE_BACKEND={backend} with "
            f"AI_CREDENTIAL_KEK_PROVIDER={provider} is not served by this build"
        )
    kek, fingerprint_key = settings.kek, settings.fingerprint_key
    if kek is None or fingerprint_key is None:  # the settings refuse this at boot
        raise UnsupportedBackendError(
            "the database backend needs a KEK and a fingerprint key"
        )
    return DatabaseCredentialStore(
        engine,
        LocalKekProvider(kek, settings.previous_keks),
        FingerprintKeys(fingerprint_key, settings.previous_fingerprint_key),
        resolve_timeout_seconds=settings.AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS,
    )


__all__ = ["UnsupportedBackendError", "build_credential_store"]

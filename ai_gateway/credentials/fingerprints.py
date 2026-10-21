"""
Scope-bound credential fingerprints (D-23, T20).

A fingerprint is HMAC-SHA256 under a dedicated key file
(``AI_CREDENTIAL_FINGERPRINT_KEY_FILE``) over a purpose tag, the
credential's **scope** and the secret. It detects the same key stored twice
in one tenant's or one user's scope. Because the scope is inside the MAC,
the same key stored in two scopes has two unrelated fingerprints: no query,
response, error or timing can tie one scope's key to another's. A
fingerprint is never returned.

``fingerprint_key_version`` names the generation; during a rotation the
previous key (``AI_CREDENTIAL_FINGERPRINT_PREVIOUS_KEY_FILE``) still
matches, and ``refingerprint`` moves every row to the active key.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

from ai_gateway.core.keyfiles import KeyMaterial

from .envelope import length_prefixed
from .store import CredentialIdentity

_PURPOSE: Final = "m8.ai.credential-fingerprint.v1"


class FingerprintKeys:
    """The active fingerprint key and, during a rotation, the previous one."""

    def __init__(
        self, active: KeyMaterial, previous: KeyMaterial | None = None
    ) -> None:
        self._active = active.version("fingerprint")
        keys = (active,) if previous is None else (previous, active)
        self._keys = {key.version("fingerprint"): key for key in keys}

    def __repr__(self) -> str:
        return f"FingerprintKeys(active={self._active!r})"

    @property
    def active_version(self) -> str:
        """The generation new fingerprints use."""
        return self._active

    def generations(self) -> frozenset[str]:
        """Every configured generation."""
        return frozenset(self._keys)

    def compute(
        self, credential: CredentialIdentity, secret: bytes, version: str | None = None
    ) -> str:
        """The fingerprint of ``secret`` in ``credential``'s scope."""
        key = self._keys[version or self._active]
        message = (
            length_prefixed(
                _PURPOSE,
                credential.scope_type.value,
                None if credential.tenant_id is None else str(credential.tenant_id),
                None
                if credential.owner_user_id is None
                else str(credential.owner_user_id),
            )
            + len(secret).to_bytes(4, "big")
            + secret
        )
        return hmac.new(key.reveal(), message, hashlib.sha256).hexdigest()

    def all(self, credential: CredentialIdentity, secret: bytes) -> dict[str, str]:
        """The fingerprint under every configured generation."""
        return {
            version: self.compute(credential, secret, version) for version in self._keys
        }


__all__ = ["FingerprintKeys"]

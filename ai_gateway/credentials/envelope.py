"""
Envelope encryption of one credential version (D-23, C-05).

Each version gets a fresh random 256-bit data key (DEK), used exactly once:
the secret is sealed with AES-256-GCM under it with a random 96-bit nonce,
and the DEK is wrapped by the KEK provider. Both are bound to the same
additional data — the version's immutable row context — so ciphertext moved
to another row, or a row whose context changed, never decrypts.

The AAD is the length-prefixed concatenation of ``credential_id``,
``version``, ``provider_id``, ``scope_type``, ``tenant_id`` and
``owner_user_id``: each field's UTF-8 bytes preceded by their 4-byte
big-endian length, ``NULL`` as length 0, so no two contexts share an
encoding.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kek import NONCE_BYTES, KekError, KekProvider, WrappedKey
from .store import CredentialIdentity

#: The ``algorithm`` column value.
ALGORITHM: Final = "AES-256-GCM"

#: Data-key length.
DEK_BYTES: Final = 32


class EnvelopeError(Exception):
    """An envelope does not open; the message never names a cause."""


def length_prefixed(*fields: str | None) -> bytes:
    """Each field as a 4-byte big-endian length and its UTF-8 bytes."""
    encoded = bytearray()
    for field in fields:
        data = b"" if field is None else field.encode("utf-8")
        encoded += len(data).to_bytes(4, "big") + data
    return bytes(encoded)


def version_aad(credential: CredentialIdentity, version: int) -> bytes:
    """The C-05 additional data of ``credential``'s version ``version``."""
    return length_prefixed(
        str(credential.credential_id),
        str(version),
        str(credential.provider_id),
        credential.scope_type.value,
        None if credential.tenant_id is None else str(credential.tenant_id),
        None if credential.owner_user_id is None else str(credential.owner_user_id),
    )


@dataclass(frozen=True)
class Envelope:
    """The stored material of one version (the C-05 envelope columns)."""

    ciphertext: bytes
    nonce: bytes
    wrapped: WrappedKey
    kek_provider: str


def seal(plaintext: bytes, aad: bytes, kek: KekProvider) -> Envelope:
    """Encrypt ``plaintext`` under a fresh DEK and wrap the DEK."""
    dek = bytearray(os.urandom(DEK_BYTES))
    try:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, plaintext, aad)
        wrapped = kek.wrap(bytes(dek), aad)
    finally:
        dek[:] = bytes(DEK_BYTES)
    return Envelope(ciphertext, nonce, wrapped, kek.provider)


def open_envelope(envelope: Envelope, aad: bytes, kek: KekProvider) -> bytearray:
    """
    Decrypt ``envelope``; :class:`EnvelopeError` on any failure.

    Never returns partial plaintext: AES-GCM authenticates before it
    releases anything.
    """
    if envelope.kek_provider != kek.provider:
        raise EnvelopeError("envelope does not open")
    try:
        dek = bytearray(kek.unwrap(envelope.wrapped, aad))
    except KekError:
        raise EnvelopeError("envelope does not open") from None
    try:
        plaintext = AESGCM(bytes(dek)).decrypt(envelope.nonce, envelope.ciphertext, aad)
    except (InvalidTag, ValueError):
        raise EnvelopeError("envelope does not open") from None
    finally:
        dek[:] = bytes(len(dek))
    return bytearray(plaintext)


def rewrapped(envelope: Envelope, aad: bytes, kek: KekProvider) -> WrappedKey:
    """The envelope's DEK wrapped again under the active generation."""
    if envelope.kek_provider != kek.provider:
        raise EnvelopeError("envelope does not open")
    try:
        return kek.rewrap(envelope.wrapped, aad)
    except KekError:
        raise EnvelopeError("envelope does not open") from None


__all__ = [
    "ALGORITHM",
    "DEK_BYTES",
    "Envelope",
    "EnvelopeError",
    "length_prefixed",
    "open_envelope",
    "rewrapped",
    "seal",
    "version_aad",
]

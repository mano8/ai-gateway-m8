"""
The model and embedding-space identities the gateway derives (C-07, D-11).

``h(*parts)`` is the first 32 hex characters of the SHA-256 of the JCS
encoding of the JSON array ``[parts…]`` — the rule ``doctools_m8.revisions``
implements — so the gateway and its consumers compute the same identity
from the same inputs:

* ``execution_identity = h(provider_id, external_model_id, model_revision)``
  — a model row's identity, frozen from its first reservation; an OCR
  profile publishes it as ``ocr_execution_identity``;
* ``embedding_space_id = h(provider_id, external_model_id, model_revision,
  dimensions, execution_config_hash)`` — per model **and** profile revision,
  so it is derived where both are known, never stored on the model;
* ``execution_config_hash = SHA-256(JCS(execution_config))`` — the full
  64-hex digest of one immutable profile revision's configuration.

``provider_id`` is the canonical lower-case UUID text; an absent
``model_revision`` is JSON ``null``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Final
from uuid import UUID

from ai_sdk_m8.signed import canonicalize

#: Length of a C-07 identity: a 128-bit SHA-256 prefix.
IDENTITY_HEX_LENGTH: Final = 32


def identity_hash(*parts: object) -> str:
    """``h(*parts)``: the 32-hex SHA-256 prefix of ``JCS([parts…])``."""
    digest = hashlib.sha256(canonicalize(list(parts))).hexdigest()
    return digest[:IDENTITY_HEX_LENGTH]


def execution_identity(
    provider_id: UUID, external_model_id: str, model_revision: str | None
) -> str:
    """``h(provider_id, external_model_id, model_revision)``."""
    return identity_hash(str(provider_id), external_model_id, model_revision)


def embedding_space_id(
    provider_id: UUID,
    external_model_id: str,
    model_revision: str | None,
    dimensions: int,
    config_hash: str,
) -> str:
    """``h(provider_id, external_model_id, model_revision, dimensions, hash)``."""
    return identity_hash(
        str(provider_id), external_model_id, model_revision, dimensions, config_hash
    )


def execution_config_hash(config: Mapping[str, object]) -> str:
    """``SHA-256(JCS(execution_config))`` as 64 lower-case hex characters."""
    return hashlib.sha256(canonicalize(dict(config))).hexdigest()


__all__ = [
    "IDENTITY_HEX_LENGTH",
    "embedding_space_id",
    "execution_config_hash",
    "execution_identity",
    "identity_hash",
]

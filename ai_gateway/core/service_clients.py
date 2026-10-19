"""
The service-client registry (``AI_SERVICE_CLIENTS``, D-06, R-07).

``AI_SERVICE_CLIENTS`` is a JSON object in the issuer's
``PRIVATE_API_CONSUMERS`` shape::

    {"media-worker": {"secret": "sha256$<salt>$<digest>",
                      "scopes": ["execute:ocr"]},
     "media-service": {"secret": "sha256$…",
                       "scopes": ["execute:embedding", "job-context:issue"],
                       "job_context_public_keys": {"<kid>": "<base64url>"}}}

Secrets are stored only as the salted digest ``ConsumerCredential`` produces,
never in plaintext. Scopes are a closed, capability-precise set and deny by
default. An issuing client lists the public keys of its job-context signer;
each ``kid`` must be the one its key derives, and no key may be registered
under two clients.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from ai_sdk_m8.schemas import Capability, V1_CAPABILITIES
from ai_sdk_m8.signed import decode_public_key, derive_kid
from ai_sdk_m8.signed import SignedObjectError
from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError

from fastapi_m8 import ConsumerCredential, ConsumerCredentialRegistry

#: Scope that lets a client sign job contexts.
JOB_CONTEXT_ISSUE: Final = "job-context:issue"

#: Scope that lets a client read profiles without a user token.
PROFILES_READ: Final = "profiles:read"


def execute_scope(capability: Capability) -> str:
    """The scope a client needs to execute ``capability``."""
    return f"execute:{capability.value}"


#: Every scope a registered client may hold.
KNOWN_SCOPES: Final = frozenset(
    {execute_scope(c) for c in V1_CAPABILITIES} | {JOB_CONTEXT_ISSUE, PROFILES_READ}
)

#: Client ids, the same shape as a job context's ``iss``/``azp`` (C-03).
_CLIENT_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class ServiceClientConfigError(ValueError):
    """``AI_SERVICE_CLIENTS`` is malformed or contradictory."""


class _Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    secret: StrictStr
    scopes: list[StrictStr]
    job_context_public_keys: dict[StrictStr, StrictStr] = {}


@dataclass(frozen=True)
class ServiceClients:
    """The parsed registry: hashed secrets, scopes and issuer public keys."""

    registry: ConsumerCredentialRegistry
    scopes: Mapping[str, frozenset[str]]
    public_keys: Mapping[str, Mapping[str, bytes]]

    def issuer_keys(self, client_id: str) -> Mapping[str, bytes]:
        """The job-context public keys of ``client_id`` (empty if none)."""
        return self.public_keys.get(client_id, {})

    def all_public_keys(self) -> list[bytes]:
        """Every registered job-context public key."""
        return [key for keys in self.public_keys.values() for key in keys.values()]

    def has_scope(self, client_id: str, scope: str) -> bool:
        """Whether a registered client holds ``scope``."""
        return scope in self.scopes.get(client_id, frozenset())


def _parse_entry(
    client_id: str, raw: object
) -> tuple[ConsumerCredential, dict[str, bytes]]:
    if not _CLIENT_ID.fullmatch(client_id):
        raise ServiceClientConfigError(f"client id {client_id!r} is not a valid token")
    try:
        entry = _Entry.model_validate(raw)
    except ValidationError:
        raise ServiceClientConfigError(
            f"client {client_id!r} must be an object with secret, scopes and "
            "optional job_context_public_keys"
        ) from None
    if not entry.secret.startswith("sha256$"):
        raise ServiceClientConfigError(
            f"client {client_id!r}: the secret must be stored as its "
            "'sha256$<salt>$<digest>' encoding, never in plaintext"
        )
    scopes = frozenset(entry.scopes)
    if len(scopes) != len(entry.scopes):
        raise ServiceClientConfigError(f"client {client_id!r} repeats a scope")
    unknown = scopes - KNOWN_SCOPES
    if unknown:
        raise ServiceClientConfigError(
            f"client {client_id!r} has unknown scopes {sorted(unknown)}"
        )
    try:
        credential = ConsumerCredential.from_encoded(client_id, entry.secret, scopes)
    except ValueError:
        raise ServiceClientConfigError(
            f"client {client_id!r}: the secret encoding is malformed"
        ) from None
    keys: dict[str, bytes] = {}
    for kid, encoded in entry.job_context_public_keys.items():
        try:
            key = decode_public_key(encoded)
        except (SignedObjectError, ValueError):
            raise ServiceClientConfigError(
                f"client {client_id!r}: public key {kid!r} is not 32 bytes of "
                "unpadded base64url"
            ) from None
        if derive_kid(key) != kid:
            raise ServiceClientConfigError(
                f"client {client_id!r}: kid {kid!r} is not the one its key derives"
            )
        keys[kid] = key
    issues = JOB_CONTEXT_ISSUE in scopes
    if issues and not keys:
        raise ServiceClientConfigError(
            f"client {client_id!r} holds {JOB_CONTEXT_ISSUE} but lists no "
            "job_context_public_keys"
        )
    if keys and not issues:
        raise ServiceClientConfigError(
            f"client {client_id!r} lists job-context keys without {JOB_CONTEXT_ISSUE}"
        )
    return credential, keys


def parse_service_clients(raw: str) -> ServiceClients:
    """Parse and check ``AI_SERVICE_CLIENTS``."""
    try:
        document = json.loads(raw)
    except ValueError:
        raise ServiceClientConfigError("AI_SERVICE_CLIENTS is not valid JSON") from None
    if not isinstance(document, dict):
        raise ServiceClientConfigError("AI_SERVICE_CLIENTS must be a JSON object")
    credentials: list[ConsumerCredential] = []
    public_keys: dict[str, dict[str, bytes]] = {}
    owners: dict[bytes, str] = {}
    for client_id, value in document.items():
        credential, keys = _parse_entry(client_id, value)
        credentials.append(credential)
        for key in keys.values():
            if key in owners:
                raise ServiceClientConfigError(
                    f"one public key is registered under both {owners[key]!r} "
                    f"and {client_id!r}"
                )
            owners[key] = client_id
        if keys:
            public_keys[client_id] = keys
    return ServiceClients(
        registry=ConsumerCredentialRegistry(credentials),
        scopes={c.client_id: frozenset(c.scopes) for c in credentials},
        public_keys=public_keys,
    )


__all__ = [
    "JOB_CONTEXT_ISSUE",
    "KNOWN_SCOPES",
    "PROFILES_READ",
    "ServiceClientConfigError",
    "ServiceClients",
    "execute_scope",
    "parse_service_clients",
]

"""Job contexts signed as an issuer would, for the execution-guard tests (C-03)."""

from __future__ import annotations

import time
import uuid

from ai_sdk_m8.signed import (
    Domain,
    b64url_encode,
    derive_kid,
    public_key_from_seed,
    sign_object,
    signing_input,
)
from ai_sdk_m8.signed._keys import sign_bytes

from conftest import MEDIA_SERVICE, TEST_ENV, ServiceIdentity

#: The ``aud`` of the test installation.
AUDIENCE = f"ai-gateway/{TEST_ENV['AI_DEPLOYMENT_ID']}"

#: OCR input claims that satisfy the closed model for ``capability = ocr``.
OCR_SPOOL_CLAIMS: dict[str, object] = {
    "capability": "ocr",
    "phase": "spool",
    "input_sha256": "b" * 64,
    "input_bytes": 1024,
    "ocr_options_hash": "c" * 64,
}


def claims(
    issuer: ServiceIdentity = MEDIA_SERVICE,
    *,
    seed: bytes | None = None,
    **overrides: object,
) -> dict[str, object]:
    """A valid embedding context of ``issuer``; an override of ``None`` drops it."""
    now = int(time.time())
    key = seed or issuer.seed
    assert key is not None
    body: dict[str, object] = {
        "v": 1,
        "typ": Domain.JOB_CONTEXT.value,
        "kid": derive_kid(public_key_from_seed(key)),
        "iss": issuer.client_id,
        "aud": AUDIENCE,
        "azp": issuer.client_id,
        "data_class": "internal",
        "capability": "embedding",
        "profile_key": "embed-default",
        "job_ref": "run-1",
        "attempt": 1,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "max_uses": 1,
    }
    body.update(overrides)
    return {name: value for name, value in body.items() if value is not None}


def mint(
    issuer: ServiceIdentity = MEDIA_SERVICE,
    *,
    seed: bytes | None = None,
    domain: Domain = Domain.JOB_CONTEXT,
    **overrides: object,
) -> str:
    """Sign :func:`claims` under ``domain`` with ``seed`` (default: the issuer's)."""
    key = seed or issuer.seed
    assert key is not None
    body = claims(issuer, seed=key, **overrides)
    if domain is not Domain.JOB_CONTEXT and "typ" not in overrides:
        body["typ"] = domain.value
    return sign_object(body, domain=domain, seed=key)


def raw_token(
    payload: bytes,
    seed: bytes | None = None,
    *,
    domain: Domain = Domain.JOB_CONTEXT,
    pad: bool = False,
) -> str:
    """A compact token over exactly ``payload``, correctly signed by ``seed``."""
    key = seed or MEDIA_SERVICE.seed
    assert key is not None
    segment = b64url_encode(payload) + ("==" if pad else "")
    signature = b64url_encode(sign_bytes(key, signing_input(domain, payload)))
    return f"{segment}.{signature}"

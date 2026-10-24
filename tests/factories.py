"""Row factories for database tests (Core inserts, no controller logic)."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, insert, update

from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.credential_version import ai_credential_version
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_binding,
    ai_profile_revision,
    ai_provider,
)

IDENTITY = "0123456789abcdef0123456789abcdef"
HASH = "a" * 64


def provider(c: Connection, **values: Any) -> uuid.UUID:
    row = {
        "id": uuid.uuid4(),
        "name": "provider",
        "provider_type": "openai_compatible",
        "base_url": "https://api.example.com",
        "auth_type": "bearer",
        "boundary": "external",
        **values,
    }
    c.execute(insert(ai_provider).values(**row))
    return row["id"]


def model(c: Connection, provider_id: uuid.UUID, **values: Any) -> uuid.UUID:
    row = {
        "id": uuid.uuid4(),
        "provider_id": provider_id,
        "external_model_id": "embed-small",
        "capabilities": ["embedding"],
        "dimensions": 768,
        "model_version_label": "v1",
        "identity_assurance": "operator_declared",
        "execution_identity": IDENTITY,
        **values,
    }
    c.execute(insert(ai_model).values(**row))
    return row["id"]


def profile(
    c: Connection, key: str | None = None, capability: str = "embedding"
) -> uuid.UUID:
    profile_id = uuid.uuid4()
    c.execute(
        insert(ai_profile).values(
            id=profile_id,
            profile_key=key or f"p{secrets.token_hex(4)}",
            capability=capability,
            current_revision=1,
        )
    )
    c.execute(
        insert(ai_profile_revision).values(
            profile_id=profile_id,
            revision=1,
            execution_config={},
            execution_config_hash=HASH,
        )
    )
    return profile_id


def credential(
    c: Connection,
    provider_id: uuid.UUID,
    *,
    scope_type: str = "tenant",
    tenant_id: uuid.UUID | None = None,
    owner_user_id: uuid.UUID | None = None,
    status: str = "active",
) -> uuid.UUID:
    """An active credential with committed version 1 (database backend)."""
    credential_id = uuid.uuid4()
    if scope_type == "tenant" and tenant_id is None:
        tenant_id = uuid.uuid4()
    if scope_type == "user" and owner_user_id is None:
        owner_user_id = uuid.uuid4()
    c.execute(
        insert(ai_credential).values(
            id=credential_id,
            scope_type=scope_type,
            tenant_id=tenant_id,
            owner_user_id=owner_user_id,
            provider_id=provider_id,
            name="key",
            status=status,
            secret_backend="database",
            current_version=1 if status == "active" else None,
            next_version=2,
        )
    )
    version(c, credential_id, 1)
    return credential_id


def version(
    c: Connection, credential_id: uuid.UUID, number: int, *, committed: bool = True
) -> None:
    c.execute(
        insert(ai_credential_version).values(
            credential_id=credential_id,
            version=number,
            ciphertext=b"c",
            nonce=b"n" * 12,
            wrapped_dek=b"w",
            wrap_nonce=b"x" * 12,
            algorithm="AES-256-GCM",
            kek_provider="local",
            kek_key_version="kek-0",
            fingerprint="f" * 64,
            fingerprint_key_version="fingerprint-0",
            prepare_id=secrets.token_hex(16),
            material_committed_at=datetime.now(UTC) if committed else None,
        )
    )


def binding(
    c: Connection,
    profile_id: uuid.UUID,
    model_id: uuid.UUID,
    credential_id: uuid.UUID | None = None,
    *,
    scope_type: str = "global",
    tenant_id: uuid.UUID | None = None,
    owner_user_id: uuid.UUID | None = None,
) -> uuid.UUID:
    binding_id = uuid.uuid4()
    c.execute(
        insert(ai_profile_binding).values(
            id=binding_id,
            profile_id=profile_id,
            scope_type=scope_type,
            tenant_id=tenant_id,
            owner_user_id=owner_user_id,
            model_id=model_id,
            credential_id=credential_id,
        )
    )
    return binding_id


def resolved_world(c: Connection) -> dict[str, uuid.UUID]:
    """A provider, model, profile and credential an execution can record."""
    provider_id = provider(c)
    model_id = model(c, provider_id)
    profile_id = profile(c)
    credential_id = credential(c, provider_id)
    return {
        "provider_id": provider_id,
        "model_id": model_id,
        "profile_id": profile_id,
        "credential_id": credential_id,
    }


def execution(
    c: Connection, world: dict[str, uuid.UUID], *, ocr: bool = False, **values: Any
) -> uuid.UUID:
    """A ``pending`` execution (or ``receiving`` for OCR)."""
    now = datetime.now(UTC)
    row: dict[str, Any] = {
        "id": uuid.uuid4(),
        "capability": "ocr" if ocr else "embedding",
        "profile_key": "p",
        "data_class": "internal",
        "client_scope_id": "media-service",
        "jti": str(uuid.uuid4()),
        "issuer": "media-service",
        "azp": "media-service",
        "job_ref": "run-1",
        "attempt": 1,
    }
    if ocr:
        row |= {
            "status": "receiving",
            "input_sha256": "b" * 64,
            "input_bytes": 10,
            "ocr_options_hash": "c" * 64,
            "spool_lease_until": now + timedelta(minutes=2),
            "spool_bytes_reserved": 4096,
        }
    else:
        row |= reservation(world, now) | {"status": "pending"}
    row.update(values)
    c.execute(insert(ai_execution).values(**row))
    return row["id"]


def reservation(world: dict[str, uuid.UUID], now: datetime) -> dict[str, Any]:
    """The columns the reservation transaction records (``→ pending``)."""
    return {
        "reserved_units": 10,
        "reservation_day": now.date(),
        "reservation_expires_at": now + timedelta(minutes=1),
        "resolved_provider_id": world["provider_id"],
        "resolved_boundary": "external",
        "resolved_model_id": world["model_id"],
        "resolved_profile_id": world["profile_id"],
        "resolved_profile_revision": 1,
        "resolved_credential_id": world["credential_id"],
        "resolved_credential_version": 1,
        "context_exp": now + timedelta(minutes=1),
    }


def set_status(
    c: Connection, execution_id: uuid.UUID, status: str, **values: Any
) -> int:
    """CAS-free status update; returns the row count."""
    result = c.execute(
        update(ai_execution)
        .where(ai_execution.c.id == execution_id)
        .values(status=status, **values)
    )
    return result.rowcount


def artifact(
    c: Connection,
    world: dict[str, uuid.UUID],
    execution_id: uuid.UUID,
    **values: Any,
) -> uuid.UUID:
    row = {
        "id": uuid.uuid4(),
        "execution_id": execution_id,
        "provider_id": world["provider_id"],
        "credential_id": world["credential_id"],
        "credential_version": 1,
        "gateway_file_name": f"m8ai-test-{uuid.uuid4()}",
        "status": "uploading",
        "upload_deadline_at": datetime.now(UTC) + timedelta(minutes=2),
        **values,
    }
    c.execute(insert(ai_provider_remote_artifact).values(**row))
    return row["id"]

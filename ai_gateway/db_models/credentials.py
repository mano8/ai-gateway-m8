"""The credential row (D-05, D-23, C-05). Its versions live in ``credential_version``."""

from __future__ import annotations

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import CredentialStatus, ScopeType

from ._common import (
    TIMESTAMP,
    created_at,
    metadata,
    one_of,
    scope_shape_check,
    updated_at,
)

ai_credential = sa.Table(
    "ai_credential",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column("scope_type", sa.Text, nullable=False),
    sa.Column("tenant_id", sa.Uuid, nullable=True),
    sa.Column("owner_user_id", sa.Uuid, nullable=True),
    sa.Column(
        "provider_id",
        sa.Uuid,
        sa.ForeignKey("ai_provider.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    ),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("secret_backend", sa.Text, nullable=False),
    sa.Column("current_version", sa.Integer, nullable=True),
    sa.Column("next_version", sa.Integer, nullable=False, server_default=sa.text("1")),
    sa.Column(
        "auth_failure_count", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("throttled_until", TIMESTAMP, nullable=True),
    sa.Column(
        "incident_listing_consent",
        sa.Boolean,
        nullable=False,
        server_default=sa.false(),
    ),
    sa.Column("secret_hint", sa.Text, nullable=True),
    sa.Column("last_validated_at", TIMESTAMP, nullable=True),
    sa.Column("deleted_at", TIMESTAMP, nullable=True),
    created_at(),
    updated_at(),
    one_of("scope_type", ScopeType, "ck_ai_credential_scope_type"),
    one_of("status", CredentialStatus, "ck_ai_credential_status"),
    one_of("secret_backend", ("database", "vault"), "ck_ai_credential_secret_backend"),
    scope_shape_check("ck_ai_credential_scope_shape"),
    sa.CheckConstraint(
        "status <> 'active' OR current_version IS NOT NULL",
        name="ck_ai_credential_active_has_version",
    ),
    sa.CheckConstraint(
        "next_version >= 1 AND (current_version IS NULL OR current_version < next_version)",
        name="ck_ai_credential_versions",
    ),
    sa.CheckConstraint(
        "auth_failure_count >= 0", name="ck_ai_credential_auth_failures"
    ),
    sa.CheckConstraint(
        "secret_hint IS NULL OR char_length(secret_hint) = 4",
        name="ck_ai_credential_secret_hint",
    ),
    sa.CheckConstraint(
        "(status = 'deleted') = (deleted_at IS NOT NULL)",
        name="ck_ai_credential_deleted_at",
    ),
    sa.ForeignKeyConstraint(
        ["id", "current_version"],
        ["ai_credential_version.credential_id", "ai_credential_version.version"],
        name="fk_ai_credential_current_version",
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
        use_alter=True,
    ),
    sa.Index("ix_ai_credential_scope", "scope_type", "tenant_id", "owner_user_id"),
)

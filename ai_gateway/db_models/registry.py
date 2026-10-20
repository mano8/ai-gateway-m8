"""Providers, models, profiles with immutable revisions, and bindings."""

from __future__ import annotations

import sqlalchemy as sa
from ai_sdk_m8.schemas import V1_CAPABILITIES, IdentityAssurance, ProviderBoundary
from ai_sdk_m8.schemas.management import (
    AuthType,
    BindingStatus,
    OnUnavailable,
    ProviderType,
    ScopeType,
)
from sqlalchemy.dialects import postgresql

from ._common import (
    TIMESTAMP,
    created_at,
    metadata,
    one_of,
    scope_shape_check,
    sql_list,
    updated_at,
)

ai_provider = sa.Table(
    "ai_provider",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("provider_type", sa.Text, nullable=False),
    sa.Column("base_url", sa.Text, nullable=False),
    sa.Column("auth_type", sa.Text, nullable=False),
    sa.Column("auth_header_name", sa.Text, nullable=True),
    sa.Column("boundary", sa.Text, nullable=False),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("first_used_at", TIMESTAMP, nullable=True),
    created_at(),
    updated_at(),
    one_of("provider_type", ProviderType, "ck_ai_provider_type"),
    one_of("auth_type", AuthType, "ck_ai_provider_auth_type"),
    one_of("boundary", ProviderBoundary, "ck_ai_provider_boundary"),
    sa.CheckConstraint(
        "(auth_type = 'api_key_header') = (auth_header_name IS NOT NULL)",
        name="ck_ai_provider_header_matches_auth",
    ),
    sa.CheckConstraint(
        "char_length(base_url) <= 2048", name="ck_ai_provider_base_url_length"
    ),
)

ai_model = sa.Table(
    "ai_model",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column(
        "provider_id",
        sa.Uuid,
        sa.ForeignKey("ai_provider.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    ),
    sa.Column("external_model_id", sa.Text, nullable=False),
    sa.Column("capabilities", postgresql.ARRAY(sa.Text), nullable=False),
    sa.Column("context_window", sa.Integer, nullable=True),
    sa.Column("max_output_tokens", sa.Integer, nullable=True),
    sa.Column("dimensions", sa.Integer, nullable=True),
    sa.Column("model_version_label", sa.Text, nullable=False),
    sa.Column("model_revision", sa.Text, nullable=True),
    sa.Column("identity_assurance", sa.Text, nullable=False),
    sa.Column("execution_identity", sa.Text, nullable=False),
    sa.Column(
        "metadata",
        postgresql.JSONB,
        nullable=False,
        server_default=sa.text("'{}'::jsonb"),
    ),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("flagged_at", TIMESTAMP, nullable=True),
    sa.Column("first_used_at", TIMESTAMP, nullable=True),
    created_at(),
    updated_at(),
    one_of("identity_assurance", IdentityAssurance, "ck_ai_model_identity_assurance"),
    sa.CheckConstraint(
        f"cardinality(capabilities) >= 1 AND capabilities <@ "
        f"ARRAY[{sql_list(V1_CAPABILITIES)}]::text[]",
        name="ck_ai_model_capabilities",
    ),
    sa.CheckConstraint(
        "NOT ('embedding' = ANY(capabilities)) OR dimensions IS NOT NULL",
        name="ck_ai_model_embedding_dimensions",
    ),
    sa.CheckConstraint(
        "(dimensions IS NULL OR dimensions > 0)"
        " AND (context_window IS NULL OR context_window > 0)"
        " AND (max_output_tokens IS NULL OR max_output_tokens > 0)",
        name="ck_ai_model_positive_sizes",
    ),
    sa.CheckConstraint(
        "execution_identity ~ '^[0-9a-f]{32}$'", name="ck_ai_model_execution_identity"
    ),
    sa.CheckConstraint(
        "octet_length(metadata::text) <= 4096", name="ck_ai_model_metadata_size"
    ),
)

ai_profile = sa.Table(
    "ai_profile",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column("profile_key", sa.Text, nullable=False, unique=True),
    sa.Column("capability", sa.Text, nullable=False),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("current_revision", sa.Integer, nullable=False),
    created_at(),
    updated_at(),
    one_of("capability", V1_CAPABILITIES, "ck_ai_profile_capability"),
    sa.CheckConstraint(
        "profile_key ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'",
        name="ck_ai_profile_key",
    ),
    sa.ForeignKeyConstraint(
        ["id", "current_revision"],
        ["ai_profile_revision.profile_id", "ai_profile_revision.revision"],
        name="fk_ai_profile_current_revision",
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
        use_alter=True,
    ),
)

ai_profile_revision = sa.Table(
    "ai_profile_revision",
    metadata,
    sa.Column(
        "profile_id",
        sa.Uuid,
        sa.ForeignKey("ai_profile.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("revision", sa.Integer, primary_key=True),
    sa.Column("execution_config", postgresql.JSONB, nullable=False),
    sa.Column("execution_config_hash", sa.Text, nullable=False),
    created_at(),
    sa.CheckConstraint("revision >= 1", name="ck_ai_profile_revision_positive"),
    sa.CheckConstraint(
        "execution_config_hash ~ '^[0-9a-f]{64}$'",
        name="ck_ai_profile_revision_hash",
    ),
    sa.CheckConstraint(
        "octet_length(execution_config::text) <= 8192",
        name="ck_ai_profile_revision_config_size",
    ),
)

ai_profile_binding = sa.Table(
    "ai_profile_binding",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column(
        "profile_id",
        sa.Uuid,
        sa.ForeignKey("ai_profile.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    sa.Column("scope_type", sa.Text, nullable=False),
    sa.Column("tenant_id", sa.Uuid, nullable=True),
    sa.Column("owner_user_id", sa.Uuid, nullable=True),
    sa.Column(
        "model_id",
        sa.Uuid,
        sa.ForeignKey("ai_model.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    sa.Column(
        "credential_id",
        sa.Uuid,
        sa.ForeignKey("ai_credential.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    ),
    sa.Column(
        "on_unavailable",
        sa.Text,
        nullable=False,
        server_default=OnUnavailable.FAIL.value,
    ),
    sa.Column(
        "status",
        sa.Text,
        nullable=False,
        server_default=BindingStatus.ACTIVE.value,
    ),
    created_at(),
    updated_at(),
    one_of("scope_type", ScopeType, "ck_ai_profile_binding_scope_type"),
    one_of("on_unavailable", OnUnavailable, "ck_ai_profile_binding_on_unavailable"),
    one_of("status", BindingStatus, "ck_ai_profile_binding_status"),
    scope_shape_check("ck_ai_profile_binding_scope_shape"),
    sa.UniqueConstraint(
        "profile_id",
        "scope_type",
        "tenant_id",
        "owner_user_id",
        name="uq_ai_profile_binding_scope",
        postgresql_nulls_not_distinct=True,
    ),
)

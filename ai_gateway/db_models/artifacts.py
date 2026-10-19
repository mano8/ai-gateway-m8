"""Provider-side temporary files tracked from before their first byte (D-43)."""

from __future__ import annotations

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import RemoteArtifactStatus

from ._common import TIMESTAMP, created_at, metadata, one_of

#: Why a row needs a human: the D-43 reasons.
MANUAL_CLEANUP_REASONS = (
    "absence_unproven",
    "listing_not_permitted",
    "material_lost",
    "attempts_exhausted",
    "pending_hours_exceeded",
)

ai_provider_remote_artifact = sa.Table(
    "ai_provider_remote_artifact",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column(
        "execution_id",
        sa.Uuid,
        sa.ForeignKey("ai_execution.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    ),
    sa.Column(
        "provider_id",
        sa.Uuid,
        sa.ForeignKey("ai_provider.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    sa.Column(
        "credential_id",
        sa.Uuid,
        sa.ForeignKey("ai_credential.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    sa.Column("credential_version", sa.Integer, nullable=False),
    sa.Column("gateway_file_name", sa.Text, nullable=False, unique=True),
    sa.Column("remote_artifact_id", sa.Text, nullable=True),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("status_reason", sa.Text, nullable=True),
    sa.Column("upload_deadline_at", TIMESTAMP, nullable=False),
    sa.Column("provider_expires_at", TIMESTAMP, nullable=True),
    sa.Column(
        "negative_listings", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("first_negative_listing_at", TIMESTAMP, nullable=True),
    sa.Column(
        "delete_attempts", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("next_attempt_at", TIMESTAMP, nullable=True),
    sa.Column("last_error_class", sa.Text, nullable=True),
    sa.Column("claim_epoch", sa.BigInteger, nullable=True),
    sa.Column("claim_holder_token", sa.Text, nullable=True),
    sa.Column("claim_until", TIMESTAMP, nullable=True),
    created_at(),
    sa.ForeignKeyConstraint(
        ["credential_id", "credential_version"],
        ["ai_credential_version.credential_id", "ai_credential_version.version"],
        name="fk_ai_provider_remote_artifact_version",
        ondelete="RESTRICT",
    ),
    one_of("status", RemoteArtifactStatus, "ck_ai_provider_remote_artifact_status"),
    sa.CheckConstraint(
        "status NOT IN ('active', 'pending_delete') OR remote_artifact_id IS NOT NULL",
        name="ck_ai_provider_remote_artifact_has_id",
    ),
    sa.CheckConstraint(
        "(status = 'manual_cleanup_required') = (status_reason IS NOT NULL)",
        name="ck_ai_provider_remote_artifact_reason",
    ),
    one_of(
        "coalesce(status_reason, 'absence_unproven')",
        MANUAL_CLEANUP_REASONS,
        "ck_ai_provider_remote_artifact_reason_value",
    ),
    sa.CheckConstraint(
        "negative_listings >= 0 AND delete_attempts >= 0",
        name="ck_ai_provider_remote_artifact_counters",
    ),
    sa.CheckConstraint(
        "(claim_epoch IS NULL) = (claim_holder_token IS NULL)"
        " AND (claim_epoch IS NULL) = (claim_until IS NULL)",
        name="ck_ai_provider_remote_artifact_claim",
    ),
    sa.Index("ix_ai_provider_remote_artifact_status", "status"),
    sa.Index(
        "ix_ai_provider_remote_artifact_version", "credential_id", "credential_version"
    ),
)

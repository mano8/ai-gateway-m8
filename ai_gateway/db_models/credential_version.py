"""
Credential versions: the envelope or the KV locator of each version (C-05).

Only ``ai_gateway/credentials/`` may import this module (``ruff`` ``TID251``).
Rows are never deleted: destruction clears the material and stamps
``material_destroyed_at``; a rolled-back prepare keeps its row with
``aborted_at`` so its number is never reused.
"""

from __future__ import annotations

import sqlalchemy as sa

from ._common import TIMESTAMP, created_at, metadata

ai_credential_version = sa.Table(
    "ai_credential_version",
    metadata,
    sa.Column(
        "credential_id",
        sa.Uuid,
        sa.ForeignKey("ai_credential.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("version", sa.Integer, primary_key=True),
    sa.Column("ciphertext", sa.LargeBinary, nullable=True),
    sa.Column("nonce", sa.LargeBinary, nullable=True),
    sa.Column("wrapped_dek", sa.LargeBinary, nullable=True),
    sa.Column("wrap_nonce", sa.LargeBinary, nullable=True),
    sa.Column("algorithm", sa.Text, nullable=True),
    sa.Column("kek_provider", sa.Text, nullable=True),
    sa.Column("kek_key_id", sa.Text, nullable=True),
    sa.Column("kek_key_version", sa.Text, nullable=True),
    sa.Column("kv_path", sa.Text, nullable=True),
    sa.Column("fingerprint", sa.Text, nullable=True),
    sa.Column("fingerprint_key_version", sa.Text, nullable=True),
    sa.Column("prepare_id", sa.Text, nullable=False),
    sa.Column("base_version", sa.Integer, nullable=True),
    sa.Column("material_committed_at", TIMESTAMP, nullable=True),
    sa.Column("material_destroyed_at", TIMESTAMP, nullable=True),
    sa.Column("material_lost_at", TIMESTAMP, nullable=True),
    sa.Column("aborted_at", TIMESTAMP, nullable=True),
    sa.Column("last_upload_deadline_at", TIMESTAMP, nullable=True),
    sa.Column("reconciled_through", TIMESTAMP, nullable=True),
    sa.Column("sweep_discharge_at", TIMESTAMP, nullable=True),
    created_at(),
    sa.CheckConstraint("version >= 1", name="ck_ai_credential_version_positive"),
    sa.CheckConstraint(
        "prepare_id ~ '^[0-9a-f]{32}$'", name="ck_ai_credential_version_prepare_id"
    ),
    sa.CheckConstraint(
        "(ciphertext IS NULL) = (nonce IS NULL)"
        " AND (ciphertext IS NULL) = (wrapped_dek IS NULL)"
        " AND (ciphertext IS NULL) = (algorithm IS NULL)"
        " AND (ciphertext IS NULL) = (kek_provider IS NULL)"
        " AND (ciphertext IS NULL) = (kek_key_version IS NULL)",
        name="ck_ai_credential_version_envelope_whole",
    ),
    sa.CheckConstraint(
        "material_destroyed_at IS NULL OR (ciphertext IS NULL AND wrap_nonce IS NULL"
        " AND fingerprint IS NULL)",
        name="ck_ai_credential_version_destroyed_has_no_material",
    ),
    sa.CheckConstraint(
        "(fingerprint IS NULL) = (fingerprint_key_version IS NULL)",
        name="ck_ai_credential_version_fingerprint_key",
    ),
    sa.CheckConstraint(
        "aborted_at IS NULL OR material_committed_at IS NULL",
        name="ck_ai_credential_version_aborted_uncommitted",
    ),
    sa.CheckConstraint(
        "ciphertext IS NULL OR kv_path IS NULL",
        name="ck_ai_credential_version_one_backend",
    ),
    sa.CheckConstraint(
        "algorithm IS NULL OR algorithm = 'AES-256-GCM'",
        name="ck_ai_credential_version_algorithm",
    ),
)

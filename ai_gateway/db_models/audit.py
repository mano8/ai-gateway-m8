"""
Audit trails (S-11).

The runtime role may only insert and read these rows; a trigger refuses every
update, and only the owner role's ``audit-prune`` may delete. ``metadata`` is
capped at 4 KiB and never carries a secret.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from typing import Any

from ._common import TIMESTAMP, json_bounded, metadata, one_of

ACTOR_KINDS = ("user", "service", "system", "operator")


def _audit_columns() -> list[sa.Column[Any]]:
    return [
        sa.Column("id", sa.BigInteger, sa.Identity(always=True), primary_key=True),
        sa.Column(
            "occurred_at", TIMESTAMP, nullable=False, server_default=sa.func.now()
        ),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("actor_kind", sa.Text, nullable=False),
        sa.Column("actor_id", sa.Text, nullable=True),
        sa.Column("actor_role", sa.Text, nullable=True),
        sa.Column("request_id", sa.Text, nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    ]


ai_credential_audit = sa.Table(
    "ai_credential_audit",
    metadata,
    *_audit_columns(),
    sa.Column("credential_id", sa.Uuid, nullable=True, index=True),
    sa.Column("scope_type", sa.Text, nullable=True),
    sa.Column("tenant_id", sa.Uuid, nullable=True),
    sa.Column("owner_user_id", sa.Uuid, nullable=True),
    one_of("actor_kind", ACTOR_KINDS, "ck_ai_credential_audit_actor_kind"),
    json_bounded("metadata", "ck_ai_credential_audit_metadata_size"),
)

ai_admin_audit = sa.Table(
    "ai_admin_audit",
    metadata,
    *_audit_columns(),
    sa.Column("target_type", sa.Text, nullable=False),
    sa.Column("target_id", sa.Text, nullable=True),
    one_of("actor_kind", ACTOR_KINDS, "ck_ai_admin_audit_actor_kind"),
    json_bounded("metadata", "ck_ai_admin_audit_metadata_size"),
)

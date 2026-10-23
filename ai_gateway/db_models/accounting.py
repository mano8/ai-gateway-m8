"""
Executions and the counters that bound them (D-24, D-44, D-45).

``ai_execution`` carries exactly the D-24 transition table; its CHECK
constraints tie every nullable field to the statuses that own it, and a
trigger refuses every transition outside the table.
"""

from __future__ import annotations

import sqlalchemy as sa
from ai_sdk_m8.schemas import V1_CAPABILITIES, DataClass, ProviderBoundary
from sqlalchemy.dialects import postgresql

from ._common import (
    TERMINAL_STATUSES,
    TIMESTAMP,
    ExecutionStatus,
    created_at,
    metadata,
    one_of,
    sql_list,
    updated_at,
)

#: Single-use redemption of a job context, keyed by its issuer (C-03).
ai_job_context_use = sa.Table(
    "ai_job_context_use",
    metadata,
    sa.Column("iss", sa.Text, primary_key=True),
    sa.Column("jti", sa.Text, primary_key=True),
    sa.Column("uses", sa.Integer, nullable=False, server_default=sa.text("1")),
    sa.Column("max_uses", sa.Integer, nullable=False),
    sa.Column("exp", TIMESTAMP, nullable=False, index=True),
    created_at(),
    sa.CheckConstraint(
        "max_uses >= 1 AND uses >= 1 AND uses <= max_uses",
        name="ck_ai_job_context_use_uses",
    ),
)

#: Per-scope, per-UTC-day admission units: reserved and settled (D-24).
ai_usage = sa.Table(
    "ai_usage",
    metadata,
    sa.Column("scope_type", sa.Text, primary_key=True),
    sa.Column("scope_id", sa.Text, primary_key=True),
    sa.Column("day", sa.Date, primary_key=True),
    sa.Column("reserved", sa.BigInteger, nullable=False, server_default=sa.text("0")),
    sa.Column("used", sa.BigInteger, nullable=False, server_default=sa.text("0")),
    one_of("scope_type", ("client", "tenant", "user"), "ck_ai_usage_scope_type"),
    sa.CheckConstraint("reserved >= 0 AND used >= 0", name="ck_ai_usage_non_negative"),
)

#: One admission per execution per principal and minute window (D-24).
ai_rate_window = sa.Table(
    "ai_rate_window",
    metadata,
    sa.Column("principal_key", sa.Text, primary_key=True),
    sa.Column("window_start", TIMESTAMP, primary_key=True),
    sa.Column("count", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.CheckConstraint("count >= 0", name="ck_ai_rate_window_count"),
)

#: In-flight slots per service client, held from row creation to terminal.
ai_client_occupancy = sa.Table(
    "ai_client_occupancy",
    metadata,
    sa.Column("client_id", sa.Text, primary_key=True),
    sa.Column("occupied", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.CheckConstraint("occupied >= 0", name="ck_ai_client_occupancy_non_negative"),
)

#: One row: the spool bytes reserved across every replica (D-45).
ai_spool_capacity = sa.Table(
    "ai_spool_capacity",
    metadata,
    sa.Column("id", sa.SmallInteger, primary_key=True, server_default=sa.text("1")),
    sa.Column(
        "reserved_bytes", sa.BigInteger, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("max_bytes", sa.BigInteger, nullable=False, server_default=sa.text("0")),
    sa.CheckConstraint("id = 1", name="ck_ai_spool_capacity_single_row"),
    sa.CheckConstraint(
        "reserved_bytes >= 0 AND max_bytes >= 0", name="ck_ai_spool_capacity_bytes"
    ),
)

_TERMINAL = sql_list(TERMINAL_STATUSES)
_DISPATCHED = sql_list(
    {
        ExecutionStatus.DISPATCHING,
        ExecutionStatus.OK,
        ExecutionStatus.FAILED,
        ExecutionStatus.CHARGED_UNCERTAIN,
    }
)

ai_execution = sa.Table(
    "ai_execution",
    metadata,
    sa.Column("id", sa.Uuid, primary_key=True),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("capability", sa.Text, nullable=False),
    sa.Column("profile_key", sa.Text, nullable=False),
    sa.Column("data_class", sa.Text, nullable=False),
    sa.Column("client_scope_id", sa.Text, nullable=False),
    sa.Column("user_scope_id", sa.Text, nullable=True),
    sa.Column("tenant_scope_id", sa.Text, nullable=True),
    sa.Column("jti", sa.Text, nullable=False),
    sa.Column("issuer", sa.Text, nullable=False),
    sa.Column("azp", sa.Text, nullable=False),
    sa.Column("job_ref", sa.Text, nullable=False),
    sa.Column("attempt", sa.Integer, nullable=False),
    sa.Column("input_sha256", sa.Text, nullable=True),
    sa.Column("input_bytes", sa.BigInteger, nullable=True),
    sa.Column("ocr_options_hash", sa.Text, nullable=True),
    # Phase 1's validated options and pin, recorded at spooled and reused by
    # :dispatch (which has no body); frozen once the row leaves receiving.
    sa.Column("ocr_options", postgresql.JSONB, nullable=True),
    sa.Column("expected_execution_identity", sa.Text, nullable=True),
    sa.Column("reserved_units", sa.BigInteger, nullable=True),
    sa.Column("reservation_day", sa.Date, nullable=True),
    sa.Column("reservation_expires_at", TIMESTAMP, nullable=True),
    sa.Column("dispatched_at", TIMESTAMP, nullable=True),
    sa.Column("dispatch_deadline_at", TIMESTAMP, nullable=True),
    sa.Column("first_byte_sent_at", TIMESTAMP, nullable=True),
    sa.Column("spool_lease_until", TIMESTAMP, nullable=True),
    sa.Column("spool_expires_at", TIMESTAMP, nullable=True),
    sa.Column("spool_bytes_reserved", sa.BigInteger, nullable=True),
    sa.Column(
        "spool_file_created", sa.Boolean, nullable=False, server_default=sa.false()
    ),
    sa.Column("cleanup_pending", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column(
        "resolved_provider_id",
        sa.Uuid,
        sa.ForeignKey("ai_provider.id", ondelete="RESTRICT"),
        nullable=True,
    ),
    sa.Column("resolved_boundary", sa.Text, nullable=True),
    sa.Column(
        "resolved_model_id",
        sa.Uuid,
        sa.ForeignKey("ai_model.id", ondelete="RESTRICT"),
        nullable=True,
    ),
    sa.Column("resolved_profile_id", sa.Uuid, nullable=True),
    sa.Column("resolved_profile_revision", sa.Integer, nullable=True),
    # Values, not foreign keys: the version the material fetch must use.
    sa.Column("resolved_credential_id", sa.Uuid, nullable=True),
    sa.Column("resolved_credential_version", sa.Integer, nullable=True),
    sa.Column("context_exp", TIMESTAMP, nullable=True),
    sa.Column("execution_identity", sa.Text, nullable=True),
    sa.Column("embedding_space_id", sa.Text, nullable=True),
    sa.Column("provider_usage", postgresql.JSONB, nullable=True),
    sa.Column("error_class", sa.Text, nullable=True),
    sa.Column("occupancy_released_at", TIMESTAMP, nullable=True),
    sa.Column("reconciled_at", TIMESTAMP, nullable=True),
    sa.Column("settled_at", TIMESTAMP, nullable=True),
    created_at(),
    updated_at(),
    sa.ForeignKeyConstraint(
        ["resolved_profile_id", "resolved_profile_revision"],
        ["ai_profile_revision.profile_id", "ai_profile_revision.revision"],
        name="fk_ai_execution_profile_revision",
        ondelete="RESTRICT",
    ),
    one_of("status", ExecutionStatus, "ck_ai_execution_status"),
    one_of("capability", V1_CAPABILITIES, "ck_ai_execution_capability"),
    one_of("data_class", DataClass, "ck_ai_execution_data_class"),
    sa.CheckConstraint(
        f"resolved_boundary IS NULL OR resolved_boundary IN ({sql_list(ProviderBoundary)})",
        name="ck_ai_execution_resolved_boundary",
    ),
    sa.CheckConstraint(
        "status NOT IN ('receiving', 'spooled') OR (capability = 'ocr'"
        " AND reserved_units IS NULL AND reservation_day IS NULL"
        " AND dispatched_at IS NULL)",
        name="ck_ai_execution_spool_phase",
    ),
    sa.CheckConstraint(
        "status <> 'receiving' OR (spool_lease_until IS NOT NULL"
        " AND spool_bytes_reserved IS NOT NULL)",
        name="ck_ai_execution_receiving",
    ),
    sa.CheckConstraint(
        "status <> 'spooled' OR (spool_expires_at IS NOT NULL AND spool_file_created"
        " AND ocr_options IS NOT NULL)",
        name="ck_ai_execution_spooled",
    ),
    sa.CheckConstraint(
        "status <> 'pending' OR (reserved_units IS NOT NULL"
        " AND reservation_day IS NOT NULL AND reservation_expires_at IS NOT NULL"
        " AND resolved_provider_id IS NOT NULL AND resolved_boundary IS NOT NULL"
        " AND resolved_model_id IS NOT NULL AND resolved_profile_id IS NOT NULL"
        " AND resolved_profile_revision IS NOT NULL AND context_exp IS NOT NULL"
        " AND dispatched_at IS NULL)",
        name="ck_ai_execution_pending",
    ),
    sa.CheckConstraint(
        f"status NOT IN ({_DISPATCHED}) OR (dispatched_at IS NOT NULL"
        " AND dispatch_deadline_at IS NOT NULL AND reserved_units IS NOT NULL"
        " AND resolved_provider_id IS NOT NULL AND resolved_model_id IS NOT NULL)",
        name="ck_ai_execution_dispatched",
    ),
    sa.CheckConstraint(
        f"(status IN ({_TERMINAL})) = (occupancy_released_at IS NOT NULL)",
        name="ck_ai_execution_occupancy_released",
    ),
    sa.CheckConstraint(
        "(capability = 'ocr') = (input_sha256 IS NOT NULL)"
        " AND (capability = 'ocr') = (input_bytes IS NOT NULL)"
        " AND (capability = 'ocr') = (ocr_options_hash IS NOT NULL)"
        " AND (capability = 'ocr'"
        " OR (ocr_options IS NULL AND expected_execution_identity IS NULL))"
        " AND (ocr_options IS NULL OR jsonb_typeof(ocr_options) = 'object')",
        name="ck_ai_execution_ocr_inputs",
    ),
    sa.CheckConstraint(
        "capability = 'ocr' OR (spool_bytes_reserved IS NULL AND NOT cleanup_pending"
        " AND NOT spool_file_created AND spool_lease_until IS NULL)",
        name="ck_ai_execution_spool_is_ocr",
    ),
    sa.CheckConstraint(
        "reconciled_at IS NULL OR status = 'charged_uncertain'",
        name="ck_ai_execution_reconciled",
    ),
    sa.CheckConstraint(
        "(resolved_credential_id IS NULL) = (resolved_credential_version IS NULL)",
        name="ck_ai_execution_resolved_credential",
    ),
    sa.CheckConstraint(
        "first_byte_sent_at IS NULL OR dispatched_at IS NOT NULL",
        name="ck_ai_execution_first_byte_after_dispatch",
    ),
    sa.CheckConstraint(
        "(reserved_units IS NULL OR reserved_units >= 0)"
        " AND (spool_bytes_reserved IS NULL OR spool_bytes_reserved >= 0)"
        " AND (input_bytes IS NULL OR input_bytes >= 0) AND attempt >= 0",
        name="ck_ai_execution_non_negative",
    ),
    sa.Index("ix_ai_execution_status", "status"),
    sa.Index("ix_ai_execution_created_at", "created_at"),
)

"""Installation identity, restore state, scheduler lease and the epoch sequence."""

from __future__ import annotations

import sqlalchemy as sa

from ._common import TIMESTAMP, created_at, metadata

#: One row: the installation identity every job context and Vault path names.
ai_installation = sa.Table(
    "ai_installation",
    metadata,
    sa.Column("id", sa.SmallInteger, primary_key=True, server_default=sa.text("1")),
    sa.Column("deployment_id", sa.Uuid, nullable=False),
    created_at(),
    sa.Column("cloned_from", sa.Uuid, nullable=True),
    sa.Column("source_kek_fingerprint", sa.Text, nullable=True),
    sa.Column("source_receipt_kid", sa.Text, nullable=True),
    sa.CheckConstraint("id = 1", name="ck_ai_installation_single_row"),
)

#: One row: the restore state machine (detected, holds, obligations, ratified).
ai_restore_state = sa.Table(
    "ai_restore_state",
    metadata,
    sa.Column("id", sa.SmallInteger, primary_key=True, server_default=sa.text("1")),
    sa.Column("detected_at", TIMESTAMP, nullable=True),
    sa.Column("hold_until", TIMESTAMP, nullable=True),
    sa.Column("budget_hold_until", TIMESTAMP, nullable=True),
    sa.Column("vault_quiescent_after", TIMESTAMP, nullable=True),
    sa.Column("external_scan_completed_at", TIMESTAMP, nullable=True),
    sa.Column("replay_safety_completed_at", TIMESTAMP, nullable=True),
    sa.Column("external_reconciliation_completed_at", TIMESTAMP, nullable=True),
    sa.Column("security_report_completed_at", TIMESTAMP, nullable=True),
    sa.Column("ratified_by", sa.Text, nullable=True),
    sa.Column("ratified_at", TIMESTAMP, nullable=True),
    sa.CheckConstraint("id = 1", name="ck_ai_restore_state_single_row"),
)

#: The fenced scheduler lease of each job (D-42).
ai_scheduler_lease = sa.Table(
    "ai_scheduler_lease",
    metadata,
    sa.Column("job", sa.Text, primary_key=True),
    sa.Column("holder", sa.Text, nullable=True),
    sa.Column("holder_token", sa.Text, nullable=True),
    sa.Column("epoch", sa.BigInteger, nullable=False, server_default=sa.text("0")),
    sa.Column(
        "lease_until",
        TIMESTAMP,
        nullable=False,
        server_default=sa.text("'1970-01-01 00:00:00+00'"),
    ),
    # Stamped under the fence after each successful run; ``/health`` reads it.
    sa.Column("last_success_at", TIMESTAMP, nullable=True),
    sa.CheckConstraint("epoch >= 0", name="ck_ai_scheduler_lease_epoch"),
)

#: The restore high-water sequence.
ai_db_epoch = sa.Sequence("ai_db_epoch", metadata=metadata)

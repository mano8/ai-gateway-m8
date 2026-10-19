"""
Initial schema of ai_db (T16).

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-19

Every table, constraint and trigger the D-04, D-23, D-24, D-42, D-43, D-44,
D-45, C-04 and C-05 decisions name, and the privileges of the runtime role:
DML on the operational tables, INSERT and SELECT only on the audit tables,
SELECT only on the installation row, and no DDL. Run only by the ai-migrate
one-shot as the schema owner. ``-x runtime_role=<name>`` names the runtime
role (default ``ai_runtime``); the role must already exist.
"""

import re
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql




TRIGGER_SQL: list[str] = [
    # --- providers: the endpoint is frozen at first use, the boundary always.
    """
    CREATE FUNCTION ai_provider_freeze() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.boundary IS DISTINCT FROM OLD.boundary THEN
            RAISE EXCEPTION 'ai_provider.boundary is immutable; create a new provider row' USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.first_used_at IS NOT NULL THEN
            IF NEW.first_used_at IS DISTINCT FROM OLD.first_used_at
               OR NEW.base_url IS DISTINCT FROM OLD.base_url
               OR NEW.provider_type IS DISTINCT FROM OLD.provider_type
               OR NEW.auth_type IS DISTINCT FROM OLD.auth_type
               OR NEW.auth_header_name IS DISTINCT FROM OLD.auth_header_name THEN
                RAISE EXCEPTION 'ai_provider endpoint is frozen after first use' USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'ai_provider.created_at is immutable' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_provider_freeze BEFORE UPDATE ON ai_provider "
    "FOR EACH ROW EXECUTE FUNCTION ai_provider_freeze()",
    "CREATE TRIGGER ai_provider_no_delete BEFORE DELETE ON ai_provider "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_delete()",
    # --- models: identity frozen at the first reservation, capabilities shrink.
    """
    CREATE FUNCTION ai_model_freeze() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.provider_id IS DISTINCT FROM OLD.provider_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'ai_model.provider_id is immutable' USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.first_used_at IS NOT NULL THEN
            IF NEW.first_used_at IS DISTINCT FROM OLD.first_used_at
               OR NEW.external_model_id IS DISTINCT FROM OLD.external_model_id
               OR NEW.dimensions IS DISTINCT FROM OLD.dimensions
               OR NEW.model_revision IS DISTINCT FROM OLD.model_revision
               OR NEW.model_version_label IS DISTINCT FROM OLD.model_version_label
               OR NEW.execution_identity IS DISTINCT FROM OLD.execution_identity THEN
                RAISE EXCEPTION 'ai_model identity is frozen after its first reservation' USING ERRCODE = 'check_violation';
            END IF;
            IF NOT (NEW.capabilities <@ OLD.capabilities) THEN
                RAISE EXCEPTION 'ai_model capabilities may only shrink after first use' USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_model_freeze BEFORE UPDATE ON ai_model "
    "FOR EACH ROW EXECUTE FUNCTION ai_model_freeze()",
    "CREATE TRIGGER ai_model_no_delete BEFORE DELETE ON ai_model "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_delete()",
    # --- profiles: revisions are immutable rows.
    """
    CREATE FUNCTION ai_refuse_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION 'this row is immutable' USING ERRCODE = 'check_violation';
    END $$
    """,
    "CREATE TRIGGER ai_profile_revision_immutable BEFORE UPDATE OR DELETE "
    "ON ai_profile_revision FOR EACH ROW EXECUTE FUNCTION ai_refuse_change()",
    """
    CREATE FUNCTION ai_profile_freeze() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.profile_key IS DISTINCT FROM OLD.profile_key
           OR NEW.capability IS DISTINCT FROM OLD.capability
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'ai_profile key and capability are immutable' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_profile_freeze BEFORE UPDATE ON ai_profile "
    "FOR EACH ROW EXECUTE FUNCTION ai_profile_freeze()",
    "CREATE TRIGGER ai_profile_no_delete BEFORE DELETE ON ai_profile "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_delete()",
    # --- bindings: the scope is fixed at creation.
    """
    CREATE FUNCTION ai_profile_binding_freeze() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.profile_id IS DISTINCT FROM OLD.profile_id
           OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'ai_profile_binding scope is immutable' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_profile_binding_freeze BEFORE UPDATE ON ai_profile_binding "
    "FOR EACH ROW EXECUTE FUNCTION ai_profile_binding_freeze()",
    # --- credentials: ownership fixed at creation, next_version monotonic.
    """
    CREATE FUNCTION ai_credential_freeze() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.provider_id IS DISTINCT FROM OLD.provider_id
           OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
           OR NEW.secret_backend IS DISTINCT FROM OLD.secret_backend
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'ai_credential provider, scope and owner are immutable' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.next_version < OLD.next_version THEN
            RAISE EXCEPTION 'ai_credential.next_version never moves back' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_credential_freeze BEFORE UPDATE ON ai_credential "
    "FOR EACH ROW EXECUTE FUNCTION ai_credential_freeze()",
    "CREATE TRIGGER ai_credential_no_delete BEFORE DELETE ON ai_credential "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_delete()",
    # The pointer of an active credential names committed, live material.
    """
    CREATE FUNCTION ai_credential_pointer_check() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE
        bad boolean;
    BEGIN
        SELECT EXISTS (
            SELECT 1 FROM ai_credential c
            JOIN ai_credential_version v
              ON v.credential_id = c.id AND v.version = c.current_version
            WHERE c.id = NEW.id
              AND c.status = 'active'
              AND (v.material_committed_at IS NULL
                   OR v.material_destroyed_at IS NOT NULL
                   OR v.material_lost_at IS NOT NULL
                   OR v.aborted_at IS NOT NULL)
        ) INTO bad;
        IF bad THEN
            RAISE EXCEPTION 'an active credential must point at committed, live material' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
    END $$
    """,
    "CREATE CONSTRAINT TRIGGER ai_credential_pointer_check AFTER INSERT OR UPDATE "
    "ON ai_credential DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
    "EXECUTE FUNCTION ai_credential_pointer_check()",
    """
    CREATE FUNCTION ai_credential_version_pointer_check() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE
        bad boolean;
    BEGIN
        SELECT EXISTS (
            SELECT 1 FROM ai_credential c
            JOIN ai_credential_version v
              ON v.credential_id = c.id AND v.version = c.current_version
            WHERE c.id = NEW.credential_id
              AND c.status = 'active'
              AND (v.material_committed_at IS NULL
                   OR v.material_destroyed_at IS NOT NULL
                   OR v.material_lost_at IS NOT NULL
                   OR v.aborted_at IS NOT NULL)
        ) INTO bad;
        IF bad THEN
            RAISE EXCEPTION 'an active credential must point at committed, live material' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
    END $$
    """,
    "CREATE CONSTRAINT TRIGGER ai_credential_version_pointer_check AFTER UPDATE "
    "ON ai_credential_version DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
    "EXECUTE FUNCTION ai_credential_version_pointer_check()",
    # --- credential versions: never deleted; numbers allocated, never reused;
    # material only ever cleared; destruction waits for every cleanup.
    """
    CREATE FUNCTION ai_credential_version_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE
        allocated integer;
    BEGIN
        SELECT next_version INTO allocated FROM ai_credential
        WHERE id = NEW.credential_id;
        IF allocated IS NULL OR NEW.version >= allocated THEN
            RAISE EXCEPTION 'a version number must be allocated from next_version first' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_credential_version_insert BEFORE INSERT ON ai_credential_version "
    "FOR EACH ROW EXECUTE FUNCTION ai_credential_version_insert()",
    "CREATE TRIGGER ai_credential_version_no_delete BEFORE DELETE ON ai_credential_version "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_delete()",
    """
    CREATE FUNCTION ai_credential_version_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
           OR NEW.version IS DISTINCT FROM OLD.version
           OR NEW.prepare_id IS DISTINCT FROM OLD.prepare_id
           OR NEW.base_version IS DISTINCT FROM OLD.base_version
           OR NEW.kv_path IS DISTINCT FROM OLD.kv_path
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'ai_credential_version identity is immutable' USING ERRCODE = 'check_violation';
        END IF;
        IF (OLD.aborted_at IS NOT NULL AND NEW.aborted_at IS DISTINCT FROM OLD.aborted_at)
           OR (OLD.material_committed_at IS NOT NULL
               AND NEW.material_committed_at IS DISTINCT FROM OLD.material_committed_at)
           OR (OLD.material_destroyed_at IS NOT NULL
               AND NEW.material_destroyed_at IS DISTINCT FROM OLD.material_destroyed_at)
           OR (OLD.material_lost_at IS NOT NULL
               AND NEW.material_lost_at IS DISTINCT FROM OLD.material_lost_at) THEN
            RAISE EXCEPTION 'a version''s lifecycle stamps are set once' USING ERRCODE = 'check_violation';
        END IF;
        IF (NEW.ciphertext IS NOT NULL AND NEW.ciphertext IS DISTINCT FROM OLD.ciphertext)
           OR (NEW.nonce IS NOT NULL AND NEW.nonce IS DISTINCT FROM OLD.nonce) THEN
            RAISE EXCEPTION 'ciphertext is never rewritten; only rewrap or destroy' USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.material_destroyed_at IS NULL AND NEW.material_destroyed_at IS NOT NULL THEN
            IF EXISTS (SELECT 1 FROM ai_provider_remote_artifact a
                       WHERE a.credential_id = NEW.credential_id
                         AND a.credential_version = NEW.version) THEN
                RAISE EXCEPTION 'a version a remote artifact references cannot be destroyed' USING ERRCODE = 'check_violation';
            END IF;
            IF NEW.sweep_discharge_at IS NOT NULL
               AND (NEW.reconciled_through IS NULL
                    OR NEW.reconciled_through < NEW.sweep_discharge_at) THEN
                RAISE EXCEPTION 'a version''s sweep obligation is still open' USING ERRCODE = 'check_violation';
            END IF;
            IF EXISTS (SELECT 1 FROM ai_credential c
                       WHERE c.id = NEW.credential_id
                         AND c.current_version = NEW.version
                         AND c.status <> 'deleted') THEN
                RAISE EXCEPTION 'the current version of a live credential cannot be destroyed' USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_credential_version_guard BEFORE UPDATE ON ai_credential_version "
    "FOR EACH ROW EXECUTE FUNCTION ai_credential_version_guard()",
    # --- executions: exactly the D-24 transition table.
    """
    CREATE FUNCTION ai_execution_transition() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NOT ((NEW.capability = 'ocr' AND NEW.status = 'receiving')
                    OR (NEW.capability <> 'ocr' AND NEW.status = 'pending')) THEN
                RAISE EXCEPTION 'an execution starts receiving (ocr) or pending' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.capability IS DISTINCT FROM OLD.capability
           OR NEW.profile_key IS DISTINCT FROM OLD.profile_key
           OR NEW.client_scope_id IS DISTINCT FROM OLD.client_scope_id
           OR NEW.user_scope_id IS DISTINCT FROM OLD.user_scope_id
           OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
           OR NEW.jti IS DISTINCT FROM OLD.jti
           OR NEW.issuer IS DISTINCT FROM OLD.issuer
           OR NEW.azp IS DISTINCT FROM OLD.azp
           OR NEW.job_ref IS DISTINCT FROM OLD.job_ref
           OR NEW.attempt IS DISTINCT FROM OLD.attempt
           OR NEW.input_sha256 IS DISTINCT FROM OLD.input_sha256
           OR NEW.input_bytes IS DISTINCT FROM OLD.input_bytes
           OR NEW.ocr_options_hash IS DISTINCT FROM OLD.ocr_options_hash
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'an execution''s binding is immutable' USING ERRCODE = 'check_violation';
        END IF;
        IF (OLD.reserved_units IS NOT NULL
                AND NEW.reserved_units IS DISTINCT FROM OLD.reserved_units)
           OR (OLD.reservation_day IS NOT NULL
                AND NEW.reservation_day IS DISTINCT FROM OLD.reservation_day)
           OR (OLD.resolved_provider_id IS NOT NULL
                AND NEW.resolved_provider_id IS DISTINCT FROM OLD.resolved_provider_id)
           OR (OLD.resolved_boundary IS NOT NULL
                AND NEW.resolved_boundary IS DISTINCT FROM OLD.resolved_boundary)
           OR (OLD.resolved_model_id IS NOT NULL
                AND NEW.resolved_model_id IS DISTINCT FROM OLD.resolved_model_id)
           OR (OLD.resolved_profile_revision IS NOT NULL
                AND NEW.resolved_profile_revision IS DISTINCT FROM OLD.resolved_profile_revision)
           OR (OLD.resolved_credential_version IS NOT NULL
                AND NEW.resolved_credential_version IS DISTINCT FROM OLD.resolved_credential_version)
           OR (OLD.dispatched_at IS NOT NULL
                AND NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at)
           OR (OLD.first_byte_sent_at IS NOT NULL
                AND NEW.first_byte_sent_at IS DISTINCT FROM OLD.first_byte_sent_at)
           OR (OLD.occupancy_released_at IS NOT NULL
                AND NEW.occupancy_released_at IS DISTINCT FROM OLD.occupancy_released_at) THEN
            RAISE EXCEPTION 'a recorded reservation, resolution or stamp never changes' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status = OLD.status THEN
            RETURN NEW;
        END IF;
        IF NOT (
            (OLD.status = 'receiving' AND NEW.status IN ('spooled', 'abandoned'))
            OR (OLD.status = 'spooled' AND NEW.status IN ('pending', 'abandoned'))
            OR (OLD.status = 'pending'
                AND NEW.status IN ('dispatching', 'released', 'abandoned'))
            OR (OLD.status = 'dispatching'
                AND NEW.status IN ('ok', 'failed', 'charged_uncertain'))
            OR (OLD.status = 'dispatching' AND NEW.status = 'released'
                AND NEW.first_byte_sent_at IS NULL)
        ) THEN
            RAISE EXCEPTION 'execution transition outside the D-24 table' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_execution_transition BEFORE INSERT OR UPDATE ON ai_execution "
    "FOR EACH ROW EXECUTE FUNCTION ai_execution_transition()",
    # --- remote artifacts: exactly the D-43 transition table.
    """
    CREATE FUNCTION ai_remote_artifact_transition() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'uploading' THEN
                RAISE EXCEPTION 'a remote artifact starts as uploading' USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' THEN
            IF OLD.status NOT IN ('uploading_unknown_id', 'pending_delete',
                                  'manual_cleanup_required') THEN
                RAISE EXCEPTION 'a remote artifact closes only from an unresolved or deletion state' USING ERRCODE = 'check_violation';
            END IF;
            RETURN OLD;
        END IF;
        IF NEW.execution_id IS DISTINCT FROM OLD.execution_id
           OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
           OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
           OR NEW.credential_version IS DISTINCT FROM OLD.credential_version
           OR NEW.gateway_file_name IS DISTINCT FROM OLD.gateway_file_name
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR (OLD.remote_artifact_id IS NOT NULL
               AND NEW.remote_artifact_id IS DISTINCT FROM OLD.remote_artifact_id) THEN
            RAISE EXCEPTION 'a remote artifact''s identity is immutable' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status = OLD.status THEN
            RETURN NEW;
        END IF;
        IF NOT (
            (OLD.status = 'uploading'
                AND NEW.status IN ('active', 'uploading_unknown_id'))
            OR (OLD.status = 'uploading_unknown_id'
                AND NEW.status IN ('pending_delete', 'manual_cleanup_required'))
            OR (OLD.status = 'active' AND NEW.status = 'pending_delete')
            OR (OLD.status = 'pending_delete' AND NEW.status = 'manual_cleanup_required')
            OR (OLD.status = 'manual_cleanup_required' AND NEW.status = 'pending_delete'
                AND OLD.status_reason = 'absence_unproven')
        ) THEN
            RAISE EXCEPTION 'remote artifact transition outside the D-43 table' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$
    """,
    "CREATE TRIGGER ai_remote_artifact_transition BEFORE INSERT OR UPDATE OR DELETE "
    "ON ai_provider_remote_artifact FOR EACH ROW "
    "EXECUTE FUNCTION ai_remote_artifact_transition()",
    # --- audit rows are never updated.
    "CREATE TRIGGER ai_credential_audit_immutable BEFORE UPDATE ON ai_credential_audit "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_change()",
    "CREATE TRIGGER ai_admin_audit_immutable BEFORE UPDATE ON ai_admin_audit "
    "FOR EACH ROW EXECUTE FUNCTION ai_refuse_change()",
]

#: Created first: shared by several triggers above.
REFUSE_DELETE_SQL = """
CREATE FUNCTION ai_refuse_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'rows of this table are never deleted' USING ERRCODE = 'check_violation';
END $$
"""

_OPERATIONAL = (
    "ai_job_context_use",
    "ai_usage",
    "ai_rate_window",
    "ai_client_occupancy",
    "ai_execution",
    "ai_provider_remote_artifact",
)

RUNTIME_GRANTS: list[str] = [
    # The web and scheduler read the revision before they start (D-04).
    "GRANT SELECT ON alembic_version_ai TO {role}",
    "GRANT SELECT ON ai_installation TO {role}",
    "GRANT SELECT, INSERT, UPDATE ON ai_restore_state, ai_scheduler_lease, "
    "ai_provider, ai_model, ai_profile, ai_credential, ai_credential_version "
    "TO {role}",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ai_profile_binding TO {role}",
    "GRANT SELECT, INSERT ON ai_profile_revision TO {role}",
    "GRANT SELECT, UPDATE ON ai_spool_capacity TO {role}",
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(_OPERATIONAL)} TO {{role}}",
    "GRANT SELECT, INSERT ON ai_credential_audit, ai_admin_audit TO {role}",
    "GRANT USAGE, SELECT ON SEQUENCE ai_db_epoch TO {role}",
]

DOWNGRADE_SQL: list[str] = [
    "ALTER TABLE ai_credential DROP CONSTRAINT fk_ai_credential_current_version",
    "ALTER TABLE ai_profile DROP CONSTRAINT fk_ai_profile_current_revision",
    "DROP TRIGGER ai_credential_pointer_check ON ai_credential",
    "DROP TRIGGER ai_credential_version_pointer_check ON ai_credential_version",
    "DROP TRIGGER ai_credential_version_no_delete ON ai_credential_version",
    "DROP TRIGGER ai_credential_no_delete ON ai_credential",
    "DROP TRIGGER ai_model_no_delete ON ai_model",
    "DROP TRIGGER ai_provider_no_delete ON ai_provider",
    "DROP TRIGGER ai_profile_no_delete ON ai_profile",
    "DROP TRIGGER ai_profile_revision_immutable ON ai_profile_revision",
    "DROP TRIGGER ai_remote_artifact_transition ON ai_provider_remote_artifact",
    "DROP SEQUENCE ai_db_epoch",
]

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_admin_audit",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column("actor_role", sa.Text(), nullable=True),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "actor_kind IN ('operator', 'service', 'system', 'user')",
            name="ck_ai_admin_audit_actor_kind",
        ),
        sa.CheckConstraint(
            "octet_length(metadata::text) <= 4096",
            name="ck_ai_admin_audit_metadata_size",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ai_client_occupancy",
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column(
            "occupied", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint("occupied >= 0", name="ck_ai_client_occupancy_non_negative"),
        sa.PrimaryKeyConstraint("client_id"),
    )
    op.create_table(
        "ai_credential_audit",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column("actor_role", sa.Text(), nullable=True),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("credential_id", sa.Uuid(), nullable=True),
        sa.Column("scope_type", sa.Text(), nullable=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=True),
        sa.Column("owner_user_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "actor_kind IN ('operator', 'service', 'system', 'user')",
            name="ck_ai_credential_audit_actor_kind",
        ),
        sa.CheckConstraint(
            "octet_length(metadata::text) <= 4096",
            name="ck_ai_credential_audit_metadata_size",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_credential_audit_credential_id"),
        "ai_credential_audit",
        ["credential_id"],
        unique=False,
    )
    op.create_table(
        "ai_installation",
        sa.Column("id", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("cloned_from", sa.Uuid(), nullable=True),
        sa.Column("source_kek_fingerprint", sa.Text(), nullable=True),
        sa.Column("source_receipt_kid", sa.Text(), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_ai_installation_single_row"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ai_job_context_use",
        sa.Column("iss", sa.Text(), nullable=False),
        sa.Column("jti", sa.Text(), nullable=False),
        sa.Column("uses", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("exp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "max_uses >= 1 AND uses >= 1 AND uses <= max_uses",
            name="ck_ai_job_context_use_uses",
        ),
        sa.PrimaryKeyConstraint("iss", "jti"),
    )
    op.create_index(
        op.f("ix_ai_job_context_use_exp"), "ai_job_context_use", ["exp"], unique=False
    )
    op.create_table(
        "ai_profile",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("profile_key", sa.Text(), nullable=False),
        sa.Column("capability", sa.Text(), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "capability IN ('embedding', 'ocr', 'rerank', 'structured_output')",
            name="ck_ai_profile_capability",
        ),
        sa.CheckConstraint(
            "profile_key ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'",
            name="ck_ai_profile_key",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("profile_key"),
    )
    op.create_table(
        "ai_provider",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("provider_type", sa.Text(), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=False),
        sa.Column("auth_type", sa.Text(), nullable=False),
        sa.Column("auth_header_name", sa.Text(), nullable=True),
        sa.Column("boundary", sa.Text(), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column("first_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(auth_type = 'api_key_header') = (auth_header_name IS NOT NULL)",
            name="ck_ai_provider_header_matches_auth",
        ),
        sa.CheckConstraint(
            "auth_type IN ('api_key_header', 'bearer', 'none')",
            name="ck_ai_provider_auth_type",
        ),
        sa.CheckConstraint(
            "boundary IN ('external', 'local')", name="ck_ai_provider_boundary"
        ),
        sa.CheckConstraint(
            "provider_type IN ('mistral', 'ollama', 'openai_compatible')",
            name="ck_ai_provider_type",
        ),
        sa.CheckConstraint(
            "char_length(base_url) <= 2048", name="ck_ai_provider_base_url_length"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ai_rate_window",
        sa.Column("principal_key", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.CheckConstraint("count >= 0", name="ck_ai_rate_window_count"),
        sa.PrimaryKeyConstraint("principal_key", "window_start"),
    )
    op.create_table(
        "ai_restore_state",
        sa.Column("id", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hold_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("budget_hold_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vault_quiescent_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "external_scan_completed_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "replay_safety_completed_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "external_reconciliation_completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "security_report_completed_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column("ratified_by", sa.Text(), nullable=True),
        sa.Column("ratified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_ai_restore_state_single_row"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ai_scheduler_lease",
        sa.Column("job", sa.Text(), nullable=False),
        sa.Column("holder", sa.Text(), nullable=True),
        sa.Column("holder_token", sa.Text(), nullable=True),
        sa.Column(
            "epoch", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "lease_until",
            sa.DateTime(timezone=True),
            server_default=sa.text("'1970-01-01 00:00:00+00'"),
            nullable=False,
        ),
        sa.CheckConstraint("epoch >= 0", name="ck_ai_scheduler_lease_epoch"),
        sa.PrimaryKeyConstraint("job"),
    )
    op.create_table(
        "ai_spool_capacity",
        sa.Column("id", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "reserved_bytes",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "max_bytes", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint("id = 1", name="ck_ai_spool_capacity_single_row"),
        sa.CheckConstraint(
            "reserved_bytes >= 0 AND max_bytes >= 0", name="ck_ai_spool_capacity_bytes"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ai_usage",
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("scope_id", sa.Text(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column(
            "reserved", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("used", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.CheckConstraint(
            "scope_type IN ('client', 'tenant', 'user')", name="ck_ai_usage_scope_type"
        ),
        sa.CheckConstraint(
            "reserved >= 0 AND used >= 0", name="ck_ai_usage_non_negative"
        ),
        sa.PrimaryKeyConstraint("scope_type", "scope_id", "day"),
    )
    op.create_table(
        "ai_credential",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=True),
        sa.Column("owner_user_id", sa.Uuid(), nullable=True),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("secret_backend", sa.Text(), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=True),
        sa.Column(
            "next_version", sa.Integer(), server_default=sa.text("1"), nullable=False
        ),
        sa.Column(
            "auth_failure_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("throttled_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "incident_listing_consent",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("secret_hint", sa.Text(), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(scope_type = 'global' AND tenant_id IS NULL AND owner_user_id IS NULL) OR (scope_type = 'tenant' AND tenant_id IS NOT NULL AND owner_user_id IS NULL) OR (scope_type = 'user' AND owner_user_id IS NOT NULL)",
            name="ck_ai_credential_scope_shape",
        ),
        sa.CheckConstraint(
            "(status = 'deleted') = (deleted_at IS NOT NULL)",
            name="ck_ai_credential_deleted_at",
        ),
        sa.CheckConstraint(
            "scope_type IN ('global', 'tenant', 'user')",
            name="ck_ai_credential_scope_type",
        ),
        sa.CheckConstraint(
            "secret_backend IN ('database', 'vault')",
            name="ck_ai_credential_secret_backend",
        ),
        sa.CheckConstraint(
            "status <> 'active' OR current_version IS NOT NULL",
            name="ck_ai_credential_active_has_version",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'deleted', 'disabled', 'invalid', 'provisioning', 'reconfirm_required', 'reprovision_required')",
            name="ck_ai_credential_status",
        ),
        sa.CheckConstraint(
            "auth_failure_count >= 0", name="ck_ai_credential_auth_failures"
        ),
        sa.CheckConstraint(
            "next_version >= 1 AND (current_version IS NULL OR current_version < next_version)",
            name="ck_ai_credential_versions",
        ),
        sa.CheckConstraint(
            "secret_hint IS NULL OR char_length(secret_hint) = 4",
            name="ck_ai_credential_secret_hint",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["ai_provider.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_credential_provider_id"),
        "ai_credential",
        ["provider_id"],
        unique=False,
    )
    op.create_index(
        "ix_ai_credential_scope",
        "ai_credential",
        ["scope_type", "tenant_id", "owner_user_id"],
        unique=False,
    )
    op.create_table(
        "ai_model",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("external_model_id", sa.Text(), nullable=False),
        sa.Column("capabilities", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("context_window", sa.Integer(), nullable=True),
        sa.Column("max_output_tokens", sa.Integer(), nullable=True),
        sa.Column("dimensions", sa.Integer(), nullable=True),
        sa.Column("model_version_label", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=True),
        sa.Column("identity_assurance", sa.Text(), nullable=False),
        sa.Column("execution_identity", sa.Text(), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column("flagged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "NOT ('embedding' = ANY(capabilities)) OR dimensions IS NOT NULL",
            name="ck_ai_model_embedding_dimensions",
        ),
        sa.CheckConstraint(
            "cardinality(capabilities) >= 1 AND capabilities <@ ARRAY['embedding', 'ocr', 'rerank', 'structured_output']::text[]",
            name="ck_ai_model_capabilities",
        ),
        sa.CheckConstraint(
            "execution_identity ~ '^[0-9a-f]{32}$'",
            name="ck_ai_model_execution_identity",
        ),
        sa.CheckConstraint(
            "identity_assurance IN ('operator_declared', 'pinned_snapshot', 'provider_digest')",
            name="ck_ai_model_identity_assurance",
        ),
        sa.CheckConstraint(
            "(dimensions IS NULL OR dimensions > 0) AND (context_window IS NULL OR context_window > 0) AND (max_output_tokens IS NULL OR max_output_tokens > 0)",
            name="ck_ai_model_positive_sizes",
        ),
        sa.CheckConstraint(
            "octet_length(metadata::text) <= 4096", name="ck_ai_model_metadata_size"
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["ai_provider.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_model_provider_id"), "ai_model", ["provider_id"], unique=False
    )
    op.create_table(
        "ai_profile_revision",
        sa.Column("profile_id", sa.Uuid(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column(
            "execution_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("execution_config_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "execution_config_hash ~ '^[0-9a-f]{64}$'",
            name="ck_ai_profile_revision_hash",
        ),
        sa.CheckConstraint(
            "octet_length(execution_config::text) <= 8192",
            name="ck_ai_profile_revision_config_size",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_ai_profile_revision_positive"),
        sa.ForeignKeyConstraint(["profile_id"], ["ai_profile.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("profile_id", "revision"),
    )
    op.create_table(
        "ai_credential_version",
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("nonce", sa.LargeBinary(), nullable=True),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=True),
        sa.Column("wrap_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("algorithm", sa.Text(), nullable=True),
        sa.Column("kek_provider", sa.Text(), nullable=True),
        sa.Column("kek_key_id", sa.Text(), nullable=True),
        sa.Column("kek_key_version", sa.Text(), nullable=True),
        sa.Column("kv_path", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.Text(), nullable=True),
        sa.Column("fingerprint_key_version", sa.Text(), nullable=True),
        sa.Column("prepare_id", sa.Text(), nullable=False),
        sa.Column("base_version", sa.Integer(), nullable=True),
        sa.Column("material_committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("material_destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("material_lost_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("aborted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_upload_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconciled_through", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sweep_discharge_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "algorithm IS NULL OR algorithm = 'AES-256-GCM'",
            name="ck_ai_credential_version_algorithm",
        ),
        sa.CheckConstraint(
            "prepare_id ~ '^[0-9a-f]{32}$'", name="ck_ai_credential_version_prepare_id"
        ),
        sa.CheckConstraint(
            "(ciphertext IS NULL) = (nonce IS NULL) AND (ciphertext IS NULL) = (wrapped_dek IS NULL) AND (ciphertext IS NULL) = (algorithm IS NULL) AND (ciphertext IS NULL) = (kek_provider IS NULL) AND (ciphertext IS NULL) = (kek_key_version IS NULL)",
            name="ck_ai_credential_version_envelope_whole",
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
            "material_destroyed_at IS NULL OR (ciphertext IS NULL AND wrap_nonce IS NULL AND fingerprint IS NULL)",
            name="ck_ai_credential_version_destroyed_has_no_material",
        ),
        sa.CheckConstraint("version >= 1", name="ck_ai_credential_version_positive"),
        sa.ForeignKeyConstraint(
            ["credential_id"], ["ai_credential.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("credential_id", "version"),
    )
    op.create_table(
        "ai_execution",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("capability", sa.Text(), nullable=False),
        sa.Column("profile_key", sa.Text(), nullable=False),
        sa.Column("data_class", sa.Text(), nullable=False),
        sa.Column("client_scope_id", sa.Text(), nullable=False),
        sa.Column("user_scope_id", sa.Text(), nullable=True),
        sa.Column("tenant_scope_id", sa.Text(), nullable=True),
        sa.Column("jti", sa.Text(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("azp", sa.Text(), nullable=False),
        sa.Column("job_ref", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("input_sha256", sa.Text(), nullable=True),
        sa.Column("input_bytes", sa.BigInteger(), nullable=True),
        sa.Column("ocr_options_hash", sa.Text(), nullable=True),
        sa.Column("reserved_units", sa.BigInteger(), nullable=True),
        sa.Column("reservation_day", sa.Date(), nullable=True),
        sa.Column("reservation_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dispatch_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_byte_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("spool_lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("spool_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("spool_bytes_reserved", sa.BigInteger(), nullable=True),
        sa.Column(
            "spool_file_created",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "cleanup_pending",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("resolved_provider_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_boundary", sa.Text(), nullable=True),
        sa.Column("resolved_model_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_profile_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_profile_revision", sa.Integer(), nullable=True),
        sa.Column("resolved_credential_id", sa.Uuid(), nullable=True),
        sa.Column("resolved_credential_version", sa.Integer(), nullable=True),
        sa.Column("context_exp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_identity", sa.Text(), nullable=True),
        sa.Column("embedding_space_id", sa.Text(), nullable=True),
        sa.Column(
            "provider_usage", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("error_class", sa.Text(), nullable=True),
        sa.Column("occupancy_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(capability = 'ocr') = (input_sha256 IS NOT NULL) AND (capability = 'ocr') = (input_bytes IS NOT NULL) AND (capability = 'ocr') = (ocr_options_hash IS NOT NULL)",
            name="ck_ai_execution_ocr_inputs",
        ),
        sa.CheckConstraint(
            "(status IN ('abandoned', 'charged_uncertain', 'failed', 'ok', 'released')) = (occupancy_released_at IS NOT NULL)",
            name="ck_ai_execution_occupancy_released",
        ),
        sa.CheckConstraint(
            "capability = 'ocr' OR (spool_bytes_reserved IS NULL AND NOT cleanup_pending AND NOT spool_file_created AND spool_lease_until IS NULL)",
            name="ck_ai_execution_spool_is_ocr",
        ),
        sa.CheckConstraint(
            "capability IN ('embedding', 'ocr', 'rerank', 'structured_output')",
            name="ck_ai_execution_capability",
        ),
        sa.CheckConstraint(
            "data_class IN ('internal', 'public', 'restricted')",
            name="ck_ai_execution_data_class",
        ),
        sa.CheckConstraint(
            "reconciled_at IS NULL OR status = 'charged_uncertain'",
            name="ck_ai_execution_reconciled",
        ),
        sa.CheckConstraint(
            "resolved_boundary IS NULL OR resolved_boundary IN ('external', 'local')",
            name="ck_ai_execution_resolved_boundary",
        ),
        sa.CheckConstraint(
            "status <> 'pending' OR (reserved_units IS NOT NULL AND reservation_day IS NOT NULL AND reservation_expires_at IS NOT NULL AND resolved_provider_id IS NOT NULL AND resolved_boundary IS NOT NULL AND resolved_model_id IS NOT NULL AND resolved_profile_id IS NOT NULL AND resolved_profile_revision IS NOT NULL AND context_exp IS NOT NULL AND dispatched_at IS NULL)",
            name="ck_ai_execution_pending",
        ),
        sa.CheckConstraint(
            "status <> 'receiving' OR (spool_lease_until IS NOT NULL AND spool_bytes_reserved IS NOT NULL)",
            name="ck_ai_execution_receiving",
        ),
        sa.CheckConstraint(
            "status <> 'spooled' OR (spool_expires_at IS NOT NULL AND spool_file_created)",
            name="ck_ai_execution_spooled",
        ),
        sa.CheckConstraint(
            "status IN ('abandoned', 'charged_uncertain', 'dispatching', 'failed', 'ok', 'pending', 'receiving', 'released', 'spooled')",
            name="ck_ai_execution_status",
        ),
        sa.CheckConstraint(
            "status NOT IN ('charged_uncertain', 'dispatching', 'failed', 'ok') OR (dispatched_at IS NOT NULL AND dispatch_deadline_at IS NOT NULL AND reserved_units IS NOT NULL AND resolved_provider_id IS NOT NULL AND resolved_model_id IS NOT NULL)",
            name="ck_ai_execution_dispatched",
        ),
        sa.CheckConstraint(
            "status NOT IN ('receiving', 'spooled') OR (capability = 'ocr' AND reserved_units IS NULL AND reservation_day IS NULL AND dispatched_at IS NULL)",
            name="ck_ai_execution_spool_phase",
        ),
        sa.CheckConstraint(
            "(reserved_units IS NULL OR reserved_units >= 0) AND (spool_bytes_reserved IS NULL OR spool_bytes_reserved >= 0) AND (input_bytes IS NULL OR input_bytes >= 0) AND attempt >= 0",
            name="ck_ai_execution_non_negative",
        ),
        sa.CheckConstraint(
            "(resolved_credential_id IS NULL) = (resolved_credential_version IS NULL)",
            name="ck_ai_execution_resolved_credential",
        ),
        sa.CheckConstraint(
            "first_byte_sent_at IS NULL OR dispatched_at IS NOT NULL",
            name="ck_ai_execution_first_byte_after_dispatch",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_model_id"], ["ai_model.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["resolved_profile_id", "resolved_profile_revision"],
            ["ai_profile_revision.profile_id", "ai_profile_revision.revision"],
            name="fk_ai_execution_profile_revision",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_provider_id"], ["ai_provider.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_ai_execution_created_at", "ai_execution", ["created_at"], unique=False
    )
    op.create_index("ix_ai_execution_status", "ai_execution", ["status"], unique=False)
    op.create_table(
        "ai_profile_binding",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("profile_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=True),
        sa.Column("owner_user_id", sa.Uuid(), nullable=True),
        sa.Column("model_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=True),
        sa.Column(
            "on_unavailable",
            sa.Text(),
            server_default=sa.text("'fail'"),
            nullable=False,
        ),
        sa.Column(
            "status", sa.Text(), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(scope_type = 'global' AND tenant_id IS NULL AND owner_user_id IS NULL) OR (scope_type = 'tenant' AND tenant_id IS NOT NULL AND owner_user_id IS NULL) OR (scope_type = 'user' AND owner_user_id IS NOT NULL)",
            name="ck_ai_profile_binding_scope_shape",
        ),
        sa.CheckConstraint(
            "on_unavailable IN ('fail', 'fall_through')",
            name="ck_ai_profile_binding_on_unavailable",
        ),
        sa.CheckConstraint(
            "scope_type IN ('global', 'tenant', 'user')",
            name="ck_ai_profile_binding_scope_type",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'credential_unavailable')",
            name="ck_ai_profile_binding_status",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"], ["ai_credential.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["model_id"], ["ai_model.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["profile_id"], ["ai_profile.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "profile_id",
            "scope_type",
            "tenant_id",
            "owner_user_id",
            name="uq_ai_profile_binding_scope",
            postgresql_nulls_not_distinct=True,
        ),
    )
    op.create_index(
        op.f("ix_ai_profile_binding_credential_id"),
        "ai_profile_binding",
        ["credential_id"],
        unique=False,
    )
    op.create_table(
        "ai_provider_remote_artifact",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("credential_version", sa.Integer(), nullable=False),
        sa.Column("gateway_file_name", sa.Text(), nullable=False),
        sa.Column("remote_artifact_id", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("upload_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "negative_listings",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "first_negative_listing_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "delete_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_class", sa.Text(), nullable=True),
        sa.Column("claim_epoch", sa.BigInteger(), nullable=True),
        sa.Column("claim_holder_token", sa.Text(), nullable=True),
        sa.Column("claim_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(status = 'manual_cleanup_required') = (status_reason IS NOT NULL)",
            name="ck_ai_provider_remote_artifact_reason",
        ),
        sa.CheckConstraint(
            "coalesce(status_reason, 'absence_unproven') IN ('absence_unproven', 'attempts_exhausted', 'listing_not_permitted', 'material_lost', 'pending_hours_exceeded')",
            name="ck_ai_provider_remote_artifact_reason_value",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'manual_cleanup_required', 'pending_delete', 'uploading', 'uploading_unknown_id')",
            name="ck_ai_provider_remote_artifact_status",
        ),
        sa.CheckConstraint(
            "status NOT IN ('active', 'pending_delete') OR remote_artifact_id IS NOT NULL",
            name="ck_ai_provider_remote_artifact_has_id",
        ),
        sa.CheckConstraint(
            "(claim_epoch IS NULL) = (claim_holder_token IS NULL) AND (claim_epoch IS NULL) = (claim_until IS NULL)",
            name="ck_ai_provider_remote_artifact_claim",
        ),
        sa.CheckConstraint(
            "negative_listings >= 0 AND delete_attempts >= 0",
            name="ck_ai_provider_remote_artifact_counters",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id", "credential_version"],
            ["ai_credential_version.credential_id", "ai_credential_version.version"],
            name="fk_ai_provider_remote_artifact_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"], ["ai_credential.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["execution_id"], ["ai_execution.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["ai_provider.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("gateway_file_name"),
    )
    op.create_index(
        op.f("ix_ai_provider_remote_artifact_execution_id"),
        "ai_provider_remote_artifact",
        ["execution_id"],
        unique=False,
    )
    op.create_index(
        "ix_ai_provider_remote_artifact_status",
        "ai_provider_remote_artifact",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_ai_provider_remote_artifact_version",
        "ai_provider_remote_artifact",
        ["credential_id", "credential_version"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_ai_profile_current_revision",
        "ai_profile",
        "ai_profile_revision",
        ["id", "current_revision"],
        ["profile_id", "revision"],
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_foreign_key(
        "fk_ai_credential_current_version",
        "ai_credential",
        "ai_credential_version",
        ["id", "current_version"],
        ["credential_id", "version"],
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
    )
    op.execute(sa.schema.CreateSequence(sa.Sequence("ai_db_epoch")))
    op.execute(REFUSE_DELETE_SQL)
    for statement in TRIGGER_SQL:
        op.execute(statement)
    role = _runtime_role()
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    for statement in RUNTIME_GRANTS:
        op.execute(statement.format(role=role))


def _runtime_role() -> str:
    role = context.get_x_argument(as_dictionary=True).get("runtime_role", "ai_runtime")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise ValueError("runtime_role is not a plain lower-case role name")
    return role


def downgrade() -> None:
    for statement in DOWNGRADE_SQL:
        op.execute(statement)
    op.drop_index(
        "ix_ai_provider_remote_artifact_version",
        table_name="ai_provider_remote_artifact",
    )
    op.drop_index(
        "ix_ai_provider_remote_artifact_status",
        table_name="ai_provider_remote_artifact",
    )
    op.drop_index(
        op.f("ix_ai_provider_remote_artifact_execution_id"),
        table_name="ai_provider_remote_artifact",
    )
    op.drop_table("ai_provider_remote_artifact")
    op.drop_index(
        op.f("ix_ai_profile_binding_credential_id"), table_name="ai_profile_binding"
    )
    op.drop_table("ai_profile_binding")
    op.drop_index("ix_ai_execution_status", table_name="ai_execution")
    op.drop_index("ix_ai_execution_created_at", table_name="ai_execution")
    op.drop_table("ai_execution")
    op.drop_table("ai_credential_version")
    op.drop_table("ai_profile_revision")
    op.drop_index(op.f("ix_ai_model_provider_id"), table_name="ai_model")
    op.drop_table("ai_model")
    op.drop_index("ix_ai_credential_scope", table_name="ai_credential")
    op.drop_index(op.f("ix_ai_credential_provider_id"), table_name="ai_credential")
    op.drop_table("ai_credential")
    op.drop_table("ai_usage")
    op.drop_table("ai_spool_capacity")
    op.drop_table("ai_scheduler_lease")
    op.drop_table("ai_restore_state")
    op.drop_table("ai_rate_window")
    op.drop_table("ai_provider")
    op.drop_table("ai_profile")
    op.drop_index(op.f("ix_ai_job_context_use_exp"), table_name="ai_job_context_use")
    op.drop_table("ai_job_context_use")
    op.drop_table("ai_installation")
    op.drop_index(
        op.f("ix_ai_credential_audit_credential_id"), table_name="ai_credential_audit"
    )
    op.drop_table("ai_credential_audit")
    op.drop_table("ai_client_occupancy")
    op.drop_table("ai_admin_audit")
    for function in (
        "ai_provider_freeze",
        "ai_model_freeze",
        "ai_refuse_change",
        "ai_profile_freeze",
        "ai_profile_binding_freeze",
        "ai_credential_freeze",
        "ai_credential_pointer_check",
        "ai_credential_version_pointer_check",
        "ai_credential_version_insert",
        "ai_credential_version_guard",
        "ai_execution_transition",
        "ai_remote_artifact_transition",
        "ai_refuse_delete",
    ):
        op.execute(f"DROP FUNCTION {function}()")

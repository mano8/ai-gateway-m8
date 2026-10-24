"""
``restore-reconcile`` and ``restore-ratify`` after an ``ai_db`` restore (D-42, D-43, D-45).

Operator commands (stop every gateway and scheduler process first)::

    python -m ai_gateway.restore reconcile [--vault]
    python -m ai_gateway.restore ratify --evidence <text>
    python -m ai_gateway.restore status

The state machine lives in the single ``ai_restore_state`` row:

1. **Entry** (``reconcile``) — the fail-closed reset, in one audited
   transaction: every provider disabled, every ``active`` credential
   ``reconfirm_required`` (its bindings follow), every ``fall_through``
   binding reset to ``fail``; ``hold_until`` = now + the context TTL + skew
   (contexts minted before the restore can no longer be replayed once it
   passes); ``budget_hold_until`` = the next UTC day (no ``--usage-from``
   reconstruction in V1). The event goes to the log sink and to
   ``/spool/.state/restore-events``. Execution refuses ``restore_detected``
   from here on.
2. **Replay safety** — the scheduler records it once ``hold_until`` passed.
3. **External reconciliation** — the spool in **restore mode** (a terminal
   row whose lock and file vanished after the snapshot point is released and
   audited as a restore artifact, never alerted as ``spool_lock_missing``;
   files whose row is absent are removed under the lock discipline) and, on
   the database backends, the audited residual-risk entry for provider files
   created under a version the restored database never saw. The ``vault`` KV
   reconciliation (C-06, ``--vault``) is ``T24``'s, not served by this build.
4. **Security report** — one audited summary of what the reset left for the
   owners and the superuser to re-confirm.
5. **Ratification** (``ratify``) — only once 2–4 completed: execution
   resumes (providers and credentials stay off until re-confirmed one by
   one), the budget hold stays until its day ends, and the high-water is
   re-baselined to this database.

The log-sink audit stream is evidence, never authority: ratification reads
only the database.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Final

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import CredentialStatus, OnUnavailable
from sqlalchemy import Connection, Engine

from ai_gateway.controllers.audit import Actor, AuditedTransaction, audited_transaction
from ai_gateway.controllers.bindings import sync_credential_status
from ai_gateway.core import restore_state
from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.installation import ai_restore_state
from ai_gateway.db_models.registry import ai_profile_binding, ai_provider
from ai_gateway.execution import spool
from ai_gateway.execution.spool import SpoolLayout
from ai_gateway.execution.sweepers import collect_orphans

logger = logging.getLogger(__name__)

_R, _E = ai_restore_state, ai_execution
_C, _P, _B = ai_credential, ai_provider, ai_profile_binding
_A = ai_provider_remote_artifact

_SCHEDULER: Final = Actor("system", "scheduler")


@dataclass(frozen=True)
class RestorePolicy:
    """The settings the state machine reads."""

    hold_seconds: int
    spool_root: Path | None
    storage_backend: str

    @classmethod
    def from_settings(cls, settings: object) -> RestorePolicy:
        """From gateway ``Settings``: the context TTL plus its skew, the spool."""
        ttl = int(str(getattr(settings, "AI_JOB_CONTEXT_MAX_TTL_SECONDS")))
        skew = int(str(getattr(settings, "AI_JOB_CONTEXT_CLOCK_SKEW_SECONDS")))
        root = getattr(settings, "AI_OCR_SPOOL_DIR")
        return cls(
            hold_seconds=ttl + skew,
            spool_root=None if root is None else Path(str(root)),
            storage_backend=str(getattr(settings, "AI_CREDENTIAL_STORAGE_BACKEND")),
        )


def _state(connection: Connection, *, lock: bool = False) -> sa.RowMapping | None:
    statement = sa.select(_R, restore_state.in_restore().label("held"))
    if lock:
        statement = statement.with_for_update(of=_R)
    return connection.execute(statement).mappings().first()


def _fail_closed(tx: AuditedTransaction, actor: Actor) -> dict[str, int]:
    """Disable every provider, hold every credential, reset every fall-through."""
    connection = tx.connection
    providers = connection.execute(
        sa.update(_P).where(_P.c.enabled.is_(True)).values(enabled=False)
    ).rowcount
    held = (
        connection.execute(
            sa.update(_C)
            .where(_C.c.status == CredentialStatus.ACTIVE.value)
            .values(
                status=CredentialStatus.RECONFIRM_REQUIRED.value,
                updated_at=sa.func.now(),
            )
            .returning(_C.c.id, _C.c.scope_type, _C.c.tenant_id, _C.c.owner_user_id)
        )
        .mappings()
        .all()
    )
    for row in held:
        bindings = sync_credential_status(connection, row["id"])
        tx.credential(
            actor,
            "credential.reconfirm_required",
            row["id"],
            dict(row),
            {"reason": "restore", "bindings_changed": bindings},
        )
    bindings = connection.execute(
        sa.update(_B)
        .where(_B.c.on_unavailable == OnUnavailable.FALL_THROUGH.value)
        .values(on_unavailable=OnUnavailable.FAIL.value)
    ).rowcount
    return {
        "providers_disabled": int(providers),
        "credentials_held": len(held),
        "fall_through_reset": int(bindings),
    }


def enter(engine: Engine, policy: RestorePolicy, actor: Actor) -> dict[str, object]:
    """
    Enter the restore state machine with the fail-closed reset.

    Re-running it while a restore is held changes nothing and reports the
    state; after a ratified restore it starts a new one.
    """
    with audited_transaction(engine) as tx:
        state = _state(tx.connection, lock=True)
        if state is None:
            raise RuntimeError(
                "ai_restore_state has no row; run the ai-migrate one-shot"
            )
        if state["held"]:
            return {"entered": False, "detected_at": state["detected_at"]}
        tx.connection.execute(
            sa.update(_R).values(
                detected_at=sa.func.now(),
                hold_until=sa.func.now() + timedelta(seconds=policy.hold_seconds),
                # The next UTC midnight of the database clock.
                budget_hold_until=sa.func.timezone(
                    "UTC",
                    sa.func.date_trunc("day", sa.func.timezone("UTC", sa.func.now()))
                    + timedelta(days=1),
                ),
                vault_quiescent_after=None,
                external_scan_completed_at=None,
                replay_safety_completed_at=None,
                external_reconciliation_completed_at=None,
                security_report_completed_at=None,
                ratified_by=None,
                ratified_at=None,
            )
        )
        reset = _fail_closed(tx, actor)
        tx.admin(actor, "restore.enter", "installation", None, reset)
    event = {"event": "restore.enter", **reset}
    logger.warning("restore_event %s", json.dumps(event, sort_keys=True))
    restore_state.append_event(policy.spool_root, event)
    return {"entered": True, **reset}


# --- the scheduler's steps -------------------------------------------------------------


def _mark(engine: Engine, column: str, fence: sa.ColumnElement[bool] | None) -> bool:
    where = sa.and_(restore_state.in_restore(), _R.c[column].is_(None))
    if fence is not None:
        where = sa.and_(where, fence)
    with engine.begin() as connection:
        return (
            connection.execute(
                sa.update(_R)
                .where(where)
                .values({column: sa.func.now()})
                .returning(_R.c.id)
            ).first()
            is not None
        )


def release_restore_artifacts(
    layout: SpoolLayout, engine: Engine, *, fence: sa.ColumnElement[bool] | None = None
) -> list[str]:
    """
    Restore mode: release spools whose lock vanished after the snapshot point.

    A terminal ``cleanup_pending`` row with ``spool_file_created`` and no lock
    file is, outside a restore, ``spool_lock_missing``; while a restore is held
    it is a spool cleaned after the backup point. Its file is removed if still
    present and its reservation released, audited as a restore artifact.
    """
    where = sa.and_(_E.c.cleanup_pending.is_(True), _E.c.spool_file_created.is_(True))
    with engine.connect() as connection:
        ids = list(connection.execute(sa.select(_E.c.id).where(where)).scalars())
    released: list[str] = []
    for execution_id in ids:
        if layout.lock(execution_id).exists():
            continue  # the normal cleaner owns it, under its lock
        with audited_transaction(engine) as tx:
            guard = sa.and_(
                where, _E.c.id == execution_id, restore_state.in_restore_exists()
            )
            if fence is not None:
                guard = sa.and_(guard, fence)
            row = tx.connection.execute(
                sa.select(_E.c.spool_bytes_reserved).where(guard).with_for_update(of=_E)
            ).first()
            if row is None:
                continue
            layout.data(execution_id).unlink(missing_ok=True)
            spool.release_reservation(tx.connection, execution_id, row[0])
            tx.admin(
                _SCHEDULER,
                "spool.restore_release",
                "execution",
                execution_id,
                {"spool_bytes_reserved": row[0], "restore_artifact": True},
            )
        released.append(str(execution_id))
    return released


def _external(
    engine: Engine,
    policy: RestorePolicy,
    fence: sa.ColumnElement[bool] | None,
) -> dict[str, object]:
    summary: dict[str, object] = {"storage_backend": policy.storage_backend}
    if policy.spool_root is not None:
        layout = SpoolLayout(policy.spool_root)
        summary["spool_released"] = len(
            release_restore_artifacts(layout, engine, fence=fence)
        )
        summary["spool_orphans_removed"] = len(collect_orphans(layout, engine))
    with audited_transaction(engine) as tx:
        if fence is not None and not tx.connection.execute(sa.select(fence)).scalar():
            return {}
        state = _state(tx.connection)
        assert state is not None  # nosec B101 - in_restore() matched it
        # Database backends: a version created after the backup point existed
        # nowhere else, so its provider files are beyond reach (D-43).
        tx.admin(
            _SCHEDULER,
            "restore.provider_files_residual",
            "installation",
            None,
            {
                "residual_risk": True,
                "window_ends": state["detected_at"].isoformat(),
                "bounded_by": "provider-side expiry",
                "storage_backend": policy.storage_backend,
            },
        )
        tx.connection.execute(
            sa.update(_R)
            .where(restore_state.in_restore())
            .values(external_scan_completed_at=sa.func.now())
        )
    return summary


def _report(engine: Engine, fence: sa.ColumnElement[bool] | None) -> dict[str, object]:
    with audited_transaction(engine) as tx:
        c = tx.connection
        if fence is not None and not c.execute(sa.select(fence)).scalar():
            return {}

        def count(statement: sa.Select[int]) -> int:
            return int(c.execute(statement).scalar_one())

        report: dict[str, object] = {
            "providers_disabled": count(
                sa.select(sa.func.count()).where(_P.c.enabled.is_(False))
            ),
            "credentials_reconfirm_required": count(
                sa.select(sa.func.count()).where(
                    _C.c.status == CredentialStatus.RECONFIRM_REQUIRED.value
                )
            ),
            "credentials_material_lost": count(
                sa.select(sa.func.count()).where(
                    _C.c.status == CredentialStatus.REPROVISION_REQUIRED.value
                )
            ),
            "remote_artifacts_manual_cleanup": count(
                sa.select(sa.func.count()).where(
                    _A.c.status == "manual_cleanup_required"
                )
            ),
            "executions_charged_uncertain": count(
                sa.select(sa.func.count()).where(
                    _E.c.status == "charged_uncertain", _E.c.reconciled_at.is_(None)
                )
            ),
        }
        tx.admin(_SCHEDULER, "restore.security_report", "installation", None, report)
    return report


def _replay(
    engine: Engine, _policy: RestorePolicy, _fence: sa.ColumnElement[bool] | None
) -> object:
    """Replay safety: due once ``hold_until`` passed on the database clock."""
    with engine.connect() as connection:
        due = connection.execute(sa.select(_R.c.hold_until <= sa.func.now())).scalar()
    return True if due else None


def _security(
    engine: Engine, _policy: RestorePolicy, fence: sa.ColumnElement[bool] | None
) -> object:
    report = _report(engine, fence)
    if report:
        logger.warning(
            "restore_event %s",
            json.dumps({"event": "restore.security_report", **report}, sort_keys=True),
        )
    return report


#: The steps in order: their result key, completion column and work.
_ORDER: Final = (
    ("replay_safety", "replay_safety_completed_at", _replay),
    ("external_reconciliation", "external_reconciliation_completed_at", _external),
    ("security_report", "security_report_completed_at", _security),
)


def advance(
    engine: Engine,
    policy: RestorePolicy,
    *,
    fence: sa.ColumnElement[bool] | None = None,
) -> dict[str, object]:
    """
    The scheduler's restore job: take every step whose predecessor completed.

    A step whose work returns nothing (not yet due, or the fence moved on) or
    whose completion stamp does not commit stops the pass.
    """
    with engine.connect() as connection:
        state = _state(connection)
    if state is None or not state["held"]:
        return {}
    done: dict[str, object] = {}
    for key, column, work in _ORDER:
        if state[column] is not None:
            continue
        result = work(engine, policy, fence)
        if not result or not _mark(engine, column, fence):
            break
        done[key] = result
    return done


# --- ratification ----------------------------------------------------------------------


def ratify(
    engine: Engine, policy: RestorePolicy, actor: Actor, evidence: str
) -> str | None:
    """Ratify a reconciled restore; ``None`` on success, else why not."""
    with audited_transaction(engine) as tx:
        state = _state(tx.connection, lock=True)
        if state is None or not state["held"]:
            return "no restore is held"
        missing = [column for _key, column, _work in _ORDER if state[column] is None]
        if missing:
            return f"steps not completed: {', '.join(missing)}"
        tx.connection.execute(
            sa.update(_R).values(ratified_at=sa.func.now(), ratified_by=actor.kind)
        )
        tx.admin(
            actor,
            "restore.ratify",
            "installation",
            None,
            {
                "evidence": evidence,
                "budget_hold_until": state["budget_hold_until"].isoformat(),
            },
        )
    if policy.spool_root is not None:
        restore_state.rebaseline(engine, policy.spool_root)
    event: dict[str, object] = {"event": "restore.ratify"}
    logger.warning("restore_event %s", json.dumps(event))
    restore_state.append_event(policy.spool_root, event)
    return None


def status(engine: Engine) -> dict[str, object]:
    """The restore row, for the operator (no secret)."""
    with engine.connect() as connection:
        state = _state(connection)
    return {} if state is None else {k: v for k, v in state.items() if k != "id"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ai_gateway.restore")
    commands = parser.add_subparsers(dest="command", required=True)
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--vault", action="store_true")
    ratification = commands.add_parser("ratify")
    ratification.add_argument("--evidence", required=True)
    commands.add_parser("status")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one command; ``0`` on success, ``1`` when refused, ``2`` when unsupported."""
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    from ai_gateway.core.deps import db_engine, settings  # noqa: PLC0415

    policy = RestorePolicy.from_settings(settings)
    operator = Actor("operator")
    if args.command == "reconcile":
        if args.vault:
            logger.error(
                "restore-reconcile --vault: the vault KV backend is not served by "
                "this build (T24); nothing to reconcile"
            )
            return 2
        print(json.dumps(enter(db_engine, policy, operator), default=str))
        return 0
    if args.command == "ratify":
        refused = ratify(db_engine, policy, operator, args.evidence)
        if refused is not None:
            logger.error("restore-ratify refused: %s", refused)
            return 1
        print(json.dumps({"ratified": True}))
        return 0
    print(json.dumps(status(db_engine), default=str))
    return 0


__all__ = [
    "RestorePolicy",
    "advance",
    "enter",
    "main",
    "ratify",
    "release_restore_artifacts",
    "status",
]

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

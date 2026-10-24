"""
Restore detection, ``restore-reconcile`` and ``restore-ratify`` (T33a).

A restore is simulated the way it looks from inside: the spool's high-water
file ahead of the database's ``ai_db_epoch``, or the operator entering the
state machine. Every refusal is taken on the shipped reservation path.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass, OcrOptions
from ai_sdk_m8.schemas.management import ProviderBoundary, ProviderType

from ai_gateway import restore
from ai_gateway.core import deps, restore_state
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.execution_guard import require_restore_clear
from ai_gateway.db_models.accounting import ai_execution, ai_spool_capacity
from ai_gateway.db_models.audit import ai_admin_audit, ai_credential_audit
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.installation import ai_restore_state
from ai_gateway.db_models.registry import ai_profile_binding, ai_provider
from ai_gateway.execution import ocr
from ai_gateway.execution.limits import ExecutionLimits
from ai_gateway.execution.reservation import reserve
from ai_gateway.execution.spool import SpoolLayout
from ai_gateway.execution.sweepers import clean_spools, sweep_spools
from ai_gateway.restore import RestorePolicy
from execution_world import (
    BYOK_POLICY,
    OPEN,
    age,
    embed_job,
    make_binding,
    make_credential,
    make_model,
    make_profile,
    make_provider,
    principal,
    world,
)
import pg_harness as pg

pytestmark = pytest.mark.usefixtures("clean_db")

_R = ai_restore_state


@pytest.fixture(autouse=True)
def no_restore() -> Iterator[None]:
    """``ai_restore_state`` is kept across tests: leave it as found."""
    yield
    with deps.db_engine.begin() as c:
        c.execute(
            sa.update(_R).values(
                {column.name: None for column in _R.columns if column.name != "id"}
            )
        )


@pytest.fixture
def spool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "spool"
    root.mkdir()
    monkeypatch.setattr(settings, "AI_OCR_SPOOL_DIR", root)
    with deps.db_engine.begin() as c:
        c.execute(sa.update(ai_spool_capacity).values(reserved_bytes=0))
    return root


def policy(spool_root: Path | None = None, hold: int = 3600) -> RestorePolicy:
    return RestorePolicy(
        hold_seconds=hold, spool_root=spool_root, storage_backend="database"
    )


def state() -> Any:
    with deps.db_engine.connect() as c:
        return c.execute(sa.select(_R)).mappings().one()


def actions(table: sa.Table = ai_admin_audit) -> list[str]:
    with deps.db_engine.connect() as c:
        return list(c.execute(sa.select(table.c.action).order_by(table.c.id)).scalars())


def superuser(statement: Any) -> None:
    admin = pg.admin_engine(pg.DB_NAME)
    try:
        with admin.connect() as c:
            c.execute(sa.text("SET session_replication_role = replica"))
            c.execute(statement)
    finally:
        admin.dispose()


def hold_passed() -> None:
    superuser(sa.update(_R).values(hold_until=sa.func.now() - timedelta(seconds=1)))


def embed(w: Any, limits: ExecutionLimits = OPEN) -> Any:
    return reserve(
        deps.db_engine,
        principal(w.profile_key),
        embed_job(w.profile_key),
        policy=BYOK_POLICY,
        limits=limits,
    )


def keyed() -> dict[str, Any]:
    """An external keyed provider with a fall-through tenant binding."""
    provider_id = make_provider(
        ProviderBoundary.EXTERNAL, ProviderType.OPENAI_COMPATIBLE
    )
    model_id = make_model(provider_id, Capability.EMBEDDING)
    profile_id, _key = make_profile(Capability.EMBEDDING)
    credential_id = make_credential(provider_id)
    binding_id = make_binding(
        profile_id, model_id, credential_id, on_unavailable="fall_through"
    )
    return {
        "provider_id": provider_id,
        "credential_id": credential_id,
        "binding_id": binding_id,
    }


def column(table: sa.Table, row_id: uuid.UUID, name: str) -> Any:
    with deps.db_engine.connect() as c:
        return c.execute(
            sa.select(table.c[name]).where(table.c.id == row_id)
        ).scalar_one()


# --- the high-water (D-45 volume, ai_db_epoch) --------------------------------------


def test_the_high_water_rises_and_a_database_behind_it_is_a_restore(
    spool: Path,
) -> None:
    first = restore_state.write_highwater(deps.db_engine, spool)
    assert first is not None and restore_state.read_highwater(spool) == first
    second = restore_state.write_highwater(deps.db_engine, spool)
    assert second is not None and second > first
    path = spool / ".state" / "db-highwater"
    assert path.stat().st_mode & 0o777 == 0o600
    # A snapshot restore rewinds the sequence; the volume keeps the file.
    path.write_text(f"{second + 1000}\n")
    with deps.db_engine.connect() as c:
        assert restore_state.database_behind(c, spool)
        with pytest.raises(GatewayError) as refused:
            restore_state.assert_not_held(c, spool, budgeted=False)
    assert refused.value.code is AiErrorCode.RESTORE_DETECTED
    with pytest.raises(GatewayError) as guarded:
        require_restore_clear()
    assert guarded.value.code is AiErrorCode.RESTORE_DETECTED
    # The scheduler never lowers it while the database is behind.
    assert restore_state.write_highwater(deps.db_engine, spool) is None
    assert restore_state.read_highwater(spool) == second + 1000
    lowered = restore_state.rebaseline(deps.db_engine, spool)
    assert restore_state.read_highwater(spool) == lowered < second + 1000
    with deps.db_engine.connect() as c:
        assert not restore_state.database_behind(c, spool)
    require_restore_clear()


def test_without_a_spool_there_is_no_high_water_to_compare(tmp_path: Path) -> None:
    with deps.db_engine.connect() as c:
        assert not restore_state.database_behind(c, None)
        assert not restore_state.database_behind(c, tmp_path)  # no file yet
        assert restore_state.database_epoch(c) >= 0
    restore_state.append_event(None, {"event": "ignored"})
    assert restore_state.read_highwater(tmp_path) is None


def test_a_missing_restore_row_holds_nothing() -> None:
    owner = pg.owner_engine()
    try:
        with owner.begin() as c:
            c.execute(sa.delete(_R))
        with deps.db_engine.connect() as c:
            restore_state.assert_not_held(c, None, budgeted=True)
    finally:
        with owner.begin() as c:
            c.execute(sa.insert(_R).values(id=1))
        owner.dispose()


def test_the_spool_job_releases_restore_artifacts_under_its_fence(
    spool: Path, tmp_path: Path
) -> None:
    from ai_gateway.scheduler.jobs import JobContext, build_jobs
    from ai_gateway.scheduler.lease import LeaseKeeper

    lock_missing_spool(spool)
    restore.enter(deps.db_engine, policy(spool), restore.Actor("operator"))
    (job,) = [
        j
        for j in build_jobs(
            JobContext(
                engine=deps.db_engine,
                artifacts=deps.artifact_scheduler,
                digests=deps.model_digests,
                restore=policy(spool),
                retention_days=90,
                spool_root=spool,
            )
        )
        if j.name == "spool"
    ]
    lease = LeaseKeeper(deps.db_engine, "a").hold("spool")
    assert lease is not None
    from execution_world import run

    summary = run(job.run(lease))
    assert summary["restore_released"] == 1 and summary["cleaned"] == {}
    assert capacity() == 0


# --- entry: the fail-closed reset --------------------------------------------------------


def test_entry_resets_every_relaxing_control_and_records_the_event(
    spool: Path, caplog: pytest.LogCaptureFixture
) -> None:
    k = keyed()
    with caplog.at_level(logging.WARNING):
        outcome = restore.enter(
            deps.db_engine, policy(spool), restore.Actor("operator")
        )
    assert outcome == {
        "entered": True,
        "providers_disabled": 1,
        "credentials_held": 1,
        "fall_through_reset": 1,
    }
    assert column(ai_provider, k["provider_id"], "enabled") is False
    assert column(ai_credential, k["credential_id"], "status") == "reconfirm_required"
    assert column(ai_profile_binding, k["binding_id"], "on_unavailable") == "fail"
    assert column(ai_profile_binding, k["binding_id"], "status") == (
        "credential_unavailable"
    )
    row = state()
    tomorrow = (datetime.now(UTC) + timedelta(days=1)).date()
    assert row["budget_hold_until"] == datetime(
        tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=UTC
    )
    assert row["hold_until"] - row["detected_at"] == timedelta(seconds=3600)
    assert actions() == ["restore.enter"]
    assert actions(ai_credential_audit)[-1] == "credential.reconfirm_required"
    assert "restore_event" in caplog.text
    (event,) = (spool / ".state" / "restore-events").read_text().splitlines()
    assert json.loads(event)["event"] == "restore.enter"
    again = restore.enter(deps.db_engine, policy(spool), restore.Actor("operator"))
    assert again["entered"] is False and actions() == ["restore.enter"]


def test_execution_refuses_restore_detected_until_ratified() -> None:
    w = world()
    restore.enter(deps.db_engine, policy(), restore.Actor("operator"))
    with pytest.raises(GatewayError) as refused:
        embed(w)
    assert refused.value.code is AiErrorCode.RESTORE_DETECTED
    assert refused.value.retry_after_seconds == restore_state.HOLD_RETRY_SECONDS
    with pytest.raises(GatewayError) as guarded:
        require_restore_clear()
    assert guarded.value.code is AiErrorCode.RESTORE_DETECTED


def test_a_spool_cannot_open_while_a_restore_is_held(spool: Path) -> None:
    from ocr_world import mistral_world

    w = mistral_world()
    restore.enter(deps.db_engine, policy(spool), restore.Actor("operator"))
    context = principal(
        w["key"],
        Capability.OCR,
        data_class=DataClass.PUBLIC,
        phase="spool",
        input_sha256="a" * 64,
        input_bytes=10,
        ocr_options_hash=ocr.options_hash(OcrOptions()),
    )
    with pytest.raises(GatewayError) as refused:
        ocr.open_spool(
            deps.db_engine,
            context,
            config=ocr.SpoolConfig.from_settings(settings),
            limits=OPEN,
            unit=4096,
        )
    assert refused.value.code is AiErrorCode.RESTORE_DETECTED


def test_entry_needs_the_seeded_row(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(restore, "_state", lambda *_a, **_k: None)
    with pytest.raises(RuntimeError, match="ai-migrate"):
        restore.enter(deps.db_engine, policy(), restore.Actor("operator"))
    assert restore.status(deps.db_engine) == {}


# --- the scheduler's steps and ratification ------------------------------------------


def lock_missing_spool(spool: Path) -> uuid.UUID:
    """A terminal row whose spool was cleaned after the snapshot point."""
    from ocr_world import mistral_world

    w = mistral_world()
    context = principal(
        w["key"],
        Capability.OCR,
        data_class=DataClass.PUBLIC,
        phase="spool",
        input_sha256="a" * 64,
        input_bytes=10,
        ocr_options_hash=ocr.options_hash(OcrOptions()),
    )
    execution_id = ocr.open_spool(
        deps.db_engine,
        context,
        config=ocr.SpoolConfig.from_settings(settings),
        limits=OPEN,
        unit=4096,
    )
    age(
        execution_id,
        spool_lease_until=datetime.now(UTC) - timedelta(seconds=1),
        spool_file_created=True,
    )
    assert sweep_spools(deps.db_engine) == [execution_id]
    return execution_id


def capacity() -> int:
    with deps.db_engine.connect() as c:
        return int(
            c.execute(sa.select(ai_spool_capacity.c.reserved_bytes)).scalar_one()
        )


def test_the_steps_run_in_order_and_ratification_waits_for_all_three(
    spool: Path, caplog: pytest.LogCaptureFixture
) -> None:
    execution_id = lock_missing_spool(spool)
    assert capacity() == 4096
    p = policy(spool)
    assert restore.advance(deps.db_engine, p) == {}  # nothing held
    restore.enter(deps.db_engine, p, restore.Actor("operator"))
    assert restore.ratify(deps.db_engine, p, restore.Actor("operator"), "x") == (
        "steps not completed: replay_safety_completed_at, "
        "external_reconciliation_completed_at, security_report_completed_at"
    )
    assert restore.advance(deps.db_engine, p) == {}  # the replay hold still runs
    hold_passed()
    with caplog.at_level(logging.WARNING):
        done = restore.advance(deps.db_engine, p)
        assert "spool_lock_missing" not in caplog.text
    assert done["replay_safety"] is True
    assert done["external_reconciliation"] == {
        "storage_backend": "database",
        "spool_released": 1,
        "spool_orphans_removed": 0,
    }
    report = done["security_report"]
    assert report["providers_disabled"] == 1
    assert report["credentials_reconfirm_required"] == 1
    assert capacity() == 0
    with deps.db_engine.connect() as c:
        row = c.execute(
            sa.select(ai_execution.c.cleanup_pending).where(
                ai_execution.c.id == execution_id
            )
        ).scalar_one()
    assert row is False
    assert clean_spools(SpoolLayout(spool), deps.db_engine) == {}
    assert actions() == [
        "restore.enter",
        "spool.restore_release",
        "restore.provider_files_residual",
        "restore.security_report",
    ]
    assert restore.advance(deps.db_engine, p) == {}  # every step taken once
    restore_state.write_highwater(deps.db_engine, spool)
    (spool / ".state" / "db-highwater").write_text("999999\n")
    assert restore.ratify(deps.db_engine, p, restore.Actor("operator"), "ok") is None
    row = state()
    assert row["ratified_at"] is not None and row["ratified_by"] == "operator"
    assert restore_state.read_highwater(spool) < 999999  # re-baselined
    assert actions()[-1] == "restore.ratify"
    events = (spool / ".state" / "restore-events").read_text().splitlines()
    assert [json.loads(e)["event"] for e in events] == [
        "restore.enter",
        "restore.ratify",
    ]
    assert restore.ratify(deps.db_engine, p, restore.Actor("operator"), "x") == (
        "no restore is held"
    )


def test_the_budget_stays_held_until_the_next_utc_day_after_ratification() -> None:
    w = world()
    p = policy(hold=1)
    restore.enter(deps.db_engine, p, restore.Actor("operator"))
    hold_passed()
    restore.advance(deps.db_engine, p)
    assert restore.ratify(deps.db_engine, p, restore.Actor("operator"), "ok") is None
    budgeted = ExecutionLimits(
        client_daily_units=100, reservation_ttl_seconds=60, total_deadline_seconds=30
    )
    with pytest.raises(GatewayError) as refused:
        embed(w, budgeted)
    assert refused.value.code is AiErrorCode.QUOTA_EXCEEDED
    assert 0 < (refused.value.retry_after_seconds or 0) <= 86400
    fresh = world()  # the restore disabled the first world's provider
    assert embed(fresh).execution_id is not None  # no budget: nothing to undercount


def test_a_new_restore_after_a_ratified_one_starts_over() -> None:
    p = policy(hold=1)
    restore.enter(deps.db_engine, p, restore.Actor("operator"))
    hold_passed()
    restore.advance(deps.db_engine, p)
    restore.ratify(deps.db_engine, p, restore.Actor("operator"), "ok")
    again = restore.enter(deps.db_engine, p, restore.Actor("operator"))
    assert again["entered"] is True
    row = state()
    assert row["ratified_at"] is None and row["security_report_completed_at"] is None


def test_a_stale_scheduler_takes_no_restore_step() -> None:
    from ai_gateway.scheduler.lease import LeaseKeeper

    p = policy(hold=1)
    restore.enter(deps.db_engine, p, restore.Actor("operator"))
    hold_passed()
    a, b = LeaseKeeper(deps.db_engine, "a"), LeaseKeeper(deps.db_engine, "b")
    stale = a.hold("restore")
    assert stale is not None
    superuser(
        sa.text(
            "UPDATE ai_scheduler_lease SET lease_until = now() - interval '1 second'"
        )
    )
    assert b.hold("restore") is not None
    assert restore.advance(deps.db_engine, p, fence=stale.fence()) == {}
    assert state()["replay_safety_completed_at"] is None
    # Each later step refuses a stale fence on its own as well.
    superuser(sa.update(_R).values(replay_safety_completed_at=sa.func.now()))
    assert restore.advance(deps.db_engine, p, fence=stale.fence()) == {}
    superuser(sa.update(_R).values(external_reconciliation_completed_at=sa.func.now()))
    assert restore.advance(deps.db_engine, p, fence=stale.fence()) == {}
    assert state()["security_report_completed_at"] is None


def test_restore_mode_leaves_a_spool_with_a_live_lock_to_the_cleaner(
    spool: Path,
) -> None:
    execution_id = lock_missing_spool(spool)
    layout = SpoolLayout(spool)
    layout.locks.mkdir(exist_ok=True)
    layout.lock(execution_id).touch()
    restore.enter(deps.db_engine, policy(spool), restore.Actor("operator"))
    assert restore.release_restore_artifacts(layout, deps.db_engine) == []
    superuser(sa.update(_R).values(ratified_at=sa.func.now()))
    layout.lock(execution_id).unlink()
    # Outside a restore the same row is never released here.
    assert restore.release_restore_artifacts(layout, deps.db_engine) == []
    assert capacity() == 4096


# --- the operator commands ----------------------------------------------------------------


def test_the_operator_commands(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_JOB_CONTEXT_MAX_TTL_SECONDS", 1)
    assert restore.main(["reconcile", "--vault"]) == 2
    assert restore.main(["reconcile"]) == 0
    assert json.loads(capsys.readouterr().out)["entered"] is True
    assert restore.main(["ratify", "--evidence", "too early"]) == 1
    hold_passed()
    restore.advance(deps.db_engine, RestorePolicy.from_settings(settings))
    assert restore.main(["status"]) == 0
    assert json.loads(capsys.readouterr().out)["security_report_completed_at"]
    assert restore.main(["ratify", "--evidence", "ticket 42"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ratified": True}

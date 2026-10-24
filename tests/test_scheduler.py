"""
The scheduler run-mode (T33a, D-42): lease, fence, per-item claims and jobs.

Leases are taken by two keepers against the one database, as two replicas
would; a "paused" leader is one whose lease row was aged past
``lease_until`` while it held it, then resumed with its old token. Jobs run
the shipped functions on rows the shipped handlers produced.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess  # nosec B404 - runs this interpreter on the shipped module
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import Capability
from ai_sdk_m8.schemas.management import ProviderType

from ai_gateway import main as web
from ai_gateway import scheduler as entrypoint
from ai_gateway.core import deps
from ai_gateway.core.config import Settings
from ai_gateway.credentials.destruction import destroy_retired
from ai_gateway.credentials.factory import build_credential_store
from ai_gateway.db_models.accounting import ai_client_occupancy, ai_rate_window
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.audit import ai_credential_audit
from ai_gateway.db_models.installation import ai_scheduler_lease
from ai_gateway.db_models.registry import ai_provider
from ai_gateway.execution import artifacts as artifact_module
from ai_gateway.execution import settlement
from ai_gateway.execution.artifacts import accept_residual
from ai_gateway.execution.reservation import reserve
from ai_gateway.execution.sweepers import (
    prune_rate_windows,
    repair_occupancy,
    sweep_contexts,
)
from ai_gateway.restore import RestorePolicy
from ai_gateway.scheduler.jobs import (
    SCHEDULE,
    Job,
    JobContext,
    build_jobs,
    expected_jobs,
    late_after,
)
from ai_gateway.scheduler.lease import LEASE_TTL_SECONDS, Lease, LeaseKeeper
from ai_gateway.scheduler.heartbeat import healthy, heartbeat_age, touch
from ai_gateway.scheduler.runner import POLL_CAP_SECONDS, Scheduler, last_successes
from conftest import MEDIA_SERVICE
from execution_world import (
    BYOK_POLICY,
    OPEN,
    age,
    embed_job,
    execution,
    occupied,
    principal,
    rotate,
    run,
    world,
)
from mistral_stub import MistralStub
from ocr_world import BLOB, artifacts, dispatch, due, mistral, mistral_world, scheduler
import pg_harness as pg

pytestmark = pytest.mark.usefixtures("clean_db")

_L = ai_scheduler_lease
_A = ai_provider_remote_artifact


# --- helpers --------------------------------------------------------------------------


def superuser(statement: Any) -> None:
    """Run ``statement`` as the database superuser with triggers off."""
    admin = pg.admin_engine(pg.DB_NAME)
    try:
        with admin.connect() as c:
            c.execute(sa.text("SET session_replication_role = replica"))
            c.execute(statement)
    finally:
        admin.dispose()


def expire(job: str) -> None:
    """The holder of ``job`` paused past its lease."""
    superuser(
        sa.update(_L)
        .where(_L.c.job == job)
        .values(lease_until=sa.func.now() - timedelta(seconds=1))
    )


def lease_row(job: str) -> Any:
    with deps.db_engine.connect() as c:
        return c.execute(sa.select(_L).where(_L.c.job == job)).mappings().one()


def pending() -> uuid.UUID:
    """An embed reservation whose ``pending`` lease already ran out."""
    w = world()
    r = reserve(
        deps.db_engine,
        principal(w.profile_key),
        embed_job(w.profile_key),
        policy=BYOK_POLICY,
        limits=OPEN,
    )
    age(r.execution_id, reservation_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    return r.execution_id


def keepers() -> tuple[LeaseKeeper, LeaseKeeper]:
    return LeaseKeeper(deps.db_engine, "a"), LeaseKeeper(deps.db_engine, "b")


def counting(name: str, interval: int = 15) -> tuple[Job, list[Lease]]:
    seen: list[Lease] = []

    async def body(lease: Lease) -> dict[str, object]:
        seen.append(lease)
        return {"ran": True}

    return Job(name, interval, body), seen


# --- the lease (D-42) -------------------------------------------------------------------


def test_one_replica_holds_a_lease_and_renews_it_under_the_same_epoch() -> None:
    a, b = keepers()
    first = a.hold("settlement")
    assert first is not None and first.epoch == 1 and len(first.holder_token) == 32
    assert b.hold("settlement") is None
    again = a.hold("settlement")
    assert again == first  # renewed, not re-acquired
    row = lease_row("settlement")
    assert row["holder"] == "a" and row["holder_token"] == first.holder_token
    assert a.holder == "a"


def test_a_killed_replica_lease_expires_and_another_takes_over() -> None:
    a, b = keepers()
    first = a.hold("contexts")
    assert first is not None
    expire("contexts")  # the process died without giving the lease up
    second = b.hold("contexts")
    assert second is not None and second.epoch == first.epoch + 1
    assert second.holder_token != first.holder_token
    assert a.hold("contexts") is None  # the missed renewal: it stops


def test_a_paused_leader_commits_nothing_after_a_successor_took_epoch_n_plus_1() -> (
    None
):
    execution_id = pending()
    a, b = keepers()
    stale = a.hold("settlement")
    assert stale is not None
    expire("settlement")  # SIGSTOP past the lease …
    fresh = b.hold("settlement")
    assert fresh is not None and fresh.epoch == stale.epoch + 1
    # … then SIGCONT: the old fence matches no lease row.
    assert settlement.sweep_expired_pending(deps.db_engine, fence=stale.fence()) == []
    assert execution(execution_id)["status"] == "pending"
    assert a.hold("settlement") is None
    assert settlement.sweep_expired_pending(deps.db_engine, fence=fresh.fence()) == [
        execution_id
    ]
    assert execution(execution_id)["status"] == "abandoned" and occupied() == 0


def test_a_leader_whose_database_was_restored_commits_nothing() -> None:
    a, _ = keepers()
    lease = a.hold("settlement")
    assert lease is not None
    # A restore rewinds the row: the epoch may even match, the token cannot.
    superuser(
        sa.update(_L)
        .where(_L.c.job == "settlement")
        .values(holder_token="0" * 32, epoch=lease.epoch)
    )
    with deps.db_engine.connect() as c:
        assert c.execute(sa.select(lease.fence())).scalar() is False
    assert not a.succeeded(lease)
    assert a.hold("settlement") is None


def test_release_hands_the_leases_over_at_once() -> None:
    a, b = keepers()
    assert a.hold("contexts") is not None
    a.release()
    assert b.hold("contexts") is not None


# --- the runner ------------------------------------------------------------------------


def test_two_replicas_run_a_job_exactly_once_per_tick(tmp_path: Path) -> None:
    job, seen = counting("contexts")
    a, b = keepers()
    first = Scheduler(deps.db_engine, a, [job], heartbeat=tmp_path / "a")
    second = Scheduler(deps.db_engine, b, [job], heartbeat=tmp_path / "b")
    assert run(first.tick()) == {"contexts": {"ran": True}}
    assert run(second.tick()) == {}
    assert len(seen) == 1 and lease_row("contexts")["last_success_at"] is not None


def test_a_successor_does_not_rerun_a_job_inside_its_interval(tmp_path: Path) -> None:
    job, seen = counting("contexts", interval=3600)
    a, b = keepers()
    assert run(Scheduler(deps.db_engine, a, [job], heartbeat=tmp_path / "a").tick())
    expire("contexts")  # a restart: the old process is gone, its lease too
    restarted = Scheduler(deps.db_engine, b, [job], heartbeat=tmp_path / "b")
    assert run(restarted.tick()) == {} and len(seen) == 1
    superuser(sa.update(_L).values(last_success_at=sa.func.now() - timedelta(hours=2)))
    restarted._next_poll.clear()
    assert run(restarted.tick()) == {"contexts": {"ran": True}} and len(seen) == 2


def test_a_failing_job_is_not_stamped_and_never_stops_the_others(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def broken(_lease: Lease) -> dict[str, object]:
        raise RuntimeError("stuck provider")

    job, seen = counting("contexts")
    a, _ = keepers()
    work = Scheduler(
        deps.db_engine, a, [Job("retention", 60, broken), job], heartbeat=tmp_path / "h"
    )
    with caplog.at_level(logging.ERROR):
        assert run(work.tick()) == {"contexts": {"ran": True}}
    assert "scheduler job retention failed" in caplog.text
    assert lease_row("retention")["last_success_at"] is None and len(seen) == 1


def test_a_job_that_loses_its_lease_while_running_is_not_stamped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def slow(_lease: Lease) -> dict[str, object]:
        expire("credentials")
        return {}

    a, _ = keepers()
    work = Scheduler(
        deps.db_engine, a, [Job("credentials", 60, slow)], heartbeat=tmp_path / "h"
    )
    with caplog.at_level(logging.WARNING):
        assert run(work.tick()) == {}
    assert "lost its lease while running" in caplog.text
    assert lease_row("credentials")["last_success_at"] is None


def test_polls_are_spaced_by_the_interval_capped_at_a_third_of_the_lease(
    tmp_path: Path,
) -> None:
    now = [1000.0]
    job, _ = counting("contexts", interval=15)
    slow, _ = counting("retention", interval=3600)
    work = Scheduler(
        deps.db_engine,
        keepers()[0],
        [job, slow],
        heartbeat=tmp_path / "h",
        clock=lambda: now[0],
    )
    run(work.tick())
    assert work._next_poll == {
        "contexts": 1015.0,
        "retention": 1000.0 + POLL_CAP_SECONDS,
    }
    assert POLL_CAP_SECONDS == LEASE_TTL_SECONDS // 3
    now[0] += 1
    assert run(work.tick()) == {}


def test_serve_stops_on_the_event_and_gives_its_leases_up(tmp_path: Path) -> None:
    stop = asyncio.Event()

    async def last(_lease: Lease) -> dict[str, object]:
        stop.set()
        return {}

    a, b = keepers()
    work = Scheduler(
        deps.db_engine, a, [Job("contexts", 15, last)], heartbeat=tmp_path / "h"
    )
    run(work.serve(stop))
    assert (tmp_path / "h").exists() and b.hold("contexts") is not None


def test_serve_waits_between_passes(tmp_path: Path) -> None:
    async def go() -> int:
        stop = asyncio.Event()
        passes = [0]
        work = Scheduler(deps.db_engine, keepers()[0], [], heartbeat=tmp_path / "h")
        original = work.tick

        async def counted() -> dict[str, Any]:
            passes[0] += 1
            if passes[0] == 2:
                stop.set()
            return await original()

        work.tick = counted  # type: ignore[method-assign]
        await work.serve(stop)
        return passes[0]

    assert run(go()) == 2


def test_the_heartbeat_answers_the_container_probe(tmp_path: Path) -> None:
    beat = tmp_path / "beat"
    assert heartbeat_age(beat) is None and not healthy(beat)
    touch(beat)
    age_now = heartbeat_age(beat)
    assert age_now is not None and age_now < 5 and healthy(beat)
    old = time.time() - 600
    os.utime(beat, (old, old))
    assert not healthy(beat)
    assert heartbeat_age(beat, now=old + 7) == pytest.approx(7, abs=1)


# --- /health (D-42) --------------------------------------------------------------------


def stamp(ages: dict[str, int]) -> None:
    with deps.db_engine.begin() as c:
        for job, seconds in ages.items():
            c.execute(
                sa.insert(_L).values(
                    job=job,
                    last_success_at=sa.func.now() - timedelta(seconds=seconds),
                )
            )


def test_health_degrades_on_a_job_that_never_ran_or_is_stuck() -> None:
    result = run(web.check_scheduler())
    assert result.status == "degraded" and "settlement" in result.meta["late"]
    assert "spool" not in result.meta["late"]  # no spool configured here
    stamp(dict.fromkeys(SCHEDULE, 1))
    result = run(web.check_scheduler())
    assert result.status == "ok" and result.meta["late"] == []
    assert result.meta["last_success_age_seconds"]["settlement"] <= 2
    superuser(
        sa.update(_L)
        .where(_L.c.job == "settlement")
        .values(last_success_at=sa.func.now() - timedelta(hours=1))
    )
    result = run(web.check_scheduler())
    assert result.status == "degraded" and result.meta["late"] == ["settlement"]


def test_health_fails_when_the_lease_table_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(_engine: Any) -> Any:
        raise sa.exc.OperationalError("SELECT", {}, Exception("down"))

    monkeypatch.setattr(web, "last_successes", broken)
    result = run(web.check_scheduler())
    assert result.status == "fail" and result.error == "OperationalError"


def test_thresholds_follow_the_schedule() -> None:
    assert late_after(15) == 15 + LEASE_TTL_SECONDS + 60
    assert late_after(3600) == 3 * 3600
    assert "spool" in expected_jobs(spool=True)
    assert set(expected_jobs(spool=False)) == set(SCHEDULE) - {"spool"}
    stamp({"contexts": 5})
    assert last_successes(deps.db_engine)["contexts"] == pytest.approx(5, abs=2)


# --- the jobs ---------------------------------------------------------------------------


def job_context(spool_root: Path | None = None) -> JobContext:
    return JobContext(
        engine=deps.db_engine,
        artifacts=deps.artifact_scheduler,
        digests=deps.model_digests,
        restore=RestorePolicy(
            hold_seconds=1, spool_root=spool_root, storage_backend="database"
        ),
        retention_days=90,
        spool_root=spool_root,
    )


def test_every_job_runs_its_pass_under_the_lease(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    spool.mkdir()
    execution_id = pending()
    jobs = build_jobs(job_context(spool))
    assert [j.name for j in jobs] == list(SCHEDULE)
    work = Scheduler(deps.db_engine, keepers()[0], jobs, heartbeat=tmp_path / "h")
    ran = run(work.tick())
    assert set(ran) == set(SCHEDULE)
    assert ran["settlement"] == {"pending": 1, "dispatching": 0, "spools": 0}
    assert ran["spool"]["highwater"] >= 1 and ran["restore"] == {}
    assert ran["retention"]["executions"] == 0
    assert execution(execution_id)["status"] == "abandoned"
    assert (spool / ".state" / "db-highwater").exists()
    assert entrypoint.HEARTBEAT_FILE.name == "ai_gateway_scheduler.heartbeat"


def test_without_a_spool_there_is_no_spool_job() -> None:
    assert "spool" not in [j.name for j in build_jobs(job_context())]


def test_build_scheduler_wires_the_process_dependencies(tmp_path: Path) -> None:
    built = entrypoint.build_scheduler(tmp_path / "h")
    assert [j.name for j in built._jobs] == [n for n in SCHEDULE if n != "spool"]
    assert built._keeper.holder.endswith(f":{os.getpid()}")


def test_rate_windows_older_than_two_windows_are_pruned() -> None:
    with deps.db_engine.begin() as c:
        for minutes in (0, 1, 2, 5):
            c.execute(
                sa.insert(ai_rate_window).values(
                    principal_key=f"k{minutes}",
                    window_start=sa.func.date_trunc("minute", sa.func.now())
                    - timedelta(minutes=minutes),
                    count=1,
                )
            )
    a, b = keepers()
    lease = a.hold("rate_windows")
    assert lease is not None
    expire("rate_windows")
    assert b.hold("rate_windows") is not None
    assert prune_rate_windows(deps.db_engine, fence=lease.fence()) == 0
    assert prune_rate_windows(deps.db_engine) == 1
    with deps.db_engine.connect() as c:
        keys = set(c.execute(sa.select(ai_rate_window.c.principal_key)).scalars())
    assert keys == {"k0", "k1", "k2"}


def test_the_context_sweep_carries_the_fence() -> None:
    a, b = keepers()
    lease = a.hold("contexts")
    assert lease is not None
    expire("contexts")
    assert b.hold("contexts") is not None
    assert sweep_contexts(deps.db_engine, fence=lease.fence()) == 0


# --- occupancy repair (the locked recount) ---------------------------------------------


def set_counter(value: int) -> None:
    superuser(
        sa.update(ai_client_occupancy)
        .where(ai_client_occupancy.c.client_id == MEDIA_SERVICE.client_id)
        .values(occupied=value)
    )


def live_rows() -> int:
    from ai_gateway.db_models.accounting import ai_execution

    with deps.db_engine.connect() as c:
        return int(
            c.execute(
                sa.select(sa.func.count()).where(
                    ai_execution.c.occupancy_released_at.is_(None)
                )
            ).scalar_one()
        )


@pytest.mark.parametrize("step", ["before", "locked", "counted"])
def test_the_repair_loses_no_concurrent_admission_or_settlement(step: str) -> None:
    w = world()

    def admission() -> None:
        reserve(
            deps.db_engine,
            principal(w.profile_key),
            embed_job(w.profile_key),
            policy=BYOK_POLICY,
            limits=OPEN,
        )

    first = reserve(
        deps.db_engine,
        principal(w.profile_key),
        embed_job(w.profile_key),
        policy=BYOK_POLICY,
        limits=OPEN,
    ).execution_id
    admission()
    age(first, reservation_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    set_counter(7)  # drifted: two rows are live
    racers = [
        threading.Thread(target=admission),
        threading.Thread(
            target=lambda: settlement.sweep_expired_pending(deps.db_engine)
        ),
    ]
    blocked: list[bool] = []

    def pause(at: str) -> None:
        if at != step:
            return
        for racer in racers:
            racer.start()
        time.sleep(1.0)
        blocked.append(all(racer.is_alive() for racer in racers))

    if step == "before":
        for racer in racers:
            racer.start()
        for racer in racers:
            racer.join()
    changed = repair_occupancy(deps.db_engine, pause=pause)
    for racer in racers:
        racer.join(timeout=30)
    if step != "before":
        assert blocked == [True]  # both waited on the counter row's lock
    assert occupied() == live_rows() == 2
    assert execution(first)["status"] == "abandoned"
    assert changed[MEDIA_SERVICE.client_id] != 0


def test_the_repair_creates_a_missing_counter_and_obeys_the_fence() -> None:
    w = world()
    reserve(
        deps.db_engine,
        principal(w.profile_key),
        embed_job(w.profile_key),
        policy=BYOK_POLICY,
        limits=OPEN,
    )
    superuser(sa.delete(ai_client_occupancy))
    a, b = keepers()
    lease = a.hold("occupancy")
    assert lease is not None
    expire("occupancy")
    assert b.hold("occupancy") is not None
    assert repair_occupancy(deps.db_engine, fence=lease.fence()) == {}
    assert occupied() == 0
    assert repair_occupancy(deps.db_engine) == {MEDIA_SERVICE.client_id: 1}
    assert occupied() == 1
    assert repair_occupancy(deps.db_engine) == {}  # nothing drifted


# --- remote artifacts under per-item claims --------------------------------------------


def test_a_stale_claim_commits_nothing_and_a_404_never_closes_the_row() -> None:
    stub = MistralStub(delete_mode="404")
    w = mistral_world()

    async def go() -> None:
        async with mistral(stub) as factory:
            await dispatch(factory, w, BLOB)
            (row,) = artifacts()
            assert row["status"] == "pending_delete"
            work = scheduler(factory)
            a, b = keepers()
            stale = a.hold("remote_artifacts")
            assert stale is not None
            due()
            assert await work.delete_pending(claim=stale) == []
            (row,) = artifacts()
            assert row["claim_epoch"] == stale.epoch and row["delete_attempts"] == 1
            deletes = len(stub.requests("DELETE"))
            expire("remote_artifacts")  # the leader is paused past its lease
            fresh = b.hold("remote_artifacts")
            assert fresh is not None
            due()
            # The paused leader resumes: its claim CAS matches nothing, no call.
            assert await work.delete_pending(claim=stale) == []
            assert len(stub.requests("DELETE")) == deletes
            # The successor waits out the old per-item claim.
            assert await work.delete_pending(claim=fresh) == []
            assert artifacts()[0]["delete_attempts"] == 1
            superuser(
                sa.update(_A).values(
                    claim_until=sa.func.now() - timedelta(seconds=1),
                    next_attempt_at=None,
                )
            )
            assert await work.resolve_unknown(claim=fresh) == []
            assert await work.revisit_parked(claim=fresh) == []
            assert await work.delete_pending(claim=fresh) == []
            (row,) = artifacts()
            assert row["status"] == "pending_delete" and row["delete_attempts"] == 2
            assert row["claim_epoch"] == fresh.epoch
            stub.delete_mode = "proof"
            due()
            assert len(await work.delete_pending(claim=fresh)) == 1
            assert artifacts() == []

    run(go())


def test_a_parked_row_another_leader_claims_is_left_alone() -> None:
    stub = MistralStub(delete_mode="404")
    w = mistral_world()

    async def go() -> None:
        async with mistral(stub) as factory:
            await dispatch(factory, w, BLOB)
            (row,) = artifacts()
            artifact_module._park(
                deps.db_engine,
                row["id"],
                artifact_module._S.PENDING_DELETE,
                "attempts_exhausted",
            )
            due()
            work = scheduler(factory)
            a, b = keepers()
            first = a.hold("remote_artifacts")
            assert first is not None
            assert await work.revisit_parked(claim=first) == []
            assert artifacts()[0]["claim_epoch"] == first.epoch
            expire("remote_artifacts")
            second = b.hold("remote_artifacts")
            assert second is not None
            due()
            deletes = len(stub.requests("DELETE"))
            assert await work.revisit_parked(claim=second) == []
            assert len(stub.requests("DELETE")) == deletes
            assert artifacts()[0]["claim_epoch"] == first.epoch

    run(go())


def test_a_deleted_credential_and_a_disabled_provider_still_have_files_cleaned() -> (
    None
):
    stub = MistralStub(delete_mode="404")
    w = mistral_world()

    async def go() -> None:
        async with mistral(stub) as factory:
            await dispatch(factory, w, BLOB)
            with deps.db_engine.begin() as c:
                deps.credential_store.delete(c, w["credential_id"])
                c.execute(
                    sa.update(ai_provider)
                    .where(ai_provider.c.id == w["provider_id"])
                    .values(enabled=False)
                )
            stub.delete_mode = "proof"
            due()
            lease = keepers()[0].hold("remote_artifacts")
            assert len(await scheduler(factory).delete_pending(claim=lease)) == 1

    run(go())
    assert artifacts() == []


# --- material destruction (D-43) --------------------------------------------------------


def versions(credential_id: uuid.UUID) -> dict[int, Any]:
    with deps.db_engine.connect() as c:
        rows = c.execute(
            sa.text(
                "SELECT version, material_destroyed_at, ciphertext "
                "FROM ai_credential_version WHERE credential_id = :id"
            ),
            {"id": credential_id},
        ).mappings()
        return {row["version"]: row for row in rows}


def test_a_retired_version_is_destroyed_only_after_its_last_artifact_row() -> None:
    stub = MistralStub(delete_mode="404")
    w = mistral_world()

    async def go() -> None:
        async with mistral(stub) as factory:
            await dispatch(factory, w, BLOB)

    run(go())
    cid = w["credential_id"]
    rotate(cid, "sk-new")  # v1 retired, still referenced
    assert destroy_retired(deps.db_engine) == []
    (row,) = artifacts()
    artifact_module._park(
        deps.db_engine,
        row["id"],
        artifact_module._S.PENDING_DELETE,
        "attempts_exhausted",
    )
    assert destroy_retired(deps.db_engine) == []  # never while parked
    from ai_gateway.controllers.audit import Actor

    assert accept_residual(deps.db_engine, row["id"], "console", Actor("operator"))
    a, b = keepers()
    stale = a.hold("credentials")
    assert stale is not None
    expire("credentials")
    assert b.hold("credentials") is not None
    assert destroy_retired(deps.db_engine, fence=stale.fence()) == []
    assert destroy_retired(deps.db_engine) == [(str(cid), 1)]
    held = versions(cid)
    assert (
        held[1]["material_destroyed_at"] is not None and held[1]["ciphertext"] is None
    )
    assert held[2]["material_destroyed_at"] is None  # the live pointer stays
    with deps.db_engine.connect() as c:
        audit = (
            c.execute(
                sa.select(ai_credential_audit).where(
                    ai_credential_audit.c.action == "credential.material_destroyed"
                )
            )
            .mappings()
            .one()
        )
    assert audit["metadata"] == {"version": 1} and audit["actor_kind"] == "system"
    with deps.db_engine.begin() as c:
        deps.credential_store.delete(c, cid)
    assert destroy_retired(deps.db_engine) == [(str(cid), 2)]
    assert destroy_retired(deps.db_engine) == []


# --- the run-mode's settings and entrypoint -------------------------------------------


def scheduler_settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.setenv("AI_RUN_MODE", "scheduler")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_the_scheduler_neither_needs_nor_reads_the_fingerprint_key_or_seed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = str(tmp_path / "absent")
    settings = scheduler_settings(
        monkeypatch,
        AI_CREDENTIAL_FINGERPRINT_KEY_FILE=missing,
        AI_EXECUTION_RECEIPT_KEY_FILE=missing,
        AI_EXECUTION_RECEIPT_KID="kid-of-another-seed",
        AI_CAPABILITIES_ENABLED="ocr",
        AI_OCR_SPOOL_DIR=str(tmp_path),
    )
    assert settings.is_scheduler and settings.fingerprint_key is None
    assert settings.receipt_seed is None
    store = build_credential_store(settings, deps.db_engine)
    w = world(provider_type=ProviderType.OPENAI_COMPATIBLE, keyed=True)
    with deps.db_engine.connect() as c:
        store.check_coverage(c)  # KEK coverage only: no fingerprint generation
    with pytest.raises(RuntimeError, match="no fingerprint key"):
        _ = store.fingerprint_version
    assert w.credential_id is not None
    monkeypatch.delenv("AI_CREDENTIAL_FINGERPRINT_KEY_FILE")
    assert scheduler_settings(monkeypatch).fingerprint_key is None


def test_the_web_mode_still_requires_both(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AI_CREDENTIAL_FINGERPRINT_KEY_FILE")
    with pytest.raises(ValueError, match="AI_CREDENTIAL_FINGERPRINT_KEY_FILE"):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_the_healthcheck_flag_reads_only_the_heartbeat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    beat = tmp_path / "beat"
    monkeypatch.setattr(entrypoint, "HEARTBEAT_FILE", beat)
    assert entrypoint.main(["--healthcheck"]) == 1
    touch(beat)
    assert entrypoint.main(["--healthcheck"]) == 0


def test_failed_start_up_checks_refuse_to_run(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_gateway import prestart

    monkeypatch.setenv("AI_RUN_MODE", "web")  # restored after the test
    monkeypatch.setattr(prestart, "main", lambda: 1)
    assert entrypoint.main([]) == 1
    assert os.environ["AI_RUN_MODE"] == "scheduler"


def test_the_shipped_entrypoint_settles_with_no_api_traffic(tmp_path: Path) -> None:
    """
    ``python -m ai_gateway.scheduler`` as its own process, no web service.

    Its fingerprint-key path names a file that does not exist: the scheduler
    never reads it. An abandoned reservation is settled, the heartbeat
    answers the probe, SIGTERM stops it and hands its leases over.
    """
    execution_id = pending()
    env = dict(os.environ)
    env.update(
        AI_RUN_MODE="scheduler",
        AI_CREDENTIAL_FINGERPRINT_KEY_FILE=str(tmp_path / "absent"),
        TMPDIR=str(tmp_path),
        PYTHONPATH=str(Path(__file__).resolve().parent.parent),
    )
    probe = [sys.executable, "-m", "ai_gateway.scheduler", "--healthcheck"]
    assert subprocess.run(probe, env=env, check=False).returncode == 1  # nosec B603
    launcher = (
        "import auth_sdk_m8.utils.paths as p; p.find_dotenv = lambda *a, **k: ''; "
        "import runpy; runpy.run_module('ai_gateway.scheduler', run_name='__main__')"
    )
    log = tmp_path / "scheduler.log"
    with log.open("w") as stderr:
        process = subprocess.Popen(  # nosec B603
            [sys.executable, "-c", launcher], env=env, stderr=stderr
        )
    try:
        deadline = time.monotonic() + 90
        while execution(execution_id)["status"] != "abandoned":
            assert process.poll() is None, log.read_text()
            assert time.monotonic() < deadline, log.read_text()
            time.sleep(0.5)
        # The heartbeat is written once the first pass over every job ends.
        while subprocess.run(probe, env=env, check=False).returncode != 0:  # nosec B603
            assert process.poll() is None, log.read_text()
            assert time.monotonic() < deadline, log.read_text()
            time.sleep(0.5)
    finally:
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=30) == 0
    assert occupied() == 0
    assert keepers()[0].hold("settlement") is not None  # released on SIGTERM


def test_retention_drains_batch_by_batch_up_to_its_cap() -> None:
    from ai_gateway.scheduler import jobs

    calls: list[int] = []

    def full(*_a: Any, **_k: Any) -> int:
        calls.append(1)
        return settlement.SWEEP_BATCH

    fence = sa.true()
    assert jobs._drain(full, job_context(), fence) == (
        jobs.RETENTION_BATCHES * settlement.SWEEP_BATCH
    )
    assert len(calls) == jobs.RETENTION_BATCHES


def test_the_entrypoint_serves_until_sigterm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def stop_myself(_lease: Lease) -> dict[str, object]:
        os.kill(os.getpid(), signal.SIGTERM)
        return {}

    work = Scheduler(
        deps.db_engine,
        keepers()[0],
        [Job("contexts", 15, stop_myself)],
        heartbeat=tmp_path / "h",
    )
    run(entrypoint._serve(work))  # returns once the handler set the event
    assert (tmp_path / "h").exists()

    from ai_gateway import prestart

    served: list[object] = []

    async def fake_serve(scheduler: object) -> None:
        served.append(scheduler)

    monkeypatch.setenv("AI_RUN_MODE", "web")
    monkeypatch.setattr(prestart, "main", lambda: 0)
    monkeypatch.setattr(entrypoint, "_serve", fake_serve)
    monkeypatch.setattr(entrypoint, "build_scheduler", lambda: work)
    assert entrypoint.main([]) == 0 and served == [work]


def test_the_module_entrypoint_imports_main() -> None:
    import runpy

    namespace = runpy.run_module("ai_gateway.scheduler.__main__")
    assert namespace["main"] is entrypoint.main


def test_capability_names_in_the_schedule_are_lease_names() -> None:
    assert all(name.isidentifier() for name in SCHEDULE)
    assert Capability.OCR.value not in SCHEDULE

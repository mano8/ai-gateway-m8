"""
The sweepers (T32): context rows, spool settlements, D-45 cleanup and recovery.

Rows are produced by the shipped spool phase and the execution core, then
aged on the database clock; every sweep is a CAS by stored status, so a
second sweep and a racing handler change nothing more.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass, OcrOptions

from ai_gateway.controllers.audit import Actor
from ai_gateway.core import deps
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.job_context import JOB_CONTEXTS
from ai_gateway.db_models.accounting import (
    ai_client_occupancy,
    ai_execution,
    ai_job_context_use,
    ai_spool_capacity,
)
from ai_gateway.db_models.audit import ai_admin_audit
from ai_gateway.execution import ocr, settlement, spool
from ai_gateway.execution.__main__ import main
from ai_gateway.execution.spool import Cleaned, Receiver, SpoolLayout
from ai_gateway.execution.sweepers import (
    clean_spools,
    collect_orphans,
    spool_repair,
    sweep_contexts,
    sweep_spools,
)
from conftest import MEDIA_SERVICE
from execution_world import age, principal, run
from job_contexts import mint
from ocr_world import mistral_world

pytestmark = pytest.mark.usefixtures("clean_db")

DOCUMENT = b"0123456789"


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SpoolLayout:
    root = tmp_path / "spool"
    root.mkdir()
    monkeypatch.setattr(settings, "AI_OCR_SPOOL_DIR", root)
    with deps.db_engine.begin() as c:
        c.execute(sa.update(ai_spool_capacity).values(reserved_bytes=0))
    return SpoolLayout(root)


def capacity() -> int:
    with deps.db_engine.connect() as c:
        return int(
            c.execute(sa.select(ai_spool_capacity.c.reserved_bytes)).scalar_one()
        )


def occupied() -> int:
    with deps.db_engine.connect() as c:
        return int(
            c.execute(
                sa.select(
                    sa.func.coalesce(sa.func.sum(ai_client_occupancy.c.occupied), 0)
                )
            ).scalar_one()
        )


def row(execution_id: uuid.UUID) -> Any:
    with deps.db_engine.connect() as c:
        return (
            c.execute(sa.select(ai_execution).where(ai_execution.c.id == execution_id))
            .mappings()
            .one()
        )


def files(layout: SpoolLayout) -> list[str]:
    return sorted(
        str(p.relative_to(layout.root)) for p in layout.root.rglob("*") if p.is_file()
    )


def receiving() -> uuid.UUID:
    w = mistral_world()
    context = principal(
        w["key"],
        Capability.OCR,
        data_class=DataClass.PUBLIC,
        phase="spool",
        input_sha256=hashlib.sha256(DOCUMENT).hexdigest(),
        input_bytes=len(DOCUMENT),
        ocr_options_hash=ocr.options_hash(OcrOptions()),
    )
    config = ocr.SpoolConfig.from_settings(settings)
    return ocr.open_spool(
        deps.db_engine,
        context,
        config=config,
        limits=deps.execution_service._limits(),
        unit=4096,
    )


def spooled(layout: SpoolLayout) -> uuid.UUID:
    execution_id = receiving()
    with deps.db_engine.begin() as c:
        c.execute(
            sa.update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(ocr_options={"pages": None})
        )
    writer = Receiver(
        layout,
        deps.db_engine,
        execution_id,
        input_bytes=len(DOCUMENT),
        lease_deadline=time.monotonic() + 60,
    )
    writer.open()
    writer.write(DOCUMENT)
    writer.commit(60)
    return execution_id


def counter(event: str) -> float:
    return JOB_CONTEXTS.labels(event=event)._value.get()


# --- context rows -------------------------------------------------------------------


def test_expired_context_rows_are_swept_on_the_database_clock() -> None:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    with deps.db_engine.begin() as c:
        for jti, exp in (
            ("old", now - timedelta(seconds=1)),
            ("live", now + timedelta(minutes=5)),
        ):
            c.execute(
                sa.insert(ai_job_context_use).values(
                    iss="media-service", jti=jti, uses=1, max_uses=1, exp=exp
                )
            )
    before = counter("swept")
    assert sweep_contexts(deps.db_engine) == 1
    assert counter("swept") == before + 1
    with deps.db_engine.connect() as c:
        assert list(c.execute(sa.select(ai_job_context_use.c.jti)).scalars()) == [
            "live"
        ]
    assert sweep_contexts(deps.db_engine) == 0


def test_n_parallel_redemptions_of_one_context_admit_exactly_one() -> None:
    from ai_gateway.core.job_context import redeem_job_context

    token = mint(MEDIA_SERVICE, capability="embedding", profile_key="p")
    payload = deps.job_contexts.verify(
        token, presenter=MEDIA_SERVICE.client_id, capability=Capability.EMBEDDING
    ).payload
    before = (counter("redeemed"), counter("replayed"))

    def attempt() -> str:
        try:
            with deps.db_engine.begin() as c:
                redeem_job_context(c, payload)
        except GatewayError as error:
            return error.code.value
        return "ok"

    async def parallel() -> list[str]:
        return await asyncio.gather(*(asyncio.to_thread(attempt) for _ in range(12)))

    outcomes = run(parallel())
    assert outcomes.count("ok") == 1
    assert outcomes.count(AiErrorCode.CONTEXT_REPLAYED.value) == 11
    assert (
        counter("redeemed") == before[0] + 1 and counter("replayed") == before[1] + 11
    )


# --- spool settlements --------------------------------------------------------------


def test_uploads_past_their_lease_and_spools_past_their_ttl_are_abandoned(
    layout: SpoolLayout,
) -> None:
    stalled = receiving()
    retained = spooled(layout)
    live = spooled(layout)
    slots = occupied()
    assert sweep_spools(deps.db_engine) == []  # nothing is due yet
    age(stalled, spool_lease_until=sa.func.now() - timedelta(seconds=1))
    age(retained, spool_expires_at=sa.func.now() - timedelta(seconds=1))
    assert sorted(sweep_spools(deps.db_engine)) == sorted([stalled, retained])
    assert sweep_spools(deps.db_engine) == []  # exactly once
    for execution_id in (stalled, retained):
        settled = row(execution_id)
        assert settled["status"] == "abandoned" and settled["error_class"] == "timeout"
        assert (
            settled["occupancy_released_at"] is not None and settled["cleanup_pending"]
        )
    assert occupied() == slots - 2 and row(live)["status"] == "spooled"
    assert clean_spools(layout, deps.db_engine) == {"released": 2}
    assert files(layout) == sorted([str(live), f".locks/{live}"])
    assert capacity() == row(live)["spool_bytes_reserved"]


def test_a_sweep_honours_its_fence(layout: SpoolLayout) -> None:
    execution_id = receiving()
    age(execution_id, spool_lease_until=sa.func.now() - timedelta(seconds=1))
    assert sweep_spools(deps.db_engine, fence=sa.false()) == []
    assert sweep_spools(deps.db_engine, fence=sa.true()) == [execution_id]


def test_a_held_lock_defers_and_a_crash_between_unlink_and_release_recovers(
    layout: SpoolLayout,
) -> None:
    execution_id = spooled(layout)
    reserved = row(execution_id)["spool_bytes_reserved"]
    ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
    holder = spool.open_lock(layout.lock(execution_id), fcntl.LOCK_SH)
    try:
        assert clean_spools(layout, deps.db_engine) == {"busy": 1}
        assert capacity() == reserved
    finally:
        assert holder is not None
        os.close(holder)
    # The crash: the data file is gone, the release not yet committed.
    layout.data(execution_id).unlink()
    assert clean_spools(layout, deps.db_engine) == {"released": 1}
    assert capacity() == 0 and files(layout) == []
    assert clean_spools(layout, deps.db_engine) == {}


def test_a_crash_between_release_and_lock_unlink_leaves_only_the_lock_to_collect(
    layout: SpoolLayout,
) -> None:
    execution_id = spooled(layout)
    ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
    layout.data(execution_id).unlink()
    assert spool._release(deps.db_engine, execution_id)  # committed, then the crash
    assert capacity() == 0 and files(layout) == [f".locks/{execution_id}"]
    assert clean_spools(layout, deps.db_engine) == {}
    assert collect_orphans(layout, deps.db_engine) == [execution_id]
    assert files(layout) == [] and capacity() == 0
    assert collect_orphans(layout, deps.db_engine) == []


def test_orphans_never_touch_a_live_spool_or_a_held_lock(layout: SpoolLayout) -> None:
    live = spooled(layout)
    absent = uuid.uuid4()
    (layout.root / str(absent)).write_bytes(b"left behind")
    (layout.locks / str(absent)).touch()
    (layout.root / "probe.lock").touch()  # not a spool name: ignored
    held = uuid.uuid4()
    (layout.locks / str(held)).touch()
    holder = spool.open_lock(layout.lock(held), fcntl.LOCK_SH)
    try:
        assert collect_orphans(layout, deps.db_engine) == [absent]
    finally:
        assert holder is not None
        os.close(holder)
    assert files(layout) == sorted(
        [str(live), f".locks/{live}", f".locks/{held}", "probe.lock"]
    )
    assert collect_orphans(layout, deps.db_engine) == [held]


def test_a_missing_lock_is_repaired_only_by_the_audited_command(
    layout: SpoolLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    execution_id = spooled(layout)
    layout.lock(execution_id).unlink()
    ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
    assert clean_spools(layout, deps.db_engine) == {"lock_missing": 1}
    assert capacity() > 0
    args = [
        "spool",
        "repair",
        "--id",
        str(execution_id),
        "--evidence",
        "no holder (lsof)",
    ]
    assert main(args) == 0 and '"repaired": true' in capsys.readouterr().out
    assert capacity() == 0
    with deps.db_engine.connect() as c:
        (audit,) = c.execute(
            sa.select(ai_admin_audit).where(ai_admin_audit.c.action == "spool.repair")
        ).mappings()
    assert audit["metadata"]["evidence"] == "no holder (lsof)"
    # The data file of the repaired row is now an orphan.
    assert collect_orphans(layout, deps.db_engine) == [execution_id]
    assert files(layout) == []
    assert main(args) == 1
    assert not spool_repair(deps.db_engine, uuid.uuid4(), Actor("operator"), "x")


def test_settlements_are_counted_by_outcome(layout: SpoolLayout) -> None:
    before = settlement.RESERVATIONS_SETTLED.labels(outcome="abandoned")._value.get()
    execution_id = receiving()
    age(execution_id, spool_lease_until=sa.func.now() - timedelta(seconds=1))
    sweep_spools(deps.db_engine)
    after = settlement.RESERVATIONS_SETTLED.labels(outcome="abandoned")._value.get()
    assert after == before + 1
    assert Cleaned.RELEASED.value == "released"


def test_a_spool_without_a_lock_directory_is_collected(layout: SpoolLayout) -> None:
    stray = uuid.uuid4()
    (layout.root / str(stray)).write_bytes(b"from before any lock")
    assert not layout.locks.exists()
    assert collect_orphans(layout, deps.db_engine) == [stray]
    assert files(layout) == []

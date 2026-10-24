"""
Retention, reconciliation, ``/v1/usage`` and ``audit-prune`` (T33, S-13, S-11).

Rows are inserted as the database superuser with triggers off (so a row can be
in any stored status the CHECK constraints allow, as a crash leaves it), then
removed — or not — by the runtime's retention. The positive predicate is held
to a matrix: every status, every owner of a row, one case each.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

import factories
import pg_harness as pg
from ai_gateway import audit_prune, main
from ai_gateway.controllers.audit import Actor
from ai_gateway.core import deps, metrics
from ai_gateway.core.config import settings
from ai_gateway.db_models.accounting import ai_execution, ai_usage
from ai_gateway.db_models.audit import ai_admin_audit, ai_credential_audit
from ai_gateway.execution import retention, settlement
from ai_gateway.execution.__main__ import main as execution_cli
from conftest import bearer

pytestmark = pytest.mark.usefixtures("clean_db")

DAYS = 90
OLD = datetime.now(UTC) - timedelta(days=DAYS + 30)
LONG_AGO = (datetime.now(UTC) - timedelta(days=DAYS + 40)).date()
PREFIX = f"{settings.API_PREFIX}/v1"
TENANT_A, TENANT_B = uuid.uuid4(), uuid.uuid4()
SU = bearer("superadmin")
ADMIN_A = bearer("admin", tenant_id=str(TENANT_A))
ADMIN_NO_TENANT = bearer("admin")
READER = bearer("reader", tenant_id=str(TENANT_A))


@pytest.fixture
def admin() -> Iterator[sa.Connection]:
    engine = pg.admin_engine(pg.DB_NAME)
    with engine.connect() as connection:
        connection.execute(sa.text("SET session_replication_role = replica"))
        yield connection
    engine.dispose()


@pytest.fixture
def world(admin: sa.Connection) -> dict[str, uuid.UUID]:
    return factories.resolved_world(admin)


def terminal(status: str, **values: Any) -> dict[str, Any]:
    """The columns a row settled in ``status`` carries, aged past retention."""
    row: dict[str, Any] = {
        "status": status,
        "occupancy_released_at": OLD,
        "settled_at": OLD,
        "updated_at": OLD,
        "created_at": OLD,
        "reservation_day": LONG_AGO,
    }
    if status in ("ok", "failed", "charged_uncertain", "dispatching"):
        row |= {"dispatched_at": OLD, "dispatch_deadline_at": OLD}
    return row | values


def insert(
    admin: sa.Connection, world: dict[str, uuid.UUID], **values: Any
) -> uuid.UUID:
    return factories.execution(admin, world, **values)


def remaining(admin: sa.Connection) -> set[uuid.UUID]:
    return set(admin.execute(sa.select(ai_execution.c.id)).scalars())


def collect(**kwargs: Any) -> int:
    return retention.collect_executions(deps.db_engine, DAYS, **kwargs)


def test_only_a_row_nothing_else_needs_is_collected(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    gone = {
        status: insert(admin, world, **terminal(status))
        for status in ("ok", "failed", "released", "abandoned")
    }
    reconciled = insert(
        admin, world, **terminal("charged_uncertain", reconciled_at=OLD)
    )
    # An OCR row abandoned before any reservation, its lock and capacity gone.
    ocr_abandoned = insert(
        admin,
        world,
        ocr=True,
        **terminal(
            "abandoned",
            reservation_day=None,
            reserved_units=None,
            spool_bytes_reserved=None,
        ),
    )
    kept = {
        "unreconciled charged_uncertain": insert(
            admin, world, **terminal("charged_uncertain")
        ),
        "pending": insert(admin, world, updated_at=OLD, created_at=OLD),
        "dispatching": insert(
            admin,
            world,
            **terminal(
                "dispatching",
                occupancy_released_at=None,
                settled_at=None,
            ),
        ),
        "receiving": insert(admin, world, ocr=True, updated_at=OLD),
        "cleanup pending": insert(
            admin,
            world,
            ocr=True,
            **terminal(
                "abandoned",
                reservation_day=None,
                reserved_units=None,
                cleanup_pending=True,
                spool_bytes_reserved=4096,
            ),
        ),
        "spool reservation held": insert(
            admin,
            world,
            ocr=True,
            **terminal(
                "abandoned",
                reservation_day=None,
                reserved_units=None,
                spool_bytes_reserved=4096,
            ),
        ),
        "reserved today": insert(
            admin,
            world,
            **terminal("ok", reservation_day=datetime.now(UTC).date()),
        ),
        "inside the window": insert(
            admin, world, **terminal("ok", updated_at=datetime.now(UTC))
        ),
    }
    artifact_owner = insert(admin, world, **terminal("ok"))
    factories.artifact(admin, world, artifact_owner, status="uploading")
    admin.commit()

    expected = {*gone.values(), reconciled, ocr_abandoned}
    assert collect() == len(expected)
    survivors = remaining(admin)
    assert survivors == {*kept.values(), artifact_owner}
    assert collect() == 0  # exactly once


def test_a_row_is_collected_once_its_artifact_rows_are_gone(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    owner = insert(admin, world, **terminal("ok"))
    artifact = factories.artifact(admin, world, owner, status="uploading")
    admin.commit()
    assert collect() == 0
    admin.execute(
        sa.text("DELETE FROM ai_provider_remote_artifact WHERE id = :id"),
        {"id": artifact},
    )
    admin.commit()
    assert collect() == 1


def test_a_fence_that_is_false_collects_nothing(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    insert(admin, world, **terminal("ok"))
    admin.commit()
    assert collect(fence=sa.false()) == 0
    assert collect(fence=sa.true(), limit=1) == 1


def test_a_stale_dispatching_row_is_settled_not_deleted(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    stale = insert(
        admin,
        world,
        **terminal("dispatching", occupancy_released_at=None, settled_at=None),
    )
    admin.commit()
    results: list[int] = []
    racing = threading.Thread(target=lambda: results.append(collect()))
    racing.start()
    moved = settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0)
    racing.join()
    assert moved == [stale] and results == [0]
    row = admin.execute(
        sa.select(ai_execution.c.status, ai_execution.c.reconciled_at).where(
            ai_execution.c.id == stale
        )
    ).one()
    # Settled uncertain, and kept: only a reconciled row is ever collected.
    assert tuple(row) == ("charged_uncertain", None)
    assert collect() == 0


def test_a_charged_uncertain_row_is_collected_only_after_reconciliation(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    row_id = insert(admin, world, **terminal("charged_uncertain"))
    admin.commit()
    assert collect() == 0
    actor = Actor("operator", "ops")
    assert retention.reconcile(deps.db_engine, row_id, actor, "provider invoice 42")
    assert not retention.reconcile(deps.db_engine, row_id, actor, "again")
    audit = (
        admin.execute(
            sa.select(ai_admin_audit).where(
                ai_admin_audit.c.action == "execution.reconcile"
            )
        )
        .mappings()
        .one()
    )
    assert audit["target_id"] == str(row_id) and audit["actor_kind"] == "operator"
    assert audit["metadata"]["evidence"] == "provider invoice 42"
    stamped = admin.execute(
        sa.select(ai_execution.c.reconciled_at, ai_execution.c.status).where(
            ai_execution.c.id == row_id
        )
    ).one()
    assert stamped[0] is not None and stamped[1] == "charged_uncertain"
    # Reconciling stamped updated_at: age it again, as a real window would.
    admin.execute(
        sa.update(ai_execution)
        .where(ai_execution.c.id == row_id)
        .values(updated_at=OLD)
    )
    admin.commit()
    assert collect() == 1


def test_an_ok_row_cannot_be_reconciled(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    row_id = insert(admin, world, **terminal("ok"))
    admin.commit()
    assert not retention.reconcile(deps.db_engine, row_id, Actor("operator"), "x")


def test_the_reconcile_command(
    admin: sa.Connection,
    world: dict[str, uuid.UUID],
    capsys: pytest.CaptureFixture[str],
) -> None:
    row_id = insert(admin, world, **terminal("charged_uncertain"))
    admin.commit()
    args = ["execution", "reconcile", "--id", str(row_id), "--evidence", "e"]
    assert execution_cli(args) == 0
    assert json.loads(capsys.readouterr().out) == {
        "reconciled": True,
        "id": str(row_id),
    }
    assert execution_cli(args) == 1


def test_a_usage_day_is_removed_only_when_no_execution_carries_it(
    admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    carried, free = LONG_AGO, LONG_AGO - timedelta(days=1)
    today = datetime.now(UTC).date()
    for day in (carried, free, today):
        admin.execute(
            sa.insert(ai_usage).values(
                scope_type="client", scope_id="media-service", day=day, used=3
            )
        )
    insert(admin, world, **terminal("ok", reservation_day=carried))
    admin.commit()
    assert retention.collect_usage(deps.db_engine, DAYS, fence=sa.false()) == 0
    assert retention.collect_usage(deps.db_engine, DAYS) == 1
    days = set(admin.execute(sa.select(ai_usage.c.day)).scalars())
    assert days == {carried, today}
    # Once the execution is collected, its day goes too.
    assert collect() == 1
    assert retention.collect_usage(deps.db_engine, DAYS) == 1


def test_the_audit_table_sizes_are_exported() -> None:
    sizes = retention.observe_audit_table_bytes(deps.db_engine)
    assert set(sizes) == set(retention.AUDIT_TABLES) and all(sizes.values())
    for table, size in sizes.items():
        sampled = metrics.AUDIT_TABLE_BYTES.labels(table=table)._value.get()
        assert sampled == size


# --- GET /v1/usage ------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


def seed_usage(admin: sa.Connection, world: dict[str, uuid.UUID]) -> None:
    today = datetime.now(UTC).date()
    for scope_type, scope_id, used in (
        ("tenant", str(TENANT_A), 7),
        ("tenant", str(TENANT_B), 11),
        ("client", "media-service", 18),
    ):
        admin.execute(
            sa.insert(ai_usage).values(
                scope_type=scope_type,
                scope_id=scope_id,
                day=today,
                used=used,
                reserved=1,
            )
        )
    for tenant, tokens in ((TENANT_A, 5), (TENANT_B, 9)):
        insert(
            admin,
            world,
            **terminal(
                "ok",
                reservation_day=today,
                updated_at=datetime.now(UTC),
                tenant_scope_id=str(tenant),
                provider_usage={"input_tokens": tokens, "output_tokens": 2},
            ),
        )
    admin.commit()


def test_a_tenant_admin_sees_only_its_own_aggregates(
    client: TestClient, admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    seed_usage(admin, world)
    body = client.get(f"{PREFIX}/usage", headers=ADMIN_A).json()
    assert body["tenant_id"] == str(TENANT_A)
    (day,) = body["days"]
    assert day["admission_units"] == {"reserved": 1, "used": 7}
    assert day["provider_usage"] == {
        "input_tokens": 5,
        "output_tokens": 2,
        "pages_processed": 0,
    }
    own = client.get(f"{PREFIX}/usage?tenant_id={TENANT_A}", headers=ADMIN_A)
    assert own.json() == body
    assert str(TENANT_B) not in json.dumps(body)


def test_another_tenant_and_a_missing_tenant_see_nothing(
    client: TestClient, admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    seed_usage(admin, world)
    other = client.get(f"{PREFIX}/usage?tenant_id={TENANT_B}", headers=ADMIN_A)
    assert other.status_code == 404
    empty = client.get(f"{PREFIX}/usage", headers=ADMIN_NO_TENANT)
    assert empty.status_code == 200 and empty.json() == {"tenant_id": None, "days": []}


def test_the_superuser_sees_the_platform_or_one_tenant(
    client: TestClient, admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    seed_usage(admin, world)
    platform = client.get(f"{PREFIX}/usage", headers=SU).json()
    assert platform["tenant_id"] is None
    (day,) = platform["days"]
    assert day["admission_units"]["used"] == 18
    assert day["provider_usage"]["input_tokens"] == 14
    one = client.get(f"{PREFIX}/usage?tenant_id={TENANT_B}&days=3", headers=SU).json()
    assert one["days"][0]["admission_units"]["used"] == 11


def test_a_provider_day_without_admission_rows_is_still_reported(
    client: TestClient, admin: sa.Connection, world: dict[str, uuid.UUID]
) -> None:
    insert(
        admin,
        world,
        **terminal(
            "ok",
            reservation_day=datetime.now(UTC).date(),
            tenant_scope_id=str(TENANT_A),
            provider_usage={"pages_processed": 4},
        ),
    )
    admin.commit()
    (day,) = client.get(f"{PREFIX}/usage", headers=ADMIN_A).json()["days"]
    assert day["admission_units"] == {"reserved": 0, "used": 0}
    assert day["provider_usage"]["pages_processed"] == 4


def test_usage_refuses_readers_and_bad_windows(client: TestClient) -> None:
    assert client.get(f"{PREFIX}/usage", headers=READER).status_code == 403
    assert client.get(f"{PREFIX}/usage?days=0", headers=SU).status_code == 422
    assert client.get(f"{PREFIX}/usage?days=91", headers=SU).status_code == 422


# --- audit-prune --------------------------------------------------------------------


def seed_audit(admin: sa.Connection) -> None:
    for when in (OLD, OLD + timedelta(days=1), datetime.now(UTC)):
        admin.execute(
            sa.insert(ai_admin_audit).values(
                occurred_at=when, action="x", actor_kind="system", target_type="t"
            )
        )
        admin.execute(
            sa.insert(ai_credential_audit).values(
                occurred_at=when, action="x", actor_kind="system"
            )
        )
    admin.commit()


def test_audit_prune_as_the_owner_removes_exactly_the_rows_before_the_date(
    admin: sa.Connection,
) -> None:
    seed_audit(admin)
    cutoff = (datetime.now(UTC) - timedelta(days=30)).date()
    owner = pg.owner_engine()
    try:
        counts = audit_prune.prune(owner, cutoff, "ops")
    finally:
        owner.dispose()
    assert counts == {"ai_credential_audit": 2, "ai_admin_audit": 2}
    assert (
        admin.execute(
            sa.select(sa.func.count()).select_from(ai_credential_audit)
        ).scalar_one()
        == 1
    )
    rows = (
        admin.execute(sa.select(ai_admin_audit).order_by(ai_admin_audit.c.id))
        .mappings()
        .all()
    )
    summary = [r for r in rows if r["action"] == "audit.prune"]
    assert len(rows) == 2 and len(summary) == 1
    assert summary[0]["actor_id"] == "ops" and summary[0]["actor_kind"] == "operator"
    assert summary[0]["metadata"]["counts"] == counts
    assert summary[0]["metadata"]["before"] == cutoff.isoformat()
    assert set(summary[0]["metadata"]["range"]) == {
        "ai_credential_audit",
        "ai_admin_audit",
    }


def test_audit_prune_as_the_runtime_fails_on_permissions_and_changes_nothing(
    admin: sa.Connection, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_audit(admin)
    cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()[:10]
    argv = ["--before", cutoff, "--operator", "ops"]
    assert audit_prune.main(argv) == 1  # deps.db_engine is ai_runtime
    count = admin.execute(
        sa.select(sa.func.count()).select_from(ai_admin_audit)
    ).scalar_one()
    assert count == 3  # the failed transaction wrote no summary row either


def test_audit_prune_command_succeeds_as_the_owner_and_refuses_the_future(
    admin: sa.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed_audit(admin)
    owner = pg.owner_engine()
    monkeypatch.setattr(deps, "db_engine", owner)
    try:
        cutoff = (datetime.now(UTC) - timedelta(days=30)).date().isoformat()
        assert audit_prune.main(["--before", cutoff, "--operator", "ops"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["pruned"] == {"ai_credential_audit": 2, "ai_admin_audit": 2}
        future = (date.today() + timedelta(days=2)).isoformat()
        assert audit_prune.main(["--before", future, "--operator", "ops"]) == 1
    finally:
        owner.dispose()

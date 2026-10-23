"""
Remote provider artifacts (D-43, T29): every scheduler transition.

Rows are produced by real ``:dispatch`` runs against the stub Mistral
account (the handler's transitions), then driven by the shipped
:class:`ArtifactScheduler` with the clocks moved forward. Cleanup uses the
recorded credential version only; a ``404``, a negative listing or a passed
``provider_expires_at`` never closes a row.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas.management import ProviderType, ScopeType

from ai_gateway.controllers.audit import Actor
from ai_gateway.core import deps
from ai_gateway.core.errors import GatewayError
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.audit import ai_admin_audit
from ai_gateway.execution import artifacts as module
from ai_gateway.execution.__main__ import main
from ai_gateway.execution.artifacts import (
    REMOTE_ARTIFACTS,
    ArtifactPolicy,
    ArtifactScheduler,
    accept_residual,
    backoff,
    file_name,
    file_prefix,
)
from ai_gateway.providers.base import ArtifactProofs
from ai_gateway.providers.mistral import MistralAdapter
from execution_world import make_credential, make_provider, rotate, run
from mistral_stub import MistralStub
from ocr_world import (
    ADAPTER,
    BLOB,
    DEPLOYMENT_ID,
    POLICY,
    Document,
    age_artifacts,
    artifacts,
    dispatch,
    due,
    mistral,
    mistral_world,
    scheduler,
)

pytestmark = pytest.mark.usefixtures("clean_db")

_A = ai_provider_remote_artifact


def scenario(stub: MistralStub, body: Any, **world: Any) -> Any:
    w = mistral_world(**world)

    async def go() -> Any:
        async with mistral(stub) as factory:
            return await body(factory, w)

    return run(go())


def one() -> Any:
    (row,) = artifacts()
    return row


def destroy(credential_id: Any, version: int = 1) -> None:
    with deps.db_engine.begin() as c:
        deps.credential_store.destroy(c, credential_id, version)


def manual_gauge() -> float:
    return REMOTE_ARTIFACTS.labels(status="manual_cleanup_required")._value.get()


# --- deletion under the recorded version ------------------------------------------


def test_a_401_on_cleanup_is_retried_with_the_recorded_version_only() -> None:
    stub = MistralStub(revoked={"sk-old"}, elsewhere={"sk-new"})

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        rotate(w["credential_id"], "sk-new")
        work = scheduler(factory)
        first = await work.delete_pending()
        after_first = one()
        due()
        stub.revoked.clear()
        second = await work.delete_pending()
        return first, after_first, second

    first, after_first, second = scenario(stub, body)
    assert first == [] and after_first["delete_attempts"] == 1
    assert after_first["last_error_class"] == "provider_rejected"
    assert after_first["next_attempt_at"] is not None
    keys = {key for _, _, key in stub.requests("DELETE")}
    assert keys == {"sk-old"}  # never the current version
    assert len(second) == 1 and artifacts() == [] and stub.files == {}


def test_a_429_sets_the_floor_of_the_next_attempt() -> None:
    stub = MistralStub(delete_mode="429")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        return await scheduler(factory).delete_pending()

    assert scenario(stub, body) == []
    row = one()
    with deps.db_engine.connect() as c:
        wait = c.execute(sa.select(_A.c.next_attempt_at - sa.func.now())).scalar_one()
    # Retry-After: 900, capped at AI_PROVIDER_MAX_BACKOFF_SECONDS (300 here).
    assert wait > timedelta(seconds=250) and row["last_error_class"] == "rate_limited"


def test_a_404_or_an_unproven_delete_never_closes_and_parks_after_the_attempts() -> (
    None
):
    stub = MistralStub(delete_mode="404")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory)
        for mode in ("404", "false", "wrong-id"):
            stub.delete_mode = mode
            assert await work.delete_pending() == []
            due()
        await work.delete_pending()  # the attempts are exhausted
        work.refresh_gauge()
        return w

    w = scenario(stub, body)
    row = one()
    assert row["status"] == "manual_cleanup_required"
    assert row["status_reason"] == "attempts_exhausted"
    assert row["delete_attempts"] == 3 and manual_gauge() == 1
    rotate(w["credential_id"], "sk-new")
    with pytest.raises(sa.exc.DBAPIError, match="remote artifact references"):
        destroy(w["credential_id"])


def test_a_row_pending_too_long_is_parked() -> None:
    stub = MistralStub(delete_mode="500")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        age_artifacts(created_at=sa.func.now() - timedelta(hours=73))
        return await scheduler(factory).delete_pending()

    assert scenario(stub, body) == []
    assert one()["status_reason"] == "pending_hours_exceeded"


def test_rotation_and_deletion_during_pending_keep_the_old_version_alive() -> None:
    stub = MistralStub(drop_upload=True)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        rotate(w["credential_id"], "sk-new")
        with deps.db_engine.begin() as c:
            deps.credential_store.delete(c, w["credential_id"])
        with pytest.raises(sa.exc.DBAPIError, match="remote artifact references"):
            destroy(w["credential_id"])
        due()
        work = scheduler(factory)
        assert len(await work.resolve_unknown()) == 1
        assert len(await work.delete_pending()) == 1
        return w

    w = scenario(stub, body)
    assert {key for _, _, key in stub.log if key} == {"sk-old"}
    assert stub.files == {} and artifacts() == []
    destroy(w["credential_id"])  # nothing references it any more


# --- unknown ids: incident listings ----------------------------------------------------


def test_negative_listings_never_close_a_row_and_a_late_listing_recovers_it() -> None:
    stub = MistralStub(drop_upload=True, hide_listings=4)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory)
        counts = []
        for _ in range(2):
            due()
            assert await work.resolve_unknown() == []
            counts.append(one()["negative_listings"])
        due()
        assert len(await work.resolve_unknown()) == 1  # the third → parked
        parked = one()
        due()
        assert await work.revisit_parked() == []  # the fourth listing hides it
        due()
        assert len(await work.revisit_parked()) == 1
        recovered = one()
        assert len(await work.delete_pending()) == 1
        return counts, parked, recovered

    counts, parked, recovered = scenario(stub, body)
    assert counts == [1, 2]
    assert parked["status"] == "manual_cleanup_required"
    assert parked["status_reason"] == "absence_unproven"
    assert recovered["status"] == "pending_delete" and recovered["delete_attempts"] == 0
    assert stub.files == {} and artifacts() == []


def test_a_listing_inside_the_grace_counts_for_nothing() -> None:
    stub = MistralStub(drop_upload=True, hide_listings=1)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        return await scheduler(factory).resolve_unknown()

    assert scenario(stub, body) == []
    row = one()
    assert row["negative_listings"] == 0 and row["next_attempt_at"] is not None


def test_an_incomplete_or_failed_listing_counts_for_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ai_gateway.providers import mistral as adapter_module

    stub = MistralStub(drop_upload=True, hide_listings=10)
    for i in range(101):
        stub.add(f"tenant-{i}.pdf")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory)
        monkeypatch.setattr(adapter_module, "MAX_LISTING_PAGES", 1)
        due()
        assert await work.resolve_unknown() == []
        stub.list_status = 500
        due()
        assert await work.resolve_unknown() == []
        return one()

    row = scenario(stub, body)
    assert row["status"] == "uploading_unknown_id" and row["negative_listings"] == 0


def test_a_documented_absence_proof_closes_on_one_complete_negative_listing() -> None:
    class Proven(MistralAdapter):
        proofs = ArtifactProofs(True, True, "documented_strong", False, False)

    stub = MistralStub(drop_upload=True, hide_listings=1)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        due()
        proven = Proven(inline_threshold_bytes=64, file_expiry_seconds=3600)
        work = ArtifactScheduler(
            deps.db_engine,
            deps.credential_store,
            factory,
            {ProviderType.MISTRAL: proven},
            POLICY,
        )
        return await work.resolve_unknown()

    assert len(scenario(stub, body)) == 1 and artifacts() == []


def test_without_permission_to_list_a_row_is_parked_after_the_grace() -> None:
    stub = MistralStub(drop_upload=True)
    closed = ArtifactPolicy(**{**POLICY.__dict__, "platform_incident_listing": False})

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory, closed)
        assert await work.resolve_unknown() == []  # inside the grace
        due()
        assert len(await work.resolve_unknown()) == 1
        due()
        assert await work.revisit_parked() == []  # no id, no listing
        return one()

    row = scenario(stub, body)
    assert row["status_reason"] == "listing_not_permitted"
    assert stub.requests("GET", "/v1/files") == []


@pytest.mark.parametrize("consent", [False, True])
def test_a_tenant_key_is_listed_only_with_its_consent(consent: bool) -> None:
    stub = MistralStub(drop_upload=True)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        due()
        return await scheduler(factory).resolve_unknown()

    moved = scenario(stub, body, scope=ScopeType.TENANT, consent=consent)
    row = one()
    assert len(moved) == 1
    if consent:
        assert row["status"] == "pending_delete"
        assert len(stub.requests("GET", "/v1/files")) == 1
    else:
        assert row["status_reason"] == "listing_not_permitted"
        assert stub.requests("GET", "/v1/files") == []


# --- parked rows: expiry is not proof, accept-residual ------------------------------


def _parked(stub: MistralStub) -> Any:
    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory)
        for _ in range(4):  # three failed attempts, then parked
            due()
            await work.delete_pending()
        return w

    return body


def test_a_passed_expiry_is_never_proof_and_a_later_proof_closes_the_row() -> None:
    stub = MistralStub(delete_mode="404")
    inner = _parked(stub)

    async def body(factory: Any, w: Any) -> Any:
        await inner(factory, w)
        work = scheduler(factory)
        due()
        assert await work.revisit_parked() == []  # not yet expired: wait
        waiting = one()
        age_artifacts(provider_expires_at=sa.func.now() - timedelta(hours=1))
        assert await work.revisit_parked() == []  # expired, still a 404
        daily = one()
        stub.delete_mode = "proof"
        due()
        closed = await work.revisit_parked()
        return waiting, daily, closed

    waiting, daily, closed = scenario(stub, body)
    assert waiting["next_attempt_at"] >= waiting["provider_expires_at"] - timedelta(
        seconds=5
    )
    assert daily["status"] == "manual_cleanup_required"
    assert daily["next_attempt_at"] > daily["provider_expires_at"] + timedelta(hours=20)
    assert len(closed) == 1 and artifacts() == []


def test_accept_residual_closes_a_parked_row_with_an_audited_risk_row(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stub = MistralStub(delete_mode="404")
    scenario(stub, _parked(stub))
    row = one()
    assert (
        main(
            [
                "remote-artifact",
                "accept-residual",
                "--id",
                str(row["id"]),
                "--evidence",
                "ticket 42",
            ]
        )
        == 0
    )
    assert '"accepted": true' in capsys.readouterr().out
    assert artifacts() == []
    with deps.db_engine.connect() as c:
        (audit,) = c.execute(
            sa.select(ai_admin_audit).where(
                ai_admin_audit.c.action == "remote_artifact.accept_residual"
            )
        ).mappings()
    assert audit["actor_kind"] == "operator" and audit["target_id"] == str(row["id"])
    assert audit["metadata"]["residual_risk"] is True
    assert audit["metadata"]["remote_artifact_id"] == row["remote_artifact_id"]
    assert audit["metadata"]["evidence"] == "ticket 42"
    assert audit["metadata"]["provider_expires_at"] is not None
    # Nothing is parked any more.
    assert (
        main(
            [
                "remote-artifact",
                "accept-residual",
                "--id",
                str(row["id"]),
                "--evidence",
                "x",
            ]
        )
        == 1
    )


def test_accept_residual_refuses_a_row_that_is_not_parked() -> None:
    stub = MistralStub(delete_mode="500")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)

    scenario(stub, body)
    assert not accept_residual(deps.db_engine, one()["id"], "e", Actor("operator"))
    assert one()["status"] == "pending_delete"


# --- the handler's crash points ---------------------------------------------------------


def test_a_crash_right_after_the_intent_commit_ends_outside_uploading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = module.record_intent

    def crash(*args: Any, **kw: Any) -> bool:
        real(*args, **kw)
        raise RuntimeError("the process died after the commit")

    monkeypatch.setattr(module, "record_intent", crash)
    stub = MistralStub()

    async def body(factory: Any, w: Any) -> Any:
        outcome = await dispatch(factory, w, BLOB)
        assert isinstance(outcome, GatewayError)
        stranded = one()
        work = scheduler(factory)
        assert work.expire_uploads() == []  # inside the grace
        due()
        return stranded, work.expire_uploads()

    stranded, moved = scenario(stub, body)
    assert stranded["status"] == "uploading" and stub.uploads == []
    assert moved == [stranded["id"]] and one()["status"] == "uploading_unknown_id"


def test_a_crash_before_the_id_is_persisted_is_found_by_the_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def crash(self: Any, remote_id: str, expires_at: int | None) -> bool:
        raise RuntimeError("the process died before the id was recorded")

    monkeypatch.setattr(module.ExecutionArtifacts, "activate", crash)
    stub = MistralStub()

    async def body(factory: Any, w: Any) -> Any:
        with pytest.raises(RuntimeError):
            await dispatch(factory, w, BLOB)
        stranded, held = one(), len(stub.files)
        due()
        work = scheduler(factory)
        expired = work.expire_uploads()
        found = await work.resolve_unknown()
        closed = await work.delete_pending()
        return stranded, held, expired, found, closed

    stranded, held, expired, found, closed = scenario(stub, body)
    assert stranded["status"] == "uploading" and held == 1
    assert expired == found == closed == [stranded["id"]]
    assert stub.ocr_bodies == [] and artifacts() == []


def test_a_mid_body_crash_ends_unknown_and_never_names_a_file() -> None:
    stub = MistralStub()

    async def body(factory: Any, w: Any) -> Any:
        outcome = await dispatch(factory, w, Document(BLOB, fail_after=1024))
        return outcome

    outcome = scenario(stub, body)
    assert isinstance(outcome, GatewayError)
    assert one()["status"] == "uploading_unknown_id" and stub.files == {}


# --- active rows ----------------------------------------------------------------


def test_an_active_file_of_a_terminal_execution_is_retired() -> None:
    stub = MistralStub(delete_mode="500")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        from ocr_world import _superuser

        with _superuser() as c:
            c.execute(sa.update(_A).values(status="active"))
        return scheduler(factory).retire_active()

    assert len(scenario(stub, body)) == 1 and one()["status"] == "pending_delete"


# --- the platform sweep ---------------------------------------------------------


def test_the_sweep_deletes_only_this_deployments_old_untracked_files(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stub = MistralStub(delete_mode="500")
    prefix = file_prefix(DEPLOYMENT_ID)
    other = "m8ai-00000000-0000-4000-8000-000000000000-x"
    stub.add(other, age=7200)
    stub.add("tenant-invoice.pdf", age=7200)
    orphan = stub.add(f"{prefix}orphan", age=7200)
    stub.add(f"{prefix}young", age=0)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)  # tracked: pending_delete, never swept
        stub.delete_mode = "proof"
        caplog.set_level(logging.DEBUG)
        return await scheduler(factory).sweep()

    assert scenario(stub, body) == [orphan]
    assert stub.held() == sorted(
        [other, "tenant-invoice.pdf", f"{prefix}young", one()["gateway_file_name"]]
    )
    assert other not in caplog.text and "tenant-invoice" not in caplog.text
    deleted = {path for _, path, _ in stub.requests("DELETE")}
    assert deleted == {
        f"/v1/files/{orphan}",
        f"/v1/files/{one()['remote_artifact_id']}",
    }


def test_the_sweep_is_off_by_default_and_never_lists_a_tenants_account() -> None:
    off = ArtifactPolicy(**{**POLICY.__dict__, "platform_sweep_enabled": False})
    stub = MistralStub()

    async def body(factory: Any, w: Any) -> Any:
        make_credential(make_provider(provider_type=ProviderType.OLLAMA))
        assert await scheduler(factory, off).sweep() == []
        return await scheduler(factory).sweep()

    assert scenario(stub, body, scope=ScopeType.TENANT) == []
    assert stub.requests("GET", "/v1/files") == []


def test_a_failed_sweep_listing_deletes_nothing() -> None:
    stub = MistralStub(list_status=500)
    stub.add(f"{file_prefix(DEPLOYMENT_ID)}orphan", age=7200)

    async def body(factory: Any, w: Any) -> Any:
        return await scheduler(factory).sweep()

    assert scenario(stub, body) == [] and len(stub.files) == 1


# --- rows no adapter can reach -----------------------------------------------------


def test_rows_whose_provider_has_no_adapter_wait_or_park() -> None:
    stub = MistralStub(drop_upload=True)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        blind = ArtifactScheduler(
            deps.db_engine, deps.credential_store, factory, {}, POLICY
        )
        due()
        assert len(await blind.resolve_unknown()) == 1  # listing_not_permitted
        due()
        assert await blind.revisit_parked() == []
        return blind

    scenario(stub, body)
    assert one()["status_reason"] == "listing_not_permitted"


def test_a_deletion_with_no_adapter_or_no_material_is_retried() -> None:
    stub = MistralStub(delete_mode="500")

    class NoMaterial:
        def resolve_for_cleanup(self, *_args: Any) -> Any:
            from ai_sdk_m8.schemas import AiErrorCode

            raise GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        blind = ArtifactScheduler(
            deps.db_engine, deps.credential_store, factory, {}, POLICY
        )
        assert await blind.delete_pending() == []
        first = one()["last_error_class"]
        due()
        lost = ArtifactScheduler(
            deps.db_engine,
            NoMaterial(),
            factory,
            {ProviderType.MISTRAL: ADAPTER},
            POLICY,  # type: ignore[arg-type]
        )
        assert await lost.delete_pending() == []
        return first

    assert scenario(stub, body) == "capability_unsupported"
    assert one()["last_error_class"] == "credential_unavailable"


# --- small parts --------------------------------------------------------------------


def test_backoff_doubles_to_its_cap_and_honours_a_cooldown() -> None:
    assert [backoff(n).total_seconds() for n in (0, 1, 2, 3, 20)] == [
        30,
        30,
        60,
        120,
        3600,
    ]
    assert backoff(1, retry_after=600).total_seconds() == 600


def test_names_policy_and_the_shipped_scheduler() -> None:
    import uuid

    execution_id = uuid.uuid4()
    assert (
        file_name(DEPLOYMENT_ID, execution_id) == f"m8ai-{DEPLOYMENT_ID}-{execution_id}"
    )
    assert file_name(DEPLOYMENT_ID, execution_id).startswith(file_prefix(DEPLOYMENT_ID))
    shipped = ArtifactPolicy.from_settings(deps.settings)
    assert shipped.deployment_id == deps.settings.deployment_id
    assert shipped.platform_incident_listing and not shipped.platform_sweep_enabled
    assert (
        shipped.max_delete_attempts
        == deps.settings.AI_REMOTE_ARTIFACT_MAX_DELETE_ATTEMPTS
    )
    assert isinstance(deps.artifact_scheduler, ArtifactScheduler)
    assert deps.artifact_scheduler._adapters is deps.adapters


def test_the_gauge_counts_rows_by_status() -> None:
    stub = MistralStub(delete_mode="500")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        return scheduler(factory).refresh_gauge()

    assert scenario(stub, body) == {"pending_delete": 1}
    assert REMOTE_ARTIFACTS.labels(status="pending_delete")._value.get() == 1
    assert REMOTE_ARTIFACTS.labels(status="active")._value.get() == 0


# --- fences, races and failures on the edges ------------------------------------------


def test_every_scheduler_transition_honours_its_fence() -> None:
    stub = MistralStub(drop_upload=True)

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory)
        due()
        assert await work.resolve_unknown(fence=sa.false()) == []
        due()
        assert len(await work.resolve_unknown(fence=sa.true())) == 1
        assert work.retire_active(fence=sa.false()) == []
        assert work.expire_uploads(fence=sa.false()) == []
        assert len(await work.delete_pending(fence=sa.true())) == 1

    scenario(stub, body)
    assert artifacts() == []


def test_a_park_that_lost_its_race_moves_nothing() -> None:
    stub = MistralStub(delete_mode="500")

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)

    scenario(stub, body)
    row = one()
    assert not module._park(
        deps.db_engine, row["id"], module._S.ACTIVE, "attempts_exhausted"
    )
    assert one()["status"] == "pending_delete"


def test_a_parked_revisit_whose_delete_fails_waits_a_day() -> None:
    stub = MistralStub(delete_mode="404")
    inner = _parked(stub)

    async def body(factory: Any, w: Any) -> Any:
        await inner(factory, w)
        age_artifacts(provider_expires_at=sa.func.now() - timedelta(hours=1))
        stub.delete_mode = "500"
        return await scheduler(factory).revisit_parked()

    assert scenario(stub, body) == []
    assert one()["status"] == "manual_cleanup_required"


@pytest.mark.parametrize("failure", ["not-permitted", "listing-fails"])
def test_a_rediscovery_that_cannot_list_leaves_the_row_parked(failure: str) -> None:
    stub = MistralStub(drop_upload=True, hide_listings=3)
    closed = ArtifactPolicy(**{**POLICY.__dict__, "platform_incident_listing": False})

    async def body(factory: Any, w: Any) -> Any:
        await dispatch(factory, w, BLOB)
        work = scheduler(factory)
        for _ in range(3):
            due()
            await work.resolve_unknown()
        assert one()["status_reason"] == "absence_unproven"
        due()
        if failure == "not-permitted":
            return await scheduler(factory, closed).revisit_parked()
        stub.list_status = 500
        return await work.revisit_parked()

    assert scenario(stub, body) == []
    assert one()["status"] == "manual_cleanup_required"


def test_a_swept_file_whose_deletion_is_unproven_is_not_reported() -> None:
    stub = MistralStub(delete_mode="404")
    stub.add(f"{file_prefix(DEPLOYMENT_ID)}orphan", age=7200)

    async def body(factory: Any, w: Any) -> Any:
        return await scheduler(factory).sweep()

    assert scenario(stub, body) == [] and len(stub.files) == 1


def test_an_empty_sweep_listing_touches_nothing() -> None:
    async def body(factory: Any, w: Any) -> Any:
        return await scheduler(factory).sweep()

    assert scenario(MistralStub(), body) == []


def test_a_sweep_absence_provider_also_owes_a_sweep_up_to_the_grace() -> None:
    from ai_gateway.credentials.obligations import note_upload_deadline
    from ai_gateway.db_models.credential_version import ai_credential_version as v

    w = mistral_world()
    with deps.db_engine.connect() as c:
        deadline = c.execute(sa.select(sa.func.now())).scalar_one()
    with deps.db_engine.begin() as c:
        note_upload_deadline(
            c, w["credential_id"], 1, deadline, sweep_grace_seconds=300
        )
        note_upload_deadline(c, w["credential_id"], 1, deadline - timedelta(hours=1))
    with deps.db_engine.connect() as c:
        row = c.execute(
            sa.select(v.c.last_upload_deadline_at, v.c.sweep_discharge_at).where(
                v.c.credential_id == w["credential_id"]
            )
        ).one()
    assert row.last_upload_deadline_at == deadline  # never lowered
    assert row.sweep_discharge_at == deadline + timedelta(seconds=300)

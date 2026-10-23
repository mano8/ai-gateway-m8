"""
The execution core (T27): the D-24 *Execution sequence*, settlement and S-13.

Every test drives the shipped ``ExecutionService`` (or its reservation and
settlement functions) against the PostgreSQL schema, with recording stub
adapters — or the real provider client against a local stub server where the
outcome depends on the transport. "Zero provider requests" means the adapter
was never invoked (and, over HTTP, the stub saw nothing).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess  # nosec B404 - runs this interpreter on a test script
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    DataClass,
    ProviderBoundary,
)
from ai_sdk_m8.schemas.management import ProviderType, ScopeType

from ai_gateway.controllers.resolution import ResolutionPolicy
from ai_gateway.core import deps
from ai_gateway.core.config import ADMISSION_SETTINGS
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.policy import DataClassPolicy, Destination
from ai_gateway.credentials.database import DatabaseCredentialStore
from ai_gateway.credentials.fingerprints import FingerprintKeys
from ai_gateway.credentials.kek import LocalKekProvider
from ai_gateway.db_models.accounting import ai_job_context_use
from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_binding,
    ai_profile_revision,
    ai_provider,
)
from ai_gateway.execution import settlement
from ai_gateway.execution.jobs import (
    DEFAULT_MAX_OUTPUT_TOKENS,
    EmbedJob,
    output_cap,
    require_object,
)
from ai_gateway.execution.limits import ExecutionLimits
from ai_gateway.execution.reservation import reserve
from ai_gateway.execution.service import ExecutionProgress, ExecutionService
from ai_gateway.providers.base import AdapterCall, EmbedOutput
from ai_gateway.providers.breaker import Breakers
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.http import ClientFactory, ProviderEndpoint
from conftest import MEDIA_SERVICE
from execution_world import (
    BYOK_POLICY,
    OPEN,
    TENANT_A,
    TENANT_B,
    USER_A,
    USER_B,
    HookedStore,
    StubAdapter,
    World,
    admissions,
    age,
    as_owner,
    embed_job,
    execution,
    executions,
    make_binding,
    make_credential,
    make_model,
    make_profile,
    make_provider,
    occupied,
    principal,
    replica,
    rerank_job,
    rotate,
    run,
    service,
    structured_job,
    update,
    usage,
    world,
)
from job_contexts import mint
import factories
import pg_harness as pg
from provider_stubs import (
    LIMITS,
    POLICY as DESTINATIONS,
    Reply,
    Resolver,
    StubServer,
    closed_port,
    socket_transport,
)

pytestmark = pytest.mark.usefixtures("clean_db")

CLIENT = MEDIA_SERVICE.client_id


def refused(coro: Any) -> GatewayError:
    with pytest.raises(GatewayError) as caught:
        run(coro)
    return caught.value


def status_of(execution_id: uuid.UUID) -> str:
    return str(execution(execution_id)["status"])


def only_execution() -> Any:
    (row,) = executions()
    return row


# --- the sequence, end to end --------------------------------------------------------


def test_an_embedding_reserves_dispatches_and_settles_ok_exactly_once() -> None:
    w = world()
    adapter = StubAdapter()
    ctx = principal(w.profile_key, tenant_id=TENANT_A, user_id=USER_A)
    done = run(service(adapter).run(ctx, embed_job(w.profile_key, ["ab", "cde"])))
    assert done.result.dimensions == 3
    assert done.result.vectors == ((1.0, 1.0, 1.0), (2.0, 2.0, 2.0))
    receipt = done.execution
    assert receipt.capability is Capability.EMBEDDING and receipt.units == 5
    assert receipt.receipt is None and receipt.provider_usage.input_tokens == 2
    provider_execution = receipt.provider_execution
    assert provider_execution.profile_key == w.profile_key
    assert provider_execution.profile_revision == 1
    assert provider_execution.embedding_space_id is not None
    row = execution(receipt.execution_id)
    assert row["status"] == "ok" and row["error_class"] is None
    assert row["resolved_provider_id"] == w.provider_id
    assert row["resolved_model_id"] == w.model_id
    assert row["resolved_profile_revision"] == 1
    assert row["resolved_boundary"] == "local"
    assert row["resolved_credential_id"] is None  # keyless local provider
    assert row["first_byte_sent_at"] is None  # the stub adapter sent nothing
    assert row["occupancy_released_at"] is not None
    assert row["provider_usage"] == {"input_tokens": 2}
    assert row["context_exp"] is not None and row["dispatched_at"] is not None
    for scope_type, scope_id in (
        ("client", CLIENT),
        ("tenant", TENANT_A),
        ("user", USER_A),
    ):
        assert usage(scope_type, scope_id) == (0, 5)
        assert admissions(f"{scope_type}:{scope_id}") == 1
    assert occupied() == 0
    (seen,) = adapter.calls
    assert seen.endpoint.provider_id == w.provider_id and seen.secret is None
    with as_owner() as c:
        assert c.execute(sa.select(ai_model.c.first_used_at)).scalar_one() is not None
        assert (
            c.execute(sa.select(ai_provider.c.first_used_at)).scalar_one() is not None
        )
        assert (
            c.execute(
                sa.select(sa.func.count()).select_from(ai_job_context_use)
            ).scalar_one()
            == 1
        )


def test_a_replayed_context_executes_nothing() -> None:
    w = world()
    adapter = StubAdapter()
    ctx = principal(w.profile_key)
    run(service(adapter).run(ctx, embed_job(w.profile_key)))
    error = refused(service(adapter).run(ctx, embed_job(w.profile_key)))
    assert error.code is AiErrorCode.CONTEXT_REPLAYED
    assert len(adapter.calls) == 1 and len(executions()) == 1


def test_a_request_for_another_profile_than_the_context_is_refused() -> None:
    w = world()
    error = refused(
        service(StubAdapter()).run(principal(w.profile_key), embed_job("other"))
    )
    assert error.code is AiErrorCode.CONTEXT_INVALID and executions() == []


def test_a_keyed_call_gets_exactly_its_recorded_secret() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    ctx = principal(w.profile_key, data_class=DataClass.PUBLIC)
    done = run(service(adapter).run(ctx, embed_job(w.profile_key)))
    row = execution(done.execution.execution_id)
    assert row["resolved_credential_id"] == w.credential_id
    assert row["resolved_credential_version"] == 1
    assert adapter.calls[0].secret == f"sk-{w.credential_id.hex}"


def test_rerank_and_structured_output_units_are_fixed_before_dispatch() -> None:
    rr = world(Capability.RERANK)
    done = run(
        service(StubAdapter()).run(
            principal(rr.profile_key, Capability.RERANK), rerank_job(rr.profile_key)
        )
    )
    assert done.execution.units == len("q?") + len("a") + len("bb") + len("ccc")
    assert [h.index for h in done.result.hits] == [0, 1, 2]
    capped = world(Capability.STRUCTURED_OUTPUT, max_output_tokens=200)
    done = run(
        service(StubAdapter()).run(
            principal(capped.profile_key, Capability.STRUCTURED_OUTPUT),
            structured_job(capped.profile_key, "12345"),
        )
    )
    assert done.execution.units == 5 + 200
    assert done.result.output == {"cap": 200, "schema": "Invoice"}
    plain = world(Capability.STRUCTURED_OUTPUT)
    done = run(
        service(StubAdapter()).run(
            principal(plain.profile_key, Capability.STRUCTURED_OUTPUT),
            structured_job(plain.profile_key, "123"),
        )
    )
    assert done.execution.units == 3 + DEFAULT_MAX_OUTPUT_TOKENS
    assert output_cap({"max_output_tokens": True}) == DEFAULT_MAX_OUTPUT_TOKENS
    assert output_cap({"max_output_tokens": 0}) == DEFAULT_MAX_OUTPUT_TOKENS


def test_a_structured_output_that_is_not_an_object_fails_charged() -> None:
    w = world(Capability.STRUCTURED_OUTPUT)

    def answer(_call: AdapterCall, _cap: Capability) -> Any:
        from ai_gateway.providers.base import StructuredOutput

        return StructuredOutput(["not", "an", "object"])

    error = refused(
        service(StubAdapter(behave=answer)).run(
            principal(w.profile_key, Capability.STRUCTURED_OUTPUT),
            structured_job(w.profile_key),
        )
    )
    assert error.code is AiErrorCode.PROVIDER_REJECTED
    row = only_execution()
    assert row["status"] == "failed" and row["error_class"] == "provider_rejected"
    assert usage("client", CLIENT)[1] == row["reserved_units"]
    assert require_object({"a": 1}) == {"a": 1}


# --- precedence over both BYOK scopes (C-04, Q6) --------------------------------------------


def three_scopes(capability: Capability = Capability.EMBEDDING) -> dict[str, Any]:
    """Global, tenant-A and user-A bindings of one profile, each with its own key."""
    provider_id = make_provider(
        ProviderBoundary.EXTERNAL, ProviderType.OPENAI_COMPATIBLE
    )
    model_id = make_model(provider_id, capability)
    profile_id, key = make_profile(capability)
    keys = {
        "global": make_credential(provider_id),
        "tenant": make_credential(provider_id, ScopeType.TENANT, tenant_id=TENANT_A),
        "user": make_credential(
            provider_id, ScopeType.USER, tenant_id=TENANT_A, owner_user_id=USER_A
        ),
    }
    make_binding(profile_id, model_id, keys["global"])
    make_binding(
        profile_id, model_id, keys["tenant"], ScopeType.TENANT, tenant_id=TENANT_A
    )
    make_binding(
        profile_id,
        model_id,
        keys["user"],
        ScopeType.USER,
        tenant_id=TENANT_A,
        owner_user_id=USER_A,
    )
    return {
        "key": key,
        "keys": keys,
        "provider_id": provider_id,
        "model_id": model_id,
        "profile_id": profile_id,
    }


@pytest.mark.parametrize(
    ("tenant", "user", "expected"),
    [
        (TENANT_A, USER_A, "user"),
        (TENANT_A, USER_B, "tenant"),
        (TENANT_A, None, "tenant"),
        (None, USER_A, "global"),
        (TENANT_B, USER_A, "global"),
        (None, None, "global"),
    ],
)
def test_user_then_tenant_then_global_is_recorded_and_dispatched(
    tenant: str | None, user: str | None, expected: str
) -> None:
    scopes = three_scopes()
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    ctx = principal(
        scopes["key"], data_class=DataClass.PUBLIC, tenant_id=tenant, user_id=user
    )
    done = run(service(adapter).run(ctx, embed_job(scopes["key"])))
    credential_id = scopes["keys"][expected]
    assert (
        execution(done.execution.execution_id)["resolved_credential_id"]
        == credential_id
    )
    assert adapter.calls[0].secret == f"sk-{credential_id.hex}"


@pytest.mark.parametrize(
    ("data_class", "case", "allowed"),
    [
        (DataClass.RESTRICTED, "no byok", False),
        (DataClass.RESTRICTED, "other tenant's byok", False),
        (DataClass.RESTRICTED, "other user's byok", False),
        (DataClass.RESTRICTED, "own tenant's byok", True),
        (DataClass.RESTRICTED, "own user's byok", True),
        (DataClass.INTERNAL, "no byok", False),
        (DataClass.INTERNAL, "own tenant's byok", True),
        (DataClass.INTERNAL, "own user's byok", True),
        (DataClass.PUBLIC, "no byok", True),
    ],
)
def test_the_data_class_matrix_on_external_destinations(
    data_class: DataClass, case: str, allowed: bool
) -> None:
    scopes = three_scopes()
    context = {
        "no byok": (TENANT_B, None),  # only the global platform key serves
        "other tenant's byok": (
            TENANT_B,
            USER_B,
        ),  # tenant A's key is not this context's
        "other user's byok": (TENANT_B, USER_A),  # user A's key belongs to tenant A
        "own tenant's byok": (TENANT_A, USER_B),
        "own user's byok": (TENANT_A, USER_A),
    }[case]
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    ctx = principal(
        scopes["key"], data_class=data_class, tenant_id=context[0], user_id=context[1]
    )
    call = service(adapter).run(ctx, embed_job(scopes["key"]))
    if allowed:
        run(call)
        assert len(adapter.calls) == 1
        return
    assert refused(call).code is AiErrorCode.DATA_CLASS_DENIED
    assert adapter.calls == [] and executions() == []
    assert usage("client", CLIENT) == (0, 0) and admissions(f"client:{CLIENT}") == 0


def test_a_fall_through_candidate_is_judged_by_d08_and_a_denial_is_terminal() -> None:
    scopes = three_scopes()
    update(ai_credential, scopes["keys"]["user"], status="disabled")
    with as_owner() as c:
        c.execute(
            sa.update(ai_profile_binding)
            .where(ai_profile_binding.c.credential_id == scopes["keys"]["user"])
            .values(on_unavailable="fall_through")
        )
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    ctx = principal(
        scopes["key"],
        data_class=DataClass.PUBLIC,
        tenant_id=TENANT_A,
        user_id=USER_A,
        allowed_boundaries=["local"],
    )
    error = refused(service(adapter).run(ctx, embed_job(scopes["key"])))
    assert error.code is AiErrorCode.BOUNDARY_DENIED  # never the global key
    assert adapter.calls == []


def test_a_user_whose_own_key_resolved_is_still_bounded_by_its_signed_identity() -> (
    None
):
    scopes = three_scopes()
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)

    def ctx() -> Any:
        return principal(
            scopes["key"],
            data_class=DataClass.PUBLIC,
            tenant_id=TENANT_A,
            user_id=USER_A,
        )

    job = embed_job(scopes["key"], ["abcd"])  # 4 units
    run(service(adapter, limits=replace(OPEN, user_daily_units=4)).run(ctx(), job))
    assert usage("user", USER_A) == (0, 4) and usage("tenant", TENANT_A) == (0, 4)
    assert admissions(f"user:{USER_A}") == 1
    over_budget = refused(
        service(adapter, limits=replace(OPEN, user_daily_units=4)).run(ctx(), job)
    )
    assert (
        over_budget.code is AiErrorCode.QUOTA_EXCEEDED
        and over_budget.retry_after_seconds
    )
    over_rate = refused(
        service(adapter, limits=replace(OPEN, rate_per_minute=1)).run(ctx(), job)
    )
    assert over_rate.code is AiErrorCode.RATE_LIMITED
    assert 1 <= (over_rate.retry_after_seconds or 0) <= 60
    held = asyncio.Event()

    async def hold(_call: AdapterCall, _cap: Capability) -> None:
        await held.wait()

    async def capped() -> GatewayError:
        busy = service(
            StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=hold),
            limits=replace(OPEN, max_inflight_per_client=1),
        )
        first = asyncio.create_task(busy.run(ctx(), job))
        while occupied() == 0:
            await asyncio.sleep(0.02)
        try:
            await busy.run(ctx(), job)
        except GatewayError as error:
            held.set()
            await first
            return error
        raise AssertionError("the second call should have been refused")

    assert run(capped()).code is AiErrorCode.RATE_LIMITED
    assert len(adapter.calls) == 1  # only the first call ever reached a provider


def test_a_scoped_binding_reports_its_own_embedding_space() -> None:
    w = world()
    local = make_provider()
    tenant_model = make_model(local)
    make_binding(w.profile_id, tenant_model, None, ScopeType.TENANT, tenant_id=TENANT_A)
    adapter = StubAdapter()
    tenant = run(
        service(adapter).run(
            principal(w.profile_key, tenant_id=TENANT_A), embed_job(w.profile_key)
        )
    )
    platform = run(
        service(adapter).run(principal(w.profile_key), embed_job(w.profile_key))
    )
    tenant_space = tenant.execution.provider_execution.embedding_space_id
    platform_space = platform.execution.provider_execution.embedding_space_id
    assert tenant_space and platform_space and tenant_space != platform_space
    assert adapter.calls[0].external_model_id != adapter.calls[1].external_model_id


def test_create_bind_execute_rotate_disable_delete_for_both_scopes() -> None:
    for scope in (ScopeType.TENANT, ScopeType.USER):
        provider_id = make_provider(
            ProviderBoundary.EXTERNAL, ProviderType.OPENAI_COMPATIBLE
        )
        model_id = make_model(provider_id)
        profile_id, key = make_profile()
        owner = USER_A if scope is ScopeType.USER else None
        credential_id = make_credential(
            provider_id,
            scope,
            tenant_id=TENANT_A,
            owner_user_id=owner,
            secret="v1-secret",
        )
        make_binding(
            profile_id,
            model_id,
            credential_id,
            scope,
            tenant_id=TENANT_A,
            owner_user_id=owner,
        )
        adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)

        def call() -> Any:
            ctx = principal(
                key, data_class=DataClass.RESTRICTED, tenant_id=TENANT_A, user_id=USER_A
            )
            return service(adapter).run(ctx, embed_job(key))

        run(call())
        rotate(credential_id, "v2-secret")
        rotated = run(call())
        assert (
            execution(rotated.execution.execution_id)["resolved_credential_version"]
            == 2
        )
        assert [c.secret for c in adapter.calls] == ["v1-secret", "v2-secret"]
        update(ai_credential, credential_id, status="disabled")
        assert refused(call()).code is AiErrorCode.CREDENTIAL_UNAVAILABLE
        update(ai_credential, credential_id, status="deleted", deleted_at=sa.func.now())
        assert refused(call()).code is AiErrorCode.CREDENTIAL_UNAVAILABLE
        assert len(adapter.calls) == 2


# --- S-13: budgets under concurrency, crashes and sweeps ------------------------------------


def test_n_parallel_calls_against_budget_m_admit_exactly_the_units_that_fit() -> None:
    w = world()
    job = embed_job(w.profile_key, ["abc"])  # 3 units each
    budget = 20  # floor(20 / 3) = 6

    async def parallel() -> list[Any]:
        svc = service(StubAdapter(), limits=replace(OPEN, client_daily_units=budget))
        calls = [svc.run(principal(w.profile_key), job) for _ in range(15)]
        return await asyncio.gather(*calls, return_exceptions=True)

    outcomes = run(parallel())
    ok = [o for o in outcomes if not isinstance(o, BaseException)]
    refusals = [o for o in outcomes if isinstance(o, GatewayError)]
    assert len(ok) == 6 and len(refusals) == 9
    assert {r.code for r in refusals} == {AiErrorCode.QUOTA_EXCEEDED}
    assert usage("client", CLIENT) == (0, 18)


def test_two_gateway_processes_share_one_budget_exactly() -> None:
    w = world()
    budget, units, per_process = 30, 3, 12  # floor(30 / 3) = 10 of 24
    tokens = [
        mint(MEDIA_SERVICE, profile_key=w.profile_key) for _ in range(2 * per_process)
    ]
    environment = dict(os.environ, PYTHONPATH=os.getcwd())
    worker = str(Path(__file__).with_name("replica_worker.py"))
    processes = []
    for start in (0, per_process):
        payload = {
            "budget": budget,
            "profile_key": w.profile_key,
            "inputs": ["x" * units],
            "presenter": CLIENT,
            "tokens": tokens[start : start + per_process],
        }
        process = subprocess.Popen(  # nosec B603 - fixed argv, no shell
            [sys.executable, worker],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            text=True,
        )
        processes.append((process, json.dumps(payload)))
    counts: dict[str, int] = {}
    for process, payload in processes:
        out, err = process.communicate(payload, timeout=120)
        assert process.returncode == 0, err[-2000:]
        for outcome, count in json.loads(out.strip().splitlines()[-1]).items():
            counts[outcome] = counts.get(outcome, 0) + count
    assert counts == {"reserved": 10, "quota_exceeded": 14}
    assert usage("client", CLIENT) == (30, 0)


def http_world() -> World:
    """An external keyed provider reached over the real client, in plain HTTP."""
    w = world(boundary=ProviderBoundary.EXTERNAL)
    update(ai_provider, w.provider_id, base_url="http://api.provider.test")
    return w


def http_service(
    adapter: StubAdapter,
    transport: Callable[[ProviderEndpoint], httpx.AsyncBaseTransport],
    **kw: Any,
) -> ExecutionService:
    factory = ClientFactory(
        DESTINATIONS, LIMITS, Breakers(), resolver=Resolver(), transport=transport
    )
    return service(adapter, factory=factory, **kw)


def posting(
    path: str = "/v1/work", *, then: Callable[[], Any] | None = None
) -> Callable[..., Any]:
    """An adapter behaviour that sends one real request per call."""

    async def behave(call: AdapterCall, _capability: Capability) -> Any:
        await call.post(path, {"inputs": 1})
        if then is not None:
            outcome = then()
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
            return outcome
        return None

    return behave


def test_a_connect_failure_before_any_byte_releases_the_reservation() -> None:
    w = http_world()
    port = closed_port()
    svc = http_service(
        StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=posting()),
        lambda _e: socket_transport(port)[0],
    )
    error = refused(
        svc.run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key),
        )
    )
    assert error.code is AiErrorCode.PROVIDER_UNREACHABLE
    row = only_execution()
    assert row["status"] == "released" and row["first_byte_sent_at"] is None
    assert row["dispatched_at"] is not None  # refunded from dispatching
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_a_timeout_after_dispatch_stays_charged() -> None:
    w = http_world()

    async def scenario() -> GatewayError:
        hang = Reply(chunks=[b" "] * 100, delay=0.2, content_length=100)
        async with StubServer(hang) as server:
            svc = http_service(
                StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=posting()),
                lambda _e: socket_transport(server.port)[0],
                limits=replace(OPEN, total_deadline_seconds=1),
            )
            try:
                await svc.run(
                    principal(w.profile_key, data_class=DataClass.PUBLIC),
                    embed_job(w.profile_key),
                )
            except GatewayError as error:
                return error
        raise AssertionError("timeout expected")

    assert run(scenario()).code is AiErrorCode.TIMEOUT
    row = only_execution()
    assert (
        row["status"] == "charged_uncertain" and row["first_byte_sent_at"] is not None
    )
    assert usage("client", CLIENT) == (0, row["reserved_units"]) and occupied() == 0


def reserved_and_marked(w: World, *, units_text: str = "abcd") -> uuid.UUID:
    """A reservation and its marker, as a handler that then died left them."""
    r = reserve(
        deps.db_engine,
        principal(w.profile_key, tenant_id=TENANT_A),
        embed_job(w.profile_key, [units_text]),
        policy=BYOK_POLICY,
        limits=OPEN,
    )
    assert settlement.mark_dispatching(
        deps.db_engine, r.execution_id, total_deadline_seconds=30
    )
    return r.execution_id


def test_a_crash_after_dispatch_is_settled_charged_by_the_sweeper() -> None:
    execution_id = reserved_and_marked(world())
    assert settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0) == []
    age(execution_id, dispatch_deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    assert settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0) == [
        execution_id
    ]
    row = execution(execution_id)
    assert row["status"] == "charged_uncertain" and row["error_class"] == "timeout"
    assert usage("client", CLIENT) == (0, 4) and usage("tenant", TENANT_A) == (0, 4)
    assert occupied() == 0


def test_a_crash_before_dispatch_is_abandoned_and_released() -> None:
    w = world()
    r = reserve(
        deps.db_engine,
        principal(w.profile_key),
        embed_job(w.profile_key, ["ab"]),
        policy=BYOK_POLICY,
        limits=OPEN,
    )
    assert settlement.sweep_expired_pending(deps.db_engine) == []
    age(r.execution_id, reservation_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert settlement.sweep_expired_pending(deps.db_engine) == [r.execution_id]
    assert status_of(r.execution_id) == "abandoned"
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_a_late_answer_after_the_sweeper_cannot_double_settle() -> None:
    execution_id = reserved_and_marked(world())
    age(execution_id, dispatch_deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0)
    from ai_gateway.db_models._common import ExecutionStatus

    assert not settlement.settle(deps.db_engine, execution_id, ExecutionStatus.OK)
    assert status_of(execution_id) == "charged_uncertain"
    assert usage("client", CLIENT) == (0, 4) and occupied() == 0


def test_a_kill_after_sending_then_two_sweeps_settle_exactly_once() -> None:
    execution_id = reserved_and_marked(world())
    assert settlement.record_first_byte(deps.db_engine, execution_id)
    assert not settlement.record_first_byte(deps.db_engine, execution_id)  # set once
    age(execution_id, dispatch_deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    first = settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0)
    second = settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0)
    assert first == [execution_id] and second == []
    assert usage("client", CLIENT) == (0, 4) and occupied() == 0


def test_settlement_uses_the_reserved_day_across_midnight() -> None:
    execution_id = reserved_and_marked(world())
    yesterday = date.today() - timedelta(days=1)
    age(execution_id, reservation_day=yesterday)
    from ai_gateway.db_models._common import ExecutionStatus

    assert settlement.settle(deps.db_engine, execution_id, ExecutionStatus.OK)
    with deps.db_engine.connect() as c:
        from ai_gateway.db_models.accounting import ai_usage

        rows = {
            (r.day, r.scope_type): (r.reserved, r.used)
            for r in c.execute(sa.select(ai_usage))
        }
    assert rows[(yesterday, "client")] == (0, 4)
    assert rows[(yesterday, "tenant")] == (0, 4)
    assert all(v == (0, 0) for (day, _), v in rows.items() if day != yesterday)


def test_a_sweep_racing_the_marker_leaves_the_handler_no_provider_call() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)

    def expire_and_sweep(_cid: uuid.UUID, _ver: int) -> None:
        (row,) = executions()
        age(row["id"], reservation_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        assert settlement.sweep_expired_pending(deps.db_engine) == [row["id"]]

    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    svc = service(adapter, store=HookedStore(expire_and_sweep))
    error = refused(
        svc.run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key),
        )
    )
    assert error.code is AiErrorCode.TIMEOUT
    assert adapter.calls == []
    assert only_execution()["status"] == "abandoned"
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_cancellation_before_the_marker_releases_on_the_reserved_day() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    fetching, proceed = threading.Event(), threading.Event()
    yesterday = date.today() - timedelta(days=1)

    def stall(_cid: uuid.UUID, _ver: int) -> None:
        (row,) = executions()
        age(row["id"], reservation_day=yesterday)
        fetching.set()
        proceed.wait(10)

    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    svc = service(adapter, store=HookedStore(stall))

    async def scenario() -> None:
        task = asyncio.create_task(
            svc.run(
                principal(w.profile_key, data_class=DataClass.PUBLIC),
                embed_job(w.profile_key),
            )
        )
        while not fetching.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        proceed.set()
        await svc.drain()

    run(scenario())
    row = only_execution()
    assert row["status"] == "released" and adapter.calls == []
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_cancellation_after_the_marker_is_charged_on_the_reserved_day() -> None:
    w = world()
    yesterday = date.today() - timedelta(days=1)

    async def hang(_call: AdapterCall, _cap: Capability) -> None:
        (row,) = executions()
        age(row["id"], reservation_day=yesterday)
        assert gate is not None
        gate.set()
        await asyncio.sleep(60)

    gate: asyncio.Event | None = None
    svc = service(StubAdapter(behave=hang))

    async def scenario() -> None:
        nonlocal gate
        gate = asyncio.Event()
        task = asyncio.create_task(
            svc.run(
                principal(w.profile_key, tenant_id=TENANT_A),
                embed_job(w.profile_key, ["abcd"]),
            )
        )
        await gate.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await svc.drain()

    run(scenario())
    row = only_execution()
    assert row["status"] == "charged_uncertain"
    with deps.db_engine.connect() as c:
        from ai_gateway.db_models.accounting import ai_usage

        days = {
            r.day: (r.reserved, r.used)
            for r in c.execute(
                sa.select(ai_usage).where(ai_usage.c.scope_type == "client")
            )
        }
    assert days[yesterday] == (0, 4) and occupied() == 0


def test_the_in_flight_cap_holds_across_replicas_and_slots_return_exactly_once() -> (
    None
):
    w = world()
    cap = 3
    limits = replace(OPEN, max_inflight_per_client=cap)
    engines = [deps.db_engine, replica()]

    async def scenario() -> GatewayError:
        gate = asyncio.Event()

        async def hold(_call: AdapterCall, _cap: Capability) -> None:
            await gate.wait()

        replicas = [
            service(StubAdapter(behave=hold), limits=limits, engine=e) for e in engines
        ]
        held = [
            asyncio.create_task(
                replicas[i % 2].run(principal(w.profile_key), embed_job(w.profile_key))
            )
            for i in range(cap)
        ]
        while sum(1 for r in executions() if r["status"] == "dispatching") < cap:
            await asyncio.sleep(0.02)
        assert occupied() == cap
        try:
            await replicas[1].run(principal(w.profile_key), embed_job(w.profile_key))
        except GatewayError as error:
            gate.set()
            await asyncio.gather(*held)
            return error
        raise AssertionError("the call over the cap should have been refused")

    try:
        refusal = run(scenario())
    finally:
        engines[1].dispose()
    assert refusal.code is AiErrorCode.RATE_LIMITED
    assert occupied() == 0
    assert sorted(r["status"] for r in executions()) == ["ok"] * cap
    # Expiry, a connect failure and repeated sweeps never drift the counter.
    pending = reserve(
        deps.db_engine,
        principal(w.profile_key),
        embed_job(w.profile_key),
        policy=BYOK_POLICY,
        limits=limits,
    )
    marked = reserved_and_marked(w)
    assert occupied() == 2
    age(
        pending.execution_id,
        reservation_expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    age(marked, dispatch_deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    for _ in range(3):
        settlement.sweep_expired_pending(deps.db_engine)
        settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0)
    assert occupied() == 0


def test_a_rate_window_refusal_carries_retry_after_and_charges_nothing() -> None:
    w = world()
    svc = service(StubAdapter(), limits=replace(OPEN, rate_per_minute=2))
    for _ in range(2):
        run(svc.run(principal(w.profile_key), embed_job(w.profile_key)))
    error = refused(svc.run(principal(w.profile_key), embed_job(w.profile_key)))
    assert error.code is AiErrorCode.RATE_LIMITED
    assert 1 <= (error.retry_after_seconds or 0) <= 60
    assert len(executions()) == 2 and admissions(f"client:{CLIENT}") == 2


def test_an_identity_pin_mismatch_is_refused_before_any_provider_call() -> None:
    w = world()

    class Pinned(EmbedJob):
        pass

    adapter = StubAdapter()
    base = embed_job(w.profile_key)
    wrong = Pinned(base.request)
    object.__setattr__(wrong, "expected_identity", "f" * 32)
    error = refused(service(adapter).run(principal(w.profile_key), wrong))
    assert error.code is AiErrorCode.EXECUTION_IDENTITY_CHANGED
    assert adapter.calls == [] and executions() == []
    with as_owner() as c:
        identity = c.execute(sa.select(ai_model.c.execution_identity)).scalar_one()
    right = Pinned(base.request)
    object.__setattr__(right, "expected_identity", identity)
    run(service(adapter).run(principal(w.profile_key), right))
    assert len(adapter.calls) == 1


def test_a_handler_resumed_past_its_deadline_sends_nothing_and_is_charged() -> None:
    w = http_world()

    async def scenario() -> tuple[GatewayError, StubServer]:
        async with StubServer(Reply()) as server:

            async def paused(call: AdapterCall, _cap: Capability) -> None:
                time.sleep(1.2)  # a pause the event loop cannot interrupt
                await call.post("/v1/work", {"inputs": 1})

            svc = http_service(
                StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=paused),
                lambda _e: socket_transport(server.port)[0],
                limits=replace(OPEN, total_deadline_seconds=1),
            )
            try:
                await svc.run(
                    principal(w.profile_key, data_class=DataClass.PUBLIC),
                    embed_job(w.profile_key),
                )
            except GatewayError as error:
                return error, server
        raise AssertionError("timeout expected")

    error, server = run(scenario())
    assert error.code is AiErrorCode.TIMEOUT and server.requests == []
    row = only_execution()
    assert row["status"] == "charged_uncertain" and row["first_byte_sent_at"] is None


# --- rerank destinations (D-08) -------------------------------------------------------------


@pytest.mark.parametrize(
    "data_class", [DataClass.PUBLIC, DataClass.INTERNAL, DataClass.RESTRICTED]
)
def test_rerank_to_an_external_provider_is_boundary_denied_for_every_class(
    data_class: DataClass,
) -> None:
    provider_id = make_provider(
        ProviderBoundary.EXTERNAL, ProviderType.OPENAI_COMPATIBLE
    )
    model_id = make_model(provider_id, Capability.RERANK)
    profile_id, key = make_profile(Capability.RERANK)
    tenant_key = make_credential(provider_id, ScopeType.TENANT, tenant_id=TENANT_A)
    make_binding(profile_id, model_id, make_credential(provider_id))
    make_binding(profile_id, model_id, tenant_key, ScopeType.TENANT, tenant_id=TENANT_A)
    widened = ResolutionPolicy(
        DataClassPolicy(
            {
                DataClass.PUBLIC: frozenset(Destination),
                DataClass.INTERNAL: frozenset(Destination),
                DataClass.RESTRICTED: frozenset(
                    {Destination.LOCAL, Destination.EXTERNAL_BYOK}
                ),
            }
        ),
        user_byok_enabled=True,
        database_backend=True,
    )
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    ctx = principal(key, Capability.RERANK, data_class=data_class, tenant_id=TENANT_A)
    error = refused(service(adapter, policy=widened).run(ctx, rerank_job(key)))
    assert error.code is AiErrorCode.BOUNDARY_DENIED and adapter.calls == []


def test_a_binding_repointed_to_external_before_resolution_is_refused() -> None:
    w = world(Capability.RERANK)
    external = make_provider(ProviderBoundary.EXTERNAL, ProviderType.OPENAI_COMPATIBLE)
    update(
        ai_profile_binding,
        w.binding_id,
        model_id=make_model(external, Capability.RERANK),
        credential_id=make_credential(external),
    )
    adapter = StubAdapter()
    error = refused(
        service(adapter).run(
            principal(w.profile_key, Capability.RERANK), rerank_job(w.profile_key)
        )
    )
    assert error.code is AiErrorCode.BOUNDARY_DENIED and adapter.calls == []


def test_a_binding_repointed_after_resolution_dispatches_the_recorded_provider() -> (
    None
):
    w = world(Capability.RERANK, keyed=True)
    other = make_provider()
    other_model = make_model(other, Capability.RERANK)

    def repoint(_cid: uuid.UUID, _ver: int) -> None:
        update(
            ai_profile_binding, w.binding_id, model_id=other_model, credential_id=None
        )

    adapter = StubAdapter()
    run(
        service(adapter, store=HookedStore(repoint)).run(
            principal(w.profile_key, Capability.RERANK), rerank_job(w.profile_key)
        )
    )
    (seen,) = adapter.calls
    assert seen.endpoint.provider_id == w.provider_id
    row = only_execution()
    assert row["resolved_model_id"] == w.model_id and row["status"] == "ok"


# --- composed workflows (D-24 multi-request rule) -----------------------------------------


def two_requests(
    port_first: int, *, second_refused: bool
) -> Callable[[ProviderEndpoint], httpx.AsyncBaseTransport]:
    import httpcore

    from provider_stubs import RemapNetwork

    class Network(RemapNetwork):
        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Any = None,
        ) -> httpcore.AsyncNetworkStream:
            if second_refused and self.connects:
                self.connects.append((host, port))
                raise httpcore.ConnectError("refused")
            return await super().connect_tcp(
                host, port, timeout, local_address, socket_options
            )

    def transport(_e: ProviderEndpoint) -> httpx.AsyncBaseTransport:
        built = httpx.AsyncHTTPTransport(retries=0, trust_env=False)
        built._pool = httpcore.AsyncConnectionPool(
            network_backend=Network(port_first), retries=0
        )
        return built

    return transport


def test_a_connect_error_on_the_second_request_after_a_successful_first_stays_charged() -> (
    None
):
    w = http_world()

    async def scenario() -> tuple[GatewayError, StubServer]:
        closing = Reply(headers=[("Connection", "close")], chunks=[b"{}"])
        async with StubServer(closing) as server:

            async def two(call: AdapterCall, cap: Capability) -> None:
                await call.post("/v1/upload", {"part": 1})
                await call.post("/v1/work", {"part": 2})

            svc = http_service(
                StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=two),
                two_requests(server.port, second_refused=True),
            )
            try:
                await svc.run(
                    principal(w.profile_key, data_class=DataClass.PUBLIC),
                    embed_job(w.profile_key),
                )
            except GatewayError as error:
                return error, server
        raise AssertionError("failure expected")

    error, server = run(scenario())
    assert error.code is AiErrorCode.PROVIDER_UNREACHABLE and len(server.requests) == 1
    row = only_execution()
    assert (
        row["status"] == "charged_uncertain" and row["first_byte_sent_at"] is not None
    )
    assert usage("client", CLIENT)[1] == row["reserved_units"]


def test_a_cleanup_failure_after_successful_work_settles_ok() -> None:
    w = http_world()

    async def scenario() -> Any:
        async with StubServer(Reply(headers=[("Connection", "close")])) as server:

            async def work_then_cleanup(call: AdapterCall, cap: Capability) -> Any:
                await call.post("/v1/work", {"part": 1})
                try:
                    await call.delete("/v1/files/x")
                except ProviderFailure:
                    pass  # cleanup is the scheduler's to retry; the work stands
                return EmbedOutput([[0.0, 0.0, 0.0], [1.0, 1.0, 1.0]])

            svc = http_service(
                StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=work_then_cleanup),
                two_requests(server.port, second_refused=True),
            )
            return await svc.run(
                principal(w.profile_key, data_class=DataClass.PUBLIC),
                embed_job(w.profile_key),
            )

    done = run(scenario())
    assert only_execution()["status"] == "ok"
    assert done.result.vectors[1] == (1.0, 1.0, 1.0)


def test_a_lost_first_response_settles_charged_uncertain() -> None:
    w = http_world()

    async def scenario() -> GatewayError:
        def vanish(received: Any) -> None:
            raise ConnectionResetError("gone before answering")

        async with StubServer(Reply(), on_request=vanish) as server:
            svc = http_service(
                StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=posting()),
                lambda _e: socket_transport(server.port)[0],
            )
            try:
                await svc.run(
                    principal(w.profile_key, data_class=DataClass.PUBLIC),
                    embed_job(w.profile_key),
                )
            except GatewayError as error:
                return error
        raise AssertionError("failure expected")

    assert run(scenario()).code is AiErrorCode.PROVIDER_UNREACHABLE
    row = only_execution()
    assert (
        row["status"] == "charged_uncertain" and row["first_byte_sent_at"] is not None
    )


# --- credential material and administrative changes before the marker ------------------------


def test_a_stalled_credential_store_releases_with_no_provider_request() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    from ai_gateway.core.config import settings

    assert settings.kek is not None and settings.fingerprint_key is not None
    quick = DatabaseCredentialStore(
        deps.db_engine,
        LocalKekProvider(settings.kek, settings.previous_keks),
        FingerprintKeys(settings.fingerprint_key, settings.previous_fingerprint_key),
        resolve_timeout_seconds=0.3,
    )
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    admin = pg.owner_engine()  # transactional: the lock lives in its transaction
    try:
        with admin.connect() as holder:
            transaction = holder.begin()
            holder.execute(
                sa.text("LOCK TABLE ai_credential_version IN ACCESS EXCLUSIVE MODE")
            )
            try:
                started = time.monotonic()
                error = refused(
                    service(adapter, store=quick).run(
                        principal(w.profile_key, data_class=DataClass.PUBLIC),
                        embed_job(w.profile_key),
                    )
                )
                elapsed = time.monotonic() - started
            finally:
                transaction.rollback()
    finally:
        admin.dispose()
    assert error.code is AiErrorCode.CREDENTIAL_UNAVAILABLE and elapsed < 5
    assert adapter.calls == []
    row = only_execution()
    assert row["status"] == "released" and row["dispatched_at"] is None
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def stalled(
    change: Callable[[World], None], w: World
) -> tuple[GatewayError, StubAdapter]:
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    svc = service(adapter, store=HookedStore(lambda _c, _v: change(w)))
    ctx = principal(w.profile_key, data_class=DataClass.PUBLIC)
    with pytest.raises(GatewayError) as caught:
        run(svc.run(ctx, embed_job(w.profile_key)))
    return caught.value, adapter


@pytest.mark.parametrize(
    "change",
    [
        "credential disabled",
        "credential rotated",
        "provider disabled",
        "model disabled",
        "model flagged",
        "profile disabled",
        "profile revised",
    ],
)
def test_a_change_committed_before_the_marker_stops_the_call(change: str) -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)

    def apply(world_: World) -> None:
        if change == "credential disabled":
            update(ai_credential, world_.credential_id, status="disabled")
        elif change == "credential rotated":
            assert world_.credential_id is not None
            rotate(world_.credential_id, "next-secret")
        elif change == "provider disabled":
            update(ai_provider, world_.provider_id, enabled=False)
        elif change == "model disabled":
            update(ai_model, world_.model_id, enabled=False)
        elif change == "model flagged":
            update(ai_model, world_.model_id, flagged_at=sa.func.now())
        elif change == "profile disabled":
            update(ai_profile, world_.profile_id, enabled=False)
        else:
            with as_owner() as c:
                c.execute(
                    sa.insert(ai_profile_revision).values(
                        profile_id=world_.profile_id,
                        revision=2,
                        execution_config={"v": 2},
                        execution_config_hash="b" * 64,
                    )
                )
                c.execute(
                    sa.update(ai_profile)
                    .where(ai_profile.c.id == world_.profile_id)
                    .values(current_revision=2)
                )

    error, adapter = stalled(apply, w)
    assert error.code is AiErrorCode.CREDENTIAL_UNAVAILABLE
    assert adapter.calls == []
    row = only_execution()
    assert row["status"] == "released" and row["dispatched_at"] is None
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_a_binding_repointed_before_the_material_fetch_fetches_the_recorded_version() -> (
    None
):
    w = world(boundary=ProviderBoundary.EXTERNAL)
    other_key = make_credential(w.provider_id, secret="other-secret")

    def repoint(_cid: uuid.UUID, _ver: int) -> None:
        update(ai_profile_binding, w.binding_id, credential_id=other_key)

    store = HookedStore(repoint)
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    run(
        service(adapter, store=store).run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key),
        )
    )
    assert store.fetched == [(w.credential_id, 1)]
    assert adapter.calls[0].secret == f"sk-{w.credential_id.hex}"


def test_a_context_expiring_before_the_marker_dispatches_nothing() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    ctx = principal(
        w.profile_key, data_class=DataClass.PUBLIC, exp=int(time.time()) + 2
    )
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    svc = service(adapter, store=HookedStore(lambda _c, _v: time.sleep(2.5)))
    error = refused(svc.run(ctx, embed_job(w.profile_key)))
    assert error.code is AiErrorCode.CONTEXT_EXPIRED and adapter.calls == []
    assert only_execution()["status"] == "released"


def test_a_throttled_credential_is_refused_with_retry_after_on_every_replica() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    update(
        ai_credential,
        w.credential_id,
        throttled_until=sa.func.now() + timedelta(seconds=40),
    )
    second = replica()
    try:
        for engine in (deps.db_engine, second):
            adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
            error = refused(
                service(adapter, engine=engine).run(
                    principal(w.profile_key, data_class=DataClass.PUBLIC),
                    embed_job(w.profile_key),
                )
            )
            assert error.code is AiErrorCode.RATE_LIMITED
            assert 35 <= (error.retry_after_seconds or 0) <= 41 and adapter.calls == []
    finally:
        second.dispose()


def test_a_throttle_set_during_the_fetch_is_diagnosed_with_retry_after() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    error, adapter = stalled(
        lambda world_: update(
            ai_credential,
            world_.credential_id,
            throttled_until=sa.func.now() + timedelta(seconds=30),
        ),
        w,
    )
    assert error.code is AiErrorCode.RATE_LIMITED and adapter.calls == []


def test_a_provider_429_sets_the_cooldown_every_replica_then_honours() -> None:
    w = http_world()

    async def scenario() -> GatewayError:
        async with StubServer(
            Reply(status=429, headers=[("Retry-After", "45")])
        ) as server:
            svc = http_service(
                StubAdapter(ProviderType.OPENAI_COMPATIBLE, behave=posting()),
                lambda _e: socket_transport(server.port)[0],
            )
            try:
                await svc.run(
                    principal(w.profile_key, data_class=DataClass.PUBLIC),
                    embed_job(w.profile_key),
                )
            except GatewayError as error:
                return error
        raise AssertionError("refusal expected")

    error = run(scenario())
    assert error.code is AiErrorCode.RATE_LIMITED and error.retry_after_seconds == 45
    assert only_execution()["status"] == "failed"
    next_call = refused(
        service(StubAdapter(ProviderType.OPENAI_COMPATIBLE)).run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key),
        )
    )
    assert next_call.code is AiErrorCode.RATE_LIMITED


def test_an_explicit_binding_with_an_unavailable_key_fails_closed() -> None:
    scopes = three_scopes()
    update(ai_credential, scopes["keys"]["tenant"], status="invalid")
    adapter = StubAdapter(ProviderType.OPENAI_COMPATIBLE)
    ctx = principal(
        scopes["key"], data_class=DataClass.PUBLIC, tenant_id=TENANT_A, user_id=USER_B
    )
    error = refused(service(adapter).run(ctx, embed_job(scopes["key"])))
    assert error.code is AiErrorCode.CREDENTIAL_UNAVAILABLE and adapter.calls == []


def test_an_adapterless_or_unserved_capability_and_an_open_breaker_release() -> None:
    w = world()
    no_adapter = refused(
        service().run(principal(w.profile_key), embed_job(w.profile_key))
    )
    assert no_adapter.code is AiErrorCode.CAPABILITY_UNSUPPORTED
    narrow = StubAdapter(capabilities=frozenset({Capability.RERANK}))
    unserved = refused(
        service(narrow).run(principal(w.profile_key), embed_job(w.profile_key))
    )
    assert unserved.code is AiErrorCode.CAPABILITY_UNSUPPORTED
    breakers = Breakers()
    breaker = breakers.for_provider(w.provider_id)
    for _ in range(5):
        breaker.failure()
    opened = refused(
        service(StubAdapter(), breakers=breakers).run(
            principal(w.profile_key), embed_job(w.profile_key)
        )
    )
    assert opened.code is AiErrorCode.BREAKER_OPEN
    assert [r["status"] for r in executions()] == ["released"] * 3
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_a_store_failure_of_any_kind_releases_as_credential_unavailable() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)

    def broken(_cid: uuid.UUID, _ver: int) -> None:
        raise RuntimeError("store bug")

    error = refused(
        service(
            StubAdapter(ProviderType.OPENAI_COMPATIBLE), store=HookedStore(broken)
        ).run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key),
        )
    )
    assert error.code is AiErrorCode.CREDENTIAL_UNAVAILABLE
    assert only_execution()["status"] == "released"


def test_an_unexpected_adapter_error_is_charged_uncertain() -> None:
    w = world()

    def bug(_call: AdapterCall, _cap: Capability) -> None:
        raise ZeroDivisionError("adapter bug")

    with pytest.raises(ZeroDivisionError):
        run(
            service(StubAdapter(behave=bug)).run(
                principal(w.profile_key), embed_job(w.profile_key)
            )
        )
    assert only_execution()["status"] == "charged_uncertain"
    assert occupied() == 0


def test_a_core_deadline_bounds_an_adapter_that_never_does_io() -> None:
    w = world()

    async def spin(_call: AdapterCall, _cap: Capability) -> None:
        await asyncio.sleep(10)

    error = refused(
        service(
            StubAdapter(behave=spin), limits=replace(OPEN, total_deadline_seconds=1)
        ).run(principal(w.profile_key), embed_job(w.profile_key))
    )
    assert error.code is AiErrorCode.TIMEOUT
    assert only_execution()["status"] == "charged_uncertain"


def test_an_ok_settlement_lost_to_a_sweeper_discards_the_late_answer() -> None:
    w = world()

    async def late(_call: AdapterCall, _cap: Capability) -> None:
        (row,) = executions()
        age(row["id"], dispatch_deadline_at=datetime.now(UTC) - timedelta(seconds=1))
        settlement.sweep_stale_dispatching(deps.db_engine, grace_seconds=0)

    error = refused(
        service(StubAdapter(behave=late)).run(
            principal(w.profile_key), embed_job(w.profile_key)
        )
    )
    assert error.code is AiErrorCode.TIMEOUT
    assert only_execution()["status"] == "charged_uncertain"
    assert usage("client", CLIENT)[1] == only_execution()["reserved_units"]


def test_progress_refuses_a_row_that_can_no_longer_send() -> None:
    execution_id = reserved_and_marked(world())
    progress = ExecutionProgress(deps.db_engine, execution_id)
    run(progress.first_byte_sent())
    run(progress.first_byte_sent())  # idempotent
    assert progress.recorded
    other = reserved_and_marked(world())
    age(other, dispatch_deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    late = ExecutionProgress(deps.db_engine, other)
    with pytest.raises(ProviderFailure) as caught:
        run(late.first_byte_sent())
    assert caught.value.code is AiErrorCode.TIMEOUT and not late.recorded


# --- the model row: first use serializes, later use never waits -------------------------------


def test_a_first_reservation_racing_an_admin_edit_sees_the_edit() -> None:
    w = world()
    adapter = StubAdapter()
    owner_engine = pg.owner_engine()
    blocked = threading.Event()
    try:
        with owner_engine.connect() as admin:
            transaction = admin.begin()
            admin.execute(
                sa.select(ai_model).where(ai_model.c.id == w.model_id).with_for_update()
            )
            admin.execute(
                sa.update(ai_model)
                .where(ai_model.c.id == w.model_id)
                .values(external_model_id="edited-model")
            )

            def reservation() -> None:
                blocked.set()
                run(
                    service(adapter).run(
                        principal(w.profile_key), embed_job(w.profile_key)
                    )
                )

            worker = threading.Thread(target=reservation)
            worker.start()
            blocked.wait(5)
            time.sleep(0.5)
            assert adapter.calls == []  # the reservation waits on the stamp
            transaction.commit()
            worker.join(10)
    finally:
        owner_engine.dispose()
    assert adapter.calls[0].external_model_id == "edited-model"


def test_later_reservations_never_lock_the_model_row_but_the_first_one_does() -> None:
    w = world()

    def stamp_in_open_transaction() -> tuple[sa.Engine, sa.Connection, Any]:
        engine = replica()
        connection = engine.connect()
        transaction = connection.begin()
        connection.execute(
            sa.update(ai_model)
            .where(ai_model.c.id == w.model_id, ai_model.c.first_used_at.is_(None))
            .values(first_used_at=sa.func.now())
        )
        return engine, connection, transaction

    def locked() -> bool:
        engine = replica()
        try:
            with engine.connect() as probe:
                try:
                    probe.execute(
                        sa.select(ai_model.c.id)
                        .where(ai_model.c.id == w.model_id)
                        .with_for_update(nowait=True)
                    )
                except sa.exc.OperationalError:
                    return True
                return False
        finally:
            engine.dispose()

    engine, connection, transaction = stamp_in_open_transaction()
    assert locked()  # the first use holds the row
    transaction.commit()
    connection.close()
    engine.dispose()
    engine, connection, transaction = stamp_in_open_transaction()
    assert not locked()  # every later "stamp" matches nothing and locks nothing
    transaction.rollback()
    connection.close()
    engine.dispose()


def test_two_hundred_reservations_across_two_replicas_never_wait_on_the_model() -> None:
    w = world()
    run(
        service(StubAdapter()).run(principal(w.profile_key), embed_job(w.profile_key))
    )  # first use
    second = replica()
    stop = threading.Event()
    waits: list[Any] = []
    admin = pg.admin_engine(pg.DB_NAME)

    def sample() -> None:
        with admin.connect() as c:
            oid = c.execute(sa.text("SELECT 'ai_model'::regclass::oid")).scalar_one()
            while not stop.is_set():
                rows = c.execute(
                    sa.text(
                        "SELECT locktype, mode FROM pg_locks WHERE NOT granted "
                        "AND (relation = :oid OR locktype = 'tuple' AND relation = :oid)"
                    ),
                    {"oid": oid},
                ).all()
                waits.extend(rows)
                time.sleep(0.005)

    sampler = threading.Thread(target=sample)
    sampler.start()
    try:
        from concurrent.futures import ThreadPoolExecutor

        def one(i: int) -> None:
            engine = (deps.db_engine, second)[i % 2]
            reserve(
                engine,
                principal(w.profile_key),
                embed_job(w.profile_key),
                policy=BYOK_POLICY,
                limits=OPEN,
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(one, range(200)))
    finally:
        stop.set()
        sampler.join()
        second.dispose()
        admin.dispose()
    assert waits == []
    assert len(executions()) == 201


# --- settings ---------------------------------------------------------------------------------


def test_limits_follow_the_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_gateway.core.config import settings

    assert ExecutionLimits.from_settings(settings).client_daily_units is None
    monkeypatch.setattr(settings, "AI_CLIENT_DAILY_BUDGET_UNITS", 7)
    monkeypatch.setattr(settings, "AI_RATE_LIMIT_PER_MINUTE", 3)
    limits = ExecutionLimits.from_settings(settings)
    assert (limits.client_daily_units, limits.rate_per_minute) == (7, 3)
    assert limits.reservation_ttl_seconds == settings.AI_RESERVATION_TTL_SECONDS
    assert limits.total_deadline_seconds == settings.AI_PROVIDER_TOTAL_DEADLINE_SECONDS
    assert set(ADMISSION_SETTINGS) == {
        "AI_CLIENT_DAILY_BUDGET_UNITS",
        "AI_TENANT_DAILY_BUDGET_UNITS",
        "AI_USER_DAILY_BUDGET_UNITS",
        "AI_RATE_LIMIT_PER_MINUTE",
        "AI_MAX_INFLIGHT_PER_CLIENT",
    }


def test_the_shipped_service_is_built_once_from_the_settings() -> None:
    shipped = deps.execution_service
    assert isinstance(shipped, ExecutionService)
    assert shipped._adapters is deps.adapters
    assert shipped._store is deps.credential_store
    assert shipped._deployment_id == deps.settings.deployment_id
    assert shipped._limits() == ExecutionLimits.from_settings(deps.settings)
    assert shipped._policy() == ResolutionPolicy.from_settings(deps.settings)


# --- races at the edges of the sequence -------------------------------------------------------


def test_a_flagged_model_is_never_reserved() -> None:
    w = world()
    update(ai_model, w.model_id, flagged_at=sa.func.now())
    adapter = StubAdapter()
    error = refused(
        service(adapter).run(principal(w.profile_key), embed_job(w.profile_key))
    )
    assert error.code is AiErrorCode.CREDENTIAL_UNAVAILABLE
    assert adapter.calls == [] and executions() == []


def test_a_capability_removed_between_resolution_and_the_stamp_is_refused() -> None:
    from ai_gateway.controllers.audit import audited_transaction
    from ai_gateway.controllers.resolution import ExecutionRequest, resolve
    from ai_gateway.execution import reservation as reservation_module

    w = world()
    with audited_transaction(deps.db_engine) as tx:
        resolution = resolve(
            tx,
            ExecutionRequest.from_context(principal(w.profile_key).payload),
            BYOK_POLICY,
        )
        tx.connection.execute(
            sa.update(ai_model)
            .where(ai_model.c.id == w.model_id)
            .values(capabilities=["rerank"], dimensions=None)
        )
        with pytest.raises(GatewayError) as caught:
            reservation_module._freeze(tx.connection, resolution, Capability.EMBEDDING)
    assert caught.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED


def test_an_embedding_model_without_dimensions_is_rejected() -> None:
    from ai_gateway.providers.base import ModelRef
    from ai_gateway.providers.http import Deadline

    job = embed_job("p")
    call = AdapterCall(
        client=None,  # type: ignore[arg-type]
        secret=None,
        model=ModelRef(model_id=uuid.uuid4(), external_model_id="m"),
        progress=None,  # type: ignore[arg-type]
        deadline=Deadline.after(5),
    )

    class Adapter:
        async def embed(self, _call: AdapterCall, inputs: Any) -> EmbedOutput:
            return EmbedOutput([[0.0]] * len(inputs))

    with pytest.raises(ProviderFailure) as caught:
        run(job.execute(Adapter(), call))  # type: ignore[arg-type]
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED


def blocked_marker(
    w: World, then: Callable[[sa.Connection, uuid.UUID], None]
) -> ExecutionService:
    """A service whose marker waits on a lock another transaction holds."""
    holder: dict[str, Any] = {}

    def lock_the_row(_cid: uuid.UUID, _ver: int) -> None:
        (row,) = executions()
        engine = pg.owner_engine()
        connection = engine.connect()
        transaction = connection.begin()
        connection.execute(
            sa.select(ai_execution.c.id)
            .where(ai_execution.c.id == row["id"])
            .with_for_update()
        )
        holder.update(
            engine=engine, connection=connection, transaction=transaction, id=row["id"]
        )

    svc = service(
        StubAdapter(ProviderType.OPENAI_COMPATIBLE), store=HookedStore(lock_the_row)
    )
    svc.holder = holder  # type: ignore[attr-defined]
    svc.then = then  # type: ignore[attr-defined]
    return svc


def cancel_during_marker(svc: ExecutionService, w: World) -> None:
    holder = svc.holder  # type: ignore[attr-defined]

    async def scenario() -> None:
        task = asyncio.create_task(
            svc.run(
                principal(w.profile_key, data_class=DataClass.PUBLIC),
                embed_job(w.profile_key),
            )
        )
        async with asyncio.timeout(20):
            while "transaction" not in holder:
                await asyncio.sleep(0.01)
        await asyncio.sleep(0.3)  # the marker is now waiting on the lock
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        svc.then(holder["connection"], holder["id"])  # type: ignore[attr-defined]
        holder["transaction"].commit()
        holder["connection"].close()
        holder["engine"].dispose()
        async with asyncio.timeout(20):
            while svc._detached or status_of(holder["id"]) in (
                "pending",
                "dispatching",
            ):
                await svc.drain()
                await asyncio.sleep(0.05)

    run(scenario())


def test_a_request_cancelled_while_its_marker_waits_is_charged_once_marked() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    svc = blocked_marker(w, lambda _c, _id: None)
    cancel_during_marker(svc, w)
    row = only_execution()
    assert row["status"] == "charged_uncertain" and row["dispatched_at"] is not None
    assert occupied() == 0


def test_a_request_cancelled_while_its_marker_waits_is_released_when_unmarked() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)

    def expire(connection: sa.Connection, execution_id: uuid.UUID) -> None:
        connection.execute(
            sa.update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(context_exp=sa.func.now() - timedelta(seconds=1))
        )

    svc = blocked_marker(w, expire)
    cancel_during_marker(svc, w)
    row = only_execution()
    assert row["status"] == "released" and row["dispatched_at"] is None
    assert usage("client", CLIENT) == (0, 0) and occupied() == 0


def test_a_failed_or_cancelled_marker_after_cancellation_settles_nothing() -> None:
    svc = service()

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        failed: asyncio.Future[Any] = loop.create_future()
        failed.set_exception(RuntimeError("database gone"))
        cancelled: asyncio.Future[Any] = loop.create_future()
        cancelled.cancel()
        for future in (failed, cancelled):
            svc._after_cancelled_mark(uuid.uuid4(), future)
        assert not svc._detached

    run(scenario())


def test_closing_a_row_with_no_reserved_units_returns_only_its_slot() -> None:
    from ai_gateway.db_models._common import ExecutionStatus
    from ai_gateway.db_models.accounting import ai_client_occupancy

    with as_owner() as c:
        world_rows = factories.resolved_world(c)
        execution_id = factories.execution(c, world_rows, ocr=True)
        c.execute(
            sa.insert(ai_client_occupancy).values(client_id="media-service", occupied=1)
        )
    with deps.db_engine.begin() as connection:
        moved = settlement.close(
            connection,
            ai_execution.c.id == execution_id,
            status=ExecutionStatus.ABANDONED,
            error=AiErrorCode.TIMEOUT,
        )
    assert moved == [execution_id]
    assert status_of(execution_id) == "abandoned" and occupied() == 0

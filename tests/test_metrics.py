"""
The C-13 collectors (T33): what each counts, and the label allowlist.

The allowlist test fails on any metric family or label the gateway adds
without naming it in :func:`~ai_gateway.core.metrics.label_allowlist`, so a
high-cardinality or content label cannot slip in.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import replace
from typing import Any

import pytest
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass, ProviderUsage
from ai_sdk_m8.schemas.management import ProviderType
from ai_sdk_m8.schemas import ProviderBoundary
from prometheus_client import REGISTRY
from prometheus_client.parser import text_string_to_metric_families

from ai_gateway.core import metrics
from ai_gateway.core.errors import GatewayError
from ai_gateway.providers.base import EmbedOutput
from ai_gateway.providers.breaker import Breakers, BreakerState
from ai_gateway.providers.errors import ProviderFailure
from execution_world import (
    OPEN,
    TENANT_A,
    USER_A,
    HookedStore,
    StubAdapter,
    embed_job,
    principal,
    run,
    service,
    world,
)
from fastapi_m8 import render_metrics

pytestmark = pytest.mark.usefixtures("clean_db")

CANARY = "sk-canary-" + "Zq7" * 12


def sample(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def delta(name: str, before: float, **labels: str) -> float:
    return sample(name, **labels) - before


def test_a_settled_embedding_is_counted_by_capability_provider_and_outcome() -> None:
    w = world()
    labels = {"capability": "embedding", "provider_type": "ollama"}
    requests = sample("ai_requests_total", status="ok", **labels)
    seconds = sample("ai_request_duration_seconds_count", **labels)
    inputs = sample("ai_embedding_inputs_total")
    tokens = sample("ai_tokens_total", direction="input")
    run(service(StubAdapter()).run(principal(w.profile_key), embed_job(w.profile_key)))
    assert delta("ai_requests_total", requests, status="ok", **labels) == 1
    assert delta("ai_request_duration_seconds_count", seconds, **labels) == 1
    assert delta("ai_embedding_inputs_total", inputs) == 2
    assert delta("ai_tokens_total", tokens, direction="input") == 2
    assert sample("ai_breaker_state", provider_type="ollama") == 0


def test_provider_usage_feeds_tokens_and_pages() -> None:
    w = world()
    out_tokens = sample("ai_tokens_total", direction="output")
    pages = sample("ai_ocr_pages_total")

    def behave(call: Any, capability: Capability) -> Any:
        return EmbedOutput(
            [[1.0] * (call.model.dimensions or 0)],
            ProviderUsage(input_tokens=4, output_tokens=7, pages_processed=3),
        )

    adapter = StubAdapter(behave=behave)
    run(service(adapter).run(principal(w.profile_key), embed_job(w.profile_key, ["a"])))
    assert delta("ai_tokens_total", out_tokens, direction="output") == 7
    assert delta("ai_ocr_pages_total", pages) == 3


def test_a_provider_answer_error_is_counted_by_closed_reason() -> None:
    w = world()
    errors = sample(
        "ai_provider_errors_total", provider_type="ollama", reason="rate_limited"
    )
    throttled = sample("ai_credential_throttled_total", provider_type="ollama")
    adapter = StubAdapter(
        behave=lambda _c, _k: (_ for _ in ()).throw(
            ProviderFailure(AiErrorCode.RATE_LIMITED, status_class="4xx")  # type: ignore[arg-type]
        )
    )
    with pytest.raises(GatewayError):
        run(service(adapter).run(principal(w.profile_key), embed_job(w.profile_key)))
    got = sample(
        "ai_provider_errors_total", provider_type="ollama", reason="rate_limited"
    )
    assert got - errors == 1
    assert (
        delta("ai_credential_throttled_total", throttled, provider_type="ollama") == 0
    )


def test_a_provider_429_with_a_credential_counts_the_throttle() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    throttled = sample(
        "ai_credential_throttled_total", provider_type="openai_compatible"
    )
    adapter = StubAdapter(
        provider_type=ProviderType.OPENAI_COMPATIBLE,
        behave=lambda _c, _k: (_ for _ in ()).throw(
            ProviderFailure(AiErrorCode.RATE_LIMITED, retry_after_seconds=1)
        ),
    )
    ctx = principal(w.profile_key, data_class=DataClass.PUBLIC)
    with pytest.raises(GatewayError):
        run(service(adapter).run(ctx, embed_job(w.profile_key)))
    after = sample("ai_credential_throttled_total", provider_type="openai_compatible")
    assert after - throttled == 1


def test_credential_resolution_is_counted_by_backend_and_outcome() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    adapter = StubAdapter(provider_type=ProviderType.OPENAI_COMPATIBLE)
    store = HookedStore()
    backend = store.backend
    ok = sample("ai_credential_resolution_total", backend=backend, status="ok")
    failed = sample("ai_credential_resolution_total", backend=backend, status="failed")
    run(
        service(adapter, store=store).run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key),
        )
    )
    assert (
        delta("ai_credential_resolution_total", ok, backend=backend, status="ok") == 1
    )

    def broken(_cid: uuid.UUID, _ver: int) -> None:
        raise RuntimeError("store down")

    with pytest.raises(GatewayError):
        run(
            service(adapter, store=HookedStore(broken)).run(
                principal(w.profile_key, data_class=DataClass.PUBLIC),
                embed_job(w.profile_key),
            )
        )
    got = delta(
        "ai_credential_resolution_total", failed, backend=backend, status="failed"
    )
    assert got == 1


def test_a_budget_refusal_is_counted_by_scope_type() -> None:
    w = world()
    before = sample("ai_quota_rejections_total", scope_type="user")
    svc = service(StubAdapter(), limits=replace(OPEN, user_daily_units=1))
    ctx = principal(w.profile_key, tenant_id=TENANT_A, user_id=USER_A)
    with pytest.raises(GatewayError) as caught:
        run(svc.run(ctx, embed_job(w.profile_key, ["too long for one unit"])))
    assert caught.value.code is AiErrorCode.QUOTA_EXCEEDED
    assert delta("ai_quota_rejections_total", before, scope_type="user") == 1
    # The refusal happened before a provider was chosen.
    assert (
        sample(
            "ai_requests_total",
            capability="embedding",
            provider_type="none",
            status="quota_exceeded",
        )
        >= 1
    )


def test_an_open_breaker_is_exported_as_its_state() -> None:
    w = world()
    breakers = Breakers()
    breaker = breakers.for_provider(w.provider_id)
    for _ in range(5):
        breaker.failure()
    with pytest.raises(GatewayError):
        run(
            service(StubAdapter(), breakers=breakers).run(
                principal(w.profile_key), embed_job(w.profile_key)
            )
        )
    assert sample("ai_breaker_state", provider_type="ollama") == 2
    metrics.publish_breaker("ollama", BreakerState.HALF_OPEN)
    assert sample("ai_breaker_state", provider_type="ollama") == 1
    metrics.publish_breaker("ollama", BreakerState.CLOSED)


def test_a_cancelled_or_crashed_request_is_counted_as_an_error() -> None:
    w = world()
    adapter = StubAdapter(behave=lambda _c, _k: (_ for _ in ()).throw(ValueError("x")))
    before = sample(
        "ai_requests_total",
        capability="embedding",
        provider_type="ollama",
        status="error",
    )
    with pytest.raises(ValueError):
        run(service(adapter).run(principal(w.profile_key), embed_job(w.profile_key)))
    after = sample(
        "ai_requests_total",
        capability="embedding",
        provider_type="ollama",
        status="error",
    )
    assert after - before == 1


def test_every_settlement_is_one_structured_audit_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    w = world()
    with caplog.at_level(logging.INFO, logger="ai_gateway.audit"):
        done = run(
            service(StubAdapter()).run(
                principal(w.profile_key), embed_job(w.profile_key)
            )
        )
    lines = [
        json.loads(r.getMessage().removeprefix("audit "))
        for r in caplog.records
        if '"trail": "execution"' in r.getMessage()
    ]
    (line,) = lines
    assert line["execution_id"] == str(done.execution.execution_id)
    assert line["status"] == "ok" and line["units"] == done.execution.units
    assert set(line) == {
        "trail",
        "execution_id",
        "status",
        "error_class",
        "units",
        "reservation_day",
    }


_SUFFIX = re.compile(r"_(total|created|bucket|count|sum)$")


def test_the_exposition_carries_only_allowlisted_families_and_labels() -> None:
    w = world(boundary=ProviderBoundary.EXTERNAL)
    # Material that must never surface: a canary credential and a canary input.
    run(
        service(
            StubAdapter(provider_type=ProviderType.OPENAI_COMPATIBLE),
        ).run(
            principal(w.profile_key, data_class=DataClass.PUBLIC),
            embed_job(w.profile_key, [CANARY]),
        )
    )
    text = render_metrics()[0].decode()
    assert CANARY not in text
    allowed = metrics.label_allowlist()
    seen: set[str] = set()
    for family in text_string_to_metric_families(text):
        if not family.name.startswith("ai_"):
            continue
        assert family.name in allowed, f"unlisted metric family {family.name}"
        seen.add(family.name)
        for s in family.samples:
            labels = set(s.labels) - {"le"}
            assert labels <= allowed[family.name], (family.name, labels)
    # Every C-13 collector is registered (it renders even with no sample).
    registered = {
        _SUFFIX.sub("", name)
        for name in REGISTRY._names_to_collectors  # noqa: SLF001
        if name.startswith("ai_")
    }
    assert registered <= set(allowed)
    assert set(allowed) <= registered | {"ai_requests", "ai_request_duration_seconds"}

"""
Credential validation (T25): ``POST …/credentials/{id}:validate`` through the app.

The validator's client factory is pointed at an in-process provider, so each
probe is the real D-20 client and the real adapter ``probe`` against scripted
answers. Only ``401``/``403`` counts; three in a row is ``invalid``; a
success resets the count in the same statement; nothing else changes it.
"""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from ai_gateway import main
from ai_gateway.app.routes import credentials as credential_routes
from ai_gateway.controllers import ratelimit
from ai_gateway.core import deps
from ai_gateway.db_models.audit import ai_credential_audit
from ai_gateway.db_models.registry import ai_provider
from ai_gateway.providers.breaker import Breakers, BreakerState
from execution_world import clients, rotate
from test_credentials import (
    ADMIN_A,
    CANARY,
    GLOBAL_BASE,
    ME,
    OTHER_KEY,
    SU,
    TENANT_A_BASE,
    TENANT_B_BASE,
    WRITER_A,
    _ok,
    created,
    provider,
    set_status,
    verb,
)

pytestmark = pytest.mark.usefixtures("clean_db")

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


class Provider:
    """Answers the probes from a script; records what it was sent."""

    def __init__(self, *answers: int | type[Exception] | Handler) -> None:
        self.answers = list(answers)
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, type):
            raise answer("scripted", request=request)  # type: ignore[call-arg]
        if callable(answer):
            return answer(request)
        return httpx.Response(answer, stream=httpx.ByteStream(b'{"data": []}'))


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Provider]:
    def install(*answers: Any, breakers: Breakers | None = None) -> Provider:
        scripted = Provider(*answers)
        factory = clients(
            transport=lambda _e: httpx.MockTransport(scripted), breakers=breakers
        )
        monkeypatch.setattr(deps.credential_validator, "_clients", factory)
        return scripted

    return install


def validate(client: TestClient, credential_id: str, base: str = TENANT_A_BASE) -> Any:
    return verb(
        client,
        base,
        credential_id,
        "validate",
        ADMIN_A if base == TENANT_A_BASE else SU,
    )


def key(client: TestClient, **overrides: object) -> dict[str, Any]:
    return created(client, TENANT_A_BASE, ADMIN_A, provider(client, **overrides))


def audits(credential_id: str) -> list[dict[str, Any]]:
    with deps.db_engine.connect() as c:
        rows = c.execute(
            select(ai_credential_audit.c.metadata)
            .where(
                ai_credential_audit.c.credential_id == uuid.UUID(credential_id),
                ai_credential_audit.c.action == "credential.validate",
            )
            .order_by(ai_credential_audit.c.id)
        ).scalars()
        return list(rows)


def test_three_consecutive_auth_failures_make_a_key_invalid(
    client: TestClient, stub: Any
) -> None:
    breakers = Breakers()
    scripted = stub(401, 403, 401, breakers=breakers)
    k = key(client)
    seen = [_ok(validate(client, k["id"])) for _ in range(3)]
    assert [s["outcome"] for s in seen] == ["auth_failed"] * 3
    assert [s["credential"]["auth_failure_count"] for s in seen] == [1, 2, 3]
    assert [s["credential"]["status"] for s in seen] == ["active", "active", "invalid"]
    # A 401/403 never feeds the provider's breaker.
    assert (
        breakers.for_provider(uuid.UUID(k["provider_id"])).state is BreakerState.CLOSED
    )
    # The probe used the current version, on the documented route.
    assert {r.url.path for r in scripted.requests} == {"/v1/models"}
    assert scripted.requests[0].headers["authorization"] == f"Bearer {CANARY}"
    # Once invalid, nothing more is probed: a rotation revives it.
    assert validate(client, k["id"]).status_code == 409
    rows = audits(k["id"])
    assert [r["outcome"] for r in rows] == ["auth_failed"] * 3
    assert rows[-1]["status"] == {"before": "active", "after": "invalid"}
    assert rows[-1]["auth_failure_count"] == {"before": 2, "after": 3}


def test_a_success_resets_the_count(client: TestClient, stub: Any) -> None:
    stub(401, 200, 401, 401)
    k = key(client)
    seen = [_ok(validate(client, k["id"])) for _ in range(4)]
    assert [s["outcome"] for s in seen] == [
        "auth_failed",
        "valid",
        "auth_failed",
        "auth_failed",
    ]
    assert [s["credential"]["auth_failure_count"] for s in seen] == [1, 0, 1, 2]
    assert seen[-1]["credential"]["status"] == "active"


@pytest.mark.parametrize(
    "answer",
    [httpx.ReadTimeout, httpx.ConnectError, 500, 503, 429, 404],
    ids=["timeout", "connect", "500", "503", "429", "404"],
)
def test_anything_but_an_auth_failure_is_inconclusive(
    client: TestClient, stub: Any, answer: Any
) -> None:
    stub(401, answer)
    k = key(client)
    first = _ok(validate(client, k["id"]))
    assert first["credential"]["auth_failure_count"] == 1
    for _ in range(3):
        seen = _ok(validate(client, k["id"]))
        assert seen["outcome"] == "inconclusive"
        assert seen["credential"]["auth_failure_count"] == 1
        assert seen["credential"]["status"] == "active"
    assert audits(k["id"])[-1]["applied"] is False


def test_ten_timeouts_leave_a_key_active(client: TestClient, stub: Any) -> None:
    stub(httpx.ReadTimeout)
    k = key(client)
    for _ in range(10):
        assert _ok(validate(client, k["id"]))["outcome"] == "inconclusive"
    assert (
        _ok(client.get(f"{TENANT_A_BASE}/credentials/{k['id']}", headers=ADMIN_A))[
            "status"
        ]
        == "active"
    )


def test_an_open_breaker_is_inconclusive(client: TestClient, stub: Any) -> None:
    breakers = Breakers()
    scripted = stub(200, breakers=breakers)
    k = key(client)
    breaker = breakers.for_provider(uuid.UUID(k["provider_id"]))
    while breaker.state is not BreakerState.OPEN:
        breaker.failure()
    seen = _ok(validate(client, k["id"]))
    assert seen["outcome"] == "inconclusive" and scripted.requests == []
    assert audits(k["id"])[-1]["error"] == "breaker_open"


def test_a_store_outage_is_inconclusive(
    client: TestClient, stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sdk_m8.schemas import AiErrorCode

    from ai_gateway.core.errors import GatewayError

    scripted = stub(401)
    k = key(client)

    class Down:
        def resolve_for_execution(self, *_args: Any) -> Any:
            raise GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE)

    monkeypatch.setattr(deps.credential_validator, "_store", Down())
    seen = _ok(validate(client, k["id"]))
    assert seen["outcome"] == "inconclusive" and scripted.requests == []
    assert seen["credential"]["auth_failure_count"] == 0


def test_a_provider_without_a_probe_is_inconclusive(
    client: TestClient, stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub(200)
    k = key(client)
    monkeypatch.setattr(deps.credential_validator, "_adapters", {})
    seen = _ok(validate(client, k["id"]))
    assert seen["outcome"] == "inconclusive"
    assert audits(k["id"])[-1]["error"] == "capability_unsupported"


def test_a_rotation_during_the_probe_is_not_charged_to_the_new_key(
    client: TestClient, stub: Any
) -> None:
    k = key(client)

    def rotating(_request: httpx.Request) -> httpx.Response:
        rotate(uuid.UUID(k["id"]), OTHER_KEY)
        return httpx.Response(401, stream=httpx.ByteStream(b""))

    stub(rotating)
    seen = _ok(validate(client, k["id"]))
    assert seen["outcome"] == "auth_failed"
    assert seen["credential"]["auth_failure_count"] == 0
    assert seen["credential"]["current_version"] == 2
    assert audits(k["id"])[-1]["applied"] is False


def test_a_success_stamps_the_validation_and_the_providers_first_use(
    client: TestClient, stub: Any
) -> None:
    stub(200)
    k = key(client, provider_type="openai_compatible", name="vllm")
    # A credential's create already stamps it; clear it as if never used.
    from ocr_world import _superuser

    with _superuser() as c:
        c.execute(
            ai_provider.update()
            .where(ai_provider.c.id == uuid.UUID(k["provider_id"]))
            .values(first_used_at=None)
        )
    seen = _ok(validate(client, k["id"]))
    assert seen["outcome"] == "valid"
    with deps.db_engine.connect() as c:
        first_used = c.execute(
            select(ai_provider.c.first_used_at).where(
                ai_provider.c.id == uuid.UUID(k["provider_id"])
            )
        ).scalar_one()
    assert first_used is not None
    from ai_gateway.db_models.credentials import ai_credential

    with deps.db_engine.connect() as c:
        stamped = c.execute(
            select(ai_credential.c.last_validated_at).where(
                ai_credential.c.id == uuid.UUID(k["id"])
            )
        ).scalar_one()
    assert stamped is not None


def test_the_probe_never_logs_a_header_or_the_secret(
    client: TestClient, stub: Any, caplog: pytest.LogCaptureFixture
) -> None:
    stub(401, 200)
    caplog.set_level(logging.DEBUG)
    k = key(client)
    _ok(validate(client, k["id"]))
    _ok(validate(client, k["id"]))
    assert CANARY not in caplog.text and "authorization" not in caplog.text.lower()
    for row in audits(k["id"]):
        assert CANARY not in str(row)


def test_only_an_active_key_in_scope_can_be_validated(
    client: TestClient, stub: Any
) -> None:
    stub(200)
    k = key(client)
    assert validate(client, k["id"], TENANT_B_BASE).status_code == 404
    assert validate(client, str(uuid.uuid4())).status_code == 404
    for status in ("disabled", "reconfirm_required"):
        set_status(k["id"], status)
        assert validate(client, k["id"]).status_code == 409


def test_the_platform_and_user_scopes_are_served(client: TestClient, stub: Any) -> None:
    from ai_gateway.core.config import settings

    stub(200)
    p = provider(client)
    platform = created(client, GLOBAL_BASE, SU, p)
    assert _ok(validate(client, platform["id"], GLOBAL_BASE))["outcome"] == "valid"
    assert settings.AI_USER_BYOK_ENABLED is not True
    assert verb(client, ME, str(uuid.uuid4()), "validate", WRITER_A).status_code == 403


def test_validations_are_rate_limited_per_subject(
    client: TestClient, stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        credential_routes,
        "charge_credential_write",
        functools.partial(ratelimit.charge_credential_write, limit=2),
    )
    stub(200)
    k = key(client)  # the create spends one
    _ok(validate(client, k["id"]))
    limited = validate(client, k["id"])
    assert limited.status_code == 429 and "retry-after" in limited.headers

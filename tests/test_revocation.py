"""Configured revocation behaviour: stateful mode against the issuer's API.

A second ``AuthDeps`` is built from the gateway's own ``Settings`` with the
stateful profile the shipped ``.env.example`` sets (issuer revocation API,
``fail_closed``). The issuer is never contacted: its HTTP reply is substituted
at the transport, so the real fastapi-m8 revocation client parses it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from ai_gateway.core.config import Settings
from conftest import bearer
from fastapi_m8 import build_auth_deps

INTROSPECTION_URL = "http://issuer.test.invalid/user/private/v1/jti-status"
SUBJECT = uuid.UUID("00000000-0000-0000-0000-0000000000a3")


def _reply(body: dict[str, Any]) -> Any:
    async def _post(self: httpx.AsyncClient, url: str, **_kw: Any) -> httpx.Response:
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))

    return _post


async def _unreachable(self: httpx.AsyncClient, url: str, **_kw: Any) -> httpx.Response:
    raise httpx.ConnectError("issuer unreachable", request=httpx.Request("POST", url))


@pytest.fixture
def client() -> Iterator[TestClient]:
    stateful = Settings(  # type: ignore[call-arg]
        _env_file=None,
        TOKEN_MODE="stateful",
        INTROSPECTION_URL=INTROSPECTION_URL,
        PRIVATE_API_SECRET="GatewayTests-PrivateApi-ai8gw-Ab12Cd",
        ACCESS_REVOCATION_FAILURE_MODE="fail_closed",
    )
    auth = build_auth_deps(stateful)
    app = FastAPI()

    @app.get("/writer", dependencies=[Depends(auth.get_current_active_writer)])
    def writer() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as test_client:
        yield test_client


def test_an_active_session_is_accepted(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = {
        "schema_version": "2",
        "active": True,
        "user_id": str(SUBJECT),
        "auth_generation": 1,
    }
    monkeypatch.setattr(httpx.AsyncClient, "post", _reply(body))
    response = client.get("/writer", headers=bearer("writer", subject=SUBJECT))
    assert response.status_code == 200


def test_a_revoked_session_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _reply({"schema_version": "2", "active": False})
    )
    response = client.get("/writer", headers=bearer("writer", subject=SUBJECT))
    assert response.status_code == 403


def test_an_unreachable_issuer_fails_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(httpx.AsyncClient, "post", _unreachable)
    response = client.get("/writer", headers=bearer("writer", subject=SUBJECT))
    assert response.status_code == 503

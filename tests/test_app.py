"""Application factory wiring, health, metrics and lifecycle teardown."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine

from ai_gateway import __version__, main
from ai_gateway.core import deps
from ai_gateway.core.config import settings

PREFIX = settings.API_PREFIX


@contextmanager
def _sqlite_session() -> Iterator[Session]:
    with Session(create_engine("sqlite://")) as session:
        yield session


def test_meta_serves_the_service_and_contract_versions() -> None:
    with TestClient(main.app) as client:
        body = client.get(f"{PREFIX}/meta").json()
    assert body["version"] == __version__
    assert body["contract"]["version"] == "1.0"
    assert body["contract"]["range"] == ">=1.0.0 <2.0.0"


def test_anonymous_health_reveals_no_check_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken() -> Any:
        raise OSError("connection refused by 10.0.0.1 password=hunter2")

    monkeypatch.setattr(deps.engine, "session", _broken)
    with TestClient(main.app) as client:
        response = client.get(f"{PREFIX}/health")
    assert response.json() == {"status": "ok"}
    assert "10.0.0.1" not in response.text


def test_check_db_reports_the_failure_without_its_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken() -> Any:
        raise OSError("connection refused by 10.0.0.1 password=hunter2")

    monkeypatch.setattr(deps.engine, "session", _broken)
    result = asyncio.run(main.check_db())
    assert result.error == "OSError"


def test_check_db_passes_on_a_reachable_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deps.engine, "session", _sqlite_session)
    result = asyncio.run(main.check_db())
    assert result.error is None
    assert result.name == "database"


def test_lifecycle_tears_down_the_auth_deps_and_the_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    real_close = deps.auth.close

    async def _close() -> None:
        calls.append("auth")
        await real_close()

    # AuthDeps is a frozen dataclass: patch its class for this test only.
    monkeypatch.setattr(type(deps.auth), "close", lambda self: _close())
    monkeypatch.setattr(deps.engine, "dispose", lambda: calls.append("engine"))
    with TestClient(main.app):
        assert calls == []
    assert calls == ["auth", "engine"]


def test_the_metrics_endpoint_is_absent_when_disabled() -> None:
    router = APIRouter()
    main._register_metrics_endpoint(router, enabled=False)
    assert router.routes == []


def test_the_metrics_endpoint_requires_its_credential() -> None:
    router = APIRouter()
    main._register_metrics_endpoint(router, enabled=True, credential="scrape-cred")
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 401
        ok = client.get("/metrics", headers={"Authorization": "Bearer scrape-cred"})
    assert ok.status_code == 200


def test_no_api_key_principal_is_wired() -> None:
    assert deps.auth.get_current_api_key_writer is None

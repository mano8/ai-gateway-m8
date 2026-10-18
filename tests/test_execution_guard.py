"""Execution routes never accept a user JWT and fail closed until verified."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from ai_gateway.app.routes import execution
from ai_gateway.core.execution_guard import (
    CONTEXT_INVALID,
    JOB_CONTEXT_HEADER,
    build_execution_router,
    require_job_context,
)
from ai_gateway.core.config import settings
from ai_gateway.main import app as gateway_app
from conftest import bearer


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    router = build_execution_router(prefix="/v1")
    router.add_api_route("/embed", lambda: {"ok": True}, methods=["POST"])
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("role", ["writer", "superadmin"])
def test_a_jwt_only_request_is_refused(client: TestClient, role: str) -> None:
    response = client.post("/v1/embed", headers=bearer(role))
    assert response.status_code == 401
    assert response.json() == {"detail": {"code": CONTEXT_INVALID}}


def test_a_request_with_a_context_is_still_refused(client: TestClient) -> None:
    headers = {
        JOB_CONTEXT_HEADER: "eyJ2IjoxfQ.c2ln",
        "X-Internal-Client": "media-service",
        "X-Internal-Token": "not-verifiable-yet",
        **bearer("superadmin"),
    }
    response = client.post("/v1/embed", headers=headers)
    assert response.status_code == 401
    assert "eyJ2IjoxfQ" not in response.text


def test_an_anonymous_request_is_refused(client: TestClient) -> None:
    assert client.post("/v1/embed").status_code == 401


def test_the_guard_cannot_be_replaced() -> None:
    with pytest.raises(TypeError):
        build_execution_router(dependencies=[])


def test_the_shipped_execution_router_carries_the_guard() -> None:
    calls = [d.dependency for d in execution.router.dependencies]
    assert calls == [require_job_context]


def test_every_gateway_execution_route_depends_on_the_guard() -> None:
    prefix = f"{settings.API_PREFIX}{execution.router.prefix}"
    for route in gateway_app.routes:
        if isinstance(route, APIRoute) and route.path.startswith(prefix):
            calls = [d.call for d in route.dependant.dependencies]
            assert require_job_context in calls, route.path

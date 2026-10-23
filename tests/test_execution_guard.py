"""Execution routes never accept a user JWT; each route's capability is declared."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from ai_sdk_m8.client import routes
from ai_sdk_m8.schemas import Capability
from fastapi import FastAPI
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient

from ai_gateway.app.routes import execution
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError, gateway_error_handler
from ai_gateway.core.execution_guard import (
    SERVICE_CLIENT_SCHEME,
    JOB_CONTEXT_HEADER,
    ROUTE_CAPABILITIES,
    build_execution_router,
    require_clock_within_bound,
    require_job_context,
)
from ai_gateway.main import app as gateway_app
from conftest import MEDIA_SERVICE, bearer
from job_contexts import mint

PREFIX = "/ai/v1/execute"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    router = build_execution_router(prefix=PREFIX)
    router.add_api_route("/embed", lambda: {"ok": True}, methods=["POST"])
    # A route the SDK route table does not declare.
    router.add_api_route("/chat", lambda: {"ok": True}, methods=["POST"])
    app = FastAPI()
    app.add_exception_handler(GatewayError, gateway_error_handler)
    app.include_router(router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("role", ["writer", "superadmin"])
def test_a_jwt_only_request_is_refused(client: TestClient, role: str) -> None:
    response = client.post(f"{PREFIX}/embed", headers=bearer(role))
    assert response.status_code == 401
    assert response.json()["code"] == "unauthorized"


def test_a_jwt_beside_a_service_client_is_never_read(client: TestClient) -> None:
    headers = {**MEDIA_SERVICE.headers(), **bearer("superadmin")}
    response = client.post(f"{PREFIX}/embed", headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "context_missing"


def test_an_anonymous_request_is_refused(client: TestClient) -> None:
    response = client.post(f"{PREFIX}/embed")
    assert response.status_code == 401
    assert response.json()["code"] == "unauthorized"


def test_an_undeclared_route_is_refused_whatever_it_carries(
    client: TestClient,
) -> None:
    headers = {**MEDIA_SERVICE.headers(), JOB_CONTEXT_HEADER: mint()}
    response = client.post(f"{PREFIX}/chat", headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "context_invalid"


def test_the_guard_cannot_be_replaced() -> None:
    with pytest.raises(TypeError):
        build_execution_router(dependencies=[])


def test_the_shipped_execution_router_carries_the_guard() -> None:
    calls = [d.dependency for d in execution.router.dependencies]
    assert calls == [
        require_clock_within_bound,
        require_job_context,
        SERVICE_CLIENT_SCHEME,
    ]


def test_the_ocr_router_answers_its_gate_first() -> None:
    from ai_gateway.app.routes import ocr

    calls = [d.dependency for d in ocr.router.dependencies]
    assert calls[:3] == [
        ocr.require_ocr_enabled,
        require_clock_within_bound,
        require_job_context,
    ]


def test_execution_routes_document_only_the_service_client_scheme() -> None:
    spec = gateway_app.openapi()
    scheme = spec["components"]["securitySchemes"]["ServiceClient"]
    assert scheme["type"] == "apiKey" and scheme["in"] == "header"
    assert scheme["name"] == "X-Internal-Client"
    assert JOB_CONTEXT_HEADER in scheme["description"]
    for path, operations in spec["paths"].items():
        if "/v1/execute/" in path:
            for operation in operations.values():
                assert operation["security"] == [{"ServiceClient": []}], path


def test_the_shipped_router_serves_the_sdk_execution_prefix() -> None:
    assert execution.router.prefix == "/v1/execute"
    for route in (
        routes.EXECUTE_OCR,
        routes.EXECUTE_OCR_DISPATCH,
        routes.EXECUTE_EMBED,
        routes.EXECUTE_RERANK,
        routes.EXECUTE_STRUCTURED_OUTPUT,
    ):
        assert route.path.startswith(execution.router.prefix.lstrip("/"))


def test_every_sdk_execution_route_has_a_capability() -> None:
    execution_paths = {
        r.path for r in routes.all_routes() if r.path.startswith("v1/execute/")
    }
    assert set(ROUTE_CAPABILITIES) == execution_paths
    assert ROUTE_CAPABILITIES[routes.EXECUTE_OCR_DISPATCH.path] is Capability.OCR
    assert set(ROUTE_CAPABILITIES.values()) == {
        Capability.OCR,
        Capability.EMBEDDING,
        Capability.RERANK,
        Capability.STRUCTURED_OUTPUT,
    }


def test_every_gateway_execution_route_depends_on_the_guard() -> None:
    # Included routers are not flattened into app.routes (FastAPI 0.143);
    # iter_route_contexts yields each effective route with its full path and
    # its router-level dependencies.
    prefix = f"{settings.API_PREFIX}{execution.router.prefix}"
    for route in iter_route_contexts(gateway_app.routes):
        if (route.path or "").startswith(prefix):
            calls = [d.call for d in route.dependant.dependencies]
            assert require_job_context in calls, route.path


def test_the_route_walk_sees_included_routers() -> None:
    paths = {route.path for route in iter_route_contexts(gateway_app.routes)}
    assert f"{settings.API_PREFIX}/v1/admin/providers" in paths

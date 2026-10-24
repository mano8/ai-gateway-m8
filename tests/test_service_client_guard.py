"""
The ``fastapi-m8`` service-client guard over the gateway's own registry.

``fastapi-m8`` 4.6.0 (``T12``) ships ``build_service_client_guard``; the gateway
binds it to ``AI_SERVICE_CLIENTS`` with capability scopes (``T17``). These tests
prove the published guard works with the registry the gateway parses, and that
the shipped lock carries the releases the requirement floors name.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from packaging.requirements import Requirement
from packaging.version import Version

from ai_gateway.core.service_clients import execute_scope, parse_service_clients
from ai_sdk_m8.schemas import Capability
from conftest import bearer
from fastapi_m8 import (
    INTERNAL_CLIENT_HEADER,
    INTERNAL_TOKEN_HEADER,
    ConsumerCredential,
    build_service_client_guard,
)

REQUIREMENTS = Path(__file__).resolve().parent.parent / "ai_gateway"
WORKER_SECRET = "w" * 64
SERVICE_SECRET = "s" * 64


def _registry_json() -> str:
    def entry(client_id: str, secret: str, scopes: list[str]) -> dict[str, object]:
        encoded = ConsumerCredential.create(client_id, secret).encoded_secret
        return {"secret": encoded, "scopes": scopes}

    return json.dumps(
        {
            "media-worker": entry(
                "media-worker", WORKER_SECRET, [execute_scope(Capability.OCR)]
            ),
            "media-service": entry(
                "media-service", SERVICE_SECRET, [execute_scope(Capability.EMBEDDING)]
            ),
        }
    )


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    registry = parse_service_clients(_registry_json()).registry
    guard = build_service_client_guard(
        registry, required_scopes={execute_scope(Capability.OCR)}
    )
    app = FastAPI()

    @app.post("/v1/execute/ocr")
    def ocr(client_id: str = Depends(guard)) -> dict[str, str]:
        return {"client_id": client_id}

    with TestClient(app) as test_client:
        yield test_client


def _headers(client_id: str, secret: str) -> dict[str, str]:
    return {INTERNAL_CLIENT_HEADER: client_id, INTERNAL_TOKEN_HEADER: secret}


def test_a_scoped_client_is_authenticated(client: TestClient) -> None:
    response = client.post(
        "/v1/execute/ocr", headers=_headers("media-worker", WORKER_SECRET)
    )
    assert response.status_code == 200
    assert response.json() == {"client_id": "media-worker"}


def test_missing_headers_are_refused(client: TestClient) -> None:
    assert client.post("/v1/execute/ocr").status_code == 401


def test_a_user_jwt_alone_is_refused(client: TestClient) -> None:
    assert client.post("/v1/execute/ocr", headers=bearer("writer")).status_code == 401


def test_unknown_client_and_wrong_secret_are_indistinguishable(
    client: TestClient,
) -> None:
    unknown = client.post("/v1/execute/ocr", headers=_headers("nobody", WORKER_SECRET))
    wrong = client.post("/v1/execute/ocr", headers=_headers("media-worker", "x" * 64))
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    assert WORKER_SECRET not in unknown.text
    assert "x" * 64 not in wrong.text


def test_an_authenticated_client_without_the_scope_is_forbidden(
    client: TestClient,
) -> None:
    response = client.post(
        "/v1/execute/ocr", headers=_headers("media-service", SERVICE_SECRET)
    )
    assert response.status_code == 403
    assert SERVICE_SECRET not in response.text


def _locked(name: str) -> Version:
    lock = (REQUIREMENTS / "requirements_prod.lock").read_text(encoding="utf-8")
    match = re.search(
        rf"^{re.escape(name)}(?:\[[^\]]*\])?==([^\s\\]+)", lock, re.MULTILINE
    )
    assert match, f"{name} is not pinned in requirements_prod.lock"
    return Version(match.group(1))


@pytest.mark.parametrize("name", ["fastapi-m8", "ai-sdk-m8"])
def test_the_lock_satisfies_the_platform_floor(name: str) -> None:
    lines = (REQUIREMENTS / "requirements_base.txt").read_text(encoding="utf-8")
    requirements = [
        Requirement(line)
        for line in lines.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    floor = next(r for r in requirements if r.name == name)
    assert _locked(name) in floor.specifier

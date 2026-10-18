"""Issuer JWT verification and management tier boundaries.

Nothing in the auth chain is overridden: tokens flow through the gateway's one
``build_auth_deps`` instance exactly as in a running stack. The routes are
built here because the scaffold ships no management route yet; they use the
tier dependencies the real routes will use.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from ai_gateway.app import deps
from conftest import TEST_AUDIENCE, TEST_ISSUER, bearer

TIERS = {
    "reader": deps.get_current_active_reader,
    "writer": deps.get_current_active_writer,
    "admin": deps.get_current_active_admin,
    "superuser": deps.get_current_active_superuser,
}

#: Expected status per (role, tier) — the fastapi-m8 tier table.
ALLOWED = {
    "user": set(),
    "reader": {"reader"},
    "writer": {"reader", "writer"},
    "admin": {"reader", "writer", "admin"},
    "superadmin": {"reader", "writer", "admin", "superuser"},
}


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    router = APIRouter()
    for tier, dependency in TIERS.items():
        router.add_api_route(
            f"/{tier}",
            lambda: {"ok": True},
            methods=["GET"],
            dependencies=[Depends(dependency)],
        )
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("role", sorted(ALLOWED))
@pytest.mark.parametrize("tier", sorted(TIERS))
def test_tier_boundaries(client: TestClient, role: str, tier: str) -> None:
    response = client.get(f"/{tier}", headers=bearer(role))
    assert response.status_code == (200 if tier in ALLOWED[role] else 403)


def test_a_valid_issuer_token_is_accepted(client: TestClient) -> None:
    assert client.get("/reader", headers=bearer("reader")).status_code == 200


@pytest.mark.parametrize(
    "token_kwargs",
    [
        {"issuer": "https://another-issuer.invalid"},
        {"audience": "another-service"},
        {"secret": "Not-The-Issuer-Key-ai8gw-Zz98Yy76Xx"},
        {"expires_in": timedelta(minutes=-1)},
    ],
    ids=["wrong-issuer", "wrong-audience", "bad-signature", "expired"],
)
def test_an_invalid_token_is_rejected(
    client: TestClient, token_kwargs: dict[str, object]
) -> None:
    # fastapi-m8 answers an unverifiable credential with 403 on every tier.
    response = client.get("/reader", headers=bearer("superadmin", **token_kwargs))
    assert response.status_code == 403
    assert response.json() == {"detail": "Could not validate credentials."}


def test_no_token_is_rejected(client: TestClient) -> None:
    assert client.get("/reader").status_code == 401


def test_the_test_tokens_bind_the_configured_boundary() -> None:
    from ai_gateway.core.config import settings

    assert settings.TOKEN_STRICT_VALIDATION is True
    assert settings.TOKEN_ISSUER == TEST_ISSUER
    assert settings.TOKEN_AUDIENCE == TEST_AUDIENCE

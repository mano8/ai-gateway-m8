"""
Every management route of the shipped app, walked.

The checks run over whatever management routes the gateway serves, so each
later route (credentials and bindings per scope, ``T20``/``T20a``) is held
to them as soon as it is registered:

* each route is in the ``ai-sdk-m8`` route table, and the table's routes the
  gateway serves so far are all registered;
* each route depends on exactly one tier: reader, writer, admin, superuser,
  or the ``profiles:read`` service client;
* an API-key presentation alone answers 401 on every route (no API-key
  dependency is wired, D-05);
* every superuser route refuses an ``ADMIN``, a ``WRITER`` and a ``USER``;
* every user-scope write route (``v1/me``) uses the fresh-revocation writer
  tier and refuses ``USER`` and ``READER`` (A-1).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Iterator

import pytest
from ai_sdk_m8.client import routes
from fastapi.dependencies.models import Dependant
from fastapi.routing import RouteContext, iter_route_contexts
from fastapi.testclient import TestClient

from ai_gateway import main
from ai_gateway.app.routes.profiles import require_profiles_client
from ai_gateway.core import deps
from ai_gateway.core.config import settings
from conftest import bearer

PREFIX = f"{settings.API_PREFIX}/"
EXECUTION = f"{settings.API_PREFIX}/v1/execute"

TIERS: dict[Callable[..., object], str] = {
    deps.get_current_active_reader: "reader",
    deps.get_current_active_writer: "writer",
    deps.get_current_active_admin: "admin",
    deps.get_current_active_superuser: "superuser",
    require_profiles_client: "service:profiles:read",
}

#: The route-table entries served since T18.
SERVED_SINCE_T18 = {
    routes.PROFILES,
    routes.PROFILE,
    routes.PROVIDERS_LIST,
    routes.PROVIDERS_CREATE,
    routes.PROVIDER_GET,
    routes.PROVIDER_UPDATE,
    routes.MODELS_LIST,
    routes.MODELS_CREATE,
    routes.MODEL_GET,
    routes.MODEL_UPDATE,
    routes.ADMIN_PROFILES_LIST,
    routes.ADMIN_PROFILES_CREATE,
    routes.ADMIN_PROFILE_GET,
    routes.ADMIN_PROFILE_UPDATE,
    routes.ADMIN_PROFILE_REVISIONS,
    *(
        routes.Route(r.method, r.path.replace("{scope}", routes.GLOBAL_SCOPE))
        for r in (
            routes.BINDINGS_LIST,
            routes.BINDINGS_CREATE,
            routes.BINDING_GET,
            routes.BINDING_UPDATE,
            routes.BINDING_DELETE,
        )
    ),
}


def _management_routes() -> list[tuple[str, RouteContext]]:
    """Every (method, effective route) under ``v1`` except execution."""
    found = []
    for route in iter_route_contexts(main.app.routes):
        path = route.path or ""
        if not path.startswith(PREFIX + "v1/") or path.startswith(EXECUTION):
            continue
        for method in sorted(route.methods or ()):
            found.append((method, route))
    return found


MANAGEMENT = _management_routes()


def _calls(dependant: Dependant) -> Iterator[Callable[..., object]]:
    for sub in dependant.dependencies:
        if sub.call is not None:
            yield sub.call
        yield from _calls(sub)


def _tiers(route: RouteContext) -> set[str]:
    return {TIERS[call] for call in _calls(route.dependant) if call in TIERS}


def _concrete(path: str | None) -> str:
    assert path is not None
    return re.sub(
        r"\{profile_key\}",
        "embed-default",
        re.sub(r"\{[a-z_]+_id\}", str(uuid.uuid4()), path),
    )


def _relative(route: RouteContext) -> str:
    return (route.path or "").removeprefix(PREFIX)


def _id(entry: tuple[str, RouteContext]) -> str:
    return f"{entry[0]} {_relative(entry[1])}"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


def test_every_management_route_is_in_the_sdk_route_table() -> None:
    table = set(routes.all_routes())
    served = {routes.Route(method, _relative(route)) for method, route in MANAGEMENT}
    assert served <= table, served - table
    assert SERVED_SINCE_T18 <= served, SERVED_SINCE_T18 - served


@pytest.mark.parametrize("entry", MANAGEMENT, ids=_id)
def test_every_management_route_has_exactly_one_tier(
    entry: tuple[str, RouteContext],
) -> None:
    assert len(_tiers(entry[1])) == 1, _tiers(entry[1])


@pytest.mark.parametrize("entry", MANAGEMENT, ids=_id)
def test_an_api_key_alone_is_401(
    client: TestClient, entry: tuple[str, RouteContext]
) -> None:
    method, route = entry
    response = client.request(
        method, _concrete(route.path), headers={"X-API-Key": "ak_" + "a" * 40}
    )
    assert response.status_code == 401


SUPERUSER_ROUTES = [e for e in MANAGEMENT if _tiers(e[1]) == {"superuser"}]


@pytest.mark.parametrize("entry", SUPERUSER_ROUTES, ids=_id)
@pytest.mark.parametrize("role", ["admin", "writer", "user"])
def test_superuser_routes_refuse_every_other_role(
    client: TestClient, entry: tuple[str, RouteContext], role: str
) -> None:
    method, route = entry
    response = client.request(method, _concrete(route.path), headers=bearer(role))
    assert response.status_code == 403


def test_every_admin_route_is_superuser_only() -> None:
    admin = [e for e in MANAGEMENT if _relative(e[1]).startswith("v1/admin/")]
    assert admin and all(_tiers(route) == {"superuser"} for _, route in admin)


def test_user_scope_writes_use_the_fresh_writer_tier(client: TestClient) -> None:
    writes = [
        (method, route)
        for method, route in MANAGEMENT
        if _relative(route).startswith("v1/me/") and method != "GET"
    ]
    for method, route in writes:
        assert _tiers(route) == {"writer"}, route.path
        for role in ("user", "reader"):
            response = client.request(
                method, _concrete(route.path), headers=bearer(role)
            )
            assert response.status_code == 403, (route.path, role)

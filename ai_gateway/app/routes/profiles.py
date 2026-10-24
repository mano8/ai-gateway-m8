"""
The published profiles: a reader JWT, or a ``profiles:read`` service client.

Media run-modes need a profile's space and identity metadata without a user
token (T18), so each route exists twice on the same path. The variant whose
route class matches only a request naming a service client
(``X-Internal-Client``) runs the ``fastapi-m8`` service-client guard with
``profiles:read``; every other request takes the reader tier on the
fresh-revocation path. Neither variant shows a credential, a provider or its
``base_url``.
"""

from __future__ import annotations

from typing import Annotated

from ai_sdk_m8.schemas import ProfilePublic
from ai_sdk_m8.schemas._base import ProfileKey
from fastapi import APIRouter, Depends, Path, Request
from fastapi.routing import APIRoute
from starlette.datastructures import Headers
from starlette.routing import Match
from starlette.types import Scope

from ai_gateway.controllers import registry
from ai_gateway.core.deps import CurrentReader, db_engine, profiles_read_guard
from ai_gateway.core.execution_guard import authenticate_service_client
from fastapi_m8 import INTERNAL_CLIENT_HEADER


class ServiceClientRoute(APIRoute):
    """A route that matches only a request naming a service client."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        """Match as usual, but only when ``X-Internal-Client`` is present."""
        match, child_scope = super().matches(scope)
        if match is not Match.NONE and INTERNAL_CLIENT_HEADER not in Headers(
            scope=scope
        ):
            return Match.NONE, {}
        return match, child_scope


def require_profiles_client(request: Request) -> str:
    """Authenticate a service client holding ``profiles:read``."""
    return authenticate_service_client(profiles_read_guard, request)


ProfilesClient = Annotated[str, Depends(require_profiles_client)]
ProfileKeyPath = Annotated[ProfileKey, Path()]

#: Tried first: requests that name a service client.
service_router = APIRouter(
    prefix="/profiles", route_class=ServiceClientRoute, include_in_schema=False
)
#: Every other request: the reader tier.
router = APIRouter(prefix="/profiles", tags=["profiles"])


def _list() -> list[ProfilePublic]:
    with db_engine.connect() as connection:
        return registry.list_public_profiles(connection)


def _get(profile_key: str) -> ProfilePublic:
    with db_engine.connect() as connection:
        return registry.get_public_profile(connection, profile_key)


@service_router.get("", response_model=list[ProfilePublic])
def list_profiles_for_service(_client: ProfilesClient) -> list[ProfilePublic]:
    """Every published profile, for a ``profiles:read`` client."""
    return _list()


@service_router.get("/{profile_key}", response_model=ProfilePublic)
def get_profile_for_service(
    profile_key: ProfileKeyPath, _client: ProfilesClient
) -> ProfilePublic:
    """One published profile, for a ``profiles:read`` client."""
    return _get(profile_key)


@router.get("", response_model=list[ProfilePublic])
def list_profiles(_user: CurrentReader) -> list[ProfilePublic]:
    """Every published profile."""
    return _list()


@router.get("/{profile_key}", response_model=ProfilePublic)
def get_profile(profile_key: ProfileKeyPath, _user: CurrentReader) -> ProfilePublic:
    """One published profile."""
    return _get(profile_key)

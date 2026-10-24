"""
The gateway's ``{API_PREFIX}/meta`` (D-03, D-08, D-23, T15).

``fastapi-m8`` mounts the fleet's fixed ``ServiceMeta`` route. The gateway
replaces it with a superset: the same four fleet fields plus a ``gateway``
block of non-secret values an operator or a caller checks against the
ratified configuration — the installation id, the user-BYOK flag, the two
context TTLs, the hash of the effective data-class policy, the enabled
capabilities, the storage backend and this replica's active key generations.
"""

from __future__ import annotations

from ai_sdk_m8.schemas.meta import GatewayMeta, GatewayMetaValues, ServiceContract
from fastapi import APIRouter, FastAPI, Response
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

from .config import Settings

#: ``Cache-Control`` of ``/meta``, as the fleet route sends it.
META_CACHE_CONTROL = "public, max-age=300"


def build_gateway_meta(settings: Settings) -> GatewayMeta:
    """The ``/meta`` body for ``settings``."""
    fleet = settings.build_service_meta()
    kek = settings.kek
    fingerprint = settings.fingerprint_key
    return GatewayMeta(
        service=fleet.service,
        version=fleet.version,
        api_version=fleet.api_version,
        contract=ServiceContract(
            name=fleet.contract.name,
            version=fleet.contract.version,
            range=fleet.contract.range,
        ),
        gateway=GatewayMetaValues(
            deployment_id=settings.deployment_id,
            user_byok_enabled=settings.user_byok_enabled,
            job_context_max_ttl_seconds=settings.AI_JOB_CONTEXT_MAX_TTL_SECONDS,
            dispatch_context_ttl_seconds=settings.AI_DISPATCH_CONTEXT_TTL_SECONDS,
            data_class_policy_sha256=settings.data_class_policy.sha256(),
            capabilities_enabled=tuple(sorted(settings.capabilities_enabled)),
            credential_storage_backend=settings.AI_CREDENTIAL_STORAGE_BACKEND,
            kek_key_version=kek.version("kek") if kek is not None else None,
            fingerprint_key_version=(
                fingerprint.version("fingerprint") if fingerprint is not None else None
            ),
        ),
    )


def _drop_route(routes: list[BaseRoute], path: str) -> None:
    """Remove every ``GET path`` route, including those of included routers."""
    routes[:] = [
        route
        for route in routes
        if not (isinstance(route, APIRoute) and route.path == path)
    ]
    for route in routes:
        # FastAPI keeps an included router's routes on its original router.
        original = getattr(route, "original_router", None)
        if isinstance(original, APIRouter):
            _drop_route(original.routes, path)


def install_gateway_meta(app: FastAPI, settings: Settings) -> None:
    """Replace the fleet ``/meta`` route with the gateway's superset."""
    path = f"{settings.API_PREFIX}/meta"
    _drop_route(app.router.routes, path)
    meta = build_gateway_meta(settings)

    def get_meta(response: Response) -> GatewayMeta:
        """Return the service identity and the gateway's reported values."""
        response.headers["Cache-Control"] = META_CACHE_CONTROL
        return meta

    app.add_api_route(
        path,
        get_meta,
        methods=["GET"],
        response_model=GatewayMeta,
        tags=["meta"],
    )
    # First match wins: keep the gateway route ahead of every included router.
    app.router.routes.insert(0, app.router.routes.pop())


__all__ = ["META_CACHE_CONTROL", "build_gateway_meta", "install_gateway_meta"]

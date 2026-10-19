"""
ai_gateway — ASGI entrypoint.

All wiring is handled by ``fastapi_m8.create_app``; this file only imports and
connects: the domain router, the health checks, the optional metrics
endpoint, the lifecycle (auth dependencies, database engine, auth event
stream, start-up assertions) and the gateway's own ``/meta`` and typed-error
handler.
"""

from fastapi import APIRouter, Depends, FastAPI
from fastapi.responses import Response
from sqlmodel import select

from fastapi_m8 import (
    AppLifecycle,
    HealthCheckResult,
    HealthConfig,
    HealthStatus,
    create_app,
    make_scrape_credential_guard,
    render_metrics,
)

from .app.main import api_router as domain_router
from .core.config import Settings, settings
from .core.deps import auth, clock, engine
from .core.errors import GatewayError, gateway_error_handler
from .core.events import make_lifespan_extras
from .core.meta import install_gateway_meta
from .core.spool_check import assert_local_spool


async def check_db() -> HealthCheckResult:
    """Check database reachability."""
    try:
        with engine.session() as s:
            s.exec(select(1))
        return HealthCheckResult.from_bool("database", True)
    except Exception as exc:
        return HealthCheckResult(
            name="database", status=HealthStatus.FAIL, error=type(exc).__name__
        )


async def check_spool_filesystem() -> None:
    """Start-up assertion: the OCR spool, when configured, is local (D-45)."""
    if settings.AI_OCR_SPOOL_DIR is not None:
        assert_local_spool(settings.AI_OCR_SPOOL_DIR)


def _metrics_response() -> Response:
    """Render the Prometheus exposition."""
    data, content_type = render_metrics()
    return Response(content=data, media_type=content_type)


def _register_metrics_endpoint(
    router: APIRouter, *, enabled: bool, credential: str | None = None
) -> None:
    """
    Expose Prometheus metrics under the API prefix when enabled.

    When ``credential`` is set, requests must present
    ``Authorization: Bearer <credential>`` (constant-time match) or receive
    ``401``. When unset the network boundary (internal entrypoint) is the sole
    control.
    """
    if not enabled:
        return

    guard = make_scrape_credential_guard(credential)
    router.add_api_route(
        "/metrics",
        _metrics_response,
        methods=["GET"],
        include_in_schema=False,
        dependencies=[Depends(guard)],
    )


def build_app(app_settings: Settings) -> FastAPI:
    """Wire the gateway application for ``app_settings``."""
    api_router = APIRouter(prefix=app_settings.API_PREFIX)
    api_router.include_router(domain_router)
    cred = app_settings.METRICS_SCRAPE_CREDENTIAL
    _register_metrics_endpoint(
        api_router,
        enabled=app_settings.METRICS_ENABLED,
        credential=cred.get_secret_value() if cred else None,
    )

    def configure(app: FastAPI) -> None:
        install_gateway_meta(app, app_settings)
        app.add_exception_handler(GatewayError, gateway_error_handler)

    return create_app(
        app_settings,
        api_router,
        service_name=app_settings.PROJECT_NAME,
        service_version=app_settings.SERVICE_VERSION,
        health=HealthConfig(checks=[check_db, clock.health_check]),
        lifecycle=AppLifecycle(
            auth_deps=auth,
            db_engine=engine,
            lifespan_extras=make_lifespan_extras(app_settings, auth),
            startup_validators=[check_spool_filesystem],
            configure=configure,
        ),
    )


app = build_app(settings)

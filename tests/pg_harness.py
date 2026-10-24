"""
PostgreSQL harness for the test suite.

The gateway is PostgreSQL-only and its invariants live in the database
(deferred foreign keys, triggers, the database clock, role privileges), so
the suite runs against a real server. ``AI_GATEWAY_TEST_PG_ADMIN_URL`` names
a superuser connection (CI starts a ``postgres`` service container); the
harness creates the two gateway roles and a fresh test database owned by
``ai_owner`` once per session. The application connects as ``ai_runtime``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Final

from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.engine import URL

if TYPE_CHECKING:
    from alembic.config import Config

ADMIN_URL: Final = make_url(
    os.environ.get(
        "AI_GATEWAY_TEST_PG_ADMIN_URL",
        "postgresql://postgres:postgres@127.0.0.1:5432/postgres",
    )
)
DB_NAME: Final = "ai_gateway_test"
OWNER: Final = "ai_owner"
OWNER_PASSWORD: Final = "GatewayTests_Own3r_Pw"  # noqa: S105 - test-only role
RUNTIME: Final = "ai_runtime"
RUNTIME_PASSWORD: Final = "GatewayTests_Passw0rd"  # noqa: S105 - test-only role


def _url(user: str, password: str, database: str = DB_NAME) -> URL:
    return ADMIN_URL.set(
        drivername="postgresql+psycopg2",
        username=user,
        password=password,
        database=database,
    )


def owner_url() -> URL:
    """Connection URL of the schema owner on the test database."""
    return _url(OWNER, OWNER_PASSWORD)


def runtime_url() -> URL:
    """Connection URL of the runtime role on the test database."""
    return _url(RUNTIME, RUNTIME_PASSWORD)


def admin_engine(database: str | None = None) -> Engine:
    """A superuser engine in autocommit mode."""
    url = ADMIN_URL.set(drivername="postgresql+psycopg2")
    if database is not None:
        url = url.set(database=database)
    return create_engine(url, isolation_level="AUTOCOMMIT")


def _ensure_role(admin: Engine, name: str, password: str) -> None:
    with admin.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": name}
        ).first()
        verb = "ALTER" if exists else "CREATE"
        # Role names are fixed constants, never input.
        connection.execute(
            text(
                f"{verb} ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "PASSWORD :password"
            ),
            {"password": password},
        )


def bootstrap_database() -> None:
    """Create both roles and a fresh, empty test database owned by ai_owner."""
    admin = admin_engine()
    try:
        _ensure_role(admin, OWNER, OWNER_PASSWORD)
        _ensure_role(admin, RUNTIME, RUNTIME_PASSWORD)
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": DB_NAME},
            )
            connection.execute(text(f"DROP DATABASE IF EXISTS {DB_NAME}"))
            connection.execute(text(f"CREATE DATABASE {DB_NAME} OWNER {OWNER}"))
            connection.execute(text(f"REVOKE ALL ON DATABASE {DB_NAME} FROM PUBLIC"))
            connection.execute(
                text(f"GRANT CONNECT ON DATABASE {DB_NAME} TO {OWNER}, {RUNTIME}")
            )
    finally:
        admin.dispose()
    on_db = admin_engine(DB_NAME)
    try:
        with on_db.connect() as connection:
            connection.execute(text(f"ALTER SCHEMA public OWNER TO {OWNER}"))
            connection.execute(text("REVOKE ALL ON SCHEMA public FROM PUBLIC"))
            connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {RUNTIME}"))
    finally:
        on_db.dispose()


def alembic_config(url: URL | None = None) -> "Config":
    """An Alembic config for the packaged migrations, as the owner role."""
    from alembic.config import Config  # noqa: PLC0415

    from ai_gateway.prestart import ALEMBIC_INI  # noqa: PLC0415

    config = Config(str(ALEMBIC_INI))
    config.set_main_option(
        "sqlalchemy.url", (url or owner_url()).render_as_string(hide_password=False)
    )
    return config


def owner_engine() -> Engine:
    """An owner-role engine on the test database."""
    return create_engine(owner_url())


def migrate_and_install(deployment_id: object, spool_max_bytes: int) -> None:
    """``alembic upgrade head`` then the installation row, as ai-migrate does."""
    from alembic import command  # noqa: PLC0415

    from ai_gateway.installation import init_installation  # noqa: PLC0415

    command.upgrade(alembic_config(), "head")
    owner = owner_engine()
    try:
        with owner.begin() as connection:
            init_installation(connection, deployment_id, spool_max_bytes)  # type: ignore[arg-type]
    finally:
        owner.dispose()


#: Tables that hold configuration the session keeps between tests.
_KEPT = (
    "alembic_version_ai",
    "ai_installation",
    "ai_spool_capacity",
    "ai_restore_state",
)


def truncate_all() -> None:
    """Empty every data table (owner role; triggers on DELETE do not fire)."""
    owner = owner_engine()
    try:
        with owner.begin() as connection:
            tables = [
                row[0]
                for row in connection.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                )
                if row[0] not in _KEPT
            ]
            if tables:
                connection.execute(
                    text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE")
                )
    finally:
        owner.dispose()

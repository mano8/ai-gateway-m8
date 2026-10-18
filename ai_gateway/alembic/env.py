"""Alembic environment for ai_gateway.

Runs only under the ai-migrate one-shot. Handles offline and online modes
against the gateway's own version table.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

import ai_gateway.db_models  # noqa: F401  (registers the tables)
from ai_gateway.core.config import settings
from ai_gateway.core.utc_session import pin_utc_session

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata

VERSION_TABLE = config.get_main_option("version_table")


def get_url() -> str:
    """Return the database URL from settings."""
    return str(settings.SQLALCHEMY_DATABASE_URI)


def include_object(
    object,  # noqa: A002
    name: str,
    type_: str,
    reflected: bool,
    compare_to: object,
) -> bool:
    """Keep the version table and every table this package defines."""
    if type_ == "table":
        if name == VERSION_TABLE:
            return True
        return not reflected
    return True


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        include_object=include_object,  # type: ignore[arg-type]
        version_table=VERSION_TABLE,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""
    configuration = config.get_section(config.config_ini_section)
    if configuration is None:
        raise RuntimeError("Alembic configuration section is missing.")
    configuration["sqlalchemy.url"] = get_url()

    connectable = pin_utc_session(
        engine_from_config(
            configuration,  # type: ignore[arg-type]
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            include_object=include_object,  # type: ignore[arg-type]
            version_table=VERSION_TABLE,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

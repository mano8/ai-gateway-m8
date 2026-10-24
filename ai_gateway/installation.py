"""
The installation identity (C-14 ``AI_DEPLOYMENT_ID``).

``ai_installation`` holds one row: the UUID generated once per installation,
which namespaces Vault paths, job-context audiences and receipts. The
``ai-migrate`` one-shot writes it after ``alembic upgrade head`` as the schema
owner (``python -m ai_gateway.installation init``); the runtime role can only
read it. Every web and scheduler start refuses an ``AI_DEPLOYMENT_ID`` that
differs from the recorded one, and a database with no recorded installation.
"""

from __future__ import annotations

import logging
import sys
from uuid import UUID

from sqlalchemy import Connection, Engine, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.db_models.accounting import ai_spool_capacity
from ai_gateway.db_models.installation import ai_installation, ai_restore_state

logger = logging.getLogger(__name__)


class InstallationError(RuntimeError):
    """The database records no installation, or a different one."""


def init_installation(
    connection: Connection, deployment_id: UUID, spool_max_bytes: int
) -> bool:
    """
    Record ``deployment_id`` once, or verify it; seed the single-row tables.

    Returns ``True`` when the installation row was created by this call.
    Raises :class:`InstallationError` when a different id is recorded.
    """
    recorded = connection.execute(
        select(ai_installation.c.deployment_id).with_for_update()
    ).scalar_one_or_none()
    created = recorded is None
    if created:
        connection.execute(
            insert(ai_installation).values(id=1, deployment_id=deployment_id)
        )
    elif recorded != deployment_id:
        raise InstallationError(
            "AI_DEPLOYMENT_ID differs from the installation recorded in the "
            "database; an installation id is never rotated"
        )
    connection.execute(
        pg_insert(ai_spool_capacity)
        .values(id=1, max_bytes=spool_max_bytes)
        .on_conflict_do_update(
            index_elements=["id"], set_={"max_bytes": spool_max_bytes}
        )
    )
    connection.execute(
        pg_insert(ai_restore_state).values(id=1).on_conflict_do_nothing()
    )
    return created


def recorded_deployment_id(engine: Engine) -> UUID | None:
    """The recorded installation id, read-only, or ``None``."""
    with engine.connect() as connection:
        value: UUID | None = connection.execute(
            select(ai_installation.c.deployment_id)
        ).scalar_one_or_none()
    return value


def check_installation(engine: Engine, deployment_id: UUID) -> None:
    """Raise unless the database records exactly ``deployment_id``."""
    recorded = recorded_deployment_id(engine)
    if recorded is None:
        raise InstallationError(
            "the database records no installation; run the ai-migrate one-shot"
        )
    if recorded != deployment_id:
        raise InstallationError(
            "AI_DEPLOYMENT_ID differs from the installation recorded in the database"
        )


def main(argv: list[str] | None = None) -> int:
    """``python -m ai_gateway.installation init`` (schema owner only)."""
    args = sys.argv[1:] if argv is None else argv
    if args != ["init"]:
        logger.error("usage: python -m ai_gateway.installation init")
        return 2
    from ai_gateway.core.config import settings  # noqa: PLC0415
    from ai_gateway.core.deps import engine  # noqa: PLC0415

    try:
        with engine._engine.begin() as connection:
            created = init_installation(
                connection, settings.AI_DEPLOYMENT_ID, settings.AI_OCR_SPOOL_MAX_BYTES
            )
    except InstallationError as exc:
        logger.error("%s", exc)
        return 1
    logger.info("installation %s", "recorded" if created else "verified")
    return 0


__all__ = [
    "InstallationError",
    "check_installation",
    "init_installation",
    "main",
    "recorded_deployment_id",
]

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

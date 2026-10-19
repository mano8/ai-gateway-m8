"""
Pre-start checks for the web and scheduler run-modes.

The checks, in order, and nothing else:

1. the OCR spool, when configured, is on a local filesystem whose locks
   exclude (D-45);
2. wait until the database answers a trivial ``SELECT``;
3. read ``alembic_version_ai`` (read-only, as the runtime role) and exit
   unless it equals the head packaged in this image;
4. exit unless the database records this ``AI_DEPLOYMENT_ID`` as its
   installation.

The run-modes never execute Alembic: no ``upgrade``, no autogenerate, no DDL.
Migrations run only through the ``ai-migrate`` one-shot
(``scripts/ai_migrate.sh``), so a half-migrated or newer database makes the
service exit instead of starting against it.

Run as ``python -m ai_gateway.prestart``.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, column, inspect, select, table, text
from tenacity import after_log, before_log, retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

MAX_TRIES = 60 * 5  # 5 minutes
WAIT_SECONDS = 5

#: The gateway's own Alembic version table.
VERSION_TABLE = "alembic_version_ai"

ALEMBIC_INI = Path(__file__).resolve().parent / "alembic.ini"


def packaged_head(ini_path: Path = ALEMBIC_INI) -> str | None:
    """
    Return the single head revision packaged with this image, if any.

    Parameters
    ----------
    ini_path
        The Alembic configuration shipped in the package.

    Returns
    -------
    str or None
        The head revision id, or ``None`` when no migration is packaged.

    Raises
    ------
    RuntimeError
        If the packaged scripts have more than one head.

    """
    config = Config(str(ini_path))
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) > 1:
        raise RuntimeError("packaged migrations have more than one head")
    return heads[0] if heads else None


def database_revision(engine: Engine) -> str | None:
    """
    Read the database's recorded revision without writing anything.

    Parameters
    ----------
    engine
        The service engine (runtime role).

    Returns
    -------
    str or None
        The single recorded revision, or ``None`` when the version table is
        absent or empty.

    Raises
    ------
    RuntimeError
        If the version table holds more than one row.

    """
    with engine.connect() as connection:
        if not inspect(connection).has_table(VERSION_TABLE):
            return None
        version_table = table(VERSION_TABLE, column("version_num"))
        rows = connection.execute(select(version_table.c.version_num)).all()
    if len(rows) > 1:
        raise RuntimeError(f"{VERSION_TABLE} holds more than one revision")
    return rows[0][0] if rows else None


def check_schema_revision(engine: Engine, head: str | None) -> bool:
    """
    Return whether the database revision equals the packaged head.

    Parameters
    ----------
    engine
        The service engine.
    head
        The packaged head, from :func:`packaged_head`.

    Returns
    -------
    bool
        ``True`` only on an exact match (both absent counts as a match).

    """
    current = database_revision(engine)
    if current != head:
        logger.error(
            "schema revision mismatch: database=%s packaged=%s; "
            "run the ai-migrate one-shot before starting this service",
            current,
            head,
        )
        return False
    logger.info("schema revision %s matches the packaged head", current)
    return True


@retry(
    stop=stop_after_attempt(MAX_TRIES),
    wait=wait_fixed(WAIT_SECONDS),
    before=before_log(logger, logging.INFO),
    after=after_log(logger, logging.WARNING),
)
def wait_for_db(engine: Engine) -> None:
    """Probe the database until it answers a trivial ``SELECT``."""
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))


def main() -> int:
    """
    Run the start-up checks.

    Returns
    -------
    int
        The process exit status: ``0`` when the service may start, ``1``
        otherwise.

    """
    from ai_gateway.core.config import settings  # noqa: PLC0415
    from ai_gateway.core.deps import engine  # noqa: PLC0415
    from ai_gateway.core.spool_check import (  # noqa: PLC0415
        SpoolFilesystemError,
        assert_local_spool,
    )

    if settings.AI_OCR_SPOOL_DIR is not None:
        try:
            assert_local_spool(settings.AI_OCR_SPOOL_DIR)
        except SpoolFilesystemError as exc:
            logger.error("spool check failed: %s", exc)
            return 1
    from ai_gateway.installation import (  # noqa: PLC0415
        InstallationError,
        check_installation,
    )

    wait_for_db(engine._engine)
    if not check_schema_revision(engine._engine, packaged_head()):
        return 1
    try:
        check_installation(engine._engine, settings.AI_DEPLOYMENT_ID)
    except InstallationError as exc:
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

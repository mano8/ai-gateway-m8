"""Pre-start checks for the web and scheduler run-modes.

Two checks, in order, and nothing else:

1. wait until the database answers a trivial ``SELECT``;
2. read ``alembic_version_ai`` (read-only, as the runtime role) and exit
   unless it equals the head packaged in this image.

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
from sqlalchemy import Engine, inspect, text
from tenacity import after_log, before_log, retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

MAX_TRIES = 60 * 5  # 5 minutes
WAIT_SECONDS = 5

#: The gateway's own Alembic version table.
VERSION_TABLE = "alembic_version_ai"

ALEMBIC_INI = Path(__file__).resolve().parent / "alembic.ini"


def packaged_head(ini_path: Path = ALEMBIC_INI) -> str | None:
    """Return the single head revision packaged with this image, if any.

    Args:
        ini_path: The Alembic configuration shipped in the package.

    Returns:
        The head revision id, or ``None`` when no migration is packaged.

    Raises:
        RuntimeError: If the packaged scripts have more than one head.
    """
    config = Config(str(ini_path))
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) > 1:
        raise RuntimeError("packaged migrations have more than one head")
    return heads[0] if heads else None


def database_revision(engine: Engine) -> str | None:
    """Read the database's recorded revision without writing anything.

    Args:
        engine: The service engine (runtime role).

    Returns:
        The single recorded revision, or ``None`` when the version table is
        absent or empty.

    Raises:
        RuntimeError: If the version table holds more than one row.
    """
    with engine.connect() as connection:
        if not inspect(connection).has_table(VERSION_TABLE):
            return None
        rows = connection.execute(
            text(f"SELECT version_num FROM {VERSION_TABLE}")  # nosec B608
        ).all()
    if len(rows) > 1:
        raise RuntimeError(f"{VERSION_TABLE} holds more than one revision")
    return rows[0][0] if rows else None


def check_schema_revision(engine: Engine, head: str | None) -> bool:
    """Return whether the database revision equals the packaged head.

    Args:
        engine: The service engine.
        head: The packaged head, from :func:`packaged_head`.

    Returns:
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
    """Run both checks against the service engine.

    Returns:
        The process exit status: ``0`` when the service may start, ``1``
        otherwise.
    """
    from ai_gateway.core.deps import engine  # noqa: PLC0415

    wait_for_db(engine._engine)
    return 0 if check_schema_revision(engine._engine, packaged_head()) else 1


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

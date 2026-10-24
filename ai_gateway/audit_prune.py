"""
``audit-prune`` (``T33``, S-11): the only deletion of audit rows.

::

    python -m ai_gateway.audit_prune --before 2026-01-01 --operator <name>

The runtime role has no ``DELETE`` on the audit tables and never prunes them.
This command ships in the image and runs only as ``ai_owner`` through the
``ai-migrate`` service. In one transaction it counts the rows it will remove,
writes its own summary row to ``ai_admin_audit`` (count, range, operator) and
only then deletes exactly the rows before the date — the summary row is newer
than any date that may be named (a future date is refused), so it survives. As ``ai_runtime`` the first
write fails on permissions and nothing changes. Nothing secret is read.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, date, datetime

import sqlalchemy as sa
from sqlalchemy import Engine

from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.db_models.audit import ai_admin_audit, ai_credential_audit

logger = logging.getLogger(__name__)

_TABLES = (ai_credential_audit, ai_admin_audit)


def prune(engine: Engine, before: date, operator: str) -> dict[str, int]:
    """
    Delete the audit rows older than ``before`` (not in the future).

    The summary row is stamped now, never before the cutoff, so it survives.
    Returns the per-table counts.
    """
    if before > datetime.now(UTC).date():
        raise ValueError("--before must not be in the future")
    cutoff = datetime(before.year, before.month, before.day, tzinfo=UTC)
    counts: dict[str, int] = {}
    with audited_transaction(engine) as tx:
        ranges: dict[str, object] = {}
        for table in _TABLES:
            count, first, last = tx.connection.execute(
                sa.select(
                    sa.func.count(),
                    sa.func.min(table.c.occurred_at),
                    sa.func.max(table.c.occurred_at),
                ).where(table.c.occurred_at < cutoff)
            ).one()
            counts[table.name] = int(count)
            ranges[table.name] = {"first": first, "last": last}
        tx.admin(
            Actor("operator", operator),
            "audit.prune",
            "audit",
            None,
            {"before": before.isoformat(), "counts": counts, "range": ranges},
        )
        for table in _TABLES:
            tx.connection.execute(sa.delete(table).where(table.c.occurred_at < cutoff))
    return counts


def main(argv: list[str] | None = None) -> int:
    """Run the prune; ``0`` on success, ``1`` when the database refuses it."""
    parser = argparse.ArgumentParser(prog="python -m ai_gateway.audit_prune")
    parser.add_argument("--before", required=True, type=date.fromisoformat)
    parser.add_argument("--operator", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    from ai_gateway.core.deps import db_engine  # noqa: PLC0415

    try:
        counts = prune(db_engine, args.before, args.operator)
    except (sa.exc.DBAPIError, ValueError) as error:
        logger.error(
            "audit-prune refused: %s", type(getattr(error, "orig", error)).__name__
        )
        return 1
    print(json.dumps({"pruned": counts, "before": args.before.isoformat()}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

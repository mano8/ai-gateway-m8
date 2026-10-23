"""
Execution operator commands (D-43, D-45)::

    python -m ai_gateway.execution remote-artifact accept-residual \
        --id <artifact-id> --evidence <text>
    python -m ai_gateway.execution spool repair \
        --id <execution-id> --evidence <text>

``accept-residual`` closes one ``manual_cleanup_required`` row as an
**accepted residual risk** — never as cleanup — and writes its
``ai_admin_audit`` row with the remote id, the file name, the provider's
expiry and the operator's evidence. It exits ``1`` when no parked row has
that id. ``spool repair`` releases the spool reservation of a terminal row
whose lock file vanished while it held one (the ``spool_lock_missing``
alert), after the operator confirmed no process holds its data file, with
an ``ai_admin_audit`` row; it exits ``1`` when no such row has that id.
Nothing secret is read or printed.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from uuid import UUID

logger = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ai_gateway.execution")
    groups = parser.add_subparsers(dest="group", required=True)
    artifacts = groups.add_parser("remote-artifact")
    commands = artifacts.add_subparsers(dest="command", required=True)
    accept = commands.add_parser("accept-residual")
    accept.add_argument("--id", required=True, type=UUID)
    accept.add_argument("--evidence", required=True)
    spools = groups.add_parser("spool")
    spool_commands = spools.add_subparsers(dest="command", required=True)
    repair = spool_commands.add_parser("repair")
    repair.add_argument("--id", required=True, type=UUID)
    repair.add_argument("--evidence", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one command; ``0`` on success, ``1`` when nothing matched."""
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    from ai_gateway.controllers.audit import Actor  # noqa: PLC0415
    from ai_gateway.core.deps import db_engine  # noqa: PLC0415
    from ai_gateway.execution.artifacts import accept_residual  # noqa: PLC0415
    from ai_gateway.execution.sweepers import spool_repair  # noqa: PLC0415

    if args.group == "spool":
        done = spool_repair(db_engine, args.id, Actor("operator"), args.evidence)
        print(json.dumps({"repaired": done, "id": str(args.id)}))
        missing = "no cleanup_pending row with a missing lock has id %s"
    else:
        done = accept_residual(db_engine, args.id, args.evidence, Actor("operator"))
        print(json.dumps({"accepted": done, "id": str(args.id)}))
        missing = "no manual_cleanup_required row has id %s"
    if not done:
        logger.error(missing, args.id)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

"""
Remote-artifact operator commands (D-43)::

    python -m ai_gateway.execution remote-artifact accept-residual \
        --id <artifact-id> --evidence <text>

``accept-residual`` closes one ``manual_cleanup_required`` row as an
**accepted residual risk** — never as cleanup — and writes its
``ai_admin_audit`` row with the remote id, the file name, the provider's
expiry and the operator's evidence. It exits ``1`` when no parked row has
that id. Nothing secret is read or printed.
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
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one command; ``0`` on success, ``1`` when nothing matched."""
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    from ai_gateway.controllers.audit import Actor  # noqa: PLC0415
    from ai_gateway.core.deps import db_engine  # noqa: PLC0415
    from ai_gateway.execution.artifacts import accept_residual  # noqa: PLC0415

    accepted = accept_residual(db_engine, args.id, args.evidence, Actor("operator"))
    print(json.dumps({"accepted": accepted, "id": str(args.id)}))
    if not accepted:
        logger.error("no manual_cleanup_required row has id %s", args.id)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

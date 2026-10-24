"""
Key-rotation commands (D-23), run on a replica that holds every generation::

    python -m ai_gateway.credentials generations
    python -m ai_gateway.credentials rewrap [--verify]
    python -m ai_gateway.credentials refingerprint [--verify]

``generations`` prints the rows per KEK and fingerprint-key generation.
``rewrap`` re-wraps every data key under an older KEK generation (ciphertext
untouched); ``refingerprint`` recomputes every fingerprint under an older
key. With ``--verify`` nothing changes, and the exit status is ``1`` while
any row is still under a generation other than the active one (step 5 of
the D-23 protocol). Each change is audited as an operator action (S-11).
Output is generation labels and counts only, never key material.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from ai_gateway.credentials.store import KeyGenerations

logger = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ai_gateway.credentials")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("generations")
    for name in ("rewrap", "refingerprint"):
        command = commands.add_parser(name)
        command.add_argument("--verify", action="store_true")
    return parser


#: Each changing command: its store method, audit action and output key.
_ROTATIONS = {
    "rewrap": ("rewrap", "credentials.rewrap", "rewrapped"),
    "refingerprint": ("refingerprint", "credentials.refingerprint", "refingerprinted"),
}


def _rotate(command: str) -> None:
    """Run one rotation in an audited transaction and print its count."""
    from ai_gateway.controllers.audit import Actor, audited_transaction  # noqa: PLC0415
    from ai_gateway.core.deps import credential_store, db_engine  # noqa: PLC0415

    method, action, label = _ROTATIONS[command]
    with audited_transaction(db_engine) as tx:
        count = getattr(credential_store, method)(tx.connection)
        tx.admin(Actor("operator"), action, "credential_store", None, {"rows": count})
    print(json.dumps({label: count}))


def _stale(command: str, held: KeyGenerations) -> list[str]:
    """The generations other than the active one that still hold rows."""
    from ai_gateway.core.deps import credential_store  # noqa: PLC0415

    if command == "rewrap":
        counts, active = held.kek, credential_store.kek_version
    else:
        counts, active = held.fingerprint, credential_store.fingerprint_version
    return sorted(version for version in counts if version != active)


def main(argv: list[str] | None = None) -> int:
    """Run one command; the exit status (see the module docstring)."""
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    verify = bool(getattr(args, "verify", False))
    if args.command in _ROTATIONS and not verify:
        _rotate(args.command)
    from ai_gateway.core.deps import credential_store, db_engine  # noqa: PLC0415

    with db_engine.connect() as connection:
        held = credential_store.generations(connection)
    print(
        json.dumps({"kek": held.kek, "fingerprint": held.fingerprint}, sort_keys=True)
    )
    if not verify:
        return 0
    stale = _stale(args.command, held)
    if stale:
        logger.error("rows remain under an older generation: %s", stale)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

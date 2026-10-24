"""
The per-version sweep obligation of remote artifacts (D-43).

Each credential version records ``last_upload_deadline_at``, the latest
``upload_deadline_at`` over the upload intents made under it. Where a
provider documents a sweep absence proof, the version stays sweep-eligible
until ``reconciled_through`` covers that bound plus the grace
(``sweep_discharge_at``); everywhere else — Mistral included — the
obligation is discharged only by every intent row closing, which the schema
already enforces (no version an artifact row references can be destroyed),
so ``sweep_discharge_at`` is left unset.

Only ``ai_gateway/credentials/`` may touch version rows (``TID251``).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Connection

# Only this package may import the version table (TID251, ``ruff.toml`` here).
from ai_gateway.db_models.credential_version import ai_credential_version  # noqa: TID251


def note_upload_deadline(
    connection: Connection,
    credential_id: UUID,
    version: int,
    deadline: datetime,
    *,
    sweep_grace_seconds: int | None = None,
) -> None:
    """
    Raise the version's ``last_upload_deadline_at`` to ``deadline``.

    ``sweep_grace_seconds`` is given only for a provider that documents a
    sweep absence proof: the version then also owes a sweep up to
    ``deadline`` plus that grace.
    """
    v = ai_credential_version
    latest = sa.func.greatest(
        sa.func.coalesce(v.c.last_upload_deadline_at, deadline), deadline
    )
    values: dict[str, object] = {"last_upload_deadline_at": latest}
    if sweep_grace_seconds is not None:
        values["sweep_discharge_at"] = latest + timedelta(seconds=sweep_grace_seconds)
    connection.execute(
        sa.update(v)
        .where(v.c.credential_id == credential_id, v.c.version == version)
        .values(**values)
    )


__all__ = ["note_upload_deadline"]

"""
The credential cooldown a provider 429 sets (D-20).

``throttled_until = now() + min(Retry-After, AI_PROVIDER_MAX_BACKOFF_SECONDS)``
on the **database** clock, and never shortened: a later, shorter answer
keeps the longer cooldown already recorded. Every replica's reservation
then refuses the credential with ``rate_limited`` and ``Retry-After`` until
it passes (C-04). The cooldown is per credential, not per model — coarser,
and conservative.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Connection

from ai_gateway.db_models.credentials import ai_credential


def apply_cooldown(connection: Connection, credential_id: UUID, seconds: int) -> None:
    """Throttle ``credential_id`` for ``seconds`` (already parsed and capped)."""
    until = sa.func.now() + timedelta(seconds=max(0, seconds))
    current = sa.func.coalesce(ai_credential.c.throttled_until, until)
    connection.execute(
        sa.update(ai_credential)
        .where(ai_credential.c.id == credential_id)
        .values(throttled_until=sa.func.greatest(current, until))
    )


__all__ = ["apply_cooldown"]

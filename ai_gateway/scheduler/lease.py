"""
The fenced scheduler lease (D-42).

One ``ai_scheduler_lease`` row per job. A process **acquires** a job's lease
only once it has expired, with a fresh random 128-bit ``holder_token`` and
``epoch + 1``; it **renews** only while it still holds the token and the
lease has not run out, and a missed renewal means it stops: the lease is
forgotten and the job does not run on that tick.

Every claim transaction carries the **fence** — an ``EXISTS`` over the lease
row asserting ``epoch``, ``holder_token`` and ``lease_until > now()``, taken
``FOR SHARE`` so a successor's acquisition waits for the statement to commit
and a statement queued behind an acquisition re-reads the new token and
matches nothing. A leader paused past its lease and resumed therefore commits
nothing, and because the token cannot be reproduced neither can a leader that
survived an ``ai_db`` restore which rewound ``epoch``.

**Per-item claims** (remote artifacts): a row is claimed by a fenced CAS that
writes ``claim_epoch``, ``claim_holder_token`` and ``claim_until``; every later
CAS on it asserts all three **and** the live lease. External effects may
repeat; none counts as complete by repetition (D-42, D-43).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Final

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.core.metrics import SCHEDULER_LEASE_EPOCH
from ai_gateway.db_models.installation import ai_scheduler_lease

_L = ai_scheduler_lease

#: How long one acquisition or renewal holds a job's lease.
LEASE_TTL_SECONDS: Final = 60

#: How long one per-item claim holds a row; renewed by claiming it again.
CLAIM_TTL_SECONDS: Final = 120


def fresh_token() -> str:
    """A random 128-bit holder token, hex."""
    return secrets.token_hex(16)


@dataclass(frozen=True)
class Lease:
    """One held lease: what every fenced statement of the job asserts."""

    job: str
    epoch: int
    holder_token: str

    def fence(self) -> sa.ColumnElement[bool]:
        """The lease row is still this one and still live, locked ``FOR SHARE``."""
        return (
            sa.select(sa.literal(1))
            .where(
                _L.c.job == self.job,
                _L.c.epoch == self.epoch,
                _L.c.holder_token == self.holder_token,
                _L.c.lease_until > sa.func.now(),
            )
            .with_for_update(read=True)
            .exists()
        )

    def claimable(self, table: sa.Table) -> sa.ColumnElement[bool]:
        """A row no live claim of another leader holds, under the fence."""
        c = table.c
        return sa.and_(
            sa.or_(
                c.claim_until.is_(None),
                c.claim_until < sa.func.now(),
                sa.and_(
                    c.claim_epoch == self.epoch,
                    c.claim_holder_token == self.holder_token,
                ),
            ),
            self.fence(),
        )

    def claim_values(self) -> dict[str, object]:
        """The columns a claim writes."""
        return {
            "claim_epoch": self.epoch,
            "claim_holder_token": self.holder_token,
            "claim_until": sa.func.now() + timedelta(seconds=CLAIM_TTL_SECONDS),
        }

    def held(self, table: sa.Table) -> sa.ColumnElement[bool]:
        """The per-item fence: this leader's live claim on the row, and the lease."""
        c = table.c
        return sa.and_(
            c.claim_epoch == self.epoch,
            c.claim_holder_token == self.holder_token,
            c.claim_until > sa.func.now(),
            self.fence(),
        )


class LeaseKeeper:
    """Acquires, renews and stamps the leases of one scheduler process."""

    def __init__(
        self, engine: Engine, holder: str, *, ttl_seconds: int = LEASE_TTL_SECONDS
    ) -> None:
        self._engine = engine
        self._holder = holder
        self._ttl = timedelta(seconds=ttl_seconds)
        self._held: dict[str, Lease] = {}

    @property
    def holder(self) -> str:
        """This process's non-secret holder name."""
        return self._holder

    def hold(self, job: str) -> Lease | None:
        """Renew the lease of ``job`` or acquire it; ``None`` when another holds it."""
        current = self._held.pop(job, None)
        if current is not None and self._renew(current):
            self._held[job] = current
            return current
        lease = self._acquire(job)
        if lease is not None:
            self._held[job] = lease
            SCHEDULER_LEASE_EPOCH.set(lease.epoch)
        return lease

    def _renew(self, lease: Lease) -> bool:
        with self._engine.begin() as connection:
            row = connection.execute(
                sa.update(_L)
                .where(
                    _L.c.job == lease.job,
                    _L.c.holder_token == lease.holder_token,
                    _L.c.lease_until > sa.func.now(),
                )
                .values(lease_until=sa.func.now() + self._ttl)
                .returning(_L.c.epoch)
            ).first()
        return row is not None and row[0] == lease.epoch

    def _acquire(self, job: str) -> Lease | None:
        token = fresh_token()
        with self._engine.begin() as connection:
            connection.execute(pg_insert(_L).values(job=job).on_conflict_do_nothing())
            row = connection.execute(
                sa.update(_L)
                .where(_L.c.job == job, _L.c.lease_until < sa.func.now())
                .values(
                    holder=self._holder,
                    holder_token=token,
                    epoch=_L.c.epoch + 1,
                    lease_until=sa.func.now() + self._ttl,
                )
                .returning(_L.c.epoch)
            ).first()
        return None if row is None else Lease(job, int(row[0]), token)

    def succeeded(self, lease: Lease) -> bool:
        """Stamp the job's last successful run, under the fence."""
        with self._engine.begin() as connection:
            row = connection.execute(
                sa.update(_L)
                .where(_L.c.job == lease.job, lease.fence())
                .values(last_success_at=sa.func.now())
                .returning(_L.c.job)
            ).first()
        return row is not None

    def release(self) -> None:
        """Give every held lease up (an orderly stop), so a peer takes over at once."""
        for lease in self._held.values():
            with self._engine.begin() as connection:
                connection.execute(
                    sa.update(_L)
                    .where(
                        _L.c.job == lease.job,
                        _L.c.holder_token == lease.holder_token,
                    )
                    .values(lease_until=sa.func.now())
                )
        self._held.clear()


__all__ = [
    "CLAIM_TTL_SECONDS",
    "LEASE_TTL_SECONDS",
    "Lease",
    "LeaseKeeper",
    "fresh_token",
]

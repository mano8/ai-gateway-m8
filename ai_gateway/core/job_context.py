"""
Job-context verification and single-use redemption (C-03, S-04).

:func:`ai_sdk_m8.jobcontext.verify` proves what a token says about itself:
the signed-object rule under ``m8.ai.job-context.v1``, the closed claim
model (``max_uses = 1`` included), the audience, the clock rule and the TTL
caps. :class:`JobContextVerifier` adds what needs the gateway's state:

* ``iss`` is a registered client holding ``job-context:issue`` and ``kid`` is
  one of **its** keys, so a context signed with another client's key fails;
* the presenting client (``X-Internal-Client``) equals ``azp``;
* the route's capability equals the ``capability`` claim;
* ``aud`` is ``ai-gateway/<deployment_id>`` as ``ai_installation`` records it,
  never a separately configured value.

The request's profile is bound after the body is parsed
(:meth:`JobContextPrincipal.require_profile`), and the ``(iss, jti)``
redemption (:func:`redeem_job_context`) runs inside the transaction of the
row transition the context authorizes. Every refusal is a typed
:class:`~ai_gateway.core.errors.GatewayError`; no message, log line or
response ever carries the token.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import sqlalchemy as sa
from prometheus_client import Counter
from ai_sdk_m8.jobcontext import JobContextError, JobContextPayload, verify
from ai_sdk_m8.schemas import AiErrorCode, Capability
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.db_models._common import TIMESTAMP
from ai_gateway.db_models.accounting import ai_job_context_use
from ai_gateway.installation import InstallationError, recorded_deployment_id

from .errors import GatewayError
from .service_clients import JOB_CONTEXT_ISSUE, ServiceClients

#: Largest accepted ``X-AI-Job-Context``, checked before any decoding (C-03).
MAX_CONTEXT_BYTES: Final = 4096


@dataclass(frozen=True)
class JobContextPrincipal:
    """A verified, not yet redeemed, job context and the client presenting it."""

    client_id: str
    payload: JobContextPayload

    def require_profile(self, profile_key: str) -> None:
        """Refuse a request whose profile is not the one the context names."""
        if profile_key != self.payload.profile_key:
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)

    def redeem(self, connection: Connection) -> None:
        """Redeem this context once, inside the caller's transaction."""
        redeem_job_context(connection, self.payload)


class InstallationAudience:
    """
    The ``aud`` of this installation, read once from ``ai_installation``.

    The installation identity is never rotated in V1, so the first successful
    read is kept for the life of the process.
    """

    def __init__(self, engine: Callable[[], Engine]) -> None:
        self._engine = engine
        self._lock = threading.Lock()
        self._audience: str | None = None

    def __call__(self) -> str:
        """``ai-gateway/<deployment_id>``; raises when none is recorded."""
        with self._lock:
            if self._audience is None:
                deployment_id = recorded_deployment_id(self._engine())
                if deployment_id is None:
                    raise InstallationError("the database records no installation")
                self._audience = f"ai-gateway/{deployment_id}"
            return self._audience


def _issuer_keys(clients: ServiceClients) -> tuple[dict[str, bytes], dict[str, str]]:
    """Every issuer's keys by ``kid``, and the client owning each ``kid``."""
    keys: dict[str, bytes] = {}
    owners: dict[str, str] = {}
    for client_id, client_keys in clients.public_keys.items():
        if not clients.has_scope(client_id, JOB_CONTEXT_ISSUE):
            continue
        for kid, key in client_keys.items():
            if kid in owners:
                raise ValueError(f"kid {kid!r} is registered under two clients")
            keys[kid] = key
            owners[kid] = client_id
    return keys, owners


class JobContextVerifier:
    """Verifies ``X-AI-Job-Context`` against the registered issuers."""

    def __init__(
        self,
        clients: ServiceClients,
        *,
        audience: Callable[[], str],
        max_ttl_seconds: int,
        skew_seconds: int,
        dispatch_ttl_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keys, self._owners = _issuer_keys(clients)
        self._audience = audience
        self._max_ttl = max_ttl_seconds
        self._skew = skew_seconds
        self._dispatch_ttl = dispatch_ttl_seconds
        self._clock = clock

    def verify(
        self, token: str | None, *, presenter: str, capability: Capability
    ) -> JobContextPrincipal:
        """
        Verify ``token`` presented by ``presenter`` on a ``capability`` route.

        Raises
        ------
        GatewayError
            ``context_missing`` when absent; ``context_expired`` when past
            ``exp``; ``context_invalid`` for everything else.

        """
        if not token:
            raise GatewayError(AiErrorCode.CONTEXT_MISSING)
        if len(token) > MAX_CONTEXT_BYTES:
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)
        try:
            payload = verify(
                token,
                public_keys=self._keys,
                aud=self._audience(),
                now=int(self._clock()),
                max_ttl=self._max_ttl,
                skew=self._skew,
                max_dispatch_ttl=self._dispatch_ttl,
            )
        except JobContextError as exc:
            raise GatewayError(exc.code) from None
        if (
            self._owners.get(payload.kid) != payload.iss
            or payload.azp != presenter
            or payload.capability is not capability
        ):
            raise GatewayError(AiErrorCode.CONTEXT_INVALID)
        return JobContextPrincipal(presenter, payload)


#: ``ai_job_contexts_total{event}`` (C-13): ``redeemed``, ``replayed``,
#: ``expired`` (counted in the redeeming transaction) and ``swept``.
JOB_CONTEXTS = Counter(
    "ai_job_contexts", "Job-context redemptions and sweeps", ["event"]
)


def redeem_job_context(connection: Connection, payload: JobContextPayload) -> None:
    """
    Count one use of ``(iss, jti)``, atomically, on the database clock.

    One ``INSERT … ON CONFLICT … WHERE uses < max_uses RETURNING`` both
    redeems and asserts ``exp > now()``, so a replica whose clock lags the
    database can never redeem a context whose row the sweeper already
    removed. Commits with the caller's transaction.

    Raises
    ------
    GatewayError
        ``context_expired`` when the database clock is past ``exp``,
        ``context_replayed`` when the context was already used.

    """
    table = ai_job_context_use
    exp = sa.literal(datetime.fromtimestamp(payload.exp, UTC), TIMESTAMP)
    live = exp > sa.func.now()
    candidate = sa.select(
        sa.literal(payload.iss, sa.Text),
        sa.literal(payload.jti, sa.Text),
        sa.literal(1, sa.Integer),
        sa.literal(payload.max_uses, sa.Integer),
        exp,
    ).where(live)
    statement = (
        pg_insert(table)
        .from_select(["iss", "jti", "uses", "max_uses", "exp"], candidate)
        .on_conflict_do_update(
            index_elements=[table.c.iss, table.c.jti],
            set_={"uses": table.c.uses + 1},
            where=sa.and_(table.c.uses < table.c.max_uses, table.c.exp > sa.func.now()),
        )
        .returning(table.c.uses)
    )
    if connection.execute(statement).first() is not None:
        JOB_CONTEXTS.labels(event="redeemed").inc()
        return
    still_live = connection.execute(sa.select(live)).scalar_one()
    JOB_CONTEXTS.labels(event="replayed" if still_live else "expired").inc()
    raise GatewayError(
        AiErrorCode.CONTEXT_REPLAYED if still_live else AiErrorCode.CONTEXT_EXPIRED
    )


__all__ = [
    "MAX_CONTEXT_BYTES",
    "InstallationAudience",
    "JobContextPrincipal",
    "JobContextVerifier",
    "redeem_job_context",
]

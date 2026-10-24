"""
Credential validation (``T25``): ``POST …/credentials/{id}:validate``.

One minimal authenticated request — the adapter's ``probe`` (Ollama ``GET
/api/tags``, OpenAI-compatible and Mistral ``GET /v1/models``) — through the
D-20 client, under the credential's **current** version, against the
provider's frozen endpoint. The probe is an outbound use: the provider's
``first_used_at`` is stamped before it, freezing the endpoint.

Only a provider **authentication failure** (``401``/``403``) counts:
``auth_failure_count`` goes up by one and the third consecutive failure moves
the credential to ``invalid`` (its bindings follow); a success sets the count
to zero and stamps ``last_validated_at`` in that same statement. Anything else
— a timeout, a transport failure, a ``5xx`` or ``429``, an open breaker, any
other answer, a credential store that cannot resolve the material — is
``inconclusive`` and changes nothing. A ``401``/``403`` never feeds the
provider's breaker (D-20). Each outcome applies only while the probed version
is still current, so a rotation during the probe is never charged with the
old key's failures. Every validation is audited (``credential.validate``);
no header, body or secret is logged or returned.

Only an ``active`` credential is probed: an ``invalid`` one recovers by
rotation, which already resets the count.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from contextlib import ExitStack
from typing import Final

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import (
    CredentialPublic,
    CredentialStatus,
    CredentialValidation,
    ProviderType,
    ValidationOutcome,
)
from sqlalchemy import Engine

from ai_gateway.core.errors import GatewayError
from ai_gateway.credentials.store import CredentialStore, ResolvedSecret
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import ai_provider
from ai_gateway.providers.base import ProviderAdapter
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.http import ClientFactory, Deadline, ProviderEndpoint

from .audit import Actor, audited_transaction
from .bindings import sync_credential_status
from .credentials import get_credential, in_scope
from .errors import Conflict, NotFound
from .registry import Row
from .scopes import Scope

#: Consecutive authentication failures that make a credential ``invalid``.
INVALID_AFTER: Final = 3

_C = ai_credential
_ACTIVE = CredentialStatus.ACTIVE.value


class CredentialValidator:
    """Probes one credential and records what the probe proved."""

    def __init__(
        self,
        engine: Engine,
        store: CredentialStore,
        clients: ClientFactory,
        adapters: Mapping[ProviderType, ProviderAdapter],
        *,
        timeout_seconds: float,
    ) -> None:
        self._engine = engine
        self._store = store
        self._clients = clients
        self._adapters = adapters
        self._timeout = timeout_seconds

    async def validate(
        self, actor: Actor, scope: Scope, credential_id: uuid.UUID
    ) -> CredentialValidation:
        """Probe the current version; count or reset; audited."""
        row = await asyncio.to_thread(self._prepare, scope, credential_id)
        outcome, error = await self._probe(row)
        credential = await asyncio.to_thread(
            self._record, actor, scope, row, outcome, error
        )
        return CredentialValidation(outcome=outcome, credential=credential)

    # --- before the probe -------------------------------------------------------

    def _prepare(self, scope: Scope, credential_id: uuid.UUID) -> Row:
        """The credential and its provider; the provider's first use stamped."""
        p = ai_provider
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    sa.select(
                        _C.c.id,
                        _C.c.status,
                        _C.c.current_version,
                        _C.c.auth_failure_count,
                        p.c.id.label("provider_id"),
                        p.c.provider_type,
                        p.c.base_url,
                        p.c.boundary,
                        p.c.auth_type,
                        p.c.auth_header_name,
                    )
                    .join(p, p.c.id == _C.c.provider_id)
                    .where(
                        in_scope(scope, credential_id),
                        _C.c.status != CredentialStatus.DELETED.value,
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                raise NotFound("no such credential")
            if row["status"] != _ACTIVE or row["current_version"] is None:
                raise Conflict("only an active credential can be validated")
            connection.execute(
                sa.update(p)
                .where(p.c.id == row["provider_id"], p.c.first_used_at.is_(None))
                .values(first_used_at=sa.func.now())
            )
        return row

    # --- the probe -----------------------------------------------------------------

    def _secret(self, stack: ExitStack, row: Row) -> ResolvedSecret:
        return stack.enter_context(
            self._store.resolve_for_execution(row["id"], row["current_version"])
        )

    async def _probe(self, row: Row) -> tuple[ValidationOutcome, str | None]:
        adapter = self._adapters.get(ProviderType(row["provider_type"]))
        probe = getattr(adapter, "probe", None)
        if probe is None:
            return ValidationOutcome.INCONCLUSIVE, "capability_unsupported"
        endpoint = ProviderEndpoint.from_row({**row, "id": row["provider_id"]})
        try:
            with ExitStack() as stack:
                secret = await asyncio.to_thread(self._secret, stack, row)
                async with self._clients.client(endpoint) as client:
                    await probe(client, secret, Deadline.after(self._timeout))
        except ProviderFailure as failure:
            if failure.auth_failure:
                return ValidationOutcome.AUTH_FAILED, failure.code.value
            return ValidationOutcome.INCONCLUSIVE, failure.code.value
        except GatewayError as error:
            return ValidationOutcome.INCONCLUSIVE, error.code.value
        return ValidationOutcome.VALID, None

    # --- after the probe -------------------------------------------------------------

    def _record(
        self,
        actor: Actor,
        scope: Scope,
        row: Row,
        outcome: ValidationOutcome,
        error: str | None,
    ) -> CredentialPublic:
        with audited_transaction(self._engine) as tx:
            applied = _apply(tx.connection, row, outcome)
            status = row["status"] if applied is None else applied["status"]
            bindings = 0
            if status != row["status"]:
                bindings = sync_credential_status(tx.connection, row["id"])
            tx.credential(
                actor,
                "credential.validate",
                row["id"],
                scope.audit(),
                {
                    "outcome": outcome.value,
                    "error": error,
                    "version": row["current_version"],
                    "applied": applied is not None,
                    "auth_failure_count": {
                        "before": row["auth_failure_count"],
                        "after": row["auth_failure_count"]
                        if applied is None
                        else applied["auth_failure_count"],
                    },
                    "status": {"before": row["status"], "after": status},
                    "bindings_changed": bindings,
                },
            )
            return get_credential(tx.connection, scope, row["id"])


def _apply(
    connection: sa.Connection, row: Row, outcome: ValidationOutcome
) -> Row | None:
    """The one counting statement; ``None`` when nothing was (or could be) applied."""
    if outcome is ValidationOutcome.INCONCLUSIVE:
        return None
    where = sa.and_(
        _C.c.id == row["id"],
        _C.c.status == _ACTIVE,
        _C.c.current_version == row["current_version"],
    )
    if outcome is ValidationOutcome.VALID:
        values: dict[str, object] = {
            "auth_failure_count": 0,
            "last_validated_at": sa.func.now(),
        }
    else:
        count = _C.c.auth_failure_count + 1
        values = {
            "auth_failure_count": count,
            "status": sa.case(
                (count >= INVALID_AFTER, CredentialStatus.INVALID.value),
                else_=_C.c.status,
            ),
        }
    return (
        connection.execute(
            sa.update(_C)
            .where(where)
            .values(**values, updated_at=sa.func.now())
            .returning(_C.c.status, _C.c.auth_failure_count)
        )
        .mappings()
        .first()
    )


__all__ = ["INVALID_AFTER", "CredentialValidator"]

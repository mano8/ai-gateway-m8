"""
Provider-verified model identities (``T28``, D-11, C-07).

An Ollama model's identity is the digest its provider lists at
``/api/tags``. :class:`DigestReader` reads it:

* **at registration** — the superuser route reads the digest before its
  transaction and records it as ``model_revision`` with ``identity_assurance
  = provider_digest``; a model the provider does not list is refused (422),
  an unreachable provider is ``503``;
* **in the scheduler** (:meth:`DigestReader.recheck`, run by ``T33a``) — each
  enabled, unflagged digest-pinned model is compared with the listing again;
  a different digest or a model no longer listed **flags** the model (audited),
  and every reservation and marker then refuses it until the superuser
  registers a new row. An unreachable provider or a malformed listing changes
  nothing: it is not evidence of a swap.

A provider behind an authenticating proxy is read with the platform's own
active credential for that provider (a global-scope key), never a tenant's
or a user's.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import groupby
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import (
    AuthType,
    CredentialStatus,
    ProviderType,
    ScopeType,
)
from ai_sdk_m8.schemas import IdentityAssurance
from pydantic import JsonValue
from sqlalchemy import Engine, RowMapping

from ai_gateway.core.errors import GatewayError
from ai_gateway.credentials.store import CredentialStore, ResolvedSecret
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import ai_model, ai_provider
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.http import ClientFactory, Deadline, ProviderEndpoint
from ai_gateway.providers.ollama import OllamaAdapter, digest_of

from .audit import Actor, audited_transaction
from .errors import Invalid, Unavailable

_SYSTEM = Actor("system")


@dataclass(frozen=True)
class DigestReader:
    """Reads Ollama digests through the hardened client."""

    engine: Engine
    clients: ClientFactory
    store: CredentialStore
    adapter: OllamaAdapter
    timeout_seconds: float

    # --- registration ------------------------------------------------------------

    def digest(self, provider_id: UUID, external_model_id: str) -> str | None:
        """
        The digest to record for a new or renamed model of ``provider_id``.

        ``None`` for a provider whose models carry no provider digest (every
        type but Ollama), or an unknown provider (the registry refuses it).
        """
        provider = self._provider(provider_id)
        if provider is None or provider["provider_type"] != ProviderType.OLLAMA.value:
            return None
        try:
            tags = asyncio.run(self._tags(provider))
        except (ProviderFailure, GatewayError):
            raise Unavailable(
                "the provider could not be reached to read the model's digest"
            ) from None
        try:
            digest = digest_of(tags, external_model_id)
        except ProviderFailure:
            raise Unavailable("the provider's model listing is malformed") from None
        if digest is None:
            raise Invalid("the provider does not list this model")
        return digest

    def digest_for_update(
        self, model_id: UUID, external_model_id: str | None
    ) -> str | None:
        """The digest of a renamed digest-pinned model, read before the change."""
        if external_model_id is None:
            return None
        with self.engine.connect() as connection:
            provider_id = connection.execute(
                sa.select(ai_model.c.provider_id).where(ai_model.c.id == model_id)
            ).scalar_one_or_none()
        if provider_id is None:
            return None
        return self.digest(provider_id, external_model_id)

    # --- the scheduler's re-check ----------------------------------------------

    async def recheck(
        self, *, fence: sa.ColumnElement[bool] | None = None
    ) -> list[UUID]:
        """Flag every digest-pinned model whose listing changed; the ids flagged."""
        flagged: list[UUID] = []
        rows = await asyncio.to_thread(self._pinned_models)
        for _provider_id, group in groupby(rows, key=lambda row: row["provider_id"]):
            models = list(group)
            try:
                tags = await self._tags(models[0])
            except (ProviderFailure, GatewayError, Invalid):
                continue  # unreachable is not evidence of a swap
            for model, listed in self._changed(tags, models):
                if await asyncio.to_thread(self._flag, model, listed, fence):
                    flagged.append(model["id"])
        return flagged

    def _changed(
        self, tags: JsonValue, models: Sequence[RowMapping]
    ) -> list[tuple[RowMapping, str | None]]:
        changed: list[tuple[RowMapping, str | None]] = []
        for model in models:
            try:
                listed = digest_of(tags, model["external_model_id"])
            except ProviderFailure:
                return []  # a malformed listing decides nothing
            if listed != model["model_revision"]:
                changed.append((model, listed))
        return changed

    def _pinned_models(self) -> list[RowMapping]:
        m, p = ai_model, ai_provider
        statement = (
            sa.select(
                m.c.id,
                m.c.external_model_id,
                m.c.model_revision,
                p.c.id.label("provider_id"),
                p.c.provider_type,
                p.c.base_url,
                p.c.boundary,
                p.c.auth_type,
                p.c.auth_header_name,
            )
            .join(p, p.c.id == m.c.provider_id)
            .where(
                p.c.provider_type == ProviderType.OLLAMA.value,
                m.c.identity_assurance == IdentityAssurance.PROVIDER_DIGEST.value,
                m.c.enabled.is_(True),
                m.c.flagged_at.is_(None),
            )
            .order_by(p.c.id, m.c.id)
        )
        with self.engine.connect() as connection:
            return list(connection.execute(statement).mappings())

    def _flag(
        self,
        model: RowMapping,
        listed: str | None,
        fence: sa.ColumnElement[bool] | None,
    ) -> bool:
        where = sa.and_(ai_model.c.id == model["id"], ai_model.c.flagged_at.is_(None))
        if fence is not None:
            where = sa.and_(where, fence)
        with audited_transaction(self.engine) as tx:
            row = tx.connection.execute(
                sa.update(ai_model)
                .where(where)
                .values(flagged_at=sa.func.now(), updated_at=sa.func.now())
                .returning(ai_model.c.id)
            ).first()
            if row is None:
                return False
            tx.admin(
                _SYSTEM,
                "model.flagged",
                "model",
                model["id"],
                {
                    "reason": "digest_changed" if listed else "not_listed",
                    "recorded": model["model_revision"],
                    "listed": listed,
                },
            )
        return True

    # --- reading the listing --------------------------------------------------------

    def _provider(self, provider_id: UUID) -> RowMapping | None:
        with self.engine.connect() as connection:
            return (
                connection.execute(
                    sa.select(
                        ai_provider.c.id.label("provider_id"),
                        ai_provider.c.provider_type,
                        ai_provider.c.base_url,
                        ai_provider.c.boundary,
                        ai_provider.c.auth_type,
                        ai_provider.c.auth_header_name,
                    ).where(ai_provider.c.id == provider_id)
                )
                .mappings()
                .first()
            )

    def _platform_credential(self, provider_id: UUID) -> tuple[UUID, int] | None:
        c = ai_credential
        with self.engine.connect() as connection:
            row = connection.execute(
                sa.select(c.c.id, c.c.current_version)
                .where(
                    c.c.provider_id == provider_id,
                    c.c.scope_type == ScopeType.GLOBAL.value,
                    c.c.status == CredentialStatus.ACTIVE.value,
                )
                .order_by(c.c.created_at.desc())
                .limit(1)
            ).first()
        return None if row is None else (row[0], int(row[1]))

    def _secret(self, stack: ExitStack, provider: RowMapping) -> ResolvedSecret | None:
        if provider["auth_type"] == AuthType.NONE.value:
            return None
        credential = self._platform_credential(provider["provider_id"])
        if credential is None:
            raise Invalid(
                "this provider authenticates; reading its digest needs an active "
                "platform credential for it"
            )
        return stack.enter_context(self.store.resolve_for_execution(*credential))

    async def _tags(self, provider: RowMapping) -> JsonValue:
        endpoint = ProviderEndpoint.from_row(
            {**provider, "id": provider["provider_id"]}
        )
        with ExitStack() as stack:
            secret = await asyncio.to_thread(self._secret, stack, provider)
            async with self.clients.client(endpoint) as client:
                return await self.adapter.tags(
                    client, secret, Deadline.after(self.timeout_seconds)
                )


__all__ = ["DigestReader"]

"""
A world for the execution-core tests (T27): registry rows, real credentials,
signed contexts, recording adapters, services and row ageing.

Credentials are stored through the shipped ``DatabaseCredentialStore``, so a
material fetch decrypts a real envelope. Contexts are minted by an issuer and
verified by the shipped verifier, so every principal is one the execution
guard would have produced.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
import sqlalchemy as sa
from ai_sdk_m8.schemas import (
    Capability,
    DataClass,
    EmbedRequest,
    ProviderBoundary,
    ProviderUsage,
    RerankRequest,
    StructuredOutputRequest,
)
from ai_sdk_m8.schemas.management import ProviderType, ScopeType
from pydantic import JsonValue, SecretStr

from ai_gateway.controllers.resolution import ResolutionPolicy
from ai_gateway.core import deps
from ai_gateway.core.job_context import JobContextPrincipal
from ai_gateway.core.policy import DEFAULT_POLICY, DataClassPolicy
from ai_gateway.credentials.store import CredentialIdentity, ResolvedSecret
from ai_gateway.db_models.accounting import (
    ai_client_occupancy,
    ai_execution,
    ai_rate_window,
    ai_usage,
)
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.execution.jobs import EmbedJob, RerankJob, StructuredOutputJob
from ai_gateway.execution.limits import ExecutionLimits
from ai_gateway.execution.service import ExecutionService
from ai_gateway.providers.base import (
    AdapterCall,
    EmbedOutput,
    RerankOutput,
    StructuredOutput,
)
from ai_gateway.providers.breaker import Breakers
from ai_gateway.providers.http import ClientFactory, ProviderEndpoint
from conftest import MEDIA_SERVICE
from job_contexts import mint
from provider_stubs import LIMITS, POLICY as DESTINATIONS, Resolver
import factories
import pg_harness as pg

TENANT_A, TENANT_B = str(uuid.uuid4()), str(uuid.uuid4())
USER_A, USER_B = str(uuid.uuid4()), str(uuid.uuid4())

BYOK_POLICY = ResolutionPolicy(
    DataClassPolicy(dict(DEFAULT_POLICY)), user_byok_enabled=True, database_backend=True
)

#: Generous bounds: tests that need a bound set their own.
OPEN = ExecutionLimits(reservation_ttl_seconds=60, total_deadline_seconds=30)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- registry rows -----------------------------------------------------------------


def owner() -> sa.Engine:
    return pg.owner_engine()


@contextmanager
def as_owner() -> Iterator[sa.Connection]:
    engine = owner()
    try:
        with engine.begin() as connection:
            yield connection
    finally:
        engine.dispose()


def make_provider(
    boundary: ProviderBoundary = ProviderBoundary.LOCAL,
    provider_type: ProviderType = ProviderType.OLLAMA,
    **values: Any,
) -> uuid.UUID:
    base_url = (
        "http://ollama:11434"
        if boundary is ProviderBoundary.LOCAL
        else "https://api.provider.test"
    )
    auth_type = "none" if provider_type is ProviderType.OLLAMA else "bearer"
    with as_owner() as c:
        return factories.provider(
            c,
            boundary=boundary.value,
            provider_type=provider_type.value,
            base_url=values.pop("base_url", base_url),
            auth_type=values.pop("auth_type", auth_type),
            **values,
        )


def make_model(
    provider_id: uuid.UUID, capability: Capability = Capability.EMBEDDING, **values: Any
) -> uuid.UUID:
    with as_owner() as c:
        return factories.model(
            c,
            provider_id,
            capabilities=[capability.value],
            dimensions=values.pop(
                "dimensions", 3 if capability is Capability.EMBEDDING else None
            ),
            external_model_id=values.pop(
                "external_model_id", f"model-{uuid.uuid4().hex[:6]}"
            ),
            **values,
        )


def make_profile(
    capability: Capability = Capability.EMBEDDING, **config: JsonValue
) -> tuple[uuid.UUID, str]:
    """A profile whose revision 1 carries ``config`` (revisions are immutable)."""
    from ai_gateway.core.identities import execution_config_hash
    from ai_gateway.db_models.registry import ai_profile, ai_profile_revision

    key = f"p{uuid.uuid4().hex[:8]}"
    profile_id = uuid.uuid4()
    with as_owner() as c:
        c.execute(
            sa.insert(ai_profile).values(
                id=profile_id,
                profile_key=key,
                capability=capability.value,
                current_revision=1,
            )
        )
        c.execute(
            sa.insert(ai_profile_revision).values(
                profile_id=profile_id,
                revision=1,
                execution_config=dict(config),
                execution_config_hash=execution_config_hash(dict(config)),
            )
        )
    return profile_id, key


def make_credential(
    provider_id: uuid.UUID,
    scope: ScopeType = ScopeType.GLOBAL,
    *,
    tenant_id: str | None = None,
    owner_user_id: str | None = None,
    secret: str | None = None,
) -> uuid.UUID:
    """A credential with a real envelope, stored through the shipped store."""
    credential_id = uuid.uuid4()
    tenant = None if tenant_id is None else uuid.UUID(tenant_id)
    user = None if owner_user_id is None else uuid.UUID(owner_user_id)
    with deps.db_engine.begin() as connection:
        connection.execute(
            sa.insert(ai_credential).values(
                id=credential_id,
                scope_type=scope.value,
                tenant_id=tenant,
                owner_user_id=user,
                provider_id=provider_id,
                name="key",
                status="provisioning",
                secret_backend="database",
            )
        )
        identity = CredentialIdentity(credential_id, provider_id, scope, tenant, user)
        deps.credential_store.store(
            connection, identity, SecretStr(secret or f"sk-{credential_id.hex}")
        )
    return credential_id


def rotate(credential_id: uuid.UUID, secret: str) -> None:
    with deps.db_engine.begin() as connection:
        row = (
            connection.execute(
                sa.select(ai_credential).where(ai_credential.c.id == credential_id)
            )
            .mappings()
            .one()
        )
        identity = CredentialIdentity(
            credential_id,
            row["provider_id"],
            ScopeType(row["scope_type"]),
            row["tenant_id"],
            row["owner_user_id"],
        )
        deps.credential_store.replace(connection, identity, SecretStr(secret))


def make_binding(
    profile_id: uuid.UUID,
    model_id: uuid.UUID,
    credential_id: uuid.UUID | None = None,
    scope: ScopeType = ScopeType.GLOBAL,
    *,
    tenant_id: str | None = None,
    owner_user_id: str | None = None,
    **values: Any,
) -> uuid.UUID:
    with as_owner() as c:
        binding_id = factories.binding(
            c,
            profile_id,
            model_id,
            credential_id,
            scope_type=scope.value,
            tenant_id=None if tenant_id is None else uuid.UUID(tenant_id),
            owner_user_id=None if owner_user_id is None else uuid.UUID(owner_user_id),
        )
        if values:
            from ai_gateway.db_models.registry import ai_profile_binding

            c.execute(
                sa.update(ai_profile_binding)
                .where(ai_profile_binding.c.id == binding_id)
                .values(**values)
            )
    return binding_id


def update(table: sa.Table, row_id: uuid.UUID, **values: Any) -> None:
    with as_owner() as c:
        c.execute(sa.update(table).where(table.c.id == row_id).values(**values))


@dataclass(frozen=True)
class World:
    """One provider, model, profile and global binding (and credential)."""

    provider_id: uuid.UUID
    model_id: uuid.UUID
    profile_id: uuid.UUID
    profile_key: str
    binding_id: uuid.UUID
    credential_id: uuid.UUID | None


def world(
    capability: Capability = Capability.EMBEDDING,
    *,
    boundary: ProviderBoundary = ProviderBoundary.LOCAL,
    provider_type: ProviderType | None = None,
    keyed: bool | None = None,
    **config: JsonValue,
) -> World:
    if provider_type is None:
        provider_type = (
            ProviderType.OLLAMA
            if boundary is ProviderBoundary.LOCAL
            else ProviderType.OPENAI_COMPATIBLE
        )
    provider_id = make_provider(boundary, provider_type)
    model_id = make_model(provider_id, capability)
    profile_id, key = make_profile(capability, **config)
    if keyed is None:
        keyed = provider_type is not ProviderType.OLLAMA
    credential_id = make_credential(provider_id) if keyed else None
    binding_id = make_binding(profile_id, model_id, credential_id)
    return World(provider_id, model_id, profile_id, key, binding_id, credential_id)


# --- contexts -----------------------------------------------------------------------


def principal(
    profile_key: str,
    capability: Capability = Capability.EMBEDDING,
    *,
    data_class: DataClass = DataClass.INTERNAL,
    tenant_id: str | None = None,
    user_id: str | None = None,
    **claims: object,
) -> JobContextPrincipal:
    """A context minted by media-service and verified as the guard would."""
    token = mint(
        MEDIA_SERVICE,
        capability=capability.value,
        profile_key=profile_key,
        data_class=data_class.value,
        tenant_id=tenant_id,
        user_id=user_id,
        **claims,
    )
    return deps.job_contexts.verify(
        token, presenter=MEDIA_SERVICE.client_id, capability=capability
    )


def embed_job(profile_key: str, inputs: Sequence[str] = ("hello", "world")) -> EmbedJob:
    return EmbedJob(EmbedRequest(profile_key=profile_key, inputs=tuple(inputs)))


def rerank_job(
    profile_key: str, documents: Sequence[str] = ("a", "bb", "ccc")
) -> RerankJob:
    return RerankJob(
        RerankRequest(profile_key=profile_key, query="q?", documents=tuple(documents))
    )


def structured_job(profile_key: str, text: str = "invoice 42") -> StructuredOutputJob:
    return StructuredOutputJob(
        StructuredOutputRequest(
            profile_key=profile_key,
            input=text,
            schema_name="Invoice",
            json_schema={"type": "object"},
        )
    )


# --- adapters -------------------------------------------------------------------------


@dataclass
class Seen:
    """One adapter invocation as the adapter received it."""

    capability: Capability
    endpoint: ProviderEndpoint
    external_model_id: str
    secret: str | None
    config: Mapping[str, JsonValue]


@dataclass
class StubAdapter:
    """A recording adapter; ``behave`` may await, raise or return an output."""

    provider_type: ProviderType = ProviderType.OLLAMA
    capabilities: frozenset[Capability] = frozenset(
        {Capability.EMBEDDING, Capability.RERANK, Capability.STRUCTURED_OUTPUT}
    )
    behave: Callable[[AdapterCall, Capability], Any] | None = None
    calls: list[Seen] = field(default_factory=list)

    async def _invoke(self, call: AdapterCall, capability: Capability) -> Any:
        secret = None if call.secret is None else call.secret.reveal()
        self.calls.append(
            Seen(
                capability,
                call.client.endpoint,
                call.model.external_model_id,
                secret,
                dict(call.config),
            )
        )
        if self.behave is not None:
            outcome = self.behave(call, capability)
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
            if outcome is not None:
                return outcome
        return None

    async def embed(self, call: AdapterCall, inputs: Sequence[str]) -> EmbedOutput:
        outcome = await self._invoke(call, Capability.EMBEDDING)
        if outcome is not None:
            return outcome  # type: ignore[no-any-return]
        dims = call.model.dimensions or 0
        vectors = [[float(i + 1)] * dims for i in range(len(inputs))]
        return EmbedOutput(vectors, ProviderUsage(input_tokens=len(inputs)))

    async def rerank(
        self, call: AdapterCall, query: str, documents: Sequence[str], top_n: int | None
    ) -> RerankOutput:
        outcome = await self._invoke(call, Capability.RERANK)
        if outcome is not None:
            return outcome  # type: ignore[no-any-return]
        return RerankOutput(tuple((i, 1.0 / (i + 1)) for i in range(len(documents))))

    async def structured_output(
        self,
        call: AdapterCall,
        text: str,
        schema_name: str,
        json_schema: Mapping[str, JsonValue],
        max_output_tokens: int,
    ) -> StructuredOutput:
        outcome = await self._invoke(call, Capability.STRUCTURED_OUTPUT)
        if outcome is not None:
            return outcome  # type: ignore[no-any-return]
        return StructuredOutput({"cap": max_output_tokens, "schema": schema_name})


# --- stores -----------------------------------------------------------------------------


class HookedStore:
    """The shipped store, with a hook run before each material fetch."""

    def __init__(self, hook: Callable[[uuid.UUID, int], None] | None = None) -> None:
        self.hook = hook
        self.fetched: list[tuple[uuid.UUID, int]] = []
        self.backend = deps.credential_store.backend

    def resolve_for_execution(
        self, credential_id: uuid.UUID, version: int
    ) -> AbstractContextManager[ResolvedSecret]:
        @contextmanager
        def fetch() -> Iterator[ResolvedSecret]:
            self.fetched.append((credential_id, version))
            if self.hook is not None:
                self.hook(credential_id, version)
            with deps.credential_store.resolve_for_execution(
                credential_id, version
            ) as s:
                yield s

        return fetch()

    def __getattr__(self, name: str) -> Any:
        return getattr(deps.credential_store, name)


# --- services ----------------------------------------------------------------------------


def clients(
    transport: Callable[[ProviderEndpoint], httpx.AsyncBaseTransport] | None = None,
    breakers: Breakers | None = None,
) -> ClientFactory:
    return ClientFactory(
        DESTINATIONS,
        LIMITS,
        breakers or Breakers(),
        resolver=Resolver(),
        transport=transport or (lambda _e: httpx.MockTransport(_unreachable)),
    )


async def _unreachable(_request: httpx.Request) -> httpx.Response:
    raise AssertionError("a stub adapter made an unexpected HTTP request")


def service(
    *adapters: StubAdapter,
    limits: ExecutionLimits = OPEN,
    policy: ResolutionPolicy = BYOK_POLICY,
    store: Any = None,
    engine: sa.Engine | None = None,
    factory: ClientFactory | None = None,
    breakers: Breakers | None = None,
    deployment_id: str | None = None,
    receipts: Any = None,
) -> ExecutionService:
    registry = {adapter.provider_type: adapter for adapter in adapters}
    breakers = breakers or Breakers()
    return ExecutionService(
        engine or deps.db_engine,
        store or deps.credential_store,
        factory or clients(breakers=breakers),
        registry,  # type: ignore[arg-type]
        policy=lambda: policy,
        limits=lambda: limits,
        breakers=breakers,
        deployment_id=deployment_id,
        receipts=receipts,
    )


def replica() -> sa.Engine:
    """A second replica's engine: its own pool, the same database."""
    return sa.create_engine(pg.runtime_url(), pool_size=20, max_overflow=20)


# --- reading and ageing rows ----------------------------------------------------------------


def execution(execution_id: uuid.UUID) -> Mapping[str, Any]:
    with deps.db_engine.connect() as c:
        return (
            c.execute(sa.select(ai_execution).where(ai_execution.c.id == execution_id))
            .mappings()
            .one()
        )


def executions() -> list[Mapping[str, Any]]:
    with deps.db_engine.connect() as c:
        return list(
            c.execute(
                sa.select(ai_execution).order_by(ai_execution.c.created_at)
            ).mappings()
        )


def usage(scope_type: str, scope_id: str) -> tuple[int, int]:
    """``(reserved, used)`` summed over every day of a scope."""
    with deps.db_engine.connect() as c:
        row = c.execute(
            sa.select(
                sa.func.coalesce(sa.func.sum(ai_usage.c.reserved), 0),
                sa.func.coalesce(sa.func.sum(ai_usage.c.used), 0),
            ).where(
                ai_usage.c.scope_type == scope_type, ai_usage.c.scope_id == scope_id
            )
        ).one()
    return int(row[0]), int(row[1])


def occupied(client_id: str = MEDIA_SERVICE.client_id) -> int:
    with deps.db_engine.connect() as c:
        value = c.execute(
            sa.select(ai_client_occupancy.c.occupied).where(
                ai_client_occupancy.c.client_id == client_id
            )
        ).scalar_one_or_none()
    return int(value or 0)


def admissions(principal_key: str) -> int:
    with deps.db_engine.connect() as c:
        value = c.execute(
            sa.select(sa.func.coalesce(sa.func.sum(ai_rate_window.c.count), 0)).where(
                ai_rate_window.c.principal_key == principal_key
            )
        ).scalar_one()
    return int(value)


def age(execution_id: uuid.UUID, **values: Any) -> None:
    """Rewrite stored timestamps (and days) as a crash or a pause would leave them.

    Runs as the database superuser with triggers off, so even the recorded
    budget day can be moved back to simulate a reservation made yesterday.
    """
    admin = pg.admin_engine(pg.DB_NAME)
    try:
        with admin.connect() as c:
            c.execute(sa.text("SET session_replication_role = replica"))
            c.execute(
                sa.update(ai_execution)
                .where(ai_execution.c.id == execution_id)
                .values(**values)
            )
            if "reservation_day" in values:
                row = (
                    c.execute(
                        sa.select(ai_execution).where(ai_execution.c.id == execution_id)
                    )
                    .mappings()
                    .one()
                )
                for scope_type, column in (
                    ("client", "client_scope_id"),
                    ("tenant", "tenant_scope_id"),
                    ("user", "user_scope_id"),
                ):
                    if row[column] is None:
                        continue
                    _move_reservation(
                        c,
                        scope_type,
                        row[column],
                        row["reserved_units"],
                        values["reservation_day"],
                    )
    finally:
        admin.dispose()


def _move_reservation(
    c: sa.Connection, scope_type: str, scope_id: str, units: int, day: Any
) -> None:
    today = sa.cast(sa.func.timezone("UTC", sa.func.now()), sa.Date)
    c.execute(
        sa.update(ai_usage)
        .where(
            ai_usage.c.scope_type == scope_type,
            ai_usage.c.scope_id == scope_id,
            ai_usage.c.day == today,
        )
        .values(reserved=ai_usage.c.reserved - units)
    )
    c.execute(
        sa.dialects.postgresql.insert(ai_usage)
        .values(
            scope_type=scope_type, scope_id=scope_id, day=day, reserved=units, used=0
        )
        .on_conflict_do_update(
            index_elements=["scope_type", "scope_id", "day"],
            set_={"reserved": ai_usage.c.reserved + units},
        )
    )


__all__ = [name for name in dir() if not name.startswith("_")]

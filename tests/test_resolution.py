"""
Tenant and user bindings (T20a) and the C-04 / D-08 resolution through them.

Credentials and bindings are created through the shipped routes; providers,
models and profiles come from the registry factories so a ``local``
provider needs no allowlist here. ``resolve`` is the function the
reservation (``T27``) calls; it makes no provider request.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass, ProviderBoundary
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from ai_gateway import main
from ai_gateway.controllers.audit import audited_transaction
from ai_gateway.controllers.resolution import (
    ExecutionRequest,
    Resolution,
    ResolutionPolicy,
    candidate_scopes,
    resolve,
)
from ai_gateway.core import deps, identities
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.policy import DEFAULT_POLICY, DataClassPolicy, Destination
from ai_gateway.db_models.audit import ai_admin_audit
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_binding,
    ai_provider,
)
from conftest import bearer
import factories

pytestmark = pytest.mark.usefixtures("clean_db")

PREFIX = f"{settings.API_PREFIX}/v1"
TENANT_A, TENANT_B = uuid.uuid4(), uuid.uuid4()
USER_A, USER_B = uuid.uuid4(), uuid.uuid4()
SU = bearer("superadmin")
ADMIN_A = bearer("admin", tenant_id=str(TENANT_A))
ADMIN_B = bearer("admin", tenant_id=str(TENANT_B))
WRITER_A = bearer("writer", subject=USER_A, tenant_id=str(TENANT_A))
WRITER_B = bearer("writer", subject=USER_B, tenant_id=str(TENANT_A))
ME, GLOBAL = f"{PREFIX}/me", f"{PREFIX}/admin"
TENANT_A_BASE, TENANT_B_BASE = (
    f"{PREFIX}/tenants/{TENANT_A}",
    f"{PREFIX}/tenants/{TENANT_B}",
)

POLICY = ResolutionPolicy(
    DataClassPolicy(dict(DEFAULT_POLICY)), user_byok_enabled=True, database_backend=True
)


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def byok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", True)


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json() if response.content else None


class World:
    """An external and a local provider, a model on each, and profiles."""

    def __init__(self) -> None:
        with deps.db_engine.begin() as c:
            self.external = factories.provider(c, name="ext", boundary="external")
            self.local = factories.provider(
                c, name="loc", boundary="local", base_url="http://ollama:11434"
            )
            self.models = {
                provider: factories.model(
                    c,
                    provider,
                    capabilities=["embedding", "rerank", "ocr"],
                    execution_identity=identities.execution_identity(
                        provider, "embed-small", None
                    ),
                )
                for provider in (self.external, self.local)
            }
            self.embed = factories.profile(c, "embed", "embedding")
            factories.profile(c, "rank", "rerank")
            factories.profile(c, "read", "ocr")


@pytest.fixture
def world() -> World:
    return World()


def credential(
    client: TestClient,
    base: str,
    headers: dict[str, str],
    provider: uuid.UUID,
    n: int = 0,
) -> str:
    body = {
        "provider_id": str(provider),
        "name": f"k{n}",
        "secret": f"sk-{n}-{uuid.uuid4().hex}",
    }
    return str(
        _ok(client.post(f"{base}/credentials", json=body, headers=headers), 201)["id"]
    )


def bind(
    client: TestClient,
    base: str,
    headers: dict[str, str],
    model: uuid.UUID,
    credential_id: str | None,
    profile_key: str = "embed",
    on_unavailable: str = "fail",
) -> Any:
    body: dict[str, object] = {
        "profile_key": profile_key,
        "model_id": str(model),
        "on_unavailable": on_unavailable,
    }
    if credential_id is not None:
        body["credential_id"] = credential_id
    return client.post(f"{base}/bindings", json=body, headers=headers)


def bound(
    client: TestClient,
    base: str,
    headers: dict[str, str],
    model: uuid.UUID,
    credential_id: str | None,
    **kw: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = _ok(
        bind(client, base, headers, model, credential_id, **kw), 201
    )
    return result


def request(
    tenant: uuid.UUID | None = TENANT_A,
    user: uuid.UUID | None = USER_A,
    *,
    profile_key: str = "embed",
    capability: Capability = Capability.EMBEDDING,
    data_class: DataClass = DataClass.INTERNAL,
    allowed: tuple[ProviderBoundary, ...] | None = None,
) -> ExecutionRequest:
    return ExecutionRequest(
        profile_key=profile_key,
        capability=capability,
        data_class=data_class,
        tenant_id=None if tenant is None else str(tenant),
        user_id=None if user is None else str(user),
        allowed_boundaries=allowed,
    )


def resolved(req: ExecutionRequest, policy: ResolutionPolicy = POLICY) -> Resolution:
    with audited_transaction(deps.db_engine) as tx:
        return resolve(tx, req, policy)


def refused(
    req: ExecutionRequest, code: AiErrorCode, policy: ResolutionPolicy = POLICY
) -> GatewayError:
    with pytest.raises(GatewayError) as error:
        resolved(req, policy)
    assert error.value.code is code
    return error.value


def fall_throughs() -> list[dict[str, Any]]:
    with deps.db_engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                select(ai_admin_audit.c.actor_kind, ai_admin_audit.c.metadata)
                .where(ai_admin_audit.c.action == "binding.fall_through")
                .order_by(ai_admin_audit.c.id)
            ).mappings()
        ]


def set_credential(credential_id: str, **values: Any) -> None:
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_credential)
            .where(ai_credential.c.id == uuid.UUID(credential_id))
            .values(**values)
        )


def verb(
    client: TestClient,
    base: str,
    credential_id: str,
    name: str,
    headers: dict[str, str],
    **kw: Any,
) -> Any:
    return _ok(
        client.post(f"{base}/credentials/{credential_id}:{name}", headers=headers, **kw)
    )


# --- binding CRUD in the tenant and user scopes ---------------------------------


@pytest.mark.parametrize(
    ("base", "headers", "other_headers"),
    [(TENANT_A_BASE, ADMIN_A, ADMIN_B), (ME, WRITER_A, WRITER_B)],
    ids=["tenant", "user"],
)
def test_binding_crud_per_scope(
    client: TestClient,
    world: World,
    base: str,
    headers: dict[str, str],
    other_headers: dict[str, str],
) -> None:
    key = credential(client, base, headers, world.external)
    created = bound(client, base, headers, world.models[world.external], key)
    scope = "tenant" if base == TENANT_A_BASE else "user"
    assert (created["scope_type"], created["status"], created["on_unavailable"]) == (
        scope,
        "active",
        "fail",
    )
    if scope == "user":
        assert (created["owner_user_id"], created["tenant_id"]) == (
            str(USER_A),
            str(TENANT_A),
        )
    assert _ok(client.get(f"{base}/bindings", headers=headers)) == [created]
    assert (
        _ok(client.get(f"{base}/bindings/{created['id']}", headers=headers)) == created
    )
    moved = _ok(
        client.patch(
            f"{base}/bindings/{created['id']}",
            json={"on_unavailable": "fall_through"},
            headers=headers,
        )
    )
    assert moved["on_unavailable"] == "fall_through"
    other_base = TENANT_B_BASE if scope == "tenant" else ME
    for method in ("GET", "PATCH", "DELETE"):
        response = client.request(
            method,
            f"{other_base}/bindings/{created['id']}",
            headers=other_headers,
            json={"on_unavailable": "fail"},
        )
        assert response.status_code == 404
    assert (
        bind(client, base, headers, world.models[world.external], key).status_code
        == 409
    )
    _ok(client.delete(f"{base}/bindings/{created['id']}", headers=headers), 204)
    with deps.db_engine.connect() as connection:
        actions = list(
            connection.execute(
                select(ai_admin_audit.c.action).where(
                    ai_admin_audit.c.target_type == "binding"
                )
            ).scalars()
        )
    assert actions == ["binding.create", "binding.update", "binding.delete"]


def test_a_binding_names_only_the_scopes_own_credential(
    client: TestClient, world: World
) -> None:
    model = world.models[world.external]
    tenant_a_key = credential(client, TENANT_A_BASE, ADMIN_A, world.external)
    tenant_b_key = credential(client, TENANT_B_BASE, ADMIN_B, world.external, 1)
    user_a_key = credential(client, ME, WRITER_A, world.external, 2)
    user_b_key = credential(client, ME, WRITER_B, world.external, 3)
    global_key = credential(client, GLOBAL, SU, world.external, 4)
    for base, headers, foreign in (
        (
            TENANT_A_BASE,
            ADMIN_A,
            [tenant_b_key, user_a_key, global_key, str(uuid.uuid4())],
        ),
        (ME, WRITER_A, [user_b_key, tenant_a_key, global_key, str(uuid.uuid4())]),
    ):
        answers = {bind(client, base, headers, model, key).text for key in foreign}
        assert len(answers) == 1  # one answer for every foreign or missing id
        for key in foreign:
            assert bind(client, base, headers, model, key).status_code == 422
    local_key = credential(client, ME, WRITER_A, world.local, 5)
    assert bind(client, ME, WRITER_A, model, local_key).status_code == 422
    for field in ("owner_user_id", "tenant_id", "scope_type"):
        body = {
            "profile_key": "embed",
            "model_id": str(model),
            "credential_id": user_a_key,
            field: str(USER_B),
        }
        assert (
            client.post(f"{ME}/bindings", json=body, headers=WRITER_A).status_code
            == 422
        )


def test_user_bindings_follow_the_byok_flag(
    client: TestClient, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = credential(client, ME, WRITER_A, world.external)
    created = bound(client, ME, WRITER_A, world.models[world.external], key)
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", False)
    assert (
        bind(
            client, ME, WRITER_A, world.models[world.local], None, profile_key="rank"
        ).status_code
        == 403
    )
    path = f"{ME}/bindings/{created['id']}"
    assert (
        client.patch(
            path, json={"on_unavailable": "fall_through"}, headers=WRITER_A
        ).status_code
        == 403
    )
    assert _ok(client.get(f"{ME}/bindings", headers=WRITER_A)) == [created]
    _ok(client.delete(path, headers=WRITER_A), 204)


# --- the lifecycle through resolution, both scopes ----------------------------------


@pytest.mark.parametrize(
    ("base", "headers"),
    [(TENANT_A_BASE, ADMIN_A), (ME, WRITER_A)],
    ids=["tenant", "user"],
)
def test_create_bind_resolve_rotate_disable_delete(
    client: TestClient, world: World, base: str, headers: dict[str, str]
) -> None:
    key = credential(client, base, headers, world.external)
    bound(client, base, headers, world.models[world.external], key)
    first = resolved(request())
    assert (str(first.credential_id), first.credential_version, first.destination) == (
        key,
        1,
        Destination.EXTERNAL_BYOK,
    )
    verb(
        client,
        base,
        key,
        "rotate",
        headers,
        json={"secret": "sk-rotated-" + uuid.uuid4().hex},
    )
    assert resolved(request()).credential_version == 2
    verb(client, base, key, "disable", headers)
    refused(request(), AiErrorCode.CREDENTIAL_UNAVAILABLE)
    verb(client, base, key, "enable", headers)
    assert resolved(request()).credential_version == 2
    _ok(client.delete(f"{base}/credentials/{key}", headers=headers), 204)
    refused(request(), AiErrorCode.CREDENTIAL_UNAVAILABLE)
    status = _ok(client.get(f"{base}/bindings", headers=headers))[0]["status"]
    assert status == "credential_unavailable"


# --- precedence (C-04, N-07) --------------------------------------------------------


def _three_scopes(client: TestClient, world: World, **kw: Any) -> dict[str, str]:
    model = world.models[world.external]
    keys = {
        "user": credential(client, ME, WRITER_A, world.external, 1),
        "tenant": credential(client, TENANT_A_BASE, ADMIN_A, world.external, 2),
        "global": credential(client, GLOBAL, SU, world.external, 3),
    }
    bound(client, ME, WRITER_A, model, keys["user"], **kw)
    bound(client, TENANT_A_BASE, ADMIN_A, model, keys["tenant"], **kw)
    bound(client, GLOBAL, SU, model, keys["global"])
    return keys


def test_the_user_binding_wins_then_the_tenant_then_the_global(
    client: TestClient, world: World
) -> None:
    keys = _three_scopes(client, world)
    public = DataClass.PUBLIC
    assert str(resolved(request(data_class=public)).credential_id) == keys["user"]
    assert (
        str(resolved(request(user=None, data_class=public)).credential_id)
        == keys["tenant"]
    )
    assert (
        str(resolved(request(TENANT_B, None, data_class=public)).credential_id)
        == keys["global"]
    )
    assert (
        str(resolved(request(None, None, data_class=public)).credential_id)
        == keys["global"]
    )


def test_a_users_binding_serves_only_its_own_tenant_and_user(
    client: TestClient, world: World
) -> None:
    keys = _three_scopes(client, world)
    # The same user signed into another tenant: not this user binding.
    other_tenant = resolved(request(TENANT_B, USER_A, data_class=DataClass.PUBLIC))
    assert str(other_tenant.credential_id) == keys["global"]
    # Another user of the same tenant: the tenant binding.
    other_user = resolved(request(TENANT_A, USER_B, data_class=DataClass.PUBLIC))
    assert str(other_user.credential_id) == keys["tenant"]


def test_candidate_scopes_come_from_well_formed_signed_claims_only() -> None:
    assert [s.scope_type.value for s in candidate_scopes(request())] == [
        "user",
        "tenant",
        "global",
    ]
    malformed = ExecutionRequest(
        "embed", Capability.EMBEDDING, DataClass.PUBLIC, "tenant-x", str(USER_A)
    )
    assert [s.scope_type.value for s in candidate_scopes(malformed)] == ["global"]
    no_tenant = ExecutionRequest(
        "embed", Capability.EMBEDDING, DataClass.PUBLIC, None, str(USER_A)
    )
    assert [(s.scope_type.value, s.tenant_id) for s in candidate_scopes(no_tenant)] == [
        ("user", None),
        ("global", None),
    ]


# --- unavailable credentials (C-04) -----------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        {"status": "disabled"},
        {"status": "invalid"},
        {"status": "reconfirm_required"},
        {"status": "deleted", "deleted_at": func.now()},
    ],
    ids=["disabled", "invalid", "reconfirm", "deleted"],
)
@pytest.mark.parametrize("scope", ["user", "tenant"])
def test_an_unavailable_bound_key_fails_closed_by_default(
    client: TestClient, world: World, state: dict[str, Any], scope: str
) -> None:
    keys = _three_scopes(client, world)
    set_credential(keys[scope], **state)
    req = request(user=USER_A if scope == "user" else None, data_class=DataClass.PUBLIC)
    refused(req, AiErrorCode.CREDENTIAL_UNAVAILABLE)
    assert fall_throughs() == []


def test_a_throttled_key_is_rate_limited_with_retry_after(
    client: TestClient, world: World
) -> None:
    keys = _three_scopes(client, world)
    set_credential(
        keys["user"],
        throttled_until=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, 42),
    )
    error = refused(request(data_class=DataClass.PUBLIC), AiErrorCode.RATE_LIMITED)
    assert (
        error.retry_after_seconds is not None and 1 <= error.retry_after_seconds <= 42
    )


def test_fall_through_follows_user_tenant_global_with_an_audit_row(
    client: TestClient, world: World
) -> None:
    keys = _three_scopes(client, world, on_unavailable="fall_through")
    public = request(data_class=DataClass.PUBLIC)
    set_credential(keys["user"], status="disabled")
    assert str(resolved(public).credential_id) == keys["tenant"]
    set_credential(
        keys["tenant"],
        throttled_until=func.now() + func.make_interval(0, 0, 0, 0, 0, 1),
    )
    assert str(resolved(public).credential_id) == keys["global"]
    reasons = [
        (row["actor_kind"], row["metadata"]["scope_type"], row["metadata"]["reason"])
        for row in fall_throughs()
    ]
    assert reasons == [
        ("system", "user", "credential_disabled"),
        ("system", "user", "credential_disabled"),
        ("system", "tenant", "credential_throttled"),
    ]


def test_each_candidate_is_judged_by_d08_and_a_denial_is_terminal(
    client: TestClient, world: World
) -> None:
    keys = _three_scopes(client, world, on_unavailable="fall_through")
    set_credential(keys["user"], status="disabled")
    # The tenant candidate is external: a local-only claim is refused there,
    # never retried against the next scope (N-06).
    refused(request(allowed=(ProviderBoundary.LOCAL,)), AiErrorCode.BOUNDARY_DENIED)
    set_credential(keys["tenant"], status="disabled")
    # The global candidate is a platform key: internal data never reaches it.
    refused(request(data_class=DataClass.INTERNAL), AiErrorCode.DATA_CLASS_DENIED)
    assert (
        resolved(request(data_class=DataClass.PUBLIC)).destination
        is Destination.EXTERNAL_PLATFORM
    )


def test_a_superuser_stopped_user_key_takes_the_same_path(
    client: TestClient, world: World
) -> None:
    keys = _three_scopes(client, world)
    _ok(client.post(f"{GLOBAL}/user-credentials/{keys['user']}:disable", headers=SU))
    refused(request(data_class=DataClass.PUBLIC), AiErrorCode.CREDENTIAL_UNAVAILABLE)


def test_byok_off_holds_user_bindings_unavailable_and_health_reports_them(
    client: TestClient, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = _three_scopes(client, world)
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", False)
    off = replace(POLICY, user_byok_enabled=False)
    # Never a silent move to the tenant's key.
    refused(
        request(data_class=DataClass.PUBLIC), AiErrorCode.CREDENTIAL_UNAVAILABLE, off
    )
    health = asyncio.run(main.check_user_bindings())
    assert (health.status, health.meta) == (
        "degraded",
        {"user_byok_enabled": False, "held_unavailable": 1},
    )
    # With fall_through set by its owner, the tenant binding serves.
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_profile_binding)
            .where(ai_profile_binding.c.scope_type == "user")
            .values(on_unavailable="fall_through")
        )
    assert (
        str(resolved(request(data_class=DataClass.PUBLIC), off).credential_id)
        == keys["tenant"]
    )
    assert fall_throughs()[0]["metadata"]["reason"] == "user_byok_disabled"


def test_health_reports_no_held_bindings_when_byok_is_on_or_none_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    on = asyncio.run(main.check_user_bindings())
    assert (on.status, on.meta) == ("ok", {"user_byok_enabled": True})
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", False)
    off = asyncio.run(main.check_user_bindings())
    assert (off.status, off.meta) == (
        "ok",
        {"user_byok_enabled": False, "held_unavailable": 0},
    )

    def broken() -> Any:
        raise OSError("db down at 10.0.0.1")

    monkeypatch.setattr(
        deps.engine, "_engine", type("E", (), {"connect": staticmethod(broken)})()
    )
    failed = asyncio.run(main.check_user_bindings())
    assert (failed.status, failed.error) == ("fail", "OSError")


# --- the destination policy (D-08) --------------------------------------------------


def test_internal_data_reaches_local_or_its_own_byok(
    client: TestClient, world: World
) -> None:
    global_key = credential(client, GLOBAL, SU, world.external)
    bound(client, GLOBAL, SU, world.models[world.external], global_key)
    refused(request(TENANT_A, None), AiErrorCode.DATA_CLASS_DENIED)
    tenant_key = credential(client, TENANT_A_BASE, ADMIN_A, world.external, 1)
    bound(client, TENANT_A_BASE, ADMIN_A, world.models[world.external], tenant_key)
    assert resolved(request(TENANT_A, None)).destination is Destination.EXTERNAL_BYOK
    restricted = request(TENANT_A, None, data_class=DataClass.RESTRICTED)
    assert resolved(restricted).destination is Destination.EXTERNAL_BYOK


def test_rerank_is_local_only_whatever_the_policy(
    client: TestClient, world: World
) -> None:
    key = credential(client, GLOBAL, SU, world.external)
    bound(client, GLOBAL, SU, world.models[world.external], key, profile_key="rank")
    widened = replace(
        POLICY,
        data_classes=DataClassPolicy({c: frozenset(Destination) for c in DataClass}),
    )
    rank = request(
        None,
        None,
        profile_key="rank",
        capability=Capability.RERANK,
        data_class=DataClass.PUBLIC,
    )
    refused(rank, AiErrorCode.BOUNDARY_DENIED, widened)
    local_key = credential(client, GLOBAL, SU, world.local, 1)
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_profile_binding).values(
                model_id=world.models[world.local], credential_id=uuid.UUID(local_key)
            )
        )
    local = resolved(rank, widened)
    assert (local.boundary, local.destination) == (
        ProviderBoundary.LOCAL,
        Destination.LOCAL,
    )


def test_restricted_ocr_never_leaves_on_the_database_backends(
    client: TestClient, world: World
) -> None:
    key = credential(client, TENANT_A_BASE, ADMIN_A, world.external)
    bound(
        client,
        TENANT_A_BASE,
        ADMIN_A,
        world.models[world.external],
        key,
        profile_key="read",
    )
    ocr = request(
        TENANT_A,
        None,
        profile_key="read",
        capability=Capability.OCR,
        data_class=DataClass.RESTRICTED,
    )
    refused(ocr, AiErrorCode.DATA_CLASS_DENIED)
    accepted = replace(POLICY, restricted_ocr_residual_accepted=True)
    assert resolved(ocr, accepted).destination is Destination.EXTERNAL_BYOK
    # The vault KV backend reconciles provider files itself: no acceptance needed.
    kv = replace(POLICY, database_backend=False)
    assert resolved(ocr, kv).destination is Destination.EXTERNAL_BYOK


# --- profiles, models, providers ---------------------------------------------------


def test_profile_model_and_provider_state_stop_resolution(
    client: TestClient, world: World
) -> None:
    key = credential(client, GLOBAL, SU, world.external)
    bound(client, GLOBAL, SU, world.models[world.external], key)
    public = request(None, None, data_class=DataClass.PUBLIC)
    result = resolved(public)
    with deps.db_engine.connect() as connection:
        row = (
            connection.execute(
                select(ai_model).where(ai_model.c.id == world.models[world.external])
            )
            .mappings()
            .one()
        )
    assert result.embedding_space_id == identities.embedding_space_id(
        world.external, row["external_model_id"], None, row["dimensions"], "a" * 64
    )
    refused(replace(public, profile_key="nope"), AiErrorCode.PROFILE_UNKNOWN)
    refused(
        replace(public, capability=Capability.RERANK),
        AiErrorCode.CAPABILITY_UNSUPPORTED,
    )
    refused(
        replace(public, profile_key="rank", capability=Capability.RERANK),
        AiErrorCode.PROFILE_UNKNOWN,
    )
    for table, row_id in (
        (ai_provider, world.external),
        (ai_model, world.models[world.external]),
    ):
        with deps.db_engine.begin() as connection:
            connection.execute(
                update(table).where(table.c.id == row_id).values(enabled=False)
            )
        refused(public, AiErrorCode.CREDENTIAL_UNAVAILABLE)
        with deps.db_engine.begin() as connection:
            connection.execute(
                update(table).where(table.c.id == row_id).values(enabled=True)
            )
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_profile)
            .where(ai_profile.c.id == world.embed)
            .values(enabled=False)
        )
    refused(public, AiErrorCode.PROFILE_UNKNOWN)


def test_a_keyless_local_binding_resolves_without_a_credential(
    client: TestClient, world: World
) -> None:
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_provider)
            .where(ai_provider.c.id == world.local)
            .values(auth_type="none")
        )
    bound(client, GLOBAL, SU, world.models[world.local], None)
    result = resolved(request(None, None, data_class=DataClass.RESTRICTED))
    assert (result.credential_id, result.credential_version, result.destination) == (
        None,
        None,
        Destination.LOCAL,
    )


def test_a_model_without_the_capability_never_resolves(
    client: TestClient, world: World
) -> None:
    key = credential(client, GLOBAL, SU, world.external)
    bound(client, GLOBAL, SU, world.models[world.external], key, profile_key="read")
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_model)
            .where(ai_model.c.id == world.models[world.external])
            .values(capabilities=["embedding"])
        )
    ocr = request(
        None,
        None,
        profile_key="read",
        capability=Capability.OCR,
        data_class=DataClass.PUBLIC,
    )
    refused(ocr, AiErrorCode.CAPABILITY_UNSUPPORTED)


def test_the_policy_follows_the_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", False)
    policy = ResolutionPolicy.from_settings(settings)
    assert (
        policy.user_byok_enabled,
        policy.database_backend,
        policy.restricted_ocr_residual_accepted,
    ) == (
        False,
        True,
        False,
    )
    assert policy.data_classes.is_default()


def test_a_request_takes_its_claims_from_the_verified_context() -> None:
    from ai_sdk_m8.jobcontext import JobContextPayload

    from job_contexts import claims

    payload = JobContextPayload.model_validate(
        claims(
            tenant_id=str(TENANT_A), user_id=str(USER_A), allowed_boundaries=["local"]
        )
    )
    assert ExecutionRequest.from_context(payload) == request(
        profile_key="embed-default", allowed=(ProviderBoundary.LOCAL,)
    )

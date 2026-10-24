"""
Credentials per scope (T20): the D-05 matrix with A-1 and A-2, through the app.

Tenant scope: a matching-tenant ``ADMIN`` or the superuser. User scope (Q6,
live from the first release): the ``WRITER`` tier and above on the caller's
own rows, owner and tenant from the token. The superuser's only action on a
user's credential is to disable or delete it.
"""

from __future__ import annotations

import functools
import json
import logging
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError

from ai_gateway import main
from ai_gateway.app.routes import credentials as credential_routes
from ai_gateway.controllers import ratelimit
from ai_gateway.core import deps
from ai_gateway.core.config import settings
from ai_gateway.db_models.audit import ai_credential_audit
from ai_gateway.db_models.credentials import ai_credential
from conftest import bearer
from fastapi_m8 import render_metrics
import factories

pytestmark = pytest.mark.usefixtures("clean_db")

PREFIX = f"{settings.API_PREFIX}/v1"
TENANT_A, TENANT_B = uuid.uuid4(), uuid.uuid4()
USER_A, USER_B = uuid.uuid4(), uuid.uuid4()
SU = bearer("superadmin")
ADMIN_A = bearer("admin", tenant_id=str(TENANT_A))
ADMIN_B = bearer("admin", tenant_id=str(TENANT_B))
ADMIN_NO_TENANT = bearer("admin")
WRITER_A = bearer("writer", subject=USER_A, tenant_id=str(TENANT_A))
WRITER_B = bearer("writer", subject=USER_B, tenant_id=str(TENANT_A))
CANARY = "sk-canary-" + "Qx9" * 12
OTHER_KEY = "sk-other-" + "Lm4" * 12

TENANT_A_BASE = f"{PREFIX}/tenants/{TENANT_A}"
TENANT_B_BASE = f"{PREFIX}/tenants/{TENANT_B}"
ME = f"{PREFIX}/me"
GLOBAL_BASE = f"{PREFIX}/admin"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def byok(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ratified first-deployment value (Q6)."""
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", True)


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json() if response.content else None


def provider(client: TestClient, **overrides: object) -> str:
    body = {
        "name": "mistral",
        "provider_type": "mistral",
        "base_url": "https://api.mistral.example",
        "auth_type": "bearer",
        "boundary": "external",
        **overrides,
    }
    return str(
        _ok(client.post(f"{PREFIX}/admin/providers", json=body, headers=SU), 201)["id"]
    )


def create(
    client: TestClient,
    base: str,
    headers: dict[str, str],
    provider_id: str,
    secret: str = CANARY,
    name: str = "key",
) -> Any:
    body = {"provider_id": provider_id, "name": name, "secret": secret}
    return client.post(f"{base}/credentials", json=body, headers=headers)


def created(
    client: TestClient, base: str, headers: dict[str, str], provider_id: str, **kw: Any
) -> dict[str, Any]:
    result: dict[str, Any] = _ok(create(client, base, headers, provider_id, **kw), 201)
    return result


def audit_actions(credential_id: str | None = None) -> list[str]:
    statement = select(ai_credential_audit.c.action).order_by(ai_credential_audit.c.id)
    if credential_id is not None:
        statement = statement.where(
            ai_credential_audit.c.credential_id == uuid.UUID(credential_id)
        )
    with deps.db_engine.connect() as connection:
        return list(connection.execute(statement).scalars())


def verb(
    client: TestClient,
    base: str,
    credential_id: str,
    name: str,
    headers: dict[str, str],
    **kw: Any,
) -> Any:
    return client.post(
        f"{base}/credentials/{credential_id}:{name}", headers=headers, **kw
    )


def set_status(credential_id: str, status: str) -> None:
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_credential)
            .where(ai_credential.c.id == uuid.UUID(credential_id))
            .values(status=status)
        )


# --- tenant scope --------------------------------------------------------------


def test_a_tenant_admin_stores_a_credential(client: TestClient) -> None:
    p = provider(client)
    response = create(client, TENANT_A_BASE, ADMIN_A, p)
    body = _ok(response, 201)
    assert CANARY not in response.text
    assert (body["scope_type"], body["tenant_id"], body["owner_user_id"]) == (
        "tenant",
        str(TENANT_A),
        None,
    )
    assert (body["status"], body["current_version"], body["secret_hint"]) == (
        "active",
        1,
        CANARY[-4:],
    )
    assert body["incident_listing_consent"] is False
    listed = _ok(client.get(f"{TENANT_A_BASE}/credentials", headers=ADMIN_A))
    assert listed == [body]
    assert (
        _ok(client.get(f"{TENANT_A_BASE}/credentials/{body['id']}", headers=ADMIN_A))
        == body
    )
    # The first credential that references the provider freezes its endpoint.
    provider_row = _ok(client.get(f"{PREFIX}/admin/providers/{p}", headers=SU))
    assert provider_row["first_used_at"] is not None
    frozen = client.patch(
        f"{PREFIX}/admin/providers/{p}",
        json={"base_url": "https://x.example"},
        headers=SU,
    )
    assert frozen.status_code == 409
    assert audit_actions() == ["credential.create"]


def test_a_short_secret_shows_no_hint(client: TestClient) -> None:
    body = created(client, TENANT_A_BASE, ADMIN_A, provider(client), secret="short-key")
    assert body["secret_hint"] is None


def test_another_tenants_admin_sees_nothing(client: TestClient) -> None:
    mine = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    for path in (
        f"{TENANT_A_BASE}/credentials",
        f"{TENANT_A_BASE}/credentials/{mine['id']}",
        f"{TENANT_B_BASE}/credentials/{mine['id']}",
    ):
        assert client.get(path, headers=ADMIN_B).status_code == 404, path
    assert _ok(client.get(f"{TENANT_B_BASE}/credentials", headers=ADMIN_B)) == []
    assert (
        client.delete(
            f"{TENANT_A_BASE}/credentials/{mine['id']}", headers=ADMIN_B
        ).status_code
        == 404
    )


def test_an_admin_without_a_tenant_matches_no_tenant(client: TestClient) -> None:
    mine = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    for method, path in (
        ("GET", f"{TENANT_A_BASE}/credentials"),
        ("GET", f"{TENANT_A_BASE}/credentials/{mine['id']}"),
        ("POST", f"{TENANT_A_BASE}/credentials/{mine['id']}:disable"),
        ("DELETE", f"{TENANT_A_BASE}/credentials/{mine['id']}"),
    ):
        assert client.request(method, path, headers=ADMIN_NO_TENANT).status_code == 404


def test_the_superuser_manages_any_tenant(client: TestClient) -> None:
    body = created(client, TENANT_B_BASE, SU, provider(client))
    assert body["tenant_id"] == str(TENANT_B)
    assert _ok(client.get(f"{TENANT_B_BASE}/credentials", headers=ADMIN_B)) == [body]


def test_the_same_key_in_another_tenant_looks_like_any_new_key(
    client: TestClient,
) -> None:
    p = provider(client)
    first = create(client, TENANT_A_BASE, ADMIN_A, p)
    second = create(client, TENANT_B_BASE, ADMIN_B, p)
    fresh = create(client, TENANT_B_BASE, ADMIN_B, p, secret=OTHER_KEY)
    assert first.status_code == second.status_code == fresh.status_code == 201
    a, b = second.json(), fresh.json()
    assert set(a) == set(b)
    differing = {k for k in a if a[k] != b[k]}
    assert differing <= {"id", "created_at", "updated_at", "secret_hint"}
    # The same key twice in one scope is refused.
    again = create(client, TENANT_A_BASE, ADMIN_A, p, name="again")
    assert again.status_code == 409


def test_a_scope_field_in_a_body_is_refused(client: TestClient, byok: None) -> None:
    p = provider(client)
    body = created(client, TENANT_A_BASE, ADMIN_A, p)
    for field, value in (
        ("provider_id", str(uuid.uuid4())),
        ("scope_type", "global"),
        ("tenant_id", str(TENANT_B)),
        ("owner_user_id", str(USER_B)),
    ):
        response = client.patch(
            f"{TENANT_A_BASE}/credentials/{body['id']}",
            json={field: value},
            headers=ADMIN_A,
        )
        assert response.status_code == 422, field
        create_body = {"provider_id": p, "name": "k", "secret": OTHER_KEY, field: value}
        if field != "provider_id":
            assert (
                client.post(
                    f"{ME}/credentials", json=create_body, headers=WRITER_A
                ).status_code
                == 422
            )


@pytest.mark.parametrize(
    "column",
    [
        "provider_id = gen_random_uuid()",
        "scope_type = 'global', tenant_id = NULL",
        "tenant_id = gen_random_uuid()",
        "owner_user_id = gen_random_uuid()",
    ],
)
def test_ownership_is_immutable_when_the_controller_is_bypassed(
    client: TestClient, column: str
) -> None:
    body = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    with pytest.raises(DBAPIError):
        with deps.db_engine.begin() as connection:
            connection.execute(
                text(f"UPDATE ai_credential SET {column} WHERE id = :id"),  # noqa: S608 - fixed SQL
                {"id": uuid.UUID(body["id"])},
            )


def test_metadata_updates_and_consent_are_audited(client: TestClient) -> None:
    body = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    updated = _ok(
        client.patch(
            f"{TENANT_A_BASE}/credentials/{body['id']}",
            json={"name": "renamed", "incident_listing_consent": True},
            headers=ADMIN_A,
        )
    )
    assert (updated["name"], updated["incident_listing_consent"]) == ("renamed", True)
    same = _ok(
        client.patch(
            f"{TENANT_A_BASE}/credentials/{body['id']}",
            json={"name": "renamed"},
            headers=ADMIN_A,
        )
    )
    assert same == updated
    assert audit_actions(body["id"]) == ["credential.create", "credential.update"]


def test_a_credential_needs_a_keyed_provider(client: TestClient) -> None:
    assert create(client, TENANT_A_BASE, ADMIN_A, str(uuid.uuid4())).status_code == 422
    keyless = provider(client, auth_type="none")
    assert create(client, TENANT_A_BASE, ADMIN_A, keyless).status_code == 422


# --- the lifecycle -----------------------------------------------------------------


def test_the_lifecycle_moves_bindings_with_the_credential(client: TestClient) -> None:
    p = provider(client)
    body = created(client, GLOBAL_BASE, SU, p)
    model = _ok(
        client.post(
            f"{PREFIX}/admin/models",
            json={
                "provider_id": p,
                "external_model_id": "mistral-embed",
                "capabilities": ["embedding"],
                "dimensions": 1024,
                "model_version_label": "v1",
            },
            headers=SU,
        ),
        201,
    )
    _ok(
        client.post(
            f"{PREFIX}/admin/profiles",
            json={"profile_key": "e", "capability": "embedding"},
            headers=SU,
        ),
        201,
    )
    binding = _ok(
        client.post(
            f"{PREFIX}/admin/bindings",
            json={
                "profile_key": "e",
                "model_id": model["id"],
                "credential_id": body["id"],
            },
            headers=SU,
        ),
        201,
    )

    def binding_status() -> str:
        return str(
            _ok(client.get(f"{PREFIX}/admin/bindings/{binding['id']}", headers=SU))[
                "status"
            ]
        )

    cid = body["id"]
    assert _ok(verb(client, GLOBAL_BASE, cid, "disable", SU))["status"] == "disabled"
    assert binding_status() == "credential_unavailable"
    assert _ok(verb(client, GLOBAL_BASE, cid, "disable", SU))["status"] == "disabled"
    assert verb(client, GLOBAL_BASE, cid, "reconfirm", SU).status_code == 409
    rotated = _ok(
        verb(client, GLOBAL_BASE, cid, "rotate", SU, json={"secret": OTHER_KEY})
    )
    assert (rotated["current_version"], rotated["status"]) == (2, "disabled")
    assert _ok(verb(client, GLOBAL_BASE, cid, "enable", SU))["status"] == "active"
    assert binding_status() == "active"
    assert verb(client, GLOBAL_BASE, cid, "enable", SU).status_code == 409
    set_status(cid, "reconfirm_required")
    assert _ok(verb(client, GLOBAL_BASE, cid, "reconfirm", SU))["status"] == "active"
    assert (
        _ok(client.delete(f"{GLOBAL_BASE}/credentials/{cid}", headers=SU), 204) is None
    )
    assert binding_status() == "credential_unavailable"
    assert client.get(f"{GLOBAL_BASE}/credentials/{cid}", headers=SU).status_code == 404
    assert _ok(client.get(f"{GLOBAL_BASE}/credentials", headers=SU)) == []
    assert (
        client.delete(f"{GLOBAL_BASE}/credentials/{cid}", headers=SU).status_code == 404
    )
    assert audit_actions(cid) == [
        "credential.create",
        "credential.disable",
        "credential.rotate",
        "credential.enable",
        "credential.reconfirm",
        "credential.delete",
    ]
    # The material stays for D-43 cleanup; execution never sees it again.
    with deps.credential_store.resolve_for_cleanup(uuid.UUID(cid), 2) as secret:
        assert secret.reveal() == OTHER_KEY


def test_a_rotation_revives_an_invalid_key_and_resets_its_counter(
    client: TestClient,
) -> None:
    body = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_credential)
            .where(ai_credential.c.id == uuid.UUID(body["id"]))
            .values(status="invalid", auth_failure_count=3)
        )
    rotated = _ok(
        verb(
            client,
            TENANT_A_BASE,
            body["id"],
            "rotate",
            ADMIN_A,
            json={"secret": OTHER_KEY},
        )
    )
    assert (
        rotated["status"],
        rotated["auth_failure_count"],
        rotated["secret_hint"],
    ) == (
        "active",
        0,
        OTHER_KEY[-4:],
    )
    with deps.credential_store.resolve_for_execution(
        uuid.UUID(body["id"]), 2
    ) as secret:
        assert secret.reveal() == OTHER_KEY


def test_rotating_to_a_key_the_scope_already_holds_is_409(client: TestClient) -> None:
    p = provider(client)
    first = created(client, TENANT_A_BASE, ADMIN_A, p)
    created(client, TENANT_A_BASE, ADMIN_A, p, secret=OTHER_KEY, name="second")
    response = verb(
        client,
        TENANT_A_BASE,
        first["id"],
        "rotate",
        ADMIN_A,
        json={"secret": OTHER_KEY},
    )
    assert response.status_code == 409


def test_remote_artifacts_show_ids_and_status_only(client: TestClient) -> None:
    p = provider(client)
    body = created(client, TENANT_A_BASE, ADMIN_A, p)
    with deps.db_engine.begin() as connection:
        world = {
            "provider_id": uuid.UUID(p),
            "credential_id": uuid.UUID(body["id"]),
            "model_id": factories.model(connection, uuid.UUID(p)),
            "profile_id": factories.profile(connection),
        }
        execution_id = factories.execution(connection, world)
        artifact_id = factories.artifact(connection, world, execution_id)
    listed = _ok(
        client.get(
            f"{TENANT_A_BASE}/credentials/{body['id']}/remote-artifacts",
            headers=ADMIN_A,
        )
    )
    assert listed == [
        {
            "id": str(artifact_id),
            "credential_version": 1,
            "status": "uploading",
            "remote_artifact_id": None,
            "provider_expires_at": None,
            "created_at": listed[0]["created_at"],
        }
    ]
    foreign = client.get(
        f"{TENANT_B_BASE}/credentials/{body['id']}/remote-artifacts", headers=ADMIN_B
    )
    assert foreign.status_code == 404


# --- caps and rate limits ---------------------------------------------------------


def test_the_per_scope_cap_holds_under_concurrency(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_MAX_CREDENTIALS_PER_SCOPE", 2)
    p = provider(client)
    outcomes: list[int] = []
    barrier = threading.Barrier(5)

    def attempt(n: int) -> None:
        barrier.wait()
        outcomes.append(
            create(
                client, TENANT_A_BASE, ADMIN_A, p, secret=f"sk-{n}-" + "k" * 30
            ).status_code
        )

    threads = [threading.Thread(target=attempt, args=(n,)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert sorted(outcomes) == [201, 201, 409, 409, 409]
    refused = create(client, TENANT_A_BASE, ADMIN_A, p, secret="sk-late-" + "k" * 30)
    assert refused.status_code == 409
    assert not any(ch.isdigit() for ch in refused.json()["detail"])
    # Another scope is unaffected, and its count is never disclosed.
    assert create(client, TENANT_B_BASE, ADMIN_B, p).status_code == 201


def test_creates_and_rotations_are_rate_limited_per_subject(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        credential_routes,
        "charge_credential_write",
        functools.partial(ratelimit.charge_credential_write, limit=2),
    )
    p = provider(client)
    first = created(client, TENANT_A_BASE, ADMIN_A, p)
    _ok(
        verb(
            client,
            TENANT_A_BASE,
            first["id"],
            "rotate",
            ADMIN_A,
            json={"secret": OTHER_KEY},
        )
    )
    limited = create(client, TENANT_A_BASE, ADMIN_A, p, secret="sk-third-" + "t" * 30)
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["retry-after"]) <= 60
    # A refused write still counted; another subject has its own allowance.
    assert (
        create(client, TENANT_A_BASE, SU, p, secret="sk-su-" + "s" * 30).status_code
        == 201
    )


# --- user scope (Q6, A-1, A-2) ------------------------------------------------------


def test_the_user_scope_lifecycle(client: TestClient, byok: None) -> None:
    p = provider(client)
    mine = created(client, ME, WRITER_A, p)
    assert (mine["scope_type"], mine["owner_user_id"], mine["tenant_id"]) == (
        "user",
        str(USER_A),
        str(TENANT_A),
    )
    cid = mine["id"]
    assert _ok(client.get(f"{ME}/credentials", headers=WRITER_A)) == [mine]
    assert (
        _ok(verb(client, ME, cid, "rotate", WRITER_A, json={"secret": OTHER_KEY}))[
            "current_version"
        ]
        == 2
    )
    assert _ok(verb(client, ME, cid, "disable", WRITER_A))["status"] == "disabled"
    assert _ok(verb(client, ME, cid, "enable", WRITER_A))["status"] == "active"
    set_status(cid, "reconfirm_required")
    assert _ok(verb(client, ME, cid, "reconfirm", WRITER_A))["status"] == "active"
    _ok(client.delete(f"{ME}/credentials/{cid}", headers=WRITER_A), 204)
    assert audit_actions(cid) == [
        "credential.create",
        "credential.rotate",
        "credential.disable",
        "credential.enable",
        "credential.reconfirm",
        "credential.delete",
    ]
    with deps.db_engine.connect() as connection:
        owners = set(
            connection.execute(
                select(
                    ai_credential_audit.c.owner_user_id, ai_credential_audit.c.actor_id
                ).where(ai_credential_audit.c.credential_id == uuid.UUID(cid))
            )
        )
    assert owners == {(USER_A, str(USER_A))}


def test_another_user_cannot_reach_my_key(client: TestClient, byok: None) -> None:
    mine = created(client, ME, WRITER_A, provider(client))
    missing = str(uuid.uuid4())
    for cid in (mine["id"], missing):
        for method, suffix, body in (
            ("GET", "", None),
            ("PATCH", "", {"name": "x"}),
            ("DELETE", "", None),
            ("POST", ":rotate", {"secret": OTHER_KEY}),
            ("POST", ":disable", None),
            ("POST", ":enable", None),
            ("GET", "/remote-artifacts", None),
        ):
            response = client.request(
                method, f"{ME}/credentials/{cid}{suffix}", headers=WRITER_B, json=body
            )
            assert response.status_code == 404, (method, suffix)
            assert response.json() == {"detail": "no such credential"}
    assert _ok(client.get(f"{ME}/credentials", headers=WRITER_B)) == []


def test_a_tenant_admin_has_no_access_to_its_users_keys(
    client: TestClient, byok: None
) -> None:
    mine = created(client, ME, WRITER_A, provider(client))
    assert (
        client.get(
            f"{TENANT_A_BASE}/credentials/{mine['id']}", headers=ADMIN_A
        ).status_code
        == 404
    )
    assert _ok(client.get(f"{TENANT_A_BASE}/credentials", headers=ADMIN_A)) == []
    assert (
        client.get(f"{ME}/credentials/{mine['id']}", headers=ADMIN_A).status_code == 404
    )
    assert (
        verb(client, TENANT_A_BASE, mine["id"], "disable", ADMIN_A).status_code == 404
    )


def test_a_writer_cannot_manage_tenant_keys(client: TestClient) -> None:
    tenant_key = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    assert (
        client.get(f"{TENANT_A_BASE}/credentials", headers=WRITER_A).status_code == 403
    )
    path = f"{TENANT_A_BASE}/credentials/{tenant_key['id']}"
    assert client.get(path, headers=WRITER_A).status_code == 403


def test_cross_scope_ids_answer_the_same_404(client: TestClient, byok: None) -> None:
    p = provider(client)
    user_key = created(client, ME, WRITER_A, p)
    tenant_key = created(client, TENANT_A_BASE, ADMIN_A, p, secret=OTHER_KEY)
    as_tenant = client.get(
        f"{TENANT_A_BASE}/credentials/{user_key['id']}", headers=ADMIN_A
    )
    as_user = client.get(f"{ME}/credentials/{tenant_key['id']}", headers=WRITER_A)
    absent = client.get(f"{ME}/credentials/{uuid.uuid4()}", headers=WRITER_A)
    assert as_tenant.status_code == as_user.status_code == absent.status_code == 404
    assert as_tenant.json() == as_user.json() == absent.json()


@pytest.mark.parametrize("role", ["user", "reader"])
def test_user_and_reader_tokens_cannot_write_user_keys(
    client: TestClient, byok: None, role: str
) -> None:
    headers = bearer(role, tenant_id=str(TENANT_A))
    assert create(client, ME, headers, provider(client)).status_code == 403


def test_user_scope_writes_are_refused_while_byok_is_off(
    client: TestClient, byok: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    mine = created(client, ME, WRITER_A, provider(client))
    _ok(verb(client, ME, mine["id"], "disable", WRITER_A))
    monkeypatch.setattr(settings, "AI_USER_BYOK_ENABLED", False)
    p = provider(client, name="other")
    assert create(client, ME, WRITER_A, p, secret=OTHER_KEY).status_code == 403
    for name, body in (
        ("rotate", {"secret": OTHER_KEY}),
        ("enable", None),
        ("reconfirm", None),
    ):
        assert (
            verb(client, ME, mine["id"], name, WRITER_A, json=body).status_code == 403
        )
    # Reading and removing one's own key stay open.
    assert _ok(client.get(f"{ME}/credentials", headers=WRITER_A))[0]["id"] == mine["id"]
    _ok(client.delete(f"{ME}/credentials/{mine['id']}", headers=WRITER_A), 204)


def test_the_superuser_can_only_stop_a_users_key(
    client: TestClient, byok: None
) -> None:
    mine = created(client, ME, WRITER_A, provider(client))
    cid = mine["id"]
    listed = _ok(
        client.get(
            f"{PREFIX}/admin/user-credentials",
            params={"owner_user_id": str(USER_A)},
            headers=SU,
        )
    )
    assert [c["id"] for c in listed] == [cid]
    for method, path in (
        ("POST", f"{PREFIX}/admin/user-credentials/{cid}:rotate"),
        ("POST", f"{PREFIX}/admin/user-credentials/{cid}:enable"),
        ("POST", f"{PREFIX}/admin/user-credentials/{cid}:validate"),
        ("GET", f"{PREFIX}/admin/user-credentials/{cid}"),
        ("POST", f"{ME}/credentials/{cid}:rotate"),
        ("POST", f"{ME}/credentials/{cid}:enable"),
        ("GET", f"{GLOBAL_BASE}/credentials/{cid}"),
        ("GET", f"{TENANT_A_BASE}/credentials/{cid}"),
    ):
        response = client.request(method, path, headers=SU, json={"secret": OTHER_KEY})
        assert response.status_code in (404, 405), (method, path)
    stopped = _ok(
        client.post(f"{PREFIX}/admin/user-credentials/{cid}:disable", headers=SU)
    )
    assert stopped["status"] == "disabled"
    # The owner may delete; the superuser may delete too.
    _ok(client.delete(f"{PREFIX}/admin/user-credentials/{cid}", headers=SU), 204)
    assert (
        client.delete(f"{PREFIX}/admin/user-credentials/{cid}", headers=SU).status_code
        == 404
    )
    assert audit_actions(cid) == [
        "credential.create",
        "credential.disable",
        "credential.delete",
    ]
    with deps.db_engine.connect() as connection:
        actors = list(
            connection.execute(
                select(ai_credential_audit.c.actor_role)
                .where(ai_credential_audit.c.credential_id == uuid.UUID(cid))
                .order_by(ai_credential_audit.c.id)
            ).scalars()
        )
    assert actors == ["writer", "superadmin", "superadmin"]


def test_the_stop_reaches_user_keys_only(client: TestClient) -> None:
    tenant_key = created(client, TENANT_A_BASE, ADMIN_A, provider(client))
    stop = f"{PREFIX}/admin/user-credentials/{tenant_key['id']}"
    assert client.post(f"{stop}:disable", headers=SU).status_code == 404
    assert client.delete(stop, headers=SU).status_code == 404
    assert (
        client.get(
            f"{PREFIX}/admin/user-credentials",
            params={"owner_user_id": str(USER_A)},
            headers=ADMIN_A,
        ).status_code
        == 403
    )


# --- S-01 on the CRUD surface -------------------------------------------------------


def test_the_canary_never_leaves_the_store(
    client: TestClient, byok: None, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    p = provider(client)
    texts: list[str] = []
    for base, headers in ((TENANT_A_BASE, ADMIN_A), (ME, WRITER_A), (GLOBAL_BASE, SU)):
        response = create(client, base, headers, p)
        texts.append(response.text)
        cid = response.json()["id"]
        for call in (
            lambda: client.get(f"{base}/credentials", headers=headers),
            lambda: client.get(f"{base}/credentials/{cid}", headers=headers),
            lambda: verb(
                client, base, cid, "rotate", headers, json={"secret": CANARY + "-2"}
            ),
            lambda: verb(
                client, base, cid, "rotate", headers, json={"secret": CANARY + "-2"}
            ),
            lambda: verb(client, base, cid, "disable", headers),
            lambda: create(client, base, headers, p),
            lambda: client.delete(f"{base}/credentials/{cid}", headers=headers),
        ):
            texts.append(call().text)
    texts.append(client.get(f"{settings.API_PREFIX}/openapi.json").text)
    data, _ = render_metrics()
    texts.append(data.decode())
    with deps.db_engine.connect() as connection:
        texts += [
            json.dumps(dict(row), default=str)
            for row in connection.execute(select(ai_credential_audit)).mappings()
        ]
        texts += [
            json.dumps(dict(row), default=str)
            for row in connection.execute(select(ai_credential)).mappings()
        ]
    texts.append(caplog.text)
    joined = "\n".join(texts)
    assert CANARY not in joined and CANARY[:-4] not in joined

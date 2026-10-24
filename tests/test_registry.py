"""
Providers, models, profiles and global bindings (T18) through the shipped app.

Every request goes through the gateway's own routes, tier dependencies and
controllers; only rows the routes cannot create yet (credentials, a model's
first reservation) are written directly.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from ai_sdk_m8.schemas.management import ModelUpdate
from fastapi.testclient import TestClient
from sqlalchemy import func, literal_column, select, text, update

from ai_gateway import main
from ai_gateway.app.routes import admin as admin_routes
from ai_gateway.controllers import registry
from ai_gateway.controllers.audit import (
    AUDIT_METADATA_MAX_BYTES,
    Actor,
    audited_transaction,
    bound_metadata,
)
from ai_gateway.controllers.errors import Conflict
from ai_gateway.core import deps, identities
from ai_gateway.core.config import settings
from ai_gateway.core.ssrf import DestinationPolicy
from ai_gateway.db_models.audit import ai_admin_audit
from ai_gateway.db_models.registry import ai_model, ai_profile_revision
from conftest import MEDIA_SERVICE, MEDIA_WORKER, PROFILE_READER, bearer
import factories

PREFIX = f"{settings.API_PREFIX}/v1"
SU_SUBJECT = uuid.UUID("00000000-0000-0000-0000-0000000005a1")
SU = bearer("superadmin", subject=SU_SUBJECT)

pytestmark = pytest.mark.usefixtures("clean_db")


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()


def provider(client: TestClient, **overrides: object) -> dict[str, Any]:
    body: dict[str, object] = {
        "name": "mistral",
        "provider_type": "mistral",
        "base_url": "https://api.mistral.example",
        "auth_type": "bearer",
        "boundary": "external",
        **overrides,
    }
    result: dict[str, Any] = _ok(
        client.post(f"{PREFIX}/admin/providers", json=body, headers=SU), 201
    )
    return result


def model(client: TestClient, provider_id: str, **overrides: object) -> dict[str, Any]:
    body: dict[str, object] = {
        "provider_id": provider_id,
        "external_model_id": "mistral-embed",
        "capabilities": ["embedding"],
        "dimensions": 1024,
        "model_version_label": "2024-01",
        **overrides,
    }
    result: dict[str, Any] = _ok(
        client.post(f"{PREFIX}/admin/models", json=body, headers=SU), 201
    )
    return result


def profile(client: TestClient, **overrides: object) -> dict[str, Any]:
    body: dict[str, object] = {
        "profile_key": "embed-default",
        "capability": "embedding",
        "execution_config": {"truncate": 1},
        **overrides,
    }
    result: dict[str, Any] = _ok(
        client.post(f"{PREFIX}/admin/profiles", json=body, headers=SU), 201
    )
    return result


def global_credential(provider_id: str, status: str = "active") -> uuid.UUID:
    with deps.db_engine.begin() as connection:
        return factories.credential(
            connection, uuid.UUID(provider_id), scope_type="global", status=status
        )


def bind(client: TestClient, **body: object) -> Any:
    return client.post(f"{PREFIX}/admin/bindings", json=body, headers=SU)


def published_embedding(client: TestClient) -> tuple[dict[str, Any], ...]:
    """A provider, model, profile and global binding: a published profile."""
    p = provider(client)
    m = model(client, p["id"])
    pr = profile(client)
    credential_id = global_credential(p["id"])
    b = _ok(
        bind(
            client,
            profile_key=pr["profile_key"],
            model_id=m["id"],
            credential_id=str(credential_id),
        ),
        201,
    )
    return p, m, pr, b


def audit_rows() -> list[Any]:
    with deps.db_engine.connect() as connection:
        return list(
            connection.execute(
                select(ai_admin_audit).order_by(ai_admin_audit.c.id)
            ).mappings()
        )


def mark_used(model_id: str) -> None:
    """A model's first reservation (``T27``) sets ``first_used_at``."""
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_model)
            .where(ai_model.c.id == uuid.UUID(model_id))
            .values(first_used_at=func.now())
        )


# --- providers -----------------------------------------------------------------


def test_provider_crud_is_audited_with_its_actor(client: TestClient) -> None:
    created = provider(client)
    assert created["first_used_at"] is None
    assert _ok(client.get(f"{PREFIX}/admin/providers", headers=SU)) == [created]
    assert (
        _ok(client.get(f"{PREFIX}/admin/providers/{created['id']}", headers=SU))
        == created
    )
    renamed = _ok(
        client.patch(
            f"{PREFIX}/admin/providers/{created['id']}",
            json={"name": "mistral-eu"},
            headers=SU,
        )
    )
    assert renamed["name"] == "mistral-eu"
    rows = audit_rows()
    assert [r["action"] for r in rows] == ["provider.create", "provider.update"]
    for row in rows:
        assert (row["actor_kind"], row["actor_id"], row["actor_role"]) == (
            "user",
            str(SU_SUBJECT),
            "superadmin",
        )
        assert (row["target_type"], row["target_id"]) == ("provider", created["id"])
    assert rows[0]["metadata"]["after"]["base_url"] == "https://api.mistral.example"
    assert rows[1]["metadata"]["changed"] == {
        "name": {"before": "mistral", "after": "mistral-eu"}
    }


def test_an_unknown_provider_is_404(client: TestClient) -> None:
    for method in ("get", "patch"):
        response = getattr(client, method)(
            f"{PREFIX}/admin/providers/{uuid.uuid4()}",
            headers=SU,
            **({"json": {"name": "x"}} if method == "patch" else {}),
        )
        assert response.status_code == 404


@pytest.mark.parametrize(
    "header",
    [
        "Host",
        "Proxy-Authorization",
        "X-Internal-Token",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-authorization",
        "forwarded",
        "cookie",
        "authorization",
        "x-forwarded-for",
        "x-internal-client",
        "x-internal-token",
        "x-ai-job-context",
    ],
)
def test_a_reserved_or_routing_header_name_is_refused(
    client: TestClient, header: str
) -> None:
    body = {
        "name": "p",
        "provider_type": "openai_compatible",
        "base_url": "https://api.example.com",
        "auth_type": "api_key_header",
        "auth_header_name": header,
        "boundary": "external",
    }
    response = client.post(f"{PREFIX}/admin/providers", json=body, headers=SU)
    assert response.status_code == 422
    assert audit_rows() == []


@pytest.mark.parametrize("header", ["x-api-key", "api-key", "x-goog-api-key"])
def test_an_allowed_header_name_is_accepted(client: TestClient, header: str) -> None:
    created = provider(client, auth_type="api_key_header", auth_header_name=header)
    assert created["auth_header_name"] == header


@pytest.mark.parametrize(
    "base_url",
    [
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://10.0.0.1",
        "https://user:pw@api.example.com",
        "https://api.example.com:8443",
        "https://api.example.com/?x=1",
    ],
)
def test_a_refused_destination_is_422(client: TestClient, base_url: str) -> None:
    response = client.post(
        f"{PREFIX}/admin/providers",
        json={
            "name": "p",
            "provider_type": "openai_compatible",
            "base_url": base_url,
            "auth_type": "bearer",
            "boundary": "external",
        },
        headers=SU,
    )
    assert response.status_code == 422


def test_a_local_provider_needs_an_allowlisted_name(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = {
        "name": "ollama",
        "provider_type": "ollama",
        "base_url": "http://ollama:11434",
        "auth_type": "none",
        "boundary": "local",
    }
    refused = client.post(f"{PREFIX}/admin/providers", json=body, headers=SU)
    assert refused.status_code == 422
    allowed = DestinationPolicy(
        production=False,
        internal_hosts=frozenset({("ollama", 11434)}),
        external_ports=frozenset({443}),
    )
    monkeypatch.setattr(admin_routes, "destination_policy", allowed)
    assert provider(client, **body)["boundary"] == "local"


def test_a_header_name_must_match_the_auth_type(client: TestClient) -> None:
    created = provider(client)
    response = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}",
        json={"auth_type": "api_key_header"},
        headers=SU,
    )
    assert response.status_code == 422
    moved = _ok(
        client.patch(
            f"{PREFIX}/admin/providers/{created['id']}",
            json={"auth_type": "api_key_header", "auth_header_name": "x-api-key"},
            headers=SU,
        )
    )
    assert moved["auth_header_name"] == "x-api-key"


def test_a_changed_base_url_is_checked_again(client: TestClient) -> None:
    created = provider(client)
    response = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}",
        json={"base_url": "https://127.0.0.1"},
        headers=SU,
    )
    assert response.status_code == 422
    moved = _ok(
        client.patch(
            f"{PREFIX}/admin/providers/{created['id']}",
            json={"base_url": "https://eu.api.mistral.example"},
            headers=SU,
        )
    )
    assert moved["base_url"] == "https://eu.api.mistral.example"


@pytest.mark.parametrize(
    "change",
    [
        {"base_url": "https://eu.api.mistral.example"},
        {"provider_type": "openai_compatible"},
        {"auth_type": "none"},
    ],
)
def test_a_referenced_provider_keeps_its_endpoint(
    client: TestClient, change: dict[str, object]
) -> None:
    created = provider(client)
    global_credential(created["id"])
    response = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}", json=change, headers=SU
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("initial", "change"),
    [
        (
            {"auth_type": "api_key_header", "auth_header_name": "x-api-key"},
            {"auth_header_name": "x-other-key"},
        ),
        ({}, {"boundary": "local"}),
        (
            {"boundary": "local", "base_url": "http://ollama:11434"},
            {"boundary": "external"},
        ),
    ],
)
def test_a_used_provider_keeps_its_header_and_boundary(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    initial: dict[str, object],
    change: dict[str, object],
) -> None:
    monkeypatch.setattr(
        admin_routes,
        "destination_policy",
        DestinationPolicy(
            production=False,
            internal_hosts=frozenset({("ollama", 11434)}),
            external_ports=frozenset({443}),
        ),
    )
    created = provider(client, **initial)
    global_credential(created["id"])
    response = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}", json=change, headers=SU
    )
    assert response.status_code == 409


def test_the_boundary_is_fixed_even_before_first_use(client: TestClient) -> None:
    created = provider(client)
    response = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}",
        json={"boundary": "local"},
        headers=SU,
    )
    assert response.status_code == 409


def test_disabling_a_used_provider_is_allowed_and_audited(client: TestClient) -> None:
    created = provider(client)
    global_credential(created["id"])
    disabled = _ok(
        client.patch(
            f"{PREFIX}/admin/providers/{created['id']}",
            json={"enabled": False},
            headers=SU,
        )
    )
    assert disabled["enabled"] is False
    assert audit_rows()[-1]["metadata"]["changed"] == {
        "enabled": {"before": True, "after": False}
    }


def test_a_no_op_update_writes_no_audit_row(client: TestClient) -> None:
    created = provider(client)
    same = _ok(
        client.patch(
            f"{PREFIX}/admin/providers/{created['id']}",
            json={"name": created["name"], "boundary": "external"},
            headers=SU,
        )
    )
    assert same == created
    assert [r["action"] for r in audit_rows()] == ["provider.create"]


# --- models --------------------------------------------------------------------


def test_model_crud_derives_the_execution_identity(client: TestClient) -> None:
    p = provider(client)
    created = model(
        client, p["id"], model_revision="r1", identity_assurance="pinned_snapshot"
    )
    expected = identities.execution_identity(uuid.UUID(p["id"]), "mistral-embed", "r1")
    assert created["execution_identity"] == expected
    assert created["identity_assurance"] == "pinned_snapshot"
    assert _ok(client.get(f"{PREFIX}/admin/models", headers=SU)) == [created]
    assert (
        _ok(client.get(f"{PREFIX}/admin/models/{created['id']}", headers=SU)) == created
    )
    moved = _ok(
        client.patch(
            f"{PREFIX}/admin/models/{created['id']}",
            json={"external_model_id": "mistral-embed-2", "model_revision": None},
            headers=SU,
        )
    )
    assert moved["execution_identity"] == identities.execution_identity(
        uuid.UUID(p["id"]), "mistral-embed-2", None
    )
    assert [r["action"] for r in audit_rows()] == [
        "provider.create",
        "model.create",
        "model.update",
    ]


def test_the_execution_identity_is_the_c07_hash(client: TestClient) -> None:
    provider_id = uuid.UUID("11111111-2222-4333-8444-555555555555")
    canonical = json.dumps(
        [str(provider_id), "mistral-ocr-2505", "2505"], separators=(",", ":")
    )
    expected = hashlib.sha256(canonical.encode()).hexdigest()[:32]
    assert (
        identities.execution_identity(provider_id, "mistral-ocr-2505", "2505")
        == expected
    )


def test_a_model_needs_an_existing_provider(client: TestClient) -> None:
    response = client.post(
        f"{PREFIX}/admin/models",
        json={
            "provider_id": str(uuid.uuid4()),
            "external_model_id": "m",
            "capabilities": ["ocr"],
            "model_version_label": "v1",
        },
        headers=SU,
    )
    assert response.status_code == 422


def test_an_unknown_model_is_404(client: TestClient) -> None:
    assert (
        client.get(f"{PREFIX}/admin/models/{uuid.uuid4()}", headers=SU).status_code
        == 404
    )


def test_identity_assurance_provider_digest_is_never_declared(
    client: TestClient,
) -> None:
    p = provider(client)
    response = client.post(
        f"{PREFIX}/admin/models",
        json={
            "provider_id": p["id"],
            "external_model_id": "m",
            "capabilities": ["ocr"],
            "model_version_label": "v1",
            "identity_assurance": "provider_digest",
        },
        headers=SU,
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "change",
    [
        {"external_model_id": "mistral-embed-2"},
        {"dimensions": 768},
        {"model_revision": "r2"},
        {"model_version_label": "2025-01"},
        {"capabilities": ["embedding", "rerank"]},
    ],
)
def test_an_executed_model_keeps_its_identity(
    client: TestClient, change: dict[str, object]
) -> None:
    created = model(client, provider(client)["id"])
    mark_used(created["id"])
    response = client.patch(
        f"{PREFIX}/admin/models/{created['id']}", json=change, headers=SU
    )
    assert response.status_code == 409


def test_an_executed_model_may_shrink_and_be_disabled(client: TestClient) -> None:
    p = provider(client)
    created = model(client, p["id"], capabilities=["embedding", "rerank"])
    mark_used(created["id"])
    shrunk = _ok(
        client.patch(
            f"{PREFIX}/admin/models/{created['id']}",
            json={"capabilities": ["embedding"], "enabled": False},
            headers=SU,
        )
    )
    assert (shrunk["capabilities"], shrunk["enabled"]) == (["embedding"], False)


def test_a_capability_a_binding_relies_on_is_never_removed(client: TestClient) -> None:
    p = provider(client)
    m = model(client, p["id"], capabilities=["embedding", "rerank"])
    profile(client)
    credential_id = global_credential(p["id"])
    _ok(
        bind(
            client,
            profile_key="embed-default",
            model_id=m["id"],
            credential_id=str(credential_id),
        ),
        201,
    )
    response = client.patch(
        f"{PREFIX}/admin/models/{m['id']}",
        json={"capabilities": ["rerank"], "dimensions": None},
        headers=SU,
    )
    assert response.status_code == 409


def test_embedding_dimensions_follow_the_capabilities(client: TestClient) -> None:
    created = model(client, provider(client)["id"])
    response = client.patch(
        f"{PREFIX}/admin/models/{created['id']}",
        json={"dimensions": None},
        headers=SU,
    )
    assert response.status_code == 422
    ocr = _ok(
        client.patch(
            f"{PREFIX}/admin/models/{created['id']}",
            json={"capabilities": ["ocr"], "dimensions": None},
            headers=SU,
        )
    )
    assert (ocr["capabilities"], ocr["dimensions"]) == (["ocr"], None)


def test_a_no_op_model_update_writes_no_audit_row(client: TestClient) -> None:
    created = model(client, provider(client)["id"])
    same = _ok(
        client.patch(
            f"{PREFIX}/admin/models/{created['id']}",
            json={"capabilities": ["embedding"]},
            headers=SU,
        )
    )
    assert same == created
    assert audit_rows()[-1]["action"] == "model.create"


def test_a_model_edit_racing_its_first_reservation_waits_then_is_refused(
    client: TestClient,
) -> None:
    created = model(client, provider(client)["id"])
    model_id = uuid.UUID(created["id"])
    outcome: dict[str, object] = {}

    def edit() -> None:
        try:
            with audited_transaction(deps.db_engine) as tx:
                registry.update_model(
                    tx,
                    Actor("user", "u", "superadmin"),
                    model_id,
                    ModelUpdate(model_revision="r2"),
                )
        except Conflict as exc:
            outcome["refused"] = exc.detail

    with deps.db_engine.connect() as reservation:
        transaction = reservation.begin()
        reservation.execute(
            select(ai_model.c.id).where(ai_model.c.id == model_id).with_for_update()
        )
        reservation.execute(
            update(ai_model)
            .where(ai_model.c.id == model_id)
            .values(first_used_at=func.now())
        )
        editor = threading.Thread(target=edit)
        editor.start()
        editor.join(timeout=1.0)
        assert editor.is_alive(), "the edit must wait for the reservation's row lock"
        transaction.commit()
    editor.join(timeout=30)
    assert "frozen" in str(outcome["refused"])


# --- profiles and revisions ----------------------------------------------------


def test_profile_crud_and_revisions(client: TestClient) -> None:
    created = profile(client)
    assert created["current"]["revision"] == 1
    assert created["current"][
        "execution_config_hash"
    ] == identities.execution_config_hash({"truncate": 1})
    assert _ok(client.get(f"{PREFIX}/admin/profiles", headers=SU)) == [created]
    key = created["profile_key"]
    assert _ok(client.get(f"{PREFIX}/admin/profiles/{key}", headers=SU)) == created
    updated = _ok(
        client.patch(
            f"{PREFIX}/admin/profiles/{key}",
            json={"execution_config": {"truncate": 0}},
            headers=SU,
        )
    )
    assert updated["current"]["revision"] == 2
    revisions = _ok(client.get(f"{PREFIX}/admin/profiles/{key}/revisions", headers=SU))
    assert [r["revision"] for r in revisions] == [1, 2]
    assert revisions[0] == created["current"]
    actions = [r["action"] for r in audit_rows()]
    assert actions == ["profile.create", "profile.update"]
    assert audit_rows()[-1]["metadata"]["changed"]["current_revision"] == {
        "before": 1,
        "after": 2,
    }


def test_a_duplicate_profile_key_is_409(client: TestClient) -> None:
    profile(client)
    response = client.post(
        f"{PREFIX}/admin/profiles",
        json={"profile_key": "embed-default", "capability": "rerank"},
        headers=SU,
    )
    assert response.status_code == 409


def test_a_reserved_capability_is_refused(client: TestClient) -> None:
    response = client.post(
        f"{PREFIX}/admin/profiles",
        json={"profile_key": "chat", "capability": "chat"},
        headers=SU,
    )
    assert response.status_code == 422


def test_an_unknown_profile_is_404(client: TestClient) -> None:
    for path in ("profiles/nope", "profiles/nope/revisions"):
        assert client.get(f"{PREFIX}/admin/{path}", headers=SU).status_code == 404
    response = client.patch(
        f"{PREFIX}/admin/profiles/nope", json={"enabled": False}, headers=SU
    )
    assert response.status_code == 404


def test_the_same_configuration_is_no_new_revision(client: TestClient) -> None:
    created = profile(client)
    same = _ok(
        client.patch(
            f"{PREFIX}/admin/profiles/{created['profile_key']}",
            json={"execution_config": {"truncate": 1}, "enabled": True},
            headers=SU,
        )
    )
    assert same == created
    disabled = _ok(
        client.patch(
            f"{PREFIX}/admin/profiles/{created['profile_key']}",
            json={"enabled": False},
            headers=SU,
        )
    )
    assert (disabled["enabled"], disabled["current"]["revision"]) == (False, 1)
    assert [r["action"] for r in audit_rows()] == ["profile.create", "profile.update"]


def _revision_bytes(revision: int) -> tuple[object, ...]:
    with deps.db_engine.connect() as connection:
        row = connection.execute(
            select(
                literal_column("execution_config::text"),
                ai_profile_revision.c.execution_config_hash,
                ai_profile_revision.c.created_at,
            ).where(ai_profile_revision.c.revision == revision)
        ).one()
    return tuple(row)


def test_a_revision_has_its_own_hash_and_space_and_the_old_one_is_unchanged(
    client: TestClient,
) -> None:
    p, m, pr, _ = published_embedding(client)
    key = pr["profile_key"]
    before = _ok(client.get(f"{PREFIX}/profiles/{key}", headers=bearer("reader")))
    first = _revision_bytes(1)
    _ok(
        client.patch(
            f"{PREFIX}/admin/profiles/{key}",
            json={"execution_config": {"truncate": 0, "normalize": 1}},
            headers=SU,
        )
    )
    after = _ok(client.get(f"{PREFIX}/profiles/{key}", headers=bearer("reader")))
    assert _revision_bytes(1) == first
    second = _revision_bytes(2)
    assert second[1] != first[1]
    assert (before["revision"], after["revision"]) == (1, 2)
    assert after["embedding_space_id"] != before["embedding_space_id"]
    assert after["embedding_space_id"] == identities.embedding_space_id(
        uuid.UUID(p["id"]), m["external_model_id"], None, 1024, str(second[1])
    )


# --- the published view --------------------------------------------------------


def test_readers_see_identities_never_a_credential_or_base_url(
    client: TestClient,
) -> None:
    p, m, pr, b = published_embedding(client)
    response = client.get(f"{PREFIX}/profiles", headers=bearer("reader"))
    body = _ok(response)
    assert body == [
        {
            "profile_key": "embed-default",
            "capability": "embedding",
            "revision": 1,
            "enabled": True,
            "identity_assurance": "operator_declared",
            "dimensions": 1024,
            "embedding_space_id": identities.embedding_space_id(
                uuid.UUID(p["id"]),
                "mistral-embed",
                None,
                1024,
                pr["current"]["execution_config_hash"],
            ),
            "ocr_execution_identity": None,
        }
    ]
    for secretish in (p["base_url"], "mistral.example", p["id"], b["credential_id"]):
        assert secretish not in response.text
    one = _ok(client.get(f"{PREFIX}/profiles/embed-default", headers=bearer("reader")))
    assert one == body[0]


def test_an_ocr_profile_publishes_its_execution_identity(client: TestClient) -> None:
    p = provider(client)
    m = model(
        client,
        p["id"],
        external_model_id="mistral-ocr-2505",
        capabilities=["ocr"],
        dimensions=None,
        model_revision="2505",
    )
    profile(client, profile_key="ocr-default", capability="ocr")
    credential_id = global_credential(p["id"])
    _ok(
        bind(
            client,
            profile_key="ocr-default",
            model_id=m["id"],
            credential_id=str(credential_id),
        ),
        201,
    )
    published = _ok(
        client.get(f"{PREFIX}/profiles/ocr-default", headers=bearer("reader"))
    )
    assert published["ocr_execution_identity"] == m["execution_identity"]
    assert published["dimensions"] is None
    assert published["embedding_space_id"] is None


def test_an_unbound_profile_is_not_published(client: TestClient) -> None:
    profile(client)
    assert _ok(client.get(f"{PREFIX}/profiles", headers=bearer("reader"))) == []
    response = client.get(f"{PREFIX}/profiles/embed-default", headers=bearer("reader"))
    assert response.status_code == 404
    assert response.json()["code"] == "profile_unknown"


def test_a_profiles_read_service_client_reads_profiles(client: TestClient) -> None:
    published_embedding(client)
    for identity in (PROFILE_READER, MEDIA_SERVICE):
        body = _ok(client.get(f"{PREFIX}/profiles", headers=identity.headers()))
        assert [p["profile_key"] for p in body] == ["embed-default"]
        one = _ok(
            client.get(f"{PREFIX}/profiles/embed-default", headers=identity.headers())
        )
        assert one["profile_key"] == "embed-default"


def test_a_service_client_without_profiles_read_is_refused(client: TestClient) -> None:
    response = client.get(f"{PREFIX}/profiles", headers=MEDIA_WORKER.headers())
    assert (response.status_code, response.json()["code"]) == (403, "forbidden_scope")
    wrong = client.get(f"{PREFIX}/profiles", headers=PROFILE_READER.headers("x" * 64))
    assert (wrong.status_code, wrong.json()["code"]) == (401, "unauthorized")


def test_the_reader_tier_guards_the_jwt_variant(client: TestClient) -> None:
    assert client.get(f"{PREFIX}/profiles").status_code == 401
    assert client.get(f"{PREFIX}/profiles", headers=bearer("user")).status_code == 403
    assert client.get(f"{PREFIX}/profiles", headers=bearer("reader")).status_code == 200


# --- global bindings -----------------------------------------------------------


def test_binding_crud_is_audited(client: TestClient) -> None:
    p, m, pr, b = published_embedding(client)
    assert b["scope_type"] == "global" and b["status"] == "active"
    assert b["tenant_id"] is None and b["owner_user_id"] is None
    assert _ok(client.get(f"{PREFIX}/admin/bindings", headers=SU)) == [b]
    assert _ok(client.get(f"{PREFIX}/admin/bindings/{b['id']}", headers=SU)) == b
    other = model(client, p["id"], external_model_id="mistral-embed-2")
    moved = _ok(
        client.patch(
            f"{PREFIX}/admin/bindings/{b['id']}",
            json={"model_id": other["id"]},
            headers=SU,
        )
    )
    assert moved["model_id"] == other["id"]
    deleted = client.delete(f"{PREFIX}/admin/bindings/{b['id']}", headers=SU)
    assert deleted.status_code == 204
    assert (
        client.get(f"{PREFIX}/admin/bindings/{b['id']}", headers=SU).status_code == 404
    )
    actions = [r["action"] for r in audit_rows() if r["target_type"] == "binding"]
    assert actions == ["binding.create", "binding.update", "binding.delete"]


def test_a_profile_bound_to_a_model_without_its_capability_is_422(
    client: TestClient,
) -> None:
    p = provider(client)
    ocr = model(client, p["id"], capabilities=["ocr"], dimensions=None)
    profile(client)
    response = bind(
        client,
        profile_key="embed-default",
        model_id=ocr["id"],
        credential_id=str(global_credential(p["id"])),
    )
    assert response.status_code == 422


def test_a_profile_binds_once_per_scope(client: TestClient) -> None:
    _, m, pr, b = published_embedding(client)
    again = bind(
        client,
        profile_key=pr["profile_key"],
        model_id=m["id"],
        credential_id=b["credential_id"],
    )
    assert again.status_code == 409


def test_a_binding_needs_the_scopes_own_credential_for_the_models_provider(
    client: TestClient,
) -> None:
    p = provider(client)
    m = model(client, p["id"])
    profile(client)
    other = provider(client, name="other")
    with deps.db_engine.begin() as connection:
        tenant_key = factories.credential(connection, uuid.UUID(p["id"]))
        deleted_key = factories.credential(
            connection, uuid.UUID(p["id"]), scope_type="global", status="disabled"
        )
        connection.execute(
            text(
                "UPDATE ai_credential SET status = 'deleted', deleted_at = now() "
                "WHERE id = :id"
            ),
            {"id": deleted_key},
        )
    for credential_id in (
        global_credential(other["id"]),
        tenant_key,
        deleted_key,
        uuid.uuid4(),
        None,
    ):
        response = bind(
            client,
            profile_key="embed-default",
            model_id=m["id"],
            credential_id=None if credential_id is None else str(credential_id),
        )
        assert response.status_code == 422, credential_id


def test_a_keyless_provider_binds_without_a_credential(client: TestClient) -> None:
    p = provider(client, auth_type="none")
    m = model(client, p["id"])
    profile(client)
    bound = _ok(bind(client, profile_key="embed-default", model_id=m["id"]), 201)
    assert (bound["credential_id"], bound["status"]) == (None, "active")
    keyed = provider(client, name="keyed")
    response = bind(
        client,
        profile_key="embed-default",
        model_id=m["id"],
        credential_id=str(global_credential(keyed["id"])),
    )
    assert response.status_code == 422


def test_a_binding_needs_a_known_profile_and_model(client: TestClient) -> None:
    p = provider(client, auth_type="none")
    m = model(client, p["id"])
    assert bind(client, profile_key="nope", model_id=m["id"]).status_code == 422
    profile(client)
    response = bind(client, profile_key="embed-default", model_id=str(uuid.uuid4()))
    assert response.status_code == 422


def test_a_global_binding_cannot_fall_through(client: TestClient) -> None:
    _, m, pr, b = published_embedding(client)
    response = client.patch(
        f"{PREFIX}/admin/bindings/{b['id']}",
        json={"on_unavailable": "fall_through"},
        headers=SU,
    )
    assert response.status_code == 422


def test_an_unavailable_credential_makes_the_binding_unavailable(
    client: TestClient,
) -> None:
    _, m, pr, b = published_embedding(client)
    p_id = _ok(client.get(f"{PREFIX}/admin/models/{m['id']}", headers=SU))[
        "provider_id"
    ]
    disabled = global_credential(p_id, status="disabled")
    moved = _ok(
        client.patch(
            f"{PREFIX}/admin/bindings/{b['id']}",
            json={"credential_id": str(disabled)},
            headers=SU,
        )
    )
    assert moved["status"] == "credential_unavailable"
    cleared = client.patch(
        f"{PREFIX}/admin/bindings/{b['id']}", json={"credential_id": None}, headers=SU
    )
    assert cleared.status_code == 422


def test_a_no_op_binding_update_writes_no_audit_row(client: TestClient) -> None:
    _, m, _, b = published_embedding(client)
    same = _ok(
        client.patch(
            f"{PREFIX}/admin/bindings/{b['id']}",
            json={"model_id": m["id"], "on_unavailable": "fail"},
            headers=SU,
        )
    )
    assert same == b
    assert audit_rows()[-1]["action"] == "binding.create"


def test_an_unknown_binding_is_404(client: TestClient) -> None:
    missing = f"{PREFIX}/admin/bindings/{uuid.uuid4()}"
    assert (
        client.patch(missing, json={"on_unavailable": "fail"}, headers=SU).status_code
        == 404
    )
    assert client.delete(missing, headers=SU).status_code == 404


# --- the audit trail -----------------------------------------------------------


def test_audit_events_are_logged_only_after_the_commit(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="ai_gateway.audit")
    created = provider(client)
    events = [r for r in caplog.records if r.name == "ai_gateway.audit"]
    assert len(events) == 1
    event = json.loads(events[0].getMessage().removeprefix("audit "))
    assert (event["action"], event["target_id"]) == ("provider.create", created["id"])
    caplog.clear()
    refused = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}",
        json={"boundary": "local"},
        headers=SU,
    )
    assert refused.status_code == 409
    assert [r for r in caplog.records if r.name == "ai_gateway.audit"] == []


def test_audit_metadata_is_bounded() -> None:
    small = {"a": "b"}
    assert bound_metadata(small) == small
    long = {"base_url": "x" * 3000, "other": "y" * 3000}
    reduced = bound_metadata(long)
    assert reduced["base_url"] == {
        "sha256": hashlib.sha256(("x" * 3000).encode()).hexdigest(),
        "length": 3000,
    }
    many = {f"k{i}": ["v" * 10] * 10 for i in range(100)}
    truncated = bound_metadata(many)
    assert truncated["truncated"] is True
    for value in (reduced, truncated):
        rendered = json.dumps(value, separators=(", ", ": "), ensure_ascii=False)
        assert len(rendered.encode()) <= AUDIT_METADATA_MAX_BYTES


def test_a_large_model_metadata_still_audits(client: TestClient) -> None:
    p = provider(client)
    metadata = {f"k{i}": "v" * 200 for i in range(18)}
    created = model(client, p["id"], metadata=metadata)
    after = audit_rows()[-1]["metadata"]["after"]
    assert after["id"] == created["id"]


def test_a_provider_used_by_an_outbound_request_keeps_its_endpoint(
    client: TestClient,
) -> None:
    from ai_gateway.db_models.registry import ai_provider

    created = provider(client)
    # A validation probe or an execution (T25, T27) stamps first_used_at.
    with deps.db_engine.begin() as connection:
        connection.execute(
            update(ai_provider)
            .where(ai_provider.c.id == uuid.UUID(created["id"]))
            .values(first_used_at=func.now())
        )
    response = client.patch(
        f"{PREFIX}/admin/providers/{created['id']}",
        json={"base_url": "https://eu.api.mistral.example"},
        headers=SU,
    )
    assert response.status_code == 409


def test_an_unused_model_may_gain_a_capability(client: TestClient) -> None:
    created = model(client, provider(client)["id"])
    grown = _ok(
        client.patch(
            f"{PREFIX}/admin/models/{created['id']}",
            json={"capabilities": ["embedding", "rerank"]},
            headers=SU,
        )
    )
    assert sorted(grown["capabilities"]) == ["embedding", "rerank"]

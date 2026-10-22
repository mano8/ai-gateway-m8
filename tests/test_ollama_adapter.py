"""
The Ollama adapter (T28): embeddings, structured output, the digest pin.

The answers under ``tests/fixtures/ollama/`` are the response bodies the
Ollama API reference documents, copied byte for byte from
``docs/api.md`` (``github.com/ollama/ollama``, ``main``, retrieved
2026-10-22, SHA-256 ``96db0308…48dd0f5``): ``GET /api/tags``, ``POST
/api/embed`` (one and two inputs) and ``POST /api/chat`` with structured
outputs. The adapter runs through the shipped execution core and the real
provider client over an in-process transport.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability, IdentityAssurance
from ai_sdk_m8.schemas.management import ProviderType, ScopeType
from fastapi.testclient import TestClient

from ai_gateway import main
from ai_gateway.app.routes import admin as admin_routes
from ai_gateway.controllers.model_identity import DigestReader
from ai_gateway.core import deps
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.identities import execution_identity
from ai_gateway.db_models.audit import ai_admin_audit
from ai_gateway.db_models.registry import ai_model, ai_provider
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.http import Deadline, ProviderEndpoint
from ai_gateway.providers.ollama import OllamaAdapter, digest_of, tagged
from ai_gateway.providers.registry import ADAPTERS, OLLAMA
from conftest import bearer
from execution_world import (
    StubAdapter,
    as_owner,
    clients,
    embed_job,
    execution,
    executions,
    make_binding,
    make_credential,
    make_model,
    make_profile,
    make_provider,
    principal,
    run,
    service,
    structured_job,
)

pytestmark = pytest.mark.usefixtures("clean_db")

FIXTURES = Path(__file__).parent / "fixtures" / "ollama"
LLAMA_DIGEST = "a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72"
SU = bearer("superadmin")
PREFIX = f"{settings.API_PREFIX}/v1"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class Provider:
    """An in-process Ollama: answers each path from a fixture or a function."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers[request.url.path]
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, httpx.Response):
            return answer
        content = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        return httpx.Response(200, stream=httpx.ByteStream(content))

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


def ollama_world(
    dimensions: int = 10, capability: Capability = Capability.EMBEDDING
) -> dict[str, Any]:
    provider_id = make_provider()
    model_id = make_model(
        provider_id,
        capability,
        external_model_id="all-minilm",
        **({"dimensions": dimensions} if capability is Capability.EMBEDDING else {}),
    )
    profile_id, key = make_profile(capability)
    make_binding(profile_id, model_id)
    return {"provider_id": provider_id, "model_id": model_id, "key": key}


def ollama_service(provider: Provider, **kw: Any) -> Any:
    factory = clients(transport=lambda _e: httpx.MockTransport(provider))
    return service(OllamaAdapter(), factory=factory, **kw)  # type: ignore[arg-type]


# --- embeddings ------------------------------------------------------------------------


def test_an_embedding_matches_the_documented_answer_and_request() -> None:
    w = ollama_world()
    provider = Provider({"/api/embed": fixture("embed_multiple.json")})
    done = run(
        ollama_service(provider).run(
            principal(w["key"]),
            embed_job(w["key"], ["Why is the sky blue?", "Why is the grass green?"]),
        )
    )
    expected = json.loads(fixture("embed_multiple.json"))["embeddings"]
    assert done.result.dimensions == 10
    assert [list(v) for v in done.result.vectors] == expected
    assert provider.body() == {
        "model": "all-minilm",
        "input": ["Why is the sky blue?", "Why is the grass green?"],
        "truncate": False,
    }
    (request,) = provider.requests
    assert (
        request.method == "POST" and str(request.url) == "http://ollama:11434/api/embed"
    )
    assert "authorization" not in request.headers  # auth_type none
    assert execution(done.execution.execution_id)["status"] == "ok"


def test_the_documented_single_answer_reports_its_prompt_tokens() -> None:
    w = ollama_world()
    provider = Provider({"/api/embed": fixture("embed.json")})
    done = run(
        ollama_service(provider).run(
            principal(w["key"]), embed_job(w["key"], ["Why is the sky blue?"])
        )
    )
    assert done.execution.provider_usage.input_tokens == 8


def test_a_dimension_mismatch_is_rejected_and_audited_against_the_model() -> None:
    w = ollama_world(dimensions=768)
    provider = Provider({"/api/embed": fixture("embed.json")})  # 10 dimensions
    with pytest.raises(GatewayError) as caught:
        run(
            ollama_service(provider).run(
                principal(w["key"]), embed_job(w["key"], ["x"])
            )
        )
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED
    (row,) = executions()
    assert row["status"] == "failed" and row["error_class"] == "provider_rejected"
    with as_owner() as c:
        audit = (
            c.execute(
                sa.select(ai_admin_audit).where(
                    ai_admin_audit.c.action == "model.incident"
                )
            )
            .mappings()
            .one()
        )
    assert audit["target_id"] == str(w["model_id"]) and audit["actor_kind"] == "system"
    assert audit["metadata"] == {
        "incident": "dimension_mismatch",
        "execution_id": str(row["id"]),
    }


@pytest.mark.parametrize(
    "embeddings",
    [
        b'{"embeddings": [[1e999, 0, 0], [0, 0, 0]]}',  # parses as infinity
        b'{"embeddings": [[-1e999, 0, 0], [0, 0, 0]]}',
        b'{"embeddings": [[NaN, 0, 0], [0, 0, 0]]}',
        b'{"embeddings": [[0, 0, 0]]}',  # one vector for two inputs
        b'{"embeddings": [[0, 0, 0], [0, 0, 0], [0, 0, 0]]}',
        b'{"embeddings": null}',
        b'["not an object"]',
    ],
    ids=["inf", "-inf", "nan", "too-few", "too-many", "null", "not-object"],
)
def test_non_finite_components_or_a_wrong_count_are_rejected(embeddings: bytes) -> None:
    w = ollama_world(dimensions=3)
    provider = Provider({"/api/embed": embeddings})
    with pytest.raises(GatewayError) as caught:
        run(
            ollama_service(provider).run(
                principal(w["key"]), embed_job(w["key"], ["a", "b"])
            )
        )
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED
    assert executions()[0]["status"] == "failed"


# --- structured output -----------------------------------------------------------------


def test_structured_output_matches_the_documented_answer_and_request() -> None:
    w = ollama_world(capability=Capability.STRUCTURED_OUTPUT)
    provider = Provider({"/api/chat": fixture("chat_structured.json")})
    job = structured_job(w["key"], "Ollama is 22 years old and busy saving the world.")
    done = run(
        ollama_service(provider).run(
            principal(w["key"], Capability.STRUCTURED_OUTPUT), job
        )
    )
    assert done.result.output == {"age": 22, "available": False}
    usage = done.execution.provider_usage
    assert (usage.input_tokens, usage.output_tokens) == (34, 12)
    assert provider.body() == {
        "model": "all-minilm",
        "messages": [
            {
                "role": "user",
                "content": "Ollama is 22 years old and busy saving the world.",
            }
        ],
        "stream": False,
        "format": {"type": "object"},
        "options": {"num_predict": 1024, "temperature": 0},
    }


@pytest.mark.parametrize(
    "answer",
    [
        {"message": {"role": "assistant", "content": "not json"}},
        {"message": {"role": "assistant", "content": 42}},
        {"message": "not an object"},
        {"done": True},
        {"message": {"content": "[" * 40 + "]" * 40}},  # over the depth cap
    ],
)
def test_a_structured_answer_that_is_not_parseable_json_is_rejected(
    answer: object,
) -> None:
    w = ollama_world(capability=Capability.STRUCTURED_OUTPUT)
    provider = Provider({"/api/chat": answer})
    with pytest.raises(GatewayError) as caught:
        run(
            ollama_service(provider).run(
                principal(w["key"], Capability.STRUCTURED_OUTPUT),
                structured_job(w["key"]),
            )
        )
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED


def test_ollama_serves_no_rerank_and_refuses_it_before_any_request() -> None:
    w = ollama_world(capability=Capability.RERANK)
    provider = Provider({})
    from execution_world import rerank_job

    with pytest.raises(GatewayError) as caught:
        run(
            ollama_service(provider).run(
                principal(w["key"], Capability.RERANK), rerank_job(w["key"])
            )
        )
    assert caught.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED
    assert provider.requests == [] and executions()[0]["status"] == "released"
    with pytest.raises(ProviderFailure) as direct:
        run(OllamaAdapter().rerank(None, "q", ["d"], None))  # type: ignore[arg-type]
    assert direct.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED


def test_the_shipped_registry_serves_ollama_with_one_adapter_instance() -> None:
    assert ADAPTERS[ProviderType.OLLAMA] is OLLAMA
    assert OLLAMA.capabilities == frozenset(
        {Capability.EMBEDDING, Capability.STRUCTURED_OUTPUT}
    )
    assert deps.model_digests.adapter is OLLAMA


# --- the digest pin ---------------------------------------------------------------------


def test_the_documented_listing_yields_each_models_digest() -> None:
    tags = json.loads(fixture("tags.json"))
    assert digest_of(tags, "llama3.2") == LLAMA_DIGEST
    assert digest_of(tags, "llama3.2:latest") == LLAMA_DIGEST
    assert (
        digest_of(tags, "deepseek-r1")
        == "0a8c266910232fd3291e71e5ba1e058cc5af9d411192cf88b6d30e92b6e73163"
    )
    assert digest_of(tags, "mistral") is None
    assert tagged("library/llama3.2") == "library/llama3.2:latest"
    assert tagged("hf.co/org/repo:Q4") == "hf.co/org/repo:Q4"


@pytest.mark.parametrize(
    "listing",
    [
        [],
        {"models": "x"},
        {"models": ["x"]},
        {"models": [{"name": "llama3.2:latest", "digest": "sha256:" + LLAMA_DIGEST}]},
        {"models": [{"name": "llama3.2:latest"}]},
    ],
)
def test_a_malformed_listing_or_digest_is_refused(listing: object) -> None:
    with pytest.raises(ProviderFailure):
        digest_of(listing, "llama3.2")  # type: ignore[arg-type]


def reader(answer: Any, **kw: Any) -> tuple[DigestReader, Provider]:
    provider = Provider({"/api/tags": answer})
    factory = clients(transport=lambda _e: httpx.MockTransport(provider))
    return (
        DigestReader(
            deps.db_engine, factory, deps.credential_store, OLLAMA, timeout_seconds=5
        ),
        provider,
    )


@pytest.fixture
def client() -> Any:
    with TestClient(main.app) as test_client:
        yield test_client


def register(client: TestClient, provider_id: uuid.UUID, **body: Any) -> Any:
    payload = {
        "provider_id": str(provider_id),
        "external_model_id": "llama3.2",
        "capabilities": ["structured_output"],
        "model_version_label": "3.2",
        **body,
    }
    return client.post(f"{PREFIX}/admin/models", json=payload, headers=SU)


def test_registering_an_ollama_model_pins_its_listed_digest(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    digests, provider = reader(fixture("tags.json"))
    monkeypatch.setattr(admin_routes, "model_digests", digests)
    provider_id = make_provider()
    created = register(client, provider_id)
    assert created.status_code == 201, created.text
    model = created.json()
    assert model["model_revision"] == LLAMA_DIGEST
    assert model["identity_assurance"] == IdentityAssurance.PROVIDER_DIGEST.value
    assert model["execution_identity"] == execution_identity(
        provider_id, "llama3.2", LLAMA_DIGEST
    )
    assert [r.url.path for r in provider.requests] == ["/api/tags"]
    assert register(client, provider_id, model_revision=LLAMA_DIGEST).status_code == 201
    other = register(client, provider_id, model_revision="some-other-revision")
    assert other.status_code == 422


def test_registration_refuses_an_unlisted_model_and_an_unreachable_provider(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider_id = make_provider()
    digests, _ = reader(fixture("tags.json"))
    monkeypatch.setattr(admin_routes, "model_digests", digests)
    assert register(client, provider_id, external_model_id="mistral").status_code == 422
    down, _ = reader(httpx.Response(503))
    monkeypatch.setattr(admin_routes, "model_digests", down)
    assert register(client, provider_id).status_code == 503
    garbled, _ = reader({"models": "garbled"})
    monkeypatch.setattr(admin_routes, "model_digests", garbled)
    assert register(client, provider_id).status_code == 503
    with as_owner() as c:
        assert (
            c.execute(sa.select(sa.func.count()).select_from(ai_model)).scalar_one()
            == 0
        )


def test_a_non_ollama_model_reads_no_digest(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    digests, provider = reader(fixture("tags.json"))
    monkeypatch.setattr(admin_routes, "model_digests", digests)
    from ai_sdk_m8.schemas import ProviderBoundary

    external = make_provider(ProviderBoundary.EXTERNAL, ProviderType.OPENAI_COMPATIBLE)
    created = register(client, external, model_revision="2026-01-01")
    assert (
        created.status_code == 201
        and created.json()["identity_assurance"] == "operator_declared"
    )
    assert provider.requests == []
    assert digests.digest(uuid.uuid4(), "x") is None  # an unknown provider


def test_a_renamed_ollama_model_is_pinned_again_and_its_revision_is_never_hand_set(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    digests, provider = reader(fixture("tags.json"))
    monkeypatch.setattr(admin_routes, "model_digests", digests)
    model = register(client, make_provider()).json()
    url = f"{PREFIX}/admin/models/{model['id']}"
    renamed = client.patch(url, json={"external_model_id": "deepseek-r1"}, headers=SU)
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["model_revision"].startswith("0a8c2669")
    assert (
        client.patch(url, json={"model_revision": "x"}, headers=SU).status_code == 422
    )
    assert (
        client.patch(
            url, json={"identity_assurance": "pinned_snapshot"}, headers=SU
        ).status_code
        == 422
    )
    assert (
        client.patch(url, json={"model_version_label": "r1"}, headers=SU).status_code
        == 200
    )
    assert len(provider.requests) == 2  # the rename only
    assert digests.digest_for_update(uuid.uuid4(), "x") is None


def test_an_authenticating_ollama_is_read_with_the_platform_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    digests, provider = reader(fixture("tags.json"))
    monkeypatch.setattr(admin_routes, "model_digests", digests)
    keyed = make_provider(auth_type="bearer")
    assert register(client, keyed).status_code == 422  # no platform key yet
    make_credential(
        keyed, ScopeType.TENANT, tenant_id=str(uuid.uuid4()), secret="tenant-key"
    )
    assert register(client, keyed).status_code == 422  # a tenant's key never serves
    make_credential(keyed, secret="platform-key")
    assert register(client, keyed).status_code == 201
    assert provider.requests[-1].headers["authorization"] == "Bearer platform-key"


def pinned(
    external_model_id: str = "llama3.2", revision: str = LLAMA_DIGEST, **kw: Any
) -> uuid.UUID:
    provider_id = kw.pop("provider_id", None) or make_provider()
    return make_model(
        provider_id,
        Capability.STRUCTURED_OUTPUT,
        external_model_id=external_model_id,
        model_revision=revision,
        identity_assurance="provider_digest",
        **kw,
    )


def audits(action: str) -> list[Any]:
    with as_owner() as c:
        return list(
            c.execute(
                sa.select(ai_admin_audit).where(ai_admin_audit.c.action == action)
            ).mappings()
        )


def test_the_recheck_flags_a_changed_or_vanished_digest_and_audits_it() -> None:
    provider_id = make_provider()
    same = pinned(provider_id=provider_id)
    changed = pinned("deepseek-r1", "f" * 64, provider_id=provider_id)
    vanished = pinned("mistral", "e" * 64, provider_id=provider_id)
    digests, provider = reader(fixture("tags.json"))
    flagged = run(digests.recheck())
    assert sorted(flagged) == sorted([changed, vanished])
    assert len(provider.requests) == 1  # one listing per provider
    with as_owner() as c:
        rows = {
            r.id: r.flagged_at
            for r in c.execute(sa.select(ai_model.c.id, ai_model.c.flagged_at))
        }
    assert rows[same] is None and rows[changed] and rows[vanished]
    reasons = {a["target_id"]: a["metadata"]["reason"] for a in audits("model.flagged")}
    assert reasons == {str(changed): "digest_changed", str(vanished): "not_listed"}
    assert run(digests.recheck()) == []  # flagged models are not checked again


def test_a_digest_change_after_first_use_refuses_every_execution() -> None:
    provider_id = make_provider()
    model_id = pinned("llama3.2", "f" * 64, provider_id=provider_id)
    profile_id, key = make_profile(Capability.STRUCTURED_OUTPUT)
    make_binding(profile_id, model_id)
    adapter = StubAdapter()
    run(
        service(adapter).run(
            principal(key, Capability.STRUCTURED_OUTPUT), structured_job(key)
        )
    )
    digests, _ = reader(fixture("tags.json"))
    assert run(digests.recheck()) == [model_id]
    with pytest.raises(GatewayError) as caught:
        run(
            service(adapter).run(
                principal(key, Capability.STRUCTURED_OUTPUT), structured_job(key)
            )
        )
    assert caught.value.code is AiErrorCode.CREDENTIAL_UNAVAILABLE
    assert len(adapter.calls) == 1


def test_an_unreachable_or_garbled_provider_flags_nothing() -> None:
    pinned()
    for answer in (
        httpx.Response(500),
        {"models": "garbled"},
        {"models": [{"name": "llama3.2:latest", "digest": "bad"}]},
    ):
        digests, _ = reader(answer)
        assert run(digests.recheck()) == []
    keyed = make_provider(auth_type="bearer")
    pinned(provider_id=keyed, revision="f" * 64)  # no platform key: skipped
    digests, _ = reader(fixture("tags.json"))
    assert run(digests.recheck()) == []


def test_the_recheck_honours_a_fence() -> None:
    model_id = pinned(revision="f" * 64)
    digests, _ = reader(fixture("tags.json"))
    assert run(digests.recheck(fence=sa.false())) == []
    assert run(digests.recheck(fence=sa.true())) == [model_id]


def test_the_probe_reads_the_listing() -> None:
    provider = Provider({"/api/tags": fixture("tags.json")})
    factory = clients(transport=lambda _e: httpx.MockTransport(provider))
    provider_id = make_provider()
    with as_owner() as c:
        row = (
            c.execute(sa.select(ai_provider).where(ai_provider.c.id == provider_id))
            .mappings()
            .one()
        )

    async def probe() -> None:
        async with factory.client(ProviderEndpoint.from_row(row)) as http:
            await OLLAMA.probe(http, None, Deadline.after(5))

    run(probe())
    assert [r.url.path for r in provider.requests] == ["/api/tags"]

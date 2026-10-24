"""
The JSON execution routes (T31) through the shipped app.

``embed``, ``rerank`` and ``structured-output`` are called as a service
client with a signed job context; the shipped execution service runs each one
against an in-process provider, so every refusal is checked on the wire and on
the number of provider requests it caused.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from ai_sdk_m8.schemas import Capability, DataClass, ProviderBoundary
from ai_sdk_m8.schemas.management import ProviderType
from fastapi.testclient import TestClient

from ai_gateway import main
from ai_gateway.core import deps
from ai_gateway.core.execution_guard import JOB_CONTEXT_HEADER
from ai_gateway.execution.schema_dialect import SchemaRefused, check_schema, validator
from ai_gateway.providers.errors import ProviderFailure
from conftest import MEDIA_SERVICE, MEDIA_WORKER, bearer
from execution_world import clients, executions, world
from job_contexts import mint

pytestmark = pytest.mark.usefixtures("clean_db")

BASE = "/ai/v1/execute"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


class Provider:
    """An in-process provider answering per path; counts what it was sent."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.dumps(self.answers[request.url.path]).encode()
        return httpx.Response(200, stream=httpx.ByteStream(body))


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> Callable[[dict[str, Any]], Provider]:
    def install(answers: dict[str, Any]) -> Provider:
        stub = Provider(answers)
        factory = clients(transport=lambda _e: httpx.MockTransport(stub))
        monkeypatch.setattr(deps.execution_service, "_clients", factory)
        return stub

    return install


def headers(key: str, capability: Capability, **claims: Any) -> dict[str, str]:
    context = mint(
        MEDIA_SERVICE,
        capability=capability.value,
        profile_key=key,
        data_class=claims.pop("data_class", DataClass.INTERNAL).value,
        **claims,
    )
    return {**MEDIA_SERVICE.headers(), JOB_CONTEXT_HEADER: context}


def post(
    client: TestClient,
    route: str,
    key: str,
    capability: Capability,
    body: Any,
    **kw: Any,
) -> Any:
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    return client.post(
        f"{BASE}/{route}",
        content=content,
        headers={**headers(key, capability), **kw.pop("extra", {})},
        **kw,
    )


EMBED_ANSWER = {"/api/embed": {"embeddings": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]}}


# --- embed --------------------------------------------------------------------------


def test_embed_runs_one_execution(client: TestClient, provider: Any) -> None:
    stub = provider(EMBED_ANSWER)
    w = world()
    response = post(
        client,
        "embed",
        w.profile_key,
        Capability.EMBEDDING,
        {"profile_key": w.profile_key, "inputs": ["a", "b"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["result"]["vectors"] == [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
    assert body["execution"]["units"] == 2 and len(stub.requests) == 1
    (row,) = executions()
    assert row["status"] == "ok"


def test_a_chunked_body_without_content_length_is_read(
    client: TestClient, provider: Any
) -> None:
    provider(EMBED_ANSWER)
    w = world()
    payload = json.dumps({"profile_key": w.profile_key, "inputs": ["a", "b"]}).encode()

    def chunks() -> Iterator[bytes]:
        yield payload[:5]
        yield payload[5:]

    response = client.post(
        f"{BASE}/embed",
        content=chunks(),
        headers=headers(w.profile_key, Capability.EMBEDDING),
    )
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("declared", [None, "10", "999999999"])
def test_a_body_over_the_cap_is_aborted_before_parsing(
    client: TestClient,
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
    declared: str | None,
) -> None:
    from ai_gateway.core.config import settings

    stub = provider(EMBED_ANSWER)
    monkeypatch.setattr(settings, "AI_MAX_REQUEST_BYTES", 64)
    w = world()

    def chunks() -> Iterator[bytes]:
        yield b'{"profile_key": "' + w.profile_key.encode() + b'", "inputs": ["'
        yield b"x" * 100
        yield b'"]}'

    extra = {} if declared is None else {"Content-Length": declared}
    response = client.post(
        f"{BASE}/embed",
        content=chunks(),
        headers={**headers(w.profile_key, Capability.EMBEDDING), **extra},
    )
    assert (
        response.status_code == 413 and response.json()["code"] == "request_too_large"
    )
    assert stub.requests == [] and executions() == []


def test_too_many_or_too_long_inputs_are_refused(
    client: TestClient, provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_gateway.core.config import settings

    stub = provider(EMBED_ANSWER)
    monkeypatch.setattr(settings, "AI_MAX_EMBED_INPUTS", 2)
    monkeypatch.setattr(settings, "AI_MAX_INPUT_CHARS", 5)
    w = world()
    for inputs in (["a", "b", "c"], ["toolong"]):
        response = post(
            client,
            "embed",
            w.profile_key,
            Capability.EMBEDDING,
            {"profile_key": w.profile_key, "inputs": inputs},
        )
        assert response.status_code == 413, response.text
    assert stub.requests == [] and executions() == []


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[1, 2",
        json.dumps({"profile_key": "p", "inputs": []}).encode(),
        b"[" * 40 + b"]" * 40,
    ],
    ids=["text", "truncated", "empty-inputs", "over-deep"],
)
def test_a_malformed_body_is_422_with_no_value_echoed(
    client: TestClient, provider: Any, body: bytes
) -> None:
    stub = provider(EMBED_ANSWER)
    w = world()
    response = post(client, "embed", w.profile_key, Capability.EMBEDDING, body)
    assert response.status_code == 422
    assert "not json" not in response.text
    assert stub.requests == []


def test_another_profile_than_the_contexts_is_refused(
    client: TestClient, provider: Any
) -> None:
    stub = provider(EMBED_ANSWER)
    w = world()
    response = post(
        client,
        "embed",
        w.profile_key,
        Capability.EMBEDDING,
        {"profile_key": "other", "inputs": ["a"]},
    )
    assert response.status_code == 401 and response.json()["code"] == "context_invalid"
    assert stub.requests == []


# --- the guard on the shipped routes ------------------------------------------------


def test_a_jwt_or_a_missing_context_never_reaches_a_route(client: TestClient) -> None:
    jwt = client.post(f"{BASE}/embed", content=b"{}", headers=bearer("superadmin"))
    assert jwt.status_code == 401 and jwt.json()["code"] == "unauthorized"
    missing = client.post(
        f"{BASE}/embed", content=b"{}", headers=MEDIA_SERVICE.headers()
    )
    assert missing.status_code == 401 and missing.json()["code"] == "context_missing"


def test_a_client_with_another_capabilitys_scope_is_forbidden(
    client: TestClient,
) -> None:
    context = mint(capability="embedding", profile_key="p")
    response = client.post(
        f"{BASE}/embed",
        content=b"{}",
        headers={**MEDIA_WORKER.headers(), JOB_CONTEXT_HEADER: context},
    )
    assert response.status_code == 403 and response.json()["code"] == "forbidden_scope"


# --- rerank ---------------------------------------------------------------------


def rerank_world() -> Any:
    """A local, keyless OpenAI-compatible rerank server."""
    from execution_world import (
        World,
        make_binding,
        make_model,
        make_profile,
        make_provider,
    )

    provider_id = make_provider(
        ProviderBoundary.LOCAL,
        ProviderType.OPENAI_COMPATIBLE,
        base_url="http://models.local:8080",
        auth_type="none",
    )
    model_id = make_model(provider_id, Capability.RERANK)
    profile_id, key = make_profile(Capability.RERANK)
    binding_id = make_binding(profile_id, model_id)
    return World(provider_id, model_id, profile_id, key, binding_id, None)


RERANK_ANSWER = {
    "/v1/rerank": {
        "results": [
            {"index": 1, "relevance_score": 0.9},
            {"index": 0, "relevance_score": 0.1},
        ]
    }
}


def test_rerank_runs_against_a_local_provider(
    client: TestClient, provider: Any
) -> None:
    stub = provider(RERANK_ANSWER)
    w = rerank_world()
    response = post(
        client,
        "rerank",
        w.profile_key,
        Capability.RERANK,
        {"profile_key": w.profile_key, "query": "q", "documents": ["a", "b"]},
    )
    assert response.status_code == 200, response.text
    assert [h["index"] for h in response.json()["result"]["hits"]] == [1, 0]
    assert len(stub.requests) == 1


def test_rerank_against_an_external_profile_is_boundary_denied(
    client: TestClient, provider: Any
) -> None:
    stub = provider(RERANK_ANSWER)
    w = world(Capability.RERANK, boundary=ProviderBoundary.EXTERNAL)
    response = post(
        client,
        "rerank",
        w.profile_key,
        Capability.RERANK,
        {"profile_key": w.profile_key, "query": "q", "documents": ["a"]},
    )
    assert response.status_code == 403 and response.json()["code"] == "boundary_denied"
    assert stub.requests == []


def test_one_candidate_over_the_bound_is_request_too_large(
    client: TestClient, provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_gateway.core.config import settings

    stub = provider(RERANK_ANSWER)
    monkeypatch.setattr(settings, "AI_MAX_RERANK_CANDIDATES", 2)
    w = rerank_world()
    response = post(
        client,
        "rerank",
        w.profile_key,
        Capability.RERANK,
        {"profile_key": w.profile_key, "query": "q", "documents": ["a", "b", "c"]},
    )
    assert response.status_code == 413 and stub.requests == []


# --- structured output ----------------------------------------------------------


SCHEMA = {
    "type": "object",
    "properties": {
        "total": {"type": "integer", "minimum": 0},
        "currency": {"type": "string", "enum": ["EUR", "USD"]},
        "issued": {"type": "string", "format": "date"},
        "lines": {"type": "array", "items": {"$ref": "#/$defs/line"}},
    },
    "required": ["total"],
    "additionalProperties": False,
    "$defs": {
        "line": {
            "type": "object",
            "properties": {"label": {"type": "string", "maxLength": 20}},
        }
    },
}


def chat(content: dict[str, Any]) -> dict[str, Any]:
    return {
        "/api/chat": {"message": {"role": "assistant", "content": json.dumps(content)}}
    }


def structured(client: TestClient, w: Any, schema: Any = SCHEMA) -> Any:
    return post(
        client,
        "structured-output",
        w.profile_key,
        Capability.STRUCTURED_OUTPUT,
        {
            "profile_key": w.profile_key,
            "input": "invoice 42",
            "schema_name": "invoice",
            "json_schema": schema,
        },
    )


def test_structured_output_is_validated_against_the_request_schema(
    client: TestClient, provider: Any
) -> None:
    good = {
        "total": 42,
        "currency": "EUR",
        "issued": "2026-10-23",
        "lines": [{"label": "a"}],
    }
    stub = provider(chat(good))
    w = world(Capability.STRUCTURED_OUTPUT)
    response = structured(client, w)
    assert response.status_code == 200, response.text
    assert response.json()["result"]["output"] == good
    sent = json.loads(stub.requests[0].content)
    assert sent["format"] == SCHEMA


@pytest.mark.parametrize(
    "output",
    [
        {"currency": "EUR"},
        {"total": -1},
        {"total": True},
        {"total": 1, "extra": 1},
        {"total": 1, "issued": "23/10/2026"},
    ],
    ids=["missing", "below-minimum", "boolean", "extra", "bad-date"],
)
def test_an_output_outside_the_schema_is_rejected_and_charged(
    client: TestClient, provider: Any, output: dict[str, Any]
) -> None:
    provider(chat(output))
    w = world(Capability.STRUCTURED_OUTPUT)
    response = structured(client, w)
    assert (
        response.status_code == 502 and response.json()["code"] == "provider_rejected"
    )
    (row,) = executions()
    assert row["status"] == "failed"


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {"a": {"type": "string", "pattern": "^(a+)+$"}},
        },
        {"type": "object", "patternProperties": {"^x": {"type": "string"}}},
        {
            "type": "object",
            "properties": {"a": {"$ref": "https://evil.test/schema.json"}},
        },
        {"type": "object", "properties": {"a": {"$ref": "other.json#/x"}}},
        {"type": "object", "properties": {"a": {"type": "string", "format": "regex"}}},
        {"type": "object", "properties": {"a": {"anyOf": [{"type": "string"}]}}},
    ],
    ids=[
        "pattern",
        "patternProperties",
        "remote-ref",
        "relative-ref",
        "regex-format",
        "anyOf",
    ],
)
def test_a_schema_outside_the_dialect_is_422_with_no_provider_call(
    client: TestClient, provider: Any, schema: Any
) -> None:
    stub = provider(chat({"a": "x"}))
    w = world(Capability.STRUCTURED_OUTPUT)
    response = structured(client, w, schema)
    assert response.status_code == 422, response.text
    assert stub.requests == [] and executions() == []


def test_an_oversize_or_over_deep_schema_is_422(
    client: TestClient, provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_gateway.core.config import settings

    stub = provider(chat({}))
    w = world(Capability.STRUCTURED_OUTPUT)
    deep: dict[str, Any] = {"type": "string"}
    for _ in range(9):
        deep = {"type": "object", "properties": {"x": deep}}
    assert structured(client, w, deep).status_code == 422
    monkeypatch.setattr(settings, "AI_MAX_SCHEMA_BYTES", 64)
    assert structured(client, w).status_code == 422
    assert stub.requests == []


# --- the dialect itself -----------------------------------------------------------


def _check(schema: Any) -> None:
    check_schema(schema, max_bytes=16384, max_depth=8)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "array"},
        {"type": "object", "properties": []},
        {"type": "object", "properties": {"a": "string"}},
        {"type": "object", "properties": {"a": {"type": "date"}}},
        {"type": "object", "properties": {"a": {"type": ["string", "null"]}}},
        {"type": "object", "required": ["missing"]},
        {
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "required": ["a", "a"],
        },
        {"type": "object", "required": "a"},
        {"type": "object", "additionalProperties": {"type": "string"}},
        {"type": "object", "properties": {"a": {"type": "string", "enum": []}}},
        {"type": "object", "properties": {"a": {"type": "string", "enum": [{"x": 1}]}}},
        {"type": "object", "properties": {"a": {"type": "string", "description": 7}}},
        {"type": "object", "properties": {"a": {"type": "integer", "minimum": "0"}}},
        {
            "type": "object",
            "properties": {"a": {"type": "number", "maximum": float("inf")}},
        },
        {"type": "object", "properties": {"a": {"type": "string", "minLength": -1}}},
        {"type": "object", "properties": {"a": {"type": "string", "maxLength": True}}},
        {"type": "object", "properties": {"a": {"$ref": "#/$defs/missing"}}},
        {
            "type": "object",
            "properties": {"a": {"$ref": "#/$defs/b", "type": "string"}},
        },
        {"type": "object", "properties": {"a": {"$ref": 7}}},
        {"type": "object", "$defs": {"b": {"$ref": "#/$defs/b"}}},
        {"type": "object", "$defs": {"bad name": {"type": "string"}}},
        {"type": "object", "$defs": []},
        {"type": "object", "properties": {"a": {"type": "string", "title": "A"}}},
    ],
)
def test_the_dialect_refuses(schema: Any) -> None:
    with pytest.raises(SchemaRefused):
        _check(schema)


def test_the_dialect_accepts_its_keywords_and_validates_by_type() -> None:
    schema = {
        "type": "object",
        "description": "an invoice",
        "properties": {
            "n": {"type": "number", "minimum": 0.5, "maximum": 10},
            "i": {"type": "integer", "maximum": 3},
            "b": {"type": "boolean"},
            "s": {"type": "string", "minLength": 1, "maxLength": 3},
            "t": {"type": "string", "format": "date-time"},
            "u": {"type": "string", "format": "uri"},
            "k": {"type": "integer", "enum": [1, 2]},
            "tags": {"type": "array"},
            "ref": {"$ref": "#/$defs/d", "description": "a reference"},
        },
        "$defs": {"d": {"type": "object"}},
    }
    _check(schema)
    validate = validator(schema)
    good = {
        "n": 1.5,
        "i": 3,
        "b": False,
        "s": "abc",
        "t": "2026-10-23T10:00:00Z",
        "u": "https://example.test/x",
        "k": 2,
        "tags": ["a"],
        "ref": {"any": 1},
        "free": "extra allowed",
    }
    assert validate(good) == good
    for bad in (
        {"n": 0.1},
        {"n": "1"},
        {"n": True},
        {"i": 1.5},
        {"i": 4},
        {"b": 0},
        {"s": ""},
        {"s": "abcd"},
        {"s": 1},
        {"t": "2026-10-23"},
        {"t": "2026-13-23T10:00:00Z"},
        {"u": "no scheme"},
        {"u": "https://a b"},
        {"k": True},
        {"k": 3},
        {"tags": [1]},
        {"tags": "a"},
        {"ref": []},
        [],
    ):
        with pytest.raises(ProviderFailure):
            validate(bad)  # type: ignore[arg-type]
    date_only = {
        "type": "object",
        "properties": {"d": {"type": "string", "format": "date"}},
    }
    with pytest.raises(ProviderFailure):
        validator(date_only)({"d": "2026-02-30"})


def test_a_structured_input_over_the_bound_is_request_too_large(
    client: TestClient, provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_gateway.core.config import settings

    stub = provider(chat({}))
    monkeypatch.setattr(settings, "AI_MAX_INPUT_CHARS", 3)
    w = world(Capability.STRUCTURED_OUTPUT)
    assert structured(client, w).status_code == 413 and stub.requests == []

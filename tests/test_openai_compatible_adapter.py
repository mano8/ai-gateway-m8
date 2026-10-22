"""
The OpenAI-compatible adapter (T30) against stub providers.

The stubs answer in the OpenAI wire shapes — ``/v1/embeddings``
(``data[].index``/``embedding``), ``/v1/chat/completions`` (``choices[0].
message.content``) — and the Jina/Cohere ``/v1/rerank`` shape vLLM and
llama.cpp serve (``results[].index``/``relevance_score``). One test drives a
real HTTP stub server through the real transport; the rest use the
in-process transport. Every call runs through the shipped execution core.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass, ProviderBoundary
from ai_sdk_m8.schemas.management import ProviderType

from ai_gateway.core.errors import GatewayError
from ai_gateway.db_models.registry import ai_provider
from ai_gateway.providers.base import require_capability
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.openai_compatible import (
    OpenAiCompatibleAdapter,
    ordered_vectors,
)
from ai_gateway.providers.registry import ADAPTERS
from execution_world import (
    as_owner,
    clients,
    embed_job,
    executions,
    make_binding,
    make_credential,
    make_model,
    make_profile,
    make_provider,
    principal,
    rerank_job,
    run,
    service,
    structured_job,
    update,
)
from provider_stubs import Reply, StubServer, socket_transport

pytestmark = pytest.mark.usefixtures("clean_db")

ADAPTER = OpenAiCompatibleAdapter()


class Provider:
    """An in-process OpenAI-compatible server."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers[request.url.path]
        if isinstance(answer, httpx.Response):
            return answer
        content = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        return httpx.Response(200, stream=httpx.ByteStream(content))

    def body(self) -> Any:
        return json.loads(self.requests[-1].content)


def openai_world(
    capability: Capability = Capability.EMBEDDING,
    boundary: ProviderBoundary = ProviderBoundary.EXTERNAL,
) -> dict[str, Any]:
    base = (
        "https://api.provider.test"
        if boundary is ProviderBoundary.EXTERNAL
        else "http://models.local:8080"
    )
    provider_id = make_provider(boundary, ProviderType.OPENAI_COMPATIBLE, base_url=base)
    model_id = make_model(
        provider_id,
        capability,
        external_model_id="text-embedding-3-small"
        if capability is Capability.EMBEDDING
        else "m",
        **({"dimensions": 3} if capability is Capability.EMBEDDING else {}),
    )
    profile_id, key = make_profile(capability)
    credential_id = make_credential(provider_id, secret="sk-platform")
    make_binding(profile_id, model_id, credential_id)
    return {"key": key, "provider_id": provider_id, "model_id": model_id}


def openai_service(provider: Any, **kw: Any) -> Any:
    factory = kw.pop("factory", None) or clients(
        transport=lambda _e: httpx.MockTransport(provider)
    )
    return service(ADAPTER, factory=factory, **kw)  # type: ignore[arg-type]


def embedding_answer(
    vectors: list[list[float]], order: list[int] | None = None
) -> dict[str, Any]:
    indexes = order or list(range(len(vectors)))
    return {
        "object": "list",
        "data": [
            {"object": "embedding", "index": i, "embedding": vectors[i]}
            for i in indexes
        ],
        "model": "text-embedding-3-small",
        "usage": {"prompt_tokens": 8, "total_tokens": 8},
    }


def embed(
    w: dict[str, Any], provider: Any, inputs: tuple[str, ...] = ("a", "b"), **kw: Any
) -> Any:
    ctx = principal(w["key"], data_class=DataClass.PUBLIC)
    return openai_service(provider, **kw).run(ctx, embed_job(w["key"], inputs))


def refused(coro: Any) -> GatewayError:
    with pytest.raises(GatewayError) as caught:
        run(coro)
    return caught.value


# --- embeddings -------------------------------------------------------------------------


def test_embeddings_come_back_in_input_order_with_the_bearer_key() -> None:
    w = openai_world()
    vectors = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
    provider = Provider({"/v1/embeddings": embedding_answer(vectors, order=[1, 0])})
    done = run(embed(w, provider))
    assert [list(v) for v in done.result.vectors] == vectors
    assert done.execution.provider_usage.input_tokens == 8
    assert provider.body() == {
        "model": "text-embedding-3-small",
        "input": ["a", "b"],
        "encoding_format": "float",
    }
    request = provider.requests[0]
    assert str(request.url) == "https://api.provider.test/v1/embeddings"
    assert request.headers["authorization"] == "Bearer sk-platform"


@pytest.mark.parametrize(
    "answer",
    [
        embedding_answer([[0.1, 0.2]] * 2),  # wrong dimension
        embedding_answer([[0.1, 0.2, 0.3]]),  # one vector for two inputs
        embedding_answer([[0.1, 0.2, 0.3]] * 3),
        embedding_answer([[0.1, 0.2, 0.3]] * 2, order=[0, 0]),  # duplicate index
        {
            "data": [
                {"index": 0, "embedding": [0, 0, 0]},
                {"index": 5, "embedding": [0, 0, 0]},
            ]
        },
        {"data": [{"embedding": [0, 0, 0]}, {"index": 1, "embedding": [0, 0, 0]}]},
        {"data": [{"index": True, "embedding": [0, 0, 0]}]},
        {"data": "not a list"},
        {"data": ["not an object"]},
        b'{"data": [{"index": 0, "embedding": [1e999, 0, 0]}, {"index": 1, "embedding": [0, 0, 0]}]}',
        ["not an object"],
    ],
    ids=[
        "dimension",
        "too-few",
        "too-many",
        "duplicate-index",
        "gap",
        "missing-index",
        "bool-index",
        "data-not-list",
        "entry-not-object",
        "infinite",
        "answer-not-object",
    ],
)
def test_a_wrong_embedding_answer_is_rejected(answer: Any) -> None:
    w = openai_world()
    error = refused(embed(w, Provider({"/v1/embeddings": answer})))
    assert error.code is AiErrorCode.PROVIDER_REJECTED
    assert executions()[0]["status"] == "failed"


def test_an_answer_without_usage_reports_none() -> None:
    w = openai_world()
    answer = embedding_answer([[0.0, 0.0, 0.0]] * 2)
    del answer["usage"]
    done = run(embed(w, Provider({"/v1/embeddings": answer})))
    assert done.execution.provider_usage is None


def test_ordered_vectors_requires_exactly_the_input_positions() -> None:
    assert ordered_vectors(
        [{"index": 1, "embedding": "b"}, {"index": 0, "embedding": "a"}]
    ) == ["a", "b"]
    assert ordered_vectors([]) == []


# --- rerank ------------------------------------------------------------------------------


def rerank_answer(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": "rerank-1",
        "model": "m",
        "usage": {"total_tokens": 9},
        "results": results,
    }


def rerank(w: dict[str, Any], provider: Any, **kw: Any) -> Any:
    ctx = principal(w["key"], Capability.RERANK)
    return openai_service(provider, **kw).run(ctx, rerank_job(w["key"]))


def test_rerank_on_a_local_model_that_declares_it() -> None:
    w = openai_world(Capability.RERANK, ProviderBoundary.LOCAL)
    results = [
        {"index": 2, "relevance_score": 0.9},
        {"index": 0, "relevance_score": 0.1},
    ]
    provider = Provider({"/v1/rerank": rerank_answer(results)})
    done = run(rerank(w, provider))
    assert [(h.index, h.relevance_score) for h in done.result.hits] == [
        (2, 0.9),
        (0, 0.1),
    ]
    assert provider.body() == {
        "model": "m",
        "query": "q?",
        "documents": ["a", "bb", "ccc"],
    }
    assert str(provider.requests[0].url) == "http://models.local:8080/v1/rerank"


def test_rerank_passes_top_n() -> None:
    w = openai_world(Capability.RERANK, ProviderBoundary.LOCAL)
    provider = Provider(
        {"/v1/rerank": rerank_answer([{"index": 1, "relevance_score": 1}])}
    )
    from ai_gateway.execution.jobs import RerankJob
    from ai_sdk_m8.schemas import RerankRequest

    job = RerankJob(
        RerankRequest(profile_key=w["key"], query="q", documents=("a", "b"), top_n=1)
    )
    done = run(
        openai_service(provider).run(principal(w["key"], Capability.RERANK), job)
    )
    assert provider.body()["top_n"] == 1 and len(done.result.hits) == 1


@pytest.mark.parametrize(
    "results",
    [
        [{"index": 3, "relevance_score": 0.5}],  # out of range
        [{"index": -1, "relevance_score": 0.5}],
        [{"index": 0, "relevance_score": 0.5}, {"index": 0, "relevance_score": 0.4}],
        [{"relevance_score": 0.5}],  # missing index
        [{"index": 0}],  # missing score
        [{"index": 0, "relevance_score": "high"}],
        "not a list",
        ["not an object"],
    ],
    ids=[
        "out-of-range",
        "negative",
        "duplicate",
        "missing-index",
        "missing-score",
        "text-score",
        "not-list",
        "not-object",
    ],
)
def test_bad_rerank_hits_are_rejected(results: Any) -> None:
    w = openai_world(Capability.RERANK, ProviderBoundary.LOCAL)
    error = refused(rerank(w, Provider({"/v1/rerank": rerank_answer(results)})))
    assert error.code is AiErrorCode.PROVIDER_REJECTED


def test_a_non_finite_rerank_score_is_rejected() -> None:
    w = openai_world(Capability.RERANK, ProviderBoundary.LOCAL)
    raw = b'{"results": [{"index": 0, "relevance_score": 1e999}]}'
    assert (
        refused(rerank(w, Provider({"/v1/rerank": raw}))).code
        is AiErrorCode.PROVIDER_REJECTED
    )


# --- structured output ----------------------------------------------------------------


def completion(content: Any, **extra: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content, **extra},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27},
    }


def structured(w: dict[str, Any], provider: Any) -> Any:
    ctx = principal(w["key"], Capability.STRUCTURED_OUTPUT, data_class=DataClass.PUBLIC)
    return openai_service(provider).run(
        ctx, structured_job(w["key"], "Invoice 42, total 7")
    )


def test_structured_output_with_a_json_schema_response_format() -> None:
    w = openai_world(Capability.STRUCTURED_OUTPUT)
    provider = Provider(
        {"/v1/chat/completions": completion('{"number": 42, "total": 7}')}
    )
    done = run(structured(w, provider))
    assert done.result.output == {"number": 42, "total": 7}
    usage = done.execution.provider_usage
    assert (usage.input_tokens, usage.output_tokens) == (20, 7)
    assert provider.body() == {
        "model": "m",
        "messages": [{"role": "user", "content": "Invoice 42, total 7"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "Invoice", "schema": {"type": "object"}},
        },
        "max_tokens": 1024,
        "temperature": 0,
    }


@pytest.mark.parametrize(
    "answer",
    [
        completion(None, refusal="I can't help with that."),
        completion("not json"),
        completion("[1, 2]"),  # not an object
        {"choices": []},
        {"choices": "x"},
        {"choices": [{"message": "x"}]},
        {"choices": ["x"]},
    ],
    ids=[
        "refusal",
        "not-json",
        "not-object",
        "no-choice",
        "choices-not-list",
        "message-not-object",
        "choice-not-object",
    ],
)
def test_an_unusable_completion_is_rejected(answer: Any) -> None:
    w = openai_world(Capability.STRUCTURED_OUTPUT)
    error = refused(structured(w, Provider({"/v1/chat/completions": answer})))
    assert error.code is AiErrorCode.PROVIDER_REJECTED


# --- capability and the probe -----------------------------------------------------------


def test_an_unsupported_capability_is_refused_before_any_call() -> None:
    with pytest.raises(ProviderFailure) as caught:
        require_capability(ADAPTER, Capability.OCR)  # type: ignore[arg-type]
    assert (
        caught.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED
        and caught.value.before_send
    )
    assert Capability.OCR not in ADAPTER.capabilities
    assert isinstance(ADAPTERS[ProviderType.OPENAI_COMPATIBLE], OpenAiCompatibleAdapter)


def test_the_probe_lists_the_models() -> None:
    from ai_gateway.credentials.store import ResolvedSecret
    from ai_gateway.providers.http import Deadline, ProviderEndpoint

    w = openai_world()
    provider = Provider({"/v1/models": {"object": "list", "data": []}})
    factory = clients(transport=lambda _e: httpx.MockTransport(provider))
    with as_owner() as c:
        row = (
            c.execute(
                sa.select(ai_provider).where(ai_provider.c.id == w["provider_id"])
            )
            .mappings()
            .one()
        )

    async def probe() -> None:
        async with factory.client(ProviderEndpoint.from_row(row)) as http:
            await ADAPTER.probe(http, ResolvedSecret(b"sk-probe"), Deadline.after(5))

    run(probe())
    (request,) = provider.requests
    assert request.method == "GET" and request.url.path == "/v1/models"
    assert request.headers["authorization"] == "Bearer sk-probe"


# --- one exchange over a real socket ------------------------------------------------------


def test_an_embedding_over_a_real_stub_server() -> None:
    w = openai_world()
    update(ai_provider, w["provider_id"], base_url="http://api.provider.test")
    answer = json.dumps(embedding_answer([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])).encode()

    async def scenario() -> Any:
        async with StubServer(Reply(chunks=[answer])) as server:
            factory = clients(transport=lambda _e: socket_transport(server.port)[0])
            done = await embed(w, None, factory=factory)
            return done, server

    done, server = run(scenario())
    assert done.result.vectors[1] == (4.0, 5.0, 6.0)
    (received,) = server.requests
    assert received.request_line == "POST /v1/embeddings HTTP/1.1"
    assert received.header("authorization") == "Bearer sk-platform"
    assert received.header("accept-encoding") == "identity"
    assert json.loads(received.body)["input"] == ["a", "b"]
    # The real transport recorded the first byte before writing it.
    assert executions()[0]["first_byte_sent_at"] is not None

"""
The OpenAI-compatible adapter (``T30``): OpenAI and servers that speak its API.

Routes, on the provider's ``base_url`` (which carries any version prefix the
server needs, such as ``/v1`` behind a gateway path):

* ``embedding`` — ``POST /v1/embeddings`` with ``encoding_format: float``;
  each ``data[]`` entry carries its ``index``, and the vectors are put back
  in input order only when those indexes are exactly ``0 … n-1``;
* ``structured_output`` — ``POST /v1/chat/completions`` with
  ``response_format = {type: json_schema, json_schema: {name, schema}}``,
  ``max_tokens`` set to the reserved output cap and ``temperature: 0``; the
  first choice's ``message.content`` is parsed as JSON under the depth cap
  (a refusal, which carries no content, is rejected);
* ``rerank`` — ``POST /v1/rerank`` (the Jina/Cohere shape vLLM and
  llama.cpp serve) for models whose row declares ``rerank``: ``results[]``
  of ``index`` and ``relevance_score``, checked by the shared validator;
* ``GET /v1/models`` — the probe.

OCR is not served: the core refuses it before any request.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from ai_sdk_m8.schemas import Capability, ProviderUsage
from ai_sdk_m8.schemas.management import ProviderType
from pydantic import JsonValue

from ai_gateway.credentials.store import ResolvedSecret

from .base import AdapterCall, EmbedOutput, RerankOutput, StructuredOutput
from .http import Deadline, ProviderHttpClient, parse_json
from .outputs import RawHit, bounded_count, rejected

EMBEDDINGS: Final = "/v1/embeddings"
CHAT_COMPLETIONS: Final = "/v1/chat/completions"
RERANK: Final = "/v1/rerank"
MODELS: Final = "/v1/models"


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise rejected()
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise rejected()
    return value


def _usage(answer: dict[str, JsonValue]) -> ProviderUsage | None:
    usage = answer.get("usage")
    if not isinstance(usage, dict):
        return None
    return ProviderUsage(
        input_tokens=bounded_count(usage.get("prompt_tokens")),
        output_tokens=bounded_count(usage.get("completion_tokens")),
    )


def ordered_vectors(data: list[JsonValue]) -> list[JsonValue]:
    """The ``data[]`` vectors in input order; indexes must be exactly 0 … n-1."""
    by_index: dict[int, JsonValue] = {}
    for item in data:
        entry = _object(item)
        index = entry.get("index")
        if isinstance(index, bool) or not isinstance(index, int) or index in by_index:
            raise rejected()
        by_index[index] = entry.get("embedding")
    if sorted(by_index) != list(range(len(by_index))):
        raise rejected()
    return [by_index[i] for i in range(len(by_index))]


async def embed_openai(call: AdapterCall, inputs: Sequence[str]) -> EmbedOutput:
    """``POST /v1/embeddings`` in the OpenAI shape (shared with Mistral)."""
    body = {
        "model": call.model.external_model_id,
        "input": list(inputs),
        "encoding_format": "float",
    }
    answer = _object((await call.post(EMBEDDINGS, body)).body)
    vectors = ordered_vectors(_list(answer.get("data")))
    return EmbedOutput(vectors, _usage(answer))


async def structured_openai(
    call: AdapterCall,
    text: str,
    schema_name: str,
    json_schema: Mapping[str, JsonValue],
    max_output_tokens: int,
) -> StructuredOutput:
    """``POST /v1/chat/completions`` with a ``json_schema`` response format."""
    body = {
        "model": call.model.external_model_id,
        "messages": [{"role": "user", "content": text}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": schema_name, "schema": dict(json_schema)},
        },
        "max_tokens": max_output_tokens,
        "temperature": 0,
    }
    answer = _object((await call.post(CHAT_COMPLETIONS, body)).body)
    choices = _list(answer.get("choices"))
    if not choices:
        raise rejected()
    content = _object(_object(choices[0]).get("message")).get("content")
    if not isinstance(content, str):
        raise rejected()
    return StructuredOutput(parse_json(content.encode("utf-8")), _usage(answer))


class OpenAiCompatibleAdapter:
    """``provider_type = openai_compatible``: embeddings, structured output, rerank."""

    provider_type: ProviderType = ProviderType.OPENAI_COMPATIBLE
    capabilities: frozenset[Capability] = frozenset(
        {Capability.EMBEDDING, Capability.STRUCTURED_OUTPUT, Capability.RERANK}
    )

    async def embed(self, call: AdapterCall, inputs: Sequence[str]) -> EmbedOutput:
        """``POST /v1/embeddings``; the vectors are validated by the core."""
        return await embed_openai(call, inputs)

    async def rerank(
        self,
        call: AdapterCall,
        query: str,
        documents: Sequence[str],
        top_n: int | None,
    ) -> RerankOutput:
        """``POST /v1/rerank``; the hits are validated by the core."""
        body: dict[str, object] = {
            "model": call.model.external_model_id,
            "query": query,
            "documents": list(documents),
        }
        if top_n is not None:
            body["top_n"] = top_n
        answer = _object((await call.post(RERANK, body)).body)
        hits: list[RawHit] = []
        for item in _list(answer.get("results")):
            entry = _object(item)
            hits.append((entry.get("index"), entry.get("relevance_score")))
        return RerankOutput(tuple(hits), _usage(answer))

    async def structured_output(
        self,
        call: AdapterCall,
        text: str,
        schema_name: str,
        json_schema: Mapping[str, JsonValue],
        max_output_tokens: int,
    ) -> StructuredOutput:
        """``POST /v1/chat/completions`` with a ``json_schema`` response format."""
        return await structured_openai(
            call, text, schema_name, json_schema, max_output_tokens
        )

    async def probe(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
    ) -> None:
        """The minimal authenticated request: ``GET /v1/models``."""
        await client.request("GET", MODELS, deadline=deadline, secret=secret)


__all__ = [
    "CHAT_COMPLETIONS",
    "EMBEDDINGS",
    "MODELS",
    "RERANK",
    "OpenAiCompatibleAdapter",
    "embed_openai",
    "ordered_vectors",
    "structured_openai",
]

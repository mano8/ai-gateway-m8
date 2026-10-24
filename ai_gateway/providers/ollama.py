"""
The Ollama adapter (``T28``): local models on ``ai_net``.

Routes, from the Ollama API reference (``docs/api.md``):

* ``embedding`` — ``POST /api/embed`` with the recorded model and every
  input, ``truncate: false`` so an input longer than the model's context
  fails instead of being embedded cut short;
* ``structured_output`` — ``POST /api/chat`` with ``stream: false``, the
  request's JSON schema as ``format``, ``options.num_predict`` set to the
  reserved output cap and ``temperature: 0``; the answer's
  ``message.content`` is parsed as JSON under the response depth cap;
* ``GET /api/tags`` — the probe, and the model's identity: the list answer
  carries each model's ``digest`` (``/api/show`` does not). The digest is
  recorded as ``model_revision`` with ``identity_assurance = provider_digest``
  when the superuser registers the model, and re-checked by the scheduler; a
  digest that changed, or a model no longer listed, flags the model and
  every execution is refused until a new row is registered — a silent
  same-dimension model swap never reaches an index.

Ollama has no rerank route. Credentials are optional (``auth_type = none``
by default; an authenticating proxy in front is served like any provider).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from ai_sdk_m8.schemas import Capability, ProviderUsage
from ai_sdk_m8.schemas.management import ProviderType
from pydantic import JsonValue

from ai_gateway.credentials.store import ResolvedSecret

from .base import AdapterCall, EmbedOutput, RerankOutput, StructuredOutput, unsupported
from .http import Deadline, ProviderHttpClient, parse_json
from .outputs import bounded_count, rejected

#: An Ollama model digest as ``/api/tags`` lists it: bare SHA-256 hex.
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")

EMBED: Final = "/api/embed"
CHAT: Final = "/api/chat"
TAGS: Final = "/api/tags"


def tagged(name: str) -> str:
    """``name`` with Ollama's implicit ``:latest`` tag made explicit."""
    return name if ":" in name.rsplit("/", 1)[-1] else f"{name}:latest"


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise rejected()
    return value


def _listed_names(entry: dict[str, JsonValue]) -> set[str]:
    return {
        tagged(name)
        for name in (entry.get("name"), entry.get("model"))
        if isinstance(name, str)
    }


def digest_of(tags: JsonValue, external_model_id: str) -> str | None:
    """
    The digest ``/api/tags`` lists for ``external_model_id``, or ``None``.

    A malformed listing, or a malformed digest for the model, is refused.
    """
    models = _object(tags).get("models")
    if not isinstance(models, list):
        raise rejected()
    wanted = tagged(external_model_id)
    for item in models:
        entry = _object(item)
        if wanted not in _listed_names(entry):
            continue
        digest = entry.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise rejected()
        return digest
    return None


class OllamaAdapter:
    """``provider_type = ollama``: embeddings and structured output."""

    provider_type: ProviderType = ProviderType.OLLAMA
    capabilities: frozenset[Capability] = frozenset(
        {Capability.EMBEDDING, Capability.STRUCTURED_OUTPUT}
    )

    async def embed(self, call: AdapterCall, inputs: Sequence[str]) -> EmbedOutput:
        """``POST /api/embed``; the vectors are validated by the core."""
        body = {
            "model": call.model.external_model_id,
            "input": list(inputs),
            "truncate": False,
        }
        answer = _object((await call.post(EMBED, body)).body)
        usage = ProviderUsage(
            input_tokens=bounded_count(answer.get("prompt_eval_count"))
        )
        return EmbedOutput(answer.get("embeddings"), usage)

    async def rerank(
        self,
        call: AdapterCall,
        query: str,
        documents: Sequence[str],
        top_n: int | None,
    ) -> RerankOutput:
        """Ollama has no rerank route."""
        raise unsupported()

    async def structured_output(
        self,
        call: AdapterCall,
        text: str,
        schema_name: str,
        json_schema: Mapping[str, JsonValue],
        max_output_tokens: int,
    ) -> StructuredOutput:
        """``POST /api/chat`` with the schema as ``format``, output capped."""
        body = {
            "model": call.model.external_model_id,
            "messages": [{"role": "user", "content": text}],
            "stream": False,
            "format": dict(json_schema),
            "options": {"num_predict": max_output_tokens, "temperature": 0},
        }
        answer = _object((await call.post(CHAT, body)).body)
        content = _object(answer.get("message")).get("content")
        if not isinstance(content, str):
            raise rejected()
        usage = ProviderUsage(
            input_tokens=bounded_count(answer.get("prompt_eval_count")),
            output_tokens=bounded_count(answer.get("eval_count")),
        )
        return StructuredOutput(parse_json(content.encode("utf-8")), usage)

    async def probe(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
    ) -> None:
        """The minimal authenticated request: ``GET /api/tags``."""
        await client.request("GET", TAGS, deadline=deadline, secret=secret)

    async def tags(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
    ) -> JsonValue:
        """The ``/api/tags`` listing; read each model's digest with :func:`digest_of`."""
        return (
            await client.request("GET", TAGS, deadline=deadline, secret=secret)
        ).body


__all__ = ["CHAT", "EMBED", "TAGS", "OllamaAdapter", "digest_of", "tagged"]

"""
What each capability asks of an execution (D-24).

A job names its capability and profile, computes its **admission units** —
fixed before dispatch from the request and the recorded profile revision,
never from what a provider later reports — and runs its one adapter call.
Validation is the job's, not the adapter's: every answer passes
:mod:`ai_gateway.providers.outputs` (or the structured-output validator)
inside :meth:`ExecutionJob.execute`, before the core settles anything.

Admission units:

* embedding — the total input characters;
* rerank — the query characters plus every candidate's;
* structured output — the input characters plus the output cap the gateway
  passes to the provider as its hard limit: the recorded revision's
  ``max_output_tokens``, or :data:`DEFAULT_MAX_OUTPUT_TOKENS`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Generic, Protocol, TypeVar

from ai_sdk_m8.schemas import (
    Capability,
    EmbedRequest,
    EmbedResult,
    ProviderUsage,
    RerankRequest,
    RerankResult,
    StructuredOutputRequest,
    StructuredOutputResult,
)
from pydantic import BaseModel, JsonValue

from ai_gateway.providers import outputs
from ai_gateway.providers.base import AdapterCall, ProviderAdapter

#: The output cap of a structured-output revision that names none.
DEFAULT_MAX_OUTPUT_TOKENS: Final = 1024

R = TypeVar("R", bound=BaseModel)


@dataclass(frozen=True)
class Completed(Generic[R]):
    """A validated result and the usage the provider reported (not charged)."""

    result: R
    usage: ProviderUsage | None = None


class Admission(Protocol):
    """What the reservation needs of a request: the facts that admit it."""

    @property
    def capability(self) -> Capability:
        """The capability the route serves."""

    @property
    def profile_key(self) -> str:
        """The profile the request names (bound to the context's)."""

    @property
    def expected_identity(self) -> str | None:
        """An execution-identity pin, refused when the resolution differs."""

    def units(self, config: Mapping[str, JsonValue]) -> int:
        """Admission units, from the request and the recorded revision."""


class ExecutionJob(Admission, Protocol[R]):
    """One capability request, as the execution core runs it."""

    async def execute(
        self, adapter: ProviderAdapter, call: AdapterCall
    ) -> Completed[R]:
        """Run the adapter call and validate its answer."""


def output_cap(config: Mapping[str, JsonValue]) -> int:
    """The output cap of a structured-output revision (positive integer)."""
    value = config.get("max_output_tokens")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return DEFAULT_MAX_OUTPUT_TOKENS


@dataclass(frozen=True)
class EmbedJob:
    """``embedding``: one finite vector of the model's dimensions per input."""

    request: EmbedRequest
    capability: Capability = field(default=Capability.EMBEDDING, init=False)
    expected_identity: None = field(default=None, init=False)

    @property
    def profile_key(self) -> str:
        """The request's profile."""
        return self.request.profile_key

    def units(self, config: Mapping[str, JsonValue]) -> int:
        """Total input characters."""
        return sum(len(text) for text in self.request.inputs)

    async def execute(
        self, adapter: ProviderAdapter, call: AdapterCall
    ) -> Completed[EmbedResult]:
        """Embed, then check count, dimensions and finiteness."""
        output = await adapter.embed(call, self.request.inputs)
        dimensions = call.model.dimensions
        if dimensions is None:
            raise outputs.rejected()
        vectors = outputs.embeddings(
            output.vectors, count=len(self.request.inputs), dimensions=dimensions
        )
        return Completed(
            EmbedResult(dimensions=dimensions, vectors=vectors), output.usage
        )


@dataclass(frozen=True)
class RerankJob:
    """``rerank``: in-range, unique hits with finite scores."""

    request: RerankRequest
    capability: Capability = field(default=Capability.RERANK, init=False)
    expected_identity: None = field(default=None, init=False)

    @property
    def profile_key(self) -> str:
        """The request's profile."""
        return self.request.profile_key

    def units(self, config: Mapping[str, JsonValue]) -> int:
        """Query characters plus every candidate's."""
        return len(self.request.query) + sum(len(d) for d in self.request.documents)

    async def execute(
        self, adapter: ProviderAdapter, call: AdapterCall
    ) -> Completed[RerankResult]:
        """Rank, then check every hit."""
        request = self.request
        output = await adapter.rerank(
            call, request.query, request.documents, request.top_n
        )
        result = outputs.rerank(
            output.hits, candidates=len(request.documents), top_n=request.top_n
        )
        return Completed(result, output.usage)


def require_object(value: JsonValue) -> dict[str, JsonValue]:
    """The minimum every structured output satisfies: a JSON object."""
    if not isinstance(value, dict):
        raise outputs.rejected()
    return value


@dataclass(frozen=True)
class StructuredOutputJob:
    """``structured_output``: a JSON object valid against the request schema."""

    request: StructuredOutputRequest
    validate: Callable[[JsonValue], dict[str, JsonValue]] = require_object
    capability: Capability = field(default=Capability.STRUCTURED_OUTPUT, init=False)
    expected_identity: None = field(default=None, init=False)

    @property
    def profile_key(self) -> str:
        """The request's profile."""
        return self.request.profile_key

    def units(self, config: Mapping[str, JsonValue]) -> int:
        """Input characters plus the output cap passed to the provider."""
        return len(self.request.input) + output_cap(config)

    async def execute(
        self, adapter: ProviderAdapter, call: AdapterCall
    ) -> Completed[StructuredOutputResult]:
        """Produce, then validate against the request's schema."""
        request = self.request
        output = await adapter.structured_output(
            call,
            request.input,
            request.schema_name,
            request.json_schema,
            output_cap(call.config),
        )
        return Completed(
            StructuredOutputResult(output=self.validate(output.output)), output.usage
        )


__all__ = [
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "Admission",
    "Completed",
    "EmbedJob",
    "ExecutionJob",
    "RerankJob",
    "StructuredOutputJob",
    "output_cap",
    "require_object",
]

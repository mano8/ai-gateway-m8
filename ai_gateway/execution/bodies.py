"""
Request bodies of the execution routes, bounded while they are read (``T31``).

Every JSON route reads ``request.stream()`` itself and counts the bytes as
they arrive — a chunked body without ``Content-Length`` included, and a
``Content-Length`` is never trusted — aborting at ``AI_MAX_REQUEST_BYTES``
with ``request_too_large`` before anything is parsed. The JSON is then
parsed under the response depth cap, and the closed SDK model validates it:
a malformed body answers FastAPI's standard ``422`` (C-01's error codes name
no malformed-request code), carrying field locations and messages only.

The per-capability input bounds (D-24) are checked on the validated model:
``AI_MAX_EMBED_INPUTS`` inputs of ``AI_MAX_INPUT_CHARS`` each,
``AI_MAX_RERANK_CANDIDATES`` candidates with the query and each candidate
within ``AI_MAX_INPUT_CHARS``, and a structured-output input within
``AI_MAX_INPUT_CHARS``, its schema inside the closed dialect
(:mod:`.schema_dialect`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TypeVar

from ai_sdk_m8.schemas import (
    AiErrorCode,
    EmbedRequest,
    RerankRequest,
    StructuredOutputRequest,
)
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, JsonValue, ValidationError

from ai_gateway.core.errors import GatewayError
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.http import parse_json

from .schema_dialect import SchemaRefused, check_schema

M = TypeVar("M", bound=BaseModel)


def too_large() -> GatewayError:
    """The refusal of a body or an input past its bound."""
    return GatewayError(AiErrorCode.REQUEST_TOO_LARGE)


async def read_bounded(chunks: AsyncIterator[bytes], limit: int) -> bytes:
    """Every byte of ``chunks``, or ``request_too_large`` at byte ``limit + 1``."""
    body = bytearray()
    async for chunk in chunks:
        if len(body) + len(chunk) > limit:
            raise too_large()
        body += chunk
    return bytes(body)


def invalid(location: str, message: str) -> RequestValidationError:
    """FastAPI's ``422`` for a request outside its model (no value echoed)."""
    return RequestValidationError(
        [{"type": "value_error", "loc": ("body", location), "msg": message}]
    )


def parse_body(raw: bytes) -> JsonValue:
    """The JSON value of a body, under the depth cap; ``422`` otherwise."""
    try:
        return parse_json(raw)
    except ProviderFailure:
        raise invalid("body", "the body is not JSON within the depth cap") from None


def validated(model: type[M], value: JsonValue) -> M:
    """``value`` as ``model``; its errors as FastAPI's ``422``, inputs dropped."""
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        errors = [
            {"type": e["type"], "loc": ("body", *e["loc"]), "msg": e["msg"]}
            for e in exc.errors(include_input=False, include_url=False)
        ]
        raise RequestValidationError(errors) from None


@dataclass(frozen=True)
class InputBounds:
    """The D-24 input bounds of the JSON routes."""

    max_embed_inputs: int
    max_input_chars: int
    max_rerank_candidates: int
    max_schema_bytes: int
    max_schema_depth: int

    @classmethod
    def from_settings(cls, settings: object) -> InputBounds:
        """From gateway ``Settings``."""
        return cls(
            max_embed_inputs=int(getattr(settings, "AI_MAX_EMBED_INPUTS")),
            max_input_chars=int(getattr(settings, "AI_MAX_INPUT_CHARS")),
            max_rerank_candidates=int(getattr(settings, "AI_MAX_RERANK_CANDIDATES")),
            max_schema_bytes=int(getattr(settings, "AI_MAX_SCHEMA_BYTES")),
            max_schema_depth=int(getattr(settings, "AI_MAX_SCHEMA_DEPTH")),
        )

    def embed(self, request: EmbedRequest) -> None:
        """At most the inputs allowed, each within the character bound."""
        if len(request.inputs) > self.max_embed_inputs or any(
            len(text) > self.max_input_chars for text in request.inputs
        ):
            raise too_large()

    def rerank(self, request: RerankRequest) -> None:
        """At most the candidates allowed; the query and each within bound."""
        texts = (request.query, *request.documents)
        if len(request.documents) > self.max_rerank_candidates or any(
            len(text) > self.max_input_chars for text in texts
        ):
            raise too_large()

    def structured(self, request: StructuredOutputRequest) -> None:
        """The input within bound; the schema inside the closed dialect."""
        if len(request.input) > self.max_input_chars:
            raise too_large()
        try:
            check_schema(
                request.json_schema,
                max_bytes=self.max_schema_bytes,
                max_depth=self.max_schema_depth,
            )
        except SchemaRefused as refused:
            raise invalid("json_schema", str(refused)) from None


__all__ = [
    "InputBounds",
    "invalid",
    "parse_body",
    "read_bounded",
    "too_large",
    "validated",
]

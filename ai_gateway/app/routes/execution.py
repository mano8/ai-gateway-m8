"""
Execution routes — provider calls authorized by a signed job context.

The router is built by :func:`ai_gateway.core.execution_guard.build_execution_router`,
so every route added here inherits the mandatory service-client and
job-context dependency. Its prefix is the SDK route table's ``v1/execute``;
each route's capability comes from that table.

``embed``, ``rerank`` and ``structured-output`` (``T31``) read their JSON
body through :mod:`ai_gateway.execution.bodies` — counted while it is read,
then validated and held to the D-24 input bounds — and run one execution
through the shipped core. A structured-output schema is accepted only in the
closed dialect, and the model's output is validated against it before the
execution settles. The OCR routes are :mod:`.ocr`'s.
"""

from __future__ import annotations

from ai_sdk_m8.schemas import (
    EmbedRequest,
    EmbedResponse,
    RerankRequest,
    RerankResponse,
    StructuredOutputRequest,
    StructuredOutputResponse,
)
from fastapi import Request
from pydantic import BaseModel

from ai_gateway.core.config import settings
from ai_gateway.core.deps import execution_service
from ai_gateway.core.execution_guard import JobContextDep, build_execution_router
from ai_gateway.execution.bodies import (
    InputBounds,
    parse_body,
    read_bounded,
    validated,
)
from ai_gateway.execution.jobs import EmbedJob, RerankJob, StructuredOutputJob
from ai_gateway.execution.schema_dialect import validator

router = build_execution_router(prefix="/v1/execute", tags=["execution"])


async def _body[M: BaseModel](request: Request, model: type[M]) -> M:
    raw = await read_bounded(request.stream(), settings.AI_MAX_REQUEST_BYTES)
    return validated(model, parse_body(raw))


def _bounds() -> InputBounds:
    return InputBounds.from_settings(settings)


@router.post("/embed", response_model=EmbedResponse)
async def execute_embed(request: Request, principal: JobContextDep) -> EmbedResponse:
    """One vector per input, of the profile's embedding space."""
    body = await _body(request, EmbedRequest)
    _bounds().embed(body)
    done = await execution_service.run(principal, EmbedJob(body))
    return EmbedResponse(result=done.result, execution=done.execution)


@router.post("/rerank", response_model=RerankResponse)
async def execute_rerank(request: Request, principal: JobContextDep) -> RerankResponse:
    """The candidates ranked against the query (local providers only)."""
    body = await _body(request, RerankRequest)
    _bounds().rerank(body)
    done = await execution_service.run(principal, RerankJob(body))
    return RerankResponse(result=done.result, execution=done.execution)


@router.post("/structured-output", response_model=StructuredOutputResponse)
async def execute_structured_output(
    request: Request, principal: JobContextDep
) -> StructuredOutputResponse:
    """A JSON object valid against the request's closed-dialect schema."""
    body = await _body(request, StructuredOutputRequest)
    _bounds().structured(body)
    job = StructuredOutputJob(body, validate=validator(body.json_schema))
    done = await execution_service.run(principal, job)
    return StructuredOutputResponse(result=done.result, execution=done.execution)


__all__ = ["router"]

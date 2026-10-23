"""
The OCR execution routes (``T31``, D-44, D-45) — served only with ``ocr``.

``POST v1/execute/ocr`` (a ``phase = spool`` context): the ``receiving`` row
first, then the two-part body read as it streams — the ``options`` part
checked against the signed hash and recorded, the ``document`` part written
into the spool under the D-45 receiver, never past the signed
``input_bytes`` and within ``AI_UPLOAD_TOTAL_TIMEOUT_SECONDS`` — then the
size and digest checked against the signed claims and the row moved to
``spooled``. The answer is ``{spool_id, expires_at}``; no provider is
called. Any failure (a refusal, a disconnect, the timeout) abandons the row
and removes the spool before it is answered.

``POST v1/execute/ocr/{spool_id}:dispatch`` (a ``phase = dispatch`` context
naming that spool): the spool is opened under ``LOCK_SH`` and held for the
whole provider read, the execution runs through the shipped core (whose
reservation is the D-44 ``spooled → pending`` binding), and a terminal row's
spool is removed before the answer.

With ``ocr`` absent from ``AI_CAPABILITIES_ENABLED`` the whole family is
``404``, before any credential is read (Q12).
"""

from __future__ import annotations

import asyncio
import time
from uuid import UUID

from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    OcrRequest,
    OcrResponse,
    OcrSpoolResult,
)
from fastapi import HTTPException, Request, status

from ai_gateway.core.config import settings
from ai_gateway.core.deps import db_engine, execution_service
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.execution_guard import JobContextDep, build_execution_router
from ai_gateway.core.job_context import JobContextPrincipal
from ai_gateway.execution import ocr
from ai_gateway.execution.bodies import parse_body, validated
from ai_gateway.execution.limits import ExecutionLimits
from ai_gateway.execution.multipart import (
    MultipartRefused,
    boundary_of,
    read_ocr_parts,
)
from ai_gateway.execution.spool import Receiver, SpoolReader, clean


def require_ocr_enabled() -> None:
    """``404`` for the whole family unless ``ocr`` is enabled (Q12)."""
    if Capability.OCR not in settings.capabilities_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND)


router = build_execution_router(
    gate=require_ocr_enabled, prefix="/v1/execute", tags=["execution"]
)


def _config() -> ocr.SpoolConfig:
    return ocr.SpoolConfig.from_settings(settings)


def _abandon(
    config: ocr.SpoolConfig, receiver: Receiver, execution_id: UUID, error: AiErrorCode
) -> None:
    """The failure path: close the receiver, settle the row, remove the spool."""
    receiver.close()
    ocr.abandon(db_engine, execution_id, error)
    clean(config.layout, db_engine, execution_id)


def _error_of(exc: BaseException) -> AiErrorCode:
    if isinstance(exc, GatewayError):
        return exc.code
    if isinstance(exc, TimeoutError):
        return AiErrorCode.TIMEOUT
    return AiErrorCode.CONTEXT_INVALID


async def _receive(
    request: Request,
    principal: JobContextPrincipal,
    config: ocr.SpoolConfig,
    receiver: Receiver,
    execution_id: UUID,
    boundary: bytes,
) -> None:
    async def on_options(raw: bytes) -> None:
        options = validated(OcrRequest, parse_body(raw))
        ocr.check_options(principal, options, config)
        await asyncio.to_thread(ocr.record_options, db_engine, execution_id, options)
        await asyncio.to_thread(receiver.open)

    async def on_document(chunk: bytes) -> None:
        await asyncio.to_thread(receiver.write, chunk)

    await read_ocr_parts(
        request.stream(),
        boundary,
        limit=config.max_request_bytes,
        on_options=on_options,
        on_document=on_document,
    )
    ocr.check_document(principal, receiver.written, receiver.sha256)


@router.post("/ocr", response_model=OcrSpoolResult)
async def execute_ocr_spool(
    request: Request, principal: JobContextDep
) -> OcrSpoolResult:
    """Phase 1: spool and verify the document; no provider call."""
    config = _config()
    try:
        boundary = boundary_of(request.headers.get("content-type"))
    except MultipartRefused as refused:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(refused)) from None
    execution_id = await asyncio.to_thread(
        ocr.open_spool,
        db_engine,
        principal,
        config=config,
        limits=ExecutionLimits.from_settings(settings),
        unit=config.layout.allocation_unit(),
    )
    receiver = Receiver(
        config.layout,
        db_engine,
        execution_id,
        input_bytes=int(principal.payload.input_bytes or 0),
        lease_deadline=time.monotonic() + config.upload_timeout_seconds,
    )
    try:
        async with asyncio.timeout(config.upload_timeout_seconds):
            await _receive(request, principal, config, receiver, execution_id, boundary)
        expires_at = await asyncio.to_thread(receiver.commit, config.ttl_seconds)
    except BaseException as exc:
        cleanup = asyncio.to_thread(
            _abandon, config, receiver, execution_id, _error_of(exc)
        )
        await asyncio.shield(cleanup)
        if isinstance(exc, MultipartRefused):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
        if isinstance(exc, TimeoutError):
            raise GatewayError(AiErrorCode.TIMEOUT) from None
        raise
    return OcrSpoolResult(spool_id=execution_id, expires_at=expires_at)


@router.post("/ocr/{spool_id}:dispatch", response_model=OcrResponse)
async def execute_ocr_dispatch(spool_id: UUID, principal: JobContextDep) -> OcrResponse:
    """Phase 2: disclose the spool to the provider under the dispatch context."""
    config = _config()
    ocr.require_dispatch_context(principal, spool_id)
    row = await asyncio.to_thread(ocr.spool_row, db_engine, spool_id)
    reader = SpoolReader(config.layout, db_engine, spool_id)
    await asyncio.to_thread(reader.open, row.input_bytes)
    try:
        job = ocr.dispatch_job(principal, row, reader, config.max_pages)
        done = await execution_service.run(principal, job)
    finally:
        reader.close()
        await asyncio.shield(
            asyncio.to_thread(clean, config.layout, db_engine, spool_id)
        )
    return OcrResponse(result=done.result, execution=done.execution)


__all__ = ["require_ocr_enabled", "router"]

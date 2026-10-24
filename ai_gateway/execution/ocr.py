"""
OCR's two phases around the spool (``T31``, D-44, D-45).

**Phase 1** (``POST v1/execute/ocr`` with a ``phase = spool`` context):
:func:`open_spool` creates the ``receiving`` row before the first body byte
is read, in one transaction — the context's ``jti`` redeemed, the run's
**one** rate-window admission per principal and its client occupancy slot,
and, under the ``ai_spool_capacity`` row's lock, the global
``AI_MAX_CONCURRENT_SPOOLS`` bound on live ``receiving`` rows and the
capacity reservation sized from the **signed** ``input_bytes`` rounded up
to the filesystem's allocation unit (A-4). A context whose ``input_bytes``
exceeds ``AI_MAX_REQUEST_BYTES`` is refused before any of it. The
``options`` part must hash to the signed ``ocr_options_hash``
(:func:`options_hash`) and name at most ``AI_MAX_OCR_PAGES`` pages; it is
recorded on the row at ``receiving → spooled``, because ``:dispatch``
carries no body.

**Phase 2** (``:dispatch``): the reservation's ``spooled → pending`` binding
is :mod:`.reservation`'s; :func:`dispatch_job` builds the job from the
row — the recorded options and pin, the reserved page list (the requested
pages, or the first ``AI_MAX_OCR_PAGES``), and the spool read under its
lock.

Any failure before ``spooled`` abandons the row (:func:`abandon`, slot and
reservation released by the terminal transition and the cleaner).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Final
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.jobcontext import JobContextPhase
from ai_sdk_m8.schemas import AiErrorCode, Capability, OcrOptions, OcrRequest
from ai_sdk_m8.signed import canonicalize
from pydantic import JsonValue
from sqlalchemy import Connection, Engine

from ai_gateway.core.errors import GatewayError
from ai_gateway.core.job_context import JobContextPrincipal
from ai_gateway.core.restore_state import assert_not_held
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.db_models.accounting import ai_execution, ai_spool_capacity

from .jobs import OcrJob
from .limits import ExecutionLimits
from .reservation import admit, scopes_of
from .settlement import close
from .spool import SpoolLayout, SpoolReader, capacity_exhausted, reserved_size

_E = ai_execution
_C = ai_spool_capacity

#: The phases a spool can be abandoned from.
_SPOOL_PHASES: Final = (ExecutionStatus.RECEIVING.value, ExecutionStatus.SPOOLED.value)


def options_hash(options: OcrOptions) -> str:
    """``SHA-256(JCS(options))`` over the closed model, ``null`` pages included."""
    return hashlib.sha256(canonicalize(options.model_dump(mode="json"))).hexdigest()


@dataclass(frozen=True)
class SpoolConfig:
    """The D-45 settings of one gateway process."""

    layout: SpoolLayout
    max_bytes: int
    ttl_seconds: int
    max_concurrent: int
    upload_timeout_seconds: int
    max_request_bytes: int
    max_pages: int

    @classmethod
    def from_settings(cls, settings: object) -> SpoolConfig:
        """From gateway ``Settings`` (``AI_OCR_SPOOL_DIR`` set with ``ocr``)."""

        def get(name: str) -> object:
            return getattr(settings, name)

        return cls(
            layout=SpoolLayout(Path(str(get("AI_OCR_SPOOL_DIR")))),
            max_bytes=int(str(get("AI_OCR_SPOOL_MAX_BYTES"))),
            ttl_seconds=int(str(get("AI_OCR_SPOOL_TTL_SECONDS"))),
            max_concurrent=int(str(get("AI_MAX_CONCURRENT_SPOOLS"))),
            upload_timeout_seconds=int(str(get("AI_UPLOAD_TOTAL_TIMEOUT_SECONDS"))),
            max_request_bytes=int(str(get("AI_MAX_REQUEST_BYTES"))),
            max_pages=int(str(get("AI_MAX_OCR_PAGES"))),
        )


# --- phase 1 ------------------------------------------------------------------------


def require_spool_context(principal: JobContextPrincipal, config: SpoolConfig) -> int:
    """A ``phase = spool`` context within the body cap; its ``input_bytes``."""
    payload = principal.payload
    if payload.phase is not JobContextPhase.SPOOL or payload.input_bytes is None:
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)
    if payload.input_bytes > config.max_request_bytes:
        raise GatewayError(AiErrorCode.REQUEST_TOO_LARGE)
    return payload.input_bytes


def _reserve_capacity(connection: Connection, size: int, config: SpoolConfig) -> None:
    """
    Under the capacity row's lock: the spool count, then the bytes.

    The row is the installation's (seeded by ``ai-migrate``); the bound is
    ``AI_OCR_SPOOL_MAX_BYTES`` of this process.
    """
    connection.execute(sa.select(_C.c.id).where(_C.c.id == 1).with_for_update())
    receiving = connection.execute(
        sa.select(sa.func.count())
        .select_from(_E)
        .where(
            _E.c.status == ExecutionStatus.RECEIVING.value,
            _E.c.spool_lease_until > sa.func.now(),
        )
    ).scalar_one()
    if receiving >= config.max_concurrent:
        raise capacity_exhausted()
    reserved = connection.execute(
        sa.update(_C)
        .where(_C.c.id == 1, _C.c.reserved_bytes + size <= config.max_bytes)
        .values(reserved_bytes=_C.c.reserved_bytes + size)
        .returning(_C.c.reserved_bytes)
    ).first()
    if reserved is None:
        raise capacity_exhausted()


def open_spool(
    engine: Engine,
    principal: JobContextPrincipal,
    *,
    config: SpoolConfig,
    limits: ExecutionLimits,
    unit: int,
) -> UUID:
    """The ``receiving`` row, its admissions, lease and reservation; its id."""
    input_bytes = require_spool_context(principal, config)
    payload = principal.payload
    size = reserved_size(input_bytes, unit)
    execution_id = uuid.uuid4()
    with engine.begin() as connection:
        assert_not_held(connection, None, budgeted=False)  # no budget before phase 2
        principal.redeem(connection)
        admit(connection, principal.client_id, scopes_of(principal, limits), limits)
        _reserve_capacity(connection, size, config)
        connection.execute(
            sa.insert(_E).values(
                id=execution_id,
                status=ExecutionStatus.RECEIVING.value,
                capability=Capability.OCR.value,
                profile_key=payload.profile_key,
                data_class=payload.data_class.value,
                client_scope_id=principal.client_id,
                tenant_scope_id=payload.tenant_id,
                user_scope_id=payload.user_id,
                jti=payload.jti,
                issuer=payload.iss,
                azp=payload.azp,
                job_ref=payload.job_ref,
                attempt=payload.attempt,
                input_sha256=payload.input_sha256,
                input_bytes=input_bytes,
                ocr_options_hash=payload.ocr_options_hash,
                spool_lease_until=sa.func.now()
                + timedelta(seconds=config.upload_timeout_seconds),
                spool_bytes_reserved=size,
            )
        )
    return execution_id


def check_options(
    principal: JobContextPrincipal, request: OcrRequest, config: SpoolConfig
) -> None:
    """The ``options`` part matches the signed claims and the page bound."""
    principal.require_profile(request.profile_key)
    if options_hash(request.options) != principal.payload.ocr_options_hash:
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)
    pages = request.options.pages
    if pages is not None and len(pages) > config.max_pages:
        raise GatewayError(AiErrorCode.REQUEST_TOO_LARGE)


def check_document(principal: JobContextPrincipal, size: int, sha256: str) -> None:
    """The spooled bytes are exactly the signed ones."""
    payload = principal.payload
    if size != payload.input_bytes or sha256 != payload.input_sha256:
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)


def record_options(engine: Engine, execution_id: UUID, request: OcrRequest) -> None:
    """Keep the options and the pin for ``:dispatch`` (while ``receiving``)."""
    with engine.begin() as connection:
        connection.execute(
            sa.update(_E)
            .where(
                _E.c.id == execution_id, _E.c.status == ExecutionStatus.RECEIVING.value
            )
            .values(
                ocr_options=request.options.model_dump(mode="json"),
                expected_execution_identity=request.expected_execution_identity,
            )
        )


def abandon(engine: Engine, execution_id: UUID, error: AiErrorCode) -> bool:
    """A spool that will not be dispatched: terminal, slot returned, cleanup due."""
    with engine.begin() as connection:
        moved = close(
            connection,
            sa.and_(_E.c.id == execution_id, _E.c.status.in_(_SPOOL_PHASES)),
            status=ExecutionStatus.ABANDONED,
            error=error,
        )
    return bool(moved)


# --- phase 2 ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpoolRow:
    """What ``:dispatch`` reads of a spool before reserving it."""

    input_bytes: int
    options: Mapping[str, JsonValue]
    expected_identity: str | None


def require_dispatch_context(principal: JobContextPrincipal, spool_id: UUID) -> None:
    """A ``phase = dispatch`` context naming this spool."""
    payload = principal.payload
    if payload.phase is not JobContextPhase.DISPATCH or payload.spool_id != str(
        spool_id
    ):
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)


def spool_row(engine: Engine, spool_id: UUID) -> SpoolRow:
    """The ``spooled`` row's recorded options; ``context_invalid`` otherwise."""
    with engine.connect() as connection:
        row = connection.execute(
            sa.select(
                _E.c.input_bytes, _E.c.ocr_options, _E.c.expected_execution_identity
            ).where(_E.c.id == spool_id, _E.c.status == ExecutionStatus.SPOOLED.value)
        ).first()
    if row is None:
        raise GatewayError(AiErrorCode.CONTEXT_INVALID)
    return SpoolRow(int(row[0]), dict(row[1]), row[2])


def dispatch_job(
    principal: JobContextPrincipal,
    row: SpoolRow,
    reader: SpoolReader,
    max_pages: int,
) -> OcrJob:
    """The OCR job of a spool: its recorded options, pin and reserved pages."""
    options = OcrOptions.model_validate(row.options)
    request = OcrRequest(
        profile_key=principal.payload.profile_key,
        options=options,
        expected_execution_identity=row.expected_identity,
    )
    pages = options.pages if options.pages is not None else tuple(range(max_pages))
    return OcrJob(request, reader, tuple(pages))


__all__ = [
    "SpoolConfig",
    "SpoolRow",
    "abandon",
    "check_document",
    "check_options",
    "dispatch_job",
    "open_spool",
    "options_hash",
    "record_options",
    "require_dispatch_context",
    "require_spool_context",
    "spool_row",
]

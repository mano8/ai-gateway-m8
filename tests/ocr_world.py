"""
OCR worlds for the Mistral and remote-artifact tests (T29).

A spooled row is planted as phase 1 (``T31``) leaves it — the spool
context's binding recorded, the run's occupancy slot taken — and the
dispatch context is minted bound to it, so every run goes through the
shipped reservation's ``spooled → pending`` path, the marker, the adapter
and one settlement.
"""

from __future__ import annotations

import contextlib
import hashlib
import time
import uuid
from collections.abc import AsyncIterator, Iterator, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from ai_sdk_m8.schemas import Capability, DataClass, OcrRequest, ProviderBoundary
from ai_sdk_m8.schemas.management import ProviderType, ScopeType
from ai_sdk_m8.signed import derive_kid, public_key_from_seed

from ai_gateway.core import deps
from ai_gateway.core.job_context import JobContextPrincipal
from ai_gateway.core.keyfiles import KeyMaterial
from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.execution.artifacts import ArtifactPolicy, ArtifactScheduler
from ai_gateway.execution.jobs import OcrJob
from ai_gateway.execution.receipts import ReceiptSigner
from ai_gateway.execution.reservation import occupy
from ai_gateway.providers.http import ClientFactory
from ai_gateway.providers.mistral import MistralAdapter
from conftest import MEDIA_SERVICE, TEST_ENV
from execution_world import (
    clients,
    make_binding,
    make_credential,
    make_model,
    make_profile,
    make_provider,
    principal,
    service,
)
from mistral_stub import MistralStub
from provider_stubs import StubServer, socket_transport
import pg_harness as pg

DEPLOYMENT_ID = TEST_ENV["AI_DEPLOYMENT_ID"]
RECEIPT_SEED = bytes(range(32))
RECEIPT_PUBLIC = public_key_from_seed(RECEIPT_SEED)
RECEIPT_KID = derive_kid(RECEIPT_PUBLIC)
SIGNER = ReceiptSigner(
    KeyMaterial(RECEIPT_SEED, Path("receipt.key")), RECEIPT_KID, DEPLOYMENT_ID
)

#: Inline below 64 bytes; every larger document is uploaded.
ADAPTER = MistralAdapter(inline_threshold_bytes=64, file_expiry_seconds=3600)

#: A short PDF (inline) and a document of no known signature (uploaded).
PDF = b"%PDF-1.7\n%stub\n"
BLOB = bytes(range(256)) * 16

POLICY = ArtifactPolicy(
    deployment_id=DEPLOYMENT_ID,
    visibility_grace_seconds=300,
    negative_listings=3,
    max_delete_attempts=3,
    max_pending_hours=72,
    platform_incident_listing=True,
    platform_sweep_enabled=True,
    total_deadline_seconds=30,
    timeout_seconds=5.0,
)

TENANT = "7a9b1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d"


class Document:
    """A verified document; optionally one that breaks mid-stream."""

    def __init__(self, data: bytes, *, fail_after: int | None = None) -> None:
        self.data = data
        self.fail_after = fail_after
        self.reads = 0

    @property
    def size(self) -> int:
        return len(self.data)

    async def chunks(self) -> AsyncIterator[bytes]:
        for start in range(0, len(self.data), 1024):
            if self.fail_after is not None and start >= self.fail_after:
                raise RuntimeError("the spool read failed mid-body")
            yield self.data[start : start + 1024]

    async def read(self) -> bytes:
        self.reads += 1
        return self.data


def mistral_world(
    scope: ScopeType = ScopeType.GLOBAL, *, consent: bool = False
) -> dict[str, Any]:
    """A Mistral provider, an OCR model and profile, one key ``sk-old``."""
    provider_id = make_provider(
        ProviderBoundary.EXTERNAL,
        ProviderType.MISTRAL,
        base_url="http://api.provider.test",
    )
    model_id = make_model(
        provider_id, Capability.OCR, external_model_id="mistral-ocr-latest"
    )
    profile_id, key = make_profile(Capability.OCR)
    tenant = TENANT if scope is ScopeType.TENANT else None
    credential_id = make_credential(
        provider_id, scope, tenant_id=tenant, secret="sk-old"
    )
    if consent:
        from ai_gateway.db_models.credentials import ai_credential

        with deps.db_engine.begin() as c:
            c.execute(
                sa.update(ai_credential)
                .where(ai_credential.c.id == credential_id)
                .values(incident_listing_consent=True)
            )
    make_binding(profile_id, model_id, credential_id, scope, tenant_id=tenant)
    return {
        "key": key,
        "provider_id": provider_id,
        "model_id": model_id,
        "credential_id": credential_id,
        "tenant": tenant,
    }


def spooled(
    w: Mapping[str, Any], document: bytes, *, options_hash: str = "c" * 64
) -> JobContextPrincipal:
    """Plant phase 1's ``spooled`` row; the dispatch context bound to it."""
    spool_id = uuid.uuid4()
    digest = hashlib.sha256(document).hexdigest()
    claims: dict[str, Any] = {
        "phase": "dispatch",
        "spool_id": str(spool_id),
        "input_sha256": digest,
        "input_bytes": len(document),
        "ocr_options_hash": options_hash,
        "tenant_id": w["tenant"],
        # A platform key may serve public data only (D-08); a tenant's, internal.
        "data_class": DataClass.PUBLIC if w["tenant"] is None else DataClass.INTERNAL,
        # A dispatch context lives at most AI_DISPATCH_CONTEXT_TTL_SECONDS.
        "exp": int(time.time()) + 25,
    }
    dispatch = principal(w["key"], Capability.OCR, **claims)
    payload = dispatch.payload
    with deps.db_engine.begin() as c:
        occupy(c, MEDIA_SERVICE.client_id, None)
        c.execute(
            sa.insert(ai_execution).values(
                id=spool_id,
                status="receiving",
                capability="ocr",
                profile_key=payload.profile_key,
                data_class=payload.data_class.value,
                client_scope_id=MEDIA_SERVICE.client_id,
                tenant_scope_id=payload.tenant_id,
                user_scope_id=payload.user_id,
                jti=str(uuid.uuid4()),
                issuer=payload.iss,
                azp=payload.azp,
                job_ref=payload.job_ref,
                attempt=payload.attempt,
                input_sha256=digest,
                input_bytes=len(document),
                ocr_options_hash=options_hash,
                spool_lease_until=sa.func.now() + timedelta(minutes=5),
                spool_bytes_reserved=len(document),
            )
        )
        c.execute(
            sa.update(ai_execution)
            .where(ai_execution.c.id == spool_id)
            .values(
                status="spooled",
                spool_file_created=True,
                spool_expires_at=sa.func.now() + timedelta(minutes=5),
            )
        )
    return dispatch


def ocr_job(
    w: Mapping[str, Any], document: Any, pages: tuple[int, ...] = (0, 1)
) -> OcrJob:
    return OcrJob(OcrRequest(profile_key=w["key"]), document, pages)


def ocr_service(factory: ClientFactory, **kw: Any) -> Any:
    kw.setdefault("deployment_id", DEPLOYMENT_ID)
    kw.setdefault("receipts", SIGNER)
    return service(ADAPTER, factory=factory, **kw)  # type: ignore[arg-type]


def scheduler(
    factory: ClientFactory, policy: ArtifactPolicy = POLICY
) -> ArtifactScheduler:
    return ArtifactScheduler(
        deps.db_engine,
        deps.credential_store,
        factory,
        {ProviderType.MISTRAL: ADAPTER},
        policy,
    )


@contextlib.asynccontextmanager
async def mistral(stub: MistralStub, **kw: Any) -> AsyncIterator[ClientFactory]:
    """A real stub server and the client factory reaching it."""
    async with StubServer(stub, **kw) as server:
        yield clients(transport=lambda _e: socket_transport(server.port)[0])


async def dispatch(
    factory: ClientFactory,
    w: Mapping[str, Any],
    document: Any,
    pages: tuple[int, ...] = (0, 1),
    **kw: Any,
) -> Any:
    """One ``:dispatch``; the outcome, or the ``GatewayError`` it raised."""
    from ai_gateway.core.errors import GatewayError

    data = document.data if isinstance(document, Document) else document
    source = document if isinstance(document, Document) else Document(document)
    svc = ocr_service(factory, **kw)
    try:
        return await svc.run(spooled(w, data), ocr_job(w, source, pages))
    except GatewayError as error:
        return error
    finally:
        await svc.drain()


def artifacts() -> list[Mapping[str, Any]]:
    with deps.db_engine.connect() as c:
        return list(
            c.execute(
                sa.select(ai_provider_remote_artifact).order_by(
                    ai_provider_remote_artifact.c.created_at
                )
            ).mappings()
        )


@contextlib.contextmanager
def _superuser() -> Iterator[sa.Connection]:
    # The admin engine autocommits: the setting is the session's, not a tx's.
    admin = pg.admin_engine(pg.DB_NAME)
    try:
        with admin.connect() as c:
            c.execute(sa.text("SET session_replication_role = replica"))
            yield c
    finally:
        admin.dispose()


def age_artifacts(**values: Any) -> None:
    """Rewrite every artifact row's clocks as time passing would (triggers off)."""
    values.setdefault("next_attempt_at", None)
    with _superuser() as c:
        c.execute(sa.update(ai_provider_remote_artifact).values(**values))


def due() -> None:
    """Every artifact row past its deadline plus the grace, and due now."""
    age_artifacts(
        upload_deadline_at=sa.func.now() - timedelta(hours=1),
        first_negative_listing_at=sa.case(
            (
                ai_provider_remote_artifact.c.first_negative_listing_at.is_(None),
                None,
            ),
            else_=sa.func.now() - timedelta(hours=1),
        ),
    )


__all__ = [
    "ADAPTER",
    "BLOB",
    "DEPLOYMENT_ID",
    "PDF",
    "POLICY",
    "RECEIPT_KID",
    "RECEIPT_PUBLIC",
    "SIGNER",
    "TENANT",
    "Document",
    "age_artifacts",
    "artifacts",
    "dispatch",
    "due",
    "mistral",
    "mistral_world",
    "ocr_job",
    "ocr_service",
    "scheduler",
    "spooled",
]

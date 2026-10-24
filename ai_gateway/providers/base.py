"""
The provider adapter protocol (D-20, D-24).

An adapter turns one capability call into requests on the call's
:class:`~ai_gateway.providers.http.ProviderHttpClient` — fixed route
templates for its ``provider_type``, the recorded model's id URL-encoded
where a path carries it, never a caller-supplied path or query — and
extracts the values of the answer. It does not decide whether those values
are usable: the execution core passes every result through
:mod:`ai_gateway.providers.outputs` before settlement, so no adapter can skip
the check.

**Dispatch progress.** Every request of a call goes through the call's
:class:`AdapterCall`, which hands the client the call's
:class:`~ai_gateway.providers.http.DispatchProgress`: ``first_byte_sent()``
is recorded before the first byte of the call's first request and never
reset, so in a workflow that spans several requests no outcome of a later
request restores refund eligibility (D-24).

An adapter declares the capabilities it serves; the core refuses any other
with ``capability_unsupported`` before a request is built.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from ai_sdk_m8.schemas import AiErrorCode, Capability, OcrPage, ProviderUsage
from ai_sdk_m8.schemas.management import ProviderType
from pydantic import JsonValue

from ai_gateway.credentials.store import ResolvedSecret

from .errors import ProviderFailure, refused_before_send
from .http import Deadline, DispatchProgress, ProviderAnswer, ProviderHttpClient
from .outputs import RawHit


@dataclass(frozen=True)
class ModelRef:
    """The recorded model row a call must use, and only it."""

    model_id: UUID
    external_model_id: str
    dimensions: int | None = None
    max_output_tokens: int | None = None
    model_revision: str | None = None


class DocumentSource(Protocol):
    """A verified OCR input: exactly ``size`` bytes, streamed or read whole."""

    @property
    def size(self) -> int:
        """The verified size in bytes (the signed ``input_bytes``)."""

    def chunks(self) -> AsyncIterator[bytes]:
        """The bytes in order, read under the spool's lock (D-45)."""

    async def read(self) -> bytes:
        """The whole document (only below the inline threshold)."""


class ArtifactTracker(Protocol):
    """The D-43 handler transitions of one execution's provider-side file."""

    @property
    def gateway_file_name(self) -> str:
        """``m8ai-<deployment_id>-<execution_id>``: the only name ever sent."""

    @property
    def intended(self) -> bool:
        """Whether the upload intent was committed (bytes may have left)."""

    def intent_progress(self) -> DispatchProgress:
        """Progress whose first byte also commits the upload intent (a)."""

    async def activate(self, remote_id: str, expires_at: int | None) -> bool:
        """(b) ``uploading → active`` before the id is used, or (d) after a loss."""

    async def lost(self) -> None:
        """(c) ``uploading → uploading_unknown_id``: the id never came back."""

    async def release(self) -> None:
        """(g) ``active → pending_delete``, in the adapter's ``finally``."""

    async def deleted(self) -> None:
        """(h) closed, on the provider's deletion proof for the recorded id."""


@dataclass(frozen=True)
class ArtifactProofs:
    """
    What a provider's recorded reference documents about its files (D-43).

    Nothing is assumed: each flag is re-read from the provider's reference
    when its adapter is written, and recorded with the step.
    """

    deletion_proof: bool
    absence_proof: bool
    list_consistency: str
    safe_server_side_prefix_listing: bool
    sweep_absence_proof: bool


@dataclass(frozen=True)
class RemoteFile:
    """One provider file of **this** deployment's prefix; nothing else is kept."""

    remote_id: str
    file_name: str
    created_at: int | None


@dataclass(frozen=True)
class Listing:
    """The prefix matches of one listing; ``complete`` when it reached the end."""

    files: tuple[RemoteFile, ...]
    complete: bool


@dataclass(frozen=True)
class AdapterCall:
    """One dispatched call: its client, credential, model and revision config."""

    client: ProviderHttpClient
    secret: ResolvedSecret | None
    model: ModelRef
    progress: DispatchProgress
    deadline: Deadline
    config: Mapping[str, JsonValue] = field(default_factory=dict)
    artifacts: ArtifactTracker | None = None

    async def post(
        self,
        path: str,
        body: Mapping[str, object],
        *,
        accept: frozenset[int] = frozenset(),
    ) -> ProviderAnswer:
        """``POST`` a JSON body under the call's deadline and progress."""
        return await self.client.request(
            "POST",
            path,
            deadline=self.deadline,
            json_body=body,
            secret=self.secret,
            progress=self.progress,
            accept=accept,
        )

    async def get(
        self,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        accept: frozenset[int] = frozenset(),
    ) -> ProviderAnswer:
        """``GET`` under the call's deadline and progress."""
        return await self.client.request(
            "GET",
            path,
            deadline=self.deadline,
            query=query,
            secret=self.secret,
            progress=self.progress,
            accept=accept,
        )

    async def delete(
        self, path: str, *, accept: frozenset[int] = frozenset()
    ) -> ProviderAnswer:
        """``DELETE`` under the call's deadline and progress."""
        return await self.client.request(
            "DELETE",
            path,
            deadline=self.deadline,
            secret=self.secret,
            progress=self.progress,
            accept=accept,
        )


@dataclass(frozen=True)
class EmbedOutput:
    """The vectors an adapter extracted, unvalidated, and reported usage."""

    vectors: object
    usage: ProviderUsage | None = None


@dataclass(frozen=True)
class RerankOutput:
    """The hits an adapter extracted, unvalidated, and reported usage."""

    hits: tuple[RawHit, ...]
    usage: ProviderUsage | None = None


@dataclass(frozen=True)
class StructuredOutput:
    """The JSON value the model produced, unvalidated, and reported usage."""

    output: JsonValue
    usage: ProviderUsage | None = None


@dataclass(frozen=True)
class OcrOutput:
    """The pages an adapter extracted (closed models), and reported usage."""

    pages: tuple[OcrPage, ...]
    usage: ProviderUsage | None = None


class ProviderAdapter(Protocol):
    """One ``provider_type``'s requests for each capability it serves."""

    #: The provider type this adapter speaks.
    provider_type: ProviderType
    #: The capabilities it serves; the core refuses every other one.
    capabilities: frozenset[Capability]

    async def embed(self, call: AdapterCall, inputs: Sequence[str]) -> EmbedOutput:
        """Embed ``inputs`` with the recorded model."""

    async def rerank(
        self,
        call: AdapterCall,
        query: str,
        documents: Sequence[str],
        top_n: int | None,
    ) -> RerankOutput:
        """Rank ``documents`` against ``query`` with the recorded model."""

    async def structured_output(
        self,
        call: AdapterCall,
        text: str,
        schema_name: str,
        json_schema: Mapping[str, JsonValue],
        max_output_tokens: int,
    ) -> StructuredOutput:
        """Produce a JSON value for ``json_schema`` from ``text``, capped output."""


class OcrAdapter(ProviderAdapter, Protocol):
    """An adapter that serves OCR and owns provider-side files (D-43)."""

    #: What the provider's reference documents about its files.
    proofs: ArtifactProofs

    async def ocr(
        self, call: AdapterCall, document: DocumentSource, pages: Sequence[int]
    ) -> OcrOutput:
        """OCR of the verified document, for exactly ``pages``."""

    async def delete_file(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
        remote_id: str,
    ) -> bool:
        """Delete one file; ``True`` only on the documented deletion proof."""

    async def list_files(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
        prefix: str,
    ) -> Listing:
        """This deployment's files only (by prefix); every other entry dropped."""


def unsupported() -> ProviderFailure:
    """The refusal of a capability an adapter does not serve; nothing was sent."""
    return refused_before_send(AiErrorCode.CAPABILITY_UNSUPPORTED)


def require_capability(adapter: ProviderAdapter, capability: Capability) -> None:
    """Refuse ``capability`` before any request unless ``adapter`` serves it."""
    if capability not in adapter.capabilities:
        raise unsupported()


__all__ = [
    "AdapterCall",
    "ArtifactProofs",
    "ArtifactTracker",
    "DocumentSource",
    "EmbedOutput",
    "Listing",
    "ModelRef",
    "OcrAdapter",
    "OcrOutput",
    "ProviderAdapter",
    "RemoteFile",
    "RerankOutput",
    "StructuredOutput",
    "require_capability",
    "unsupported",
]

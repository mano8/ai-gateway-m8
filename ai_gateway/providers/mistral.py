"""
The Mistral adapter (``T29``): embeddings, structured output and OCR.

Routes, from Mistral's published OpenAPI document (``docs.mistral.ai/
openapi.yaml``, re-read when this step started and recorded in the plan):

* ``embedding`` and ``structured_output`` — ``POST /v1/embeddings`` and ``POST
  /v1/chat/completions`` in the OpenAI shape (shared with
  :mod:`.openai_compatible`);
* ``ocr`` — ``POST /v1/ocr`` with the gateway's **own** page list, always
  ``include_image_base64: false`` and ``include_blocks: false`` (the reference
  now defaults blocks to true); the document is

  * **inline** below ``AI_OCR_UPLOAD_INLINE_THRESHOLD_BYTES`` — a base64
    ``document_url`` (PDF) or ``image_url`` (PNG, JPEG, WebP, GIF, TIFF) data
    URL, chosen by the verified bytes' signature; anything else is uploaded;
  * **uploaded** otherwise — ``POST /v1/files`` as ``purpose=ocr``,
    ``visibility=user`` (the reference's default is ``workspace``), the
    shortest ``expiry`` covering ``AI_PROVIDER_FILE_EXPIRY_SECONDS`` and the
    gateway's own file name ``m8ai-<deployment_id>-<execution_id>`` with a
    fixed media type — never the caller's file name.

**Remote artifacts (D-43).** The upload intent is committed with
``first_byte_sent_at`` immediately before the upload's first byte, so a
connection that never opened leaves no row. The returned id is recorded
(``active``) before it is used; ``purpose``, ``visibility`` and ``expires_at``
are asserted before the OCR request, and any mismatch deletes the file and
fails the call. The adapter's ``finally`` moves the row to
``pending_delete`` and tries the deletion with the same, recorded
credential version; only ``200 {deleted: true, id}`` for the recorded id
closes it — the scheduler retries everything else. A lost upload answer
leaves the row ``uploading_unknown_id`` for the scheduler's listings.

**Proofs, as the reference documents them:** a deletion proof (that
``200``), **no** absence proof (a ``404`` or a negative listing is evidence
only), undocumented list consistency, no safe prefix filter (``search``
exists but its semantics are not documented; ``purpose`` is), so no sweep
absence proof.
"""

from __future__ import annotations

import asyncio
import base64
import math
import time
from collections.abc import Mapping, Sequence
from typing import Final

from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    OcrImage,
    OcrPage,
    PixelBox,
    ProviderUsage,
)
from ai_sdk_m8.schemas.management import ProviderType
from pydantic import JsonValue, ValidationError

from ai_gateway.credentials.store import ResolvedSecret

from .base import (
    AdapterCall,
    ArtifactProofs,
    ArtifactTracker,
    DocumentSource,
    EmbedOutput,
    Listing,
    OcrOutput,
    RemoteFile,
    RerankOutput,
    StructuredOutput,
    unsupported,
)
from .errors import ProviderFailure
from .http import Deadline, ProviderHttpClient, Upload, route
from .openai_compatible import MODELS, embed_openai, structured_openai
from .outputs import bounded_count, rejected

OCR: Final = "/v1/ocr"
FILES: Final = "/v1/files"
FILE: Final = "/v1/files/{file_id}"

#: The media type of every uploaded file: the gateway declares nothing more.
UPLOAD_MEDIA_TYPE: Final = "application/octet-stream"

#: Files per listing page, and the most pages one listing reads.
PAGE_SIZE: Final = 100
MAX_LISTING_PAGES: Final = 200

#: Slack allowed past the requested expiry when the answer is checked.
EXPIRY_SLACK_SECONDS: Final = 3600

#: Mistral's D-43 capabilities, from its reference (re-read 2026-10-22).
PROOFS: Final = ArtifactProofs(
    deletion_proof=True,
    absence_proof=False,
    list_consistency="undocumented",
    safe_server_side_prefix_listing=False,
    sweep_absence_proof=False,
)

_SIGNATURES: Final = (
    (b"%PDF-", "document_url", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image_url", "image/png"),
    (b"\xff\xd8\xff", "image_url", "image/jpeg"),
    (b"GIF87a", "image_url", "image/gif"),
    (b"GIF89a", "image_url", "image/gif"),
    (b"II*\x00", "image_url", "image/tiff"),
    (b"MM\x00*", "image_url", "image/tiff"),
)


def inline_reference(data: bytes) -> dict[str, str] | None:
    """A data-URL document for ``data``, or ``None`` when it must be uploaded."""
    kind_and_type = None
    for signature, kind, media_type in _SIGNATURES:
        if data.startswith(signature):
            kind_and_type = (kind, media_type)
            break
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind_and_type = ("image_url", "image/webp")
    if kind_and_type is None:
        return None
    kind, media_type = kind_and_type
    encoded = base64.b64encode(data).decode("ascii")
    return {"type": kind, kind: f"data:{media_type};base64,{encoded}"}


def expiry_hours(seconds: int) -> int:
    """The shortest whole-hour ``expiry`` covering ``seconds`` (at least 1)."""
    return max(1, math.ceil(seconds / 3600))


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise rejected()
    return value


def _int(value: JsonValue) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _image(entry: JsonValue) -> OcrImage | None:
    """An image region; one whose box the answer leaves incomplete is dropped."""
    image = _object(entry)
    corners = [
        _int(image.get(name))
        for name in ("top_left_x", "top_left_y", "bottom_right_x", "bottom_right_y")
    ]
    image_id = image.get("id")
    if not isinstance(image_id, str):
        raise rejected()
    x0, y0, x1, y1 = corners
    if x0 is None or y0 is None or x1 is None or y1 is None:
        return None
    return OcrImage(image_id=image_id, bbox=PixelBox(x0=x0, y0=y0, x1=x1, y1=y1))


def ocr_page(entry: JsonValue) -> OcrPage:
    """One answer page as the closed, float-free ``OcrPage``."""
    page = _object(entry)
    dimensions = _object(page.get("dimensions"))
    images = page.get("images")
    if not isinstance(images, list):
        raise rejected()
    kept = [image for image in map(_image, images) if image is not None]
    try:
        return OcrPage.model_validate(
            {
                "index": page.get("index"),
                "width_px": dimensions.get("width"),
                "height_px": dimensions.get("height"),
                "dpi": _int(dimensions.get("dpi")) or None,
                "markdown": page.get("markdown"),
                "images": kept,
            }
        )
    except ValidationError:
        raise rejected() from None


def _pages(answer: dict[str, JsonValue]) -> OcrOutput:
    pages = answer.get("pages")
    if not isinstance(pages, list):
        raise rejected()
    usage_info = answer.get("usage_info")
    usage = None
    if isinstance(usage_info, dict):
        usage = ProviderUsage(
            pages_processed=bounded_count(usage_info.get("pages_processed"))
        )
    return OcrOutput(tuple(ocr_page(p) for p in pages), usage)


class MistralAdapter:
    """``provider_type = mistral``: embeddings, structured output and OCR."""

    provider_type: ProviderType = ProviderType.MISTRAL
    capabilities: frozenset[Capability] = frozenset(
        {Capability.EMBEDDING, Capability.STRUCTURED_OUTPUT, Capability.OCR}
    )
    proofs: ArtifactProofs = PROOFS

    def __init__(
        self, *, inline_threshold_bytes: int, file_expiry_seconds: int
    ) -> None:
        self._inline_threshold = inline_threshold_bytes
        self._expiry_seconds = file_expiry_seconds

    async def embed(self, call: AdapterCall, inputs: Sequence[str]) -> EmbedOutput:
        """``POST /v1/embeddings``."""
        return await embed_openai(call, inputs)

    async def rerank(
        self,
        call: AdapterCall,
        query: str,
        documents: Sequence[str],
        top_n: int | None,
    ) -> RerankOutput:
        """Not served (rerank is local-only, and Mistral is external)."""
        raise unsupported()

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

    # --- OCR ------------------------------------------------------------------------

    async def ocr(
        self, call: AdapterCall, document: DocumentSource, pages: Sequence[int]
    ) -> OcrOutput:
        """OCR of the verified document, for exactly the gateway's ``pages``."""
        if document.size < self._inline_threshold:
            reference = inline_reference(await document.read())
            if reference is not None:
                return await self._recognize(call, reference, pages)
        if call.artifacts is None or call.secret is None:
            raise unsupported()  # no tracked upload without a recorded credential
        return await self._uploaded(call, call.artifacts, document, pages)

    async def _recognize(
        self, call: AdapterCall, reference: Mapping[str, str], pages: Sequence[int]
    ) -> OcrOutput:
        body = {
            "model": call.model.external_model_id,
            "document": dict(reference),
            "pages": list(pages),
            "include_image_base64": False,
            "include_blocks": False,
        }
        return _pages(_object((await call.post(OCR, body)).body))

    async def _uploaded(
        self,
        call: AdapterCall,
        artifacts: ArtifactTracker,
        document: DocumentSource,
        pages: Sequence[int],
    ) -> OcrOutput:
        upload = Upload(
            fields={
                "purpose": "ocr",
                "visibility": "user",
                "expiry": str(expiry_hours(self._expiry_seconds)),
            },
            field_name="file",
            file_name=artifacts.gateway_file_name,
            media_type=UPLOAD_MEDIA_TYPE,
            size=document.size,
            chunks=document.chunks,
        )
        try:
            answer = await call.client.upload(
                FILES,
                upload,
                deadline=call.deadline,
                secret=call.secret,
                progress=artifacts.intent_progress(),
            )
            stored = _object(answer.body)
            remote_id = stored.get("id")
            if not isinstance(remote_id, str) or not 0 < len(remote_id) <= 256:
                raise rejected()
        except BaseException:
            if artifacts.intended:  # bytes may have reached the provider
                await asyncio.shield(artifacts.lost())
            raise
        expires_at = _int(stored.get("expires_at"))
        if not await artifacts.activate(remote_id, expires_at):
            # Too late: a scheduler already owns the row; the id is never used.
            raise ProviderFailure(AiErrorCode.TIMEOUT)
        try:
            self._check_stored(stored, expires_at, call.deadline)
            return await self._recognize(
                call, {"type": "file", "file_id": remote_id}, pages
            )
        finally:
            await self._clean_up(call, artifacts, remote_id)

    def _check_stored(
        self, stored: dict[str, JsonValue], expires_at: int | None, deadline: Deadline
    ) -> None:
        """The file is private to the key's user and expires soon enough."""
        now = time.time()
        latest = now + expiry_hours(self._expiry_seconds) * 3600 + EXPIRY_SLACK_SECONDS
        if (
            stored.get("purpose") != "ocr"
            or stored.get("visibility") != "user"
            or expires_at is None
            or not now + deadline.remaining() <= expires_at <= latest
        ):
            raise rejected()

    async def _clean_up(
        self, call: AdapterCall, artifacts: ArtifactTracker, remote_id: str
    ) -> None:
        """Release the file and try its deletion; never reclassify the work."""
        try:
            await artifacts.release()
            if await self.delete_file(
                call.client, call.secret, call.deadline, remote_id
            ):
                await artifacts.deleted()
        except Exception:  # noqa: BLE001 - the scheduler retries a failed cleanup
            return

    # --- what the scheduler uses (D-43) ---------------------------------------

    async def delete_file(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
        remote_id: str,
    ) -> bool:
        """Delete one file; ``True`` only on the documented proof for that id."""
        answer = await client.request(
            "DELETE",
            route(FILE, file_id=remote_id),
            deadline=deadline,
            secret=secret,
            accept=frozenset({404}),
        )
        if answer.status != 200 or not isinstance(answer.body, dict):
            return False
        return answer.body.get("deleted") is True and answer.body.get("id") == remote_id

    async def list_files(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
        prefix: str,
    ) -> Listing:
        """
        Every ``purpose=ocr`` file whose name starts with ``prefix``.

        Pages to the documented end (an empty or short page, or ``total``);
        every other entry is discarded unread beyond its name — never logged,
        never kept.
        """
        found: list[RemoteFile] = []
        seen = 0
        for page in range(MAX_LISTING_PAGES):
            answer = await client.request(
                "GET",
                FILES,
                deadline=deadline,
                secret=secret,
                query={
                    "page": str(page),
                    "page_size": str(PAGE_SIZE),
                    "purpose": "ocr",
                },
            )
            body = _object(answer.body)
            data = body.get("data")
            if not isinstance(data, list):
                raise rejected()
            seen += len(data)
            found.extend(
                _remote_file(entry) for entry in data if _matches(entry, prefix)
            )
            total = _int(body.get("total"))
            if len(data) < PAGE_SIZE or (total is not None and seen >= total):
                return Listing(tuple(found), complete=True)
        return Listing(tuple(found), complete=False)

    async def probe(
        self,
        client: ProviderHttpClient,
        secret: ResolvedSecret | None,
        deadline: Deadline,
    ) -> None:
        """The minimal authenticated request: ``GET /v1/models``."""
        await client.request("GET", MODELS, deadline=deadline, secret=secret)


def _matches(entry: JsonValue, prefix: str) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("filename"), str)
        and str(entry["filename"]).startswith(prefix)
        and isinstance(entry.get("id"), str)
    )


def _remote_file(entry: JsonValue) -> RemoteFile:
    assert isinstance(entry, dict)  # nosec B101 - filtered by _matches
    return RemoteFile(
        remote_id=str(entry["id"]),
        file_name=str(entry["filename"]),
        created_at=_int(entry.get("created_at")),
    )


__all__ = [
    "FILE",
    "FILES",
    "OCR",
    "PROOFS",
    "MistralAdapter",
    "expiry_hours",
    "inline_reference",
    "ocr_page",
]

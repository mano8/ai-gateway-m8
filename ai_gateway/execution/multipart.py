"""
The OCR body: ``multipart/form-data`` read as it streams (``T31``).

Never FastAPI's spooling ``UploadFile``: :func:`read_ocr_parts` reads
``request.stream()`` once and enforces every bound **while** reading —
``AI_MAX_REQUEST_BYTES`` on the whole body (a chunked body without
``Content-Length`` included; the header is never trusted), at most
:data:`MAX_PART_HEADERS` bytes of headers per part, a bounded ``options``
part — and requires exactly two parts in order, ``options`` then
``document``; any other count, order or name is refused. The ``document``
part is handed to its sink chunk by chunk and never held whole; the
client-supplied file name is ignored. A refusal is :class:`MultipartRefused`
(``400``), or ``request_too_large`` for the body cap.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Final

from .bodies import too_large

#: The largest header block of one part.
MAX_PART_HEADERS: Final = 8 * 1024
#: The largest ``options`` part (an ``OcrRequest`` JSON).
MAX_OPTIONS_BYTES: Final = 64 * 1024
#: The largest preamble before the first delimiter.
MAX_PREAMBLE: Final = 1024

_BOUNDARY: Final = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]")
_PARAM: Final = re.compile(r';\s*([A-Za-z-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;\s]*)')
_PARTS: Final = ("options", "document")


class MultipartRefused(ValueError):
    """The body is not the two-part OCR form; the message names the rule only."""


def _params(value: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for name, raw in _PARAM.findall(";" + value.partition(";")[2]):
        text = raw[1:-1].replace('\\"', '"') if raw.startswith('"') else raw
        found.setdefault(name.lower(), text)
    return found


def boundary_of(content_type: str | None) -> bytes:
    """The boundary of a ``multipart/form-data`` content type; refused otherwise."""
    if content_type is None:
        raise MultipartRefused("multipart/form-data is required")
    kind = content_type.partition(";")[0].strip().lower()
    boundary = _params(content_type).get("boundary", "")
    if kind != "multipart/form-data" or not _BOUNDARY.fullmatch(boundary):
        raise MultipartRefused("multipart/form-data with a valid boundary is required")
    return boundary.encode("ascii")


def part_name(headers: bytes) -> str:
    """The ``name`` of a part's ``Content-Disposition: form-data`` header."""
    for line in headers.decode("latin-1").split("\r\n"):
        key, colon, value = line.partition(":")
        if not colon:
            raise MultipartRefused("a part header is malformed")
        if key.strip().lower() == "content-disposition":
            if value.partition(";")[0].strip().lower() != "form-data":
                raise MultipartRefused("a part is not form-data")
            name = _params(value).get("name")
            if name is None:
                raise MultipartRefused("a part has no name")
            return name
    raise MultipartRefused("a part has no Content-Disposition")


class _Stream:
    """A body read once, counted against its cap, buffered only at the edges."""

    def __init__(self, chunks: AsyncIterator[bytes], limit: int) -> None:
        self._chunks = chunks.__aiter__()
        self._buffer = bytearray()
        self._limit = limit
        self._total = 0

    async def _more(self) -> bool:
        try:
            chunk = await anext(self._chunks)
        except StopAsyncIteration:
            return False
        self._total += len(chunk)
        if self._total > self._limit:
            raise too_large()
        self._buffer += chunk
        return True

    async def until(self, marker: bytes, most: int) -> bytes:
        """The bytes before ``marker`` (consumed), at most ``most`` of them."""
        while True:
            at = self._buffer.find(marker)
            if 0 <= at <= most:
                data = bytes(self._buffer[:at])
                del self._buffer[: at + len(marker)]
                return data
            if len(self._buffer) > most + len(marker) or at > most:
                raise MultipartRefused("a part or its headers exceed their bound")
            if not await self._more():
                raise MultipartRefused("the body ends inside a part")

    async def stream_until(
        self, marker: bytes, sink: Callable[[bytes], Awaitable[None]]
    ) -> None:
        """Hand every byte before ``marker`` to ``sink``; consume ``marker``."""
        keep = len(marker) - 1
        while True:
            at = self._buffer.find(marker)
            if at >= 0:
                if at:
                    await sink(bytes(self._buffer[:at]))
                del self._buffer[: at + len(marker)]
                return
            if len(self._buffer) > keep:
                ready = len(self._buffer) - keep
                await sink(bytes(self._buffer[:ready]))
                del self._buffer[:ready]
            if not await self._more():
                raise MultipartRefused("the body ends inside a part")

    async def take(self, size: int) -> bytes:
        """Exactly ``size`` bytes."""
        while len(self._buffer) < size:
            if not await self._more():
                raise MultipartRefused("the body ends early")
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    async def drain(self) -> None:
        """Read (and count) whatever follows the closing delimiter."""
        self._buffer.clear()
        while await self._more():
            self._buffer.clear()


async def read_ocr_parts(
    chunks: AsyncIterator[bytes],
    boundary: bytes,
    *,
    limit: int,
    on_options: Callable[[bytes], Awaitable[None]],
    on_document: Callable[[bytes], Awaitable[None]],
) -> None:
    """Read the two-part OCR body, handing each part over as it arrives."""
    stream = _Stream(chunks, limit)
    delimiter = b"--" + boundary
    await stream.until(delimiter, MAX_PREAMBLE)
    for expected in _PARTS:
        if await stream.take(2) != b"\r\n":
            raise MultipartRefused("exactly two parts: options, then document")
        headers = await stream.until(b"\r\n\r\n", MAX_PART_HEADERS)
        if part_name(headers) != expected:
            raise MultipartRefused("exactly two parts: options, then document")
        if expected == "options":
            await on_options(await stream.until(b"\r\n" + delimiter, MAX_OPTIONS_BYTES))
        else:
            await stream.stream_until(b"\r\n" + delimiter, on_document)
    if await stream.take(2) != b"--":
        raise MultipartRefused("exactly two parts: options, then document")
    await stream.drain()


__all__ = [
    "MAX_OPTIONS_BYTES",
    "MAX_PART_HEADERS",
    "MultipartRefused",
    "boundary_of",
    "part_name",
    "read_ocr_parts",
]

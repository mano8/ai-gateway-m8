"""
The OCR body reader and the D-45 spool protocol at their edges (T31).

The routes' tests drive the common paths; these drive the parser's and the
file protocol's refusals directly: a malformed form, a truncated body, a
retired lock, a lease that ran out, a full volume, a file that changed size.
"""

from __future__ import annotations

import errno
import fcntl
import os
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass

from ai_gateway.core import deps
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError
from ai_gateway.db_models.accounting import ai_execution, ai_spool_capacity
from ai_gateway.execution import ocr, spool
from ai_gateway.execution.multipart import (
    MultipartRefused,
    boundary_of,
    part_name,
    read_ocr_parts,
)
from ai_gateway.execution.spool import (
    Cleaned,
    Receiver,
    SpoolLayout,
    SpoolReader,
    clean,
    reserved_size,
)
from execution_world import principal, run
from ocr_world import mistral_world

pytestmark = pytest.mark.usefixtures("clean_db")


# --- the multipart reader ---------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "boundary"),
    [
        ("multipart/form-data; boundary=abc", b"abc"),
        ('multipart/form-data; charset=utf-8; boundary="a b:c"', b"a b:c"),
        ("Multipart/Form-Data;boundary=x", b"x"),
    ],
)
def test_the_boundary_is_read_from_the_content_type(
    header: str, boundary: bytes
) -> None:
    assert boundary_of(header) == boundary


@pytest.mark.parametrize(
    "header",
    [
        None,
        "application/json",
        "multipart/form-data",
        "multipart/mixed; boundary=abc",
        "multipart/form-data; boundary=" + "a" * 71,
        'multipart/form-data; boundary="ends with space "',
    ],
)
def test_a_content_type_without_a_valid_boundary_is_refused(header: str | None) -> None:
    with pytest.raises(MultipartRefused):
        boundary_of(header)


def test_a_part_name_is_read_and_a_file_name_ignored() -> None:
    assert (
        part_name(
            b'Content-Disposition: form-data; filename="name=\\"x\\""; name="document"'
        )
        == "document"
    )
    assert (
        part_name(
            b"Content-Type: text/plain\r\ncontent-disposition: form-data; name=options"
        )
        == "options"
    )


@pytest.mark.parametrize(
    "headers",
    [
        b"no colon here",
        b'Content-Disposition: attachment; name="document"',
        b'Content-Disposition: form-data; filename="x"',
        b"Content-Type: application/json",
    ],
)
def test_a_part_header_outside_the_form_is_refused(headers: bytes) -> None:
    with pytest.raises(MultipartRefused):
        part_name(headers)


async def _chunks(*pieces: bytes) -> AsyncIterator[bytes]:
    for piece in pieces:
        yield piece


def _read(*pieces: bytes, limit: int = 1 << 20) -> tuple[list[bytes], list[bytes]]:
    options: list[bytes] = []
    document: list[bytes] = []

    async def on_options(raw: bytes) -> None:
        options.append(raw)

    async def on_document(raw: bytes) -> None:
        document.append(raw)

    run(
        read_ocr_parts(
            _chunks(*pieces),
            b"B",
            limit=limit,
            on_options=on_options,
            on_document=on_document,
        )
    )
    return options, document


def _form(document: bytes = b"abc", epilogue: bytes = b"") -> bytes:
    return (
        b'preamble\r\n--B\r\nContent-Disposition: form-data; name="options"\r\n\r\n{}\r\n'
        b'--B\r\nContent-Disposition: form-data; name="document"\r\n\r\n'
        + document
        + b"\r\n--B--\r\n"
        + epilogue
    )


def test_a_form_split_anywhere_is_read_with_its_epilogue() -> None:
    body = _form(b"x\r\n--Cnot-a-delimiter-B" * 3, epilogue=b"trailing")
    pieces = [body[i : i + 3] for i in range(0, len(body), 3)]
    options, document = _read(*pieces)
    assert options == [b"{}"]
    assert b"".join(document) == b"x\r\n--Cnot-a-delimiter-B" * 3


@pytest.mark.parametrize(
    "body",
    [
        _form()[:40],
        _form()[:-12],
        b"x" * 2048,
        _form().replace(b"--B--", b"--B\r\n"),
        _form().replace(
            b'\r\n--B\r\nContent-Disposition: form-data; name="document"',
            b'--B\r\nContent-Disposition: form-data; name="document"',
        ),
        _form()[:-4],
    ],
    ids=[
        "inside-options",
        "inside-document",
        "no-delimiter",
        "no-close",
        "glued-delimiter",
        "ends-at-delimiter",
    ],
)
def test_a_truncated_or_malformed_form_is_refused(body: bytes) -> None:
    with pytest.raises(MultipartRefused):
        _read(body)


def test_the_body_cap_is_counted_while_reading() -> None:
    with pytest.raises(GatewayError) as caught:
        _read(_form(b"x" * 500), limit=200)
    assert caught.value.code is AiErrorCode.REQUEST_TOO_LARGE


# --- the spool protocol -----------------------------------------------------------


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SpoolLayout:
    root = tmp_path / "spool"
    root.mkdir()
    monkeypatch.setattr(settings, "AI_OCR_SPOOL_DIR", root)
    with deps.db_engine.begin() as c:
        c.execute(sa.update(ai_spool_capacity).values(reserved_bytes=0))
    return SpoolLayout(root)


def receiving(document: bytes = b"0123456789") -> uuid.UUID:
    import hashlib

    from ai_sdk_m8.schemas import OcrOptions

    w = mistral_world()
    context = principal(
        w["key"],
        Capability.OCR,
        data_class=DataClass.PUBLIC,
        phase="spool",
        input_sha256=hashlib.sha256(document).hexdigest(),
        input_bytes=len(document),
        ocr_options_hash=ocr.options_hash(OcrOptions()),
    )
    config = ocr.SpoolConfig.from_settings(settings)
    return ocr.open_spool(
        deps.db_engine,
        context,
        config=config,
        limits=deps.execution_service._limits(),
        unit=4096,
    )


def receiver(layout: SpoolLayout, execution_id: uuid.UUID, **kw: Any) -> Receiver:
    kw.setdefault("input_bytes", 10)
    kw.setdefault("lease_deadline", time.monotonic() + 60)
    return Receiver(layout, deps.db_engine, execution_id, **kw)


def test_reservations_round_up_to_the_allocation_unit(layout: SpoolLayout) -> None:
    assert [reserved_size(n, 4096) for n in (1, 4096, 4097)] == [4096, 4096, 8192]
    assert layout.allocation_unit() > 0


def test_a_write_after_the_lease_deadline_is_refused(layout: SpoolLayout) -> None:
    execution_id = receiving()
    late = receiver(layout, execution_id, lease_deadline=time.monotonic() - 1)
    late.open()
    with pytest.raises(GatewayError) as caught:
        late.write(b"0")
    assert caught.value.code is AiErrorCode.TIMEOUT
    late.close()


@pytest.mark.parametrize(
    ("failure", "expected"),
    [(errno.ENOSPC, GatewayError), (errno.EIO, OSError)],
    ids=["full-volume", "io-error"],
)
def test_a_write_failure_is_typed_when_the_volume_is_full(
    layout: SpoolLayout, monkeypatch: pytest.MonkeyPatch, failure: int, expected: type
) -> None:
    execution_id = receiving()
    writer = receiver(layout, execution_id)
    writer.open()

    def broken(_fd: int, _data: Any) -> int:
        raise OSError(failure, os.strerror(failure))

    monkeypatch.setattr(spool.os, "write", broken)
    with pytest.raises(expected) as caught:
        writer.write(b"0123")
    if expected is GatewayError:
        assert caught.value.code is AiErrorCode.CAPACITY_EXHAUSTED  # type: ignore[attr-defined]
    monkeypatch.undo()
    writer.close()


def test_a_commit_after_the_row_left_receiving_is_refused(layout: SpoolLayout) -> None:
    execution_id = receiving()
    writer = receiver(layout, execution_id)
    writer.open()
    writer.write(b"0123456789")
    with deps.db_engine.begin() as c:
        c.execute(
            sa.update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(ocr_options={"pages": None})
        )
    assert ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
    with pytest.raises(GatewayError) as caught:
        writer.commit(60)
    assert caught.value.code is AiErrorCode.TIMEOUT
    writer.close()
    assert clean(layout, deps.db_engine, execution_id) is Cleaned.RELEASED


def _spooled(layout: SpoolLayout, document: bytes = b"0123456789") -> uuid.UUID:
    execution_id = receiving(document)
    with deps.db_engine.begin() as c:
        c.execute(
            sa.update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(ocr_options={"pages": None})
        )
    writer = receiver(layout, execution_id, input_bytes=len(document))
    writer.open()
    writer.write(document)
    writer.commit(60)
    return execution_id


def test_a_reader_refuses_a_row_or_a_file_that_changed(layout: SpoolLayout) -> None:
    execution_id = _spooled(layout)
    reader = SpoolReader(layout, deps.db_engine, execution_id)
    with pytest.raises(GatewayError):
        reader.open(11)  # the file is not the signed size
    ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
    with pytest.raises(GatewayError):
        SpoolReader(layout, deps.db_engine, execution_id).open(10)  # no longer spooled


def test_a_reader_stops_at_a_shortened_file(layout: SpoolLayout) -> None:
    execution_id = _spooled(layout)
    reader = SpoolReader(layout, deps.db_engine, execution_id)
    reader.open(10)
    os.truncate(layout.data(execution_id), 4)
    assert run(reader.read()) == b"0123"
    reader.close()
    reader.close()  # idempotent


def test_a_lock_whose_path_was_replaced_is_retired(
    layout: SpoolLayout, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution_id = _spooled(layout)
    lock = layout.lock(execution_id)
    fd = os.open(lock, os.O_RDONLY)
    try:
        assert spool._current(fd, lock)
        lock.unlink()
        assert not spool._current(fd, lock)
        lock.touch()  # a new inode under the old name
        assert not spool._current(fd, lock)
    finally:
        os.close(fd)
    # Retired between the open and the lock: the reader refuses.
    monkeypatch.setattr(spool, "_current", lambda _fd, _path: False)
    with pytest.raises(GatewayError):
        SpoolReader(layout, deps.db_engine, execution_id).open(10)


def test_a_cleaner_meets_a_held_lock_and_the_release_happens_once(
    layout: SpoolLayout,
) -> None:
    execution_id = _spooled(layout)
    holder = os.open(layout.lock(execution_id), os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_SH)
    try:
        ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
        assert clean(layout, deps.db_engine, execution_id) is Cleaned.BUSY
    finally:
        os.close(holder)
    assert clean(layout, deps.db_engine, execution_id) is Cleaned.RELEASED
    assert not spool._release(deps.db_engine, execution_id)
    with deps.db_engine.connect() as c:
        assert (
            c.execute(sa.select(ai_spool_capacity.c.reserved_bytes)).scalar_one() == 0
        )

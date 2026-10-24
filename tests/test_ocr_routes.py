"""
The OCR routes (T31, D-44, D-45) through the shipped app.

Phase 1 spools and verifies under a ``phase = spool`` context; phase 2
dispatches under a ``phase = dispatch`` context bound to the spool. The
spool directory is a temporary one; the provider is an in-process Mistral
that answers OCR, so each refusal is checked on the wire, on the rows, on
the spool files and on the number of provider requests.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from ai_sdk_m8.schemas import AiErrorCode, Capability, DataClass, OcrOptions
from fastapi.testclient import TestClient

from ai_gateway import main
from ai_gateway.core import deps
from ai_gateway.core.config import settings
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.execution_guard import JOB_CONTEXT_HEADER
from ai_gateway.db_models.accounting import (
    ai_client_occupancy,
    ai_execution,
    ai_rate_window,
    ai_spool_capacity,
)
from ai_gateway.execution import ocr
from ai_gateway.execution.spool import (
    Cleaned,
    Receiver,
    SpoolLayout,
    SpoolReader,
    clean,
)
from conftest import MEDIA_SERVICE, MEDIA_WORKER
from execution_world import clients, executions
from job_contexts import mint
from mistral_stub import page
from ocr_world import SIGNER, mistral_world

pytestmark = pytest.mark.usefixtures("clean_db")

BASE = "/ai/v1/execute"
PDF = b"%PDF-1.7\n" + b"x" * 300
BOUNDARY = "gw-test-boundary"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


class Provider:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        wanted = json.loads(request.content)["pages"][:2]
        body = {
            "pages": [page(i) for i in wanted],
            "usage_info": {"pages_processed": 2},
        }
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(body).encode()))


def _reset_capacity() -> None:
    # The capacity row is installation configuration the session keeps.
    with deps.db_engine.begin() as c:
        c.execute(sa.update(ai_spool_capacity).values(reserved_bytes=0))


@pytest.fixture
def spool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "spool"
    root.mkdir()
    monkeypatch.setattr(settings, "AI_OCR_SPOOL_DIR", root)
    monkeypatch.setattr(settings, "_capabilities", frozenset({Capability.OCR}))
    monkeypatch.setattr(deps.execution_service, "_receipts", SIGNER)
    _reset_capacity()
    yield root
    _reset_capacity()


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> Provider:
    stub = Provider()
    factory = clients(transport=lambda _e: httpx.MockTransport(stub))
    monkeypatch.setattr(deps.execution_service, "_clients", factory)
    return stub


def options_json(pages: list[int] | None = None, key: str = "p") -> bytes:
    body: dict[str, Any] = {"profile_key": key, "options": {"pages": pages}}
    return json.dumps(body).encode()


def claims(
    document: bytes, pages: list[int] | None = None, **extra: Any
) -> dict[str, Any]:
    return {
        "capability": "ocr",
        "azp": MEDIA_WORKER.client_id,
        "data_class": "public",
        "input_sha256": hashlib.sha256(document).hexdigest(),
        "input_bytes": len(document),
        "ocr_options_hash": ocr.options_hash(
            OcrOptions(pages=None if pages is None else tuple(pages))
        ),
        **extra,
    }


def context_headers(key: str, **overrides: Any) -> dict[str, str]:
    token = mint(MEDIA_SERVICE, profile_key=key, **overrides)
    return {**MEDIA_WORKER.headers(), JOB_CONTEXT_HEADER: token}


def form(parts: list[tuple[str, bytes, str]]) -> bytes:
    body = b""
    for name, content, extra in parts:
        body += (
            (
                f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"{extra}\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + content
            + b"\r\n"
        )
    return body + f"--{BOUNDARY}--\r\n".encode()


def spool_call(
    client: TestClient,
    key: str,
    document: bytes,
    *,
    body: bytes | Iterator[bytes] | None = None,
    pages: list[int] | None = None,
    signed: bytes | None = None,
    **overrides: Any,
) -> Any:
    signed_document = document if signed is None else signed
    content = (
        body
        if body is not None
        else form(
            [
                ("options", options_json(pages, key), ""),
                ("document", document, '; filename="secret-invoice.pdf"'),
            ]
        )
    )
    headers = context_headers(
        key, **{"phase": "spool", **claims(signed_document, pages), **overrides}
    )
    headers["Content-Type"] = f"multipart/form-data; boundary={BOUNDARY}"
    return client.post(f"{BASE}/ocr", content=content, headers=headers)


def dispatch_call(
    client: TestClient, key: str, target: str, document: bytes, **overrides: Any
) -> Any:
    fields = {
        **claims(document, overrides.pop("pages", None)),
        "phase": "dispatch",
        "spool_id": target,
        "exp": int(time.time()) + 25,
        **overrides,
    }
    return client.post(
        f"{BASE}/ocr/{target}:dispatch", headers=context_headers(key, **fields)
    )


def files(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def capacity() -> int:
    with deps.db_engine.connect() as c:
        return int(
            c.execute(
                sa.select(
                    sa.func.coalesce(sa.func.sum(ai_spool_capacity.c.reserved_bytes), 0)
                )
            ).scalar_one()
        )


def counters() -> tuple[int, int]:
    with deps.db_engine.connect() as c:
        windows = c.execute(
            sa.select(sa.func.coalesce(sa.func.sum(ai_rate_window.c.count), 0))
        ).scalar_one()
        occupied = c.execute(
            sa.select(sa.func.coalesce(sa.func.sum(ai_client_occupancy.c.occupied), 0))
        ).scalar_one()
    return int(windows), int(occupied)


def row(execution_id: str) -> Any:
    with deps.db_engine.connect() as c:
        return (
            c.execute(
                sa.select(ai_execution).where(
                    ai_execution.c.id == uuid.UUID(execution_id)
                )
            )
            .mappings()
            .one()
        )


# --- the workflow -------------------------------------------------------------------


def test_one_workflow_spools_dispatches_and_charges_once(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    key = w["key"]
    before = counters()
    spooled = spool_call(client, key, PDF, pages=[0, 1])
    assert spooled.status_code == 200, spooled.text
    spool_id = spooled.json()["spool_id"]
    assert files(spool) == sorted([spool_id, f".locks/{spool_id}"])
    spooled_row = row(spool_id)
    assert spooled_row["status"] == "spooled" and spooled_row["ocr_options"] == {
        "pages": [0, 1]
    }
    assert provider.requests == []
    # The reservation covers the allocated blocks of the retained file (A-4).
    assert (
        os.stat(spool / spool_id).st_blocks * 512 <= spooled_row["spool_bytes_reserved"]
    )
    assert capacity() == spooled_row["spool_bytes_reserved"]
    done = dispatch_call(client, key, spool_id, PDF, pages=[0, 1])
    assert done.status_code == 200, done.text
    body = done.json()
    assert [p["index"] for p in body["result"]["pages"]] == [0, 1]
    assert body["execution"]["receipt"] and body["execution"]["units"] == 2
    assert len(provider.requests) == 1
    sent = json.loads(provider.requests[0].content)
    assert sent["pages"] == [0, 1] and sent["document"]["type"] == "document_url"
    # One rate-window admission, and the occupancy slot back where it was.
    windows, occupied = counters()
    assert windows == before[0] + 1 and occupied == before[1]
    assert row(spool_id)["status"] == "ok" and not row(spool_id)["cleanup_pending"]
    assert files(spool) == [] and capacity() == 0


def test_a_spool_without_pages_reserves_the_page_bound(
    client: TestClient, spool: Path, provider: Provider, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_MAX_OCR_PAGES", 5)
    w = mistral_world()
    spool_id = spool_call(client, w["key"], PDF).json()["spool_id"]
    done = dispatch_call(client, w["key"], spool_id, PDF)
    assert done.status_code == 200, done.text
    assert json.loads(provider.requests[0].content)["pages"] == [0, 1, 2, 3, 4]
    assert done.json()["execution"]["units"] == 5


def test_a_chunked_body_with_any_content_length_is_sized_by_the_signed_bytes(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    body = form([("options", options_json(None, w["key"]), ""), ("document", PDF, "")])

    def chunks() -> Iterator[bytes]:
        for start in range(0, len(body), 7):
            yield body[start : start + 7]

    for declared in (None, "3", str(len(body) * 10)):
        headers = context_headers(w["key"], phase="spool", **claims(PDF))
        headers["Content-Type"] = f"multipart/form-data; boundary={BOUNDARY}"
        if declared is not None:
            headers["Content-Length"] = declared
        response = client.post(f"{BASE}/ocr", content=chunks(), headers=headers)
        assert response.status_code == 200, response.text
        assert row(response.json()["spool_id"])["spool_bytes_reserved"] >= len(PDF)


# --- refusals before any provider request ------------------------------------------------


def test_a_digest_that_differs_from_the_signed_one_sends_nothing(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    response = spool_call(client, w["key"], PDF, signed=b"%PDF-1.7\n" + b"y" * 300)
    assert response.status_code == 401 and response.json()["code"] == "context_invalid"
    (only,) = executions()
    assert only["status"] == "abandoned" and not only["cleanup_pending"]
    assert files(spool) == [] and capacity() == 0 and provider.requests == []


def test_changed_options_are_refused(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    body = form([("options", options_json([0], w["key"]), ""), ("document", PDF, "")])
    response = spool_call(client, w["key"], PDF, body=body, pages=None)
    assert response.json()["code"] == "context_invalid"
    assert files(spool) == [] and capacity() == 0


def test_one_byte_past_the_signed_size_aborts_with_nothing_retained(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    longer = PDF + b"!"
    body = form(
        [("options", options_json(None, w["key"]), ""), ("document", longer, "")]
    )
    response = spool_call(client, w["key"], PDF, body=body)
    assert response.status_code == 401 and response.json()["code"] == "context_invalid"
    assert files(spool) == [] and capacity() == 0


def test_a_context_larger_than_the_body_cap_creates_nothing(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_MAX_REQUEST_BYTES", 100)
    w = mistral_world()
    response = spool_call(client, w["key"], PDF)
    assert (
        response.status_code == 413 and response.json()["code"] == "request_too_large"
    )
    assert executions() == [] and files(spool) == [] and capacity() == 0


def test_too_many_pages_are_refused(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_MAX_OCR_PAGES", 2)
    w = mistral_world()
    response = spool_call(client, w["key"], PDF, pages=[0, 1, 2])
    assert response.status_code == 413 and files(spool) == []


@pytest.mark.parametrize(
    "parts",
    [
        [("options", b"{}", ""), ("document", PDF, ""), ("extra", b"x", "")],
        [("document", PDF, ""), ("options", b"{}", "")],
        [("options", b"{}", "")],
        [("options", b"{}", '; x="' + "a" * 9 * 1024 + '"'), ("document", PDF, "")],
        [("meta", b"{}", ""), ("document", PDF, "")],
    ],
    ids=["three-parts", "reordered", "one-part", "9k-header", "wrong-name"],
)
def test_a_body_that_is_not_the_two_part_form_is_400(
    client: TestClient, spool: Path, parts: list[tuple[str, bytes, str]]
) -> None:
    w = mistral_world()
    fixed = [
        (n, options_json(None, w["key"]) if n == "options" else c, e)
        for n, c, e in parts
    ]
    response = spool_call(client, w["key"], PDF, body=form(fixed))
    assert response.status_code == 400, response.text
    assert files(spool) == [] and capacity() == 0
    assert all(r["status"] == "abandoned" for r in executions())


def test_a_body_that_is_not_multipart_creates_no_row(
    client: TestClient, spool: Path
) -> None:
    w = mistral_world()
    headers = context_headers(w["key"], phase="spool", **claims(PDF))
    headers["Content-Type"] = "application/json"
    assert client.post(f"{BASE}/ocr", content=b"{}", headers=headers).status_code == 400
    assert executions() == []


def _receiving(key: str) -> uuid.UUID:
    """A live ``receiving`` row, as a concurrent upload in progress leaves it."""
    from execution_world import principal

    signed = {
        k: v
        for k, v in claims(PDF).items()
        if k in ("input_sha256", "input_bytes", "ocr_options_hash")
    }
    context = principal(
        key, Capability.OCR, data_class=DataClass.PUBLIC, phase="spool", **signed
    )
    config = ocr.SpoolConfig.from_settings(settings)
    return ocr.open_spool(
        deps.db_engine,
        context,
        config=config,
        limits=deps.execution_service._limits(),
        unit=4096,
    )


def test_the_concurrent_spool_bound_is_503_with_retry_after(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_MAX_CONCURRENT_SPOOLS", 1)
    w = mistral_world()
    _receiving(w["key"])
    response = spool_call(client, w["key"], PDF)
    assert (
        response.status_code == 503 and response.json()["code"] == "capacity_exhausted"
    )
    assert "retry-after" in response.headers
    assert len(executions()) == 1 and files(spool) == []


def test_a_full_capacity_is_503_before_any_byte(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_OCR_SPOOL_MAX_BYTES", 10)
    w = mistral_world()
    response = spool_call(client, w["key"], PDF)
    assert (
        response.status_code == 503 and response.json()["code"] == "capacity_exhausted"
    )
    assert executions() == [] and files(spool) == []


def test_an_upload_past_its_total_timeout_leaves_no_file(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_UPLOAD_TOTAL_TIMEOUT_SECONDS", 1)
    w = mistral_world()
    head = form([("options", options_json(None, w["key"]), ""), ("document", PDF, "")])

    def slow() -> Iterator[bytes]:
        yield head[:-60]
        time.sleep(2)
        yield head[-60:]

    response = spool_call(client, w["key"], PDF, body=slow())
    assert response.status_code == 504 and response.json()["code"] == "timeout"
    assert files(spool) == [] and capacity() == 0


# --- dispatch refusals ------------------------------------------------------------------


def _spooled(client: TestClient, key: str) -> str:
    response = spool_call(client, key, PDF)
    assert response.status_code == 200, response.text
    return str(response.json()["spool_id"])


@pytest.mark.parametrize(
    "overrides",
    [
        {"phase": "spool", "spool_id": None},
        {"spool_id": str(uuid.uuid4())},
        {"job_ref": "another-run"},
        {"attempt": 2},
        {"ocr_options_hash": "d" * 64},
    ],
    ids=["spool-phase", "other-spool", "other-run", "other-attempt", "other-options"],
)
def test_a_dispatch_context_not_bound_to_the_spool_sends_nothing(
    client: TestClient, spool: Path, provider: Provider, overrides: dict[str, Any]
) -> None:
    w = mistral_world()
    spool_id = _spooled(client, w["key"])
    response = dispatch_call(client, w["key"], spool_id, PDF, **overrides)
    assert response.status_code == 401 and response.json()["code"] == "context_invalid"
    assert provider.requests == [] and row(spool_id)["status"] == "spooled"
    assert files(spool) == sorted([spool_id, f".locks/{spool_id}"])


def test_an_expired_dispatch_context_is_refused(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    spool_id = _spooled(client, w["key"])
    now = int(time.time())
    response = dispatch_call(
        client, w["key"], spool_id, PDF, iat=now - 40, nbf=now - 40, exp=now - 15
    )
    assert response.status_code == 401 and response.json()["code"] == "context_expired"
    assert provider.requests == []


def test_the_family_is_404_without_ocr(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "_capabilities", frozenset())
    assert client.post(f"{BASE}/ocr").status_code == 404
    assert client.post(f"{BASE}/ocr/{uuid.uuid4()}:dispatch").status_code == 404


# --- the D-45 protocol ----------------------------------------------------------------


def test_a_spool_past_its_ttl_is_abandoned_and_removed(
    client: TestClient, spool: Path
) -> None:
    w = mistral_world()
    spool_id = uuid.UUID(_spooled(client, w["key"]))
    assert ocr.abandon(deps.db_engine, spool_id, AiErrorCode.TIMEOUT)
    assert clean(SpoolLayout(spool), deps.db_engine, spool_id) is Cleaned.RELEASED
    assert files(spool) == [] and capacity() == 0
    assert clean(SpoolLayout(spool), deps.db_engine, spool_id) is Cleaned.NOTHING


def test_a_reader_holding_the_spool_defers_the_cleaner(
    client: TestClient, spool: Path
) -> None:
    w = mistral_world()
    spool_id = uuid.UUID(_spooled(client, w["key"]))
    layout = SpoolLayout(spool)
    reader = SpoolReader(layout, deps.db_engine, spool_id)
    reader.open(len(PDF))
    try:
        ocr.abandon(deps.db_engine, spool_id, AiErrorCode.TIMEOUT)
        assert clean(layout, deps.db_engine, spool_id) is Cleaned.BUSY
        assert capacity() > 0 and (spool / str(spool_id)).exists()
    finally:
        reader.close()
    assert clean(layout, deps.db_engine, spool_id) is Cleaned.RELEASED
    assert capacity() == 0 and files(spool) == []


def test_a_receiver_paused_before_its_file_creates_nothing_once_cleaned(
    client: TestClient, spool: Path
) -> None:
    w = mistral_world()
    config = ocr.SpoolConfig.from_settings(settings)
    execution_id = _receiving(w["key"])
    ocr.abandon(deps.db_engine, execution_id, AiErrorCode.TIMEOUT)
    assert clean(config.layout, deps.db_engine, execution_id) is Cleaned.RELEASED
    receiver = Receiver(
        config.layout,
        deps.db_engine,
        execution_id,
        input_bytes=len(PDF),
        lease_deadline=time.monotonic() + 60,
    )
    with pytest.raises(GatewayError):
        receiver.open()
    assert files(spool) == [] and capacity() == 0


def test_a_missing_lock_with_a_created_file_keeps_the_capacity_charged(
    client: TestClient, spool: Path, caplog: pytest.LogCaptureFixture
) -> None:
    w = mistral_world()
    spool_id = uuid.UUID(_spooled(client, w["key"]))
    (spool / ".locks" / str(spool_id)).unlink()
    ocr.abandon(deps.db_engine, spool_id, AiErrorCode.TIMEOUT)
    assert clean(SpoolLayout(spool), deps.db_engine, spool_id) is Cleaned.LOCK_MISSING
    assert capacity() > 0 and "spool_lock_missing" in caplog.text


def test_a_dispatch_of_a_retired_spool_is_refused(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    spool_id = _spooled(client, w["key"])
    (spool / ".locks" / spool_id).unlink()
    response = dispatch_call(client, w["key"], spool_id, PDF)
    assert response.json()["code"] == "context_invalid" and provider.requests == []


def test_only_the_spool_module_opens_spool_files() -> None:
    root = Path(main.__file__).parent
    # Key files are not spool files; the start-up check opens only its probe;
    # the restore state writes only under /spool/.state, never a data or lock
    # file (its high-water and event log, T33a).
    openers = {
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if "os.open(" in (text := path.read_text(encoding="utf-8"))
        and "spool" in text.lower()
    }
    assert openers == {
        "execution/spool.py",
        "core/spool_check.py",
        "core/restore_state.py",
    }


def test_a_dispatch_context_on_the_spool_route_is_refused(
    client: TestClient, spool: Path
) -> None:
    w = mistral_world()
    response = spool_call(
        client,
        w["key"],
        PDF,
        phase="dispatch",
        spool_id=str(uuid.uuid4()),
        exp=int(time.time()) + 25,
    )
    assert response.json()["code"] == "context_invalid" and executions() == []


def test_a_dispatch_naming_no_spool_is_refused(
    client: TestClient, spool: Path, provider: Provider
) -> None:
    w = mistral_world()
    response = dispatch_call(client, w["key"], str(uuid.uuid4()), PDF)
    assert response.json()["code"] == "context_invalid" and provider.requests == []


def test_an_options_part_outside_its_model_is_422_and_abandons(
    client: TestClient, spool: Path
) -> None:
    w = mistral_world()
    body = form([("options", b'{"profile_key": 7}', ""), ("document", PDF, "")])
    response = spool_call(client, w["key"], PDF, body=body)
    assert response.status_code == 422
    (only,) = executions()
    assert only["status"] == "abandoned" and only["error_class"] == "context_invalid"
    assert files(spool) == []


def test_the_upload_timeout_closes_the_spool(
    client: TestClient, spool: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from ai_gateway.app.routes import ocr as routes

    async def stalled(*_args: Any) -> None:
        await asyncio.sleep(5)

    monkeypatch.setattr(settings, "AI_UPLOAD_TOTAL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(routes, "_receive", stalled)
    w = mistral_world()
    response = spool_call(client, w["key"], PDF)
    assert response.status_code == 504 and response.json()["code"] == "timeout"
    (only,) = executions()
    assert only["status"] == "abandoned" and only["error_class"] == "timeout"
    assert files(spool) == [] and capacity() == 0

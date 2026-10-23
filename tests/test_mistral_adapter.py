"""
The Mistral adapter (T29) through the shipped execution core.

Every OCR run starts from a planted ``spooled`` row (phase 1 is ``T31``)
and goes through the reservation's ``spooled → pending`` binding, the
marker, the adapter against a real stub server on the real transport, the
adapter's own cleanup and one settlement. The stub speaks the wire shapes
of the reference re-read when the step started (recorded in the plan).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

import httpx
import pytest
import sqlalchemy as sa
from ai_sdk_m8.jobcontext import JobContextPayload, OcrReceiptPayload
from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    DataClass,
    ExecutionReceipt,
    OcrResult,
)
from ai_sdk_m8.schemas.management import ProviderType
from ai_sdk_m8.signed import Domain, SignedObjectError, canonicalize, verify_object

from ai_gateway.core import deps
from ai_gateway.core.errors import GatewayError
from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.execution.receipts import result_sha256
from ai_gateway.providers.base import AdapterCall, ModelRef
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.mistral import (
    PROOFS,
    MistralAdapter,
    expiry_hours,
    inline_reference,
    ocr_page,
)
from ai_gateway.providers.registry import build_adapters
from execution_world import clients, executions, run
from mistral_stub import MistralStub, page
from ocr_world import (
    ADAPTER,
    BLOB,
    DEPLOYMENT_ID,
    PDF,
    RECEIPT_KID,
    RECEIPT_PUBLIC,
    Document,
    artifacts,
    dispatch,
    mistral,
    mistral_world,
    ocr_job,
    ocr_service,
    scheduler,
    spooled,
)
from provider_stubs import endpoint, mock_client

pytestmark = pytest.mark.usefixtures("clean_db")

KEYS = {RECEIPT_KID: RECEIPT_PUBLIC}


def ocr(
    stub: MistralStub, document: Any, pages: tuple[int, ...] = (0, 1), **kw: Any
) -> Any:
    w = kw.pop("world", None) or mistral_world()

    async def scenario() -> Any:
        async with mistral(stub, **kw.pop("server", {})) as factory:
            return await dispatch(factory, w, document, pages, **kw)

    return run(scenario())


def only_execution() -> Any:
    (row,) = executions()
    return row


# --- the inline path --------------------------------------------------------------------


def test_a_small_pdf_is_sent_inline_as_a_data_url_and_never_uploaded() -> None:
    stub = MistralStub()
    done = ocr(stub, PDF)
    (body,) = stub.ocr_bodies
    assert body["model"] == "mistral-ocr-latest"
    assert body["pages"] == [0, 1]
    assert body["include_image_base64"] is False and body["include_blocks"] is False
    encoded = base64.b64encode(PDF).decode()
    assert body["document"] == {
        "type": "document_url",
        "document_url": f"data:application/pdf;base64,{encoded}",
    }
    assert stub.uploads == [] and artifacts() == []
    assert [p.index for p in done.result.pages] == [0, 1]
    assert done.result.pages[0].images[0].bbox.x1 == 110
    assert done.execution.provider_usage.pages_processed == 2
    row = only_execution()
    assert row["status"] == "ok" and row["reserved_units"] == 2


@pytest.mark.parametrize(
    ("data", "kind", "media_type"),
    [
        (b"%PDF-1.4 x", "document_url", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n...", "image_url", "image/png"),
        (b"\xff\xd8\xff\xe0...", "image_url", "image/jpeg"),
        (b"GIF87a...", "image_url", "image/gif"),
        (b"GIF89a...", "image_url", "image/gif"),
        (b"II*\x00....", "image_url", "image/tiff"),
        (b"MM\x00*....", "image_url", "image/tiff"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image_url", "image/webp"),
    ],
)
def test_inline_references_are_chosen_by_the_verified_signature(
    data: bytes, kind: str, media_type: str
) -> None:
    reference = inline_reference(data)
    assert reference is not None and reference["type"] == kind
    assert reference[kind].startswith(f"data:{media_type};base64,")


@pytest.mark.parametrize("data", [b"plain text", b"RIFF\x00\x00\x00\x00WAVE", b""])
def test_an_unknown_signature_is_never_inlined(data: bytes) -> None:
    assert inline_reference(data) is None


def test_a_small_document_of_unknown_type_is_uploaded_instead() -> None:
    stub = MistralStub()
    done = ocr(stub, b"short but no known signature")
    assert len(stub.uploads) == 1 and done.execution.receipt is not None


# --- the upload path --------------------------------------------------------------------


def test_an_upload_is_private_expiring_and_named_by_the_gateway_only() -> None:
    stub = MistralStub()
    done = ocr(stub, BLOB)
    execution_id = done.execution.execution_id
    (upload,) = stub.uploads
    assert upload == {
        "purpose": "ocr",
        "visibility": "user",
        "expiry": "1",
        "filename": f"m8ai-{DEPLOYMENT_ID}-{execution_id}",
        "content_type": "application/octet-stream",
        "size": len(BLOB),
    }
    (body,) = stub.ocr_bodies
    remote_id = body["document"]["file_id"]
    assert body["document"] == {"type": "file", "file_id": remote_id}
    # Cleaned up in the adapter's own finally, under the recorded key.
    assert ("DELETE", f"/v1/files/{remote_id}", "sk-old") in stub.log
    assert stub.files == {} and artifacts() == []
    row = only_execution()
    assert row["status"] == "ok" and row["first_byte_sent_at"] is not None


def test_the_intent_row_exists_before_the_provider_reads_the_upload() -> None:
    seen: list[Any] = []

    def on_request(received: Any) -> None:
        if received.request_line.startswith("POST /v1/files"):
            seen.append((artifacts(), only_execution()))

    stub = MistralStub()
    ocr(stub, BLOB, server={"on_request": on_request})
    ((rows, execution),) = seen
    (row,) = rows
    assert row["status"] == "uploading" and row["remote_artifact_id"] is None
    assert row["credential_version"] == 1
    assert row["upload_deadline_at"] == execution["dispatch_deadline_at"]
    assert execution["first_byte_sent_at"] is not None
    assert row["gateway_file_name"] == f"m8ai-{DEPLOYMENT_ID}-{execution['id']}"


def test_the_id_is_recorded_before_use_and_a_scheduler_tick_never_deletes_it() -> None:
    seen: list[Any] = []

    def on_ocr() -> None:
        retired = scheduler(clients()).retire_active()
        seen.append((artifacts(), retired))

    stub = MistralStub(on_ocr=on_ocr)
    ocr(stub, BLOB)
    ((rows, retired),) = seen
    (row,) = rows
    assert retired == []
    assert row["status"] == "active" and row["remote_artifact_id"] == "file-0001"
    assert row["provider_expires_at"] is not None


@pytest.mark.parametrize(
    "stub",
    [
        MistralStub(visibility="workspace"),
        MistralStub(expires=False),
        MistralStub(expires_in=30 * 24 * 3600),
        MistralStub(expires_in=1),
    ],
    ids=["workspace", "no-expiry", "expiry-too-late", "expiry-too-soon"],
)
def test_a_stored_file_out_of_policy_is_deleted_and_never_read(
    stub: MistralStub,
) -> None:
    outcome = ocr(stub, BLOB)
    assert isinstance(outcome, GatewayError)
    assert outcome.code is AiErrorCode.PROVIDER_REJECTED
    assert stub.ocr_bodies == [] and stub.files == {} and artifacts() == []
    # Charged: the upload left the process (multi-request rule).
    assert only_execution()["status"] == "failed"


def test_more_pages_than_reserved_are_refused_after_cleanup() -> None:
    stub = MistralStub(pages=lambda wanted: [page(i) for i in (*wanted, 7)])
    outcome = ocr(stub, BLOB)
    assert outcome.code is AiErrorCode.PROVIDER_REJECTED
    assert only_execution()["status"] == "failed" and stub.files == {}


@pytest.mark.parametrize(
    "answer",
    [
        lambda _wanted: [page(1), page(0)],
        lambda _wanted: [page(3)],
        lambda _wanted: [],
    ],
    ids=["unordered", "unrequested", "empty"],
)
def test_pages_are_held_to_the_reserved_list(answer: Any) -> None:
    outcome = ocr(MistralStub(pages=answer), PDF)
    assert outcome.code is AiErrorCode.PROVIDER_REJECTED


def test_a_truncated_answer_of_fewer_pages_is_returned_as_is() -> None:
    done = ocr(MistralStub(pages=lambda wanted: [page(wanted[0])]), PDF, (0, 1, 2))
    assert [p.index for p in done.result.pages] == [0]
    assert only_execution()["reserved_units"] == 3


# --- composed settlement ------------------------------------------------------------


def _mock_mistral(handler: Any) -> Any:
    return clients(transport=lambda _e: httpx.MockTransport(handler))


def test_an_ocr_connect_error_after_an_upload_is_charged_uncertain() -> None:
    w = mistral_world()
    deletes: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/files":
            body = {
                "id": "file-1",
                "purpose": "ocr",
                "visibility": "user",
                "expires_at": int(time.time()) + 3600,
            }
            return httpx.Response(
                200, stream=httpx.ByteStream(json.dumps(body).encode())
            )
        if request.url.path == "/v1/ocr":
            raise httpx.ConnectError("refused", request=request)
        deletes.append(request.url.path)
        body = {"id": "file-1", "object": "file", "deleted": True}
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(body).encode()))

    outcome = run(dispatch(_mock_mistral(handler), w, BLOB))
    assert outcome.code is AiErrorCode.PROVIDER_UNREACHABLE
    assert only_execution()["status"] == "charged_uncertain"
    assert deletes == ["/v1/files/file-1"] and artifacts() == []


def test_an_ok_ocr_whose_delete_fails_is_ok_and_left_to_the_scheduler() -> None:
    stub = MistralStub(delete_mode="500")
    w = mistral_world()

    async def scenario() -> Any:
        async with mistral(stub) as factory:
            done = await dispatch(factory, w, BLOB)
            (pending,) = artifacts()
            assert pending["status"] == "pending_delete"
            stub.delete_mode = "proof"
            closed = await scheduler(factory).delete_pending()
            return done, pending, closed

    done, pending, closed = run(scenario())
    assert done.execution.receipt is not None
    assert only_execution()["status"] == "ok"
    assert closed == [pending["id"]] and artifacts() == [] and stub.files == {}


def test_a_lost_upload_answer_is_charged_and_the_listing_collects_the_file() -> None:
    from ocr_world import due

    stub = MistralStub(drop_upload=True)
    w = mistral_world()

    async def scenario() -> Any:
        async with mistral(stub) as factory:
            outcome = await dispatch(factory, w, BLOB)
            (lost,) = artifacts()
            due()
            work = scheduler(factory)
            found = await work.resolve_unknown()
            (named,) = artifacts()
            closed = await work.delete_pending()
            return outcome, lost, found, named, closed

    outcome, lost, found, named, closed = run(scenario())
    assert isinstance(outcome, GatewayError)
    assert only_execution()["status"] == "charged_uncertain"
    assert (
        lost["status"] == "uploading_unknown_id" and lost["remote_artifact_id"] is None
    )
    assert found == [lost["id"]] and named["remote_artifact_id"] == "file-0001"
    assert closed == [lost["id"]] and stub.files == {} and artifacts() == []
    assert stub.ocr_bodies == []


def test_a_mid_body_failure_leaves_an_unknown_id_row_charged() -> None:
    outcome = ocr(MistralStub(), Document(BLOB, fail_after=1024))
    assert isinstance(outcome, GatewayError)
    (row,) = artifacts()
    assert row["status"] == "uploading_unknown_id"
    assert only_execution()["status"] == "charged_uncertain"


def test_an_activation_after_the_scheduler_moved_the_row_is_never_used() -> None:
    from ai_gateway.execution import artifacts as module

    stub = MistralStub()
    w = mistral_world()

    def on_request(received: Any) -> None:
        if received.request_line.startswith("POST /v1/files"):
            (row,) = artifacts()
            module._cas(
                deps.db_engine,
                row["id"],
                module._S.UPLOADING,
                status=module._S.UPLOADING_UNKNOWN_ID.value,
            )

    async def scenario() -> Any:
        async with mistral(stub, on_request=on_request) as factory:
            return await dispatch(factory, w, BLOB)

    outcome = run(scenario())
    assert outcome.code is AiErrorCode.TIMEOUT
    (row,) = artifacts()
    assert (
        row["status"] == "pending_delete" and row["remote_artifact_id"] == "file-0001"
    )
    assert stub.ocr_bodies == []
    assert only_execution()["status"] == "charged_uncertain"


def test_an_intent_that_finds_no_dispatching_row_sends_no_byte() -> None:
    from ai_gateway.execution.artifacts import ExecutionArtifacts
    from ai_gateway.execution.service import ExecutionProgress
    import uuid

    execution_id = uuid.uuid4()
    tracker = ExecutionArtifacts(
        deps.db_engine,
        ExecutionProgress(deps.db_engine, execution_id),
        execution_id=execution_id,
        provider_id=uuid.uuid4(),
        credential_id=uuid.uuid4(),
        credential_version=1,
        deployment_id=DEPLOYMENT_ID,
    )
    with pytest.raises(ProviderFailure) as caught:
        run(tracker.intent_progress().first_byte_sent())
    assert caught.value.code is AiErrorCode.TIMEOUT
    assert not tracker.intended and tracker.artifact_id is None


# --- the receipt (C-01) -------------------------------------------------------------


def _receipt() -> tuple[Any, OcrReceiptPayload, Any]:
    stub = MistralStub()
    w = mistral_world()

    async def scenario() -> Any:
        async with mistral(stub) as factory:
            dispatch_principal = spooled(w, PDF)
            svc = ocr_service(factory)
            done = await svc.run(dispatch_principal, ocr_job(w, Document(PDF)))
            return done, dispatch_principal

    done, dispatch_principal = run(scenario())
    payload = verify_object(
        done.execution.receipt,
        domain=Domain.OCR_RECEIPT,
        public_keys=KEYS,
        model=OcrReceiptPayload,
    )
    return done, payload, dispatch_principal


def test_the_receipt_verifies_and_binds_the_exact_result_returned() -> None:
    done, payload, context = _receipt()
    claims = context.payload
    assert payload.iss == f"ai-gateway/{DEPLOYMENT_ID}"
    assert payload.execution_id == str(done.execution.execution_id)
    assert (payload.job_ref, payload.attempt, payload.azp) == (
        claims.job_ref,
        claims.attempt,
        claims.azp,
    )
    assert payload.profile_key == claims.profile_key
    assert payload.input_sha256 == hashlib.sha256(PDF).hexdigest()
    assert payload.ocr_options_hash == claims.ocr_options_hash
    assert (
        payload.execution_identity
        == done.execution.provider_execution.execution_identity
    )
    # The consumer recomputes SHA-256(JCS(OcrResult)) from the body it got.
    wire = json.loads(done.result.model_dump_json())
    # ASCII keys and integers only: sorted compact JSON is the JCS form.
    independent = json.dumps(
        wire, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert hashlib.sha256(independent).hexdigest() == payload.result_sha256
    assert result_sha256(OcrResult.model_validate(wire)) == payload.result_sha256
    ExecutionReceipt.model_validate(done.execution.model_dump())


def test_the_receipt_fails_when_altered_or_presented_for_another_purpose() -> None:
    done, _payload, _context = _receipt()
    token = done.execution.receipt
    segment, signature = token.split(".")
    from ai_sdk_m8.signed import b64url_decode, b64url_encode

    body = json.loads(b64url_decode(segment))
    for name, value in (
        ("result_sha256", "0" * 64),
        ("profile_key", "other-profile"),
        ("attempt", body["attempt"] + 1),
    ):
        altered = canonicalize({**body, name: value})
        with pytest.raises(SignedObjectError):
            verify_object(
                f"{b64url_encode(altered)}.{signature}",
                domain=Domain.OCR_RECEIPT,
                public_keys=KEYS,
                model=OcrReceiptPayload,
            )
    for domain in (Domain.JOB_CONTEXT, Domain.SANDBOX_ATTESTATION):
        with pytest.raises(SignedObjectError):
            verify_object(
                token, domain=domain, public_keys=KEYS, model=JobContextPayload
            )


def test_ocr_without_a_receipt_seed_is_refused_before_any_request() -> None:
    w = mistral_world()
    outcome = run(dispatch(clients(), w, PDF, receipts=None))
    assert outcome.code is AiErrorCode.CAPABILITY_UNSUPPORTED
    assert only_execution()["status"] == "released"


# --- the spool binding (D-44) -------------------------------------------------------


def test_a_dispatch_context_that_differs_from_the_spool_binding_is_refused() -> None:
    w = mistral_world()
    good = spooled(w, PDF)
    from execution_world import principal

    other = principal(
        w["key"],
        Capability.OCR,
        phase="dispatch",
        spool_id=good.payload.spool_id,
        input_sha256=good.payload.input_sha256,
        input_bytes=good.payload.input_bytes,
        ocr_options_hash="d" * 64,
        data_class=DataClass.PUBLIC,
        exp=int(time.time()) + 25,
    )
    svc = ocr_service(clients())
    with pytest.raises(GatewayError) as caught:
        run(svc.run(other, ocr_job(w, Document(PDF))))
    assert caught.value.code is AiErrorCode.CONTEXT_INVALID
    assert only_execution()["status"] == "spooled"


def test_an_expired_spool_cannot_be_dispatched() -> None:
    w = mistral_world()
    context = spooled(w, PDF)
    from ocr_world import _superuser

    with _superuser() as c:
        c.execute(
            sa.update(ai_execution).values(
                spool_expires_at=sa.func.now() - sa.text("interval '1 second'")
            )
        )
    with pytest.raises(GatewayError) as caught:
        run(ocr_service(clients()).run(context, ocr_job(w, Document(PDF))))
    assert caught.value.code is AiErrorCode.CONTEXT_INVALID


def test_a_context_without_a_spool_id_is_refused() -> None:
    from types import SimpleNamespace

    from ai_gateway.execution.reservation import _bind_spool

    with pytest.raises(GatewayError) as caught:
        _bind_spool(None, SimpleNamespace(payload=SimpleNamespace(spool_id=None)), {})  # type: ignore[arg-type]
    assert caught.value.code is AiErrorCode.CONTEXT_INVALID


# --- the answer's shape -------------------------------------------------------------


def test_an_image_whose_box_is_incomplete_is_dropped() -> None:
    entry = page(0)
    entry["images"][0]["bottom_right_y"] = None
    entry["dimensions"]["dpi"] = 0
    parsed = ocr_page(entry)
    assert parsed.images == () and parsed.dpi is None


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(images="none"),
        lambda e: e["images"][0].update(id=7),
        lambda e: e["dimensions"].update(width=0),
        lambda e: e.update(markdown=None),
        lambda e: e.update(dimensions=[]),
    ],
)
def test_a_page_outside_the_closed_model_is_rejected(change: Any) -> None:
    entry = page(0)
    change(entry)
    with pytest.raises(ProviderFailure) as caught:
        ocr_page(entry)
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED


def _call(handler: Any, **kw: Any) -> AdapterCall:
    from provider_stubs import Progress

    from ai_gateway.credentials.store import ResolvedSecret
    from ai_gateway.providers.http import Deadline

    return AdapterCall(
        client=mock_client(
            handler, target=endpoint(provider_type=ProviderType.MISTRAL)
        ),
        secret=kw.pop("secret", ResolvedSecret(b"sk")),
        model=ModelRef(
            model_id=__import__("uuid").uuid4(), external_model_id="m", dimensions=2
        ),
        progress=Progress(),
        deadline=Deadline.after(5),
        **kw,
    )


def _answer(body: Any) -> Any:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(body).encode()))

    return handler


@pytest.mark.parametrize(
    "body",
    [
        {"pages": "none"},
        [],
        {"pages": [page(0)], "usage_info": "n/a"},
    ],
)
def test_the_ocr_answer_shape(body: Any) -> None:
    call = _call(_answer(body))
    if isinstance(body, dict) and isinstance(body.get("pages"), list):
        output = run(ADAPTER.ocr(call, Document(PDF), [0]))
        assert output.usage is None and len(output.pages) == 1
        return
    with pytest.raises(ProviderFailure):
        run(ADAPTER.ocr(call, Document(PDF), [0]))


def test_an_upload_without_a_tracker_or_a_credential_is_refused() -> None:
    for kw in ({}, {"secret": None}):
        call = _call(_answer({}), **kw)
        with pytest.raises(ProviderFailure) as caught:
            run(ADAPTER.ocr(call, Document(BLOB), [0]))
        assert caught.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED


@pytest.mark.parametrize(
    "stored", [{"object": "file"}, {"id": ""}, {"id": "x" * 257}, []]
)
def test_an_upload_answer_without_a_usable_id_counts_as_lost(stored: Any) -> None:
    class Tracker:
        gateway_file_name = "m8ai-x-y"
        intended = True
        lost_calls = 0

        def intent_progress(self) -> Any:
            from provider_stubs import Progress

            return Progress()

        async def lost(self) -> None:
            Tracker.lost_calls += 1

    call = _call(_answer(stored), artifacts=Tracker())
    with pytest.raises(ProviderFailure) as caught:
        run(ADAPTER.ocr(call, Document(BLOB), [0]))
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED
    assert Tracker.lost_calls == 1


def test_a_failure_before_any_intent_records_no_loss() -> None:
    class Tracker:
        gateway_file_name = "m8ai-x-y"
        intended = False

        def intent_progress(self) -> Any:
            from provider_stubs import Progress

            return Progress()

        async def lost(self) -> None:  # pragma: no cover - must not run
            raise AssertionError("no intent, no loss")

    async def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(ProviderFailure):
        run(ADAPTER.ocr(_call(refuse, artifacts=Tracker()), Document(BLOB), [0]))


def test_a_cleanup_failure_never_reclassifies_the_work() -> None:
    class Tracker:
        async def release(self) -> None:
            raise RuntimeError("database down")

    run(ADAPTER._clean_up(_call(_answer({})), Tracker(), "file-1"))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("status", "body", "proven"),
    [
        (200, {"id": "file-1", "deleted": True}, True),
        (200, {"id": "file-2", "deleted": True}, False),
        (200, {"id": "file-1", "deleted": False}, False),
        (200, {"id": "file-1", "deleted": "true"}, False),
        (200, ["file-1"], False),
        (404, {"detail": "not found"}, False),
    ],
)
def test_only_a_deletion_of_the_recorded_id_is_proof(
    status: int, body: Any, proven: bool
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, stream=httpx.ByteStream(json.dumps(body).encode())
        )

    call = _call(handler)
    assert (
        run(ADAPTER.delete_file(call.client, call.secret, call.deadline, "file-1"))
        is proven
    )


def test_listings_keep_only_this_deployments_prefix_across_pages() -> None:
    prefix = f"m8ai-{DEPLOYMENT_ID}-"
    entries = [
        {"id": f"f{i}", "filename": f"{prefix}{i}" if i % 3 == 0 else f"tenant-{i}.pdf"}
        for i in range(150)
    ]
    entries += [{"id": 5, "filename": f"{prefix}bad"}, {"filename": 7}, "junk"]
    queries: list[dict[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        query = dict(request.url.params)
        queries.append(query)
        number, size = int(query["page"]), int(query["page_size"])
        chunk = entries[number * size : (number + 1) * size]
        body = {"data": chunk}
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(body).encode()))

    call = _call(handler)
    listing = run(ADAPTER.list_files(call.client, call.secret, call.deadline, prefix))
    assert listing.complete
    assert [f.remote_id for f in listing.files] == [f"f{i}" for i in range(0, 150, 3)]
    assert {q["purpose"] for q in queries} == {"ocr"} and len(queries) == 2


def test_a_listing_reports_total_and_its_page_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ai_gateway.providers import mistral as module

    full = [{"id": f"f{i}", "filename": f"m8ai-x-{i}"} for i in range(100)]

    def answer(total: int | None) -> Any:
        body: dict[str, Any] = {"data": full}
        if total is not None:
            body["total"] = total
        return _answer(body)

    call = _call(answer(100))
    assert run(
        ADAPTER.list_files(call.client, call.secret, call.deadline, "m8ai-x-")
    ).complete
    monkeypatch.setattr(module, "MAX_LISTING_PAGES", 2)
    call = _call(answer(None))
    listing = run(
        ADAPTER.list_files(call.client, call.secret, call.deadline, "m8ai-x-")
    )
    assert not listing.complete and len(listing.files) == 200
    with pytest.raises(ProviderFailure):
        call = _call(_answer({"data": "none"}))
        run(ADAPTER.list_files(call.client, call.secret, call.deadline, "m8ai-x-"))


# --- embeddings, structured output, probe, registry --------------------------------


def test_embeddings_and_structured_output_use_the_openai_shapes() -> None:
    bodies: list[Any] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        bodies.append((request.url.path, json.loads(request.content)))
        if request.url.path == "/v1/embeddings":
            body: Any = {"data": [{"index": 0, "embedding": [0.5, 1.0]}]}
        else:
            body = {"choices": [{"message": {"content": '{"total": 42}'}}]}
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(body).encode()))

    call = _call(handler)
    assert run(ADAPTER.embed(call, ["a"])).vectors == [[0.5, 1.0]]
    out = run(ADAPTER.structured_output(call, "t", "invoice", {"type": "object"}, 64))
    assert out.output == {"total": 42}
    assert [path for path, _ in bodies] == ["/v1/embeddings", "/v1/chat/completions"]
    assert bodies[1][1]["response_format"]["type"] == "json_schema"
    with pytest.raises(ProviderFailure) as caught:
        run(ADAPTER.rerank(call, "q", ["d"], None))
    assert caught.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED


def test_the_probe_lists_the_models() -> None:
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, stream=httpx.ByteStream(b'{"data": []}'))

    call = _call(handler)
    run(ADAPTER.probe(call.client, call.secret, call.deadline))
    assert paths == ["/v1/models"]


def test_the_recorded_capabilities_and_the_shipped_registry() -> None:
    assert ADAPTER.capabilities == frozenset(
        {Capability.EMBEDDING, Capability.STRUCTURED_OUTPUT, Capability.OCR}
    )
    assert PROOFS.deletion_proof and not PROOFS.absence_proof
    assert PROOFS.list_consistency == "undocumented"
    assert not PROOFS.safe_server_side_prefix_listing and not PROOFS.sweep_absence_proof
    assert [expiry_hours(s) for s in (1, 3600, 3601, 7200)] == [1, 1, 2, 2]
    shipped = build_adapters(inline_threshold_bytes=10, file_expiry_seconds=7200)
    mistral_adapter = shipped[ProviderType.MISTRAL]
    assert isinstance(mistral_adapter, MistralAdapter)
    assert (
        mistral_adapter._inline_threshold == 10
        and mistral_adapter._expiry_seconds == 7200
    )
    assert isinstance(deps.adapters[ProviderType.MISTRAL], MistralAdapter)
    assert deps.execution_service._receipts is deps.receipt_signer


# --- the result's JCS -----------------------------------------------------------------


def test_jcs_matches_the_sdk_rule_and_sorts_keys_by_utf16_units() -> None:
    from ai_gateway.execution.receipts import jcs

    shallow = {"b": [1, True, None], "a": '\u00e9\n"', "c": {"z": -5}}
    assert jcs(shallow) == canonicalize(shallow)
    # U+FF61 sorts after U+1F600 by code point but before it by UTF-16 units.
    assert jcs({"\U0001f600": 1, "\uff61": 2}) == '{"\U0001f600":1,"\uff61":2}'.encode()
    deep: Any = 0
    for _ in range(32):
        deep = [deep]
    jcs(deep)
    for container in ([deep], {"k": deep}):
        with pytest.raises(ValueError, match="too deep"):
            jcs(container)
    with pytest.raises(SignedObjectError):
        jcs({"x": 0.5})


def test_jcs_bounds_object_nesting_too() -> None:
    from ai_gateway.execution.receipts import jcs

    deep: Any = 0
    for _ in range(33):
        deep = {"k": deep}
    with pytest.raises(ValueError, match="too deep"):
        jcs(deep)


def test_a_recorded_progress_is_not_recorded_twice() -> None:
    import uuid

    from ai_gateway.execution.service import ExecutionProgress

    progress = ExecutionProgress(deps.db_engine, uuid.uuid4())
    progress.recorded = True
    calls: list[int] = []
    run(progress.record_with(lambda: bool(calls.append(1)), once=True))
    assert calls == []


# --- the multipart upload (D-20) --------------------------------------------------


def _upload(size: int, chunks: list[bytes], **kw: Any) -> Any:
    from ai_gateway.providers.http import Deadline, Upload

    async def source() -> Any:
        for chunk in chunks:
            yield chunk

    upload = Upload(
        fields=kw.pop("fields", {"purpose": "ocr"}),
        field_name="file",
        file_name=kw.pop("file_name", "m8ai-x-y"),
        media_type="application/octet-stream",
        size=size,
        chunks=source,
    )
    client = mock_client(_answer({"id": "file-1"}))
    from ai_gateway.credentials.store import ResolvedSecret

    return run(
        client.upload(
            "/v1/files",
            upload,
            deadline=Deadline.after(5),
            secret=ResolvedSecret(b"sk"),
        )
    )


def test_an_upload_larger_than_the_request_cap_is_refused_before_sending() -> None:
    with pytest.raises(ProviderFailure) as caught:
        _upload(64 * 1024 + 1, [])
    assert (
        caught.value.code is AiErrorCode.REQUEST_TOO_LARGE and caught.value.before_send
    )


@pytest.mark.parametrize(
    "chunks", [[b"abc", b"def"], [b"ab"]], ids=["longer", "shorter"]
)
def test_a_source_that_changed_size_stops_the_upload(chunks: list[bytes]) -> None:
    with pytest.raises(ProviderFailure) as caught:
        _upload(4, chunks)
    assert caught.value.code is AiErrorCode.PROVIDER_UNREACHABLE


@pytest.mark.parametrize(
    "kw",
    [{"file_name": 'invoice".pdf'}, {"fields": {"purpose": "ocr\r\nX: y"}}],
    ids=["file-name", "field-value"],
)
def test_a_form_token_outside_the_safe_set_is_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ProviderFailure) as caught:
        _upload(1, [b"a"], **kw)
    assert (
        caught.value.code is AiErrorCode.PROVIDER_REJECTED and caught.value.before_send
    )


def test_an_exact_upload_is_framed_with_its_content_length() -> None:
    assert _upload(3, [b"abc"]).body == {"id": "file-1"}

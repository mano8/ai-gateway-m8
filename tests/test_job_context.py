"""
The S-04 job-context matrix against the shipped execution dependency.

Nothing in the chain is overridden: the routes below sit on a router built by
``build_execution_router``, so each request runs the gateway's own clock
guard, the ``fastapi-m8`` service-client guard over ``AI_SERVICE_CLIENTS``
and the verifier built in ``core/deps.py``; each handler then binds the
profile and redeems the context in its own transaction, as an execution
handler does.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from ai_sdk_m8.jobcontext import JobContextPayload
from ai_sdk_m8.schemas import AiErrorCode, Capability
from ai_sdk_m8.signed import (
    Domain,
    canonicalize,
    generate_seed,
    public_key_from_seed,
    sign_object,
)
from ai_sdk_m8.signed import _rule
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy import select

from ai_gateway.core import deps, job_context
from ai_gateway.core.errors import GatewayError, gateway_error_handler
from ai_gateway.core.execution_guard import (
    JOB_CONTEXT_HEADER,
    JobContextDep,
    build_execution_router,
)
from ai_gateway.core.job_context import (
    InstallationAudience,
    JobContextVerifier,
    redeem_job_context,
)
from ai_gateway.core.service_clients import ServiceClients
from ai_gateway.db_models.accounting import ai_job_context_use
from ai_gateway.installation import InstallationError
from conftest import (
    DOC_ISSUER,
    MEDIA_SERVICE,
    MEDIA_WORKER,
    ServiceIdentity,
    bearer,
)
from fastapi_m8 import ConsumerCredentialRegistry
from job_contexts import AUDIENCE, OCR_SPOOL_CLAIMS, claims, mint, raw_token

PREFIX = "/ai/v1/execute"


class _Body(BaseModel):
    profile_key: str


def _execute(principal: JobContextDep, body: _Body) -> dict[str, object]:
    principal.require_profile(body.profile_key)
    with deps.engine._engine.begin() as connection:
        principal.redeem(connection)
    payload = principal.payload
    return {
        "client_id": principal.client_id,
        "iss": payload.iss,
        "azp": payload.azp,
        "capability": payload.capability.value,
        "data_class": payload.data_class.value,
    }


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    router = build_execution_router(prefix=PREFIX)
    for path in ("/embed", "/ocr", "/rerank", "/structured-output"):
        router.add_api_route(path, _execute, methods=["POST"])
    app = FastAPI()
    app.add_exception_handler(GatewayError, gateway_error_handler)
    app.include_router(router)
    with TestClient(app) as test_client:
        yield test_client


def _call(
    client: TestClient,
    token: str | None,
    *,
    presenter: ServiceIdentity | None = MEDIA_SERVICE,
    path: str = "/embed",
    profile_key: str = "embed-default",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    sent = dict(headers or {})
    if presenter is not None:
        sent.update(presenter.headers())
    if token is not None:
        sent[JOB_CONTEXT_HEADER] = token
    response = client.post(
        f"{PREFIX}{path}", json={"profile_key": profile_key}, headers=sent
    )
    if token:
        assert token not in response.text
    body: dict[str, object] = response.json()
    return response.status_code, body


def _refused(
    client: TestClient, token: str | None, code: AiErrorCode, **kwargs: object
) -> None:
    status, body = _call(client, token, **kwargs)  # type: ignore[arg-type]
    assert body["code"] == code.value
    assert status == (403 if code is AiErrorCode.FORBIDDEN_SCOPE else 401)
    assert set(body) == {"code", "request_id"}


# --- accepted ----------------------------------------------------------------


@pytest.mark.usefixtures("clean_db")
def test_a_valid_context_is_accepted_and_redeemed(client: TestClient) -> None:
    jti = str(uuid.uuid4())
    status, body = _call(client, mint(jti=jti))
    assert status == 200
    assert body == {
        "client_id": "media-service",
        "iss": "media-service",
        "azp": "media-service",
        "capability": "embedding",
        "data_class": "internal",
    }
    with deps.engine._engine.connect() as connection:
        row = connection.execute(
            select(ai_job_context_use).where(ai_job_context_use.c.jti == jti)
        ).one()
    assert (row.iss, row.uses, row.max_uses) == ("media-service", 1, 1)


@pytest.mark.usefixtures("clean_db")
def test_the_worker_presents_a_context_media_service_signed_for_it(
    client: TestClient,
) -> None:
    token = mint(azp="media-worker", **OCR_SPOOL_CLAIMS)
    status, body = _call(client, token, presenter=MEDIA_WORKER, path="/ocr")
    assert status == 200
    assert body["client_id"] == body["azp"] == "media-worker"
    assert body["iss"] == "media-service"


@pytest.mark.usefixtures("clean_db")
@pytest.mark.parametrize(
    ("path", "capability"),
    [("/rerank", "rerank"), ("/structured-output", "structured_output")],
)
def test_each_route_takes_its_own_capability(
    client: TestClient, path: str, capability: str
) -> None:
    status, body = _call(client, mint(capability=capability), path=path)
    assert (status, body["capability"]) == (200, capability)


@pytest.mark.usefixtures("clean_db")
def test_nbf_inside_the_skew_bound_is_accepted(client: TestClient) -> None:
    now = int(time.time())
    status, _ = _call(client, mint(iat=now + 3, nbf=now + 3, exp=now + 60))
    assert status == 200


@pytest.mark.usefixtures("clean_db")
def test_the_same_jti_under_two_issuers_is_independent(client: TestClient) -> None:
    jti = str(uuid.uuid4())
    assert _call(client, mint(MEDIA_SERVICE, jti=jti))[0] == 200
    assert _call(client, mint(DOC_ISSUER, jti=jti), presenter=DOC_ISSUER)[0] == 200


# --- service client ----------------------------------------------------------


def test_a_missing_context_is_context_missing(client: TestClient) -> None:
    _refused(client, None, AiErrorCode.CONTEXT_MISSING)


def test_a_jwt_on_an_execution_route_is_refused(client: TestClient) -> None:
    _refused(
        client,
        mint(),
        AiErrorCode.UNAUTHORIZED,
        presenter=None,
        headers=bearer("superadmin"),
    )


def test_unknown_client_and_wrong_secret_answer_alike(client: TestClient) -> None:
    ghost = ServiceIdentity("ghost", ("execute:embedding",))
    _refused(client, mint(), AiErrorCode.UNAUTHORIZED, presenter=ghost)
    _refused(
        client,
        mint(),
        AiErrorCode.UNAUTHORIZED,
        headers=MEDIA_SERVICE.headers("x" * 64),
        presenter=None,
    )


def test_a_presenter_without_the_execute_scope_is_forbidden(
    client: TestClient,
) -> None:
    token = mint(**OCR_SPOOL_CLAIMS)
    _refused(client, token, AiErrorCode.FORBIDDEN_SCOPE, path="/ocr")


# --- issuer, key and audience ------------------------------------------------


def test_an_unknown_kid_is_refused(client: TestClient) -> None:
    _refused(client, mint(seed=generate_seed()), AiErrorCode.CONTEXT_INVALID)


def test_an_unknown_issuer_is_refused(client: TestClient) -> None:
    _refused(client, mint(iss="ghost"), AiErrorCode.CONTEXT_INVALID)


def test_a_registered_client_without_the_issue_scope_cannot_issue(
    client: TestClient,
) -> None:
    token = mint(iss="media-worker", azp="media-worker", **OCR_SPOOL_CLAIMS)
    _refused(
        client, token, AiErrorCode.CONTEXT_INVALID, presenter=MEDIA_WORKER, path="/ocr"
    )


def test_a_context_signed_with_another_clients_key_is_refused(
    client: TestClient,
) -> None:
    token = mint(MEDIA_SERVICE, seed=DOC_ISSUER.seed)
    _refused(client, token, AiErrorCode.CONTEXT_INVALID)


@pytest.mark.parametrize(
    "aud", [f"ai-gateway/{uuid.uuid4()}", "ai-gateway/staging", AUDIENCE + "x"]
)
def test_another_installations_audience_is_refused(
    client: TestClient, aud: str
) -> None:
    _refused(client, mint(aud=aud), AiErrorCode.CONTEXT_INVALID)


# --- presenter, capability and profile binding -------------------------------


def test_a_presenter_other_than_azp_is_refused(client: TestClient) -> None:
    _refused(client, mint(azp="media-worker"), AiErrorCode.CONTEXT_INVALID)
    _refused(
        client,
        mint(azp="media-service"),
        AiErrorCode.CONTEXT_INVALID,
        presenter=DOC_ISSUER,
    )


def test_a_capability_mismatch_is_refused(client: TestClient) -> None:
    _refused(client, mint(capability="rerank"), AiErrorCode.CONTEXT_INVALID)


def test_a_profile_mismatch_is_refused(client: TestClient) -> None:
    _refused(client, mint(), AiErrorCode.CONTEXT_INVALID, profile_key="other-profile")


# --- clock and lifetime ------------------------------------------------------


def test_an_nbf_beyond_the_skew_is_refused(client: TestClient) -> None:
    now = int(time.time())
    _refused(client, mint(nbf=now + 30, exp=now + 60), AiErrorCode.CONTEXT_INVALID)


def test_an_expired_context_is_context_expired(client: TestClient) -> None:
    now = int(time.time())
    token = mint(iat=now - 61, nbf=now - 61, exp=now - 1)
    _refused(client, token, AiErrorCode.CONTEXT_EXPIRED)


def test_a_ttl_over_the_cap_is_refused(client: TestClient) -> None:
    now = int(time.time())
    _refused(client, mint(exp=now + 901), AiErrorCode.CONTEXT_INVALID)


def test_a_dispatch_context_over_its_ttl_is_refused(client: TestClient) -> None:
    now = int(time.time())
    token = mint(
        azp="media-worker",
        **{**OCR_SPOOL_CLAIMS, "phase": "dispatch"},
        spool_id=str(uuid.uuid4()),
        exp=now + 31,
    )
    _refused(
        client, token, AiErrorCode.CONTEXT_INVALID, presenter=MEDIA_WORKER, path="/ocr"
    )


# --- redemption --------------------------------------------------------------


@pytest.mark.usefixtures("clean_db")
def test_a_replay_is_context_replayed(client: TestClient) -> None:
    token = mint()
    assert _call(client, token)[0] == 200
    _refused(client, token, AiErrorCode.CONTEXT_REPLAYED)


@pytest.mark.usefixtures("clean_db")
def test_concurrent_redemptions_admit_exactly_one() -> None:
    payload = JobContextPayload.model_validate(claims())
    barrier = threading.Barrier(8)

    def attempt(_: int) -> str:
        barrier.wait()
        try:
            with deps.engine._engine.begin() as connection:
                redeem_job_context(connection, payload)
        except GatewayError as exc:
            return exc.code.value
        return "ok"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count("ok") == 1
    assert outcomes.count("context_replayed") == 7


@pytest.mark.usefixtures("clean_db")
def test_a_redemption_rolls_back_with_its_transaction() -> None:
    payload = JobContextPayload.model_validate(claims())
    with pytest.raises(RuntimeError):
        with deps.engine._engine.begin() as connection:
            redeem_job_context(connection, payload)
            raise RuntimeError("the row transition failed")
    with deps.engine._engine.begin() as connection:
        redeem_job_context(connection, payload)


@pytest.mark.usefixtures("clean_db")
def test_a_lagging_replica_cannot_redeem_past_the_database_clock(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = int(time.time())
    # The row a sweeper would have removed is gone (never written here); the
    # replica's own clock still thinks the context is live.
    token = mint(iat=now - 200, nbf=now - 200, exp=now - 10)
    monkeypatch.setattr(deps.job_contexts, "_clock", lambda: now - 100)
    _refused(client, token, AiErrorCode.CONTEXT_EXPIRED)
    with deps.engine._engine.connect() as connection:
        assert connection.execute(select(ai_job_context_use)).first() is None


def test_max_uses_other_than_one_is_refused(client: TestClient) -> None:
    _refused(client, mint(max_uses=2), AiErrorCode.CONTEXT_INVALID)


# --- encoding, before any signature work -------------------------------------


@pytest.fixture
def signature_checks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    real = _rule.verify_bytes

    def counted(public_key: bytes, signature: bytes, message: bytes) -> bool:
        calls.append(1)
        return real(public_key, signature, message)

    monkeypatch.setattr(_rule, "verify_bytes", counted)
    return calls


def _canonical(**overrides: object) -> bytes:
    return canonicalize(claims(**overrides))


def _malformed() -> dict[str, str]:
    canonical = _canonical()
    reordered = json.dumps(claims(), separators=(",", ":"), sort_keys=False).encode()
    assert reordered != canonical
    duplicated = canonical[:-1] + b',"v":1}'
    floated = canonical.replace(b'"attempt":1', b'"attempt":1.0')
    assert floated != canonical
    return {
        "non-canonical": raw_token(reordered),
        "duplicate-key": raw_token(duplicated),
        "float": raw_token(floated),
        "padded-base64url": raw_token(canonical, pad=True),
    }


@pytest.mark.parametrize("case", sorted(_malformed()))
def test_a_malformed_encoding_is_refused_before_the_signature(
    client: TestClient, signature_checks: list[int], case: str
) -> None:
    _refused(client, _malformed()[case], AiErrorCode.CONTEXT_INVALID)
    assert signature_checks == []


def test_a_header_over_4_kib_is_refused_before_decoding(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoded: list[int] = []
    monkeypatch.setattr(job_context, "verify", lambda *a, **k: decoded.append(1))
    _refused(client, "a" * 5120, AiErrorCode.CONTEXT_INVALID)
    assert decoded == []


def test_a_tampered_payload_or_signature_is_refused(client: TestClient) -> None:
    payload, signature = mint().split(".")
    other = mint(job_ref="run-2").split(".")[0]
    _refused(client, f"{other}.{signature}", AiErrorCode.CONTEXT_INVALID)
    middle = len(signature) // 2
    flipped = "A" if signature[middle] != "A" else "B"
    tampered = signature[:middle] + flipped + signature[middle + 1 :]
    _refused(client, f"{payload}.{tampered}", AiErrorCode.CONTEXT_INVALID)


# --- cross-purpose substitution ----------------------------------------------


def _receipt() -> str:
    assert MEDIA_SERVICE.seed is not None
    body = {
        "v": 1,
        "typ": Domain.OCR_RECEIPT.value,
        "kid": MEDIA_SERVICE.kid,
        "iss": AUDIENCE,
        "execution_id": str(uuid.uuid4()),
        "capability": "ocr",
        "job_ref": "run-1",
        "attempt": 1,
        "azp": "media-service",
        "profile_key": "embed-default",
        "input_sha256": "b" * 64,
        "ocr_options_hash": "c" * 64,
        "execution_identity": "0" * 32,
        "result_sha256": "d" * 64,
        "produced_at": int(time.time()),
    }
    return sign_object(body, domain=Domain.OCR_RECEIPT, seed=MEDIA_SERVICE.seed)


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(_receipt, id="ocr-receipt"),
        pytest.param(lambda: mint(domain=Domain.OCR_RECEIPT), id="context-as-receipt"),
        pytest.param(
            lambda: mint(domain=Domain.SANDBOX_ATTESTATION), id="context-as-attestation"
        ),
    ],
)
def test_an_object_signed_for_another_purpose_is_refused(
    client: TestClient, token: object
) -> None:
    assert callable(token)
    _refused(client, token(), AiErrorCode.CONTEXT_INVALID)


# --- disclosure --------------------------------------------------------------


@pytest.mark.usefixtures("clean_db")
def test_no_token_reaches_a_log_line(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    tokens = [mint(), mint(seed=generate_seed()), mint(capability="rerank")]
    tokens.append(tokens[0])  # a replay
    for token in tokens:
        _call(client, token)
    for token in tokens:
        assert token not in caplog.text
        assert token.split(".")[1] not in caplog.text


# --- the verifier and the audience, directly ---------------------------------


def _verifier(clients: ServiceClients) -> JobContextVerifier:
    return JobContextVerifier(
        clients,
        audience=lambda: AUDIENCE,
        max_ttl_seconds=900,
        skew_seconds=5,
        dispatch_ttl_seconds=30,
    )


def _clients(
    scopes: frozenset[str], keys: dict[str, dict[str, bytes]]
) -> ServiceClients:
    return ServiceClients(
        registry=ConsumerCredentialRegistry([]),
        scopes={client_id: scopes for client_id in keys},
        public_keys=keys,
    )


def test_keys_of_a_client_without_the_issue_scope_never_verify() -> None:
    issuer = ServiceIdentity("x", (), seed=generate_seed())
    assert issuer.seed is not None
    keys = {"x": {issuer.kid: public_key_from_seed(issuer.seed)}}
    token = mint(issuer)
    with pytest.raises(GatewayError) as refused:
        _verifier(_clients(frozenset({"execute:embedding"}), keys)).verify(
            token, presenter="x", capability=Capability.EMBEDDING
        )
    assert refused.value.code is AiErrorCode.CONTEXT_INVALID
    accepted = _verifier(_clients(frozenset({"job-context:issue"}), keys)).verify(
        token, presenter="x", capability=Capability.EMBEDDING
    )
    assert accepted.payload.iss == "x"


def test_a_kid_under_two_clients_is_refused_at_build() -> None:
    keys = {"a": {"K": b"\x01" * 32}, "b": {"K": b"\x02" * 32}}
    with pytest.raises(ValueError, match="two clients"):
        _verifier(_clients(frozenset({"job-context:issue"}), keys))


def test_the_audience_is_read_once_from_the_installation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []
    recorded = uuid.UUID(AUDIENCE.removeprefix("ai-gateway/"))

    def read(_engine: object) -> uuid.UUID:
        reads.append(1)
        return recorded

    monkeypatch.setattr(job_context, "recorded_deployment_id", read)
    audience = InstallationAudience(lambda: deps.engine._engine)
    assert audience() == audience() == AUDIENCE
    assert reads == [1]


def test_no_recorded_installation_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(job_context, "recorded_deployment_id", lambda _e: None)
    with pytest.raises(InstallationError):
        InstallationAudience(lambda: deps.engine._engine)()


def test_the_shipped_audience_is_the_recorded_installation() -> None:
    assert InstallationAudience(lambda: deps.engine._engine)() == AUDIENCE

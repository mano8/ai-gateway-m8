"""
The hardened provider client (T26, D-20, D-24, D-41, S-02).

In-process tests drive the real client over ``httpx.MockTransport``; the
socket tests drive it over httpx's real transport and connection pool
against a local stub (``provider_stubs``), so connection failures, TLS
verification, the trace-based dispatch marker and the total deadline are
exercised for real.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
import logging
import re
import ssl
import time
import traceback
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import format_datetime
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from ai_sdk_m8.schemas import AiErrorCode, Capability, ProviderBoundary
from ai_sdk_m8.schemas.errors import ProviderStatusClass
from ai_sdk_m8.schemas.management import AuthType
from pydantic import ValidationError
from sqlalchemy import select

import ai_gateway
from ai_gateway.core.config import settings
from ai_gateway.core.errors import error_response
from ai_gateway.credentials.store import ResolvedSecret
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.providers import http as provider_http
from ai_gateway.providers.base import (
    AdapterCall,
    ModelRef,
    require_capability,
    unsupported,
)
from ai_gateway.providers.breaker import BreakerState, Breakers, CircuitBreaker
from ai_gateway.providers.cooldown import apply_cooldown
from ai_gateway.providers.errors import (
    ProviderFailure,
    class_of,
    gateway_error,
    refused_before_send,
)
from ai_gateway.providers.http import (
    MAX_RESPONSE_JSON_DEPTH,
    BoundedBody,
    ClientFactory,
    ClientLimits,
    Deadline,
    ProviderAnswer,
    ProviderEndpoint,
    ProviderHttpClient,
    credential_headers,
    json_depth,
    parse_json,
    route,
)
from ai_gateway.providers.retry_after import (
    DEFAULT_RETRY_AFTER_SECONDS,
    parse_retry_after,
)
from provider_stubs import (
    HOST,
    LIMITS,
    POLICY,
    Progress,
    Reply,
    Resolver,
    StubServer,
    TestPki,
    closed_port,
    endpoint,
    mock_client,
    socket_transport,
)
import factories
import pg_harness as pg

CANARY = "sk-canary-0f1e2d3c4b5a69788796a5b4c3d2e1f0"


def run(coro: Any) -> Any:
    return asyncio.run(coro)


@dataclass(frozen=True)
class Canned:
    """A reply, built fresh and streamed for each request.

    ``httpx.Response(content=...)`` reads (and decodes) its body at
    construction; a real transport never does, so the stubs stream theirs.
    """

    status: int = 200
    content: bytes = b""
    headers: tuple[tuple[str, str], ...] = ()

    def response(self) -> httpx.Response:
        return httpx.Response(
            self.status,
            headers=list(self.headers),
            stream=httpx.ByteStream(self.content),
        )


def json_reply(
    body: object, status: int = 200, headers: tuple[tuple[str, str], ...] = ()
) -> Canned:
    content = json.dumps(body).encode()
    return Canned(status, content, (("content-type", "application/json"), *headers))


async def call(
    client: ProviderHttpClient,
    path: str = "/v1/embeddings",
    *,
    deadline: Deadline | None = None,
    **kwargs: Any,
) -> ProviderAnswer:
    async with client:
        return await client.request(
            kwargs.pop("method", "POST"),
            path,
            deadline=deadline or Deadline.after(5),
            **kwargs,
        )


def failure_of(coro: Any) -> ProviderFailure:
    with pytest.raises(ProviderFailure) as caught:
        run(coro)
    return caught.value


class Recorder:
    """A MockTransport handler answering ``responder`` and keeping the requests."""

    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self._responder = responder
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responder(request)


def answering(canned: Canned) -> Recorder:
    return Recorder(lambda _request: canned.response())


# --- the request the client builds ------------------------------------------------


def test_a_json_answer_comes_back_parsed_and_the_request_is_fixed() -> None:
    handler = answering(json_reply({"data": [1, 2]}))
    answer = run(
        call(
            mock_client(handler),
            json_body={"input": ["a"]},
            secret=ResolvedSecret(b"sk-test-value"),
        )
    )
    assert answer == ProviderAnswer(200, {"data": [1, 2]})
    (request,) = handler.requests
    assert str(request.url) == f"https://{HOST}/v1/embeddings"
    assert request.headers["authorization"] == "Bearer sk-test-value"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["accept"] == "application/json"
    assert request.headers["user-agent"] == "ai-gateway-m8"
    assert request.headers["content-type"] == "application/json"
    assert request.content == b'{"input":["a"]}'


def test_the_base_path_prefixes_every_route_and_query_is_adapter_fixed() -> None:
    handler = answering(json_reply({}))
    target = endpoint(f"https://{HOST}/openai/")
    run(
        call(
            mock_client(handler, target=target),
            "/v1/files",
            method="GET",
            query={"page": "0"},
            secret=ResolvedSecret(b"k"),
        )
    )
    assert str(handler.requests[0].url) == f"https://{HOST}/openai/v1/files?page=0"


def test_route_encodes_every_segment() -> None:
    assert route("/api/models/{model}", model="org/model:v1?x#y") == (
        "/api/models/org%2Fmodel%3Av1%3Fx%23y"
    )
    assert route("/v1/files/{id}", id="../admin") == "/v1/files/..%2Fadmin"


@pytest.mark.parametrize(
    "path", ["v1/x", "/v1/../admin", "/v1/./x", "/a?b=1", "/a#b", "/a b", "/", "//x"]
)
def test_a_path_outside_the_fixed_templates_is_refused_before_sending(
    path: str,
) -> None:
    handler = answering(json_reply({}))
    failure = failure_of(call(mock_client(handler), path, secret=ResolvedSecret(b"k")))
    assert failure.code is AiErrorCode.PROVIDER_REJECTED and failure.before_send
    assert handler.requests == []


def test_an_api_key_header_credential_travels_under_its_header_only() -> None:
    handler = answering(json_reply({}))
    target = endpoint(auth_type=AuthType.API_KEY_HEADER, auth_header_name="x-api-key")
    run(call(mock_client(handler, target=target), secret=ResolvedSecret(b"key-1")))
    headers = handler.requests[0].headers
    assert headers["x-api-key"] == "key-1"
    assert "authorization" not in headers


def test_auth_type_none_sends_no_credential_even_when_one_is_given() -> None:
    handler = answering(json_reply({}))
    target = endpoint(
        "http://ollama:11434",
        auth_type=AuthType.NONE,
        boundary=ProviderBoundary.LOCAL,
    )
    run(call(mock_client(handler, target=target), secret=ResolvedSecret(b"unused")))
    headers = handler.requests[0].headers
    assert "authorization" not in headers and "unused" not in str(headers)


@pytest.mark.parametrize(
    ("target", "secret"),
    [
        (endpoint(), None),
        (endpoint(), ResolvedSecret(b"line\r\nX-Injected: 1")),
        (endpoint(), ResolvedSecret(b" leading-space")),
        (endpoint(), ResolvedSecret("café".encode())),
        (endpoint(auth_type=AuthType.API_KEY_HEADER), ResolvedSecret(b"k")),
        (
            endpoint(auth_type=AuthType.API_KEY_HEADER, auth_header_name="x-ai-key"),
            ResolvedSecret(b"k"),
        ),
        (
            endpoint(auth_type=AuthType.API_KEY_HEADER, auth_header_name="Host"),
            ResolvedSecret(b"k"),
        ),
    ],
)
def test_a_credential_that_cannot_travel_safely_is_refused_before_sending(
    target: ProviderEndpoint, secret: ResolvedSecret | None
) -> None:
    handler = answering(json_reply({}))
    failure = failure_of(call(mock_client(handler, target=target), secret=secret))
    assert failure.code is AiErrorCode.CREDENTIAL_UNAVAILABLE and failure.before_send
    assert handler.requests == []


def test_credential_headers_by_auth_type() -> None:
    secret = ResolvedSecret(b"s3cr3t")
    assert credential_headers(endpoint(auth_type=AuthType.NONE), None) == {}
    assert credential_headers(endpoint(), secret) == {"Authorization": "Bearer s3cr3t"}
    keyed = endpoint(auth_type=AuthType.API_KEY_HEADER, auth_header_name="api-key")
    assert credential_headers(keyed, secret) == {"api-key": "s3cr3t"}


def test_an_oversize_request_body_is_refused_before_sending() -> None:
    handler = answering(json_reply({}))
    body = {"input": "x" * (LIMITS.max_request_bytes + 1)}
    failure = failure_of(
        call(mock_client(handler), json_body=body, secret=ResolvedSecret(b"k"))
    )
    assert failure.code is AiErrorCode.REQUEST_TOO_LARGE and failure.before_send
    assert handler.requests == []


@pytest.mark.parametrize("body", [{"v": float("nan")}, {"v": object()}])
def test_a_body_that_is_not_json_is_refused_before_sending(
    body: dict[str, Any],
) -> None:
    handler = answering(json_reply({}))
    failure = failure_of(
        call(mock_client(handler), json_body=body, secret=ResolvedSecret(b"k"))
    )
    assert failure.code is AiErrorCode.PROVIDER_REJECTED and failure.before_send


# --- the destination guard on every request -----------------------------------------


def test_the_guard_runs_on_every_request() -> None:
    resolver = Resolver()
    handler = answering(json_reply({}))

    async def two() -> None:
        async with mock_client(handler, resolver=resolver) as client:
            for _ in range(2):
                await client.request(
                    "GET",
                    "/v1/models",
                    deadline=Deadline.after(5),
                    secret=ResolvedSecret(b"k"),
                )

    run(two())
    assert resolver.lookups == [HOST, HOST]
    assert len(handler.requests) == 2


@pytest.mark.parametrize(
    "answers",
    [
        ["169.254.169.254"],
        ["10.0.0.1"],
        ["100.64.0.1"],
        ["::ffff:10.0.0.1"],
        ["93.184.216.34", "192.168.1.10"],
        ["127.0.0.1"],
        [],
    ],
)
def test_an_external_host_resolving_anywhere_private_is_never_contacted(
    answers: list[str],
) -> None:
    handler = answering(json_reply({}))
    failure = failure_of(
        call(
            mock_client(handler, resolver=Resolver(answers)),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert failure.code is AiErrorCode.PROVIDER_UNREACHABLE and failure.before_send
    assert handler.requests == []


def test_a_resolution_failure_is_refused_before_sending() -> None:
    def broken(_host: str) -> list[str]:
        raise OSError("no such host")

    handler = answering(json_reply({}))
    failure = failure_of(
        call(mock_client(handler, resolver=broken), secret=ResolvedSecret(b"k"))
    )
    assert failure.before_send and handler.requests == []


def test_a_request_for_another_origin_never_passes_the_guard() -> None:
    client = mock_client(answering(json_reply({})))
    for url in (
        "https://evil.test/v1/x",
        f"http://{HOST}/v1/x",
        f"https://{HOST}:8443/v1/x",
    ):
        with pytest.raises(provider_http._GuardRefused):
            run(client._guard(httpx.Request("GET", url)))
    run(client._guard(httpx.Request("GET", f"https://{HOST}/v1/x")))
    run(client.aclose())


def test_an_endpoint_that_is_not_a_valid_target_builds_no_client() -> None:
    with pytest.raises(ProviderFailure) as caught:
        mock_client(answering(json_reply({})), target=endpoint("ftp://files.test"))
    assert caught.value.code is AiErrorCode.PROVIDER_UNREACHABLE
    assert caught.value.before_send


def test_a_redirect_to_a_metadata_address_is_not_followed() -> None:
    handler = answering(
        Canned(302, headers=(("Location", "http://169.254.169.254/latest/meta-data/"),))
    )
    failure = failure_of(call(mock_client(handler), secret=ResolvedSecret(b"k")))
    assert failure.code is AiErrorCode.PROVIDER_REJECTED
    assert failure.status_class is ProviderStatusClass.REDIRECT
    assert len(handler.requests) == 1


# --- answers by status ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code", "klass", "auth"),
    [
        (400, AiErrorCode.PROVIDER_REJECTED, ProviderStatusClass.CLIENT_ERROR, False),
        (401, AiErrorCode.PROVIDER_REJECTED, ProviderStatusClass.CLIENT_ERROR, True),
        (403, AiErrorCode.PROVIDER_REJECTED, ProviderStatusClass.CLIENT_ERROR, True),
        (404, AiErrorCode.PROVIDER_REJECTED, ProviderStatusClass.CLIENT_ERROR, False),
        (
            500,
            AiErrorCode.PROVIDER_UNREACHABLE,
            ProviderStatusClass.SERVER_ERROR,
            False,
        ),
        (
            503,
            AiErrorCode.PROVIDER_UNREACHABLE,
            ProviderStatusClass.SERVER_ERROR,
            False,
        ),
    ],
)
def test_a_non_success_answer_maps_to_a_closed_failure(
    status: int, code: AiErrorCode, klass: ProviderStatusClass, auth: bool
) -> None:
    failure = failure_of(
        call(
            mock_client(answering(json_reply({"e": 1}, status))),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert (failure.code, failure.status_class, failure.auth_failure) == (
        code,
        klass,
        auth,
    )
    assert not failure.before_send


def test_an_accepted_status_comes_back_with_its_body_discarded() -> None:
    handler = answering(json_reply({"detail": "not found"}, 404))
    answer = run(
        call(
            mock_client(handler),
            method="DELETE",
            accept=frozenset({404}),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert answer == ProviderAnswer(404, None)


def test_an_empty_success_body_is_none() -> None:
    answer = run(call(mock_client(answering(Canned())), secret=ResolvedSecret(b"k")))
    assert answer.body is None


def test_a_429_carries_its_bounded_retry_after() -> None:
    def with_header(value: str) -> int | None:
        response = Canned(429, headers=(("Retry-After", value),))
        failure = failure_of(
            call(mock_client(answering(response)), secret=ResolvedSecret(b"k"))
        )
        assert failure.code is AiErrorCode.RATE_LIMITED and failure.throttled
        return failure.retry_after_seconds

    assert with_header("30") == 30
    assert with_header("999999") == LIMITS.max_backoff_seconds
    assert with_header("soon") == DEFAULT_RETRY_AFTER_SECONDS
    later = format_datetime(datetime.now(UTC) + timedelta(seconds=120), usegmt=True)
    assert 115 <= (with_header(later) or 0) <= 121


# --- transport failures ----------------------------------------------------------------


def raising(exc: Exception) -> Recorder:
    def respond(_request: httpx.Request) -> httpx.Response:
        raise exc

    return Recorder(respond)


@pytest.mark.parametrize(
    ("exc", "code", "before_send"),
    [
        (httpx.ConnectError("refused"), AiErrorCode.PROVIDER_UNREACHABLE, True),
        (httpx.ConnectTimeout("slow"), AiErrorCode.PROVIDER_UNREACHABLE, True),
        (httpx.ReadTimeout("slow"), AiErrorCode.TIMEOUT, False),
        (httpx.WriteTimeout("slow"), AiErrorCode.TIMEOUT, False),
        (httpx.PoolTimeout("busy"), AiErrorCode.TIMEOUT, False),
        (httpx.ReadError("reset"), AiErrorCode.PROVIDER_UNREACHABLE, False),
        (httpx.WriteError("reset"), AiErrorCode.PROVIDER_UNREACHABLE, False),
        (httpx.RemoteProtocolError("bad"), AiErrorCode.PROVIDER_UNREACHABLE, False),
        (httpx.DecodingError("bad"), AiErrorCode.PROVIDER_REJECTED, False),
    ],
)
def test_a_transport_failure_is_closed_and_only_connect_failures_are_pre_send(
    exc: Exception, code: AiErrorCode, before_send: bool
) -> None:
    progress = Progress()
    failure = failure_of(
        call(mock_client(raising(exc)), secret=ResolvedSecret(b"k"), progress=progress)
    )
    assert (failure.code, failure.before_send) == (code, before_send)
    assert failure.__cause__ is None and "refused" not in str(failure)


def test_a_passed_deadline_stops_the_call_before_any_request() -> None:
    handler = answering(json_reply({}))
    failure = failure_of(
        call(
            mock_client(handler),
            deadline=Deadline.after(-1),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert failure.code is AiErrorCode.TIMEOUT and not failure.before_send
    assert handler.requests == []


def test_deadline_counts_down_on_its_clock() -> None:
    now = [100.0]
    deadline = Deadline.after(5, clock=lambda: now[0])
    assert deadline.remaining() == 5
    now[0] = 106.0
    assert deadline.remaining() == -1
    with pytest.raises(ProviderFailure):
        deadline.require()


def test_a_cancelled_call_frees_the_breaker_trial() -> None:
    clock = [0.0]
    breaker = CircuitBreaker(
        failure_threshold=1, reset_seconds=1, clock=lambda: clock[0]
    )
    breaker.failure()
    clock[0] = 2.0
    assert breaker.state is BreakerState.HALF_OPEN

    async def hang(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        raise AssertionError("unreachable")

    async def cancelled() -> None:
        client = mock_client(hang, breaker=breaker)
        task = asyncio.create_task(call(client, secret=ResolvedSecret(b"k")))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(cancelled())
    assert breaker.allow()


# --- bounded answers ----------------------------------------------------------------------


def body_reply(content: bytes, encoding: str | None = None) -> Canned:
    headers = (("content-encoding", encoding),) if encoding else ()
    return Canned(200, content, headers)


def test_an_oversize_answer_is_aborted() -> None:
    big = json.dumps({"x": "y" * LIMITS.max_response_bytes}).encode()
    failure = failure_of(
        call(mock_client(answering(body_reply(big))), secret=ResolvedSecret(b"k"))
    )
    assert failure.code is AiErrorCode.RESPONSE_TOO_LARGE


def test_a_gzip_bomb_under_the_raw_cap_is_aborted_at_the_decoded_cap() -> None:
    bomb = gzip.compress(b"[" + b"0," * (8 * 1024 * 1024) + b"0]", 9)
    assert len(bomb) < LIMITS.max_response_bytes
    failure = failure_of(
        call(
            mock_client(answering(body_reply(bomb, "gzip"))),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert failure.code is AiErrorCode.RESPONSE_TOO_LARGE


def test_the_decoded_count_never_grows_past_the_cap_while_inflating() -> None:
    limit = 1024
    body = BoundedBody("gzip", limit)
    bomb = gzip.compress(b"\0" * (10 * 1024 * 1024))
    with pytest.raises(ProviderFailure) as caught:
        for start in range(0, len(bomb), 512):
            body.feed(bomb[start : start + 512])
    assert caught.value.code is AiErrorCode.RESPONSE_TOO_LARGE
    assert len(body._decoded) <= limit


def test_an_inflated_body_one_byte_past_the_cap_is_refused() -> None:
    body = BoundedBody("gzip", 199)
    data = gzip.compress(b"x" * 200, mtime=0)
    with pytest.raises(ProviderFailure) as caught:
        for index in range(len(data)):
            body.feed(data[index : index + 1])
    assert caught.value.code is AiErrorCode.RESPONSE_TOO_LARGE
    assert len(body._decoded) <= 199


@pytest.mark.parametrize("encoding", ["gzip", "x-gzip", "deflate", "identity", None])
def test_a_compressed_answer_inside_the_cap_is_decoded(encoding: str | None) -> None:
    raw = b'{"ok": true}'
    content = raw
    if encoding in ("gzip", "x-gzip"):
        content = gzip.compress(raw)
    elif encoding == "deflate":
        content = zlib.compress(raw)
    answer = run(
        call(
            mock_client(answering(body_reply(content, encoding))),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert answer.body == {"ok": True}


@pytest.mark.parametrize(
    ("content", "encoding"),
    [
        (b"{}", "br"),
        (b"{}", "gzip, br"),
        (gzip.compress(b'{"ok": true}')[:-6], "gzip"),
        (gzip.compress(b"{}") + b"trailing", "gzip"),
        (b"not gzip at all", "gzip"),
    ],
)
def test_an_unknown_or_broken_encoding_is_rejected(
    content: bytes, encoding: str
) -> None:
    failure = failure_of(
        call(
            mock_client(answering(body_reply(content, encoding))),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert failure.code is AiErrorCode.PROVIDER_REJECTED
    assert failure.status_class is ProviderStatusClass.SUCCESS


def nested(depth: int) -> bytes:
    return b"[" * depth + b"]" * depth


@pytest.mark.parametrize(
    "content",
    [
        nested(MAX_RESPONSE_JSON_DEPTH + 1),
        nested(20_000),  # past the parser's recursion limit, under the size cap
        b'{"v": NaN}',
        b'{"v": Infinity}',
        b'{"v": "\xff"}',
        b"{not json",
    ],
    ids=["over-depth", "recursion", "nan", "infinity", "not-utf8", "malformed"],
)
def test_an_over_deep_or_malformed_json_answer_is_rejected(content: bytes) -> None:
    failure = failure_of(
        call(mock_client(answering(body_reply(content))), secret=ResolvedSecret(b"k"))
    )
    assert failure.code is AiErrorCode.PROVIDER_REJECTED


def test_json_at_the_depth_cap_is_accepted_and_depth_is_measured() -> None:
    assert parse_json(nested(MAX_RESPONSE_JSON_DEPTH)) is not None
    assert parse_json(b"") is None
    assert json_depth(3) == 0
    assert json_depth({"a": [1, {"b": []}]}) == 4
    assert parse_json(b'{"a": 1.5}', max_depth=1) == {"a": 1.5}


# --- the breaker -----------------------------------------------------------------------------


def test_the_breaker_opens_on_5xx_and_timeouts_and_refuses_before_sending() -> None:
    breaker = CircuitBreaker(failure_threshold=3)
    statuses = iter([500, 502])

    def respond(_request: httpx.Request) -> httpx.Response:
        status = next(statuses, None)
        if status is None:
            raise httpx.ReadTimeout("slow")
        return httpx.Response(status)

    handler = Recorder(respond)
    for _ in range(3):
        failure_of(
            call(mock_client(handler, breaker=breaker), secret=ResolvedSecret(b"k"))
        )
    assert breaker.state is BreakerState.OPEN
    refused = failure_of(
        call(mock_client(handler, breaker=breaker), secret=ResolvedSecret(b"k"))
    )
    assert refused.code is AiErrorCode.BREAKER_OPEN and refused.before_send
    assert len(handler.requests) == 3


def test_the_breaker_stays_closed_through_any_number_of_credential_outcomes() -> None:
    breaker = CircuitBreaker(failure_threshold=2)
    statuses = iter([401, 403, 429] * 20)
    handler = Recorder(lambda _r: httpx.Response(next(statuses)))
    for _ in range(60):
        failure_of(
            call(mock_client(handler, breaker=breaker), secret=ResolvedSecret(b"k"))
        )
    assert breaker.state is BreakerState.CLOSED
    assert len(handler.requests) == 60


def test_a_tenants_invalid_key_opens_no_breaker_for_another_tenant() -> None:
    breaker = CircuitBreaker(failure_threshold=1)
    rejected = Recorder(lambda _r: httpx.Response(401))
    for _ in range(10):
        failure_of(
            call(mock_client(rejected, breaker=breaker), secret=ResolvedSecret(b"bad"))
        )
    served = answering(json_reply({"ok": True}))
    answer = run(
        call(mock_client(served, breaker=breaker), secret=ResolvedSecret(b"good"))
    )
    assert answer.body == {"ok": True}


def test_a_half_open_breaker_closes_on_success_and_reopens_on_failure() -> None:
    clock = [0.0]
    breaker = CircuitBreaker(
        failure_threshold=1, reset_seconds=10, clock=lambda: clock[0]
    )
    breaker.failure()
    assert breaker.state is BreakerState.OPEN and not breaker.allow()
    clock[0] = 11.0
    assert breaker.allow() and not breaker.allow()  # one trial at a time
    breaker.failure()
    assert breaker.state is BreakerState.OPEN
    clock[0] = 22.0
    assert breaker.allow()
    breaker.neutral()  # a credential outcome frees the trial
    assert breaker.allow()
    breaker.success()
    assert breaker.state is BreakerState.CLOSED and breaker.allow()


def test_breakers_are_one_per_provider() -> None:
    registry = Breakers()
    target = endpoint()
    first = registry.for_provider(target.provider_id)
    assert registry.for_provider(target.provider_id) is first
    other_id = endpoint().provider_id
    other = registry.for_provider(other_id)
    for _ in range(5):
        first.failure()
    assert registry.states() == {
        target.provider_id: BreakerState.OPEN,
        other_id: BreakerState.CLOSED,
    }
    assert other.state is BreakerState.CLOSED


# --- no secret reaches a response, a log or a trace -------------------------------------------


def _forms(secret: str) -> list[str]:
    raw = secret.encode()
    return [
        secret,
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        secret[: len(secret) // 2],
        secret[len(secret) // 2 :],
        raw.hex(),
    ]


def test_a_malicious_error_body_never_reaches_the_failure_or_the_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    half = len(CANARY) // 2
    hostile = (
        f"error: {CANARY} b64={base64.b64encode(CANARY.encode()).decode()} "
        f"split={CANARY[:half]}\n{CANARY[half:]}"
    ).encode()
    texts: list[str] = []
    for status in (400, 401, 429, 500):
        response = Canned(
            status, hostile, (("x-echo", CANARY), ("retry-after", CANARY))
        )
        failure = failure_of(
            call(
                mock_client(answering(response)), secret=ResolvedSecret(CANARY.encode())
            )
        )
        texts += [str(failure), repr(failure), *map(str, failure.args)]
        texts.append("".join(traceback.format_exception(failure)))
        texts.append(error_response(gateway_error(failure)).body.decode())
    texts.append(caplog.text)
    for form in _forms(CANARY):
        assert all(form not in text for text in texts), form


# --- dispatch progress, over real sockets ------------------------------------------------------


def test_progress_is_recorded_before_the_provider_sees_a_byte() -> None:
    progress = Progress()
    seen_recorded: list[bool] = []

    async def scenario() -> ProviderAnswer:
        server = StubServer(
            Reply(chunks=[b'{"ok":true}']),
            on_request=lambda _r: seen_recorded.append(progress.recorded),
        )
        async with server:
            client, _network = socket_client(server.port)
            return await call(
                client,
                json_body={"a": 1},
                secret=ResolvedSecret(b"k"),
                progress=progress,
            )

    answer = run(scenario())
    assert answer.body == {"ok": True}
    assert seen_recorded == [True]


def socket_client(
    port: int, *, target: ProviderEndpoint | None = None, **kw: Any
) -> tuple[ProviderHttpClient, Any]:
    transport, network = socket_transport(port, ssl_context=kw.pop("ssl_context", None))
    client = ProviderHttpClient(
        target or endpoint(f"http://{HOST}"),
        policy=POLICY,
        limits=kw.pop("limits", LIMITS),
        breaker=kw.pop("breaker", CircuitBreaker()),
        resolver=Resolver(),
        transport=transport,
    )
    return client, network


def test_a_refused_connection_is_pre_send_and_records_no_progress() -> None:
    progress = Progress()
    client, network = socket_client(closed_port())
    failure = failure_of(call(client, secret=ResolvedSecret(b"k"), progress=progress))
    assert failure.code is AiErrorCode.PROVIDER_UNREACHABLE and failure.before_send
    assert progress.calls == 0 and network.connects == [(HOST, 80)]


def test_a_slow_drip_answer_is_cancelled_at_the_total_deadline() -> None:
    progress = Progress()

    async def scenario() -> tuple[ProviderFailure, float]:
        drip = Reply(chunks=[b" "] * 50, delay=0.1, content_length=50)
        async with StubServer(drip) as server:
            client, _network = socket_client(server.port)
            started = time.monotonic()
            try:
                await call(
                    client,
                    deadline=Deadline.after(0.5),
                    secret=ResolvedSecret(b"k"),
                    progress=progress,
                )
            except ProviderFailure as failure:
                return failure, time.monotonic() - started
        raise AssertionError("the call should have timed out")

    failure, elapsed = run(scenario())
    assert failure.code is AiErrorCode.TIMEOUT and not failure.before_send
    assert 0.4 <= elapsed < 2.0
    assert progress.recorded


def test_no_time_left_at_connect_opens_no_connection() -> None:
    reads = iter([0.0, 0.0])

    def clock() -> float:
        return next(reads, 10.0)

    async def scenario() -> tuple[ProviderFailure, StubServer, Any]:
        async with StubServer(Reply()) as server:
            client, network = socket_client(server.port)
            try:
                await call(
                    client,
                    deadline=Deadline(1.0, clock=clock),
                    secret=ResolvedSecret(b"k"),
                )
            except ProviderFailure as failure:
                return failure, server, network
        raise AssertionError("refused expected")

    failure, server, network = run(scenario())
    assert failure.code is AiErrorCode.TIMEOUT
    assert network.connects == [] and server.requests == []


def test_no_time_left_before_writing_sends_no_byte_and_no_progress() -> None:
    reads = iter([0.0, 0.0, 0.0])
    progress = Progress()

    def clock() -> float:
        return next(reads, 10.0)

    async def scenario() -> tuple[ProviderFailure, StubServer]:
        async with StubServer(Reply()) as server:
            client, _network = socket_client(server.port)
            try:
                await call(
                    client,
                    deadline=Deadline(1.0, clock=clock),
                    secret=ResolvedSecret(b"k"),
                    progress=progress,
                )
            except ProviderFailure as failure:
                await asyncio.sleep(0.05)
                return failure, server
        raise AssertionError("refused expected")

    failure, server = run(scenario())
    assert failure.code is AiErrorCode.TIMEOUT
    assert server.requests == [] and progress.calls == 0


@pytest.mark.parametrize(
    "fail", [RuntimeError("database down"), ProviderFailure(AiErrorCode.TIMEOUT)]
)
def test_progress_that_cannot_be_persisted_stops_the_write(fail: BaseException) -> None:
    progress = Progress(fail=fail)

    async def scenario() -> tuple[ProviderFailure, StubServer]:
        async with StubServer(Reply()) as server:
            client, _network = socket_client(server.port)
            try:
                await call(client, secret=ResolvedSecret(b"k"), progress=progress)
            except ProviderFailure as failure:
                await asyncio.sleep(0.05)
                return failure, server
        raise AssertionError("refused expected")

    failure, server = run(scenario())
    assert not failure.before_send
    assert server.requests == []


def test_a_transport_without_trace_still_records_progress_once_answered() -> None:
    progress = Progress()
    run(
        call(
            mock_client(answering(json_reply({}))),
            secret=ResolvedSecret(b"k"),
            progress=progress,
        )
    )
    assert progress.recorded


def test_the_header_canary_never_reaches_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    async def scenario() -> None:
        async with StubServer(Reply(chunks=[b'{"ok":true}'])) as server:
            client, _network = socket_client(server.port)
            await call(
                client, json_body={"q": 1}, secret=ResolvedSecret(CANARY.encode())
            )
            assert server.requests[0].header("authorization") == f"Bearer {CANARY}"

    run(scenario())
    assert "httpcore" in caplog.text  # the transport's own DEBUG lines were captured
    for form in _forms(CANARY):
        assert form not in caplog.text


# --- TLS ---------------------------------------------------------------------------------------


def tls_scenario(server_context: ssl.SSLContext, pki: TestPki) -> Any:
    async def scenario() -> Any:
        async with StubServer(
            Reply(chunks=[b'{"tls":true}']), ssl_context=server_context
        ) as server:
            client, network = socket_client(
                server.port,
                target=endpoint(f"https://{HOST}"),
                ssl_context=pki.client_context(),
            )
            progress = Progress()
            try:
                answer = await call(
                    client, secret=ResolvedSecret(b"k"), progress=progress
                )
            except ProviderFailure as failure:
                return failure, progress, network
            return answer, progress, network

    return scenario()


def test_tls_is_verified_and_a_trusted_certificate_for_the_host_is_served() -> None:
    pki = TestPki()
    answer, progress, _network = run(tls_scenario(pki.server_context(HOST), pki))
    assert answer.body == {"tls": True} and progress.recorded


@pytest.mark.parametrize("case", ["other host", "untrusted CA"])
def test_a_certificate_that_does_not_verify_fails_before_sending(case: str) -> None:
    pki = TestPki()
    stranger = TestPki("someone else's CA")
    server = (
        pki.server_context("evil.test")
        if case == "other host"
        else stranger.server_context(HOST)
    )
    failure, progress, _network = run(tls_scenario(server, pki))
    assert failure.code is AiErrorCode.PROVIDER_UNREACHABLE and failure.before_send
    assert progress.calls == 0


def test_dns_rebinding_residual_is_mitigated_only_by_certificate_verification() -> None:
    """
    The T19 residual, with TLS (carried to T26).

    The guard resolves the host to a public answer and passes; the
    connection then lands somewhere else (here: the stub on 127.0.0.1, as a
    rebinding answer would). Without a certificate for the host the
    handshake fails before any byte is sent; a target holding a valid
    certificate for the host is reached — the stated residual, closed only by
    connect-time destination enforcement (Q13, a named follow-on).
    """
    pki = TestPki()
    mitigated, _progress, network = run(
        tls_scenario(pki.server_context("rebound.test"), pki)
    )
    assert isinstance(mitigated, ProviderFailure) and mitigated.before_send
    assert network.connects == [(HOST, 443)]
    residual, _progress, _network = run(tls_scenario(pki.server_context(HOST), pki))
    assert residual.body == {"tls": True}


# --- configuration --------------------------------------------------------------------------------


def test_the_default_transport_verifies_tls_and_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    client = ProviderHttpClient(
        endpoint(), policy=POLICY, limits=LIMITS, breaker=CircuitBreaker()
    )
    inner = client._client
    assert inner.trust_env is False and inner.follow_redirects is False
    assert inner._mounts == {}
    transport = inner._transport
    assert isinstance(transport, httpx.AsyncHTTPTransport)
    context = transport._pool._ssl_context
    assert context.verify_mode is ssl.CERT_REQUIRED and context.check_hostname
    assert client.endpoint.base_url == f"https://{HOST}"
    run(client.aclose())


def test_no_code_turns_tls_verification_off() -> None:
    pattern = re.compile(
        r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False"
        r"|_create_unverified_context|trust_env\s*=\s*True"
    )
    package = Path(ai_gateway.__file__).parent
    offenders = [
        str(path) for path in package.rglob("*.py") if pattern.search(path.read_text())
    ]
    assert offenders == []


def test_limits_and_endpoints_come_from_settings_and_rows() -> None:
    limits = ClientLimits.from_settings(settings)
    assert limits == ClientLimits(
        timeout_seconds=float(settings.AI_PROVIDER_TIMEOUT_SECONDS),
        max_request_bytes=settings.AI_MAX_REQUEST_BYTES,
        max_response_bytes=settings.AI_MAX_RESPONSE_BYTES,
        max_backoff_seconds=settings.AI_PROVIDER_MAX_BACKOFF_SECONDS,
    )
    target = endpoint()
    row = {
        "id": target.provider_id,
        "provider_type": "openai_compatible",
        "base_url": target.base_url,
        "boundary": "external",
        "auth_type": "bearer",
        "auth_header_name": None,
    }
    assert ProviderEndpoint.from_row(row) == target
    keyed = ProviderEndpoint.from_row(
        row | {"auth_type": "api_key_header", "auth_header_name": "x-api-key"}
    )
    assert keyed.auth_header_name == "x-api-key"


def test_the_factory_builds_one_client_per_call_on_the_providers_breaker() -> None:
    breakers = Breakers()
    seen: list[ProviderEndpoint] = []

    def transport(target: ProviderEndpoint) -> httpx.AsyncBaseTransport:
        seen.append(target)
        return httpx.MockTransport(lambda _r: json_reply({"via": "factory"}).response())

    factory = ClientFactory(
        POLICY, LIMITS, breakers, resolver=Resolver(), transport=transport
    )
    target = endpoint()
    answer = run(call(factory.client(target), secret=ResolvedSecret(b"k")))
    assert answer.body == {"via": "factory"} and seen == [target]
    plain = ClientFactory(POLICY, LIMITS, breakers).client(target)
    assert plain._breaker is breakers.for_provider(target.provider_id)
    run(plain.aclose())


# --- adapter calls -------------------------------------------------------------------------------


def test_an_adapter_call_sends_through_its_client_deadline_and_progress() -> None:
    handler = answering(json_reply({"ok": 1}))
    progress = Progress()

    async def scenario() -> list[ProviderAnswer]:
        async with mock_client(handler) as client:
            adapter_call = AdapterCall(
                client=client,
                secret=ResolvedSecret(b"k"),
                model=ModelRef(model_id=endpoint().provider_id, external_model_id="m"),
                progress=progress,
                deadline=Deadline.after(5),
            )
            return [
                await adapter_call.post("/v1/a", {"x": 1}),
                await adapter_call.get("/v1/b", query={"page": "1"}),
                await adapter_call.delete("/v1/c"),
            ]

    answers = run(scenario())
    assert [a.body for a in answers] == [{"ok": 1}] * 3
    assert [(r.method, r.url.path) for r in handler.requests] == [
        ("POST", "/v1/a"),
        ("GET", "/v1/b"),
        ("DELETE", "/v1/c"),
    ]
    assert handler.requests[1].url.params["page"] == "1"
    assert progress.recorded


def test_an_unserved_capability_is_refused_before_any_request() -> None:
    class Adapter:
        capabilities = frozenset({Capability.EMBEDDING})

    require_capability(Adapter(), Capability.EMBEDDING)  # type: ignore[arg-type]
    with pytest.raises(ProviderFailure) as caught:
        require_capability(Adapter(), Capability.RERANK)  # type: ignore[arg-type]
    assert caught.value.code is AiErrorCode.CAPABILITY_UNSUPPORTED
    assert caught.value.before_send and unsupported().before_send


# --- failures and their public form -----------------------------------------------------------


def test_a_failure_shows_its_code_only_and_validates_its_metadata() -> None:
    failure = ProviderFailure(
        AiErrorCode.PROVIDER_REJECTED,
        status_class=ProviderStatusClass.CLIENT_ERROR,
        metadata={"pages_returned": 3},
    )
    assert str(failure) == "provider_rejected"
    assert repr(failure) == "ProviderFailure(provider_rejected)"
    assert failure.metadata == {"pages_returned": 3} and not failure.throttled
    with pytest.raises(ValidationError):
        ProviderFailure(AiErrorCode.PROVIDER_REJECTED, metadata={"text": "x" * 300})
    with pytest.raises(ValidationError):
        ProviderFailure(AiErrorCode.PROVIDER_REJECTED, metadata={"a": {"b": {"c": 1}}})
    assert refused_before_send(AiErrorCode.TIMEOUT).before_send


@pytest.mark.parametrize(
    ("status", "klass"),
    [
        (101, ProviderStatusClass.SUCCESS),
        (204, ProviderStatusClass.SUCCESS),
        (307, ProviderStatusClass.REDIRECT),
        (418, ProviderStatusClass.CLIENT_ERROR),
        (599, ProviderStatusClass.SERVER_ERROR),
    ],
)
def test_status_classes(status: int, klass: ProviderStatusClass) -> None:
    assert class_of(status) is klass


def test_the_public_error_carries_the_typed_fields_only() -> None:
    failure = ProviderFailure(
        AiErrorCode.RATE_LIMITED,
        status_class=ProviderStatusClass.CLIENT_ERROR,
        retry_after_seconds=30,
        metadata={"retryable": True},
    )
    response = error_response(gateway_error(failure))
    body = json.loads(response.body)
    assert response.status_code == 429 and response.headers["retry-after"] == "30"
    assert set(body) == {
        "code",
        "request_id",
        "provider_status_class",
        "retry_after_seconds",
        "provider_metadata",
    }
    assert body["provider_status_class"] == "4xx"


# --- Retry-After and the credential cooldown (D-20) ----------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30", 30),
        (" 30 ", 30),
        ("0", 0),
        ("999999", 300),
        ("9" * 40, 300),
        ("", 60),
        ("soon", 60),
        ("-5", 60),
        ("3.5", 60),
        ("Mon, 99 Foo 2026 00:00:00 GMT", 60),
        ("Wed, 21 Oct 2015 07:28:00", 60),
        (None, 60),
    ],
)
def test_retry_after_is_parsed_and_bounded(value: str | None, expected: int) -> None:
    assert parse_retry_after(value, cap_seconds=300, now=time.time()) == expected


def test_an_http_date_is_honoured_within_the_cap_and_a_past_one_is_zero() -> None:
    now = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)

    def at(delta: int) -> str:
        return format_datetime(now + timedelta(seconds=delta), usegmt=True)

    stamp = now.timestamp()
    assert parse_retry_after(at(90), cap_seconds=300, now=stamp) == 90
    assert parse_retry_after(at(9000), cap_seconds=300, now=stamp) == 300
    assert parse_retry_after(at(-90), cap_seconds=300, now=stamp) == 0
    assert parse_retry_after(None, cap_seconds=20, now=stamp) == 20


@pytest.fixture
def credential_id(clean_db: None) -> Any:
    engine = pg.owner_engine()
    try:
        with engine.begin() as connection:
            provider_id = factories.provider(connection)
            created = factories.credential(connection, provider_id)
    finally:
        engine.dispose()
    return created


def _cooldown_left(credential_id: Any) -> float:
    from sqlalchemy import func

    from ai_gateway.core.deps import db_engine

    with db_engine.connect() as connection:
        value = connection.execute(
            select(
                func.extract("epoch", ai_credential.c.throttled_until - func.now())
            ).where(ai_credential.c.id == credential_id)
        ).scalar_one()
    return float(value)


def _cooldown_from(header: str | None, credential_id: Any) -> float:
    headers = () if header is None else (("Retry-After", header),)
    failure = failure_of(
        call(
            mock_client(answering(Canned(429, headers=headers))),
            secret=ResolvedSecret(b"k"),
        )
    )
    assert failure.throttled and failure.retry_after_seconds is not None
    from ai_gateway.core.deps import db_engine

    with db_engine.begin() as connection:
        apply_cooldown(connection, credential_id, failure.retry_after_seconds)
    return _cooldown_left(credential_id)


def test_a_429_sets_the_credential_cooldown_on_the_database_clock(
    credential_id: Any,
) -> None:
    assert 28.5 <= _cooldown_from("30", credential_id) <= 30.5


@pytest.mark.parametrize(
    ("header", "low", "high"),
    [
        ("999999", 299, 300.5),
        (None, 59, 60.5),
        ("garbage", 59, 60.5),
    ],
)
def test_the_cooldown_is_capped_and_falls_back_to_sixty_seconds(
    credential_id: Any, header: str | None, low: float, high: float
) -> None:
    assert low <= _cooldown_from(header, credential_id) <= high


def test_an_http_date_cooldown_is_honoured_within_the_cap(credential_id: Any) -> None:
    later = format_datetime(datetime.now(UTC) + timedelta(seconds=120), usegmt=True)
    assert 113 <= _cooldown_from(later, credential_id) <= 121


def test_a_later_shorter_cooldown_never_shortens_an_earlier_one(
    credential_id: Any,
) -> None:
    from ai_gateway.core.deps import db_engine

    with db_engine.begin() as connection:
        apply_cooldown(connection, credential_id, 120)
        apply_cooldown(connection, credential_id, 5)
    assert _cooldown_left(credential_id) > 100
    with db_engine.begin() as connection:
        apply_cooldown(connection, credential_id, 250)
    assert _cooldown_left(credential_id) > 240

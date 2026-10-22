"""
The hardened provider HTTP client (D-20, S-02).

One :class:`ProviderHttpClient` serves one provider call: it is built for
the call's provider and closed when the call ends, so no connection, header
or credential is ever shared between providers, and every connection
follows a fresh destination check.

Every request, in order:

1. the body is encoded and bounded by ``AI_MAX_REQUEST_BYTES``, and the
   credential is put in the provider's validated header from the call's
   :class:`~ai_gateway.credentials.store.ResolvedSecret` — nowhere else;
2. the provider's circuit breaker must admit the call;
3. the call's total deadline must have time left;
4. the ``T19`` guard re-checks the endpoint and **every** A/AAAA answer of
   its host (an httpx request hook: it runs for every request the client
   sends) and the request must target the endpoint's own origin;
5. immediately before the first byte of a request is written, the call's
   dispatch progress is recorded (``first_byte_sent()``, D-24), and the
   remaining time is checked again before connecting and before writing;
6. the answer is streamed: raw **and** decoded bytes are counted against
   ``AI_MAX_RESPONSE_BYTES`` (``Accept-Encoding: identity`` is requested; a
   ``gzip``/``deflate`` answer is inflated under the cap, any other coding
   refused) and JSON is parsed under a nesting-depth cap, ``NaN`` and
   ``Infinity`` refused.

The exchange runs under ``asyncio.timeout_at`` at the call's absolute
deadline, which the execution core derives from the stored
``dispatch_deadline_at``. Redirects are never followed, proxy variables and
``.netrc`` are never read (``trust_env=False``), TLS verification is never
off. Every failure is one :class:`~ai_gateway.providers.errors.ProviderFailure`;
provider bodies, headers and exception text are discarded, never excerpted.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import zlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, Literal, Protocol
from urllib.parse import quote
from uuid import UUID

import httpx
from ai_sdk_m8.schemas import AiErrorCode, ProviderBoundary
from ai_sdk_m8.schemas.errors import ProviderStatusClass
from ai_sdk_m8.schemas.management import (
    RESERVED_HEADER_PREFIXES,
    AuthType,
    ProviderType,
)
from pydantic import JsonValue

from ai_gateway.core.ssrf import (
    DestinationError,
    DestinationPolicy,
    ProviderTarget,
    Resolver,
    check_resolved,
    default_resolver,
    parse_target,
)
from ai_gateway.credentials.store import ResolvedSecret

from .breaker import Breakers, CircuitBreaker
from .errors import ProviderFailure, class_of, refused_before_send
from .retry_after import parse_retry_after

#: Nesting depth beyond which a provider's JSON answer is refused. C-14
#: names no setting: a capability answer is at most a few levels deep.
MAX_RESPONSE_JSON_DEPTH: Final = 32

#: The ``User-Agent`` of every provider request.
USER_AGENT: Final = "ai-gateway-m8"

#: Connections one call may open (a multi-request workflow reuses one).
MAX_CONNECTIONS: Final = 4

_HEADER_NAME: Final = re.compile(r"(?:x-[a-z0-9-]{1,60}|api-key)")
# A credential is printable ASCII without surrounding spaces: nothing can
# split the header or smuggle another one.
_HEADER_VALUE: Final = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]{0,8190}[\x21-\x7e])?")
_ROUTE: Final = re.compile(r"(?:/[A-Za-z0-9._~%:@!$&'()*+,;=-]+)+")

#: httpcore trace events: before connecting, before writing a request.
_CONNECT_EVENTS: Final = frozenset({"connection.connect_tcp.started"})
_SEND_EVENTS: Final = frozenset(
    {"http11.send_request_headers.started", "http2.send_request_headers.started"}
)

Method = Literal["GET", "POST", "DELETE"]


class Deadline:
    """
    A call's absolute deadline on the monotonic clock (D-24).

    Built once from the stored ``dispatch_deadline_at`` and the database
    time the marker transaction returned; never re-derived from a fresh
    relative timeout, so a paused process cannot extend it.
    """

    __slots__ = ("_at", "_clock")

    def __init__(
        self, at: float, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._at = at
        self._clock = clock

    @classmethod
    def after(
        cls, seconds: float, *, clock: Callable[[], float] = time.monotonic
    ) -> Deadline:
        """The deadline ``seconds`` from now."""
        return cls(clock() + seconds, clock=clock)

    def remaining(self) -> float:
        """Seconds left; zero or negative once the deadline passed."""
        return self._at - self._clock()

    def require(self) -> None:
        """Refuse to start more provider I/O once no time remains."""
        if self.remaining() <= 0:
            raise ProviderFailure(AiErrorCode.TIMEOUT)


class DispatchProgress(Protocol):
    """How a provider call tells the execution core it may have sent a byte."""

    async def first_byte_sent(self) -> None:
        """Persist ``first_byte_sent_at`` before the first request byte; idempotent."""


@dataclass(frozen=True)
class ClientLimits:
    """The bounds every provider request runs under."""

    timeout_seconds: float
    max_request_bytes: int
    max_response_bytes: int
    max_backoff_seconds: int

    @classmethod
    def from_settings(cls, settings: object) -> ClientLimits:
        """From gateway ``Settings``."""
        return cls(
            timeout_seconds=float(getattr(settings, "AI_PROVIDER_TIMEOUT_SECONDS")),
            max_request_bytes=int(getattr(settings, "AI_MAX_REQUEST_BYTES")),
            max_response_bytes=int(getattr(settings, "AI_MAX_RESPONSE_BYTES")),
            max_backoff_seconds=int(
                getattr(settings, "AI_PROVIDER_MAX_BACKOFF_SECONDS")
            ),
        )


@dataclass(frozen=True)
class ProviderEndpoint:
    """The frozen endpoint of one provider row."""

    provider_id: UUID
    provider_type: ProviderType
    base_url: str
    boundary: ProviderBoundary
    auth_type: AuthType
    auth_header_name: str | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, object]) -> ProviderEndpoint:
        """From an ``ai_provider`` row."""
        provider_id = row["id"]
        assert isinstance(provider_id, UUID)  # nosec B101 - a uuid column
        header = row["auth_header_name"]
        return cls(
            provider_id=provider_id,
            provider_type=ProviderType(str(row["provider_type"])),
            base_url=str(row["base_url"]),
            boundary=ProviderBoundary(str(row["boundary"])),
            auth_type=AuthType(str(row["auth_type"])),
            auth_header_name=None if header is None else str(header),
        )


@dataclass(frozen=True)
class ProviderAnswer:
    """A provider answer the adapter may read: its status and JSON body."""

    status: int
    body: JsonValue


def route(template: str, **segments: str) -> str:
    """
    A request path from a fixed template; every segment is URL-encoded.

    Provider model ids and file ids reach a path only through here, so no
    caller-supplied ``/``, ``?``, ``#`` or ``..`` can change the route.
    """
    return template.format_map({k: quote(v, safe="") for k, v in segments.items()})


def credential_headers(
    endpoint: ProviderEndpoint, secret: ResolvedSecret | None
) -> dict[str, str]:
    """
    The credential header of ``endpoint``, from ``secret`` only.

    ``auth_type = none`` sends no credential at all. A bearer credential
    travels in ``Authorization``; an ``api_key_header`` one under the
    provider's header name, re-validated here against the D-20 rule.
    """
    if endpoint.auth_type is AuthType.NONE:
        return {}
    if secret is None:
        raise refused_before_send(AiErrorCode.CREDENTIAL_UNAVAILABLE)
    value = secret.reveal()
    if not _HEADER_VALUE.fullmatch(value):
        raise refused_before_send(AiErrorCode.CREDENTIAL_UNAVAILABLE)
    if endpoint.auth_type is AuthType.BEARER:
        return {"Authorization": f"Bearer {value}"}
    name = endpoint.auth_header_name
    if (
        name is None
        or not _HEADER_NAME.fullmatch(name)
        or name.startswith(RESERVED_HEADER_PREFIXES)
    ):
        raise refused_before_send(AiErrorCode.CREDENTIAL_UNAVAILABLE)
    return {name: value}


def encode_json_body(body: Mapping[str, object], max_bytes: int) -> bytes:
    """Compact UTF-8 JSON of ``body``, refused above ``max_bytes``."""
    try:
        content = json.dumps(
            body, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise refused_before_send(AiErrorCode.PROVIDER_REJECTED) from None
    if len(content) > max_bytes:
        raise refused_before_send(AiErrorCode.REQUEST_TOO_LARGE)
    return content


def _rejected() -> ProviderFailure:
    return ProviderFailure(
        AiErrorCode.PROVIDER_REJECTED, status_class=ProviderStatusClass.SUCCESS
    )


def _too_large() -> ProviderFailure:
    return ProviderFailure(
        AiErrorCode.RESPONSE_TOO_LARGE, status_class=ProviderStatusClass.SUCCESS
    )


def _refuse_constant(_name: str) -> None:
    raise ValueError("NaN and Infinity are not JSON")


def json_depth(value: JsonValue) -> int:
    """The nesting depth of a parsed JSON value (a scalar is 0)."""
    deepest = 0
    stack: list[tuple[JsonValue, int]] = [(value, 1)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, dict):
            children = list(node.values())
        elif isinstance(node, list):
            children = node
        else:
            continue
        deepest = max(deepest, level)
        stack.extend((child, level + 1) for child in children)
    return deepest


def parse_json(body: bytes, *, max_depth: int = MAX_RESPONSE_JSON_DEPTH) -> JsonValue:
    """Strict UTF-8 JSON, ``NaN``/``Infinity`` refused, at most ``max_depth`` deep."""
    if not body:
        return None
    try:
        value: JsonValue = json.loads(
            body.decode("utf-8"), parse_constant=_refuse_constant
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _rejected() from None
    if json_depth(value) > max_depth:
        raise _rejected()
    return value


def _inflater(content_encoding: str | None) -> zlib._Decompress | None:
    codings = [c.strip() for c in (content_encoding or "").lower().split(",")]
    codings = [c for c in codings if c]
    if codings in ([], ["identity"]):
        return None
    if codings in (["gzip"], ["x-gzip"]):
        return zlib.decompressobj(zlib.MAX_WBITS | 16)
    if codings == ["deflate"]:
        return zlib.decompressobj(zlib.MAX_WBITS)
    raise _rejected()


class BoundedBody:
    """
    One answer's body, counted on the wire **and** after decoding.

    A compressed answer is inflated in steps that never produce more than
    the bytes still allowed, so a decompression bomb stops at the cap
    instead of being expanded first.
    """

    def __init__(self, content_encoding: str | None, limit: int) -> None:
        self._limit = limit
        self._raw = 0
        self._decoded = bytearray()
        self._inflater = _inflater(content_encoding)

    def feed(self, chunk: bytes) -> None:
        """Add one raw chunk; refuse once either count passes the cap."""
        self._raw += len(chunk)
        if self._raw > self._limit:
            raise _too_large()
        if self._inflater is None:
            self._append(chunk)
            return
        room = self._limit - len(self._decoded) + 1
        try:
            inflated = self._inflater.decompress(chunk, room)
        except zlib.error:
            raise _rejected() from None
        if self._inflater.unconsumed_tail:
            raise _too_large()
        self._append(inflated)

    def _append(self, data: bytes) -> None:
        if len(self._decoded) + len(data) > self._limit:
            raise _too_large()
        self._decoded += data

    def finish(self) -> bytes:
        """The decoded body; a truncated or trailing-garbage stream is refused."""
        if self._inflater is not None and (
            not self._inflater.eof or self._inflater.unused_data
        ):
            raise _rejected()
        return bytes(self._decoded)


class _Outcome(Enum):
    """What one exchange tells the provider's breaker (D-20)."""

    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"


class _Classified(Exception):
    """A failure and what it means for the breaker; never leaves the module."""

    def __init__(self, failure: ProviderFailure, outcome: _Outcome) -> None:
        super().__init__(failure.code.value)
        self.failure = failure
        self.outcome = outcome


class _GuardRefused(Exception):
    """The destination guard refused the request before any connection."""


async def _record(progress: DispatchProgress) -> None:
    try:
        await progress.first_byte_sent()
    except ProviderFailure:
        raise
    except Exception:
        # Progress could not be persisted, so no byte may be written; the
        # call is past its marker and settles as charged.
        raise ProviderFailure(AiErrorCode.PROVIDER_UNREACHABLE) from None


def _trace(
    progress: DispatchProgress | None, deadline: Deadline
) -> Callable[[str, Mapping[str, object]], Awaitable[None]]:
    """The httpcore trace hook: deadline before I/O, progress before writing."""

    async def trace(event: str, _info: Mapping[str, object]) -> None:
        if event in _CONNECT_EVENTS:
            deadline.require()
        elif event in _SEND_EVENTS:
            deadline.require()
            if progress is not None:
                await _record(progress)

    return trace


def _status_failure(response: httpx.Response, max_backoff: int) -> _Classified:
    status = response.status_code
    klass = class_of(status)
    if status == 429:
        seconds = parse_retry_after(
            response.headers.get("retry-after"),
            cap_seconds=max_backoff,
            now=time.time(),
        )
        failure = ProviderFailure(
            AiErrorCode.RATE_LIMITED, status_class=klass, retry_after_seconds=seconds
        )
        return _Classified(failure, _Outcome.NEUTRAL)
    if status in (401, 403):
        failure = ProviderFailure(
            AiErrorCode.PROVIDER_REJECTED, status_class=klass, auth_failure=True
        )
        return _Classified(failure, _Outcome.NEUTRAL)
    if status >= 500:
        failure = ProviderFailure(AiErrorCode.PROVIDER_UNREACHABLE, status_class=klass)
        return _Classified(failure, _Outcome.FAILURE)
    failure = ProviderFailure(AiErrorCode.PROVIDER_REJECTED, status_class=klass)
    return _Classified(failure, _Outcome.SUCCESS)


def _transport_failure(exc: Exception) -> _Classified:
    """Map an exception raised while sending or reading, never keeping its text."""
    if isinstance(exc, ProviderFailure):
        # From the trace hook: no I/O started for this request.
        return _Classified(exc, _Outcome.NEUTRAL)
    if isinstance(exc, _GuardRefused):
        return _Classified(
            refused_before_send(AiErrorCode.PROVIDER_UNREACHABLE), _Outcome.NEUTRAL
        )
    if isinstance(exc, httpx.ConnectError | httpx.ConnectTimeout):
        # No request byte left the process (TLS handshake failures included).
        return _Classified(
            refused_before_send(AiErrorCode.PROVIDER_UNREACHABLE), _Outcome.FAILURE
        )
    if isinstance(exc, httpx.TimeoutException):
        return _Classified(ProviderFailure(AiErrorCode.TIMEOUT), _Outcome.FAILURE)
    if isinstance(exc, httpx.TransportError):
        return _Classified(
            ProviderFailure(AiErrorCode.PROVIDER_UNREACHABLE), _Outcome.FAILURE
        )
    return _Classified(ProviderFailure(AiErrorCode.PROVIDER_REJECTED), _Outcome.NEUTRAL)


def _default_transport() -> httpx.AsyncHTTPTransport:
    """
    TLS verification against the bundled store, no connection retries.

    ``trust_env=False`` here as well as on the client: the transport's own
    flag would let ``SSL_CERT_FILE``/``SSL_CERT_DIR`` replace the trust store.
    """
    return httpx.AsyncHTTPTransport(
        verify=True,
        trust_env=False,
        retries=0,
        limits=httpx.Limits(
            max_connections=MAX_CONNECTIONS,
            max_keepalive_connections=MAX_CONNECTIONS,
        ),
    )


class ProviderHttpClient:
    """The D-20 client of one provider call; use as an async context manager."""

    def __init__(
        self,
        endpoint: ProviderEndpoint,
        *,
        policy: DestinationPolicy,
        limits: ClientLimits,
        breaker: CircuitBreaker,
        resolver: Resolver = default_resolver,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            self._target: ProviderTarget = parse_target(
                endpoint.base_url, endpoint.boundary
            )
        except DestinationError:
            raise refused_before_send(AiErrorCode.PROVIDER_UNREACHABLE) from None
        self._endpoint = endpoint
        self._policy = policy
        self._limits = limits
        self._breaker = breaker
        self._resolver = resolver
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(limits.timeout_seconds),
            transport=transport or _default_transport(),
            event_hooks={"request": [self._guard]},
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        )

    @property
    def endpoint(self) -> ProviderEndpoint:
        """The provider this client talks to, and nothing else."""
        return self._endpoint

    async def __aenter__(self) -> ProviderHttpClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close every connection of this call."""
        await self._client.aclose()

    async def _guard(self, request: httpx.Request) -> None:
        """The ``T19`` call-time pass, for every request this client sends."""
        url = request.url
        target = self._target
        port = url.port or (443 if url.scheme == "https" else 80)
        host = url.raw_host.decode("ascii").lower()
        if (url.scheme, host, port) != (target.scheme, target.host, target.port):
            raise _GuardRefused()
        try:
            await asyncio.to_thread(
                check_resolved,
                self._endpoint.base_url,
                self._endpoint.boundary,
                self._policy,
                self._resolver,
            )
        except DestinationError:
            raise _GuardRefused() from None

    def _url(self, path: str) -> str:
        if not _ROUTE.fullmatch(path) or "/../" in f"{path}/" or "/./" in f"{path}/":
            raise refused_before_send(AiErrorCode.PROVIDER_REJECTED)
        return f"{self._target.origin()}{self._target.path}{path}"

    def _build(
        self,
        method: Method,
        path: str,
        deadline: Deadline,
        json_body: Mapping[str, object] | None,
        query: Mapping[str, str] | None,
        secret: ResolvedSecret | None,
        progress: DispatchProgress | None,
    ) -> httpx.Request:
        """The request, with every refusal that needs no I/O already made."""
        headers = {
            "Accept": "application/json",
            **credential_headers(self._endpoint, secret),
        }
        content = None
        if json_body is not None:
            content = encode_json_body(json_body, self._limits.max_request_bytes)
            headers["Content-Type"] = "application/json"
        return self._client.build_request(
            method,
            self._url(path),
            params=dict(query) if query else None,
            content=content,
            headers=headers,
            extensions={"trace": _trace(progress, deadline)},
        )

    async def request(
        self,
        method: Method,
        path: str,
        *,
        deadline: Deadline,
        json_body: Mapping[str, object] | None = None,
        query: Mapping[str, str] | None = None,
        secret: ResolvedSecret | None = None,
        progress: DispatchProgress | None = None,
        accept: frozenset[int] = frozenset(),
    ) -> ProviderAnswer:
        """
        Send one request to this provider; its answer, or a closed failure.

        ``path`` is built by :func:`route` from a fixed template and ``query``
        holds fixed, adapter-chosen parameters, never caller input. ``secret``
        travels only in its header; ``progress`` is recorded before the first
        byte; ``accept`` lists non-2xx statuses returned to the adapter with
        the body discarded instead of failing — a ``404`` that is evidence
        only. A 2xx answer comes back with its parsed JSON body.
        """
        request = self._build(
            method, path, deadline, json_body, query, secret, progress
        )
        if not self._breaker.allow():
            raise refused_before_send(AiErrorCode.BREAKER_OPEN)
        try:
            answer = await self._timed(request, deadline, progress, accept)
        except _Classified as classified:
            self._feed(classified.outcome)
            raise classified.failure from None
        except BaseException:
            self._breaker.neutral()
            raise
        self._breaker.success()
        return answer

    def _feed(self, outcome: _Outcome) -> None:
        if outcome is _Outcome.SUCCESS:
            self._breaker.success()
        elif outcome is _Outcome.FAILURE:
            self._breaker.failure()
        else:
            self._breaker.neutral()

    async def _timed(
        self,
        request: httpx.Request,
        deadline: Deadline,
        progress: DispatchProgress | None,
        accept: frozenset[int],
    ) -> ProviderAnswer:
        try:
            deadline.require()
        except ProviderFailure as failure:
            raise _Classified(failure, _Outcome.NEUTRAL) from None
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout_at(loop.time() + deadline.remaining()):
                return await self._exchange(request, progress, accept)
        except TimeoutError:
            raise _Classified(
                ProviderFailure(AiErrorCode.TIMEOUT), _Outcome.FAILURE
            ) from None

    async def _exchange(
        self,
        request: httpx.Request,
        progress: DispatchProgress | None,
        accept: frozenset[int],
    ) -> ProviderAnswer:
        try:
            response = await self._client.send(request, stream=True)
        except (ProviderFailure, _GuardRefused, httpx.HTTPError) as exc:
            raise _transport_failure(exc) from None
        try:
            if progress is not None:
                # A transport that emits no trace has still sent the request.
                await _record(progress)
            return await self._answer(response, accept)
        except (ProviderFailure, httpx.HTTPError) as exc:
            raise _transport_failure(exc) from None
        finally:
            await response.aclose()

    async def _answer(
        self, response: httpx.Response, accept: frozenset[int]
    ) -> ProviderAnswer:
        status = response.status_code
        if 200 <= status < 300:
            body = BoundedBody(
                response.headers.get("content-encoding"),
                self._limits.max_response_bytes,
            )
            try:
                async for chunk in response.aiter_raw():
                    body.feed(chunk)
                parsed = parse_json(body.finish())
            except ProviderFailure as failure:
                raise _Classified(failure, _Outcome.SUCCESS) from None
            return ProviderAnswer(status, parsed)
        if status in accept:
            return ProviderAnswer(status, None)
        raise _status_failure(response, self._limits.max_backoff_seconds)


@dataclass(frozen=True)
class ClientFactory:
    """Builds the client of each provider call with the process's settings."""

    policy: DestinationPolicy
    limits: ClientLimits
    breakers: Breakers
    resolver: Resolver = default_resolver
    transport: Callable[[ProviderEndpoint], httpx.AsyncBaseTransport] | None = None

    def client(self, endpoint: ProviderEndpoint) -> ProviderHttpClient:
        """A new client for one call to ``endpoint``."""
        return ProviderHttpClient(
            endpoint,
            policy=self.policy,
            limits=self.limits,
            breaker=self.breakers.for_provider(endpoint.provider_id),
            resolver=self.resolver,
            transport=None if self.transport is None else self.transport(endpoint),
        )


__all__ = [
    "MAX_RESPONSE_JSON_DEPTH",
    "BoundedBody",
    "ClientFactory",
    "ClientLimits",
    "Deadline",
    "DispatchProgress",
    "ProviderAnswer",
    "ProviderEndpoint",
    "ProviderHttpClient",
    "credential_headers",
    "encode_json_body",
    "json_depth",
    "parse_json",
    "route",
]

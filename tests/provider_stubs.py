"""
Provider stubs for the client and adapter tests.

Two kinds:

* :func:`mock_client` — the real :class:`ProviderHttpClient` over an
  in-process ``httpx.MockTransport``;
* :class:`StubServer` with :func:`socket_transport` — a real HTTP/1.1 (or
  TLS) server on ``127.0.0.1``, reached through httpcore's real connection
  pool. Every TCP connection is remapped to the stub, whatever host the
  request names: the destination guard sees the endpoint's host and the
  resolver's answer (a public address), while the bytes go to the stub —
  which is also what a DNS answer that changes between the guard's check
  and the connection looks like.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import tempfile
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpcore
import httpx
from ai_sdk_m8.schemas import ProviderBoundary
from ai_sdk_m8.schemas.management import AuthType, ProviderType
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ai_gateway.core.ssrf import DestinationPolicy
from ai_gateway.providers.breaker import CircuitBreaker
from ai_gateway.providers.http import ClientLimits, ProviderEndpoint, ProviderHttpClient

#: A globally routable answer for every external host.
PUBLIC_IP = "93.184.216.34"

POLICY = DestinationPolicy(
    production=False,
    internal_hosts=frozenset({("ollama", 11434), ("models.local", 8080)}),
    external_ports=frozenset({80, 443}),
)

LIMITS = ClientLimits(
    timeout_seconds=5.0,
    max_request_bytes=64 * 1024,
    max_response_bytes=64 * 1024,
    max_backoff_seconds=300,
)

HOST = "api.provider.test"


def endpoint(
    base_url: str = f"https://{HOST}",
    *,
    auth_type: AuthType = AuthType.BEARER,
    auth_header_name: str | None = None,
    boundary: ProviderBoundary = ProviderBoundary.EXTERNAL,
    provider_type: ProviderType = ProviderType.OPENAI_COMPATIBLE,
) -> ProviderEndpoint:
    """A provider endpoint with a fresh id."""
    return ProviderEndpoint(
        provider_id=uuid4(),
        provider_type=provider_type,
        base_url=base_url,
        boundary=boundary,
        auth_type=auth_type,
        auth_header_name=auth_header_name,
    )


class Resolver:
    """A resolver answering ``answers`` and counting lookups."""

    def __init__(self, answers: Iterable[str] = (PUBLIC_IP,)) -> None:
        self.answers = list(answers)
        self.lookups: list[str] = []

    def __call__(self, host: str) -> list[str]:
        self.lookups.append(host)
        return list(self.answers)


class Progress:
    """A ``DispatchProgress`` double: idempotent like the real one, counted."""

    def __init__(self, *, fail: BaseException | None = None) -> None:
        self.calls = 0
        self.recorded = False
        self._fail = fail

    async def first_byte_sent(self) -> None:
        self.calls += 1
        if self._fail is not None:
            raise self._fail
        self.recorded = True


Handler = Callable[[httpx.Request], Awaitable[httpx.Response]]


def mock_client(
    handler: Handler,
    *,
    target: ProviderEndpoint | None = None,
    breaker: CircuitBreaker | None = None,
    resolver: Callable[[str], list[str]] | None = None,
    limits: ClientLimits = LIMITS,
) -> ProviderHttpClient:
    """The real client over an in-process transport."""
    return ProviderHttpClient(
        target or endpoint(),
        policy=POLICY,
        limits=limits,
        breaker=breaker or CircuitBreaker(),
        resolver=resolver or Resolver(),
        transport=httpx.MockTransport(handler),
    )


# --- real sockets ---------------------------------------------------------------


@dataclass
class Reply:
    """What the stub server sends back."""

    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    chunks: list[bytes] = field(default_factory=lambda: [b"{}"])
    delay: float = 0.0
    content_length: int | None = None
    #: Close the connection without answering (a lost response).
    drop: bool = False


@dataclass
class Received:
    """One request as the stub read it off the wire."""

    head: bytes
    body: bytes

    @property
    def request_line(self) -> str:
        return self.head.split(b"\r\n", 1)[0].decode("latin-1")

    def header(self, name: str) -> str | None:
        for line in self.head.split(b"\r\n")[1:]:
            key, _, value = line.decode("latin-1").partition(":")
            if key.strip().lower() == name.lower():
                return value.strip()
        return None


class StubServer:
    """An HTTP/1.1 server on ``127.0.0.1`` answering one scripted reply per request."""

    def __init__(
        self,
        reply: Reply | Callable[[Received], Reply],
        *,
        ssl_context: ssl.SSLContext | None = None,
        on_request: Callable[[Received], None] | None = None,
    ) -> None:
        self._reply = reply
        self._ssl = ssl_context
        self._on_request = on_request
        self.requests: list[Received] = []
        self.port = 0
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()

    async def __aenter__(self) -> StubServer:
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self._ssl
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        # A client may leave a connection open (a cancelled handshake): end
        # every handler rather than wait for its peer.
        for handler in list(self._handlers):
            handler.cancel()
        await asyncio.gather(*self._handlers, return_exceptions=True)
        await self._server.wait_closed()

    async def _read(self, reader: asyncio.StreamReader) -> Received:
        head = await reader.readuntil(b"\r\n\r\n")
        received = Received(head, b"")
        length = received.header("content-length")
        if length:
            received.body = await reader.readexactly(int(length))
        return received

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._handlers.add(task)
        try:
            while True:
                received = await self._read(reader)
                self.requests.append(received)
                if self._on_request is not None:
                    self._on_request(received)
                reply = self._reply(received) if callable(self._reply) else self._reply
                await self._send(writer, reply)
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            self._handlers.discard(task)
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError, asyncio.CancelledError):
                await writer.wait_closed()

    async def _send(self, writer: asyncio.StreamWriter, reply: Reply) -> None:
        if reply.drop:
            writer.transport.abort()
            raise ConnectionAbortedError("the stub dropped the response")
        length = reply.content_length
        if length is None:
            length = sum(len(chunk) for chunk in reply.chunks)
        lines = [f"HTTP/1.1 {reply.status} Stub", f"Content-Length: {length}"]
        lines += [f"{name}: {value}" for name, value in reply.headers]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await writer.drain()
        for chunk in reply.chunks:
            writer.write(chunk)
            await writer.drain()
            if reply.delay:
                await asyncio.sleep(reply.delay)


class RemapNetwork(httpcore.AsyncNetworkBackend):
    """Connect every TCP request to ``127.0.0.1:port``, recording the asked target."""

    def __init__(self, port: int) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._port = port
        self.connects: list[tuple[str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connects.append((host, port))
        return await self._inner.connect_tcp(
            "127.0.0.1",
            self._port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def socket_transport(
    port: int, *, ssl_context: ssl.SSLContext | None = None
) -> tuple[httpx.AsyncHTTPTransport, RemapNetwork]:
    """httpx's real transport and pool, connected to the stub on ``port``."""
    network = RemapNetwork(port)
    transport = httpx.AsyncHTTPTransport(retries=0, trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context, network_backend=network, retries=0
    )
    return transport, network


def closed_port() -> int:
    """A local port nothing listens on."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# --- a throwaway PKI ------------------------------------------------------------

_PKI_DIR = Path(tempfile.mkdtemp(prefix="ai-gateway-test-pki-"))


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _validity(builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
    now = datetime.now(UTC)
    return builder.not_valid_before(now - timedelta(minutes=5)).not_valid_after(
        now + timedelta(days=1)
    )


class TestPki:
    """A CA and leaf certificates for TLS stubs (never a real trust anchor)."""

    __test__ = False

    def __init__(self, name: str = "ai-gateway test CA") -> None:
        self._key = _key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        public = self._key.public_key()
        self.cert = (
            _validity(x509.CertificateBuilder())
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), False)
            .sign(self._key, hashes.SHA256())
        )

    def server_context(self, hostname: str) -> ssl.SSLContext:
        """A server context presenting a leaf for ``hostname`` signed by this CA."""
        key = _key()
        leaf = (
            _validity(x509.CertificateBuilder())
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            )
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._key.public_key()
                ),
                False,
            )
            .sign(self._key, hashes.SHA256())
        )
        stem = _PKI_DIR / uuid4().hex
        cert_file, key_file = stem.with_suffix(".crt"), stem.with_suffix(".key")
        cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        return context

    def client_context(self) -> ssl.SSLContext:
        """A verifying client context that trusts this CA only."""
        pem = self.cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        return ssl.create_default_context(cadata=pem)


__all__ = [
    "HOST",
    "LIMITS",
    "POLICY",
    "PUBLIC_IP",
    "Progress",
    "Received",
    "RemapNetwork",
    "Reply",
    "Resolver",
    "StubServer",
    "TestPki",
    "closed_port",
    "endpoint",
    "mock_client",
    "socket_transport",
]

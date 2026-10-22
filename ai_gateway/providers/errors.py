"""
Closed provider failures (D-41).

A provider call that does not produce a usable answer raises one
:class:`ProviderFailure`. It carries only typed facts: a closed
:class:`~ai_sdk_m8.schemas.AiErrorCode`, the provider's HTTP status class,
a bounded ``Retry-After``, adapter-chosen metadata from the closed
``provider_metadata`` shape, and whether the transport guarantees that no
request byte left the process. It never carries a provider body, header,
URL, query or exception text: its ``str`` is the code alone and it chains no
cause, so nothing a provider sent reaches a response, an audit row, a log
line or a trace through it.

``before_send`` is the D-24 refund fact. It is true only when the failure is
established before any request byte could have been written: the
destination guard or the breaker refused, the credential could not be put
in a header, the body exceeded its cap, or the transport failed to connect
(``httpx.ConnectError``, ``httpx.ConnectTimeout``, a TLS handshake failure).

An ``incident`` marks an answer that contradicts the registered model — an
embedding of another dimension — which settlement also writes to the admin
audit trail.
Everything after that point — a timeout, a protocol error, a provider
answer of any kind — is not a refund, whatever its code.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from ai_sdk_m8.schemas import AiErrorCode
from ai_sdk_m8.schemas.errors import ProviderMetadata, ProviderStatusClass
from pydantic import TypeAdapter

from ai_gateway.core.errors import GatewayError

_METADATA: TypeAdapter[ProviderMetadata] = TypeAdapter(ProviderMetadata)


def class_of(status: int) -> ProviderStatusClass:
    """The status class of an HTTP ``status`` (``1xx`` counts as ``2xx``)."""
    if status >= 500:
        return ProviderStatusClass.SERVER_ERROR
    if status >= 400:
        return ProviderStatusClass.CLIENT_ERROR
    if status >= 300:
        return ProviderStatusClass.REDIRECT
    return ProviderStatusClass.SUCCESS


class Incident(StrEnum):
    """A provider answer that contradicts the registered model (audited)."""

    DIMENSION_MISMATCH = "dimension_mismatch"


class ProviderFailure(Exception):
    """A provider call failed; only closed, typed facts travel with it."""

    def __init__(
        self,
        code: AiErrorCode,
        *,
        status_class: ProviderStatusClass | None = None,
        retry_after_seconds: int | None = None,
        before_send: bool = False,
        auth_failure: bool = False,
        metadata: Mapping[str, object] | None = None,
        incident: Incident | None = None,
    ) -> None:
        self.code = code
        self.incident = incident
        self.status_class = status_class
        self.retry_after_seconds = retry_after_seconds
        self.before_send = before_send
        self.auth_failure = auth_failure
        # Validated against the closed AiError shape: scalars, depth <= 2,
        # <= 32 items, <= 4 KiB; never free text from a provider.
        self.metadata = (
            None if metadata is None else _METADATA.validate_python(metadata)
        )
        super().__init__(code.value)

    def __repr__(self) -> str:
        return f"ProviderFailure({self.code.value})"

    @property
    def throttled(self) -> bool:
        """A provider 429: settlement sets the credential's cooldown (D-20)."""
        return self.code is AiErrorCode.RATE_LIMITED


def refused_before_send(code: AiErrorCode) -> ProviderFailure:
    """A failure established before any request byte could be written."""
    return ProviderFailure(code, before_send=True)


def gateway_error(failure: ProviderFailure) -> GatewayError:
    """The public ``AiError`` refusal of ``failure``: its typed fields only."""
    return GatewayError(
        failure.code,
        retry_after_seconds=failure.retry_after_seconds,
        provider_status_class=failure.status_class,
        provider_metadata=failure.metadata,
    )


__all__ = [
    "Incident",
    "ProviderFailure",
    "class_of",
    "gateway_error",
    "refused_before_send",
]

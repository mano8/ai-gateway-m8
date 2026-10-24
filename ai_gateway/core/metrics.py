"""
The gateway's Prometheus collectors (C-13), declared in one place.

Every label is a member of a closed vocabulary — a capability, a provider
type, a stored status, an error code, a backend, a scope type, a table name.
No collector is ever labelled with a user, tenant, client, filename, query,
model input or key material (S-11), and :func:`label_allowlist` is the
single list ``tests/test_metrics.py`` holds the whole registry to: a new
collector or label that is not named there fails the build.

Three collectors predate this module and live beside the code that feeds
them: ``ai_job_contexts_total`` (:mod:`~ai_gateway.core.job_context`),
``ai_reservations_settled_total`` (:mod:`~ai_gateway.execution.settlement`)
and ``ai_remote_artifacts`` (:mod:`~ai_gateway.execution.artifacts`).
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge, Histogram

from ai_gateway.providers.breaker import BreakerState

REQUESTS: Final = Counter(
    "ai_requests",
    "Execution requests by capability, provider type and outcome",
    ["capability", "provider_type", "status"],
)
REQUEST_SECONDS: Final = Histogram(
    "ai_request_duration_seconds",
    "Execution request duration",
    ["capability", "provider_type"],
)
PROVIDER_ERRORS: Final = Counter(
    "ai_provider_errors",
    "Provider failures by closed reason",
    ["provider_type", "reason"],
)
OCR_PAGES: Final = Counter("ai_ocr_pages", "Pages the provider reported processing")
EMBEDDING_INPUTS: Final = Counter("ai_embedding_inputs", "Inputs embedded")
TOKENS: Final = Counter(
    "ai_tokens", "Provider-reported tokens (recorded, not bounded)", ["direction"]
)
CREDENTIAL_RESOLUTION: Final = Counter(
    "ai_credential_resolution",
    "Credential material fetches for an execution",
    ["backend", "status"],
)
QUOTA_REJECTIONS: Final = Counter(
    "ai_quota_rejections", "Daily-budget refusals", ["scope_type"]
)
BREAKER_STATE: Final = Gauge(
    "ai_breaker_state",
    "Last observed breaker state (0 closed, 1 half-open, 2 open)",
    ["provider_type"],
)
CREDENTIAL_THROTTLED: Final = Counter(
    "ai_credential_throttled", "Provider 429s that set a cooldown", ["provider_type"]
)
AUDIT_TABLE_BYTES: Final = Gauge(
    "ai_audit_table_bytes", "Total relation size of an audit table", ["table"]
)
SCHEDULER_LEASE_EPOCH: Final = Gauge(
    "ai_scheduler_lease_epoch", "Epoch of the scheduler lease this process saw"
)

_BREAKER_LEVEL: Final = {
    BreakerState.CLOSED: 0,
    BreakerState.HALF_OPEN: 1,
    BreakerState.OPEN: 2,
}


def publish_breaker(provider_type: str, state: BreakerState) -> None:
    """Record ``state`` as the last one observed for ``provider_type``."""
    BREAKER_STATE.labels(provider_type=provider_type).set(_BREAKER_LEVEL[state])


def label_allowlist() -> dict[str, frozenset[str]]:
    """Every ``ai_`` metric family and the only labels it may carry."""
    return {
        "ai_requests": frozenset({"capability", "provider_type", "status"}),
        "ai_request_duration_seconds": frozenset({"capability", "provider_type"}),
        "ai_provider_errors": frozenset({"provider_type", "reason"}),
        "ai_ocr_pages": frozenset(),
        "ai_embedding_inputs": frozenset(),
        "ai_tokens": frozenset({"direction"}),
        "ai_credential_resolution": frozenset({"backend", "status"}),
        "ai_job_contexts": frozenset({"event"}),
        "ai_quota_rejections": frozenset({"scope_type"}),
        "ai_breaker_state": frozenset({"provider_type"}),
        "ai_remote_artifacts": frozenset({"status"}),
        "ai_credential_throttled": frozenset({"provider_type"}),
        "ai_audit_table_bytes": frozenset({"table"}),
        "ai_scheduler_lease_epoch": frozenset(),
        "ai_reservations_settled": frozenset({"outcome"}),
    }

"""
Remote provider artifacts (D-43): the handler's transitions and the scheduler's.

A provider-side temporary file is durable state from **before** its first
upload byte. Every transition is a compare-and-set on the stored status (the
T16 trigger refuses any other), "closed" means the row is deleted — which
alone releases the credential-version foreign key — and every scheduler
transition can carry the scheduler's fence (``T33a``); the jobs that reach a
provider per row also take a per-item claim (:class:`ItemClaim`, D-42).

**Handler** (:class:`ExecutionArtifacts`): (a) ``∅ → uploading`` committed
together with ``first_byte_sent_at`` immediately before the upload's first
byte, ``upload_deadline_at`` = the execution's stored deadline; (b)
``uploading → active`` when the id comes back, before it is used — or (d)
``uploading_unknown_id → pending_delete`` when a scheduler moved the row
first; (c) ``uploading → uploading_unknown_id`` on a lost answer; (g) ``active
→ pending_delete`` in the adapter's ``finally``; (h) closed on the
provider's deletion proof for the recorded id.

**Scheduler** (:class:`ArtifactScheduler`): (c) aged ``uploading`` rows; (g)
``active`` rows of terminal executions or past their deadline plus the
visibility grace — never a file a call may still read; (h)/(i) deletion with
retries and backoff until a proof, then ``manual_cleanup_required`` after
``AI_REMOTE_ARTIFACT_MAX_DELETE_ATTEMPTS`` or
``AI_REMOTE_ARTIFACT_MAX_PENDING_HOURS``; (d)/(e)/(f) incident listings for
``uploading_unknown_id`` rows — under a platform credential when
``AI_REMOTE_ARTIFACT_PLATFORM_INCIDENT_LISTING`` permits, under a tenant's or
a user's only with its ``incident_listing_consent``, otherwise
``listing_not_permitted`` once the grace passed; (j) a later proof for a
parked row, re-attempted after ``provider_expires_at`` and then daily, or the
audited ``accept-residual``; (k) late discovery of an ``absence_unproven``
file; the periodic sweep of platform credentials only (no safe server-side
filter is documented), deleting an untracked file of this deployment's
prefix once older than the total deadline plus the grace.

Cleanup uses the **recorded** credential version only (``resolve_for_cleanup``)
against the frozen endpoint, whatever the provider's, model's or
credential's state. A ``404``, a negative listing or a passed
``provider_expires_at`` is never a proof.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Final, Protocol
from uuid import UUID

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import (
    CredentialStatus,
    ProviderType,
    RemoteArtifactStatus,
    ScopeType,
)
from prometheus_client import Gauge
from sqlalchemy import Engine, RowMapping

from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.core.errors import GatewayError
from ai_gateway.credentials.obligations import note_upload_deadline
from ai_gateway.credentials.store import CredentialStore, ResolvedSecret
from ai_gateway.db_models._common import TERMINAL_STATUSES, ExecutionStatus
from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import ai_provider
from ai_gateway.providers.base import OcrAdapter, ProviderAdapter
from ai_gateway.providers.errors import ProviderFailure
from ai_gateway.providers.http import (
    ClientFactory,
    Deadline,
    DispatchProgress,
    ProviderEndpoint,
)

logger = logging.getLogger(__name__)

_A = ai_provider_remote_artifact
_E = ai_execution
_S = RemoteArtifactStatus

#: Rows one scheduler pass handles per job.
BATCH: Final = 50

#: Deletion backoff: 30 s doubling, at most an hour; a parked row daily.
BACKOFF_BASE_SECONDS: Final = 30
BACKOFF_MAX_SECONDS: Final = 3600
PARKED_RETRY: Final = timedelta(days=1)

#: The wait between two incident listings of one unresolved upload.
RELIST: Final = timedelta(seconds=BACKOFF_BASE_SECONDS)

#: ``ai_remote_artifacts{status}`` (C-13); an alert watches the manual status.
REMOTE_ARTIFACTS = Gauge(
    "ai_remote_artifacts", "Provider-side temporary files by status", ["status"]
)


def file_name(deployment_id: str, execution_id: UUID) -> str:
    """The only name a provider ever sees: ``m8ai-<deployment>-<execution>``."""
    return f"m8ai-{deployment_id}-{execution_id}"


def file_prefix(deployment_id: str) -> str:
    """The prefix every file of this installation carries."""
    return f"m8ai-{deployment_id}-"


def _epoch(value: int | None) -> datetime | None:
    return None if value is None else datetime.fromtimestamp(value, UTC)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _cas(
    engine: Engine,
    artifact_id: UUID,
    expected: _S,
    fence: sa.ColumnElement[bool] | None = None,
    **values: object,
) -> bool:
    where = sa.and_(_A.c.id == artifact_id, _A.c.status == expected.value)
    if fence is not None:
        where = sa.and_(where, fence)
    with engine.begin() as connection:
        row = connection.execute(
            sa.update(_A).where(where).values(**values).returning(_A.c.id)
        ).first()
    return row is not None


def _close(
    engine: Engine,
    artifact_id: UUID,
    expected: _S,
    fence: sa.ColumnElement[bool] | None = None,
) -> bool:
    where = sa.and_(_A.c.id == artifact_id, _A.c.status == expected.value)
    if fence is not None:
        where = sa.and_(where, fence)
    with engine.begin() as connection:
        row = connection.execute(sa.delete(_A).where(where).returning(_A.c.id)).first()
    return row is not None


def _park(
    engine: Engine,
    artifact_id: UUID,
    expected: _S,
    reason: str,
    fence: sa.ColumnElement[bool] | None = None,
) -> bool:
    """Move a row to ``manual_cleanup_required``; every entry is alerted."""
    parked = _cas(
        engine,
        artifact_id,
        expected,
        fence,
        status=_S.MANUAL_CLEANUP_REQUIRED.value,
        status_reason=reason,
        next_attempt_at=sa.func.now(),
    )
    if parked:
        logger.warning(
            "remote_artifact.manual_cleanup_required artifact_id=%s reason=%s",
            artifact_id,
            reason,
        )
    return parked


# --- the handler's transitions -------------------------------------------------------


def record_intent(
    engine: Engine,
    *,
    artifact_id: UUID,
    execution_id: UUID,
    provider_id: UUID,
    credential_id: UUID,
    credential_version: int,
    gateway_file_name: str,
) -> bool:
    """
    (a) The upload intent and ``first_byte_sent_at``, in one transaction.

    Only while the execution is ``dispatching`` inside its stored deadline;
    ``False`` otherwise, and no byte may follow.
    """
    with engine.begin() as connection:
        execution = connection.execute(
            sa.update(_E)
            .where(
                _E.c.id == execution_id,
                _E.c.status == ExecutionStatus.DISPATCHING.value,
                _E.c.dispatch_deadline_at > sa.func.now(),
            )
            .values(
                first_byte_sent_at=sa.func.coalesce(
                    _E.c.first_byte_sent_at, sa.func.now()
                ),
                updated_at=sa.func.now(),
            )
            .returning(_E.c.dispatch_deadline_at)
        ).first()
        if execution is None:
            return False
        deadline = execution[0]
        connection.execute(
            sa.insert(_A).values(
                id=artifact_id,
                execution_id=execution_id,
                provider_id=provider_id,
                credential_id=credential_id,
                credential_version=credential_version,
                gateway_file_name=gateway_file_name,
                status=_S.UPLOADING.value,
                upload_deadline_at=deadline,
            )
        )
        note_upload_deadline(connection, credential_id, credential_version, deadline)
    return True


class Recorder(Protocol):
    """The execution's progress: commits a transaction that records the byte."""

    async def record_with(
        self, record: Callable[[], bool], *, once: bool = False
    ) -> None:
        """Commit ``record``; ``timeout`` when it matched no sendable row."""


class _IntentProgress:
    """A request's progress whose first byte commits the upload intent."""

    def __init__(self, artifacts: ExecutionArtifacts) -> None:
        self._artifacts = artifacts

    async def first_byte_sent(self) -> None:
        await self._artifacts.intent()


class ExecutionArtifacts:
    """The D-43 handler transitions of one execution's upload."""

    def __init__(
        self,
        engine: Engine,
        progress: Recorder,
        *,
        execution_id: UUID,
        provider_id: UUID,
        credential_id: UUID,
        credential_version: int,
        deployment_id: str,
    ) -> None:
        self._engine = engine
        self._progress = progress
        self._execution_id = execution_id
        self._provider_id = provider_id
        self._credential_id = credential_id
        self._version = credential_version
        self._artifact_id: UUID | None = None
        self._lock = asyncio.Lock()
        self.gateway_file_name = file_name(deployment_id, execution_id)

    @property
    def intended(self) -> bool:
        """Whether the intent row exists (bytes may have left)."""
        return self._artifact_id is not None

    @property
    def artifact_id(self) -> UUID | None:
        """The intent row's id, once committed."""
        return self._artifact_id

    def intent_progress(self) -> DispatchProgress:
        """Progress whose first byte also commits the upload intent (a)."""
        return _IntentProgress(self)

    async def intent(self) -> None:
        """(a), once; a row that can no longer send gets no byte (``timeout``)."""
        async with self._lock:
            if self._artifact_id is not None:
                return
            artifact_id = uuid.uuid4()
            await self._progress.record_with(
                partial(
                    record_intent,
                    self._engine,
                    artifact_id=artifact_id,
                    execution_id=self._execution_id,
                    provider_id=self._provider_id,
                    credential_id=self._credential_id,
                    credential_version=self._version,
                    gateway_file_name=self.gateway_file_name,
                )
            )
            self._artifact_id = artifact_id

    def _id(self) -> UUID:
        assert self._artifact_id is not None  # nosec B101 - after intent()
        return self._artifact_id

    async def activate(self, remote_id: str, expires_at: int | None) -> bool:
        """(b) ``uploading → active``; or (d) when a scheduler moved it first."""
        values = {
            "remote_artifact_id": remote_id,
            "provider_expires_at": _epoch(expires_at),
        }
        if await asyncio.to_thread(
            _cas,
            self._engine,
            self._id(),
            _S.UPLOADING,
            None,
            status=_S.ACTIVE.value,
            **values,
        ):
            return True
        await asyncio.to_thread(
            _cas,
            self._engine,
            self._id(),
            _S.UPLOADING_UNKNOWN_ID,
            None,
            status=_S.PENDING_DELETE.value,
            next_attempt_at=sa.func.now(),
            **values,
        )
        return False

    async def lost(self) -> None:
        """(c) the id never came back: the scheduler's listings own the row."""
        await asyncio.to_thread(
            _cas,
            self._engine,
            self._id(),
            _S.UPLOADING,
            None,
            status=_S.UPLOADING_UNKNOWN_ID.value,
        )

    async def release(self) -> None:
        """(g) ``active → pending_delete``, in the adapter's ``finally``."""
        await asyncio.to_thread(
            _cas,
            self._engine,
            self._id(),
            _S.ACTIVE,
            None,
            status=_S.PENDING_DELETE.value,
            next_attempt_at=sa.func.now(),
        )

    async def deleted(self) -> None:
        """(h) closed on the deletion proof."""
        await asyncio.to_thread(_close, self._engine, self._id(), _S.PENDING_DELETE)


# --- the scheduler's jobs -----------------------------------------------------------


@dataclass(frozen=True)
class ArtifactPolicy:
    """The D-43 settings the scheduler applies."""

    deployment_id: str
    visibility_grace_seconds: int
    negative_listings: int
    max_delete_attempts: int
    max_pending_hours: int
    platform_incident_listing: bool
    platform_sweep_enabled: bool
    total_deadline_seconds: int
    timeout_seconds: float

    @classmethod
    def from_settings(cls, settings: object) -> ArtifactPolicy:
        """From gateway ``Settings``."""

        def get(name: str) -> object:
            return getattr(settings, name)

        return cls(
            deployment_id=str(get("deployment_id")),
            visibility_grace_seconds=int(
                str(get("AI_REMOTE_ARTIFACT_VISIBILITY_GRACE_SECONDS"))
            ),
            negative_listings=int(str(get("AI_REMOTE_ARTIFACT_NEGATIVE_LISTINGS"))),
            max_delete_attempts=int(str(get("AI_REMOTE_ARTIFACT_MAX_DELETE_ATTEMPTS"))),
            max_pending_hours=int(str(get("AI_REMOTE_ARTIFACT_MAX_PENDING_HOURS"))),
            platform_incident_listing=bool(
                get("AI_REMOTE_ARTIFACT_PLATFORM_INCIDENT_LISTING")
            ),
            platform_sweep_enabled=bool(
                get("AI_REMOTE_ARTIFACT_PLATFORM_SWEEP_ENABLED")
            ),
            total_deadline_seconds=int(str(get("AI_PROVIDER_TOTAL_DEADLINE_SECONDS"))),
            timeout_seconds=float(str(get("AI_PROVIDER_TIMEOUT_SECONDS"))),
        )


class ItemClaim(Protocol):
    """The scheduler's per-item claim on a row (D-42; ``scheduler.lease.Lease``)."""

    def claimable(self, table: sa.Table) -> sa.ColumnElement[bool]:
        """No other leader's live claim holds the row, and the lease is live."""

    def claim_values(self) -> dict[str, object]:
        """``claim_epoch``, ``claim_holder_token`` and ``claim_until``."""

    def held(self, table: sa.Table) -> sa.ColumnElement[bool]:
        """This leader's live claim on the row, and the live lease."""


#: A row another leader holds: the pass leaves it alone.
_TAKEN: Final = sa.false()


def backoff(attempts: int, retry_after: int | None = None) -> timedelta:
    """The wait before the next deletion attempt; a 429's cooldown is a floor."""
    seconds = min(BACKOFF_BASE_SECONDS * 2 ** max(0, attempts - 1), BACKOFF_MAX_SECONDS)
    return timedelta(seconds=max(seconds, retry_after or 0))


class ArtifactScheduler:
    """Every scheduler-owned D-43 transition; each returns the ids it moved."""

    def __init__(
        self,
        engine: Engine,
        store: CredentialStore,
        clients: ClientFactory,
        adapters: Mapping[ProviderType, ProviderAdapter],
        policy: ArtifactPolicy,
    ) -> None:
        self._engine = engine
        self._store = store
        self._clients = clients
        self._adapters = adapters
        self._policy = policy

    @property
    def _grace(self) -> timedelta:
        return timedelta(seconds=self._policy.visibility_grace_seconds)

    def _bulk(
        self,
        expected: _S,
        due: sa.ColumnElement[bool],
        fence: sa.ColumnElement[bool] | None,
        **values: object,
    ) -> list[UUID]:
        where = sa.and_(_A.c.status == expected.value, due)
        if fence is not None:
            where = sa.and_(where, fence)
        with self._engine.begin() as connection:
            rows = connection.execute(
                sa.update(_A).where(where).values(**values).returning(_A.c.id)
            )
            return [row[0] for row in rows]

    def expire_uploads(self, fence: sa.ColumnElement[bool] | None = None) -> list[UUID]:
        """(c) ``uploading`` past its deadline plus the grace: no handler can finish it."""
        due = _A.c.upload_deadline_at + self._grace < sa.func.now()
        return self._bulk(
            _S.UPLOADING, due, fence, status=_S.UPLOADING_UNKNOWN_ID.value
        )

    def retire_active(self, fence: sa.ColumnElement[bool] | None = None) -> list[UUID]:
        """(g) ``active`` files no call can still read → ``pending_delete``."""
        terminal = sa.exists().where(
            _E.c.id == _A.c.execution_id,
            _E.c.status.in_([s.value for s in TERMINAL_STATUSES]),
        )
        due = sa.or_(terminal, _A.c.upload_deadline_at + self._grace < sa.func.now())
        return self._bulk(
            _S.ACTIVE,
            due,
            fence,
            status=_S.PENDING_DELETE.value,
            next_attempt_at=sa.func.now(),
        )

    def _claim(
        self,
        row: RowMapping,
        fence: sa.ColumnElement[bool] | None,
        claim: ItemClaim | None,
    ) -> sa.ColumnElement[bool] | None:
        """
        Claim ``row`` before any provider call; the fence its later CASes carry.

        Without a claim the job's own fence is returned unchanged. With one,
        a row another leader holds yields :data:`_TAKEN` and is skipped.
        """
        if claim is None:
            return fence
        if not _cas(
            self._engine,
            row["id"],
            _S(row["status"]),
            claim.claimable(_A),
            **claim.claim_values(),
        ):
            return _TAKEN
        return claim.held(_A)

    # --- reaching the provider under the recorded version -----------------------

    def _rows(self, status: _S) -> list[RowMapping]:
        """The due rows of ``status``, oldest first, one batch."""
        a, c, p = _A, ai_credential, ai_provider
        statement = (
            sa.select(
                a,
                c.c.scope_type,
                c.c.incident_listing_consent,
                p.c.provider_type,
                p.c.base_url,
                p.c.boundary,
                p.c.auth_type,
                p.c.auth_header_name,
            )
            .join(c, c.c.id == a.c.credential_id)
            .join(p, p.c.id == a.c.provider_id)
            .where(
                a.c.status == status.value,
                sa.or_(
                    a.c.next_attempt_at.is_(None), a.c.next_attempt_at <= sa.func.now()
                ),
            )
            .order_by(a.c.created_at)
            .limit(BATCH)
        )
        with self._engine.connect() as connection:
            return list(connection.execute(statement).mappings())

    def _adapter(self, row: RowMapping) -> OcrAdapter | None:
        adapter = self._adapters.get(ProviderType(row["provider_type"]))
        return adapter if hasattr(adapter, "delete_file") else None  # type: ignore[return-value]

    def _endpoint(self, row: RowMapping) -> ProviderEndpoint:
        return ProviderEndpoint.from_row({**row, "id": row["provider_id"]})

    def _secret(
        self, stack: ExitStack, credential_id: UUID, version: int
    ) -> ResolvedSecret:
        return stack.enter_context(
            self._store.resolve_for_cleanup(credential_id, version)
        )

    async def _delete(self, row: RowMapping, adapter: OcrAdapter) -> bool:
        """One deletion attempt under the recorded version; ``True`` on proof."""
        with ExitStack() as stack:
            secret = await asyncio.to_thread(
                self._secret, stack, row["credential_id"], row["credential_version"]
            )
            async with self._clients.client(self._endpoint(row)) as client:
                return await adapter.delete_file(
                    client,
                    secret,
                    Deadline.after(self._policy.timeout_seconds),
                    row["remote_artifact_id"],
                )

    async def _list(
        self, row: RowMapping, adapter: OcrAdapter, name: str
    ) -> tuple[list[str], bool]:
        """The remote ids filed under ``name``, and whether the listing completed."""
        with ExitStack() as stack:
            secret = await asyncio.to_thread(
                self._secret, stack, row["credential_id"], row["credential_version"]
            )
            async with self._clients.client(self._endpoint(row)) as client:
                listing = await adapter.list_files(
                    client, secret, Deadline.after(self._policy.timeout_seconds), name
                )
        ids = [f.remote_id for f in listing.files if f.file_name == name]
        return ids, listing.complete

    # --- (h)/(i) deletion -------------------------------------------------------------

    def _exhausted(self, row: RowMapping) -> str | None:
        if row["delete_attempts"] >= self._policy.max_delete_attempts:
            return "attempts_exhausted"
        age = datetime.now(UTC) - row["created_at"]
        if age > timedelta(hours=self._policy.max_pending_hours):
            return "pending_hours_exceeded"
        return None

    def _retry_later(
        self,
        row: RowMapping,
        error: str,
        retry_after: int | None,
        fence: sa.ColumnElement[bool] | None,
    ) -> None:
        attempts = row["delete_attempts"] + 1
        _cas(
            self._engine,
            row["id"],
            _S(row["status"]),
            fence,
            delete_attempts=attempts,
            next_attempt_at=sa.func.now() + backoff(attempts, retry_after),
            last_error_class=error,
        )

    async def _attempt(
        self, row: RowMapping, fence: sa.ColumnElement[bool] | None
    ) -> bool:
        """Try one deletion; close on proof, else schedule the next attempt."""
        adapter = self._adapter(row)
        if adapter is None:
            self._retry_later(row, "capability_unsupported", None, fence)
            return False
        try:
            proven = await self._delete(row, adapter)
        except ProviderFailure as failure:
            self._retry_later(
                row, failure.code.value, failure.retry_after_seconds, fence
            )
            return False
        except GatewayError as error:
            self._retry_later(row, error.code.value, None, fence)
            return False
        if proven:
            return _close(self._engine, row["id"], _S(row["status"]), fence)
        self._retry_later(row, "deletion_unproven", None, fence)
        return False

    async def delete_pending(
        self,
        fence: sa.ColumnElement[bool] | None = None,
        *,
        claim: ItemClaim | None = None,
    ) -> list[UUID]:
        """(h) delete ``pending_delete`` files until proven; (i) park the exhausted."""
        closed: list[UUID] = []
        for row in self._rows(_S.PENDING_DELETE):
            item = self._claim(row, fence, claim)
            if item is _TAKEN:
                continue
            reason = self._exhausted(row)
            if reason is not None:
                _park(self._engine, row["id"], _S.PENDING_DELETE, reason, item)
                continue
            if await self._attempt(row, item):
                closed.append(row["id"])
        return closed

    # --- (d)/(e)/(f) incident listings ---------------------------------------------

    def _listing_permitted(self, row: RowMapping) -> bool:
        if row["scope_type"] == ScopeType.GLOBAL.value:
            return self._policy.platform_incident_listing
        return bool(row["incident_listing_consent"])

    def _past_grace(self, moment: datetime | None) -> bool:
        return moment is not None and moment + self._grace < datetime.now(UTC)

    async def resolve_unknown(
        self,
        fence: sa.ColumnElement[bool] | None = None,
        *,
        claim: ItemClaim | None = None,
    ) -> list[UUID]:
        """Find, or give up on, the files whose id never came back."""
        moved: list[UUID] = []
        for row in self._rows(_S.UPLOADING_UNKNOWN_ID):
            item = self._claim(row, fence, claim)
            if item is _TAKEN:
                continue
            if await self._resolve_one(row, item):
                moved.append(row["id"])
            else:
                self._later(row, _S.UPLOADING_UNKNOWN_ID, RELIST, item)
        return moved

    def _later(
        self,
        row: RowMapping,
        status: _S,
        wait: timedelta,
        fence: sa.ColumnElement[bool] | None,
    ) -> None:
        """Push an unresolved row back, so no batch is starved by it."""
        _cas(
            self._engine, row["id"], status, fence, next_attempt_at=sa.func.now() + wait
        )

    async def _resolve_one(
        self, row: RowMapping, fence: sa.ColumnElement[bool] | None
    ) -> bool:
        adapter = self._adapter(row)
        if adapter is None or not self._listing_permitted(row):
            if self._past_grace(row["upload_deadline_at"]):
                return _park(
                    self._engine,
                    row["id"],
                    _S.UPLOADING_UNKNOWN_ID,
                    "listing_not_permitted",
                    fence,
                )
            return False
        try:
            ids, complete = await self._list(row, adapter, row["gateway_file_name"])
        except (ProviderFailure, GatewayError):
            return False
        if ids:
            return _cas(
                self._engine,
                row["id"],
                _S.UPLOADING_UNKNOWN_ID,
                fence,
                status=_S.PENDING_DELETE.value,
                remote_artifact_id=ids[0],
                next_attempt_at=sa.func.now(),
            )
        if not complete:
            return False
        return self._negative(row, adapter, fence)

    def _negative(
        self, row: RowMapping, adapter: OcrAdapter, fence: sa.ColumnElement[bool] | None
    ) -> bool:
        """One complete negative listing: evidence only, unless documented as proof."""
        if not self._past_grace(row["upload_deadline_at"]):
            return False  # too early for a listing to count at all
        proofs = adapter.proofs
        if proofs.absence_proof and proofs.list_consistency == "documented_strong":
            return _close(
                self._engine, row["id"], _S.UPLOADING_UNKNOWN_ID, fence
            )  # (e)
        first = row["first_negative_listing_at"] or datetime.now(UTC)
        count = row["negative_listings"] + 1
        if count >= self._policy.negative_listings and self._past_grace(first):
            return _park(
                self._engine,
                row["id"],
                _S.UPLOADING_UNKNOWN_ID,
                "absence_unproven",
                fence,
            )
        _cas(
            self._engine,
            row["id"],
            _S.UPLOADING_UNKNOWN_ID,
            fence,
            negative_listings=count,
            first_negative_listing_at=sa.func.coalesce(
                _A.c.first_negative_listing_at, sa.func.now()
            ),
        )
        return False

    # --- (j)/(k) parked rows ----------------------------------------------------------

    async def revisit_parked(
        self,
        fence: sa.ColumnElement[bool] | None = None,
        *,
        claim: ItemClaim | None = None,
    ) -> list[UUID]:
        """(j) a later proof closes a parked row; (k) a late listing un-parks one."""
        moved: list[UUID] = []
        for row in self._rows(_S.MANUAL_CLEANUP_REQUIRED):
            item = self._claim(row, fence, claim)
            if item is _TAKEN:
                continue
            if await self._revisit(row, item):
                moved.append(row["id"])
            else:
                self._later(row, _S.MANUAL_CLEANUP_REQUIRED, self._wait(row), item)
        return moved

    @staticmethod
    def _wait(row: RowMapping) -> timedelta:
        """Until the provider's own expiry, once; daily after it."""
        expires = row["provider_expires_at"]
        now = datetime.now(UTC)
        if expires is not None and expires > now:
            return expires - now
        return PARKED_RETRY

    async def _revisit(
        self, row: RowMapping, fence: sa.ColumnElement[bool] | None
    ) -> bool:
        adapter = self._adapter(row)
        if adapter is None:
            return False
        if row["status_reason"] == "absence_unproven":
            return await self._rediscover(row, adapter, fence)
        if row["remote_artifact_id"] is None:
            return False  # nothing to name: only accept-residual closes it
        expires = row["provider_expires_at"]
        if expires is not None and expires > datetime.now(UTC):
            return False  # re-attempted once after the provider's own expiry
        try:
            proven = await self._delete(row, adapter)
        except (ProviderFailure, GatewayError):
            return False
        return proven and _close(
            self._engine, row["id"], _S.MANUAL_CLEANUP_REQUIRED, fence
        )

    async def _rediscover(
        self, row: RowMapping, adapter: OcrAdapter, fence: sa.ColumnElement[bool] | None
    ) -> bool:
        if not self._listing_permitted(row):
            return False
        try:
            ids, _complete = await self._list(row, adapter, row["gateway_file_name"])
        except (ProviderFailure, GatewayError):
            return False
        if not ids:
            return False
        return _cas(
            self._engine,
            row["id"],
            _S.MANUAL_CLEANUP_REQUIRED,
            fence,
            status=_S.PENDING_DELETE.value,
            status_reason=None,
            remote_artifact_id=ids[0],
            delete_attempts=0,
            next_attempt_at=sa.func.now(),
        )

    # --- the periodic sweep ---------------------------------------------------------

    def _platform_keys(self) -> list[RowMapping]:
        c, p = ai_credential, ai_provider
        statement = (
            sa.select(
                c.c.id.label("credential_id"),
                c.c.current_version.label("credential_version"),
                c.c.provider_id,
                p.c.provider_type,
                p.c.base_url,
                p.c.boundary,
                p.c.auth_type,
                p.c.auth_header_name,
            )
            .join(p, p.c.id == c.c.provider_id)
            .where(
                c.c.scope_type == ScopeType.GLOBAL.value,
                c.c.status == CredentialStatus.ACTIVE.value,
                c.c.current_version.is_not(None),
            )
        )
        with self._engine.connect() as connection:
            return list(connection.execute(statement).mappings())

    def _tracked(self, names: list[str]) -> set[str]:
        if not names:
            return set()
        with self._engine.connect() as connection:
            rows = connection.execute(
                sa.select(_A.c.gateway_file_name).where(
                    _A.c.gateway_file_name.in_(names)
                )
            )
            return {row[0] for row in rows}

    async def sweep(self) -> list[str]:
        """
        Delete untracked files of this installation's prefix, platform keys only.

        Only when ``AI_REMOTE_ARTIFACT_PLATFORM_SWEEP_ENABLED``; never over a
        tenant's or a user's account (no safe server-side filter is
        documented). A file younger than the total deadline plus the grace
        may still be an upload in flight and is left alone.
        """
        if not self._policy.platform_sweep_enabled:
            return []
        deleted: list[str] = []
        cutoff = datetime.now(UTC) - timedelta(
            seconds=self._policy.total_deadline_seconds
            + self._policy.visibility_grace_seconds
        )
        for key in self._platform_keys():
            adapter = self._adapter(key)
            if adapter is None:
                continue
            deleted += await self._sweep_key(key, adapter, cutoff)
        return deleted

    async def _sweep_key(
        self, key: RowMapping, adapter: OcrAdapter, cutoff: datetime
    ) -> list[str]:
        prefix = file_prefix(self._policy.deployment_id)
        deleted: list[str] = []
        try:
            with ExitStack() as stack:
                secret = await asyncio.to_thread(
                    self._secret, stack, key["credential_id"], key["credential_version"]
                )
                async with self._clients.client(self._endpoint(key)) as client:
                    deadline = Deadline.after(self._policy.timeout_seconds)
                    listing = await adapter.list_files(client, secret, deadline, prefix)
                    tracked = self._tracked([f.file_name for f in listing.files])
                    for remote in listing.files:
                        created = _epoch(remote.created_at)
                        if (
                            remote.file_name in tracked
                            or created is None
                            or created > cutoff
                        ):
                            continue
                        if await adapter.delete_file(
                            client, secret, deadline, remote.remote_id
                        ):
                            deleted.append(remote.remote_id)
        except (ProviderFailure, GatewayError):
            return deleted
        return deleted

    # --- the residual acceptance and the gauge --------------------------------------

    def refresh_gauge(self) -> dict[str, int]:
        """Set ``ai_remote_artifacts{status}`` from the stored rows."""
        with self._engine.connect() as connection:
            rows = connection.execute(
                sa.select(_A.c.status, sa.func.count()).group_by(_A.c.status)
            ).all()
        counts: dict[str, int] = {str(status): int(count) for status, count in rows}
        for status in _S:
            REMOTE_ARTIFACTS.labels(status=status.value).set(
                counts.get(status.value, 0)
            )
        return counts


def accept_residual(
    engine: Engine, artifact_id: UUID, evidence: str, actor: Actor
) -> bool:
    """
    (j) Close a parked row as an accepted residual risk — never as cleanup.

    Audited in ``ai_admin_audit`` with the remote id, the file name, the
    provider's expiry and the operator's evidence.
    """
    with audited_transaction(engine) as tx:
        row = (
            tx.connection.execute(
                sa.delete(_A)
                .where(
                    _A.c.id == artifact_id,
                    _A.c.status == _S.MANUAL_CLEANUP_REQUIRED.value,
                )
                .returning(
                    _A.c.remote_artifact_id,
                    _A.c.gateway_file_name,
                    _A.c.provider_expires_at,
                    _A.c.status_reason,
                    _A.c.credential_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return False
        tx.admin(
            actor,
            "remote_artifact.accept_residual",
            "remote_artifact",
            artifact_id,
            {
                "residual_risk": True,
                "remote_artifact_id": row["remote_artifact_id"],
                "gateway_file_name": row["gateway_file_name"],
                "provider_expires_at": _iso(row["provider_expires_at"]),
                "reason": row["status_reason"],
                "credential_id": row["credential_id"],
                "evidence": evidence,
            },
        )
    return True


__all__ = [
    "BATCH",
    "REMOTE_ARTIFACTS",
    "ArtifactPolicy",
    "ArtifactScheduler",
    "ExecutionArtifacts",
    "ItemClaim",
    "accept_residual",
    "backoff",
    "file_name",
    "file_prefix",
    "record_intent",
]

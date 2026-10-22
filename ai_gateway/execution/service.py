"""
``ExecutionService.run`` — the D-24 *Execution sequence*, in order.

1. The guard already verified the job context (pure computation); the
   request's profile is bound to it here.
2. :func:`~.reservation.reserve` — the reservation transaction (``pending``).
3. Before any credential material: the adapter must serve the capability and
   the provider's breaker must not be open, else ``pending → released``.
4. **Credential material** for exactly the recorded ``(credential_id,
   version)`` — the only credential-store I/O of the call, bounded by
   ``AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS``; any failure is ``pending →
   released`` (``credential_unavailable``) with no provider request.
5. The **marker** (:func:`~.settlement.mark_dispatching`); zero rows releases
   the row if it is still ``pending`` and answers why, with no provider call.
6. **Provider I/O** with exactly the recorded model and revision, under the
   stored absolute deadline (``asyncio.timeout_at`` here and on every request
   of the client), then **one settlement**:

   * a validated result → ``ok``;
   * a failure established before any request byte, with no
     ``first_byte_sent_at`` recorded → ``dispatching → released``;
   * a provider answer — an error status, or an answer the validator refused
     — → ``failed``; a provider 429 also sets the credential's cooldown;
   * anything else after the marker — a timeout, a transport loss, a
     cancellation, an unexpected error — → ``charged_uncertain``.

The credential's plaintext lives from the material fetch to the end of the
adapter call and is wiped on every path, a zero-row marker and a cancelled
request included. A client disconnect before the marker releases; after it,
the settlement still runs to completion. Settlements run in worker threads,
which a cancelled request does not stop.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from functools import partial
from typing import Generic, TypeVar
from uuid import UUID

from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    ExecutionReceipt,
    ProviderExecution,
)
from ai_sdk_m8.schemas.management import ProviderType
from pydantic import BaseModel
from sqlalchemy import Engine

from ai_gateway.controllers.resolution import ResolutionPolicy
from ai_gateway.core.errors import GatewayError
from ai_gateway.core.job_context import JobContextPrincipal
from ai_gateway.credentials.store import CredentialStore, ResolvedSecret
from ai_gateway.db_models._common import ExecutionStatus
from ai_gateway.providers.base import AdapterCall, ProviderAdapter, require_capability
from ai_gateway.providers.breaker import Breakers, BreakerState
from ai_gateway.providers.errors import (
    ProviderFailure,
    gateway_error,
    refused_before_send,
)
from ai_gateway.providers.http import ClientFactory, Deadline

from . import settlement
from .jobs import Completed, ExecutionJob
from .limits import ExecutionLimits
from .reservation import Reservation, reserve

R = TypeVar("R", bound=BaseModel)


@dataclass(frozen=True)
class Executed(Generic[R]):
    """A settled ``ok`` execution: its validated result and its accounting."""

    result: R
    execution: ExecutionReceipt


class ExecutionProgress:
    """
    The persisted dispatch progress of one execution (D-24, ``T26``).

    ``first_byte_sent()`` commits ``first_byte_sent_at`` before the first
    request byte, once; a row that is no longer ``dispatching`` inside its
    deadline gets no byte at all (``timeout``).
    """

    def __init__(self, engine: Engine, execution_id: UUID) -> None:
        self._engine = engine
        self._execution_id = execution_id
        self._lock = asyncio.Lock()
        self.recorded = False

    async def first_byte_sent(self) -> None:
        """Record dispatch progress once; refuse when the row cannot send."""
        async with self._lock:
            if self.recorded:
                return
            if not await asyncio.to_thread(
                settlement.record_first_byte, self._engine, self._execution_id
            ):
                raise ProviderFailure(AiErrorCode.TIMEOUT)
            self.recorded = True


def _exit_quietly(context: AbstractContextManager[ResolvedSecret]) -> None:
    """Close a resolution whose caller is gone (best effort, never raises)."""
    with contextlib.suppress(Exception):
        context.__exit__(None, None, None)


@dataclass(frozen=True)
class _Dispatch:
    """The marked destination and the absolute deadline derived from it."""

    marked: settlement.Marked
    deadline: Deadline


class ExecutionService:
    """Runs one capability request through the D-24 sequence."""

    def __init__(
        self,
        engine: Engine,
        store: CredentialStore,
        clients: ClientFactory,
        adapters: Mapping[ProviderType, ProviderAdapter],
        *,
        policy: Callable[[], ResolutionPolicy],
        limits: Callable[[], ExecutionLimits],
        breakers: Breakers,
    ) -> None:
        self._engine = engine
        self._store = store
        self._clients = clients
        self._adapters = adapters
        self._policy = policy
        self._limits = limits
        self._breakers = breakers
        self._detached: set[asyncio.Future[object]] = set()

    async def run(
        self, principal: JobContextPrincipal, job: ExecutionJob[R]
    ) -> Executed[R]:
        """Execute ``job`` under ``principal``'s verified job context."""
        principal.require_profile(job.profile_key)
        limits = self._limits()
        reservation = await asyncio.to_thread(
            reserve, self._engine, principal, job, policy=self._policy(), limits=limits
        )
        execution_id = reservation.execution_id
        try:
            adapter = self._admissible(reservation, job.capability)
        except ProviderFailure as failure:
            await self._release(execution_id, failure.code)
            raise gateway_error(failure) from None
        with ExitStack() as stack:
            secret = await self._material(stack, reservation)
            dispatch = await self._mark(execution_id, limits.total_deadline_seconds)
            return await self._dispatch(reservation, dispatch, adapter, job, secret)

    # --- before the marker ----------------------------------------------------

    def _admissible(
        self, reservation: Reservation, capability: Capability
    ) -> ProviderAdapter:
        resolution = reservation.resolution
        adapter = self._adapters.get(ProviderType(resolution.provider_type))
        if adapter is None:
            raise refused_before_send(AiErrorCode.CAPABILITY_UNSUPPORTED)
        require_capability(adapter, capability)
        breaker = self._breakers.for_provider(resolution.provider_id)
        if breaker.state is BreakerState.OPEN:
            raise refused_before_send(AiErrorCode.BREAKER_OPEN)
        return adapter

    async def _release(self, execution_id: UUID, error: AiErrorCode) -> None:
        await asyncio.to_thread(settlement.release, self._engine, execution_id, error)

    async def _material(
        self, stack: ExitStack, reservation: Reservation
    ) -> ResolvedSecret | None:
        """The recorded version's plaintext, wiped when ``stack`` closes."""
        resolution = reservation.resolution
        if resolution.credential_id is None or resolution.credential_version is None:
            return None
        execution_id = reservation.execution_id
        context = self._store.resolve_for_execution(
            resolution.credential_id, resolution.credential_version
        )
        entering = asyncio.ensure_future(asyncio.to_thread(context.__enter__))
        try:
            secret = await asyncio.shield(entering)
        except asyncio.CancelledError:
            # The fetch completes in its thread anyway: wipe what it yields.
            entering.add_done_callback(lambda _done: _exit_quietly(context))
            self._detach(
                settlement.release,
                self._engine,
                execution_id,
                AiErrorCode.CREDENTIAL_UNAVAILABLE,
            )
            raise
        except GatewayError as error:
            await self._release(execution_id, error.code)
            raise
        except Exception:
            await self._release(execution_id, AiErrorCode.CREDENTIAL_UNAVAILABLE)
            raise GatewayError(AiErrorCode.CREDENTIAL_UNAVAILABLE) from None
        stack.push(context)
        return secret

    async def _mark(self, execution_id: UUID, total_deadline_seconds: int) -> _Dispatch:
        """Commit the marker, or release and refuse with no provider call."""
        started = time.monotonic()
        marking = asyncio.ensure_future(
            asyncio.to_thread(
                settlement.mark_dispatching,
                self._engine,
                execution_id,
                total_deadline_seconds=total_deadline_seconds,
            )
        )
        try:
            marked = await asyncio.shield(marking)
        except asyncio.CancelledError:
            marking.add_done_callback(partial(self._after_cancelled_mark, execution_id))
            raise
        if marked is None:
            await self._release(execution_id, AiErrorCode.CREDENTIAL_UNAVAILABLE)
            raise await asyncio.to_thread(
                settlement.diagnose, self._engine, execution_id
            )
        return _Dispatch(marked, Deadline(started + marked.remaining_seconds))

    def _after_cancelled_mark(
        self, execution_id: UUID, marking: asyncio.Future[settlement.Marked | None]
    ) -> None:
        """A request cancelled during its marker: refund or charge by outcome."""
        if marking.cancelled() or marking.exception() is not None:
            return
        if marking.result() is None:
            self._detach(
                settlement.release,
                self._engine,
                execution_id,
                AiErrorCode.CREDENTIAL_UNAVAILABLE,
            )
            return
        self._detach_charged(execution_id)

    # --- after the marker -----------------------------------------------------

    async def _dispatch(
        self,
        reservation: Reservation,
        dispatch: _Dispatch,
        adapter: ProviderAdapter,
        job: ExecutionJob[R],
        secret: ResolvedSecret | None,
    ) -> Executed[R]:
        execution_id = reservation.execution_id
        progress = ExecutionProgress(self._engine, execution_id)
        try:
            completed = await self._call(dispatch, adapter, job, secret, progress)
        except ProviderFailure as failure:
            await self._settle_failure(reservation, failure, progress)
            raise gateway_error(failure) from None
        except asyncio.CancelledError:
            self._detach_charged(execution_id)
            raise
        except BaseException:
            await asyncio.to_thread(
                settlement.settle,
                self._engine,
                execution_id,
                ExecutionStatus.CHARGED_UNCERTAIN,
                error=AiErrorCode.PROVIDER_UNREACHABLE,
            )
            raise
        settled = await asyncio.to_thread(
            settlement.settle,
            self._engine,
            execution_id,
            ExecutionStatus.OK,
            usage=completed.usage,
        )
        if not settled:
            # A sweeper settled the row meanwhile: a late answer is discarded.
            raise GatewayError(AiErrorCode.TIMEOUT)
        receipt = self._receipt(reservation, dispatch.marked, job, completed)
        return Executed(completed.result, receipt)

    async def _call(
        self,
        dispatch: _Dispatch,
        adapter: ProviderAdapter,
        job: ExecutionJob[R],
        secret: ResolvedSecret | None,
        progress: ExecutionProgress,
    ) -> Completed[R]:
        deadline = dispatch.deadline
        deadline.require()
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout_at(loop.time() + deadline.remaining()):
                async with self._clients.client(dispatch.marked.endpoint) as client:
                    call = AdapterCall(
                        client=client,
                        secret=secret,
                        model=dispatch.marked.model,
                        progress=progress,
                        deadline=deadline,
                        config=dispatch.marked.config,
                    )
                    return await job.execute(adapter, call)
        except TimeoutError:
            raise ProviderFailure(AiErrorCode.TIMEOUT) from None

    async def _settle_failure(
        self,
        reservation: Reservation,
        failure: ProviderFailure,
        progress: ExecutionProgress,
    ) -> None:
        execution_id = reservation.execution_id
        if failure.before_send and not progress.recorded:
            await asyncio.to_thread(
                settlement.release,
                self._engine,
                execution_id,
                failure.code,
                dispatched=True,
            )
            return
        status = (
            ExecutionStatus.FAILED
            if failure.status_class is not None
            else ExecutionStatus.CHARGED_UNCERTAIN
        )
        resolution = reservation.resolution
        cooldown = None
        if failure.throttled and resolution.credential_id is not None:
            cooldown = (resolution.credential_id, failure.retry_after_seconds or 0)
        incident = None
        if failure.incident is not None:
            incident = (failure.incident, resolution.model_id)
        await asyncio.to_thread(
            settlement.settle,
            self._engine,
            execution_id,
            status,
            error=failure.code,
            cooldown=cooldown,
            incident=incident,
        )

    def _receipt(
        self,
        reservation: Reservation,
        marked: settlement.Marked,
        job: ExecutionJob[R],
        completed: Completed[R],
    ) -> ExecutionReceipt:
        resolution = reservation.resolution
        return ExecutionReceipt(
            execution_id=reservation.execution_id,
            capability=job.capability,
            units=reservation.units,
            provider_usage=completed.usage,
            provider_execution=ProviderExecution(
                profile_key=job.profile_key,
                profile_revision=resolution.profile_revision,
                execution_identity=reservation.execution_identity,
                embedding_space_id=reservation.embedding_space_id,
                identity_assurance=marked.identity_assurance,
            ),
        )

    # --- settlements nobody awaits -------------------------------------------

    def _detach_charged(self, execution_id: UUID) -> None:
        self._detach(
            settlement.settle,
            self._engine,
            execution_id,
            ExecutionStatus.CHARGED_UNCERTAIN,
            error=AiErrorCode.TIMEOUT,
        )

    def _detach(
        self, fn: Callable[..., object], *args: object, **kwargs: object
    ) -> None:
        """Run a settlement to completion though its request is gone."""
        future = asyncio.get_running_loop().run_in_executor(
            None, partial(fn, *args, **kwargs)
        )
        self._detached.add(future)
        future.add_done_callback(self._detached.discard)

    async def drain(self) -> None:
        """Wait for every detached settlement (tests, shutdown)."""
        while self._detached:
            await asyncio.gather(*self._detached, return_exceptions=True)


__all__ = ["ExecutionProgress", "ExecutionService", "Executed"]

"""Immutable temporal work authority references and cancellation signals."""

from __future__ import annotations

import asyncio
import math
import threading
import uuid
from dataclasses import dataclass
from enum import Enum

from chat_engine.security.epochs import SessionEpochV1


class WorkOperationKindV1(str, Enum):
    """Closed Milestone 3A operation kinds.

    Later milestones may add subsystem-specific kinds without changing the
    fence or controller model.
    """

    GENERIC_ASYNC = "GENERIC_ASYNC"
    GENERIC_EXTERNAL_CALL = "GENERIC_EXTERNAL_CALL"
    GENERIC_STATE_MUTATION = "GENERIC_STATE_MUTATION"
    GENERIC_EGRESS = "GENERIC_EGRESS"


class WorkValidationBoundaryV1(str, Enum):
    """Conceptual validation boundaries shared by future integrations."""

    ADMISSION = "ADMISSION"
    QUEUE_DEQUEUE = "QUEUE_DEQUEUE"
    BEFORE_EXTERNAL_CALL = "BEFORE_EXTERNAL_CALL"
    AFTER_RETURN_OR_CALLBACK = "AFTER_RETURN_OR_CALLBACK"
    BEFORE_STATE_MUTATION = "BEFORE_STATE_MUTATION"
    BEFORE_PRIVATE_STORE_WRITE = "BEFORE_PRIVATE_STORE_WRITE"
    BEFORE_EGRESS = "BEFORE_EGRESS"


class WorkCancellationSignalV1:
    """Read-only cooperative cancellation signal exposed with a work lease."""

    __slots__ = ("__async_waiters", "__event", "__waiter_lock")

    def __init__(self) -> None:
        self.__event = threading.Event()
        self.__waiter_lock = threading.Lock()
        self.__async_waiters: set[
            tuple[asyncio.AbstractEventLoop, asyncio.Future[bool]]
        ] = set()

    @property
    def is_cancelled(self) -> bool:
        return self.__event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self.__event.wait(timeout)

    async def wait_async(
        self,
        max_wait_seconds: float | None = None,
    ) -> bool:
        """Wait without retaining a controller lock across an await."""

        if self.__event.is_set():
            return True
        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[bool] = loop.create_future()
        entry = (loop, waiter)
        with self.__waiter_lock:
            if self.__event.is_set():
                return True
            self.__async_waiters.add(entry)
        try:
            if max_wait_seconds is None:
                return await waiter
            try:
                return await asyncio.wait_for(waiter, max_wait_seconds)
            except TimeoutError:
                return self.__event.is_set()
        finally:
            with self.__waiter_lock:
                self.__async_waiters.discard(entry)

    def _cancel_v1(self) -> None:
        with self.__waiter_lock:
            self.__event.set()
            waiters = tuple(self.__async_waiters)
            self.__async_waiters.clear()
        for loop, waiter in waiters:

            def resolve(waiter: asyncio.Future[bool] = waiter) -> None:
                if not waiter.done():
                    waiter.set_result(True)

            try:
                loop.call_soon_threadsafe(resolve)
            except RuntimeError:
                continue

    def __repr__(self) -> str:
        return "WorkCancellationSignalV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class WorkFenceV1:
    """Authenticated canonical reference to one registered operation."""

    authority_id: str
    session_epoch: SessionEpochV1
    operation_id: uuid.UUID
    operation_kind: WorkOperationKindV1
    deadline_monotonic: float
    authenticator: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, uuid.UUID):
            raise TypeError("operation_id must be a UUID")
        if not isinstance(self.operation_kind, WorkOperationKindV1):
            raise TypeError("operation_kind must be a WorkOperationKindV1")
        if (
            isinstance(self.deadline_monotonic, bool)
            or not isinstance(self.deadline_monotonic, (int, float))
            or not math.isfinite(self.deadline_monotonic)
        ):
            raise ValueError("deadline_monotonic must be finite")

    def __repr__(self) -> str:
        return "WorkFenceV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class WorkLeaseV1:
    """Single-release lease that owns one registered-work cleanup token."""

    authority_id: str
    session_epoch: SessionEpochV1
    operation_id: uuid.UUID
    token_id: uuid.UUID
    authenticator: bytes

    def __repr__(self) -> str:
        return "WorkLeaseV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class RegisteredWorkV1:
    """Fence, cancellation signal, and cleanup-owning lease returned atomically."""

    fence: WorkFenceV1
    cancellation: WorkCancellationSignalV1
    lease: WorkLeaseV1

    def __repr__(self) -> str:
        return "RegisteredWorkV1(<opaque>)"

"""Thin production adapter for Milestone 3 session work authority.

This module does not create another cancellation or fencing model.  It keeps
the existing :class:`SessionWorkControllerV1` as the sole temporal authority
and provides only:

* a thread-local, server-owned execution scope for handler callbacks;
* a redacted queue item that keeps work authority outside payload metadata;
* exact-once lease release bookkeeping; and
* the final Milestone 2 + Milestone 3 composition check used by egress.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from loguru import logger

from chat_engine.security.dispatch import (
    ConsumerCapabilityV1,
    SecurityEnvelopeReferenceV1,
)
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    RegisteredWorkV1,
    WorkFenceV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

if TYPE_CHECKING:
    from chat_engine.security.authority import SecurityAuthorityV1
    from certificate_capture.isolation import (
        NormalApplicationAdmissionViewV1,
    )


_DEFAULT_WORK_LIFETIME_SECONDS_V1: dict[WorkOperationKindV1, float] = {
    WorkOperationKindV1.GENERIC_ASYNC: 120.0,
    WorkOperationKindV1.GENERIC_EXTERNAL_CALL: 300.0,
    WorkOperationKindV1.GENERIC_STATE_MUTATION: 120.0,
    WorkOperationKindV1.GENERIC_EGRESS: 60.0,
    WorkOperationKindV1.PERCEPTION_INFERENCE: 60.0,
    WorkOperationKindV1.PERCEPTION_HEARTBEAT: 300.0,
    WorkOperationKindV1.CHAT_AGENT_LLM: 300.0,
    WorkOperationKindV1.CHAT_AGENT_PROACTIVE: 300.0,
    WorkOperationKindV1.TOOL_EXECUTION: 300.0,
    WorkOperationKindV1.TTS_SYNTHESIS: 300.0,
    WorkOperationKindV1.WS_EGRESS: 60.0,
    WorkOperationKindV1.RTC_EGRESS: 60.0,
    WorkOperationKindV1.CAPTURE_FRAME_UPLOAD: 15.0,
    WorkOperationKindV1.CAPTURE_INACTIVITY_TIMER: 15 * 60.0,
    WorkOperationKindV1.CAPTURE_MOCK_PROCESSOR: 30.0,
}


@dataclass(frozen=True, slots=True, repr=False)
class WorkExecutionScopeV1:
    """Server-owned callback scope; never copied into application payloads."""

    registered_work: RegisteredWorkV1
    envelope_ref: SecurityEnvelopeReferenceV1 | None = None

    def __repr__(self) -> str:
        return "WorkExecutionScopeV1(<opaque>)"


@dataclass(slots=True, repr=False)
class WorkBoundItemV1:
    """Queue-owned payload plus separate M2 and M3 authority references."""

    payload: Any
    registered_work: RegisteredWorkV1
    envelope_ref: SecurityEnvelopeReferenceV1 | None = None
    _release_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )
    _released: bool = field(default=False, init=False, repr=False)

    @property
    def fence(self) -> WorkFenceV1:
        return self.registered_work.fence

    @property
    def cancellation(self):
        return self.registered_work.cancellation

    def release_once_v1(self, runtime: SessionWorkRuntimeV1) -> bool:
        """Release the work lease at most once, including racing cleanup."""

        with self._release_lock:
            if self._released:
                return False
            self._released = True
        return runtime.release_work_v1(self.registered_work)

    def __repr__(self) -> str:
        return "WorkBoundItemV1(<redacted>)"


class SessionWorkRuntimeV1:
    """Production-facing view over exactly one session work controller."""

    __slots__ = (
        "__controller",
        "__normal_application_admission",
        "__scope_var",
        "__security_authority",
    )

    def __init__(
        self,
        controller: SessionWorkControllerV1,
        security_authority: SecurityAuthorityV1 | None = None,
        normal_application_admission: (
            NormalApplicationAdmissionViewV1 | None
        ) = None,
    ) -> None:
        if not isinstance(controller, SessionWorkControllerV1):
            raise TypeError("controller must be SessionWorkControllerV1")
        self.__controller = controller
        self.__security_authority = security_authority
        self.__normal_application_admission = (
            normal_application_admission
        )
        self.__scope_var: contextvars.ContextVar[
            tuple[WorkExecutionScopeV1, ...]
        ] = contextvars.ContextVar(
            f"session_work_scope_v1_{id(self)}",
            default=(),
        )

    def _scope_stack_v1(self) -> tuple[WorkExecutionScopeV1, ...]:
        return self.__scope_var.get()

    def current_scope_v1(self) -> WorkExecutionScopeV1 | None:
        stack = self._scope_stack_v1()
        return stack[-1] if stack else None

    def current_work_v1(self) -> RegisteredWorkV1 | None:
        scope = self.current_scope_v1()
        return scope.registered_work if scope is not None else None

    def current_fence_v1(self) -> WorkFenceV1 | None:
        work = self.current_work_v1()
        return work.fence if work is not None else None

    def current_envelope_ref_v1(
        self,
    ) -> SecurityEnvelopeReferenceV1 | None:
        scope = self.current_scope_v1()
        return scope.envelope_ref if scope is not None else None

    @contextmanager
    def activate_work_v1(
        self,
        registered_work: RegisteredWorkV1,
        envelope_ref: SecurityEnvelopeReferenceV1 | None = None,
    ) -> Iterator[WorkExecutionScopeV1]:
        if not isinstance(registered_work, RegisteredWorkV1):
            raise TypeError("registered_work must be RegisteredWorkV1")
        scope = WorkExecutionScopeV1(
            registered_work=registered_work,
            envelope_ref=envelope_ref,
        )
        stack = self._scope_stack_v1()
        token = self.__scope_var.set((*stack, scope))
        try:
            yield scope
        finally:
            current = self._scope_stack_v1()
            if not current or current[-1] is not scope:
                self.__scope_var.reset(token)
                raise RuntimeError("work execution scope stack corrupted")
            self.__scope_var.reset(token)

    @staticmethod
    def deadline_for_kind_v1(
        operation_kind: WorkOperationKindV1,
    ) -> float:
        lifetime = _DEFAULT_WORK_LIFETIME_SECONDS_V1.get(operation_kind)
        if lifetime is None:
            raise WorkAdmissionDeniedV1("unknown work operation kind")
        return time.monotonic() + lifetime

    def register_root_work_v1(
        self,
        operation_kind: WorkOperationKindV1,
        *,
        deadline_monotonic: float | None = None,
    ) -> RegisteredWorkV1:
        deadline = (
            self.deadline_for_kind_v1(operation_kind)
            if deadline_monotonic is None
            else deadline_monotonic
        )
        return self.__controller.register_work_v1(
            operation_kind,
            deadline,
            _admission_guard_v1=(
                self.normal_application_admission_is_open_v1
            ),
        )

    def register_child_work_v1(
        self,
        parent: RegisteredWorkV1 | WorkFenceV1 | None,
        operation_kind: WorkOperationKindV1,
        *,
        deadline_monotonic: float | None = None,
    ) -> RegisteredWorkV1:
        if parent is None:
            current = self.current_work_v1()
            parent_fence = current.fence if current is not None else None
        elif isinstance(parent, RegisteredWorkV1):
            parent_fence = parent.fence
        else:
            parent_fence = parent
        if parent_fence is None:
            raise WorkAdmissionDeniedV1(
                "child work requires an exact parent fence"
            )
        deadline = (
            self.deadline_for_kind_v1(operation_kind)
            if deadline_monotonic is None
            else deadline_monotonic
        )
        return self.__controller.register_child_work_v1(
            parent_fence,
            operation_kind,
            deadline,
            _admission_guard_v1=(
                self.normal_application_admission_is_open_v1
            ),
        )

    def make_child_item_v1(
        self,
        payload: Any,
        operation_kind: WorkOperationKindV1,
        *,
        parent: RegisteredWorkV1 | WorkFenceV1 | None = None,
        envelope_ref: SecurityEnvelopeReferenceV1 | None = None,
        deadline_monotonic: float | None = None,
    ) -> WorkBoundItemV1:
        current_scope = self.current_scope_v1()
        child = self.register_child_work_v1(
            parent,
            operation_kind,
            deadline_monotonic=deadline_monotonic,
        )
        return WorkBoundItemV1(
            payload=payload,
            registered_work=child,
            envelope_ref=(
                envelope_ref
                if envelope_ref is not None
                else (
                    current_scope.envelope_ref
                    if current_scope is not None
                    else None
                )
            ),
        )

    def validate_work_v1(
        self,
        work: RegisteredWorkV1 | WorkFenceV1 | None,
        boundary: WorkValidationBoundaryV1,
    ) -> bool:
        if (
            work is None
            or not self.normal_application_admission_is_open_v1()
        ):
            return False
        fence = work.fence if isinstance(work, RegisteredWorkV1) else work
        return self.__controller.validate_work_v1(fence, boundary)

    def validate_current_v1(
        self,
        boundary: WorkValidationBoundaryV1,
    ) -> bool:
        return self.validate_work_v1(self.current_work_v1(), boundary)

    def perform_if_live_v1(
        self,
        work: RegisteredWorkV1 | WorkFenceV1 | None,
        boundary: WorkValidationBoundaryV1,
        action: Callable[[], Any],
    ) -> bool:
        if work is None:
            return False
        fence = work.fence if isinstance(work, RegisteredWorkV1) else work
        return self.__controller.perform_if_live_v1(
            fence,
            boundary,
            action,
            _admission_guard_v1=(
                self.normal_application_admission_is_open_v1
            ),
        )

    def perform_current_if_live_v1(
        self,
        boundary: WorkValidationBoundaryV1,
        action: Callable[[], Any],
    ) -> bool:
        return self.perform_if_live_v1(
            self.current_work_v1(),
            boundary,
            action,
        )

    def m2_consumer_allows_v1(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1 | None,
        consumer_capability: ConsumerCapabilityV1 | None,
    ) -> bool:
        authority = self.__security_authority
        if authority is None:
            return True
        if envelope_ref is None or consumer_capability is None:
            return False
        return authority.consumer_is_authorized_v1(
            envelope_ref,
            consumer_capability,
        )

    def perform_item_egress_if_live_v1(
        self,
        item: WorkBoundItemV1,
        consumer_capability: ConsumerCapabilityV1 | None,
        action: Callable[[], Any],
    ) -> bool:
        """Require M2 authorization and atomic M3 liveness for final egress."""

        if not isinstance(item, WorkBoundItemV1):
            return False

        def composed_action() -> None:
            if not self.m2_consumer_allows_v1(
                item.envelope_ref,
                consumer_capability,
            ):
                raise PermissionError(
                    "security envelope does not authorize egress"
                )
            action()

        try:
            return self.perform_if_live_v1(
                item.registered_work,
                WorkValidationBoundaryV1.BEFORE_EGRESS,
                composed_action,
            )
        except PermissionError:
            return False

    async def perform_item_egress_async_if_live_v1(
        self,
        item: WorkBoundItemV1,
        consumer_capability: ConsumerCapabilityV1 | None,
        action: Callable[[], Awaitable[Any]],
        abort_action_v1: Callable[[], Awaitable[Any] | Any],
    ) -> bool:
        """Compose M2 with controller-serialized awaited M3 egress."""

        if (
            not isinstance(item, WorkBoundItemV1)
            or not self.m2_consumer_allows_v1(
                item.envelope_ref,
                consumer_capability,
            )
        ):
            return False
        return await self.__controller.perform_if_live_async_v1(
            item.registered_work.fence,
            WorkValidationBoundaryV1.BEFORE_EGRESS,
            action,
            abort_action_v1,
            _admission_guard_v1=(
                self.normal_application_admission_is_open_v1
            ),
        )

    def item_egress_is_allowed_v1(
        self,
        item: WorkBoundItemV1,
        consumer_capability: ConsumerCapabilityV1 | None,
    ) -> bool:
        """Non-blocking preflight for awaited transport send boundaries.

        Awaited send paths re-run this immediately before each actual send.
        Short synchronous egress must prefer
        :meth:`perform_item_egress_if_live_v1`.
        """

        return (
            isinstance(item, WorkBoundItemV1)
            and self.m2_consumer_allows_v1(
                item.envelope_ref,
                consumer_capability,
            )
            and self.validate_work_v1(
                item.registered_work,
                WorkValidationBoundaryV1.BEFORE_EGRESS,
            )
        )

    def release_work_v1(self, work: RegisteredWorkV1) -> bool:
        if not isinstance(work, RegisteredWorkV1):
            return False
        return self.__controller.release_work_v1(work.lease)

    def cancel_work_v1(
        self,
        work: RegisteredWorkV1 | WorkFenceV1,
    ) -> bool:
        fence = work.fence if isinstance(work, RegisteredWorkV1) else work
        return self.__controller.cancel_work_v1(fence)

    def log_late_drop_v1(
        self,
        work: RegisteredWorkV1 | WorkFenceV1,
        reason: str,
    ) -> None:
        fence = work.fence if isinstance(work, RegisteredWorkV1) else work
        logger.bind(
            security_event_code="LATE_CALLBACK_DROPPED",
            operation_kind=fence.operation_kind.value,
            operation_id=str(fence.operation_id),
            reason=reason,
        ).warning("LATE_CALLBACK_DROPPED")

    def is_usable_v1(self) -> bool:
        return self.__controller.is_usable_v1()

    def normal_application_admission_is_open_v1(self) -> bool:
        admission = self.__normal_application_admission
        return admission is None or admission.is_open_v1()

    def transport_keepalive_is_allowed_v1(self) -> bool:
        admission = self.__normal_application_admission
        return (
            admission is None
            or admission.transport_keepalive_is_allowed_v1()
        )

    async def wait_for_retirement_settled_async_v1(self) -> bool:
        """Expose only the controller's bounded teardown-ordering barrier."""

        return await self.__controller.wait_for_retirement_settled_async_v1()

    def _controller_for_test_v1(self) -> SessionWorkControllerV1:
        return self.__controller


__all__ = [
    "SessionWorkRuntimeV1",
    "WorkBoundItemV1",
    "WorkExecutionScopeV1",
]

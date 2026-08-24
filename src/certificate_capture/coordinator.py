"""Session-owned Secure Certificate Capture V1 Milestone 4A coordinator."""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.isolation import (
    NormalApplicationAdmissionViewV1,
    _create_normal_mode_isolation_v1,
    _NormalModeIsolationControllerV1,
)
from certificate_capture.state import (
    CaptureFailureReasonV1,
    CaptureStateV1,
    CaptureTransitionKindV1,
    CaptureTransitionPhaseV1,
    CaptureTransitionPointV1,
)
from certificate_capture.status import CaptureStatusV1
from chat_engine.security.audit_events import (
    CoreSecurityAuditV1,
    SecurityAuditEventCodeV1,
    SecurityAuditEventV1,
)
from chat_engine.security.cleanup_fence import (
    CleanupActionV1,
    CleanupTokenV1,
    GenerationRetirementV1,
    RetiredGenerationCleanupStateV1,
)
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import UINT64_MAX_V1, new_uuid7_v1
from chat_engine.security.session_work_controller import (
    GenerationRetirementReasonV1,
    SessionGenerationOverflowV1,
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
)


class CaptureTransitionRejectedV1(RuntimeError):
    """Stable, payload-free invalid-state or stale-authority result."""

    __slots__ = ("reason_code",)

    def __init__(self, reason: CaptureFailureReasonV1) -> None:
        self.reason_code = reason.value
        super().__init__(f"capture transition rejected ({self.reason_code})")


class CaptureFailedClosedV1(RuntimeError):
    """Stable result returned after a fatal transition uncertainty."""

    __slots__ = ("reason_code",)

    def __init__(self, reason: CaptureFailureReasonV1) -> None:
        self.reason_code = reason.value
        super().__init__(f"capture transition failed closed ({self.reason_code})")


@dataclass(slots=True, repr=False)
class _CaptureTransitionV1:
    transition_id: uuid.UUID
    kind: CaptureTransitionKindV1
    capture_id: uuid.UUID | None
    capture_seq: int
    origin_candidates: tuple[SessionEpochV1, ...]
    bound_origin_epoch: SessionEpochV1 | None
    target_generation: int | None
    phase: CaptureTransitionPhaseV1
    cleanup_token: CleanupTokenV1 | None = None
    superseded_transition_id: uuid.UUID | None = None

    def __repr__(self) -> str:
        return "_CaptureTransitionV1(<opaque>)"


class _TransitionFailureV1(RuntimeError):
    __slots__ = ("reason",)

    def __init__(self, reason: CaptureFailureReasonV1) -> None:
        self.reason = reason
        super().__init__(reason.value)


class _TransitionSupersededV1(RuntimeError):
    pass


SessionLiveActionV1 = Callable[[Callable[[], None]], bool]
QuiescenceDrainV1 = Callable[[SessionEpochV1], None]
SemanticCleanupV1 = Callable[[SessionEpochV1], None]
FailureTerminatorV1 = Callable[[], None]
TransitionHookV1 = Callable[
    [CaptureTransitionPointV1],
    object,
]

_COORDINATOR_CONSTRUCTION_AUTHORITY_V1 = object()


class CaptureCoordinatorV1:
    """Own one capture-mode lifecycle for one authenticated secure session."""

    __slots__ = (
        "_active_transition",
        "_audit",
        "_capture_epoch",
        "_capture_id",
        "_capture_seq",
        "_destroyed",
        "_failure_reason",
        "_failure_terminator_v1",
        "_fatal_failure",
        "_feature_enabled_v1",
        "_isolation_controller",
        "_isolation_view",
        "_last_session_generation",
        "_lock",
        "_operation_idle",
        "_operation_lock",
        "_quiescence_complete",
        "_quiescence_drain_v1",
        "_security_authority_usable_v1",
        "_semantic_cleanup_v1",
        "_session_live_action_v1",
        "_shutdown_started",
        "_state",
        "_termination_requested",
        "_transition_hook_for_test_v1",
        "_work_controller",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        work_controller: SessionWorkControllerV1,
        isolation_controller: _NormalModeIsolationControllerV1,
        isolation_view: NormalApplicationAdmissionViewV1,
        feature_enabled_v1: Callable[[], bool],
        security_authority_usable_v1: Callable[[], bool],
        session_live_action_v1: SessionLiveActionV1,
        quiescence_drain_v1: QuiescenceDrainV1,
        semantic_cleanup_v1: SemanticCleanupV1,
        failure_terminator_v1: FailureTerminatorV1 | None,
    ) -> None:
        if _construction_authority_v1 is not _COORDINATOR_CONSTRUCTION_AUTHORITY_V1:
            raise RuntimeError("capture coordinator construction denied")
        if not isinstance(work_controller, SessionWorkControllerV1):
            raise TypeError("work_controller must be SessionWorkControllerV1")
        self._work_controller = work_controller
        self._isolation_controller = isolation_controller
        self._isolation_view = isolation_view
        self._feature_enabled_v1 = feature_enabled_v1
        self._security_authority_usable_v1 = security_authority_usable_v1
        self._session_live_action_v1 = session_live_action_v1
        self._quiescence_drain_v1 = quiescence_drain_v1
        self._semantic_cleanup_v1 = semantic_cleanup_v1
        self._failure_terminator_v1 = failure_terminator_v1
        self._lock = threading.RLock()
        self._operation_lock = asyncio.Lock()
        self._operation_idle = threading.Event()
        self._operation_idle.set()
        self._state = CaptureStateV1.IDLE
        self._capture_epoch: CaptureEpochV1 | None = None
        self._capture_id: uuid.UUID | None = None
        self._capture_seq = 0
        self._active_transition: _CaptureTransitionV1 | None = None
        self._failure_reason: CaptureFailureReasonV1 | None = None
        self._fatal_failure: CaptureFailureReasonV1 | None = None
        self._quiescence_complete = False
        self._shutdown_started = False
        self._destroyed = False
        self._termination_requested = False
        self._last_session_generation = work_controller.current_epoch_v1().generation
        self._audit = CoreSecurityAuditV1()
        self._transition_hook_for_test_v1: TransitionHookV1 | None = None

    @classmethod
    def _create_for_session_v1(
        cls,
        *,
        work_controller: SessionWorkControllerV1,
        feature_enabled_v1: Callable[[], bool],
        security_authority_usable_v1: Callable[[], bool],
        session_live_action_v1: SessionLiveActionV1,
        quiescence_drain_v1: QuiescenceDrainV1,
        semantic_cleanup_v1: SemanticCleanupV1,
        failure_terminator_v1: FailureTerminatorV1 | None = None,
    ) -> tuple[
        CaptureCoordinatorV1,
        NormalApplicationAdmissionViewV1,
    ]:
        """Core-only construction seam used once by one secure ChatSession."""

        isolation_controller, isolation_view = _create_normal_mode_isolation_v1()
        coordinator = cls(
            _construction_authority_v1=(_COORDINATOR_CONSTRUCTION_AUTHORITY_V1),
            work_controller=work_controller,
            isolation_controller=isolation_controller,
            isolation_view=isolation_view,
            feature_enabled_v1=feature_enabled_v1,
            security_authority_usable_v1=(security_authority_usable_v1),
            session_live_action_v1=session_live_action_v1,
            quiescence_drain_v1=quiescence_drain_v1,
            semantic_cleanup_v1=semantic_cleanup_v1,
            failure_terminator_v1=failure_terminator_v1,
        )
        return coordinator, isolation_view

    def _set_transition_hook_for_test_v1(
        self,
        hook: TransitionHookV1 | None,
    ) -> None:
        with self._lock:
            self._transition_hook_for_test_v1 = hook

    def _set_capture_sequence_for_test_v1(self, capture_seq: int) -> None:
        with self._lock:
            if (
                self._state is not CaptureStateV1.IDLE
                or self._active_transition is not None
                or self._capture_epoch is not None
                or self._destroyed
            ):
                raise RuntimeError("capture sequence test seam unavailable")
            self._capture_seq = capture_seq

    async def _call_transition_hook_v1(
        self,
        point: CaptureTransitionPointV1,
    ) -> None:
        with self._lock:
            hook = self._transition_hook_for_test_v1
        if hook is None:
            return
        result = hook(point)
        if inspect.isawaitable(result):
            await result

    def _record_v1(self, code: SecurityAuditEventCodeV1) -> None:
        self._audit.record(code)

    def audit_events_v1(self) -> tuple[SecurityAuditEventV1, ...]:
        return self._audit.snapshot()

    def normal_application_admission_view_v1(
        self,
    ) -> NormalApplicationAdmissionViewV1:
        return self._isolation_view

    def _feature_is_enabled_v1(self) -> bool:
        try:
            return bool(self._feature_enabled_v1())
        except Exception:  # noqa: BLE001 - callback failure closes admission
            return False

    def _security_authority_is_usable_v1(self) -> bool:
        try:
            return bool(self._security_authority_usable_v1())
        except Exception:  # noqa: BLE001 - callback failure closes admission
            return False

    def _run_if_session_live_v1(
        self,
        action: Callable[[], None],
    ) -> bool:
        try:
            return bool(self._session_live_action_v1(action))
        except Exception:  # noqa: BLE001 - authority callback is fail closed
            return False

    def _reject_v1(self, reason: CaptureFailureReasonV1) -> None:
        self._record_v1(SecurityAuditEventCodeV1.CAPTURE_TRANSITION_REJECTED)
        raise CaptureTransitionRejectedV1(reason)

    def _active_is_v1(self, transition: _CaptureTransitionV1) -> bool:
        with self._lock:
            return not self._destroyed and self._active_transition is transition

    def _require_active_v1(
        self,
        transition: _CaptureTransitionV1,
        expected_state: CaptureStateV1,
    ) -> None:
        with self._lock:
            if (
                self._destroyed
                or self._active_transition is not transition
                or self._state is not expected_state
            ):
                raise _TransitionSupersededV1

    def _set_phase_v1(
        self,
        transition: _CaptureTransitionV1,
        phase: CaptureTransitionPhaseV1,
    ) -> None:
        with self._lock:
            if self._destroyed or self._active_transition is not transition:
                raise _TransitionSupersededV1
            transition.phase = phase

    @asynccontextmanager
    async def _serialized_operation_v1(self):
        await self._operation_lock.acquire()
        self._operation_idle.clear()
        try:
            yield
        finally:
            self._operation_idle.set()
            self._operation_lock.release()

    def _request_failure_termination_v1(self) -> None:
        with self._lock:
            if self._termination_requested:
                return
            self._termination_requested = True
            terminator = self._failure_terminator_v1
        if terminator is None:
            return
        try:
            terminator()
        except Exception:  # noqa: BLE001 - termination remains best effort
            return

    def _enter_failed_closed_v1(
        self,
        transition: _CaptureTransitionV1 | None,
        reason: CaptureFailureReasonV1,
    ) -> bool:
        with self._lock:
            if self._destroyed:
                return False
            if transition is not None and self._active_transition is not transition:
                return False
            self._isolation_controller.close_v1()
            self._isolation_controller.disable_transport_keepalive_v1()
            self._fatal_failure = reason
            self._failure_reason = reason
            self._state = CaptureStateV1.FAILED_CLOSED
            self._active_transition = None
            self._quiescence_complete = False
            self._record_v1(SecurityAuditEventCodeV1.CAPTURE_FAILED_CLOSED)
            return True

    def _fail_transition_v1(
        self,
        transition: _CaptureTransitionV1,
        reason: CaptureFailureReasonV1,
    ) -> None:
        if not self._enter_failed_closed_v1(transition, reason):
            raise _TransitionSupersededV1
        self._request_failure_termination_v1()

    def _close_transition_cleanup_token_v1(
        self,
        transition: _CaptureTransitionV1,
    ) -> None:
        token = transition.cleanup_token
        if token is None:
            return
        transition.cleanup_token = None
        try:
            self._work_controller._close_cleanup_participant_v1(token)
        except Exception:  # noqa: BLE001 - teardown remains fail closed
            return

    def _claim_begin_v1(self) -> _CaptureTransitionV1:
        claimed: list[_CaptureTransitionV1] = []
        rejected: list[CaptureFailureReasonV1] = []
        fatal: list[CaptureFailureReasonV1] = []

        def claim() -> None:
            with self._lock:

                def fail_precondition(
                    reason: CaptureFailureReasonV1,
                ) -> None:
                    if self._enter_failed_closed_v1(None, reason):
                        fatal.append(reason)
                    else:
                        rejected.append(CaptureFailureReasonV1.SESSION_SHUTDOWN)

                if self._destroyed or self._shutdown_started:
                    rejected.append(CaptureFailureReasonV1.SESSION_SHUTDOWN)
                    return
                if not self._feature_is_enabled_v1():
                    fail_precondition(CaptureFailureReasonV1.FEATURE_DISABLED)
                    return
                if not self._security_authority_is_usable_v1():
                    fail_precondition(
                        CaptureFailureReasonV1.SECURITY_AUTHORITY_UNAVAILABLE
                    )
                    return
                if not self._work_controller.is_usable_v1():
                    fail_precondition(
                        CaptureFailureReasonV1.WORK_CONTROLLER_UNAVAILABLE
                    )
                    return
                if (
                    self._state is not CaptureStateV1.IDLE
                    or self._active_transition is not None
                    or self._capture_epoch is not None
                ):
                    rejected.append(CaptureFailureReasonV1.CAPTURE_BUSY)
                    return
                if self._capture_seq == UINT64_MAX_V1:
                    fail_precondition(CaptureFailureReasonV1.CAPTURE_SEQUENCE_OVERFLOW)
                    return

                origin_epoch = self._work_controller.current_epoch_v1()
                next_seq = self._capture_seq + 1
                capture_id = new_uuid7_v1()
                transition = _CaptureTransitionV1(
                    transition_id=new_uuid7_v1(),
                    kind=CaptureTransitionKindV1.BEGIN,
                    capture_id=capture_id,
                    capture_seq=next_seq,
                    origin_candidates=(origin_epoch,),
                    bound_origin_epoch=origin_epoch,
                    target_generation=origin_epoch.generation + 1,
                    phase=CaptureTransitionPhaseV1.CLAIMED,
                )

                def commit() -> None:
                    isolation = self._isolation_controller.snapshot_v1()
                    if (
                        not isolation.admission_open
                        or isolation.destroyed
                        or not self._isolation_controller.close_v1()
                    ):
                        return
                    self._capture_seq = next_seq
                    self._capture_id = capture_id
                    self._capture_epoch = None
                    self._failure_reason = None
                    self._fatal_failure = None
                    self._quiescence_complete = False
                    self._active_transition = transition
                    self._state = CaptureStateV1.ENTERING
                    self._record_v1(SecurityAuditEventCodeV1.CAPTURE_ENTERING)
                    claimed.append(transition)

                if not (
                    self._work_controller._perform_current_epoch_control_action_v1(
                        origin_epoch,
                        commit,
                    )
                ):
                    fail_precondition(
                        CaptureFailureReasonV1.WORK_CONTROLLER_UNAVAILABLE
                    )
                elif not claimed:
                    self._state = CaptureStateV1.FAILED_CLOSED
                    self._failure_reason = CaptureFailureReasonV1.INTERNAL_FAILURE
                    self._fatal_failure = self._failure_reason
                    self._record_v1(SecurityAuditEventCodeV1.CAPTURE_FAILED_CLOSED)
                    fatal.append(self._failure_reason)

        if not self._run_if_session_live_v1(claim):
            reason = CaptureFailureReasonV1.SESSION_AUTHORITY_UNAVAILABLE
            if self._enter_failed_closed_v1(None, reason):
                self._request_failure_termination_v1()
                raise CaptureFailedClosedV1(reason)
            self._reject_v1(CaptureFailureReasonV1.SESSION_SHUTDOWN)
        if claimed:
            return claimed[0]
        if fatal:
            self._request_failure_termination_v1()
            raise CaptureFailedClosedV1(fatal[0])
        self._reject_v1(
            rejected[0] if rejected else CaptureFailureReasonV1.INTERNAL_FAILURE
        )
        raise AssertionError("unreachable")

    def _publish_quiescing_v1(
        self,
        transition: _CaptureTransitionV1,
        retirement: GenerationRetirementV1,
    ) -> bool:
        with self._lock:
            self._last_session_generation = retirement.new_epoch.generation
            if (
                self._destroyed
                or self._active_transition is not transition
                or self._state is not CaptureStateV1.ENTERING
            ):
                return False
            if (
                transition.bound_origin_epoch is None
                or retirement.new_epoch.session_instance_id
                != transition.bound_origin_epoch.session_instance_id
                or retirement.new_epoch.generation != transition.target_generation
            ):
                raise _TransitionFailureV1(CaptureFailureReasonV1.GENERATION_MISMATCH)
            transition.phase = CaptureTransitionPhaseV1.CLEANING
            self._state = CaptureStateV1.QUIESCING
            self._record_v1(SecurityAuditEventCodeV1.CAPTURE_QUIESCING)
            return True

    async def _drain_ack_wait_and_clear_v1(
        self,
        transition: _CaptureTransitionV1,
        retirement: GenerationRetirementV1,
        *,
        timeout_reason: CaptureFailureReasonV1,
        timeout_event: SecurityAuditEventCodeV1,
    ) -> None:
        drain_succeeded = False
        try:
            self._quiescence_drain_v1(retirement.new_epoch)
            drain_succeeded = True
        except Exception:  # noqa: BLE001 - failed drain cannot acknowledge
            drain_succeeded = False

        token = transition.cleanup_token
        acknowledged = (
            drain_succeeded
            and token is not None
            and self._work_controller.release_cleanup_v1(
                retirement.cleanup_fence,
                token,
                action=CleanupActionV1.ACK_CLEANUP,
            )
        )
        if acknowledged:
            transition.cleanup_token = None
        cleanup_succeeded = await self._work_controller.wait_for_cleanup_async_v1(
            retirement.cleanup_fence
        )
        if not cleanup_succeeded:
            self._record_v1(timeout_event)
            raise _TransitionFailureV1(timeout_reason)
        if not drain_succeeded or not acknowledged:
            raise _TransitionFailureV1(CaptureFailureReasonV1.QUIESCENCE_DRAIN_FAILED)

        status = self._work_controller.cleanup_status_v1(retirement.cleanup_fence)
        if (
            status is None
            or status.state is not RetiredGenerationCleanupStateV1.COMPLETE
            or status.outstanding_work_tokens != 0
            or status.outstanding_cleanup_tokens != 0
        ):
            raise _TransitionFailureV1(timeout_reason)
        try:
            self._semantic_cleanup_v1(retirement.new_epoch)
        except Exception:  # noqa: BLE001 - semantic uncertainty is fatal
            raise _TransitionFailureV1(
                CaptureFailureReasonV1.SEMANTIC_CLEANUP_FAILED
            ) from None

    def _publish_armed_v1(
        self,
        transition: _CaptureTransitionV1,
        retirement: GenerationRetirementV1,
    ) -> CaptureEpochV1 | None:
        if transition.capture_id is None:
            raise _TransitionFailureV1(CaptureFailureReasonV1.INTERNAL_FAILURE)
        published: list[CaptureEpochV1] = []
        candidate = CaptureEpochV1(
            session_epoch=retirement.new_epoch,
            capture_id=transition.capture_id,
            capture_seq=transition.capture_seq,
        )

        def publish_if_session_live() -> None:
            with self._lock:
                if (
                    self._destroyed
                    or self._shutdown_started
                    or self._active_transition is not transition
                    or self._state is not CaptureStateV1.QUIESCING
                    or self._fatal_failure is not None
                    or not self._quiescence_complete
                    or not self._feature_is_enabled_v1()
                    or not self._security_authority_is_usable_v1()
                    or self._isolation_controller.snapshot_v1().admission_open
                ):
                    return

                def publish_on_current_epoch() -> None:
                    cleanup = self._work_controller.cleanup_status_v1(
                        retirement.cleanup_fence
                    )
                    if (
                        cleanup is None
                        or cleanup.state is not RetiredGenerationCleanupStateV1.COMPLETE
                        or cleanup.outstanding_work_tokens != 0
                        or cleanup.outstanding_cleanup_tokens != 0
                    ):
                        return
                    self._capture_epoch = candidate
                    self._last_session_generation = candidate.session_epoch.generation
                    transition.phase = CaptureTransitionPhaseV1.VERIFYING
                    self._state = CaptureStateV1.ARMED
                    self._active_transition = None
                    self._failure_reason = None
                    self._record_v1(SecurityAuditEventCodeV1.CAPTURE_ARMED)
                    published.append(candidate)

                (
                    self._work_controller._perform_current_epoch_control_action_v1(
                        retirement.new_epoch,
                        publish_on_current_epoch,
                    )
                )

        if not self._run_if_session_live_v1(publish_if_session_live):
            return None
        return published[0] if published else None

    async def begin_capture_v1(self) -> CaptureEpochV1:
        """Quiesce normal application work and return only after ARMED."""

        transition = self._claim_begin_v1()
        try:
            await self._call_transition_hook_v1(CaptureTransitionPointV1.AFTER_ENTERING)
            async with self._serialized_operation_v1():
                self._require_active_v1(
                    transition,
                    CaptureStateV1.ENTERING,
                )
                transition.cleanup_token = (
                    self._work_controller.register_cleanup_participant_v1()
                )
                await self._call_transition_hook_v1(
                    CaptureTransitionPointV1.BEFORE_BEGIN_RETIREMENT
                )
                if not self._active_is_v1(transition):
                    self._work_controller.withdraw_cleanup_participant_v1(
                        transition.cleanup_token
                    )
                    transition.cleanup_token = None
                    raise _TransitionSupersededV1
                self._set_phase_v1(
                    transition,
                    CaptureTransitionPhaseV1.RETIRING,
                )
                retirement = await self._work_controller.retire_generation_async_v1(
                    GenerationRetirementReasonV1.CAPTURE_BEGIN
                )
                await self._call_transition_hook_v1(
                    CaptureTransitionPointV1.AFTER_BEGIN_RETIREMENT
                )
                published_quiescing = self._publish_quiescing_v1(
                    transition,
                    retirement,
                )
                if published_quiescing:
                    await self._call_transition_hook_v1(
                        CaptureTransitionPointV1.AFTER_QUIESCING
                    )
                await self._drain_ack_wait_and_clear_v1(
                    transition,
                    retirement,
                    timeout_reason=(CaptureFailureReasonV1.QUIESCENCE_TIMEOUT),
                    timeout_event=(SecurityAuditEventCodeV1.CAPTURE_QUIESCENCE_TIMEOUT),
                )
                self._require_active_v1(
                    transition,
                    CaptureStateV1.QUIESCING,
                )
                with self._lock:
                    self._quiescence_complete = True
                self._set_phase_v1(
                    transition,
                    CaptureTransitionPhaseV1.VERIFYING,
                )
                await self._call_transition_hook_v1(
                    CaptureTransitionPointV1.BEFORE_ARMED
                )
                capture_epoch = self._publish_armed_v1(
                    transition,
                    retirement,
                )
                if capture_epoch is None:
                    raise _TransitionFailureV1(
                        CaptureFailureReasonV1.SESSION_AUTHORITY_UNAVAILABLE
                    )
                return capture_epoch
        except _TransitionSupersededV1:
            self._record_v1(SecurityAuditEventCodeV1.CAPTURE_TRANSITION_REJECTED)
            raise CaptureTransitionRejectedV1(
                CaptureFailureReasonV1.STALE_TRANSITION
            ) from None
        except _TransitionFailureV1 as exception:
            try:
                self._fail_transition_v1(
                    transition,
                    exception.reason,
                )
            except _TransitionSupersededV1:
                raise CaptureTransitionRejectedV1(
                    CaptureFailureReasonV1.STALE_TRANSITION
                ) from None
            raise CaptureFailedClosedV1(exception.reason) from None
        except (
            SessionGenerationOverflowV1,
            WorkAdmissionDeniedV1,
        ):
            reason = CaptureFailureReasonV1.GENERATION_RETIREMENT_FAILED
            try:
                self._fail_transition_v1(transition, reason)
            except _TransitionSupersededV1:
                raise CaptureTransitionRejectedV1(
                    CaptureFailureReasonV1.STALE_TRANSITION
                ) from None
            raise CaptureFailedClosedV1(reason) from None
        except asyncio.CancelledError:
            try:
                self._fail_transition_v1(
                    transition,
                    CaptureFailureReasonV1.INTERNAL_FAILURE,
                )
            except _TransitionSupersededV1:
                pass
            raise
        except Exception:  # noqa: BLE001 - stable fail-closed API
            reason = CaptureFailureReasonV1.INTERNAL_FAILURE
            try:
                self._fail_transition_v1(transition, reason)
            except _TransitionSupersededV1:
                raise CaptureTransitionRejectedV1(
                    CaptureFailureReasonV1.STALE_TRANSITION
                ) from None
            raise CaptureFailedClosedV1(reason) from None
        finally:
            self._close_transition_cleanup_token_v1(transition)

    def _claim_end_v1(
        self,
        capture_epoch: CaptureEpochV1 | None,
        capture_seq: int | None,
    ) -> _CaptureTransitionV1:
        claimed: list[_CaptureTransitionV1] = []
        rejected: list[CaptureFailureReasonV1] = []

        def claim() -> None:
            with self._lock:
                if self._destroyed or self._shutdown_started:
                    rejected.append(CaptureFailureReasonV1.SESSION_SHUTDOWN)
                    return
                state = self._state
                if state is CaptureStateV1.IDLE:
                    rejected.append(CaptureFailureReasonV1.INVALID_STATE)
                    return
                if state is CaptureStateV1.ENDING:
                    rejected.append(CaptureFailureReasonV1.CAPTURE_BUSY)
                    return
                if state not in {
                    CaptureStateV1.ENTERING,
                    CaptureStateV1.QUIESCING,
                    CaptureStateV1.ARMED,
                    CaptureStateV1.FAILED_CLOSED,
                }:
                    rejected.append(CaptureFailureReasonV1.INVALID_STATE)
                    return

                canonical_epoch = self._capture_epoch
                if canonical_epoch is not None:
                    if capture_epoch is not canonical_epoch:
                        rejected.append(CaptureFailureReasonV1.CAPTURE_EPOCH_MISMATCH)
                        return
                    if (
                        capture_seq is not None
                        and capture_seq != canonical_epoch.capture_seq
                    ):
                        rejected.append(
                            CaptureFailureReasonV1.CAPTURE_SEQUENCE_MISMATCH
                        )
                        return
                else:
                    if capture_epoch is not None:
                        rejected.append(CaptureFailureReasonV1.CAPTURE_EPOCH_MISMATCH)
                        return
                    if capture_seq != self._capture_seq:
                        rejected.append(
                            CaptureFailureReasonV1.CAPTURE_SEQUENCE_MISMATCH
                        )
                        return

                superseded = self._active_transition
                if (
                    superseded is not None
                    and superseded.kind is CaptureTransitionKindV1.BEGIN
                ):
                    origin = superseded.bound_origin_epoch
                    if origin is None or superseded.target_generation is None:
                        rejected.append(CaptureFailureReasonV1.GENERATION_MISMATCH)
                        return
                    candidates = (
                        origin,
                        SessionEpochV1(
                            origin.session_instance_id,
                            superseded.target_generation,
                        ),
                    )
                elif canonical_epoch is not None:
                    candidates = (canonical_epoch.session_epoch,)
                else:
                    candidates = (self._work_controller.current_epoch_v1(),)

                transition = _CaptureTransitionV1(
                    transition_id=new_uuid7_v1(),
                    kind=CaptureTransitionKindV1.END,
                    capture_id=(
                        canonical_epoch.capture_id
                        if canonical_epoch is not None
                        else self._capture_id
                    ),
                    capture_seq=self._capture_seq,
                    origin_candidates=candidates,
                    bound_origin_epoch=None,
                    target_generation=None,
                    phase=CaptureTransitionPhaseV1.CLAIMED,
                    superseded_transition_id=(
                        superseded.transition_id if superseded is not None else None
                    ),
                )
                self._active_transition = transition
                self._state = CaptureStateV1.ENDING
                self._quiescence_complete = False
                self._record_v1(SecurityAuditEventCodeV1.CAPTURE_ENDING)
                claimed.append(transition)

        if not self._run_if_session_live_v1(claim):
            reason = CaptureFailureReasonV1.SESSION_AUTHORITY_UNAVAILABLE
            if self._enter_failed_closed_v1(None, reason):
                self._request_failure_termination_v1()
                raise CaptureFailedClosedV1(reason)
            self._reject_v1(CaptureFailureReasonV1.SESSION_SHUTDOWN)
        if claimed:
            return claimed[0]
        self._reject_v1(
            rejected[0] if rejected else CaptureFailureReasonV1.INTERNAL_FAILURE
        )
        raise AssertionError("unreachable")

    def _bind_end_origin_v1(
        self,
        transition: _CaptureTransitionV1,
    ) -> SessionEpochV1:
        with self._lock:
            if (
                self._destroyed
                or self._active_transition is not transition
                or self._state is not CaptureStateV1.ENDING
            ):
                raise _TransitionSupersededV1
            current = self._work_controller.current_epoch_v1()
            if all(current != candidate for candidate in transition.origin_candidates):
                raise _TransitionFailureV1(CaptureFailureReasonV1.GENERATION_MISMATCH)
            transition.bound_origin_epoch = current
            transition.target_generation = current.generation + 1
            transition.phase = CaptureTransitionPhaseV1.RETIRING
            return current

    def _invalidate_capture_epoch_v1(
        self,
        transition: _CaptureTransitionV1,
        new_epoch: SessionEpochV1,
    ) -> None:
        with self._lock:
            if (
                self._destroyed
                or self._active_transition is not transition
                or self._state is not CaptureStateV1.ENDING
            ):
                raise _TransitionSupersededV1
            if (
                transition.bound_origin_epoch is None
                or new_epoch.session_instance_id
                != transition.bound_origin_epoch.session_instance_id
                or new_epoch.generation != transition.target_generation
            ):
                raise _TransitionFailureV1(CaptureFailureReasonV1.GENERATION_MISMATCH)
            self._capture_epoch = None
            self._last_session_generation = new_epoch.generation
            transition.phase = CaptureTransitionPhaseV1.VERIFYING

    def _publish_resumed_v1(
        self,
        transition: _CaptureTransitionV1,
        retirement: GenerationRetirementV1,
    ) -> bool:
        resumed: list[bool] = []

        def publish_if_session_live() -> None:
            with self._lock:
                if (
                    self._destroyed
                    or self._shutdown_started
                    or self._active_transition is not transition
                    or self._state is not CaptureStateV1.ENDING
                    or self._capture_epoch is not None
                    or not self._feature_is_enabled_v1()
                    or not self._security_authority_is_usable_v1()
                    or self._isolation_controller.snapshot_v1().admission_open
                ):
                    return

                def resume_on_current_epoch() -> None:
                    cleanup = self._work_controller.cleanup_status_v1(
                        retirement.cleanup_fence
                    )
                    if (
                        cleanup is None
                        or cleanup.state is not RetiredGenerationCleanupStateV1.COMPLETE
                        or cleanup.outstanding_work_tokens != 0
                        or cleanup.outstanding_cleanup_tokens != 0
                        or not self._isolation_controller.reopen_v1()
                    ):
                        return
                    self._state = CaptureStateV1.IDLE
                    self._active_transition = None
                    self._capture_id = None
                    self._failure_reason = None
                    self._fatal_failure = None
                    self._quiescence_complete = False
                    self._last_session_generation = retirement.new_epoch.generation
                    self._record_v1(SecurityAuditEventCodeV1.CAPTURE_RESUMED)
                    resumed.append(True)

                (
                    self._work_controller._perform_current_epoch_control_action_v1(
                        retirement.new_epoch,
                        resume_on_current_epoch,
                    )
                )

        if not self._run_if_session_live_v1(publish_if_session_live):
            return False
        return bool(resumed)

    async def end_capture_v1(
        self,
        capture_epoch: CaptureEpochV1 | None = None,
        *,
        capture_seq: int | None = None,
    ) -> CaptureStatusV1:
        """Retire capture mode and reopen only after a fresh cleanup barrier."""

        transition = self._claim_end_v1(
            capture_epoch,
            capture_seq,
        )
        try:
            await self._call_transition_hook_v1(CaptureTransitionPointV1.AFTER_ENDING)
            async with self._serialized_operation_v1():
                self._require_active_v1(
                    transition,
                    CaptureStateV1.ENDING,
                )
                origin_epoch = self._bind_end_origin_v1(transition)
                transition.cleanup_token = (
                    self._work_controller.register_cleanup_participant_v1()
                )
                await self._call_transition_hook_v1(
                    CaptureTransitionPointV1.BEFORE_END_RETIREMENT
                )
                if not self._active_is_v1(transition):
                    self._work_controller.withdraw_cleanup_participant_v1(
                        transition.cleanup_token
                    )
                    transition.cleanup_token = None
                    raise _TransitionSupersededV1
                if self._work_controller.current_epoch_v1() is not origin_epoch:
                    raise _TransitionFailureV1(
                        CaptureFailureReasonV1.GENERATION_MISMATCH
                    )
                retirement = await self._work_controller.retire_generation_async_v1(
                    GenerationRetirementReasonV1.CAPTURE_END
                )
                await self._call_transition_hook_v1(
                    CaptureTransitionPointV1.AFTER_END_RETIREMENT
                )
                self._set_phase_v1(
                    transition,
                    CaptureTransitionPhaseV1.CLEANING,
                )
                await self._drain_ack_wait_and_clear_v1(
                    transition,
                    retirement,
                    timeout_reason=(CaptureFailureReasonV1.CLEANUP_TIMEOUT),
                    timeout_event=(SecurityAuditEventCodeV1.CAPTURE_CLEANUP_TIMEOUT),
                )
                self._invalidate_capture_epoch_v1(
                    transition,
                    retirement.new_epoch,
                )
                await self._call_transition_hook_v1(
                    CaptureTransitionPointV1.BEFORE_RESUME
                )
                if not self._publish_resumed_v1(
                    transition,
                    retirement,
                ):
                    raise _TransitionFailureV1(
                        CaptureFailureReasonV1.RESUME_BARRIER_FAILED
                    )
                return self.snapshot_v1()
        except _TransitionSupersededV1:
            self._record_v1(SecurityAuditEventCodeV1.CAPTURE_TRANSITION_REJECTED)
            raise CaptureTransitionRejectedV1(
                CaptureFailureReasonV1.STALE_TRANSITION
            ) from None
        except _TransitionFailureV1 as exception:
            try:
                self._fail_transition_v1(
                    transition,
                    exception.reason,
                )
            except _TransitionSupersededV1:
                raise CaptureTransitionRejectedV1(
                    CaptureFailureReasonV1.STALE_TRANSITION
                ) from None
            raise CaptureFailedClosedV1(exception.reason) from None
        except (
            SessionGenerationOverflowV1,
            WorkAdmissionDeniedV1,
        ):
            reason = CaptureFailureReasonV1.GENERATION_RETIREMENT_FAILED
            try:
                self._fail_transition_v1(transition, reason)
            except _TransitionSupersededV1:
                raise CaptureTransitionRejectedV1(
                    CaptureFailureReasonV1.STALE_TRANSITION
                ) from None
            raise CaptureFailedClosedV1(reason) from None
        except asyncio.CancelledError:
            try:
                self._fail_transition_v1(
                    transition,
                    CaptureFailureReasonV1.INTERNAL_FAILURE,
                )
            except _TransitionSupersededV1:
                pass
            raise
        except Exception:  # noqa: BLE001 - stable fail-closed API
            reason = CaptureFailureReasonV1.INTERNAL_FAILURE
            try:
                self._fail_transition_v1(transition, reason)
            except _TransitionSupersededV1:
                raise CaptureTransitionRejectedV1(
                    CaptureFailureReasonV1.STALE_TRANSITION
                ) from None
            raise CaptureFailedClosedV1(reason) from None
        finally:
            self._close_transition_cleanup_token_v1(transition)

    def _fail_closed_for_test_v1(
        self,
        reason: CaptureFailureReasonV1 = (CaptureFailureReasonV1.INTERNAL_FAILURE),
    ) -> None:
        with self._lock:
            transition = self._active_transition
        if self._enter_failed_closed_v1(transition, reason):
            self._request_failure_termination_v1()

    def _start_shutdown_v1(self) -> None:
        with self._lock:
            if self._destroyed:
                return
            self._shutdown_started = True
            was_active = self._state is not CaptureStateV1.IDLE
            self._active_transition = None
            self._capture_epoch = None
            self._capture_id = None
            self._quiescence_complete = False
            self._isolation_controller.destroy_v1()
            if was_active:
                self._state = CaptureStateV1.FAILED_CLOSED
                self._failure_reason = CaptureFailureReasonV1.SESSION_SHUTDOWN
                self._fatal_failure = self._failure_reason
                self._record_v1(SecurityAuditEventCodeV1.CAPTURE_FAILED_CLOSED)
            self._destroyed = True

    def shutdown_v1(self) -> bool:
        """Destroy capture authority before synchronous session teardown."""

        self._start_shutdown_v1()
        return self._operation_idle.wait(
            timeout=self._work_controller.cleanup_timeout_seconds_v1()
        )

    async def shutdown_async_v1(self) -> bool:
        """Destroy capture authority without retaining a lock across awaits."""

        self._start_shutdown_v1()
        deadline = time.monotonic() + self._work_controller.cleanup_timeout_seconds_v1()
        while not self._operation_idle.is_set():
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.01)
        return True

    def snapshot_v1(self) -> CaptureStatusV1:
        try:
            generation = self._work_controller.current_epoch_v1().generation
        except Exception:  # noqa: BLE001 - return last redacted generation
            with self._lock:
                generation = self._last_session_generation
        with self._lock:
            transition = self._active_transition
            capture_id = (
                self._capture_epoch.capture_id
                if self._capture_epoch is not None
                else self._capture_id
            )
            return CaptureStatusV1(
                state=self._state,
                capture_id=capture_id,
                capture_seq=self._capture_seq,
                session_generation=generation,
                transition_id=(
                    transition.transition_id if transition is not None else None
                ),
                transition_kind=(transition.kind if transition is not None else None),
                transition_phase=(transition.phase if transition is not None else None),
                failure_reason_code=self._failure_reason,
                normal_application_admission_open=(self._isolation_view.is_open_v1()),
                quiescence_complete=self._quiescence_complete,
                shutdown_started=self._shutdown_started,
                destroyed=self._destroyed,
            )


__all__ = [
    "CaptureCoordinatorV1",
    "CaptureFailedClosedV1",
    "CaptureTransitionRejectedV1",
]

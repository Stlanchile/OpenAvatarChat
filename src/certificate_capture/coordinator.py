"""Session-owned Secure Certificate Capture V1 Milestone 4A coordinator."""

from __future__ import annotations

import asyncio
import hmac
import inspect
import math
import threading
import time
import uuid
from collections.abc import Callable, Coroutine
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any, TypeVar

from certificate_capture.capabilities import (
    ActiveCaptureCapabilityV1,
    CaptureCapabilityAuthorityV1,
    CaptureCapabilityBindingV1,
)
from certificate_capture.contracts.admission_notice import (
    AdmissionNoticeExtractionV1,
    StoredAdmissionNoticeExtractionV1,
)
from certificate_capture.contracts.admission_notice_template import (
    HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1,
)
from certificate_capture.contracts.evidence import EvidenceFrameV1
from certificate_capture.contracts.inference import InferenceIdentityV1
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    StoredOcrResultV1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.extraction.service import (
    AdmissionNoticeExtractionFailureReasonV1,
    AdmissionNoticeExtractionServiceErrorV1,
    PrivateAdmissionNoticeExtractionServiceV1,
)
from certificate_capture.isolation import (
    NormalApplicationAdmissionViewV1,
    _create_normal_mode_isolation_v1,
    _NormalModeIsolationControllerV1,
)
from certificate_capture.ocr.client import (
    OcrDeploymentConfigV1,
    OcrTransportClientV1,
)
from certificate_capture.ocr.protocol import (
    MAX_OCR_FRAMES_PER_OPERATION_V1,
    OcrFailureReasonV1,
    OcrHealthStatusV1,
    OcrServiceErrorV1,
)
from certificate_capture.ocr.service import PrivateOcrServiceV1
from certificate_capture.private_authority import (
    PrivateEvidenceAccessKindV1,
    PrivateEvidenceAccessV1,
    PrivateEvidenceAuthorityV1,
)
from certificate_capture.private_store import (
    PrivateEvidenceStoreErrorV1,
    PrivateEvidenceStoreReasonV1,
    PrivateEvidenceStoreV1,
)
from certificate_capture.processor import CaptureProcessorV1
from certificate_capture.protocol import (
    CAPTURE_BEGIN_MINIMUM_SESSION_REMAINING_SECONDS_V1,
    CAPTURE_INACTIVITY_SECONDS_V1,
    FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1,
    MAX_CAPTURE_ENCODED_BYTES_V1,
    MAX_CAPTURE_FRAMES_V1,
    MAX_CONCURRENT_UPLOADS_PER_CAPTURE_V1,
    MAX_OUTSTANDING_CONTROL_MUTATIONS_V1,
    MINIMUM_MOCK_UNIQUE_FRAMES_V1,
    BeginCaptureGrantV1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
    CapturePublicStatusV1,
    EndCaptureResultV1,
    FrameUploadPermitV1,
    FrameUploadResultV1,
    MockProcessingInputV1,
    SealOutcomeV1,
    SealReasonCodeV1,
    SealResultV1,
    ValidatedJpegFrameV1,
)
from certificate_capture.replay import (
    ControlOperationV1,
    ControlReplayLedgerV1,
    ControlReplayRecordV1,
    canonical_control_request_digest_v1,
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
    RetiredGenerationCleanupFenceV1,
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
from chat_engine.security.work_fence import (
    RegisteredWorkV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

_ControlResultV1 = TypeVar("_ControlResultV1")


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
    cleanup_fence: RetiredGenerationCleanupFenceV1 | None = None
    superseded_transition_id: uuid.UUID | None = None

    def __repr__(self) -> str:
        return "_CaptureTransitionV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class _BeginReplayResultV1:
    capture_epoch: CaptureEpochV1
    capability_binding: CaptureCapabilityBindingV1

    def __repr__(self) -> str:
        return "_BeginReplayResultV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _FrameRecordV1:
    evidence_frame: EvidenceFrameV1
    accepted_at_monotonic: float
    result: FrameUploadResultV1

    @property
    def frame_seq(self) -> int:
        return self.evidence_frame.frame_seq

    @property
    def encoded_size(self) -> int:
        return self.evidence_frame.encoded_size

    @property
    def decoded_width(self) -> int:
        return self.evidence_frame.canonical_width

    @property
    def decoded_height(self) -> int:
        return self.evidence_frame.canonical_height

    @property
    def sha256_digest(self) -> bytes:
        return self.evidence_frame.sha256

    def __repr__(self) -> str:
        return "_FrameRecordV1(<private-metadata>)"


@dataclass(frozen=True, slots=True, repr=False)
class _DetachedPrivateCaptureWorkV1:
    capture_epoch: CaptureEpochV1 | None
    ocr_service: PrivateOcrServiceV1 | None
    extraction_service: PrivateAdmissionNoticeExtractionServiceV1
    timer_task: asyncio.Task[None] | None
    processor_task: asyncio.Task[None] | None
    timer_work: RegisteredWorkV1 | None
    processor_work: RegisteredWorkV1 | None

    def __repr__(self) -> str:
        return "_DetachedPrivateCaptureWorkV1(<private>)"


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
        "_accepted_frame_bytes_v1",
        "_active_capture_capability_v1",
        "_active_frame_upload_permits_v1",
        "_active_transition",
        "_admission_extraction_service_v1",
        "_audit",
        "_capability_authority_v1",
        "_capture_epoch",
        "_capture_id",
        "_capture_seq",
        "_control_lock_v1",
        "_control_waiters_v1",
        "_destroyed",
        "_failure_reason",
        "_failure_terminator_v1",
        "_fatal_failure",
        "_feature_enabled_v1",
        "_frame_metadata_commit_hook_for_test_v1",
        "_frame_records_v1",
        "_inactivity_deadline_epoch_v1",
        "_inactivity_deadline_monotonic_v1",
        "_inactivity_event_v1",
        "_inactivity_revision_v1",
        "_inactivity_task_v1",
        "_inactivity_work_v1",
        "_isolation_controller",
        "_isolation_view",
        "_last_seal_result_v1",
        "_last_session_generation",
        "_lock",
        "_monotonic_clock_v1",
        "_ocr_service_v1",
        "_operation_idle",
        "_operation_lock",
        "_private_evidence_authority_v1",
        "_private_evidence_store_v1",
        "_private_store_cleanup_access_v1",
        "_private_store_cleanup_token_v1",
        "_private_store_delete_access_v1",
        "_private_store_read_access_v1",
        "_private_store_write_access_v1",
        "_processor_task_v1",
        "_processor_work_v1",
        "_profile_id_v1",
        "_quiescence_complete",
        "_quiescence_drain_v1",
        "_replay_ledger_v1",
        "_seal_attempt_seq_v1",
        "_security_authority_usable_v1",
        "_semantic_cleanup_v1",
        "_session_live_action_v1",
        "_shutdown_started",
        "_state",
        "_termination_requested",
        "_test_processor_v1",
        "_transition_hook_for_test_v1",
        "_unique_frame_digests_v1",
        "_wall_clock_v1",
        "_work_controller",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        work_controller: SessionWorkControllerV1,
        isolation_controller: _NormalModeIsolationControllerV1,
        isolation_view: NormalApplicationAdmissionViewV1,
        private_evidence_authority_v1: PrivateEvidenceAuthorityV1,
        feature_enabled_v1: Callable[[], bool],
        security_authority_usable_v1: Callable[[], bool],
        session_live_action_v1: SessionLiveActionV1,
        quiescence_drain_v1: QuiescenceDrainV1,
        semantic_cleanup_v1: SemanticCleanupV1,
        failure_terminator_v1: FailureTerminatorV1 | None,
        test_processor_v1: CaptureProcessorV1 | None = None,
        wall_clock_v1: Callable[[], float] = time.time,
        monotonic_clock_v1: Callable[[], float] = time.monotonic,
    ) -> None:
        if _construction_authority_v1 is not _COORDINATOR_CONSTRUCTION_AUTHORITY_V1:
            raise RuntimeError("capture coordinator construction denied")
        if not isinstance(work_controller, SessionWorkControllerV1):
            raise TypeError("work_controller must be SessionWorkControllerV1")
        if not isinstance(
            private_evidence_authority_v1,
            PrivateEvidenceAuthorityV1,
        ):
            raise TypeError(
                "private_evidence_authority_v1 must be "
                "PrivateEvidenceAuthorityV1"
            )
        if test_processor_v1 is not None and not callable(
            getattr(test_processor_v1, "process_capture_v1", None)
        ):
            raise TypeError("test processor must implement process_capture_v1")
        self._work_controller = work_controller
        self._isolation_controller = isolation_controller
        self._isolation_view = isolation_view
        self._feature_enabled_v1 = feature_enabled_v1
        self._security_authority_usable_v1 = security_authority_usable_v1
        self._session_live_action_v1 = session_live_action_v1
        self._quiescence_drain_v1 = quiescence_drain_v1
        self._semantic_cleanup_v1 = semantic_cleanup_v1
        self._failure_terminator_v1 = failure_terminator_v1
        self._test_processor_v1 = test_processor_v1
        self._wall_clock_v1 = wall_clock_v1
        self._monotonic_clock_v1 = monotonic_clock_v1
        self._lock = threading.RLock()
        self._operation_lock = asyncio.Lock()
        self._control_lock_v1 = asyncio.Lock()
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
        self._frame_metadata_commit_hook_for_test_v1: (
            Callable[[], None] | None
        ) = None
        self._capability_authority_v1 = CaptureCapabilityAuthorityV1()
        self._active_capture_capability_v1: (
            ActiveCaptureCapabilityV1 | None
        ) = None
        self._replay_ledger_v1 = ControlReplayLedgerV1()
        self._frame_records_v1: dict[int, _FrameRecordV1] = {}
        self._unique_frame_digests_v1: set[bytes] = set()
        self._accepted_frame_bytes_v1 = 0
        self._active_frame_upload_permits_v1: set[uuid.UUID] = set()
        self._profile_id_v1: str | None = None
        self._seal_attempt_seq_v1 = 0
        self._last_seal_result_v1: SealResultV1 | None = None
        self._inactivity_deadline_epoch_v1: float | None = None
        self._inactivity_deadline_monotonic_v1: float | None = None
        self._inactivity_revision_v1 = 0
        self._inactivity_event_v1: asyncio.Event | None = None
        self._inactivity_task_v1: asyncio.Task[None] | None = None
        self._inactivity_work_v1: RegisteredWorkV1 | None = None
        self._processor_task_v1: asyncio.Task[None] | None = None
        self._processor_work_v1: RegisteredWorkV1 | None = None
        self._ocr_service_v1: PrivateOcrServiceV1 | None = None
        self._control_waiters_v1 = 0
        self._private_evidence_authority_v1 = (
            private_evidence_authority_v1
        )
        self._private_store_write_access_v1 = (
            private_evidence_authority_v1._access_for_core_v1(
                PrivateEvidenceAccessKindV1.WRITE
            )
        )
        self._private_store_read_access_v1 = (
            private_evidence_authority_v1._access_for_core_v1(
                PrivateEvidenceAccessKindV1.READ
            )
        )
        self._private_store_delete_access_v1 = (
            private_evidence_authority_v1._access_for_core_v1(
                PrivateEvidenceAccessKindV1.DELETE
            )
        )
        self._private_store_cleanup_access_v1 = (
            private_evidence_authority_v1._access_for_core_v1(
                PrivateEvidenceAccessKindV1.CLEANUP
            )
        )
        self._private_store_cleanup_token_v1: CleanupTokenV1 | None = None
        self._private_evidence_store_v1 = (
            PrivateEvidenceStoreV1._create_for_session_v1(
                private_authority=private_evidence_authority_v1,
                work_controller=work_controller,
                capture_is_live_v1=(
                    self._private_store_operation_is_live_v1
                ),
            )
        )
        self._admission_extraction_service_v1 = (
            PrivateAdmissionNoticeExtractionServiceV1
            ._create_for_coordinator_v1(
                private_authority=private_evidence_authority_v1,
                store=self._private_evidence_store_v1,
                read_access=self._private_store_read_access_v1,
                write_access=self._private_store_write_access_v1,
                work_controller=work_controller,
                capture_is_live_v1=(
                    self
                    ._private_admission_extraction_operation_is_live_v1
                ),
                fatal_store_failure_v1=self._fail_protocol_runtime_v1,
                wall_clock_v1=self._wall_clock_v1,
            )
        )

    @classmethod
    def _create_for_session_v1(
        cls,
        *,
        work_controller: SessionWorkControllerV1,
        private_evidence_authority_v1: PrivateEvidenceAuthorityV1,
        feature_enabled_v1: Callable[[], bool],
        security_authority_usable_v1: Callable[[], bool],
        session_live_action_v1: SessionLiveActionV1,
        quiescence_drain_v1: QuiescenceDrainV1,
        semantic_cleanup_v1: SemanticCleanupV1,
        failure_terminator_v1: FailureTerminatorV1 | None = None,
        _test_processor_v1: CaptureProcessorV1 | None = None,
        _wall_clock_for_test_v1: Callable[[], float] | None = None,
        _monotonic_clock_for_test_v1: Callable[[], float] | None = None,
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
            private_evidence_authority_v1=(
                private_evidence_authority_v1
            ),
            feature_enabled_v1=feature_enabled_v1,
            security_authority_usable_v1=(security_authority_usable_v1),
            session_live_action_v1=session_live_action_v1,
            quiescence_drain_v1=quiescence_drain_v1,
            semantic_cleanup_v1=semantic_cleanup_v1,
            failure_terminator_v1=failure_terminator_v1,
            test_processor_v1=_test_processor_v1,
            wall_clock_v1=(
                _wall_clock_for_test_v1
                if _wall_clock_for_test_v1 is not None
                else time.time
            ),
            monotonic_clock_v1=(
                _monotonic_clock_for_test_v1
                if _monotonic_clock_for_test_v1 is not None
                else time.monotonic
            ),
        )
        return coordinator, isolation_view

    def _set_transition_hook_for_test_v1(
        self,
        hook: TransitionHookV1 | None,
    ) -> None:
        with self._lock:
            self._transition_hook_for_test_v1 = hook

    def _set_frame_metadata_commit_hook_for_test_v1(
        self,
        hook: Callable[[], None] | None,
    ) -> None:
        with self._lock:
            self._frame_metadata_commit_hook_for_test_v1 = hook

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

    def _read_protocol_clocks_v1(self) -> tuple[float, float]:
        try:
            now_epoch = self._wall_clock_v1()
            now_monotonic = self._monotonic_clock_v1()
        except Exception:  # noqa: BLE001 - injected/system clocks fail closed
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
            ) from None
        if (
            isinstance(now_epoch, bool)
            or not isinstance(now_epoch, (int, float))
            or not math.isfinite(now_epoch)
            or isinstance(now_monotonic, bool)
            or not isinstance(now_monotonic, (int, float))
            or not math.isfinite(now_monotonic)
        ):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
            )
        return float(now_epoch), float(now_monotonic)

    def _claim_control_waiter_v1(self) -> None:
        with self._lock:
            if (
                self._destroyed
                or self._shutdown_started
                or self._control_waiters_v1
                >= MAX_OUTSTANDING_CONTROL_MUTATIONS_V1
            ):
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CONTROL_BUSY
                )
            self._control_waiters_v1 += 1

    def _release_control_waiter_v1(self) -> None:
        with self._lock:
            if self._control_waiters_v1 > 0:
                self._control_waiters_v1 -= 1

    @staticmethod
    def _protocol_error_for_lifecycle_v1(
        exception: BaseException,
    ) -> CaptureProtocolErrorV1:
        if isinstance(exception, CaptureProtocolErrorV1):
            return exception
        reason_code = getattr(exception, "reason_code", None)
        if reason_code in {
            CaptureFailureReasonV1.CAPTURE_BUSY.value,
            CaptureFailureReasonV1.INVALID_STATE.value,
            CaptureFailureReasonV1.CAPTURE_EPOCH_MISMATCH.value,
            CaptureFailureReasonV1.CAPTURE_SEQUENCE_MISMATCH.value,
            CaptureFailureReasonV1.STALE_TRANSITION.value,
        }:
            reason = CaptureProtocolReasonV1.CAPTURE_BUSY
        elif isinstance(exception, CaptureFailedClosedV1):
            reason = CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
        elif reason_code in {
            CaptureFailureReasonV1.SESSION_AUTHORITY_UNAVAILABLE.value,
            CaptureFailureReasonV1.SESSION_SHUTDOWN.value,
        }:
            reason = CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
        else:
            reason = CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
        return CaptureProtocolErrorV1(reason)

    async def begin_capture_protocol_v1(
        self,
        *,
        request_id: uuid.UUID,
        control_seq: int,
        profile_id: str,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        session_expires_at_epoch_seconds: float,
    ) -> BeginCaptureGrantV1:
        """Replay-protected Begin that delegates quiescence to Milestone 4A."""

        if profile_id != HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.UNSUPPORTED_PROFILE
            )
        await self._expire_active_capture_before_control_v1()
        request_digest = canonical_control_request_digest_v1(
            operation=ControlOperationV1.BEGIN,
            request_id=request_id,
            control_seq=control_seq,
            profile_id=profile_id,
        )
        self._claim_control_waiter_v1()
        try:
            async with self._control_lock_v1:
                replayed_result: _BeginReplayResultV1 | None = None
                with self._lock:
                    record, replayed = self._replay_ledger_v1.lookup_or_claim_v1(
                        operation=ControlOperationV1.BEGIN,
                        request_id=request_id,
                        control_seq=control_seq,
                        request_digest=request_digest,
                    )
                    if replayed:
                        replay_result = self._replay_ledger_v1.replay_result_v1(
                            record
                        )
                        if not isinstance(replay_result, _BeginReplayResultV1):
                            raise CaptureProtocolErrorV1(
                                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
                            )
                        replayed_result = replay_result
                if replayed_result is not None:
                    return self._grant_for_live_begin_replay_v1(
                        replayed_result,
                        session_id=session_id,
                        owner_issuer=owner_issuer,
                        owner_subject=owner_subject,
                    )

                async def execute_begin_v1() -> _BeginReplayResultV1:
                    now_epoch, _ = self._read_protocol_clocks_v1()
                    remaining = session_expires_at_epoch_seconds - now_epoch
                    if (
                        not math.isfinite(remaining)
                        or remaining
                        < CAPTURE_BEGIN_MINIMUM_SESSION_REMAINING_SECONDS_V1
                    ):
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.SESSION_LIFETIME_INSUFFICIENT
                        )
                    capture_epoch = await self.begin_capture_v1()
                    return await self._activate_protocol_capture_v1(
                        capture_epoch=capture_epoch,
                        profile_id=profile_id,
                        session_id=session_id,
                        owner_issuer=owner_issuer,
                        owner_subject=owner_subject,
                        session_expires_at_epoch_seconds=(
                            session_expires_at_epoch_seconds
                        ),
                    )

                try:
                    replay_result, caller_cancelled = (
                        await self._await_control_operation_to_completion_v1(
                            execute_begin_v1()
                        )
                    )
                except asyncio.CancelledError:
                    with self._lock:
                        self._replay_ledger_v1.complete_error_v1(
                            record,
                            CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED,
                        )
                    raise
                except Exception as exception:  # noqa: BLE001
                    protocol_error = self._protocol_error_for_lifecycle_v1(
                        exception
                    )
                    with self._lock:
                        self._replay_ledger_v1.complete_error_v1(
                            record,
                            protocol_error.reason,
                        )
                    raise protocol_error from None

                with self._lock:
                    record.authorization_binding = (
                        replay_result.capability_binding
                    )
                    self._replay_ledger_v1.complete_result_v1(
                        record,
                        replay_result,
                    )
                if caller_cancelled:
                    raise asyncio.CancelledError
                return self._grant_for_live_begin_replay_v1(
                    replay_result,
                    session_id=session_id,
                    owner_issuer=owner_issuer,
                    owner_subject=owner_subject,
                )
        finally:
            self._release_control_waiter_v1()

    def _grant_for_live_begin_replay_v1(
        self,
        replay_result: _BeginReplayResultV1,
        *,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
    ) -> BeginCaptureGrantV1:
        now_epoch, now_monotonic = self._read_protocol_clocks_v1()
        grants: list[BeginCaptureGrantV1] = []

        def authorize() -> None:
            with self._lock:
                capture_epoch = replay_result.capture_epoch
                if (
                    self._destroyed
                    or self._shutdown_started
                    or self._fatal_failure is not None
                    or self._capture_epoch is not capture_epoch
                    or self._state
                    not in {
                        CaptureStateV1.ARMED,
                        CaptureStateV1.CAPTURING,
                        CaptureStateV1.BUILDING_ASSERTIONS,
                        CaptureStateV1.READY,
                    }
                    or self._work_controller.current_epoch_v1()
                    != capture_epoch.session_epoch
                    or not self._feature_is_enabled_v1()
                    or not self._security_authority_is_usable_v1()
                    or self._inactivity_deadline_monotonic_v1 is None
                    or now_monotonic
                    >= self._inactivity_deadline_monotonic_v1
                    or not self._capability_authority_v1.binding_is_live_v1(
                        self._active_capture_capability_v1,
                        binding=replay_result.capability_binding,
                        session_id=session_id,
                        owner_issuer=owner_issuer,
                        owner_subject=owner_subject,
                        capture_epoch=capture_epoch,
                        now_epoch_seconds=now_epoch,
                        now_monotonic=now_monotonic,
                    )
                ):
                    return
                grants.append(
                    BeginCaptureGrantV1(
                        capture_epoch=capture_epoch,
                        capture_capability=(
                            self._capability_authority_v1.render_for_replay_v1(
                                replay_result.capability_binding
                            )
                        ),
                        expires_at_epoch_seconds=(
                            replay_result.capability_binding
                            .expires_at_epoch_seconds
                        ),
                    )
                )

        if not self._run_if_session_live_v1(authorize) or not grants:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return grants[0]

    async def _activate_protocol_capture_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        profile_id: str,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        session_expires_at_epoch_seconds: float,
    ) -> _BeginReplayResultV1:
        now_epoch, now_monotonic = self._read_protocol_clocks_v1()
        capability_lifetime = session_expires_at_epoch_seconds - now_epoch
        if capability_lifetime <= 0:
            self._fail_protocol_runtime_v1()
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
            )
        binding = self._capability_authority_v1.create_binding_v1(
            session_id=session_id,
            owner_issuer=owner_issuer,
            owner_subject=owner_subject,
            capture_epoch=capture_epoch,
            expires_at_epoch_seconds=session_expires_at_epoch_seconds,
            expires_at_monotonic=now_monotonic + capability_lifetime,
        )
        active_capability, _ = self._capability_authority_v1.activate_v1(binding)
        inactivity_deadline_monotonic = min(
            now_monotonic + CAPTURE_INACTIVITY_SECONDS_V1,
            binding.expires_at_monotonic,
        )
        if inactivity_deadline_monotonic <= now_monotonic:
            self._fail_protocol_runtime_v1()
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
            )

        try:
            inactivity_work = self._work_controller.register_work_v1(
                WorkOperationKindV1.CAPTURE_INACTIVITY_TIMER,
                binding.expires_at_monotonic
                + self._work_controller.cleanup_timeout_seconds_v1(),
                _admission_guard_v1=(
                    lambda: self._capture_work_admission_is_open_v1(
                        capture_epoch,
                        {
                            CaptureStateV1.ARMED,
                            CaptureStateV1.CAPTURING,
                            CaptureStateV1.BUILDING_ASSERTIONS,
                            CaptureStateV1.READY,
                        },
                    )
                ),
            )
        except Exception:  # noqa: BLE001 - timer authority is mandatory
            self._fail_protocol_runtime_v1()
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
            ) from None
        try:
            partition_work = self._work_controller.register_work_v1(
                WorkOperationKindV1.CAPTURE_EVIDENCE_PARTITION_OPEN,
                min(
                    now_monotonic + FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1,
                    binding.expires_at_monotonic,
                ),
                _admission_guard_v1=(
                    lambda: self._capture_work_admission_is_open_v1(
                        capture_epoch,
                        {CaptureStateV1.ARMED},
                    )
                ),
            )
        except Exception:  # noqa: BLE001 - encrypted partition is mandatory
            self._work_controller.release_work_v1(inactivity_work.lease)
            self._fail_protocol_runtime_v1()
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
            ) from None

        event = asyncio.Event()
        task_started = asyncio.Event()
        partition_created = False
        partition_committed = False
        cleanup_token: CleanupTokenV1 | None = None
        try:
            cleanup_token = (
                self._work_controller.register_cleanup_participant_v1()
            )
            with self._lock:
                if (
                    self._destroyed
                    or self._shutdown_started
                    or self._state is not CaptureStateV1.ARMED
                    or self._capture_epoch is not capture_epoch
                    or self._active_capture_capability_v1 is not None
                    or self._private_store_cleanup_token_v1 is not None
                ):
                    raise RuntimeError(
                        "capture partition activation precondition failed"
                    )
                self._private_evidence_store_v1.create_capture_partition_v1(
                    access=self._private_store_write_access_v1,
                    capture_epoch=capture_epoch,
                    fence=partition_work.fence,
                    profile_id=profile_id,
                    capture_created_at_epoch_seconds=now_epoch,
                    maximum_expires_at_epoch_seconds=(
                        session_expires_at_epoch_seconds
                    ),
                )
                partition_created = True
                self._private_store_cleanup_token_v1 = cleanup_token
                if not (
                    self._private_evidence_store_v1
                    ._commit_capture_partition_for_owner_v1(
                        access=self._private_store_write_access_v1,
                        capture_epoch=capture_epoch,
                    )
                ):
                    raise RuntimeError(
                        "capture partition publication failed"
                    )
                partition_committed = True
                self._active_capture_capability_v1 = active_capability
                self._profile_id_v1 = profile_id
                self._frame_records_v1.clear()
                self._unique_frame_digests_v1.clear()
                self._accepted_frame_bytes_v1 = 0
                self._active_frame_upload_permits_v1.clear()
                self._seal_attempt_seq_v1 = 0
                self._last_seal_result_v1 = None
                self._inactivity_deadline_monotonic_v1 = (
                    inactivity_deadline_monotonic
                )
                self._inactivity_deadline_epoch_v1 = now_epoch + (
                    inactivity_deadline_monotonic - now_monotonic
                )
                self._inactivity_revision_v1 += 1
                self._inactivity_event_v1 = event
                self._inactivity_work_v1 = inactivity_work
                task = asyncio.create_task(
                    self._run_inactivity_timer_v1(
                        capture_epoch,
                        inactivity_work,
                        event,
                        task_started,
                    )
                )
                self._inactivity_task_v1 = task
            if not self._work_controller.release_work_v1(
                partition_work.lease
            ):
                raise RuntimeError("partition work release failed")
        except BaseException:  # noqa: BLE001 - rollback includes cancellation
            self._work_controller.release_work_v1(partition_work.lease)
            self._work_controller.release_work_v1(inactivity_work.lease)
            if partition_created and not partition_committed:
                self._private_evidence_store_v1._rollback_uncommitted_capture_v1(
                    access=self._private_store_cleanup_access_v1,
                    capture_epoch=capture_epoch,
                )
            if not partition_committed and cleanup_token is not None:
                self._work_controller.withdraw_cleanup_participant_v1(
                    cleanup_token
                )
                with self._lock:
                    if self._private_store_cleanup_token_v1 is cleanup_token:
                        self._private_store_cleanup_token_v1 = None
            self._fail_protocol_runtime_v1()
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
            ) from None
        timer_started = await self._wait_committed_task_started_v1(
            task_started,
            task,
        )
        if not timer_started:
            with self._lock:
                if self._inactivity_task_v1 is task:
                    self._inactivity_task_v1 = None
                if self._inactivity_work_v1 is inactivity_work:
                    self._inactivity_work_v1 = None
                if self._inactivity_event_v1 is event:
                    self._inactivity_event_v1 = None
            self._retire_unstarted_work_v1(inactivity_work)
            self._fail_protocol_runtime_v1()
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
            )
        return _BeginReplayResultV1(
            capture_epoch=capture_epoch,
            capability_binding=binding,
        )

    def _capture_work_admission_is_open_v1(
        self,
        capture_epoch: CaptureEpochV1,
        permitted_states: set[CaptureStateV1],
    ) -> bool:
        with self._lock:
            return bool(
                not self._destroyed
                and not self._shutdown_started
                and self._capture_epoch is capture_epoch
                and self._state in permitted_states
                and self._fatal_failure is None
            )

    def _private_store_operation_is_live_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        return self._capture_work_admission_is_open_v1(
            capture_epoch,
            {
                CaptureStateV1.ARMED,
                CaptureStateV1.CAPTURING,
                CaptureStateV1.BUILDING_ASSERTIONS,
                CaptureStateV1.READY,
            },
        )

    def _active_capability_authorizes_locked_v1(
        self,
        *,
        capture_id: uuid.UUID,
        presented_capability: object,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        permitted_states: set[CaptureStateV1],
        now_epoch: float,
        now_monotonic: float,
    ) -> CaptureEpochV1:
        capture_epoch = self._capture_epoch
        if (
            self._destroyed
            or self._shutdown_started
            or self._fatal_failure is not None
            or capture_epoch is None
            or capture_epoch.capture_id != capture_id
            or self._state not in permitted_states
            or self._work_controller.current_epoch_v1()
            != capture_epoch.session_epoch
            or not self._feature_is_enabled_v1()
            or not self._security_authority_is_usable_v1()
            or not self._capability_authority_v1.authorizes_v1(
                self._active_capture_capability_v1,
                presented_capability=presented_capability,
                session_id=session_id,
                owner_issuer=owner_issuer,
                owner_subject=owner_subject,
                capture_epoch=capture_epoch,
                now_epoch_seconds=now_epoch,
                now_monotonic=now_monotonic,
            )
        ):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return capture_epoch

    async def admit_frame_upload_v1(
        self,
        *,
        capture_id: uuid.UUID,
        frame_seq: int,
        capture_capability: str,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
    ) -> FrameUploadPermitV1:
        """Authorize and reserve one bounded upload before its body is read."""

        if (
            isinstance(frame_seq, bool)
            or not isinstance(frame_seq, int)
            or not 1 <= frame_seq <= MAX_CAPTURE_FRAMES_V1
        ):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.FRAME_SEQUENCE_INVALID
            )
        now_epoch, now_monotonic = self._read_protocol_clocks_v1()
        expired_epoch: CaptureEpochV1 | None = None
        with self._lock:
            active = self._active_capture_capability_v1
            if (
                active is not None
                and self._capture_epoch is active.binding.capture_epoch
                and (
                    now_epoch >= active.binding.expires_at_epoch_seconds
                    or now_monotonic >= active.binding.expires_at_monotonic
                    or (
                        self._inactivity_deadline_monotonic_v1 is not None
                        and now_monotonic
                        >= self._inactivity_deadline_monotonic_v1
                    )
                )
            ):
                expired_epoch = active.binding.capture_epoch
        if expired_epoch is not None:
            await self._expire_capture_if_current_v1(expired_epoch)
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )

        permit_id: uuid.UUID | None = None
        permit_epoch: CaptureEpochV1 | None = None

        def claim() -> None:
            nonlocal permit_epoch, permit_id
            with self._lock:
                capture_epoch = self._active_capability_authorizes_locked_v1(
                    capture_id=capture_id,
                    presented_capability=capture_capability,
                    session_id=session_id,
                    owner_issuer=owner_issuer,
                    owner_subject=owner_subject,
                    permitted_states={
                        CaptureStateV1.ARMED,
                        CaptureStateV1.CAPTURING,
                    },
                    now_epoch=now_epoch,
                    now_monotonic=now_monotonic,
                )
                if (
                    frame_seq not in self._frame_records_v1
                    and len(self._frame_records_v1) >= MAX_CAPTURE_FRAMES_V1
                ):
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.FRAME_LIMIT_REACHED
                    )
                if (
                    len(self._active_frame_upload_permits_v1)
                    >= MAX_CONCURRENT_UPLOADS_PER_CAPTURE_V1
                ):
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.UPLOAD_BUSY
                    )
                permit_id = uuid.uuid4()
                permit_epoch = capture_epoch
                self._active_frame_upload_permits_v1.add(permit_id)

        if not self._run_if_session_live_v1(claim):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        if permit_id is None or permit_epoch is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        try:
            active = self._active_capture_capability_v1
            if active is None:
                raise WorkAdmissionDeniedV1
            work_deadline = min(
                now_monotonic
                + FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1
                + 1.0,
                active.binding.expires_at_monotonic,
            )
            registered_work = self._work_controller.register_work_v1(
                WorkOperationKindV1.CAPTURE_FRAME_UPLOAD,
                work_deadline,
                _admission_guard_v1=(
                    lambda: self._capture_work_admission_is_open_v1(
                        permit_epoch,
                        {
                            CaptureStateV1.ARMED,
                            CaptureStateV1.CAPTURING,
                        },
                    )
                ),
            )
        except Exception:  # noqa: BLE001 - bounded upload admission
            with self._lock:
                self._active_frame_upload_permits_v1.discard(permit_id)
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            ) from None
        with self._lock:
            if (
                permit_id not in self._active_frame_upload_permits_v1
                or self._capture_epoch is not permit_epoch
                or self._state
                not in {CaptureStateV1.ARMED, CaptureStateV1.CAPTURING}
            ):
                self._work_controller.release_work_v1(
                    registered_work.lease
                )
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
        return FrameUploadPermitV1(
            permit_id=permit_id,
            capture_epoch=permit_epoch,
            frame_seq=frame_seq,
            registered_work=registered_work,
        )

    async def commit_frame_upload_v1(
        self,
        permit: FrameUploadPermitV1,
        validated_frame: ValidatedJpegFrameV1,
        encoded_frame: bytearray,
    ) -> FrameUploadResultV1:
        """Encrypt immediately and atomically commit store plus metadata."""

        if (
            not isinstance(permit, FrameUploadPermitV1)
            or not isinstance(validated_frame, ValidatedJpegFrameV1)
            or not isinstance(encoded_frame, bytearray)
            or len(encoded_frame) != validated_frame.encoded_size
        ):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
            )
        async with self._serialized_frame_commit_v1(
            permit.registered_work
        ):
            now_epoch, now_monotonic = self._read_protocol_clocks_v1()
            result: FrameUploadResultV1 | None = None
            fatal_store_failure: list[bool] = []

            def commit() -> None:
                nonlocal result
                with self._lock:
                    capture_epoch = self._capture_epoch
                    if (
                        permit.permit_id
                        not in self._active_frame_upload_permits_v1
                        or capture_epoch is not permit.capture_epoch
                        or self._state
                        not in {
                            CaptureStateV1.ARMED,
                            CaptureStateV1.CAPTURING,
                        }
                        or self._fatal_failure is not None
                        or not self._work_controller.validate_work_v1(
                            permit.registered_work.fence,
                            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                        )
                        or self._work_controller.current_epoch_v1()
                        != capture_epoch.session_epoch
                    ):
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                        )
                    active_capability = self._active_capture_capability_v1
                    if (
                        active_capability is None
                        or now_epoch
                        >= active_capability.binding.expires_at_epoch_seconds
                        or now_monotonic
                        >= active_capability.binding.expires_at_monotonic
                        or self._inactivity_deadline_monotonic_v1 is None
                        or now_monotonic
                        >= self._inactivity_deadline_monotonic_v1
                    ):
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                        )

                    existing = self._frame_records_v1.get(permit.frame_seq)
                    if existing is not None:
                        if not hmac.compare_digest(
                            existing.sha256_digest,
                            validated_frame.sha256_digest,
                        ):
                            raise CaptureProtocolErrorV1(
                                CaptureProtocolReasonV1.FRAME_SEQUENCE_CONFLICT
                            )
                        result = existing.result
                        return

                    if len(self._frame_records_v1) >= MAX_CAPTURE_FRAMES_V1:
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.FRAME_LIMIT_REACHED
                        )
                    next_total = (
                        self._accepted_frame_bytes_v1
                        + validated_frame.encoded_size
                    )
                    if next_total > MAX_CAPTURE_ENCODED_BYTES_V1:
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.CAPTURE_BYTE_LIMIT_REACHED
                        )
                    next_count = len(self._frame_records_v1) + 1
                    next_state = (
                        CaptureStateV1.CAPTURING
                        if self._state is CaptureStateV1.ARMED
                        else self._state
                    )
                    accepted = FrameUploadResultV1(
                        capture_id=capture_epoch.capture_id,
                        capture_seq=capture_epoch.capture_seq,
                        frame_seq=permit.frame_seq,
                        state=next_state,
                        encoded_size=validated_frame.encoded_size,
                        decoded_width=validated_frame.decoded_width,
                        decoded_height=validated_frame.decoded_height,
                        accepted_frame_count=next_count,
                        remaining_frame_slots=(
                            MAX_CAPTURE_FRAMES_V1 - next_count
                        ),
                        total_accepted_bytes=next_total,
                    )

                    previous_records = dict(self._frame_records_v1)
                    previous_digests = set(self._unique_frame_digests_v1)
                    previous_total = self._accepted_frame_bytes_v1
                    previous_state = self._state
                    previous_deadline_epoch = (
                        self._inactivity_deadline_epoch_v1
                    )
                    previous_deadline_monotonic = (
                        self._inactivity_deadline_monotonic_v1
                    )
                    previous_revision = self._inactivity_revision_v1

                    def commit_metadata(
                        evidence_frame: EvidenceFrameV1,
                    ) -> None:
                        nonlocal result
                        try:
                            hook = (
                                self
                                ._frame_metadata_commit_hook_for_test_v1
                            )
                            if hook is not None:
                                hook()
                            self._frame_records_v1[
                                permit.frame_seq
                            ] = _FrameRecordV1(
                                evidence_frame=evidence_frame,
                                accepted_at_monotonic=now_monotonic,
                                result=accepted,
                            )
                            self._unique_frame_digests_v1.add(
                                bytes(validated_frame.sha256_digest)
                            )
                            self._accepted_frame_bytes_v1 = next_total
                            if self._state is CaptureStateV1.ARMED:
                                self._state = CaptureStateV1.CAPTURING
                            self._reset_inactivity_locked_v1(
                                now_epoch,
                                now_monotonic,
                            )
                            result = accepted
                        except BaseException:
                            self._frame_records_v1 = previous_records
                            self._unique_frame_digests_v1 = (
                                previous_digests
                            )
                            self._accepted_frame_bytes_v1 = previous_total
                            self._state = previous_state
                            self._inactivity_deadline_epoch_v1 = (
                                previous_deadline_epoch
                            )
                            self._inactivity_deadline_monotonic_v1 = (
                                previous_deadline_monotonic
                            )
                            self._inactivity_revision_v1 = (
                                previous_revision
                            )
                            result = None
                            raise

                    try:
                        self._private_evidence_store_v1.put_frame_v1(
                            access=self._private_store_write_access_v1,
                            capture_epoch=capture_epoch,
                            fence=permit.registered_work.fence,
                            frame_seq=permit.frame_seq,
                            received_at_epoch_seconds=now_epoch,
                            encoded_frame=encoded_frame,
                            encoded_size=validated_frame.encoded_size,
                            canonical_width=(
                                validated_frame.decoded_width
                            ),
                            canonical_height=(
                                validated_frame.decoded_height
                            ),
                            sha256_digest=(
                                validated_frame.sha256_digest
                            ),
                            metadata_commit_v1=commit_metadata,
                        )
                    except PrivateEvidenceStoreErrorV1 as exception:
                        if exception.reason in {
                            PrivateEvidenceStoreReasonV1
                            .INTEGRITY_FAILURE,
                            PrivateEvidenceStoreReasonV1
                            .INVARIANT_FAILURE,
                        }:
                            fatal_store_failure.append(True)
                            reason = (
                                CaptureProtocolReasonV1
                                .CAPTURE_FAILED_CLOSED
                            )
                        elif exception.reason in {
                            PrivateEvidenceStoreReasonV1.ACCESS_DENIED,
                            PrivateEvidenceStoreReasonV1.CAPTURE_CLOSED,
                        }:
                            reason = (
                                CaptureProtocolReasonV1
                                .CAPTURE_ACCESS_DENIED
                            )
                        else:
                            reason = (
                                CaptureProtocolReasonV1
                                .CAPTURE_OPERATION_FAILED
                            )
                        raise CaptureProtocolErrorV1(reason) from None

            try:
                session_live = self._run_if_session_live_v1(commit)
            except CaptureProtocolErrorV1:
                if fatal_store_failure:
                    self._fail_protocol_runtime_v1()
                raise
            if not session_live:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            if result is None:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
                )
            return result

    def release_frame_upload_permit_v1(
        self,
        permit: FrameUploadPermitV1,
    ) -> None:
        if not isinstance(permit, FrameUploadPermitV1):
            return
        with self._lock:
            self._active_frame_upload_permits_v1.discard(permit.permit_id)
        self._work_controller.release_work_v1(
            permit.registered_work.lease
        )

    def _read_private_frame_for_test_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        frame_id: uuid.UUID,
        registered_work: RegisteredWorkV1,
        access: PrivateEvidenceAccessV1,
    ) -> bytes:
        """Authorized internal read seam; no production consumer exists in 5A."""

        if not isinstance(registered_work, RegisteredWorkV1):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        result: list[bytes] = []
        integrity_failure: list[bool] = []

        def read() -> None:
            try:
                result.append(
                    self._private_evidence_store_v1.get_frame_v1(
                        access=access,
                        capture_epoch=capture_epoch,
                        fence=registered_work.fence,
                        frame_id=frame_id,
                    )
                )
            except PrivateEvidenceStoreErrorV1 as exception:
                if exception.reason in {
                    PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE,
                    PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE,
                    PrivateEvidenceStoreReasonV1
                    .RECORD_TYPE_MISMATCH,
                }:
                    integrity_failure.append(True)
                raise

        try:
            session_live = self._run_if_session_live_v1(read)
        except PrivateEvidenceStoreErrorV1:
            if integrity_failure:
                self._fail_protocol_runtime_v1()
            raise
        if not session_live or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    async def _install_private_ocr_service_v1(
        self,
        client: OcrTransportClientV1,
    ) -> None:
        """Install one exact ready sidecar identity; no runtime switching."""

        if (
            not callable(getattr(client, "health_v1", None))
            or not callable(getattr(client, "exchange_v1", None))
            or not callable(getattr(client, "close_v1", None))
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
        expected_identity = getattr(client, "expected_identity_v1", None)
        expected_qualification = getattr(
            client,
            "expected_qualification_record_sha256_v1",
            None,
        )
        if (
            not isinstance(expected_identity, InferenceIdentityV1)
            or not isinstance(expected_qualification, str)
            or len(expected_qualification) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_qualification
            )
        ):
            try:
                await client.close_v1()
            except Exception:  # noqa: BLE001, S110 - transport stays closed
                pass
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
        try:
            health = await client.health_v1()
        except OcrServiceErrorV1:
            try:
                await client.close_v1()
            except Exception:  # noqa: BLE001, S110 - transport stays closed
                pass
            raise
        except Exception:  # noqa: BLE001 - stable installation boundary
            try:
                await client.close_v1()
            except Exception:  # noqa: BLE001, S110 - transport stays closed
                pass
            raise OcrServiceErrorV1(
                OcrFailureReasonV1.OCR_UNAVAILABLE
            ) from None
        if (
            not isinstance(health, OcrHealthStatusV1)
            or not hmac.compare_digest(
                health.identity.inference_identity_sha256,
                expected_identity.inference_identity_sha256,
            )
            or not hmac.compare_digest(
                health.qualification_record_sha256,
                expected_qualification,
            )
        ):
            try:
                await client.close_v1()
            except Exception:  # noqa: BLE001, S110 - transport stays closed
                pass
            raise OcrServiceErrorV1(OcrFailureReasonV1.IDENTITY_MISMATCH)
        service = PrivateOcrServiceV1._create_for_coordinator_v1(
            client=client,
            expected_identity=expected_identity,
            expected_qualification_record_sha256=(
                expected_qualification
            ),
            private_authority=self._private_evidence_authority_v1,
            store=self._private_evidence_store_v1,
            read_access=self._private_store_read_access_v1,
            write_access=self._private_store_write_access_v1,
            work_controller=self._work_controller,
            capture_is_live_v1=self._private_ocr_operation_is_live_v1,
            fatal_store_failure_v1=self._fail_protocol_runtime_v1,
            wall_clock_v1=self._wall_clock_v1,
            monotonic_clock_v1=self._monotonic_clock_v1,
        )
        installed = False
        with self._lock:
            if (
                not self._destroyed
                and not self._shutdown_started
                and self._ocr_service_v1 is None
                and self._security_authority_is_usable_v1()
            ):
                self._ocr_service_v1 = service
                installed = True
        if not installed:
            try:
                await client.close_v1()
            except Exception:  # noqa: BLE001, S110 - transport stays closed
                pass
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)

    async def _bootstrap_private_ocr_runtime_v1(
        self,
        deployment: OcrDeploymentConfigV1,
    ) -> None:
        """Owner-only bootstrap for one reviewed, qualified UDS deployment."""

        if (
            not isinstance(deployment, OcrDeploymentConfigV1)
            or not self._feature_is_enabled_v1()
            or not self._security_authority_is_usable_v1()
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
        await self._install_private_ocr_service_v1(
            deployment.create_client_v1()
        )

    def _private_ocr_operation_is_live_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        return bool(
            self._security_authority_is_usable_v1()
            and self._capture_work_admission_is_open_v1(
                capture_epoch,
                {
                    CaptureStateV1.CAPTURING,
                    CaptureStateV1.BUILDING_ASSERTIONS,
                },
            )
        )

    def _private_admission_extraction_operation_is_live_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        return bool(
            self._run_if_session_live_v1(lambda: None)
            and self._security_authority_is_usable_v1()
            and self._capture_work_admission_is_open_v1(
                capture_epoch,
                {
                    CaptureStateV1.CAPTURING,
                    CaptureStateV1.BUILDING_ASSERTIONS,
                },
            )
        )

    async def _process_private_ocr_frames_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        frame_ids: tuple[uuid.UUID, ...],
    ) -> tuple[StoredOcrResultV1, ...]:
        """Trusted internal M6A API; it never exposes OCR plaintext."""

        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or not isinstance(frame_ids, tuple)
            or not 1
            <= len(frame_ids)
            <= MAX_OCR_FRAMES_PER_OPERATION_V1
            or len(set(frame_ids)) != len(frame_ids)
            or any(
                not isinstance(frame_id, uuid.UUID)
                or frame_id.version != 7
                or frame_id.variant != uuid.RFC_4122
                for frame_id in frame_ids
            )
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.REQUEST_REJECTED)
        with self._lock:
            service = self._ocr_service_v1
            if (
                service is None
                or self._capture_epoch is not capture_epoch
                or self._state
                not in {
                    CaptureStateV1.CAPTURING,
                    CaptureStateV1.BUILDING_ASSERTIONS,
                }
                or not self._private_evidence_authority_v1.is_usable_v1()
            ):
                raise OcrServiceErrorV1(
                    OcrFailureReasonV1.OCR_UNAVAILABLE
                )
            evidence_by_id = {
                record.evidence_frame.frame_id: record.evidence_frame
                for record in self._frame_records_v1.values()
            }
            try:
                evidence_frames = tuple(
                    evidence_by_id[frame_id] for frame_id in frame_ids
                )
            except KeyError:
                raise OcrServiceErrorV1(
                    OcrFailureReasonV1.REQUEST_REJECTED
                ) from None
        return await service.process_frames_v1(
            capture_epoch=capture_epoch,
            evidence_frames=evidence_frames,
        )

    def _read_private_ocr_result_for_test_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        receipt: StoredOcrResultV1,
        registered_work: RegisteredWorkV1,
        access: PrivateEvidenceAccessV1,
    ) -> OcrPageResultV1:
        """Authorized test seam for inspecting one encrypted OCR record."""

        if not isinstance(registered_work, RegisteredWorkV1):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        result: list[OcrPageResultV1] = []

        def read() -> None:
            result.append(
                self._private_evidence_store_v1.get_ocr_result_v1(
                    access=access,
                    capture_epoch=capture_epoch,
                    fence=registered_work.fence,
                    receipt=receipt,
                )
            )

        if not self._run_if_session_live_v1(read) or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    async def _process_private_admission_notice_extraction_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        ocr_receipts: tuple[StoredOcrResultV1, ...],
        parent_work: RegisteredWorkV1,
    ) -> StoredAdmissionNoticeExtractionV1:
        """Trusted internal M6B API; plaintext never crosses this seam."""

        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or not isinstance(parent_work, RegisteredWorkV1)
        ):
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1
                .EXTRACTION_INPUT_INVALID
            )
        with self._lock:
            if (
                self._capture_epoch is not capture_epoch
                or self._state
                not in {
                    CaptureStateV1.CAPTURING,
                    CaptureStateV1.BUILDING_ASSERTIONS,
                }
                or not self._private_evidence_authority_v1.is_usable_v1()
            ):
                raise AdmissionNoticeExtractionServiceErrorV1(
                    AdmissionNoticeExtractionFailureReasonV1
                    .EXTRACTION_AUTHORITY_INVALID
                )
            service = self._admission_extraction_service_v1
        return await service.extract_v1(
            capture_epoch=capture_epoch,
            ocr_receipts=ocr_receipts,
            parent_work=parent_work,
        )

    def _read_private_admission_extraction_for_test_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        receipt: StoredAdmissionNoticeExtractionV1,
        registered_work: RegisteredWorkV1,
        access: PrivateEvidenceAccessV1,
    ) -> AdmissionNoticeExtractionV1:
        """Authorized test seam for one encrypted extraction record."""

        if not isinstance(registered_work, RegisteredWorkV1):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        result: list[AdmissionNoticeExtractionV1] = []

        def read() -> None:
            result.append(
                self._private_evidence_store_v1
                .get_admission_notice_extraction_v1(
                    access=access,
                    capture_epoch=capture_epoch,
                    fence=registered_work.fence,
                    receipt=receipt,
                )
            )

        if not self._run_if_session_live_v1(read) or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    async def capture_public_status_v1(
        self,
        *,
        capture_id: uuid.UUID,
        capture_capability: str,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
    ) -> CapturePublicStatusV1:
        """Return a private control projection without extending inactivity."""

        now_epoch, now_monotonic = self._read_protocol_clocks_v1()
        expired_epoch: CaptureEpochV1 | None = None
        with self._lock:
            active = self._active_capture_capability_v1
            if (
                active is not None
                and self._capture_epoch is active.binding.capture_epoch
                and (
                    now_epoch >= active.binding.expires_at_epoch_seconds
                    or now_monotonic >= active.binding.expires_at_monotonic
                    or (
                        self._inactivity_deadline_monotonic_v1 is not None
                        and now_monotonic
                        >= self._inactivity_deadline_monotonic_v1
                    )
                )
            ):
                expired_epoch = active.binding.capture_epoch
        if expired_epoch is not None:
            await self._expire_capture_if_current_v1(expired_epoch)
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )

        result: CapturePublicStatusV1 | None = None

        def read_status() -> None:
            nonlocal result
            with self._lock:
                capture_epoch = self._active_capability_authorizes_locked_v1(
                    capture_id=capture_id,
                    presented_capability=capture_capability,
                    session_id=session_id,
                    owner_issuer=owner_issuer,
                    owner_subject=owner_subject,
                    permitted_states={
                        CaptureStateV1.ARMED,
                        CaptureStateV1.CAPTURING,
                        CaptureStateV1.BUILDING_ASSERTIONS,
                        CaptureStateV1.READY,
                    },
                    now_epoch=now_epoch,
                    now_monotonic=now_monotonic,
                )
                inactivity_expiry = self._inactivity_deadline_epoch_v1
                if inactivity_expiry is None:
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                    )
                last_seal = self._last_seal_result_v1
                count = len(self._frame_records_v1)
                result = CapturePublicStatusV1(
                    capture_id=capture_epoch.capture_id,
                    capture_seq=capture_epoch.capture_seq,
                    state=self._state,
                    accepted_frame_count=count,
                    remaining_frame_slots=MAX_CAPTURE_FRAMES_V1 - count,
                    total_accepted_bytes=self._accepted_frame_bytes_v1,
                    independent_correlation_groups=len(
                        self._unique_frame_digests_v1
                    ),
                    inactivity_expires_at_epoch_seconds=inactivity_expiry,
                    last_seal_outcome=(
                        last_seal.outcome if last_seal is not None else None
                    ),
                    reason_codes=(
                        last_seal.reason_codes
                        if last_seal is not None
                        else ()
                    ),
                    restart_required=(
                        last_seal.restart_required
                        if last_seal is not None
                        else False
                    ),
                )

        if not self._run_if_session_live_v1(read_status):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        if result is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return result

    async def seal_capture_protocol_v1(
        self,
        *,
        request_id: uuid.UUID,
        control_seq: int,
        capture_id: uuid.UUID,
        capture_capability: str,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
    ) -> SealResultV1:
        await self._expire_active_capture_before_control_v1()
        request_digest = canonical_control_request_digest_v1(
            operation=ControlOperationV1.SEAL,
            request_id=request_id,
            control_seq=control_seq,
            capture_id=capture_id,
        )
        self._claim_control_waiter_v1()
        try:
            async with self._control_lock_v1:
                now_epoch, now_monotonic = self._read_protocol_clocks_v1()
                with self._lock:
                    candidate = self._replay_ledger_v1.candidate_record_v1(
                        request_id
                    )
                    if candidate is not None:
                        self._require_replay_candidate_authority_v1(
                            record=candidate,
                            presented_capability=capture_capability,
                            capture_id=capture_id,
                            session_id=session_id,
                            owner_issuer=owner_issuer,
                            owner_subject=owner_subject,
                            now_epoch=now_epoch,
                            now_monotonic=now_monotonic,
                        )
                    existing = self._replay_ledger_v1.existing_record_v1(
                        operation=ControlOperationV1.SEAL,
                        request_id=request_id,
                        control_seq=control_seq,
                        request_digest=request_digest,
                    )
                    if existing is not None:
                        replay = self._replay_ledger_v1.replay_result_v1(
                            existing
                        )
                        if not isinstance(replay, SealResultV1):
                            raise CaptureProtocolErrorV1(
                                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
                            )
                        return replay

                    capture_epoch = self._active_capability_authorizes_locked_v1(
                        capture_id=capture_id,
                        presented_capability=capture_capability,
                        session_id=session_id,
                        owner_issuer=owner_issuer,
                        owner_subject=owner_subject,
                        permitted_states={CaptureStateV1.CAPTURING},
                        now_epoch=now_epoch,
                        now_monotonic=now_monotonic,
                    )
                    active = self._active_capture_capability_v1
                    assert active is not None
                    record, _ = self._replay_ledger_v1.lookup_or_claim_v1(
                        operation=ControlOperationV1.SEAL,
                        request_id=request_id,
                        control_seq=control_seq,
                        request_digest=request_digest,
                    )
                    record.authorization_binding = active.binding

                try:
                    result, caller_cancelled = (
                        await self._await_control_operation_to_completion_v1(
                            self._execute_seal_attempt_v1(capture_epoch)
                        )
                    )
                except asyncio.CancelledError:
                    with self._lock:
                        self._replay_ledger_v1.complete_error_v1(
                            record,
                            CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED,
                        )
                    raise
                except Exception as exception:  # noqa: BLE001
                    protocol_error = self._protocol_error_for_lifecycle_v1(
                        exception
                    )
                    with self._lock:
                        self._replay_ledger_v1.complete_error_v1(
                            record,
                            protocol_error.reason,
                        )
                    raise protocol_error from None
                with self._lock:
                    self._replay_ledger_v1.complete_result_v1(
                        record,
                        result,
                    )
                if caller_cancelled:
                    raise asyncio.CancelledError
                return result
        finally:
            self._release_control_waiter_v1()

    async def _execute_seal_attempt_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> SealResultV1:
        async with self._serialized_operation_v1():
            now_epoch, now_monotonic = self._read_protocol_clocks_v1()
            result: SealResultV1 | None = None
            processing_input: MockProcessingInputV1 | None = None

            def seal_atomically() -> None:
                nonlocal processing_input, result
                with self._lock:
                    if (
                        self._capture_epoch is not capture_epoch
                        or self._state is not CaptureStateV1.CAPTURING
                        or self._fatal_failure is not None
                        or self._processor_task_v1 is not None
                        or self._work_controller.current_epoch_v1()
                        != capture_epoch.session_epoch
                    ):
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.CAPTURE_STATE_INVALID
                        )
                    active = self._active_capture_capability_v1
                    if (
                        active is None
                        or now_epoch
                        >= active.binding.expires_at_epoch_seconds
                        or now_monotonic
                        >= active.binding.expires_at_monotonic
                        or self._inactivity_deadline_monotonic_v1 is None
                        or now_monotonic
                        >= self._inactivity_deadline_monotonic_v1
                    ):
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                        )
                    self._seal_attempt_seq_v1 += 1
                    self._reset_inactivity_locked_v1(
                        now_epoch,
                        now_monotonic,
                    )
                    accepted_count = len(self._frame_records_v1)
                    unique_count = len(self._unique_frame_digests_v1)
                    remaining = MAX_CAPTURE_FRAMES_V1 - accepted_count
                    if unique_count < MINIMUM_MOCK_UNIQUE_FRAMES_V1:
                        result = SealResultV1(
                            seal_attempt_seq=self._seal_attempt_seq_v1,
                            outcome=SealOutcomeV1.NEEDS_RECAPTURE,
                            capture_state=CaptureStateV1.CAPTURING,
                            accepted_frame_count=accepted_count,
                            independent_correlation_groups=unique_count,
                            remaining_frame_slots=remaining,
                            reason_codes=(
                                SealReasonCodeV1.TOO_FEW_UNIQUE_FRAMES,
                            ),
                            restart_required=remaining == 0,
                        )
                        self._last_seal_result_v1 = result
                        return
                    if self._test_processor_v1 is None:
                        raise CaptureProtocolErrorV1(
                            CaptureProtocolReasonV1.PROCESSOR_NOT_READY
                        )
                    self._state = CaptureStateV1.BUILDING_ASSERTIONS
                    result = SealResultV1(
                        seal_attempt_seq=self._seal_attempt_seq_v1,
                        outcome=SealOutcomeV1.BUILD_STARTED,
                        capture_state=CaptureStateV1.BUILDING_ASSERTIONS,
                        accepted_frame_count=accepted_count,
                        independent_correlation_groups=unique_count,
                        remaining_frame_slots=remaining,
                        reason_codes=(),
                        restart_required=False,
                    )
                    self._last_seal_result_v1 = result
                    processing_input = MockProcessingInputV1(
                        capture_seq=capture_epoch.capture_seq,
                        accepted_frame_count=accepted_count,
                        independent_correlation_groups=unique_count,
                    )

            if not self._run_if_session_live_v1(seal_atomically):
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            if result is None:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
                )
            if processing_input is None:
                return result

            processor_deadline = now_monotonic + 30.0
            try:
                processor_work = self._work_controller.register_work_v1(
                    WorkOperationKindV1.CAPTURE_MOCK_PROCESSOR,
                    processor_deadline,
                    _admission_guard_v1=(
                        lambda: self._capture_work_admission_is_open_v1(
                            capture_epoch,
                            {CaptureStateV1.BUILDING_ASSERTIONS},
                        )
                    ),
                )
            except Exception:  # noqa: BLE001 - build cannot run unfenced
                self._fail_protocol_runtime_v1()
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
                ) from None

            with self._lock:
                if (
                    self._capture_epoch is not capture_epoch
                    or self._state is not CaptureStateV1.BUILDING_ASSERTIONS
                    or self._processor_task_v1 is not None
                ):
                    self._work_controller.release_work_v1(
                        processor_work.lease
                    )
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.CAPTURE_STATE_INVALID
                    )
                task_started = asyncio.Event()
                processor_task = asyncio.create_task(
                    self._run_mock_processor_v1(
                        capture_epoch,
                        processor_work,
                        processing_input,
                        task_started,
                    )
                )
                self._processor_work_v1 = processor_work
                self._processor_task_v1 = processor_task
            processor_started = await self._wait_committed_task_started_v1(
                task_started,
                processor_task,
            )
            if not processor_started:
                with self._lock:
                    if self._processor_task_v1 is processor_task:
                        self._processor_task_v1 = None
                    if self._processor_work_v1 is processor_work:
                        self._processor_work_v1 = None
                self._retire_unstarted_work_v1(processor_work)
                self._fail_protocol_runtime_v1()
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
                )
            return result

    async def end_capture_protocol_v1(
        self,
        *,
        request_id: uuid.UUID,
        control_seq: int,
        capture_id: uuid.UUID,
        capture_capability: str,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
    ) -> EndCaptureResultV1:
        await self._expire_active_capture_before_control_v1()
        request_digest = canonical_control_request_digest_v1(
            operation=ControlOperationV1.END,
            request_id=request_id,
            control_seq=control_seq,
            capture_id=capture_id,
        )
        self._claim_control_waiter_v1()
        try:
            async with self._control_lock_v1:
                now_epoch, now_monotonic = self._read_protocol_clocks_v1()
                with self._lock:
                    candidate = self._replay_ledger_v1.candidate_record_v1(
                        request_id
                    )
                    if candidate is not None:
                        self._require_replay_candidate_authority_v1(
                            record=candidate,
                            presented_capability=capture_capability,
                            capture_id=capture_id,
                            session_id=session_id,
                            owner_issuer=owner_issuer,
                            owner_subject=owner_subject,
                            now_epoch=now_epoch,
                            now_monotonic=now_monotonic,
                        )
                    existing = self._replay_ledger_v1.existing_record_v1(
                        operation=ControlOperationV1.END,
                        request_id=request_id,
                        control_seq=control_seq,
                        request_digest=request_digest,
                    )
                    if existing is not None:
                        replay = self._replay_ledger_v1.replay_result_v1(
                            existing
                        )
                        if not isinstance(replay, EndCaptureResultV1):
                            raise CaptureProtocolErrorV1(
                                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
                            )
                        return replay

                    capture_epoch = self._active_capability_authorizes_locked_v1(
                        capture_id=capture_id,
                        presented_capability=capture_capability,
                        session_id=session_id,
                        owner_issuer=owner_issuer,
                        owner_subject=owner_subject,
                        permitted_states={
                            CaptureStateV1.ARMED,
                            CaptureStateV1.CAPTURING,
                            CaptureStateV1.BUILDING_ASSERTIONS,
                            CaptureStateV1.READY,
                        },
                        now_epoch=now_epoch,
                        now_monotonic=now_monotonic,
                    )
                    active = self._active_capture_capability_v1
                    assert active is not None
                    record, _ = self._replay_ledger_v1.lookup_or_claim_v1(
                        operation=ControlOperationV1.END,
                        request_id=request_id,
                        control_seq=control_seq,
                        request_digest=request_digest,
                    )
                    record.authorization_binding = active.binding

                async def execute_end_v1() -> EndCaptureResultV1:
                    status = await self.end_capture_v1(capture_epoch)
                    return EndCaptureResultV1(
                        capture_id=capture_epoch.capture_id,
                        capture_seq=capture_epoch.capture_seq,
                        session_generation=status.session_generation,
                        state=status.state,
                    )

                try:
                    result, caller_cancelled = (
                        await self._await_control_operation_to_completion_v1(
                            execute_end_v1()
                        )
                    )
                except asyncio.CancelledError:
                    with self._lock:
                        self._replay_ledger_v1.complete_error_v1(
                            record,
                            CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED,
                        )
                    raise
                except Exception as exception:  # noqa: BLE001
                    protocol_error = self._protocol_error_for_lifecycle_v1(
                        exception
                    )
                    with self._lock:
                        self._replay_ledger_v1.complete_error_v1(
                            record,
                            protocol_error.reason,
                        )
                    raise protocol_error from None
                with self._lock:
                    self._replay_ledger_v1.complete_result_v1(
                        record,
                        result,
                    )
                    self._replay_ledger_v1.retain_only_v1(record)
                if caller_cancelled:
                    raise asyncio.CancelledError
                return result
        finally:
            self._release_control_waiter_v1()

    def _require_replay_candidate_authority_v1(
        self,
        *,
        record: ControlReplayRecordV1,
        presented_capability: object,
        capture_id: uuid.UUID,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        now_epoch: float,
        now_monotonic: float,
    ) -> None:
        binding = record.authorization_binding
        if isinstance(binding, CaptureCapabilityBindingV1):
            if not self._capability_authority_v1.replay_capability_matches_v1(
                binding,
                presented_capability,
            ):
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            if (
                record.operation is ControlOperationV1.END
                and record.completed
                and isinstance(record.result, EndCaptureResultV1)
                and self._state is CaptureStateV1.IDLE
                and self._active_capture_capability_v1 is None
                and now_epoch < binding.expires_at_epoch_seconds
                and now_monotonic < binding.expires_at_monotonic
            ):
                return
            capture_id = binding.capture_epoch.capture_id
        self._active_capability_authorizes_locked_v1(
            capture_id=capture_id,
            presented_capability=presented_capability,
            session_id=session_id,
            owner_issuer=owner_issuer,
            owner_subject=owner_subject,
            permitted_states={
                CaptureStateV1.ARMED,
                CaptureStateV1.CAPTURING,
                CaptureStateV1.BUILDING_ASSERTIONS,
                CaptureStateV1.READY,
            },
            now_epoch=now_epoch,
            now_monotonic=now_monotonic,
        )

    async def _expire_active_capture_before_control_v1(self) -> None:
        """Make an observed expired capture destructive before mutation."""

        now_epoch, now_monotonic = self._read_protocol_clocks_v1()
        expired_epoch: CaptureEpochV1 | None = None
        with self._lock:
            active = self._active_capture_capability_v1
            if (
                active is not None
                and self._capture_epoch is active.binding.capture_epoch
                and (
                    now_epoch >= active.binding.expires_at_epoch_seconds
                    or now_monotonic >= active.binding.expires_at_monotonic
                    or (
                        self._inactivity_deadline_monotonic_v1 is not None
                        and now_monotonic
                        >= self._inactivity_deadline_monotonic_v1
                    )
                )
            ):
                expired_epoch = active.binding.capture_epoch
        if expired_epoch is not None:
            await self._expire_capture_if_current_v1(expired_epoch)

    def _reset_inactivity_locked_v1(
        self,
        now_epoch: float,
        now_monotonic: float,
    ) -> None:
        active = self._active_capture_capability_v1
        event = self._inactivity_event_v1
        if active is None or event is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
            )
        deadline = min(
            now_monotonic + CAPTURE_INACTIVITY_SECONDS_V1,
            active.binding.expires_at_monotonic,
        )
        if deadline <= now_monotonic:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_EXPIRED
            )
        self._inactivity_deadline_monotonic_v1 = deadline
        self._inactivity_deadline_epoch_v1 = now_epoch + (
            deadline - now_monotonic
        )
        self._inactivity_revision_v1 += 1
        event.set()

    async def _run_inactivity_timer_v1(
        self,
        capture_epoch: CaptureEpochV1,
        registered_work: RegisteredWorkV1,
        reset_event: asyncio.Event,
        task_started: asyncio.Event,
    ) -> None:
        lease_released = False
        task_started.set()
        try:
            while True:
                with self._lock:
                    if (
                        self._capture_epoch is not capture_epoch
                        or self._inactivity_work_v1 is not registered_work
                        or self._inactivity_event_v1 is not reset_event
                        or self._state
                        not in {
                            CaptureStateV1.ARMED,
                            CaptureStateV1.CAPTURING,
                            CaptureStateV1.BUILDING_ASSERTIONS,
                            CaptureStateV1.READY,
                        }
                    ):
                        return
                    deadline = self._inactivity_deadline_monotonic_v1
                    revision = self._inactivity_revision_v1
                if deadline is None:
                    return
                _, now_monotonic = self._read_protocol_clocks_v1()
                wait_seconds = max(0.0, deadline - now_monotonic)
                try:
                    await asyncio.wait_for(
                        reset_event.wait(),
                        timeout=wait_seconds,
                    )
                except TimeoutError:
                    pass
                with self._lock:
                    if (
                        self._capture_epoch is not capture_epoch
                        or self._inactivity_work_v1 is not registered_work
                    ):
                        return
                    _, current_monotonic = self._read_protocol_clocks_v1()
                    if (
                        self._inactivity_revision_v1 != revision
                        or current_monotonic
                        < (
                            self._inactivity_deadline_monotonic_v1
                            if self._inactivity_deadline_monotonic_v1
                            is not None
                            else current_monotonic
                        )
                    ):
                        reset_event.clear()
                        continue
                    self._inactivity_task_v1 = None
                    self._inactivity_work_v1 = None
                    self._inactivity_event_v1 = None
                if not self._work_controller.validate_work_v1(
                    registered_work.fence,
                    WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                ):
                    return
                self._work_controller.release_work_v1(
                    registered_work.lease
                )
                lease_released = True
                await self._expire_capture_if_current_v1(capture_epoch)
                return
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001 - timer uncertainty fails closed
            with self._lock:
                still_current = self._capture_epoch is capture_epoch
            if still_current:
                self._fail_protocol_runtime_v1()
        finally:
            with self._lock:
                if self._inactivity_work_v1 is registered_work:
                    self._inactivity_work_v1 = None
                    self._inactivity_task_v1 = None
                    self._inactivity_event_v1 = None
            if not lease_released:
                self._work_controller.release_work_v1(
                    registered_work.lease
                )

    async def _expire_capture_if_current_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> None:
        async with self._control_lock_v1:
            with self._lock:
                if (
                    self._capture_epoch is not capture_epoch
                    or self._state
                    not in {
                        CaptureStateV1.ARMED,
                        CaptureStateV1.CAPTURING,
                        CaptureStateV1.BUILDING_ASSERTIONS,
                        CaptureStateV1.READY,
                    }
                ):
                    return
            try:
                await self.end_capture_v1(capture_epoch)
                with self._lock:
                    self._replay_ledger_v1.discard_replay_records_v1()
            except CaptureTransitionRejectedV1:
                return
            except CaptureFailedClosedV1:
                return
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - M4A end already fails closed
                self._fail_protocol_runtime_v1()

    async def _run_mock_processor_v1(
        self,
        capture_epoch: CaptureEpochV1,
        registered_work: RegisteredWorkV1,
        processing_input: MockProcessingInputV1,
        task_started: asyncio.Event,
    ) -> None:
        current_task = asyncio.current_task()
        processor = self._test_processor_v1
        failed = False
        task_started.set()
        try:
            if (
                processor is None
                or not self._work_controller.validate_work_v1(
                    registered_work.fence,
                    WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
                )
                or not self._capture_work_admission_is_open_v1(
                    capture_epoch,
                    {CaptureStateV1.BUILDING_ASSERTIONS},
                )
            ):
                return
            await processor.process_capture_v1(processing_input)
            if not self._work_controller.validate_work_v1(
                registered_work.fence,
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
            ):
                return

            published: list[bool] = []

            def publish_ready() -> None:
                with self._lock:
                    if (
                        self._capture_epoch is not capture_epoch
                        or self._state
                        is not CaptureStateV1.BUILDING_ASSERTIONS
                        or self._processor_work_v1 is not registered_work
                        or self._processor_task_v1 is not current_task
                        or self._work_controller.current_epoch_v1()
                        != capture_epoch.session_epoch
                    ):
                        return
                    self._state = CaptureStateV1.READY
                    self._processor_task_v1 = None
                    self._processor_work_v1 = None
                    published.append(True)

            if not self._run_if_session_live_v1(publish_ready) or not published:
                return
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001 - mock failure is a runtime failure
            failed = True
        finally:
            with self._lock:
                if self._processor_task_v1 is current_task:
                    self._processor_task_v1 = None
                if self._processor_work_v1 is registered_work:
                    self._processor_work_v1 = None
            self._work_controller.release_work_v1(
                registered_work.lease
            )
        if failed:
            with self._lock:
                still_current = self._capture_epoch is capture_epoch
            if still_current:
                self._fail_protocol_runtime_v1()

    @staticmethod
    async def _wait_committed_task_started_v1(
        task_started: asyncio.Event,
        committed_task: asyncio.Task[None],
    ) -> bool:
        """Observe child startup or its terminal pre-start cancellation."""

        started_waiter = asyncio.create_task(task_started.wait())
        try:
            while True:
                try:
                    done, _ = await asyncio.wait(
                        {started_waiter, committed_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                except asyncio.CancelledError:
                    continue
                if task_started.is_set():
                    return True
                if committed_task in done:
                    return False
        finally:
            if not started_waiter.done():
                started_waiter.cancel()
            with suppress(asyncio.CancelledError):
                await started_waiter

    def _retire_unstarted_work_v1(
        self,
        registered_work: RegisteredWorkV1,
    ) -> None:
        """Conclude a work lease whose owning coroutine never entered."""

        try:
            self._work_controller.cancel_work_v1(registered_work.fence)
        except Exception:  # noqa: BLE001, S110 - fail closed below
            pass
        try:
            self._work_controller.release_work_v1(registered_work.lease)
        except Exception:  # noqa: BLE001, S110 - fail closed below
            pass

    @staticmethod
    async def _await_control_operation_to_completion_v1(
        operation: Coroutine[Any, Any, _ControlResultV1],
    ) -> tuple[_ControlResultV1, bool]:
        """Durably finish a claimed mutation before honoring cancellation."""

        operation_task = asyncio.create_task(operation)
        caller_cancelled = False
        while True:
            try:
                result = await asyncio.shield(operation_task)
                return result, caller_cancelled
            except asyncio.CancelledError:
                if operation_task.done() and operation_task.cancelled():
                    raise
                caller_cancelled = True

    @staticmethod
    def _cancel_task_v1(task: asyncio.Task[None] | None) -> None:
        if task is None or task.done():
            return
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = task.get_loop()
            if loop is asyncio.get_running_loop():
                task.cancel()
                return
        except RuntimeError:
            pass
        try:
            if loop is not None:
                loop.call_soon_threadsafe(task.cancel)
        except RuntimeError:
            return

    def _detach_private_capture_work_locked_v1(
        self,
    ) -> _DetachedPrivateCaptureWorkV1:
        capture_epoch = self._capture_epoch
        ocr_service = self._ocr_service_v1
        extraction_service = self._admission_extraction_service_v1
        timer_task = self._inactivity_task_v1
        processor_task = self._processor_task_v1
        timer_work = self._inactivity_work_v1
        processor_work = self._processor_work_v1

        self._inactivity_deadline_epoch_v1 = None
        self._inactivity_deadline_monotonic_v1 = None
        self._inactivity_revision_v1 += 1
        self._inactivity_event_v1 = None
        self._inactivity_task_v1 = None
        self._inactivity_work_v1 = None
        self._processor_task_v1 = None
        self._processor_work_v1 = None

        return _DetachedPrivateCaptureWorkV1(
            capture_epoch=capture_epoch,
            ocr_service=ocr_service,
            extraction_service=extraction_service,
            timer_task=timer_task,
            processor_task=processor_task,
            timer_work=timer_work,
            processor_work=processor_work,
        )

    def _cancel_detached_private_capture_work_v1(
        self,
        detached: _DetachedPrivateCaptureWorkV1,
    ) -> None:
        capture_epoch = detached.capture_epoch
        ocr_service = detached.ocr_service
        extraction_service = detached.extraction_service
        if capture_epoch is not None and ocr_service is not None:
            ocr_service.retire_capture_v1(capture_epoch)
        if capture_epoch is not None:
            extraction_service.retire_capture_v1(capture_epoch)
        for work in (detached.timer_work, detached.processor_work):
            if work is not None:
                try:
                    self._work_controller.cancel_work_v1(work.fence)
                except Exception:  # noqa: BLE001, S110 - fail closed
                    pass
        self._cancel_task_v1(detached.timer_task)
        self._cancel_task_v1(detached.processor_task)

    def _clear_private_capture_metadata_locked_v1(self) -> None:
        self._frame_records_v1.clear()
        self._unique_frame_digests_v1.clear()
        self._accepted_frame_bytes_v1 = 0
        self._profile_id_v1 = None
        self._seal_attempt_seq_v1 = 0
        self._last_seal_result_v1 = None

    def _prepare_private_capture_end_locked_v1(
        self,
    ) -> tuple[bool, _DetachedPrivateCaptureWorkV1 | None]:
        """Close admission and work before retired-generation destruction."""

        capture_epoch = self._capture_epoch
        self._active_capture_capability_v1 = None
        self._active_frame_upload_permits_v1.clear()
        if capture_epoch is not None:
            try:
                closed = (
                    self._private_evidence_store_v1
                    ._close_capture_admission_for_owner_v1(
                        access=self._private_store_cleanup_access_v1,
                        capture_epoch=capture_epoch,
                    )
                )
            except Exception:  # noqa: BLE001 - cleanup uncertainty is fatal
                closed = False
            if not closed:
                return False, None
        return True, self._detach_private_capture_work_locked_v1()

    def _destroy_private_capture_with_cleanup_fence_v1(
        self,
        cleanup_fence: RetiredGenerationCleanupFenceV1,
    ) -> bool:
        """Perform key-first erasure under one exact M3 cleanup fence."""

        with self._lock:
            capture_epoch = self._capture_epoch
            cleanup_token = self._private_store_cleanup_token_v1
        if capture_epoch is None:
            return bool(
                cleanup_token is None
                and self._private_evidence_store_v1.is_capture_clear_v1()
            )
        if (
            cleanup_fence.session_instance_id
            != capture_epoch.session_epoch.session_instance_id
            or cleanup_fence.retired_generation
            != capture_epoch.session_epoch.generation
        ):
            return False
        if self._private_evidence_store_v1.is_capture_clear_v1():
            destroyed = True
        else:
            try:
                destroyed = (
                    self._private_evidence_store_v1.destroy_capture_v1(
                        access=self._private_store_cleanup_access_v1,
                        capture_epoch=capture_epoch,
                        cleanup_fence=cleanup_fence,
                    )
                )
            except Exception:  # noqa: BLE001 - cleanup uncertainty is fatal
                destroyed = False
        if not destroyed:
            return False
        with self._lock:
            if self._capture_epoch is not capture_epoch:
                return False
            self._clear_private_capture_metadata_locked_v1()
            cleanup_token = self._private_store_cleanup_token_v1
        if cleanup_token is not None:
            try:
                acknowledged = self._work_controller.release_cleanup_v1(
                    cleanup_fence,
                    cleanup_token,
                    action=CleanupActionV1.ACK_CLEANUP,
                )
            except Exception:  # noqa: BLE001 - cleanup uncertainty is fatal
                acknowledged = False
            if not acknowledged:
                return False
            with self._lock:
                if self._private_store_cleanup_token_v1 is cleanup_token:
                    self._private_store_cleanup_token_v1 = None
        return self._private_evidence_store_v1.is_capture_clear_v1()

    def _erase_failed_private_capture_v1(
        self,
        transition: _CaptureTransitionV1 | None,
    ) -> bool:
        """Retire the failed capture generation and erase through M3."""

        with self._lock:
            capture_epoch = self._capture_epoch
            cleanup_token = self._private_store_cleanup_token_v1
            cleanup_fence = (
                transition.cleanup_fence
                if transition is not None
                else None
            )
        if capture_epoch is None:
            return self._private_evidence_store_v1.is_capture_clear_v1()
        if (
            cleanup_token is None
            and self._private_evidence_store_v1.is_capture_clear_v1()
        ):
            with self._lock:
                self._clear_private_capture_metadata_locked_v1()
            return True
        if cleanup_fence is None:
            try:
                retirement = self._work_controller.retire_generation_v1(
                    GenerationRetirementReasonV1.GENERIC
                )
            except Exception:  # noqa: BLE001 - failure remains closed
                return False
            cleanup_fence = retirement.cleanup_fence
            with self._lock:
                self._last_session_generation = (
                    retirement.new_epoch.generation
                )
        return self._destroy_private_capture_with_cleanup_fence_v1(
            cleanup_fence
        )

    def _private_capture_is_clear_locked_v1(self) -> bool:
        return bool(
            self._active_capture_capability_v1 is None
            and not self._frame_records_v1
            and not self._unique_frame_digests_v1
            and self._accepted_frame_bytes_v1 == 0
            and not self._active_frame_upload_permits_v1
            and self._profile_id_v1 is None
            and self._inactivity_task_v1 is None
            and self._inactivity_work_v1 is None
            and self._processor_task_v1 is None
            and self._processor_work_v1 is None
            and (
                self._ocr_service_v1 is None
                or self._ocr_service_v1.active_request_count_v1() == 0
            )
            and (
                self._admission_extraction_service_v1
                .active_request_count_v1()
                == 0
            )
            and self._private_store_cleanup_token_v1 is None
            and self._private_evidence_store_v1.is_capture_clear_v1()
        )

    def _fail_protocol_runtime_v1(self) -> None:
        with self._lock:
            capture_was_active = self._capture_epoch is not None
            transition = self._active_transition
        if capture_was_active and self._enter_failed_closed_v1(
            transition,
            CaptureFailureReasonV1.INTERNAL_FAILURE,
        ):
            self._request_failure_termination_v1()

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
        except (CaptureProtocolErrorV1, PrivateEvidenceStoreErrorV1):
            raise
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

    @asynccontextmanager
    async def _serialized_frame_commit_v1(
        self,
        registered_work: RegisteredWorkV1,
    ):
        """Acquire the mutation lock without deadlocking retired upload work."""

        if registered_work.cancellation.is_cancelled:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        acquire_task = asyncio.create_task(self._operation_lock.acquire())
        cancellation_task = asyncio.create_task(
            registered_work.cancellation.wait_async()
        )
        acquired = False
        acquire_result_observed = False
        try:
            done, _ = await asyncio.wait(
                {acquire_task, cancellation_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if acquire_task in done:
                acquired = bool(acquire_task.result())
                acquire_result_observed = True
            if (
                registered_work.cancellation.is_cancelled
                or cancellation_task in done
            ):
                if not acquire_task.done():
                    acquire_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await acquire_task
                elif not acquired:
                    acquired = bool(acquire_task.result())
                    acquire_result_observed = True
                if acquired:
                    self._operation_lock.release()
                    acquired = False
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            if not acquired:
                acquired = bool(await acquire_task)
                acquire_result_observed = True
            if registered_work.cancellation.is_cancelled:
                self._operation_lock.release()
                acquired = False
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            self._operation_idle.clear()
            try:
                yield
            finally:
                self._operation_idle.set()
                self._operation_lock.release()
                acquired = False
        finally:
            if not cancellation_task.done():
                cancellation_task.cancel()
                with suppress(asyncio.CancelledError):
                    await cancellation_task
            if not acquire_task.done():
                acquire_task.cancel()
                with suppress(asyncio.CancelledError):
                    await acquire_task
            elif (
                not acquire_result_observed
                and not acquire_task.cancelled()
                and acquire_task.exception() is None
                and acquire_task.result()
            ):
                self._operation_lock.release()
            if acquired:
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
        detached_work: _DetachedPrivateCaptureWorkV1 | None = None
        with self._lock:
            if self._destroyed:
                return False
            if transition is not None and self._active_transition is not transition:
                return False
            cleanup_prepared, detached_work = (
                self._prepare_private_capture_end_locked_v1()
            )
            self._isolation_controller.close_v1()
            self._isolation_controller.disable_transport_keepalive_v1()
            self._fatal_failure = reason
            self._failure_reason = reason
            self._state = CaptureStateV1.FAILED_CLOSED
            self._active_transition = None
            self._quiescence_complete = False
            self._record_v1(SecurityAuditEventCodeV1.CAPTURE_FAILED_CLOSED)
        if detached_work is not None:
            self._cancel_detached_private_capture_work_v1(detached_work)
        cleanup_succeeded = bool(
            cleanup_prepared
            and self._erase_failed_private_capture_v1(transition)
        )
        if not cleanup_succeeded:
            self._request_failure_termination_v1()
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

        if transition.kind is CaptureTransitionKindV1.END:
            with self._lock:
                capture_epoch = self._capture_epoch
                if (
                    self._active_transition is not transition
                    or self._state is not CaptureStateV1.ENDING
                ):
                    raise _TransitionFailureV1(
                        CaptureFailureReasonV1.STALE_TRANSITION
                    )
            if capture_epoch is not None:
                destroyed = (
                    self._destroy_private_capture_with_cleanup_fence_v1(
                        retirement.cleanup_fence
                    )
                )
            else:
                destroyed = (
                    self._private_store_cleanup_token_v1 is None
                    and self._private_evidence_store_v1.is_capture_clear_v1()
                )
            if not destroyed:
                raise _TransitionFailureV1(
                    CaptureFailureReasonV1.SEMANTIC_CLEANUP_FAILED
                )

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
                transition.cleanup_fence = retirement.cleanup_fence
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
        detached_work: list[_DetachedPrivateCaptureWorkV1] = []
        rejected: list[CaptureFailureReasonV1] = []
        failed: list[_CaptureTransitionV1] = []

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
                    CaptureStateV1.CAPTURING,
                    CaptureStateV1.BUILDING_ASSERTIONS,
                    CaptureStateV1.READY,
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
                prepared, detached = (
                    self._prepare_private_capture_end_locked_v1()
                )
                if detached is not None:
                    detached_work.append(detached)
                if not prepared:
                    failed.append(transition)
                    return
                self._record_v1(SecurityAuditEventCodeV1.CAPTURE_ENDING)
                claimed.append(transition)

        try:
            session_live = self._run_if_session_live_v1(claim)
        finally:
            for detached in detached_work:
                self._cancel_detached_private_capture_work_v1(detached)
        if not session_live:
            reason = CaptureFailureReasonV1.SESSION_AUTHORITY_UNAVAILABLE
            if self._enter_failed_closed_v1(None, reason):
                self._request_failure_termination_v1()
                raise CaptureFailedClosedV1(reason)
            self._reject_v1(CaptureFailureReasonV1.SESSION_SHUTDOWN)
        if failed:
            reason = CaptureFailureReasonV1.INTERNAL_FAILURE
            self._enter_failed_closed_v1(failed[0], reason)
            self._request_failure_termination_v1()
            raise CaptureFailedClosedV1(reason)
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
                    or not self._private_capture_is_clear_locked_v1()
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
                transition.cleanup_fence = retirement.cleanup_fence
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

    def _prepare_shutdown_v1(self) -> bool:
        detached_work: _DetachedPrivateCaptureWorkV1 | None = None
        ocr_service: PrivateOcrServiceV1 | None = None
        with self._lock:
            if self._destroyed:
                return self._private_evidence_store_v1.is_capture_clear_v1()
            self._shutdown_started = True
            ocr_service = self._ocr_service_v1
            was_active = self._state is not CaptureStateV1.IDLE
            transition = self._active_transition
            self._active_transition = None
            cleanup_prepared, detached_work = (
                self._prepare_private_capture_end_locked_v1()
            )
            if was_active:
                self._state = CaptureStateV1.FAILED_CLOSED
                self._failure_reason = (
                    CaptureFailureReasonV1.SESSION_SHUTDOWN
                )
                self._fatal_failure = self._failure_reason
                self._record_v1(
                    SecurityAuditEventCodeV1.CAPTURE_FAILED_CLOSED
                )
        if ocr_service is not None:
            ocr_service.close_admission_v1()
        self._admission_extraction_service_v1.close_admission_v1()
        if detached_work is not None:
            self._cancel_detached_private_capture_work_v1(detached_work)
        if transition is not None:
            self._close_transition_cleanup_token_v1(transition)
        return cleanup_prepared

    def _cleanup_private_capture_for_shutdown_fence_v1(
        self,
        cleanup_fence: RetiredGenerationCleanupFenceV1,
    ) -> bool:
        with self._lock:
            capture_epoch = self._capture_epoch
        if capture_epoch is None:
            return True
        if (
            cleanup_fence.session_instance_id
            != capture_epoch.session_epoch.session_instance_id
            or cleanup_fence.retired_generation
            != capture_epoch.session_epoch.generation
        ):
            return True
        return self._destroy_private_capture_with_cleanup_fence_v1(
            cleanup_fence
        )

    def _finish_shutdown_v1(
        self,
        *,
        cleanup_prepared: bool,
        controller_cleanup_succeeded: bool,
    ) -> bool:
        with self._lock:
            if self._destroyed:
                return bool(
                    controller_cleanup_succeeded
                    and self._private_evidence_store_v1
                    .is_capture_clear_v1()
                )
            private_cleanup_succeeded = bool(
                cleanup_prepared
                and self._private_store_cleanup_token_v1 is None
                and self._private_evidence_store_v1.is_capture_clear_v1()
            )
            try:
                store_shutdown = (
                    self._private_evidence_store_v1.shutdown_v1(
                        cleanup_access=(
                            self._private_store_cleanup_access_v1
                        )
                    )
                )
            except Exception:  # noqa: BLE001 - shutdown remains failed closed
                store_shutdown = False
            private_cleanup_succeeded = bool(
                private_cleanup_succeeded and store_shutdown
            )
            if not private_cleanup_succeeded:
                self._state = CaptureStateV1.FAILED_CLOSED
                self._failure_reason = (
                    CaptureFailureReasonV1.SESSION_SHUTDOWN
                )
                self._fatal_failure = self._failure_reason
                self._record_v1(
                    SecurityAuditEventCodeV1.CAPTURE_FAILED_CLOSED
                )
                return False
            self._replay_ledger_v1.clear_v1()
            self._capability_authority_v1.close_v1()
            self._active_transition = None
            self._capture_epoch = None
            self._capture_id = None
            self._quiescence_complete = False
            self._isolation_controller.destroy_v1()
            self._destroyed = True
            return bool(controller_cleanup_succeeded)

    def _start_shutdown_v1(self) -> bool:
        """Compatibility teardown for M4A harnesses with no M5A partition."""

        cleanup_prepared = self._prepare_shutdown_v1()
        if (
            self._private_store_cleanup_token_v1 is not None
            or not self._private_evidence_store_v1.is_capture_clear_v1()
        ):
            return False
        return self._finish_shutdown_v1(
            cleanup_prepared=cleanup_prepared,
            controller_cleanup_succeeded=True,
        )

    def shutdown_v1(
        self,
        retired_cleanup_v1: Callable[[], None] | None = None,
        *,
        _retire_work_controller_v1: bool = False,
    ) -> bool:
        """Destroy capture authority before synchronous session teardown."""

        cleanup_prepared = self._prepare_shutdown_v1()
        private_partition_active = bool(
            self._private_store_cleanup_token_v1 is not None
            or not self._private_evidence_store_v1.is_capture_clear_v1()
        )
        if not _retire_work_controller_v1 and not private_partition_active:
            finalized = self._finish_shutdown_v1(
                cleanup_prepared=cleanup_prepared,
                controller_cleanup_succeeded=True,
            )
            return bool(
                finalized
                and self._operation_idle.wait(
                    timeout=(
                        self._work_controller
                        .cleanup_timeout_seconds_v1()
                    ),
                )
            )
        finalized_before_controller = bool(
            not private_partition_active
            and self._finish_shutdown_v1(
                cleanup_prepared=cleanup_prepared,
                controller_cleanup_succeeded=True,
            )
        )
        controller_cleanup_succeeded = self._work_controller.shutdown(
            retired_cleanup_v1,
            destructive_cleanup_v1=(
                self._cleanup_private_capture_for_shutdown_fence_v1
            ),
        )
        operation_idle = self._operation_idle.wait(
            timeout=self._work_controller.cleanup_timeout_seconds_v1(),
        )
        finalized = self._finish_shutdown_v1(
            cleanup_prepared=cleanup_prepared,
            controller_cleanup_succeeded=(
                controller_cleanup_succeeded and operation_idle
            ),
        )
        return bool(
            finalized
            and (
                finalized_before_controller
                or controller_cleanup_succeeded
            )
            and operation_idle
        )

    async def _close_ocr_transport_async_v1(self) -> bool:
        with self._lock:
            service = self._ocr_service_v1
        if service is None:
            return True
        try:
            await service.close_v1()
        except Exception:  # noqa: BLE001 - shutdown remains fail closed
            return False
        return service.active_request_count_v1() == 0

    async def shutdown_async_v1(
        self,
        retired_cleanup_v1: Callable[[], None] | None = None,
        *,
        _retire_work_controller_v1: bool = False,
    ) -> bool:
        """Destroy capture authority without retaining a lock across awaits."""

        cleanup_prepared = self._prepare_shutdown_v1()
        private_partition_active = bool(
            self._private_store_cleanup_token_v1 is not None
            or not self._private_evidence_store_v1.is_capture_clear_v1()
        )
        if not _retire_work_controller_v1 and not private_partition_active:
            finalized = self._finish_shutdown_v1(
                cleanup_prepared=cleanup_prepared,
                controller_cleanup_succeeded=True,
            )
            deadline = (
                time.monotonic()
                + self._work_controller.cleanup_timeout_seconds_v1()
            )
            while not self._operation_idle.is_set():
                if time.monotonic() >= deadline:
                    return False
                await asyncio.sleep(0.01)
            return bool(
                finalized
                and await self._close_ocr_transport_async_v1()
            )
        finalized_before_controller = bool(
            not private_partition_active
            and self._finish_shutdown_v1(
                cleanup_prepared=cleanup_prepared,
                controller_cleanup_succeeded=True,
            )
        )
        controller_cleanup_succeeded = (
            await self._work_controller.shutdown_async(
                retired_cleanup_v1,
                destructive_cleanup_v1=(
                    self._cleanup_private_capture_for_shutdown_fence_v1
                ),
            )
        )
        deadline = (
            time.monotonic()
            + self._work_controller.cleanup_timeout_seconds_v1()
        )
        while not self._operation_idle.is_set():
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.01)
        finalized = self._finish_shutdown_v1(
            cleanup_prepared=cleanup_prepared,
            controller_cleanup_succeeded=controller_cleanup_succeeded,
        )
        ocr_transport_closed = await self._close_ocr_transport_async_v1()
        return bool(
            finalized
            and ocr_transport_closed
            and (
                finalized_before_controller
                or controller_cleanup_succeeded
            )
        )

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

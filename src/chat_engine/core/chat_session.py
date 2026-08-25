import asyncio
import contextlib
import queue
import threading
import time
import uuid
from collections.abc import Callable
from typing import Dict, List, Iterable

from loguru import logger

from chat_engine.core.signal_manager import SignalManager
from chat_engine.core.stream_manager import (
    ChatDataSubmitter,
    ChatDataSubmitterConsumerViewV1,
    StreamManager,
)
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_stream import ChatStreamIdentity
from chat_engine.data_models.chat_stream_status import ChatStreamStatus

from chat_engine.common.logic_base import LogicBase
from chat_engine.common.handler_base import HandlerBase

from chat_engine.data_models.internal.chat_data_endpoints import DataSink
from chat_engine.data_models.internal.handler_definition_data import HandlerBaseInfo
from chat_engine.data_models.internal.handler_session_data import HandlerRegistry, HandlerRecord, HandlerEnv
from chat_engine.data_models.internal.logic_definition_data import LogicBaseInfo
from chat_engine.data_models.internal.logic_session_data import LogicEnv

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.chat_engine_config_data import (HandlerBaseConfigModel, ChatEngineConfigModel,
                                                             LogicBaseConfigModel)
from chat_engine.data_models.chat_signal import ChatSignal, SignalFilterRule
from chat_engine.data_models.chat_signal_type import ChatSignalType

from chat_engine.contexts.session_context import SessionContext
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import (
    CoreRegistrarCapabilityV1,
    ConsumerCapabilityV1,
    ProducerAuthorityReferenceV1,
    ValidatedDispatchV1,
)
from chat_engine.security.envelope import SecurityClassificationV1
from chat_engine.security.history import SessionHistoryConsumerViewV1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkValidationBoundaryV1
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)
from certificate_capture.coordinator import CaptureCoordinatorV1
from certificate_capture.contracts.ocr import StoredOcrResultV1
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.isolation import (
    NormalApplicationAdmissionViewV1,
)
from certificate_capture.ocr.client import OcrDeploymentConfigV1
from certificate_capture.private_authority import (
    PrivateEvidenceAuthorityV1,
)
from certificate_capture.protocol import (
    BeginCaptureGrantV1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
    CapturePublicStatusV1,
    EndCaptureResultV1,
    FrameUploadPermitV1,
    FrameUploadResultV1,
    SealResultV1,
    ValidatedJpegFrameV1,
)
from certificate_capture.status import CaptureStatusV1
from service.service_security.certificate_session_authority import (
    SessionOwnershipV1,
)


class ChatSession:
    input_type_mapping = {
        EngineChannelType.VIDEO: [ChatDataType.CAMERA_VIDEO],
        EngineChannelType.AUDIO: [ChatDataType.MIC_AUDIO],
        EngineChannelType.TEXT: [ChatDataType.HUMAN_TEXT]
    }

    def __init__(
        self,
        session_context: SessionContext,
        _engine_config: ChatEngineConfigModel,
        *,
        _security_authority_v1: SecurityAuthorityV1 | None = None,
        _security_registrar_v1: CoreRegistrarCapabilityV1 | None = None,
        _work_controller_v1: SessionWorkControllerV1 | None = None,
        _capture_session_live_action_v1: (
            Callable[[Callable[[], None]], bool] | None
        ) = None,
        _capture_feature_enabled_v1: (
            Callable[[], bool] | None
        ) = None,
        _capture_failure_terminator_v1: (
            Callable[[], None] | None
        ) = None,
        _certificate_ocr_deployment_v1: (
            OcrDeploymentConfigV1 | None
        ) = None,
    ):
        self.session_context = session_context
        if (
            _certificate_ocr_deployment_v1 is not None
            and (
                not isinstance(
                    _certificate_ocr_deployment_v1,
                    OcrDeploymentConfigV1,
                )
                or not self.session_context.certificate_capture_enabled_v1
            )
        ):
            raise RuntimeError("private OCR deployment unavailable")
        self._certificate_ocr_deployment_v1 = (
            _certificate_ocr_deployment_v1
        )
        self._certificate_ocr_bootstrap_lock_v1 = asyncio.Lock()
        self._certificate_ocr_bootstrapped_v1 = False
        self._stop_state_lock_v1 = threading.Lock()
        self._stop_finalize_lock_v1 = threading.Lock()
        self._stop_complete_event_v1 = threading.Event()
        self._fully_quiesced_event_v1 = threading.Event()
        self._stop_started_v1 = False
        self._shutdown_deadline_monotonic_v1: float | None = None
        self._shutdown_quarantined_v1 = False
        self._signal_shutdown_started_v1 = False
        self._context_cleanup_threads_v1: dict[
            str, threading.Thread
        ] = {}
        self._context_cleanup_failures_v1: set[str] = set()
        self._capture_external_session_live_action_v1 = (
            _capture_session_live_action_v1
        )
        self._security_authority: SecurityAuthorityV1 | None = None
        self._security_registrar_v1: (
            CoreRegistrarCapabilityV1 | None
        ) = None
        if self.session_context.secure_dispatch_enabled_v1:
            if _security_authority_v1 is None:
                (
                    self._security_authority,
                    self._security_registrar_v1,
                ) = SecurityAuthorityV1.create_v1()
            else:
                if _security_registrar_v1 is None:
                    raise RuntimeError(
                        "injected security authority requires registrar"
                    )
                self._security_authority = _security_authority_v1
                self._security_registrar_v1 = _security_registrar_v1
        elif (
            _security_authority_v1 is not None
            or _security_registrar_v1 is not None
        ):
            raise RuntimeError(
                "security authority requires a secure session"
            )
        self._history_capability: ConsumerCapabilityV1 | None = None
        self._history_producer_authority: (
            ProducerAuthorityReferenceV1 | None
        ) = None
        if self._security_authority is not None:
            self._history_capability = (
                self._security_authority
                ._issue_public_consumer_capability_v1(
                    self._security_registrar_v1
                )
            )
            if self._history_capability is None:
                raise RuntimeError("secure dispatch authority unavailable")
            self._history_producer_authority = (
                self._security_authority._issue_producer_authority_v1(
                    self._security_registrar_v1,
                    self._history_capability,
                )
            )
            if self._history_producer_authority is None:
                raise RuntimeError("secure history authority unavailable")
            self.session_context.session_history.configure_security_write_authorizer_v1(
                self._security_authority.history_writer_is_authorized_v1
            )
        self._work_controller_v1: SessionWorkControllerV1 | None = None
        if self.session_context.secure_dispatch_enabled_v1:
            self._work_controller_v1 = (
                _work_controller_v1
                if _work_controller_v1 is not None
                else SessionWorkControllerV1()
            )
            if not self._work_controller_v1._claim_session_owner_v1():
                raise RuntimeError("secure work controller unavailable")
        elif _work_controller_v1 is not None:
            raise RuntimeError(
                "work controller requires a secure session"
            )
        self._capture_coordinator_v1: CaptureCoordinatorV1 | None = None
        self._private_evidence_authority_v1: (
            PrivateEvidenceAuthorityV1 | None
        ) = None
        self._normal_application_admission_v1: (
            NormalApplicationAdmissionViewV1 | None
        ) = None
        if self.session_context.certificate_capture_enabled_v1:
            if (
                self._work_controller_v1 is None
                or self._security_authority is None
            ):
                raise RuntimeError(
                    "capture coordinator security authority unavailable"
                )
            if self._security_registrar_v1 is None:
                raise RuntimeError(
                    "capture coordinator registrar unavailable"
                )
            self._private_evidence_authority_v1 = (
                PrivateEvidenceAuthorityV1._create_for_session_v1(
                    security_authority=self._security_authority,
                    registrar=self._security_registrar_v1,
                )
            )
            (
                self._capture_coordinator_v1,
                self._normal_application_admission_v1,
            ) = CaptureCoordinatorV1._create_for_session_v1(
                work_controller=self._work_controller_v1,
                private_evidence_authority_v1=(
                    self._private_evidence_authority_v1
                ),
                feature_enabled_v1=(
                    _capture_feature_enabled_v1
                    if _capture_feature_enabled_v1 is not None
                    else (
                        lambda: self.session_context
                        .certificate_capture_enabled_v1
                    )
                ),
                security_authority_usable_v1=(
                    self._security_authority.is_usable_v1
                ),
                session_live_action_v1=(
                    self._perform_if_capture_session_live_v1
                ),
                quiescence_drain_v1=(
                    self._drain_capture_transition_work_v1
                ),
                semantic_cleanup_v1=(
                    self._clear_capture_transition_semantic_state_v1
                ),
                failure_terminator_v1=(
                    _capture_failure_terminator_v1
                ),
            )
        self._work_runtime_v1: SessionWorkRuntimeV1 | None = None
        if self._work_controller_v1 is not None:
            self._work_runtime_v1 = SessionWorkRuntimeV1(
                self._work_controller_v1,
                self._security_authority,
                self._normal_application_admission_v1,
            )
        self.signal_manager = SignalManager(
            self.session_context.session_clock,
            security_authority=self._security_authority,
            work_runtime_v1=self._work_runtime_v1,
        )
        self.signal_manager.init()
        self.stream_manager = StreamManager(
            self.signal_manager,
            security_authority=self._security_authority,
            work_runtime_v1=self._work_runtime_v1,
        )
        self.stream_manager.enable_debug_logging(True)
        self.data_sinks: Dict[ChatDataType, List[DataSink]] = {}
        self.handlers: Dict[str, HandlerRecord] = {}
        self._playback_begin_event_ids: Dict[str, str] = {}
        self._register_playback_auto_recorder()

    def _perform_if_capture_session_live_v1(
        self,
        action: Callable[[], None],
    ) -> bool:
        ran: list[bool] = []

        def perform_locally() -> None:
            with self._stop_state_lock_v1:
                if (
                    self._stop_started_v1
                    or not self.session_context.shared_states.active
                ):
                    return
                action()
                ran.append(True)

        external = self._capture_external_session_live_action_v1
        if external is not None:
            if not external(perform_locally):
                return False
        else:
            perform_locally()
        return bool(ran)

    async def _begin_certificate_capture_v1(self) -> CaptureEpochV1:
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise RuntimeError("capture coordinator unavailable")
        return await coordinator.begin_capture_v1()

    async def _end_certificate_capture_v1(
        self,
        capture_epoch: CaptureEpochV1 | None = None,
        *,
        capture_seq: int | None = None,
    ) -> CaptureStatusV1:
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise RuntimeError("capture coordinator unavailable")
        return await coordinator.end_capture_v1(
            capture_epoch,
            capture_seq=capture_seq,
        )

    def _certificate_capture_status_v1(self) -> CaptureStatusV1:
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise RuntimeError("capture coordinator unavailable")
        return coordinator.snapshot_v1()

    async def _bootstrap_certificate_ocr_v1(
        self,
        deployment: OcrDeploymentConfigV1,
    ) -> None:
        """Install one reviewed private OCR runtime for this owning session."""

        coordinator = self._capture_coordinator_v1
        if (
            coordinator is None
            or not self.session_context.certificate_capture_enabled_v1
            or not isinstance(deployment, OcrDeploymentConfigV1)
            or (
                self._certificate_ocr_deployment_v1 is not None
                and deployment != self._certificate_ocr_deployment_v1
            )
        ):
            raise RuntimeError("private OCR unavailable")
        async with self._certificate_ocr_bootstrap_lock_v1:
            if self._certificate_ocr_bootstrapped_v1:
                return
            await coordinator._bootstrap_private_ocr_runtime_v1(deployment)
            self._certificate_ocr_deployment_v1 = deployment
            self._certificate_ocr_bootstrapped_v1 = True

    async def _process_certificate_ocr_frames_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        frame_ids: tuple[uuid.UUID, ...],
    ) -> tuple[StoredOcrResultV1, ...]:
        """Trusted owner seam returning opaque encrypted-record receipts."""

        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise RuntimeError("private OCR unavailable")
        if not self._certificate_ocr_bootstrapped_v1:
            deployment = self._certificate_ocr_deployment_v1
            if deployment is None:
                raise RuntimeError("private OCR unavailable")
            await self._bootstrap_certificate_ocr_v1(deployment)
        return await coordinator._process_private_ocr_frames_v1(
            capture_epoch=capture_epoch,
            frame_ids=frame_ids,
        )

    def _require_certificate_capture_ownership_v1(
        self,
        ownership: SessionOwnershipV1,
    ) -> None:
        admission = self.session_context.session_admission
        if (
            not isinstance(ownership, SessionOwnershipV1)
            or admission is None
            or ownership.session_id != admission.session_id
            or ownership.owner_issuer != admission.owner_issuer
            or ownership.owner_subject != admission.owner_subject
            or self.session_context.session_info.session_id
            != ownership.session_id
        ):
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )

    async def _begin_certificate_capture_protocol_v1(
        self,
        *,
        request_id: uuid.UUID,
        control_seq: int,
        profile_id: str,
        ownership: SessionOwnershipV1,
    ) -> BeginCaptureGrantV1:
        self._require_certificate_capture_ownership_v1(ownership)
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return await coordinator.begin_capture_protocol_v1(
            request_id=request_id,
            control_seq=control_seq,
            profile_id=profile_id,
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
            session_expires_at_epoch_seconds=(
                ownership.expires_at_epoch_seconds
            ),
        )

    async def _admit_certificate_frame_upload_v1(
        self,
        *,
        capture_id: uuid.UUID,
        frame_seq: int,
        capture_capability: str,
        ownership: SessionOwnershipV1,
    ) -> FrameUploadPermitV1:
        self._require_certificate_capture_ownership_v1(ownership)
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return await coordinator.admit_frame_upload_v1(
            capture_id=capture_id,
            frame_seq=frame_seq,
            capture_capability=capture_capability,
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
        )

    async def _commit_certificate_frame_upload_v1(
        self,
        permit: FrameUploadPermitV1,
        validated_frame: ValidatedJpegFrameV1,
        encoded_frame: bytearray,
    ) -> FrameUploadResultV1:
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return await coordinator.commit_frame_upload_v1(
            permit,
            validated_frame,
            encoded_frame,
        )

    def _release_certificate_frame_upload_v1(
        self,
        permit: FrameUploadPermitV1,
    ) -> None:
        coordinator = self._capture_coordinator_v1
        if coordinator is not None:
            coordinator.release_frame_upload_permit_v1(permit)

    async def _seal_certificate_capture_protocol_v1(
        self,
        *,
        request_id: uuid.UUID,
        control_seq: int,
        capture_id: uuid.UUID,
        capture_capability: str,
        ownership: SessionOwnershipV1,
    ) -> SealResultV1:
        self._require_certificate_capture_ownership_v1(ownership)
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return await coordinator.seal_capture_protocol_v1(
            request_id=request_id,
            control_seq=control_seq,
            capture_id=capture_id,
            capture_capability=capture_capability,
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
        )

    async def _certificate_capture_public_status_v1(
        self,
        *,
        capture_id: uuid.UUID,
        capture_capability: str,
        ownership: SessionOwnershipV1,
    ) -> CapturePublicStatusV1:
        self._require_certificate_capture_ownership_v1(ownership)
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return await coordinator.capture_public_status_v1(
            capture_id=capture_id,
            capture_capability=capture_capability,
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
        )

    async def _end_certificate_capture_protocol_v1(
        self,
        *,
        request_id: uuid.UUID,
        control_seq: int,
        capture_id: uuid.UUID,
        capture_capability: str,
        ownership: SessionOwnershipV1,
    ) -> EndCaptureResultV1:
        self._require_certificate_capture_ownership_v1(ownership)
        coordinator = self._capture_coordinator_v1
        if coordinator is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return await coordinator.end_capture_protocol_v1(
            request_id=request_id,
            control_seq=control_seq,
            capture_id=capture_id,
            capture_capability=capture_capability,
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
        )

    @classmethod
    def handler_pumper(
        cls,
        session_context: SessionContext,
        handler_env: HandlerEnv,
        security_authority: SecurityAuthorityV1 | None = None,
    ):
        shared_states = session_context.shared_states
        input_queue = handler_env.input_queue
        handler = handler_env.handler
        context = handler_env.context
        output_info = handler_env.output_info
        # Use handler_output_info (with original type keys) if available,
        # so handler code can use its declared types even with output_type_override
        handler_visible_output_info = handler_env.handler_output_info or output_info
        if output_info is None:
            output_info = {}
        if handler_visible_output_info is None:
            handler_visible_output_info = {}
        handler.warmup_context(session_context, context)
        
        # Track stream begin events for auto history recording
        stream_begin_events: Dict[str, str] = {}  # stream_key -> event_id

        while shared_states.active:
            try:
                queued_item = input_queue.get_nowait()
            except (queue.Empty, asyncio.QueueEmpty):
                time.sleep(0.03)
                continue
            runtime = context.work_runtime_v1
            work_item: WorkBoundItemV1 | None = None
            envelope_ref = None
            if runtime is not None:
                candidate = getattr(
                    queued_item,
                    "work_item_v1",
                    None,
                )
                if isinstance(candidate, WorkBoundItemV1):
                    work_item = candidate
                    if not runtime.validate_work_v1(
                        work_item.registered_work,
                        WorkValidationBoundaryV1.QUEUE_DEQUEUE,
                    ):
                        runtime.log_late_drop_v1(
                            work_item.registered_work,
                            "QUEUE_DEQUEUE",
                        )
                        work_item.release_once_v1(runtime)
                        continue
                    envelope_ref = work_item.envelope_ref

            try:
                scope = (
                    runtime.activate_work_v1(
                        work_item.registered_work,
                        envelope_ref,
                    )
                    if runtime is not None and work_item is not None
                    else contextlib.nullcontext()
                )
                with scope:
                    cls._process_handler_item_v1(
                        handler_env=handler_env,
                        security_authority=security_authority,
                        queued_item=queued_item,
                        handler_visible_output_info=(
                            handler_visible_output_info
                        ),
                        stream_begin_events=stream_begin_events,
                    )
            finally:
                if runtime is not None and work_item is not None:
                    work_item.release_once_v1(runtime)

    @classmethod
    def _process_handler_item_v1(
        cls,
        *,
        handler_env: HandlerEnv,
        security_authority: SecurityAuthorityV1 | None,
        queued_item,
        handler_visible_output_info,
        stream_begin_events: Dict[str, str],
    ) -> None:
        handler = handler_env.handler
        context = handler_env.context
        runtime = context.work_runtime_v1

        def protected(boundary, action) -> bool:
            if runtime is None:
                action()
                return True
            return runtime.perform_current_if_live_v1(boundary, action)

        validated_dispatch: ValidatedDispatchV1 | None = None
        history_authorized = True
        if security_authority is not None:
            capability = handler_env.consumer_capability
            if capability is None:
                security_authority._record(
                    SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
                )
                return
            validated_dispatch = (
                security_authority.validate_dequeued_dispatch_v1(
                    queued_item,
                    capability,
                )
            )
            if validated_dispatch is None:
                return
            if runtime is not None and runtime.current_work_v1() is None:
                security_authority._record(
                    SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED,
                    dispatch_id=validated_dispatch.dispatch_id,
                )
                return
            if (
                runtime is not None
                and runtime.current_envelope_ref_v1()
                != validated_dispatch.envelope_ref
            ):
                security_authority._record(
                    SecurityAuditEventCodeV1.DISPATCH_DENIED,
                    dispatch_id=validated_dispatch.dispatch_id,
                )
                return
            input_data = validated_dispatch.payload
            if not isinstance(input_data, ChatData):
                security_authority._record(
                    SecurityAuditEventCodeV1.DISPATCH_DENIED,
                    dispatch_id=validated_dispatch.dispatch_id,
                )
                return
            producer_authority = handler_env.producer_authority
            if (
                producer_authority is None
                or not security_authority.record_dispatch_for_producer_v1(
                    producer_authority,
                    capability,
                    validated_dispatch,
                )
            ):
                return

            trusted_identity = validated_dispatch.stream_ref.identity
            input_data.stream_id = ChatStreamIdentity(
                data_type=trusted_identity.data_type,
                builder_id=trusted_identity.builder_id,
                stream_id=trusted_identity.stream_id,
                name=trusted_identity.name,
                producer_name=trusted_identity.producer_name,
            )
            input_data.type = validated_dispatch.trusted_data_type
            input_data.source = validated_dispatch.trusted_source
            if not protected(
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                lambda: handler_env.core_data_submitter
                .update_input_dispatch_v1(validated_dispatch),
            ):
                return
            history_capability = handler_env.history_capability
            history_authorized = (
                history_capability is not None
                and security_authority.consumer_is_authorized_v1(
                    validated_dispatch.envelope_ref,
                    history_capability,
                    audit_denial=False,
                )
            )
        else:
            input_data = queued_item
            handler_env.core_data_submitter.update_input_stream(input_data)

        if input_data.stream_id is not None:
            stream_manager = getattr(context, "stream_manager", None)
            if stream_manager is not None:
                stream = stream_manager.find_stream(input_data.stream_id)
                if (
                    stream is not None
                    and stream.status == ChatStreamStatus.CANCELLED
                ):
                    return

        if (
            input_data.is_first_data
            and history_authorized
            and handler.should_auto_record_history(input_data.type)
            and input_data.stream_id is not None
        ):
            stream_key_obj = input_data.stream_id.key
            stream_key_str = (
                str(stream_key_obj) if stream_key_obj else None
            )
            def record_history_begin() -> None:
                event_id = handler.on_history_record(
                    context,
                    signal_type=ChatSignalType.STREAM_BEGIN,
                    data_type=input_data.type,
                    source_stream_key=stream_key_str,
                )
                if event_id and stream_key_str:
                    stream_begin_events[stream_key_str] = event_id

            protected(
                WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
                record_history_begin,
            )

        if (
            handler.should_auto_record_history(input_data.type)
            and history_authorized
            and input_data.stream_id is not None
            and input_data.data is not None
            and context.session_history is not None
        ):
            try:
                text_data = input_data.data.get_main_data()
                if text_data and isinstance(text_data, str):
                    stream_key_obj = input_data.stream_id.key
                    stream_key_str = (
                        str(stream_key_obj) if stream_key_obj else None
                    )
                    if stream_key_str:
                        chunk_id = (
                            f"{input_data.timestamp[0]}:"
                            f"{input_data.timestamp[1]}"
                        )
                        protected(
                            WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
                            lambda: context.session_history
                            .accumulate_stream_data(
                                stream_key_str,
                                text_data,
                                chunk_id,
                            ),
                        )
            except Exception:
                pass

        actual_type = input_data.type
        if handler_env.input_type_reverse_mapping:
            original_type = handler_env.input_type_reverse_mapping.get(
                actual_type
            )
            if original_type:
                input_data.type = original_type

        try:
            if (
                runtime is not None
                and not runtime.validate_current_v1(
                    WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL
                )
            ):
                input_data.type = actual_type
                return
            handler_result = handler.handle(
                context,
                input_data,
                handler_visible_output_info,
            )
        except Exception as error:
            if (
                validated_dispatch is not None
                and validated_dispatch.classification
                is SecurityClassificationV1.CERTIFICATE_PRIVATE
            ):
                logger.bind(
                    dispatch_id=validated_dispatch.dispatch_id
                ).error("PRIVATE_HANDLER_FAILURE_V1")
            elif runtime is not None and not runtime.validate_current_v1(
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK
            ):
                current = runtime.current_work_v1()
                if current is not None:
                    runtime.log_late_drop_v1(
                        current,
                        "HANDLER_EXCEPTION_AFTER_RETIREMENT",
                    )
            else:
                handler_name = (
                    handler_env.handler_info.name
                    if handler_env.handler_info
                    else "Unknown"
                )
                if runtime is None:
                    logger.opt(exception=error).error(
                        f"Handler {handler_name} raised exception "
                        "during handle()."
                    )
                else:
                    logger.error("SECURE_HANDLER_FAILURE_V1")
            input_data.type = actual_type
            return

        input_data.type = actual_type

        if (
            input_data.is_last_data
            and history_authorized
            and handler.should_auto_record_history(input_data.type)
            and input_data.stream_id is not None
        ):
            stream_key_obj = input_data.stream_id.key
            stream_key_str = (
                str(stream_key_obj) if stream_key_obj else None
            )
            def finalize_history() -> None:
                begin_event_id = (
                    stream_begin_events.pop(stream_key_str, None)
                    if stream_key_str
                    else None
                )
                data_content = None
                if context.session_history is not None and stream_key_str:
                    data_content = (
                        context.session_history
                        .finalize_stream_accumulator(stream_key_str)
                    )
                if not data_content and input_data.data is not None:
                    try:
                        data_content = input_data.data.get_main_data()
                    except Exception:
                        pass
                handler.on_history_record(
                    context,
                    signal_type=ChatSignalType.STREAM_END,
                    data_type=input_data.type,
                    data=data_content,
                    related_event_id=begin_event_id,
                    source_stream_key=stream_key_str,
                )

            protected(
                WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
                finalize_history,
            )

        if not isinstance(handler_result, Iterable):
            handler_result = [handler_result]
        for handler_output in handler_result:
            if context.data_submitter is None:
                continue
            try:
                handler_env.core_data_submitter.submit(handler_output)
            except Exception as error:
                if (
                    validated_dispatch is not None
                    and validated_dispatch.classification
                    is SecurityClassificationV1.CERTIFICATE_PRIVATE
                ):
                    logger.bind(
                        dispatch_id=validated_dispatch.dispatch_id
                    ).error("PRIVATE_OUTPUT_REJECTED_V1")
                elif runtime is None or runtime.validate_current_v1(
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK
                ):
                    if runtime is None:
                        logger.opt(exception=error).error(
                            "Handler output submission failed."
                        )
                    else:
                        logger.error(
                            "SECURE_HANDLER_OUTPUT_SUBMISSION_FAILED_V1"
                        )

    def _register_playback_auto_recorder(self):
        """Register signal listeners to auto-record CLIENT_PLAYBACK stream lifecycle to SessionHistory."""
        for signal_type in (ChatSignalType.STREAM_BEGIN, ChatSignalType.STREAM_END, ChatSignalType.STREAM_CANCEL):
            self.signal_manager.register_listener(
                listener=self._on_playback_stream_signal,
                signal_filter=SignalFilterRule(signal_type, None, ChatDataType.CLIENT_PLAYBACK),
                consumer_capability=self._history_capability,
            )

    def _on_playback_stream_signal(self, signal: ChatSignal):
        """Auto-record CLIENT_PLAYBACK stream lifecycle events to SessionHistory.
        
        Parent stream ancestry (AVATAR_AUDIO etc.) is navigable through StreamManager
        at query time — no need to denormalize into history events.
        """
        session_history = self.session_context.session_history
        if session_history is None or signal.related_stream is None:
            return
        stream_key_str = signal.related_stream.stream_key_str

        def record_playback_history() -> None:
            if signal.type == ChatSignalType.STREAM_BEGIN:
                event_id = session_history.create_and_add_event(
                    data_type=ChatDataType.CLIENT_PLAYBACK,
                    signal_type=ChatSignalType.STREAM_BEGIN,
                    source_stream_key=stream_key_str,
                    owner=signal.source_name,
                    _security_writer_v1=(
                        self._history_producer_authority
                    ),
                )
                if event_id and stream_key_str:
                    self._playback_begin_event_ids[
                        stream_key_str
                    ] = event_id
            elif signal.type in (
                ChatSignalType.STREAM_END,
                ChatSignalType.STREAM_CANCEL,
            ):
                begin_event_id = (
                    self._playback_begin_event_ids.pop(
                        stream_key_str,
                        None,
                    )
                    if stream_key_str
                    else None
                )
                session_history.create_and_add_event(
                    data_type=ChatDataType.CLIENT_PLAYBACK,
                    signal_type=signal.type,
                    source_stream_key=stream_key_str,
                    owner=signal.source_name,
                    parent_event_id=begin_event_id,
                    _security_writer_v1=(
                        self._history_producer_authority
                    ),
                )

        if self._work_runtime_v1 is None:
            record_playback_history()
            return
        self._work_runtime_v1.perform_current_if_live_v1(
            WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
            record_playback_history,
        )

    def prepare_handler(
        self,
        handler: HandlerBase,
        handler_info: HandlerBaseInfo,
        handler_config: HandlerBaseConfigModel,
        *,
        _consumer_capability_v1: ConsumerCapabilityV1 | None = None,
    ):
        if (
            self._security_authority is not None
            and self._security_registrar_v1 is None
        ):
            raise RuntimeError("secure consumer registration is closed")
        consumer_capability = _consumer_capability_v1
        if self._security_authority is not None:
            if consumer_capability is None:
                consumer_capability = (
                    self._security_authority
                    ._issue_public_consumer_capability_v1(
                        self._security_registrar_v1
                    )
                )
            if consumer_capability is None:
                raise RuntimeError("secure consumer capability unavailable")
        producer_authority: ProducerAuthorityReferenceV1 | None = None
        if self._security_authority is not None:
            producer_authority = (
                self._security_authority._issue_producer_authority_v1(
                    self._security_registrar_v1,
                    consumer_capability
                )
            )
            if producer_authority is None:
                raise RuntimeError("secure producer authority unavailable")
        handler_env = HandlerEnv(handler_info=handler_info, handler=handler, config=handler_config)
        handler_env.consumer_capability = consumer_capability
        handler_env.history_capability = self._history_capability
        handler_env.producer_authority = producer_authority
        handler_env.context = handler.create_context(self.session_context, handler_env.config)
        handler_env.context.owner = handler_info.name
        handler_env.input_queue = queue.Queue()
        io_detail = handler.get_handler_detail(self.session_context, handler_env.context)
        io_detail.validate()
        
        # Type override mappings: original_type -> actual_type
        input_type_mapping: Dict[ChatDataType, ChatDataType] = {}
        output_type_mapping: Dict[ChatDataType, ChatDataType] = {}
        
        # Apply input type overrides from configuration
        if handler_config.input_type_override:
            logger.info(f"Handler {handler_info.name}: processing input_type_override {handler_config.input_type_override}, current inputs: {list(io_detail.inputs.keys())}")
            for orig_type_name, target_type_name in handler_config.input_type_override.items():
                try:
                    orig_type = ChatDataType[orig_type_name]
                    target_type = ChatDataType[target_type_name]
                    if orig_type in io_detail.inputs:
                        input_info = io_detail.inputs.pop(orig_type)
                        input_info.type = target_type
                        io_detail.inputs[target_type] = input_info
                        input_type_mapping[orig_type] = target_type
                        logger.info(f"Handler {handler_info.name}: input type override {orig_type_name} -> {target_type_name}")
                    else:
                        logger.warning(f"Handler {handler_info.name}: input type {orig_type_name} not in handler's declared inputs, skipping override")
                except KeyError as e:
                    logger.warning(f"Handler {handler_info.name}: invalid type override - {e}")
        
        # Apply output type overrides from configuration
        # Note: We only create streamer for the target type, not the original type.
        # Handler code can still use original type names because _output_type_mapping
        # handles the translation in ChatDataSubmitter.get_streamer()
        if handler_config.output_type_override:
            for orig_type_name, target_type_name in handler_config.output_type_override.items():
                try:
                    orig_type = ChatDataType[orig_type_name]
                    target_type = ChatDataType[target_type_name]
                    if orig_type in io_detail.outputs:
                        output_info = io_detail.outputs.pop(orig_type)
                        output_info.type = target_type
                        io_detail.outputs[target_type] = output_info
                        # Record mapping so handler can use original type names via get_streamer()
                        output_type_mapping[orig_type] = target_type
                        logger.debug(f"Handler {handler_info.name}: output type override {orig_type_name} -> {target_type_name}")
                except KeyError as e:
                    logger.warning(f"Handler {handler_info.name}: invalid type override - {e}")
        
        inputs = io_detail.inputs
        for input_type, input_info in inputs.items():
            sink_list = self.data_sinks.setdefault(input_type, [])
            data_sink = DataSink(
                owner=handler_info.name,
                sink_queue=handler_env.input_queue,
                consume_info=input_info,
                consumer_capability=consumer_capability,
            )
            sink_list.append(data_sink)
        handler_env.output_info = io_detail.outputs
        
        # Build reverse mapping: actual_type -> original_type
        # This allows handler code to check against its originally declared types
        if input_type_mapping:
            handler_env.input_type_reverse_mapping = {v: k for k, v in input_type_mapping.items()}

        # Build handler-visible output_info with original type keys
        # so handler code can use its declared types (e.g. HUMAN_TEXT instead of HUMAN_DUPLEX_TEXT)
        if output_type_mapping:
            output_type_reverse = {v: k for k, v in output_type_mapping.items()}
            handler_output_info = {}
            for key, value in io_detail.outputs.items():
                orig_key = output_type_reverse.get(key, key)
                handler_output_info[orig_key] = value
            handler_env.handler_output_info = handler_output_info

        handler_context = handler_env.context
        handler_context.work_runtime_v1 = self._work_runtime_v1
        handler_context.work_consumer_capability_v1 = (
            consumer_capability
        )

        filters = io_detail.signal_filters
        if filters is None or len(filters) == 0:
            filters = [SignalFilterRule(None, None, None)]
        # TODO multiple signal filter should be merged.
        for signal_filter in filters:
            self.signal_manager.register_listener(
                listener=lambda signal: handler.on_signal(handler_env.context, signal),
                signal_filter=signal_filter,
                consumer_capability=consumer_capability,
                producer_authority=producer_authority,
            )
        core_data_submitter = ChatDataSubmitter(
            security_authority=self._security_authority,
            producer_authority=producer_authority,
            work_runtime_v1=self._work_runtime_v1,
        )
        handler_env.core_data_submitter = core_data_submitter
        handler_context.signal_emitter = self.signal_manager.get_emitter(
            handler_info.name,
            producer_authority=producer_authority,
        )
        # Set type mapping for override support - handlers can use original type names
        if output_type_mapping:
            core_data_submitter.set_output_type_mapping(
                output_type_mapping
            )
        # Inject session history for duplex conversation support
        if self._security_authority is None:
            handler_context.session_history = (
                self.session_context.session_history
            )
        else:
            handler_context.session_history = SessionHistoryConsumerViewV1(
                self.session_context.session_history,
                producer_authority,
            )
        # Inject stream_manager so handlers can query stream graph and create lifecycle streams
        if self._security_authority is None:
            handler_context.stream_manager = self.stream_manager
        else:
            handler_context.stream_manager = (
                self.stream_manager.create_consumer_view_v1(
                    producer_authority
                )
            )

        for output_type, output_data_info in handler_env.output_info.items():
            streamer = self.stream_manager.create_streamer(
                data_info=output_data_info,
                data_sinks=self.data_sinks,
                producer_name=handler_info.name,
                data_name=output_data_info.data_name,
                config=output_data_info.output_stream_config,
                producer_authority=producer_authority,
            )
            core_data_submitter.register_streamer(streamer)
        if self._security_authority is None:
            handler_context.data_submitter = core_data_submitter
        else:
            handler_context.data_submitter = (
                ChatDataSubmitterConsumerViewV1(core_data_submitter)
            )
        self.handlers[handler_info.name] = HandlerRecord(env=handler_env)
        return handler_env

    def create_logic_context(self, handler_registries: List[HandlerRegistry], logic: LogicBase,
                             logic_info: LogicBaseInfo, logic_config: LogicBaseConfigModel):
        logic_env = LogicEnv(logic_info=logic_info, logic=logic, config=logic_config)
        logic_env.context = logic.create_context(handler_registries, self.session_context, logic_env.config)
        logic_env.context.owner = logic_info.name
        logic_detail = logic.get_logic_detail(self.session_context, logic_env.context)
        logic_detail.validate()

    def sort_sinks(self):
        for input_type, sink_list in self.data_sinks.items():
            sink_list.sort(key=lambda x: x.consume_info)

    def start(self):
        if self.session_context.shared_states.active:
            return
        self.sort_sinks()
        # Capability/producer issuance is construction-time only. Remove the
        # registrar before any handler lifecycle code can execute.
        if (
            self._security_authority is not None
            and (
                self._security_registrar_v1 is None
                or not self._security_authority.close_registration_v1(
                    self._security_registrar_v1
                )
            )
        ):
            raise RuntimeError("secure consumer registration close failed")
        self._security_registrar_v1 = None
        self.session_context.shared_states.active = True
        for handler_name, handler_record in self.handlers.items():
            start_args = (
                self.session_context,
                handler_record.env,
                self._security_authority,
            )
            handler_record.env.handler.start_context(self.session_context, handler_record.env.context)
            handler_record.pump_thread = threading.Thread(target=self.handler_pumper, args=start_args)
            handler_record.pump_thread.start()
        self.session_context.get_clock().start()

    def stop(self):
        if (
            self._work_controller_v1 is not None
            and not self._stop_complete_event_v1.is_set()
        ):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:
                raise RuntimeError(
                    "secure session stop requires await stop_async()"
                )
        stop_already_complete = self._stop_complete_event_v1.is_set()
        if not self._claim_stop_owner_v1():
            self._stop_complete_event_v1.wait()
            if stop_already_complete and not self.is_fully_quiesced_v1():
                self._reap_quarantined_stop_v1()
            return
        deadline = self._begin_shutdown_budget_v1()
        try:
            if self._capture_coordinator_v1 is not None:
                capture_cleanup_succeeded = (
                    self._capture_coordinator_v1.shutdown_v1(
                        self._prepare_retired_work_cleanup_v1,
                        _retire_work_controller_v1=True,
                    )
                )
                if not capture_cleanup_succeeded:
                    logger.error(
                        "CAPTURE_COORDINATOR_CLEANUP_FAILED_V1"
                    )
            elif self._work_controller_v1 is not None:
                cleanup_succeeded = self._work_controller_v1.shutdown(
                    self._prepare_retired_work_cleanup_v1
                )
                if not cleanup_succeeded:
                    logger.error("SECURE_SESSION_WORK_CLEANUP_FAILED_V1")
        finally:
            try:
                self.session_context.shared_states.active = False
                if not self._finish_stop_v1(deadline):
                    logger.error("SECURE_SESSION_HANDLER_QUARANTINED_V1")
            finally:
                self._stop_complete_event_v1.set()

    async def stop_async(self):
        """Stop a secure session without blocking its cooperative event loop."""

        stop_already_complete = self._stop_complete_event_v1.is_set()
        if not self._claim_stop_owner_v1():
            while not self._stop_complete_event_v1.is_set():
                await asyncio.sleep(0.01)
            if stop_already_complete and not self.is_fully_quiesced_v1():
                await self._reap_quarantined_stop_async_v1()
            return
        deadline = self._begin_shutdown_budget_v1()
        try:
            if self._capture_coordinator_v1 is not None:
                capture_cleanup_succeeded = (
                    await self._capture_coordinator_v1
                    .shutdown_async_v1(
                        self._prepare_retired_work_cleanup_v1,
                        _retire_work_controller_v1=True,
                    )
                )
                if not capture_cleanup_succeeded:
                    logger.error(
                        "CAPTURE_COORDINATOR_CLEANUP_FAILED_V1"
                    )
            elif self._work_controller_v1 is not None:
                cleanup_succeeded = (
                    await self._work_controller_v1.shutdown_async(
                        self._prepare_retired_work_cleanup_v1
                    )
                )
                if not cleanup_succeeded:
                    logger.error("SECURE_SESSION_WORK_CLEANUP_FAILED_V1")
        finally:
            try:
                self.session_context.shared_states.active = False
                finished = await self._finish_stop_async_v1(
                    deadline,
                )
                if not finished:
                    logger.error("SECURE_SESSION_HANDLER_QUARANTINED_V1")
            finally:
                self._stop_complete_event_v1.set()

    def _claim_stop_owner_v1(self) -> bool:
        with self._stop_state_lock_v1:
            if self._stop_started_v1:
                return False
            self._stop_started_v1 = True
            if self._work_controller_v1 is None:
                self.session_context.shared_states.active = False
            return True

    def _begin_shutdown_budget_v1(self) -> float | None:
        controller = self._work_controller_v1
        if controller is None:
            return None
        with self._stop_state_lock_v1:
            if self._shutdown_deadline_monotonic_v1 is None:
                self._shutdown_deadline_monotonic_v1 = (
                    time.monotonic()
                    + controller.cleanup_timeout_seconds_v1()
                )
            return self._shutdown_deadline_monotonic_v1

    @staticmethod
    def _remaining_shutdown_budget_v1(
        deadline_monotonic: float | None,
    ) -> float | None:
        if deadline_monotonic is None:
            return None
        return max(0.0, deadline_monotonic - time.monotonic())

    def is_fully_quiesced_v1(self) -> bool:
        if self._work_controller_v1 is None:
            return self._stop_complete_event_v1.is_set()
        return self._fully_quiesced_event_v1.is_set()

    def shutdown_deadline_monotonic_v1(self) -> float | None:
        return self._shutdown_deadline_monotonic_v1

    def _reap_quarantined_stop_v1(self) -> bool:
        controller = self._work_controller_v1
        if controller is None:
            return True
        deadline = (
            time.monotonic()
            + controller.cleanup_timeout_seconds_v1()
        )
        return self._finish_stop_v1(deadline)

    async def _reap_quarantined_stop_async_v1(self) -> bool:
        controller = self._work_controller_v1
        if controller is None:
            return True
        deadline = (
            time.monotonic()
            + controller.cleanup_timeout_seconds_v1()
        )
        return await self._finish_stop_async_v1(deadline)

    def _release_queued_work_v1(self, queued_item) -> None:
        runtime = self._work_runtime_v1
        if runtime is None:
            return
        work_item = (
            queued_item
            if isinstance(queued_item, WorkBoundItemV1)
            else getattr(queued_item, "work_item_v1", None)
        )
        if isinstance(work_item, WorkBoundItemV1):
            work_item.release_once_v1(runtime)

    def _drain_handler_input_queue_v1(
        self,
        handler_record: HandlerRecord,
    ) -> None:
        while True:
            try:
                queued_item = handler_record.env.input_queue.get_nowait()
            except (queue.Empty, asyncio.QueueEmpty):
                return
            self._release_queued_work_v1(queued_item)

    def _drain_capture_transition_work_v1(
        self,
        new_epoch,
    ) -> None:
        """Drain fenced generic queues without stopping authenticated transport."""

        controller = self._work_controller_v1
        admission = self._normal_application_admission_v1
        if (
            controller is None
            or admission is None
            or admission.is_open_v1()
            or controller.current_epoch_v1() is not new_epoch
        ):
            raise RuntimeError("capture quiescence authority mismatch")

        for handler_record in tuple(self.handlers.values()):
            self._drain_handler_input_queue_v1(handler_record)
            handler = handler_record.env.handler
            context = handler_record.env.context
            quiesce = getattr(
                handler,
                "quiesce_normal_work_v1",
                None,
            )
            if callable(quiesce):
                quiesce(context)
            delegate = getattr(
                context,
                "client_session_delegate",
                None,
            )
            drain_delegate = getattr(
                delegate,
                "drain_application_output_v1",
                None,
            )
            if callable(drain_delegate):
                drain_delegate()
        self.signal_manager.drain_registered_work_v1()

    def _clear_capture_transition_semantic_state_v1(
        self,
        new_epoch,
    ) -> None:
        """Clear stale generic semantic state after the M3 barrier completes."""

        controller = self._work_controller_v1
        admission = self._normal_application_admission_v1
        if (
            controller is None
            or admission is None
            or admission.is_open_v1()
            or controller.current_epoch_v1() is not new_epoch
        ):
            raise RuntimeError("capture semantic authority mismatch")

        for handler_record in tuple(self.handlers.values()):
            handler = handler_record.env.handler
            context = handler_record.env.context
            clear_handler = getattr(
                handler,
                "clear_normal_semantic_state_v1",
                None,
            )
            if callable(clear_handler):
                clear_handler(context, new_epoch.generation)
            delegate = getattr(
                context,
                "client_session_delegate",
                None,
            )
            clear_delegate = getattr(
                delegate,
                "clear_normal_semantic_state_v1",
                None,
            )
            if callable(clear_delegate):
                clear_delegate(new_epoch.generation)
            (
                handler_record.env.core_data_submitter
                .clear_normal_semantic_state_v1()
            )

        self.stream_manager.clear_normal_semantic_state_v1()
        if not (
            self.session_context.session_history
            .clear_pending_stream_accumulators_v1(
                _security_writer_v1=(
                    self._history_producer_authority
                ),
            )
        ):
            raise RuntimeError("pending history cleanup denied")

    def _prepare_retired_work_cleanup_v1(self) -> None:
        """Stop consumers and release queued application work after retirement."""

        self.session_context.shared_states.active = False
        for handler_record in tuple(self.handlers.values()):
            self._drain_handler_input_queue_v1(handler_record)
            handler = handler_record.env.handler
            context = handler_record.env.context
            drain_handler = getattr(
                handler,
                "drain_registered_work_v1",
                None,
            )
            if callable(drain_handler):
                try:
                    drain_handler(context)
                except Exception:  # noqa: BLE001 - payload-free cleanup log
                    logger.error("HANDLER_WORK_QUEUE_DRAIN_FAILED_V1")
            delegate = getattr(
                context,
                "client_session_delegate",
                None,
            )
            drain_delegate = getattr(
                delegate,
                "drain_application_output_v1",
                None,
            )
            if callable(drain_delegate):
                try:
                    drain_delegate()
                except Exception:  # noqa: BLE001 - payload-free cleanup log
                    logger.error("CLIENT_OUTPUT_QUEUE_DRAIN_FAILED_V1")
        self.signal_manager.drain_registered_work_v1()

    def _start_context_cleanup_v1(
        self,
        handler_name: str,
        handler_record: HandlerRecord,
    ) -> threading.Thread:
        existing = self._context_cleanup_threads_v1.get(handler_name)
        if existing is not None:
            return existing

        def destroy_context() -> None:
            try:
                handler_record.env.handler.destroy_context(
                    handler_record.env.context
                )
            except Exception:  # noqa: BLE001 - payload-free cleanup failure
                with self._stop_state_lock_v1:
                    self._context_cleanup_failures_v1.add(handler_name)
                logger.error("HANDLER_CONTEXT_DESTROY_FAILED_V1")

        cleanup_thread = threading.Thread(
            target=destroy_context,
            name="secure_context_cleanup_v1",
            daemon=True,
        )
        self._context_cleanup_threads_v1[handler_name] = cleanup_thread
        cleanup_thread.start()
        return cleanup_thread

    def _finish_stop_v1(
        self,
        deadline_monotonic: float | None = None,
    ) -> bool:
        with self._stop_finalize_lock_v1:
            if self._fully_quiesced_event_v1.is_set():
                return True

            secure = self._work_controller_v1 is not None
            completed_handlers: list[str] = []
            for handler_name, handler_record in tuple(
                self.handlers.items()
            ):
                pump_thread = handler_record.pump_thread
                if pump_thread is not None:
                    pump_thread.join(
                        timeout=(
                            self._remaining_shutdown_budget_v1(
                                deadline_monotonic
                            )
                            if secure
                            else None
                        )
                    )
                    if pump_thread.is_alive():
                        self._shutdown_quarantined_v1 = True
                        continue
                    handler_record.pump_thread = None

                self._drain_handler_input_queue_v1(handler_record)
                if secure:
                    cleanup_thread = self._start_context_cleanup_v1(
                        handler_name,
                        handler_record,
                    )
                    cleanup_thread.join(
                        timeout=self._remaining_shutdown_budget_v1(
                            deadline_monotonic
                        )
                    )
                    if cleanup_thread.is_alive():
                        self._shutdown_quarantined_v1 = True
                        continue
                    if handler_name in self._context_cleanup_failures_v1:
                        self._shutdown_quarantined_v1 = True
                        continue
                else:
                    handler_record.env.handler.destroy_context(
                        handler_record.env.context
                    )
                completed_handlers.append(handler_name)

            for handler_name in completed_handlers:
                self.handlers.pop(handler_name, None)
                self._context_cleanup_threads_v1.pop(
                    handler_name,
                    None,
                )

            if self.handlers:
                return False

            if self._signal_shutdown_started_v1:
                signal_stopped = (
                    self.signal_manager.finalize_shutdown_v1()
                )
            else:
                self._signal_shutdown_started_v1 = True
                signal_stopped = self.signal_manager.shutdown(
                    timeout=(
                        self._remaining_shutdown_budget_v1(
                            deadline_monotonic
                        )
                        if secure
                        else None
                    )
                )
            if not signal_stopped:
                self._shutdown_quarantined_v1 = True
                return False

            self.data_sinks.clear()
            self._playback_begin_event_ids.clear()
            self.session_context.cleanup()
            if self._security_authority is not None:
                self.stream_manager.release_secure_state_v1()
                self._security_authority.close()
            self._shutdown_quarantined_v1 = False
            self._fully_quiesced_event_v1.set()
            logger.info("chat session stopped")
            return True

    async def _finish_stop_async_v1(
        self,
        deadline_monotonic: float | None,
    ) -> bool:
        if self._work_controller_v1 is None:
            return await asyncio.to_thread(
                self._finish_stop_v1,
                None,
            )
        while True:
            if self._finish_stop_v1(time.monotonic()):
                return True
            remaining = self._remaining_shutdown_budget_v1(
                deadline_monotonic
            )
            if remaining is None or remaining <= 0:
                return False
            await asyncio.sleep(min(remaining, 0.01))

    def get_timestamp(self):
        return self.session_context.get_clock().get_timestamp()

    def emit_signal(self, signal: ChatSignal):
        self.signal_manager.get_emitter("chat_session").emit(signal)

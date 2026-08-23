from contextlib import nullcontext
from typing import Any, Callable, Optional, TYPE_CHECKING
from loguru import logger

from chat_engine.data_models.chat_data.chat_data_model import StreamableData
from chat_engine.data_models.chat_signal import ChatSignal

if TYPE_CHECKING:
    from chat_engine.core.signal_manager import SignalEmitter
    from chat_engine.core.stream_manager import ChatDataSubmitter, StreamManager
    from chat_engine.contexts.session_history import SessionHistory
    from chat_engine.security.dispatch import ConsumerCapabilityV1
    from chat_engine.security.work_fence import (
        RegisteredWorkV1,
        WorkOperationKindV1,
        WorkValidationBoundaryV1,
    )
    from chat_engine.security.work_runtime import SessionWorkRuntimeV1


class CommonModuleContext(object):
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.owner: Optional[str] = None
        self.signal_emitter: Optional["SignalEmitter"] = None
        self.data_submitter: Optional["ChatDataSubmitter"] = None
        self.session_history: Optional["SessionHistory"] = None
        self.stream_manager: Optional["StreamManager"] = None
        # Core-owned temporal authority is injected only for secure sessions.
        # It is deliberately separate from DataBundle/stream metadata.
        self.work_runtime_v1: Optional["SessionWorkRuntimeV1"] = None
        self.work_consumer_capability_v1: Optional[
            "ConsumerCapabilityV1"
        ] = None

    def submit_data(self, data: StreamableData, finish_stream: Optional[bool] = None):
        if self.data_submitter is None:
            logger.error("Session is not started, data submitter not ready.")
            return
        self.data_submitter.submit(data, finish_stream=finish_stream)

    def emit_signal(self, signal: ChatSignal):
        if self.signal_emitter is None:
            logger.error("Session is not started, signal emitter not ready.")
            return
        self.signal_emitter.emit(signal)

    def current_work_v1(self):
        runtime = self.work_runtime_v1
        return runtime.current_work_v1() if runtime is not None else None

    def current_work_envelope_v1(self):
        runtime = self.work_runtime_v1
        return (
            runtime.current_envelope_ref_v1()
            if runtime is not None
            else None
        )

    def register_root_work_v1(
        self,
        operation_kind: "WorkOperationKindV1",
    ):
        runtime = self.work_runtime_v1
        if runtime is None:
            return None
        return runtime.register_root_work_v1(operation_kind)

    def register_child_work_v1(
        self,
        operation_kind: "WorkOperationKindV1",
        parent: "RegisteredWorkV1 | None" = None,
    ):
        runtime = self.work_runtime_v1
        if runtime is None:
            return None
        return runtime.register_child_work_v1(parent, operation_kind)

    def activate_work_v1(
        self,
        work: "RegisteredWorkV1 | None",
        envelope_ref=None,
    ):
        runtime = self.work_runtime_v1
        if runtime is None or work is None:
            return nullcontext()
        return runtime.activate_work_v1(work, envelope_ref)

    def perform_work_if_live_v1(
        self,
        work: "RegisteredWorkV1 | None",
        boundary: "WorkValidationBoundaryV1",
        action: Callable[[], Any],
    ) -> bool:
        runtime = self.work_runtime_v1
        if runtime is None:
            action()
            return True
        return runtime.perform_if_live_v1(work, boundary, action)

    def validate_work_v1(
        self,
        work: "RegisteredWorkV1 | None",
        boundary: "WorkValidationBoundaryV1",
    ) -> bool:
        runtime = self.work_runtime_v1
        if runtime is None:
            return True
        return runtime.validate_work_v1(work, boundary)

    def release_work_v1(self, work: "RegisteredWorkV1 | None") -> bool:
        runtime = self.work_runtime_v1
        if runtime is None or work is None:
            return True
        return runtime.release_work_v1(work)

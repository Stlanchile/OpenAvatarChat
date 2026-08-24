from __future__ import annotations

import asyncio
import json
import sys
import time
from types import MethodType, ModuleType, SimpleNamespace

import numpy as np
import pytest

from certificate_capture.coordinator import CaptureTransitionRejectedV1
from certificate_capture.state import (
    CaptureFailureReasonV1,
    CaptureStateV1,
    CaptureTransitionPointV1,
)
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.chat_session import ChatSession
from chat_engine.core.stream_manager import ChatDataSubmitter
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.session_info_data import SessionInfoData
from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import WorkBoundItemV1
from handlers.agent.chat_agent_handler import (
    ChatAgentContext,
    ChatAgentHandler,
)
from handlers.agent.perception.perception_handler import (
    PerceptionContext,
    PerceptionHandler,
)
from handlers.client.ws_client.ws_input_delegate import (
    ConnectionInfo,
    WsInputSessionDelegate,
)
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    HandlerTTS as BailianTTSHandler,
)
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    TTSContext as BailianTTSContext,
)
from handlers.tts.cosyvoice.tts_handler_cosyvoice import (
    HandlerTask,
)
from handlers.tts.cosyvoice.tts_handler_cosyvoice import (
    HandlerTTS as CosyVoiceHandler,
)
from handlers.tts.cosyvoice.tts_handler_cosyvoice import (
    TTSContext as CosyVoiceContext,
)
from service.rtc_service.rtc_stream import RtcStream

if "edge_tts" not in sys.modules:
    edge_tts_stub = ModuleType("edge_tts")
    edge_tts_stub.Communicate = object
    sys.modules["edge_tts"] = edge_tts_stub

from handlers.tts.edgetts.tts_handler_edgetts import (
    HandlerTTS as EdgeTTSHandler,
)
from handlers.tts.edgetts.tts_handler_edgetts import (
    TTSContext as EdgeTTSContext,
)

APPLICATION_LANES = (
    ("camera", WorkOperationKindV1.PERCEPTION_INFERENCE),
    ("microphone", WorkOperationKindV1.GENERIC_ASYNC),
    ("human_text", WorkOperationKindV1.CHAT_AGENT_LLM),
    ("duplex_text", WorkOperationKindV1.CHAT_AGENT_LLM),
    ("duplex_audio", WorkOperationKindV1.GENERIC_ASYNC),
    ("perception", WorkOperationKindV1.PERCEPTION_INFERENCE),
    ("proactive", WorkOperationKindV1.CHAT_AGENT_PROACTIVE),
    ("environment_event", WorkOperationKindV1.CHAT_AGENT_PROACTIVE),
    ("tool", WorkOperationKindV1.TOOL_EXECUTION),
    ("generic_tts", WorkOperationKindV1.TTS_SYNTHESIS),
    ("ws_egress", WorkOperationKindV1.WS_EGRESS),
    ("rtc_egress", WorkOperationKindV1.RTC_EGRESS),
)


def _attempt_application_admission(harness, payload: str, kind) -> bool:
    try:
        work = harness.runtime.register_root_work_v1(kind)
    except WorkAdmissionDeniedV1:
        return False
    try:
        return harness.runtime.perform_if_live_v1(
            work,
            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
            lambda: harness.admitted_payloads.append(payload),
        )
    finally:
        harness.runtime.release_work_v1(work)


@pytest.mark.asyncio
async def test_all_normal_application_lanes_drop_in_every_active_state(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    harness.admitted_payloads = []
    observed_states: set[CaptureStateV1] = set()

    async def hook(point: CaptureTransitionPointV1) -> None:
        state = harness.coordinator.snapshot_v1().state
        if point in {
            CaptureTransitionPointV1.AFTER_ENTERING,
            CaptureTransitionPointV1.AFTER_QUIESCING,
            CaptureTransitionPointV1.AFTER_ENDING,
        }:
            observed_states.add(state)
            for lane, kind in APPLICATION_LANES:
                assert not _attempt_application_admission(
                    harness,
                    f"{state.value}:{lane}",
                    kind,
                )

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    capture_epoch = await harness.coordinator.begin_capture_v1()
    observed_states.add(CaptureStateV1.ARMED)
    for lane, kind in APPLICATION_LANES:
        assert not _attempt_application_admission(
            harness,
            f"ARMED:{lane}",
            kind,
        )
    await harness.coordinator.end_capture_v1(capture_epoch)

    second = await harness.coordinator.begin_capture_v1()
    harness.coordinator._fail_closed_for_test_v1(
        CaptureFailureReasonV1.INTERNAL_FAILURE
    )
    observed_states.add(CaptureStateV1.FAILED_CLOSED)
    for lane, kind in APPLICATION_LANES:
        assert not _attempt_application_admission(
            harness,
            f"FAILED_CLOSED:{lane}",
            kind,
        )
    recovered = await harness.coordinator.end_capture_v1(second)

    assert observed_states == {
        CaptureStateV1.ENTERING,
        CaptureStateV1.QUIESCING,
        CaptureStateV1.ARMED,
        CaptureStateV1.ENDING,
        CaptureStateV1.FAILED_CLOSED,
    }
    assert harness.admitted_payloads == []
    assert recovered.state is CaptureStateV1.IDLE


@pytest.mark.asyncio
async def test_input_received_while_armed_is_not_buffered_or_replayed(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    harness.admitted_payloads = []
    assert _attempt_application_admission(
        harness,
        "normal-before",
        WorkOperationKindV1.GENERIC_ASYNC,
    )
    capture_epoch = await harness.coordinator.begin_capture_v1()

    for payload, kind in APPLICATION_LANES:
        assert not _attempt_application_admission(
            harness,
            f"dropped-{payload}",
            kind,
        )
    assert harness.admitted_payloads == ["normal-before"]

    await harness.coordinator.end_capture_v1(capture_epoch)
    assert harness.admitted_payloads == ["normal-before"]
    assert _attempt_application_admission(
        harness,
        "fresh-after",
        WorkOperationKindV1.GENERIC_ASYNC,
    )
    assert harness.admitted_payloads == [
        "normal-before",
        "fresh-after",
    ]


@pytest.mark.asyncio
async def test_queued_application_egress_is_denied_as_isolation_begins(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    parent = harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
    child = harness.runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.WS_EGRESS,
    )
    item = WorkBoundItemV1(
        payload="old-output",
        registered_work=child,
    )
    published: list[str] = []

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENTERING:
            assert not harness.runtime.perform_item_egress_if_live_v1(
                item,
                None,
                lambda: published.append(item.payload),
            )
            item.release_once_v1(harness.runtime)
            harness.runtime.release_work_v1(parent)

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    capture_epoch = await harness.coordinator.begin_capture_v1()

    assert published == []
    await harness.coordinator.end_capture_v1(capture_epoch)
    assert published == []


@pytest.mark.asyncio
async def test_runtime_child_and_proactive_admission_share_the_core_gate(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    parent = harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENTERING:
            with pytest.raises(WorkAdmissionDeniedV1):
                harness.runtime.register_child_work_v1(
                    parent,
                    WorkOperationKindV1.CHAT_AGENT_PROACTIVE,
                )
            with pytest.raises(WorkAdmissionDeniedV1):
                harness.runtime.register_child_work_v1(
                    parent,
                    WorkOperationKindV1.TOOL_EXECUTION,
                )
            harness.runtime.release_work_v1(parent)

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    capture_epoch = await harness.coordinator.begin_capture_v1()
    await harness.coordinator.end_capture_v1(capture_epoch)


class _ImmediateWebSocket:
    def __init__(self) -> None:
        self.sent: list[object] = []

    async def send_json(self, value) -> None:
        self.sent.append(value)


class _QueuedWebSocket(_ImmediateWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.received: asyncio.Queue[dict] = asyncio.Queue()
        self.receive_count = 0

    async def receive(self):
        value = await self.received.get()
        self.receive_count += 1
        return value


async def _wait_for_receive_count(
    websocket: _QueuedWebSocket,
    expected: int,
) -> None:
    for _ in range(200):
        if websocket.receive_count >= expected:
            await asyncio.sleep(0)
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"WebSocket did not receive message {expected}")


@pytest.mark.asyncio
async def test_ws_closed_mode_accepts_only_heartbeat_control_without_buffering(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = harness.runtime
    delegate.data_submitter = ChatDataSubmitter(work_runtime_v1=harness.runtime)
    websocket = _ImmediateWebSocket()
    connection = ConnectionInfo(
        connection_id=1,
        websocket=websocket,
        role="primary",
    )
    previous_heartbeat = connection.last_heartbeat_time

    text_message = {
        "text": json.dumps(
            {
                "header": {
                    "name": "SendHumanText",
                    "request_id": "sensitive-request",
                },
                "payload": {
                    "stream_key": "old-stream",
                    "mode": "increment",
                    "text": "must-not-buffer",
                    "end_of_speech": False,
                },
            }
        )
    }
    assert not await delegate._process_transport_control_message_v1(
        websocket,
        connection,
        text_message,
    )
    assert delegate.text_buffer == {}
    assert websocket.sent == []

    assert not await delegate._process_transport_control_message_v1(
        websocket,
        connection,
        {"bytes": b"not-a-certificate-frame"},
    )
    assert list(delegate.binary_stream_assembler._queue) == []
    assert websocket.sent == []

    await asyncio.sleep(0)
    heartbeat = {
        "text": json.dumps(
            {
                "header": {
                    "name": "TriggerHeartbeat",
                    "request_id": "heartbeat-request",
                }
            }
        )
    }
    assert not await delegate._process_transport_control_message_v1(
        websocket,
        connection,
        heartbeat,
    )
    assert connection.last_heartbeat_time >= previous_heartbeat
    assert websocket.sent[0]["header"]["name"] == "AvatarHeartbeat"
    assert delegate.text_buffer == {}

    await harness.coordinator.end_capture_v1(capture_epoch)

    failed_epoch = await harness.coordinator.begin_capture_v1()
    harness.coordinator._fail_closed_for_test_v1(
        CaptureFailureReasonV1.INTERNAL_FAILURE
    )
    failed_heartbeat_time = connection.last_heartbeat_time
    sent_count = len(websocket.sent)
    assert not await delegate._process_transport_control_message_v1(
        websocket,
        connection,
        heartbeat,
    )
    assert connection.last_heartbeat_time == failed_heartbeat_time
    assert len(websocket.sent) == sent_count
    assert not harness.gate.transport_keepalive_is_allowed_v1()
    await harness.coordinator.end_capture_v1(failed_epoch)


@pytest.mark.asyncio
async def test_full_ws_receive_loop_drops_armed_and_ending_input(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = harness.runtime
    delegate.data_submitter = ChatDataSubmitter(work_runtime_v1=harness.runtime)
    websocket = _QueuedWebSocket()
    connection = ConnectionInfo(
        connection_id=2,
        websocket=websocket,
        role="primary",
    )
    processed: list[dict] = []

    async def record_message(
        _delegate,
        _websocket,
        observed_connection,
        raw_msg,
    ) -> bool:
        processed.append(raw_msg)
        observed_connection.quit.set()
        return False

    delegate._process_ws_input_message_v1 = MethodType(
        record_message,
        delegate,
    )
    input_task = asyncio.create_task(delegate._ws_input_task(connection))

    armed_message = {"text": "armed-normal-input"}
    await websocket.received.put(armed_message)
    await _wait_for_receive_count(websocket, 1)
    assert processed == []
    assert delegate.text_buffer == {}
    assert list(delegate.binary_stream_assembler._queue) == []

    before_resume = asyncio.Event()
    release_resume = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_RESUME:
            before_resume.set()
            await release_resume.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    ending = asyncio.create_task(harness.coordinator.end_capture_v1(capture_epoch))
    await before_resume.wait()
    ending_message = {"bytes": b"ending-normal-input"}
    await websocket.received.put(ending_message)
    await _wait_for_receive_count(websocket, 2)
    assert processed == []
    assert delegate.text_buffer == {}
    assert list(delegate.binary_stream_assembler._queue) == []

    release_resume.set()
    await ending
    fresh_message = {"text": "fresh-normal-input"}
    await websocket.received.put(fresh_message)
    await _wait_for_receive_count(websocket, 3)
    await input_task

    assert processed == [fresh_message]
    assert armed_message not in processed
    assert ending_message not in processed
    assert delegate.text_buffer == {}
    assert list(delegate.binary_stream_assembler._queue) == []


class _RtcIngressProbe:
    def __init__(self, harness) -> None:
        self.work_runtime_v1 = harness.runtime
        self.data_submitter = ChatDataSubmitter(work_runtime_v1=harness.runtime)
        self.received: list[EngineChannelType] = []
        self.signals = []

    def ingress_work_scope_v1(self):
        return self.data_submitter.ingress_work_scope_v1()

    def get_timestamp(self):
        return (1, 1)

    def put_data(self, modality, *_args, **_kwargs) -> None:
        self.received.append(modality)

    def emit_signal(self, signal) -> None:
        self.signals.append(signal)


class _RtcDataChannelProbe:
    def __init__(self) -> None:
        self.handlers = {}

    def on(self, name):
        def register(handler):
            self.handlers[name] = handler
            return handler

        return register


@pytest.mark.asyncio
async def test_live_rtc_ingress_drops_media_and_text_until_resume(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    stream = RtcStream("secure-session", stream_start_delay=0)
    probe = _RtcIngressProbe(harness)
    stream.client_session_delegate = probe
    channel = _RtcDataChannelProbe()
    stream.set_channel(channel)
    text_message = json.dumps(
        {
            "header": {"name": "SendHumanText"},
            "payload": {
                "text": "normal RTC text",
                "end_of_speech": True,
            },
        }
    )

    capture_epoch = await harness.coordinator.begin_capture_v1()
    await stream.receive((16000, np.ones((1, 160), dtype=np.float32)))
    await stream.video_receive(np.ones((2, 2, 3), dtype=np.uint8))
    channel.handlers["message"](text_message)

    assert probe.received == []
    assert probe.signals == []

    await harness.coordinator.end_capture_v1(capture_epoch)
    await stream.receive((16000, np.ones((1, 160), dtype=np.float32)))
    await stream.video_receive(np.ones((2, 2, 3), dtype=np.uint8))
    channel.handlers["message"](text_message)

    assert probe.received == [
        EngineChannelType.AUDIO,
        EngineChannelType.VIDEO,
        EngineChannelType.TEXT,
    ]
    assert len(probe.signals) == 1


def test_semantic_clear_hooks_remove_only_generation_local_state():
    perception = PerceptionContext("perception")
    perception.frame_buffer.append(np.ones((1, 1, 3)))
    perception.previous_frame = np.ones((1, 1, 3))
    perception.current_perception = object()
    perception.last_event_times["motion"] = time.time()
    perception.last_summary_time = time.time()
    PerceptionHandler().clear_normal_semantic_state_v1(
        perception,
        4,
    )
    assert perception.frame_buffer == []
    assert perception.previous_frame is None
    assert perception.current_perception is None
    assert perception.last_event_times == {}
    assert perception._secure_generation_v1 == 4

    chat = ChatAgentContext("chat")
    memory = object()
    chat.memory = memory
    chat.input_buffer = "old"
    chat.pending_events.append(object())
    chat.responded_events["old"] = time.time()
    chat.cached_perception = object()
    chat.active_stream_keys.add("old-stream")
    ChatAgentHandler().clear_normal_semantic_state_v1(chat, 5)
    assert chat.memory is memory
    assert chat.input_buffer == ""
    assert chat.pending_events == []
    assert chat.responded_events == {}
    assert chat.cached_perception is None
    assert chat.active_stream_keys == set()
    assert chat._secure_generation_v1 == 5

    edge_context = EdgeTTSContext("edge")
    edge_context.input_text = "old edge text"
    EdgeTTSHandler().clear_normal_semantic_state_v1(
        edge_context,
        6,
    )
    assert edge_context.input_text == ""
    assert edge_context._secure_generation_v1 == 6

    cosy = object.__new__(CosyVoiceHandler)
    cosy.cancelled_work_v1 = {}
    cosy_context = CosyVoiceContext("cosy")
    cosy_context.task_queue = __import__("collections").deque(
        [HandlerTask(operation_ref_v1="old-operation")]
    )
    cosy.quiesce_normal_work_v1(cosy_context)
    assert cosy.cancelled_work_v1["old-operation"]
    assert list(cosy_context.task_queue)
    cosy.clear_normal_semantic_state_v1(cosy_context, 7)
    assert list(cosy_context.task_queue) == []
    assert cosy_context._secure_generation_v1 == 7

    bailian = object.__new__(BailianTTSHandler)
    bailian_context = BailianTTSContext("bailian")
    bailian_context.api_links["old"] = SimpleNamespace(reset=lambda: None)
    bailian.quiesce_normal_work_v1(bailian_context)
    bailian.clear_normal_semantic_state_v1(
        bailian_context,
        8,
    )
    assert bailian_context.api_links == {}
    assert bailian_context._secure_generation_v1 == 8


@pytest.mark.asyncio
async def test_chat_session_owns_one_coordinator_only_when_feature_enabled():
    legacy_context = SessionContext(
        SessionInfoData(session_id="legacy", timestamp_base=0)
    )
    legacy = ChatSession(legacy_context, ChatEngineConfigModel())
    assert legacy._capture_coordinator_v1 is None
    assert legacy._normal_application_admission_v1 is None
    legacy.stop()

    secure_without_capture = SessionContext(
        SessionInfoData(session_id="secure-m2", timestamp_base=0),
        session_admission=object(),
    )
    m2_only = ChatSession(
        secure_without_capture,
        ChatEngineConfigModel(),
    )
    assert m2_only._capture_coordinator_v1 is None
    await m2_only.stop_async()

    enabled_context = SessionContext(
        SessionInfoData(session_id="capture", timestamp_base=0),
        session_admission=object(),
        certificate_capture_enabled_v1=True,
    )
    enabled = ChatSession(enabled_context, ChatEngineConfigModel())
    coordinator = enabled._capture_coordinator_v1
    assert coordinator is not None
    assert enabled._capture_coordinator_v1 is coordinator
    assert (
        coordinator.normal_application_admission_view_v1()
        is enabled._normal_application_admission_v1
    )
    enabled.start()
    capture_epoch = await enabled._begin_certificate_capture_v1()
    await enabled._end_certificate_capture_v1(capture_epoch)
    await enabled.stop_async()
    assert enabled.is_fully_quiesced_v1()


@pytest.mark.asyncio
async def test_capture_clears_pending_history_only_and_keeps_prior_events():
    context = SessionContext(
        SessionInfoData(session_id="history", timestamp_base=0),
        session_admission=object(),
        certificate_capture_enabled_v1=True,
    )
    session = ChatSession(context, ChatEngineConfigModel())
    session.start()
    history = context.session_history
    writer = session._history_producer_authority
    assert history.accumulate_stream_data(
        "unfinished",
        "old partial text",
        _security_writer_v1=writer,
    )
    event_id = history.create_and_add_event(
        data="valid prior chat",
        owner="client",
        _security_writer_v1=writer,
    )

    capture_epoch = await session._begin_certificate_capture_v1()
    assert history.get_accumulated_data("unfinished") is None
    assert event_id in history._event_index
    assert history._event_index[event_id].data == "valid prior chat"

    await session._end_certificate_capture_v1(capture_epoch)
    await session.stop_async()


@pytest.mark.asyncio
async def test_stale_capture_input_cannot_be_reused_as_new_generation_work(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    with pytest.raises(WorkAdmissionDeniedV1):
        stale = harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
        del stale
    await harness.coordinator.end_capture_v1(capture_epoch)

    fresh = harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
    assert fresh.fence.session_epoch.generation == 3
    assert harness.runtime.release_work_v1(fresh)


@pytest.mark.asyncio
async def test_stale_end_callback_cannot_mutate_later_cycle(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    first = await harness.coordinator.begin_capture_v1()
    await harness.coordinator.end_capture_v1(first)
    second = await harness.coordinator.begin_capture_v1()

    with pytest.raises(CaptureTransitionRejectedV1) as stale:
        await harness.coordinator.end_capture_v1(first)
    assert stale.value.reason_code == "CAPTURE_EPOCH_MISMATCH"
    assert harness.coordinator.snapshot_v1().capture_id == second.capture_id
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ARMED

    await harness.coordinator.end_capture_v1(second)

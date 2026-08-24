from __future__ import annotations

import asyncio
import fractions
import time
from types import SimpleNamespace

import numpy as np
import pytest
from aiortc.rtcsctptransport import DataChunk
from fastrtc.utils import AdditionalOutputs, CloseStream
from starlette.websockets import WebSocketState

from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)
from handlers.client.rtc_client.client_handler_rtc import ClientHandlerRtc
from handlers.client.ws_client.ws_input_delegate import (
    ConnectionInfo,
    WsInputSessionDelegate,
)
from handlers.client.ws_client.ws_message_protocol import (
    EchoHumanText,
    EchoTextPayload,
    MessageHeader,
    MessageType,
)
from service.rtc_service import fenced_tracks as fenced_tracks_module
from service.rtc_service.fenced_tracks import (
    FencedAudioCallbackV1,
    FencedRtcAudioPayloadV1,
    FencedRtcVideoPayloadV1,
    FencedVideoStreamHandlerV1,
    _data_channel_send_v1,
    _FencedAudioFrameV1,
    _FencedRtcControlV1,
    _FencedRtpPayloadsV1,
    _retransmit_v1,
    _RtpPublicationV1,
    _SctpPublicationV1,
    _send_rtp_v1,
    _send_rtp_with_publication_v1,
    _send_sctp_chunk_v1,
    _send_sctp_message_v1,
    fenced_player_worker_decode_v1,
    send_fenced_data_channel_v1,
)
from tests.service import (
    test_certificate_rtc_admission as rtc_admission_tests,
)


class _BlockingWebSocket:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.sent: list[object] = []
        self.closed = False
        self.client_state = WebSocketState.CONNECTED

    async def send_json(self, value) -> None:
        self.started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        self.sent.append(value)

    async def send_bytes(self, value) -> None:
        await self.send_json(value)

    async def close(self, code=1000, reason="") -> None:
        del code, reason
        self.closed = True
        self.client_state = WebSocketState.DISCONNECTED


class _ImmediateWebSocket(_BlockingWebSocket):
    async def send_json(self, value) -> None:
        self.sent.append(value)

    async def send_bytes(self, value) -> None:
        self.sent.append(value)


class _CancellationResistantWebSocket(_BlockingWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.closed_event = asyncio.Event()

    async def send_json(self, value) -> None:
        self.started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.closed_event.wait()
        if not self.closed:
            self.sent.append(value)

    async def close(self, code=1000, reason="") -> None:
        await super().close(code=code, reason=reason)
        self.closed_event.set()


class _Channel:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(self, value: str) -> None:
        self.sent.append(value)


class _RejectedLoop:
    @staticmethod
    def is_running() -> bool:
        return True

    @staticmethod
    def call_soon_threadsafe(*_args) -> None:
        raise RuntimeError("loop closed")


def _runtime_item(kind: WorkOperationKindV1):
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
    child = runtime.register_child_work_v1(parent, kind)
    return (
        controller,
        runtime,
        parent,
        WorkBoundItemV1(payload="public", registered_work=child),
    )


@pytest.mark.asyncio
async def test_ws_actual_send_racing_retirement_is_cancelled():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.WS_EGRESS)
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = runtime
    websocket = _BlockingWebSocket()
    info = ConnectionInfo(
        connection_id=1,
        websocket=websocket,
        role="primary",
    )
    delegate.connection_infos[1] = info
    delegate.primary_connection_id = 1

    send_task = asyncio.create_task(
        delegate._broadcast_json(
            {"type": "public"},
            item,
        )
    )
    await websocket.started.wait()
    retirement = await controller.retire_generation_async_v1()
    await send_task

    assert websocket.cancelled.is_set()
    assert websocket.sent == []
    assert item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert await controller.wait_for_cleanup_async_v1(retirement.cleanup_fence)
    await delegate.retire_transport_async_v1()
    assert websocket.closed
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
async def test_ws_cancellation_resistant_send_closes_transport_without_leak():
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.WS_EGRESS
    )
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = runtime
    websocket = _CancellationResistantWebSocket()
    info = ConnectionInfo(
        connection_id=1,
        websocket=websocket,
        role="primary",
    )
    delegate.connection_infos[1] = info
    delegate.primary_connection_id = 1

    send_task = asyncio.create_task(
        delegate._broadcast_json(
            {"type": "public"},
            item,
        )
    )
    await websocket.started.wait()
    retirement = await controller.retire_generation_async_v1()
    await send_task

    assert websocket.cancelled.is_set()
    assert websocket.closed
    assert websocket.sent == []
    assert item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
async def test_ws_listener_stubborn_task_is_retained_until_reaped():
    controller = SessionWorkControllerV1()
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = SessionWorkRuntimeV1(controller)
    websocket = _ImmediateWebSocket()
    info = ConnectionInfo(
        connection_id=1,
        websocket=websocket,
        role="listener",
    )
    delegate.connection_infos[1] = info
    started = asyncio.Event()
    release = asyncio.Event()
    stubborn_tasks: list[asyncio.Task] = []

    async def stubborn_input(_info) -> None:
        task = asyncio.current_task()
        assert task is not None
        stubborn_tasks.append(task)
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await release.wait()

    async def completed_heartbeat(_info) -> None:
        await started.wait()

    delegate._ws_input_task = stubborn_input
    delegate._heartbeat_monitor_task = completed_heartbeat

    await delegate._serve_listener_connection(info)

    assert len(stubborn_tasks) == 1
    stubborn_task = stubborn_tasks[0]
    assert not stubborn_task.done()
    assert (
        stubborn_task
        in delegate._quarantined_connection_tasks_v1
    )
    release.set()
    await asyncio.wait_for(stubborn_task, timeout=1)
    await asyncio.sleep(0)

    assert delegate._quarantined_connection_tasks_v1 == set()
    assert controller.shutdown()


def test_ws_stale_queued_application_payload_is_dropped_at_dequeue():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.WS_EGRESS)
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = runtime
    retirement = controller.retire_generation_v1()

    payload, stale_item = delegate._unwrap_output_item_v1(item)

    assert payload is None
    assert stale_item is item
    assert item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_ws_disabled_mode_preserves_legacy_send():
    delegate = WsInputSessionDelegate()
    websocket = _ImmediateWebSocket()
    delegate.connection_infos[1] = ConnectionInfo(
        connection_id=1,
        websocket=websocket,
        role="primary",
    )

    await delegate._broadcast_json({"legacy": True})

    assert websocket.sent == [{"legacy": True}]


@pytest.mark.asyncio
async def test_ws_normal_retirement_preserves_same_transport_for_new_epoch():
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.WS_EGRESS
    )
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = runtime
    websocket = _ImmediateWebSocket()
    delegate.connection_infos[1] = ConnectionInfo(
        connection_id=1,
        websocket=websocket,
        role="primary",
    )
    retirement = controller.retire_generation_v1()

    await delegate._broadcast_json({"stale": True}, item)

    assert websocket.sent == []
    assert not websocket.closed
    assert item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)

    current_parent = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    current_item = WorkBoundItemV1(
        payload="public",
        registered_work=runtime.register_child_work_v1(
            current_parent,
            WorkOperationKindV1.WS_EGRESS,
        ),
    )
    await delegate._broadcast_json({"current": True}, current_item)

    assert websocket.sent == [{"current": True}]
    assert current_item.release_once_v1(runtime)
    assert runtime.release_work_v1(current_parent)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_rtc_data_channel_task_scheduled_before_retire_drops_after():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    channel = _Channel()
    stream = SimpleNamespace(
        chat_channel=channel,
        chat_channel_loop=asyncio.get_running_loop(),
    )
    handler = ClientHandlerRtc()
    handler.rtc_streamer_factory = SimpleNamespace(streams={"session": stream})
    message = EchoHumanText(
        header=MessageHeader(
            name=MessageType.ECHO_HUMAN_TEXT,
            request_id="request",
        ),
        payload=EchoTextPayload(
            stream_key="stream",
            mode="full_text",
            text="public",
            end_of_speech=True,
            metadata=None,
        ),
    )

    assert handler._send_message_to_chat_channel(
        "session",
        message,
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )
    retirement = controller.retire_generation_v1()
    await asyncio.sleep(0)

    assert channel.sent == []
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_rtc_data_channel_schedule_failure_releases_work_once():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    stream = SimpleNamespace(
        chat_channel=_Channel(),
        chat_channel_loop=_RejectedLoop(),
    )
    handler = ClientHandlerRtc()
    handler.rtc_streamer_factory = SimpleNamespace(streams={"session": stream})
    message = EchoHumanText(
        header=MessageHeader(
            name=MessageType.ECHO_HUMAN_TEXT,
            request_id="request",
        ),
        payload=EchoTextPayload(
            stream_key="stream",
            mode="full_text",
            text="public",
            end_of_speech=True,
            metadata=None,
        ),
    )

    assert not handler._send_message_to_chat_channel(
        "session",
        message,
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )
    assert not item.release_once_v1(runtime)
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 1),)
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_rtc_disabled_mode_preserves_legacy_data_channel_send():
    channel = _Channel()
    stream = SimpleNamespace(
        chat_channel=channel,
        chat_channel_loop=asyncio.get_running_loop(),
    )
    handler = ClientHandlerRtc()
    handler.rtc_streamer_factory = SimpleNamespace(streams={"session": stream})
    message = EchoHumanText(
        header=MessageHeader(
            name=MessageType.ECHO_HUMAN_TEXT,
            request_id="request",
        ),
        payload=EchoTextPayload(
            stream_key="stream",
            mode="full_text",
            text="legacy",
            end_of_speech=True,
            metadata=None,
        ),
    )

    assert handler._send_message_to_chat_channel(
        "session",
        message,
    )
    await asyncio.sleep(0)

    assert len(channel.sent) == 1


def test_secure_ws_loopback_never_places_raw_payload_in_output_queue():
    class _Submitter:
        def __init__(self) -> None:
            self.calls = 0

        def submit_ingress_v1(self, *_args, **_kwargs) -> None:
            self.calls += 1

    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    delegate = WsInputSessionDelegate()
    delegate.work_runtime_v1 = runtime
    delegate.data_submitter = _Submitter()
    from chat_engine.data_models.runtime_data.data_bundle import (
        DataBundleDefinition,
        DataBundleEntry,
    )

    definition = DataBundleDefinition()
    definition.add_entry(DataBundleEntry.create_text_entry("human_text"))
    definition.lockdown()
    delegate.input_data_definitions[EngineChannelType.TEXT] = definition

    delegate.put_data(
        EngineChannelType.TEXT,
        "public",
        timestamp=(0, 1),
        loopback=True,
    )

    assert delegate.data_submitter.calls == 1
    assert delegate.output_queues[EngineChannelType.TEXT].empty()
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_fastrtc_video_track_revalidates_after_frame_timing():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    timing_started = asyncio.Event()
    release_timing = asyncio.Event()
    wrapper = FencedRtcVideoPayloadV1(
        frame_array=np.zeros((2, 2, 3), dtype=np.uint8),
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )

    class _Handler:
        def __init__(self) -> None:
            self.calls = 0

        async def video_emit(self):
            self.calls += 1
            return wrapper if self.calls == 1 else None

    class _Track:
        def __init__(self) -> None:
            self.event_handler = _Handler()
            self.set_additional_outputs = None
            self.channel = _Channel()
            self.mode = "send-receive"

        @staticmethod
        async def start() -> None:
            return

        @staticmethod
        def array_to_frame(_array):
            return SimpleNamespace(pts=None, time_base=None)

        @staticmethod
        async def next_timestamp():
            timing_started.set()
            await release_timing.wait()
            return 1, fractions.Fraction(1, 30)

    track = _Track()
    send_task = asyncio.create_task(FencedVideoStreamHandlerV1.recv(track))
    await timing_started.wait()
    retirement = controller.retire_generation_v1()
    release_timing.set()

    assert await send_task is None
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_fastrtc_audio_track_drops_frame_retired_during_playback_wait():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    timing_started = asyncio.Event()

    class _TimedFrame:
        def __init__(self, frame_time: float, signal=None) -> None:
            self._frame_time = frame_time
            self._signal = signal

        @property
        def time(self) -> float:
            if self._signal is not None:
                self._signal.set()
            return self._frame_time

    stale_frame = _TimedFrame(0.2, timing_started)
    fenced_frame = _FencedAudioFrameV1(
        frame=stale_frame,
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )

    class _Track:
        def __init__(self) -> None:
            self.readyState = "live"
            channel = _Channel()
            self.event_handler = SimpleNamespace(
                channel_set=asyncio.Event(),
                channel=channel,
                output_frame_size=480,
                output_sample_rate=24000,
            )
            self.event_handler.channel_set.set()
            self.channel = channel
            self.queue = asyncio.Queue()
            self.queue.put_nowait(fenced_frame)
            self.queue.put_nowait(CloseStream())
            self._start = time.time()
            self.last_timestamp = time.time()
            self.stopped = False

        @staticmethod
        async def start() -> None:
            return

        def stop(self) -> None:
            self.stopped = True

    track = _Track()
    send_task = asyncio.create_task(FencedAudioCallbackV1.recv(track))
    await timing_started.wait()
    retirement = controller.retire_generation_v1()

    assert await send_task is None
    assert track.stopped
    assert track.channel.sent == []
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_secure_audio_track_drops_raw_terminal_before_first_frame():
    class _Track:
        def __init__(self) -> None:
            self._secure_rtc_track_v1 = True
            self.readyState = "live"
            self.channel = _Channel()
            self.event_handler = SimpleNamespace(
                channel_set=asyncio.Event(),
                channel=self.channel,
            )
            self.event_handler.channel_set.set()
            self.queue = asyncio.Queue()
            self.queue.put_nowait(
                CloseStream("UNFENCED_TERMINAL_CANARY")
            )
            self.stopped = False

        @staticmethod
        async def start() -> None:
            return

        def stop(self) -> None:
            self.stopped = True

    track = _Track()

    assert await FencedAudioCallbackV1.recv(track) is None
    assert track.stopped
    assert track.channel.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("control_kind", ["end_stream", "fetch_output"])
async def test_secure_audio_worker_drops_raw_control_before_first_frame(
    control_kind: str,
):
    class _SecureEmitter:
        _secure_admission_required_v1 = True

        async def emit(self):
            if control_kind == "end_stream":
                return CloseStream("UNFENCED_TERMINAL_CANARY")
            return AdditionalOutputs("UNFENCED_OUTPUT_CANARY")

    channel = _Channel()
    additional_outputs = []
    output_queue = asyncio.Queue()
    await fenced_player_worker_decode_v1(
        _SecureEmitter().emit,
        output_queue,
        asyncio.Event(),
        lambda: channel,
        additional_outputs.append,
        quit_on_none=True,
        sample_rate=24000,
        frame_size=480,
    )

    assert channel.sent == []
    assert additional_outputs == []


@pytest.mark.asyncio
@pytest.mark.parametrize("control_kind", ["end_stream", "fetch_output"])
async def test_secure_video_track_drops_raw_control_before_first_frame(
    control_kind: str,
):
    class _Handler:
        async def video_emit(self):
            if control_kind == "end_stream":
                return CloseStream("UNFENCED_TERMINAL_CANARY")
            return AdditionalOutputs("UNFENCED_OUTPUT_CANARY")

    class _Track:
        def __init__(self) -> None:
            self._secure_rtc_track_v1 = True
            self.event_handler = _Handler()
            self.additional_outputs = []
            self.set_additional_outputs = (
                self.additional_outputs.append
            )
            self.channel = _Channel()
            self.stopped = False

        @staticmethod
        async def start() -> None:
            return

        def stop(self) -> None:
            self.stopped = True

    track = _Track()

    assert await FencedVideoStreamHandlerV1.recv(track) is None
    assert track.channel.sent == []
    assert track.additional_outputs == []
    assert track.stopped is (control_kind == "end_stream")


@pytest.mark.asyncio
async def test_fastrtc_audio_decoder_registers_frame_before_queue():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    payload = FencedRtcAudioPayloadV1(
        sample_rate=24000,
        audio_array=np.ones((1, 960), dtype=np.float32),
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )
    calls = 0

    async def next_frame():
        nonlocal calls
        calls += 1
        return payload if calls == 1 else None

    output_queue = asyncio.Queue()
    await fenced_player_worker_decode_v1(
        next_frame,
        output_queue,
        asyncio.Event(),
        None,
        None,
        quit_on_none=True,
        sample_rate=24000,
        frame_size=480,
    )
    queued = []
    while not output_queue.empty():
        queued.append(output_queue.get_nowait())
    frames = [entry for entry in queued if isinstance(entry, _FencedAudioFrameV1)]

    assert frames
    assert not item.release_once_v1(runtime)
    for frame in frames:
        assert frame.work_item_v1.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("retired_before_recv", [False, True])
async def test_fastrtc_audio_end_stream_uses_reserved_control_authority(
    retired_before_recv: bool,
):
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.RTC_EGRESS
    )
    payload = FencedRtcAudioPayloadV1(
        sample_rate=24000,
        audio_array=np.ones((1, 960), dtype=np.float32),
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )
    calls = 0

    async def next_frame():
        nonlocal calls
        calls += 1
        if calls == 1:
            return payload
        return CloseStream("synthetic public close")

    output_queue = asyncio.Queue()
    await fenced_player_worker_decode_v1(
        next_frame,
        output_queue,
        asyncio.Event(),
        None,
        None,
        quit_on_none=True,
        sample_rate=24000,
        frame_size=480,
    )
    queued = []
    while not output_queue.empty():
        queued.append(output_queue.get_nowait())
    frames = [
        entry
        for entry in queued
        if isinstance(entry, _FencedAudioFrameV1)
    ]
    controls = [
        entry
        for entry in queued
        if isinstance(entry, _FencedRtcControlV1)
    ]
    assert frames
    assert len(controls) == 1

    retirement = None
    if retired_before_recv:
        retirement = controller.retire_generation_v1()
        await asyncio.sleep(0)

    class _Track:
        def __init__(self) -> None:
            self.readyState = "live"
            self.channel = _Channel()
            self.event_handler = SimpleNamespace(
                channel_set=asyncio.Event(),
                channel=self.channel,
            )
            self.event_handler.channel_set.set()
            self.queue = asyncio.Queue()
            self.queue.put_nowait(controls[0])
            self.stopped = False

        @staticmethod
        async def start() -> None:
            return

        def stop(self) -> None:
            self.stopped = True

    track = _Track()
    assert await FencedAudioCallbackV1.recv(track) is None
    assert track.stopped
    assert len(track.channel.sent) == (
        0 if retired_before_recv else 1
    )

    for frame in frames:
        frame.work_item_v1.release_once_v1(runtime)
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    if retirement is not None:
        assert controller.wait_for_cleanup_v1(
            retirement.cleanup_fence
        )
    assert controller.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("control_kind", ["end_stream", "fetch_output"])
@pytest.mark.parametrize("retired_before_control", [False, True])
async def test_fastrtc_video_controls_use_reserved_authority(
    control_kind: str,
    retired_before_control: bool,
):
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.RTC_EGRESS
    )
    wrapper = FencedRtcVideoPayloadV1(
        frame_array=np.zeros((2, 2, 3), dtype=np.uint8),
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )

    class _Handler:
        def __init__(self) -> None:
            self.calls = 0

        async def video_emit(self):
            self.calls += 1
            if self.calls == 1:
                return wrapper
            if control_kind == "end_stream":
                return CloseStream("synthetic public close")
            return AdditionalOutputs("synthetic public output")

    class _Track:
        def __init__(self) -> None:
            self.event_handler = _Handler()
            self.additional_outputs = []
            self.set_additional_outputs = (
                self.additional_outputs.append
            )
            self.channel = _Channel()
            self.stopped = False
            self.rtp_publication = None

        @staticmethod
        async def start() -> None:
            return

        @staticmethod
        def array_to_frame(_array):
            return SimpleNamespace(pts=None, time_base=None)

        @staticmethod
        async def next_timestamp():
            return 1, fractions.Fraction(1, 30)

        def _install_pending_rtp_publication_v1(
            self,
            publication,
        ) -> bool:
            self.rtp_publication = publication
            return True

        def stop(self) -> None:
            self.stopped = True

    track = _Track()
    assert await FencedVideoStreamHandlerV1.recv(track) is not None
    assert track.rtp_publication is not None
    assert track.rtp_publication.release_once_v1()

    retirement = None
    if retired_before_control:
        retirement = controller.retire_generation_v1()
        await asyncio.sleep(0)

    assert await FencedVideoStreamHandlerV1.recv(track) is None
    expected_count = 0 if retired_before_control else 1
    assert len(track.channel.sent) == expected_count
    assert len(track.additional_outputs) == (
        expected_count if control_kind == "fetch_output" else 0
    )
    assert track.stopped is (control_kind == "end_stream")
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    if retirement is not None:
        assert controller.wait_for_cleanup_v1(
            retirement.cleanup_fence
        )
    assert controller.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("media_kind", ["audio", "video"])
async def test_aiortc_sender_revalidates_after_track_handoff_retirement(
    media_kind: str,
):
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    completed: list[object] = []
    owner = SimpleNamespace(
        _forget_rtp_publication_v1=lambda publication: completed.append(publication)
    )
    publication = _RtpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
        owner_track_v1=owner,
    )
    payloads = _FencedRtpPayloadsV1(
        [media_kind.encode()],
        publication,
    )
    retirement = controller.retire_generation_v1()
    sent: list[bytes] = []

    async def send_payload(payload: bytes) -> None:
        sent.append(payload)

    results = []
    for payload in payloads:
        results.append(
            await _send_rtp_with_publication_v1(
                lambda payload=payload: send_payload(payload)
            )
        )

    assert results == [False]
    assert sent == []
    assert completed == [publication]
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_aiortc_transport_send_racing_retirement_is_cancelled():
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    owner = SimpleNamespace(_forget_rtp_publication_v1=lambda _publication: None)
    publication = _RtpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
        owner_track_v1=owner,
    )
    payloads = _FencedRtpPayloadsV1(
        [b"public-media"],
        publication,
    )
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def blocked_send() -> None:
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def send_payloads() -> list[bool]:
        return [
            await _send_rtp_with_publication_v1(blocked_send) for _payload in payloads
        ]

    send_task = asyncio.create_task(send_payloads())
    await started.wait()
    retirement = await controller.retire_generation_async_v1()

    assert await send_task == [False]
    assert cancelled.is_set()
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert await controller.wait_for_cleanup_async_v1(retirement.cleanup_fence)
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
async def test_aiortc_cancellation_resistant_send_stops_sender_without_commit():
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.RTC_EGRESS
    )
    teardown_complete = asyncio.Event()
    teardown_pending_generations: list[int | None] = []

    class _TrustedAdmission:
        async def abort_stream(self, _stream) -> None:
            teardown_pending_generations.append(
                controller._retirement_pending_generation
            )
            teardown_complete.set()

    secure_stream = SimpleNamespace(
        client_session_delegate=SimpleNamespace(
            work_runtime_v1=runtime
        ),
        trusted_rtc_admission=_TrustedAdmission(),
    )
    owner = SimpleNamespace(
        _forget_rtp_publication_v1=lambda _publication: None,
        event_handler=secure_stream,
    )
    committed: list[bool] = []
    publication = _RtpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
        owner_track_v1=owner,
        commit_v1=lambda: committed.append(True),
    )

    class _Sender:
        def __init__(self) -> None:
            self.stopped = asyncio.Event()

        async def stop(self) -> None:
            self.stopped.set()

    sender = _Sender()
    publication.bind_sender_v1(sender)
    payloads = _FencedRtpPayloadsV1(
        [b"public-media"],
        publication,
    )
    started = asyncio.Event()
    sent: list[bytes] = []

    async def stubborn_send() -> None:
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await sender.stopped.wait()
        if not sender.stopped.is_set():
            sent.append(b"public-media")

    async def send_payloads() -> list[bool]:
        return [
            await _send_rtp_with_publication_v1(stubborn_send)
            for _payload in payloads
        ]

    send_task = asyncio.create_task(send_payloads())
    await started.wait()
    retirement = await controller.retire_generation_async_v1()

    assert await send_task == [False]
    await asyncio.wait_for(teardown_complete.wait(), timeout=1)
    assert sender.stopped.is_set()
    assert sent == []
    assert committed == []
    assert teardown_pending_generations == [None]
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
@pytest.mark.parametrize("media_kind", ["audio", "video"])
async def test_aiortc_nack_retransmission_reuses_retired_publication(
    monkeypatch,
    media_kind: str,
):
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    owner = SimpleNamespace(_forget_rtp_publication_v1=lambda _publication: None)
    sender = SimpleNamespace()
    publication = _RtpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
        owner_track_v1=owner,
    )
    publication.bind_sender_v1(sender)
    sequence_number = 41
    sent: list[bytes] = []
    packet = (
        b"\x80"
        + (b"\x60" if media_kind == "audio" else b"\x61")
        + sequence_number.to_bytes(2, "big")
        + b"public-media"
    )

    async def original_send_rtp(_transport, payload):
        sent.append(payload)

    monkeypatch.setattr(
        fenced_tracks_module,
        "_ORIGINAL_SEND_RTP_V1",
        original_send_rtp,
    )
    payloads = _FencedRtpPayloadsV1([packet], publication)
    for payload in payloads:
        await _send_rtp_v1(SimpleNamespace(), payload)
    assert sent == [packet]
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 2),)

    async def original_retransmit(_sender, _sequence_number):
        await _send_rtp_with_publication_v1(
            lambda: _append_async(sent, media_kind.encode())
        )

    monkeypatch.setattr(
        fenced_tracks_module,
        "_ORIGINAL_RETRANSMIT_V1",
        original_retransmit,
    )
    retirement = controller.retire_generation_v1()

    await _retransmit_v1(sender, sequence_number)
    await asyncio.sleep(0)

    assert sent == [packet]
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


async def _append_async(target: list[bytes], value: bytes) -> None:
    target.append(value)


@pytest.mark.asyncio
async def test_rtc_data_channel_retains_authority_until_sctp_finishes(
    monkeypatch,
):
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    transport = SimpleNamespace(_data_channel_queue=[])

    def original_data_channel_send(
        target_transport,
        channel,
        data,
    ) -> None:
        user_data = data.encode() if isinstance(data, str) else data
        target_transport._data_channel_queue.append((channel, 51, user_data))

    monkeypatch.setattr(
        fenced_tracks_module,
        "_ORIGINAL_DATA_CHANNEL_SEND_V1",
        original_data_channel_send,
    )

    class _FencedChannel:
        def send(self, value) -> None:
            _data_channel_send_v1(transport, self, value)

    assert send_fenced_data_channel_v1(
        _FencedChannel(),
        "public",
        item,
        runtime,
        None,
    )
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 2),)

    retirement = controller.retire_generation_v1()
    await asyncio.sleep(0)

    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_sctp_retransmission_reuses_retired_publication(
    monkeypatch,
):
    controller, runtime, parent, item = _runtime_item(WorkOperationKindV1.RTC_EGRESS)
    publication = _SctpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )
    chunk = DataChunk()
    chunk._abandoned = False
    chunk._retransmit = True
    publication.attach_chunk_v1(chunk)
    sent: list[DataChunk] = []

    async def original_send_chunk(_transport, sent_chunk):
        sent.append(sent_chunk)

    monkeypatch.setattr(
        fenced_tracks_module,
        "_ORIGINAL_SEND_SCTP_CHUNK_V1",
        original_send_chunk,
    )
    retirement = controller.retire_generation_v1()

    await _send_sctp_chunk_v1(SimpleNamespace(), chunk)

    assert sent == []
    assert chunk._abandoned
    assert not chunk._retransmit
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_sctp_cancellation_resistant_send_stops_transport_without_leak(
    monkeypatch,
):
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.RTC_EGRESS
    )
    teardown_complete = asyncio.Event()
    teardown_pending_generations: list[int | None] = []

    class _TrustedAdmission:
        async def abort_stream(self, _stream) -> None:
            teardown_pending_generations.append(
                controller._retirement_pending_generation
            )
            teardown_complete.set()

    secure_stream = SimpleNamespace(
        client_session_delegate=SimpleNamespace(
            work_runtime_v1=runtime
        ),
        trusted_rtc_admission=_TrustedAdmission(),
    )
    publication = _SctpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
        secure_stream_v1=secure_stream,
    )
    stopped = asyncio.Event()
    transport = SimpleNamespace()

    async def stop_transport() -> None:
        stopped.set()

    transport.stop = stop_transport
    publication.adopt_v1(transport, b"public-data")
    chunk = DataChunk()
    chunk._abandoned = False
    chunk._retransmit = True
    publication.attach_chunk_v1(chunk)
    started = asyncio.Event()
    sent: list[DataChunk] = []

    async def stubborn_send_chunk(_transport, sent_chunk):
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await stopped.wait()
        if not stopped.is_set():
            sent.append(sent_chunk)

    monkeypatch.setattr(
        fenced_tracks_module,
        "_ORIGINAL_SEND_SCTP_CHUNK_V1",
        stubborn_send_chunk,
    )
    send_task = asyncio.create_task(
        _send_sctp_chunk_v1(transport, chunk)
    )
    await started.wait()
    retirement = await controller.retire_generation_async_v1()
    await send_task
    await asyncio.wait_for(teardown_complete.wait(), timeout=1)

    assert stopped.is_set()
    assert sent == []
    assert chunk._abandoned
    assert not chunk._retransmit
    assert teardown_pending_generations == [None]
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
@pytest.mark.parametrize("transport_kind", ["rtp", "sctp"])
async def test_rtc_physical_stop_failure_still_schedules_teardown_once(
    transport_kind: str,
):
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.RTC_EGRESS
    )
    teardown_complete = asyncio.Event()
    teardown_calls = 0

    class _TrustedAdmission:
        async def abort_stream(self, _stream) -> None:
            nonlocal teardown_calls
            teardown_calls += 1
            teardown_complete.set()

    secure_stream = SimpleNamespace(
        client_session_delegate=SimpleNamespace(
            work_runtime_v1=runtime
        ),
        trusted_rtc_admission=_TrustedAdmission(),
    )

    def fail_stop() -> None:
        raise RuntimeError("synthetic stop failure")

    if transport_kind == "rtp":
        publication = _RtpPublicationV1(
            work_item_v1=item,
            work_runtime_v1=runtime,
            consumer_capability_v1=None,
            owner_track_v1=SimpleNamespace(
                event_handler=secure_stream,
                _forget_rtp_publication_v1=(
                    lambda _publication: None
                ),
            ),
        )
        endpoint = SimpleNamespace(stop=fail_stop)
        publication.bind_sender_v1(endpoint)
    else:
        publication = _SctpPublicationV1(
            work_item_v1=item,
            work_runtime_v1=runtime,
            consumer_capability_v1=None,
            secure_stream_v1=secure_stream,
        )
        endpoint = SimpleNamespace(stop=fail_stop)
        publication.adopt_v1(endpoint, b"public-data")

    with pytest.raises(RuntimeError, match="synthetic stop failure"):
        publication.abort_egress_v1()
    with pytest.raises(RuntimeError, match="synthetic stop failure"):
        publication.abort_egress_v1()
    await asyncio.wait_for(teardown_complete.wait(), timeout=1)
    await asyncio.sleep(0)

    assert teardown_calls == 1
    assert publication.release_once_v1()
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_rtc_physical_abort_blocks_then_permits_same_session_replacement():
    environment = rtc_admission_tests._environment()
    principal, session, first_ticket = rtc_admission_tests._issue(
        environment
    )
    caller_webrtc_id = "work-fence-abort-replacement"
    environment.fastrtc.pause_peer_close = True

    async with environment.client() as client:
        first = await client.post(
            rtc_admission_tests.RTC_SIGNALING_ROUTE_V1,
            headers=rtc_admission_tests._offer_headers(
                session.session_id,
                first_ticket.admission_ticket,
            ),
            json=rtc_admission_tests._offer_body(
                caller_webrtc_id
            ),
        )
        assert first.status_code == 200
        old_stream = environment.fastrtc.last_handler
        old_peer = environment.fastrtc.last_peer
        assert old_stream is not None
        assert old_peer is not None
        old_internal_id = old_stream.transport_id
        old_delegate = old_stream.client_session_delegate
        assert old_delegate is not None

        controller, runtime, parent, item = _runtime_item(
            WorkOperationKindV1.RTC_EGRESS
        )
        old_delegate.work_runtime_v1 = runtime
        owner = SimpleNamespace(
            event_handler=old_stream,
            _forget_rtp_publication_v1=(
                lambda _publication: None
            ),
        )
        publication = _RtpPublicationV1(
            work_item_v1=item,
            work_runtime_v1=runtime,
            consumer_capability_v1=None,
            owner_track_v1=owner,
        )

        class _Sender:
            def __init__(self) -> None:
                self.stopped = asyncio.Event()

            async def stop(self) -> None:
                self.stopped.set()

        sender = _Sender()
        publication.bind_sender_v1(sender)
        payloads = _FencedRtpPayloadsV1(
            [b"synthetic-public-media"],
            publication,
        )
        send_started = asyncio.Event()

        async def stubborn_send() -> None:
            send_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await sender.stopped.wait()

        async def send_payloads() -> list[bool]:
            return [
                await _send_rtp_with_publication_v1(
                    stubborn_send
                )
                for _payload in payloads
            ]

        send_task = asyncio.create_task(send_payloads())
        await send_started.wait()
        retirement = await controller.retire_generation_async_v1()
        assert await send_task == [False]
        await asyncio.wait_for(
            environment.fastrtc.peer_close_waiting.wait(),
            timeout=1,
        )
        abort_task = old_stream._work_fence_abort_task_v1

        blocked_ticket = (
            environment.authority.issue_admission_ticket(
                principal,
                session.session_id,
                session.session_capability,
                rtc_admission_tests.SessionAdmissionChannelV1.RTC,
            )
        )
        blocked = await client.post(
            rtc_admission_tests.RTC_SIGNALING_ROUTE_V1,
            headers=rtc_admission_tests._offer_headers(
                session.session_id,
                blocked_ticket.admission_ticket,
            ),
            json=rtc_admission_tests._offer_body(
                caller_webrtc_id
            ),
        )
        assert blocked.status_code == 409

        environment.fastrtc.peer_close_release.set()
        await asyncio.wait_for(
            asyncio.shield(abort_task),
            timeout=1,
        )
        assert old_peer.closed
        assert old_internal_id not in environment.fastrtc.pcs
        assert environment.controller.snapshot() == {
            "active_bindings": 0,
            "attached_sessions": 0,
        }
        assert (
            session.session_id
            in environment.handler_delegate.stop_calls
        )
        assert (
            session.session_id
            not in environment.handler_delegate.session_delegates
        )

        replacement_ticket = (
            environment.authority.issue_admission_ticket(
                principal,
                session.session_id,
                session.session_capability,
                rtc_admission_tests.SessionAdmissionChannelV1.RTC,
            )
        )
        environment.fastrtc.pause_peer_close = False
        replacement = await client.post(
            rtc_admission_tests.RTC_SIGNALING_ROUTE_V1,
            headers=rtc_admission_tests._offer_headers(
                session.session_id,
                replacement_ticket.admission_ticket,
            ),
            json=rtc_admission_tests._offer_body(
                caller_webrtc_id
            ),
        )

    assert replacement.status_code == 200
    replacement_stream = environment.fastrtc.last_handler
    assert replacement_stream is not None
    assert replacement_stream.transport_id != old_internal_id
    assert environment.controller.snapshot() == {
        "active_bindings": 1,
        "attached_sessions": 1,
    }
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()
    replacement_admission = replacement_stream.trusted_rtc_admission
    assert replacement_admission is not None
    await replacement_admission.abort_stream(replacement_stream)


@pytest.mark.asyncio
async def test_sctp_retirement_prevents_queue_and_sequence_mutation():
    controller, runtime, parent, item = _runtime_item(
        WorkOperationKindV1.RTC_EGRESS
    )
    publication = _SctpPublicationV1(
        work_item_v1=item,
        work_runtime_v1=runtime,
        consumer_capability_v1=None,
    )
    transmit_calls = 0

    async def transmit() -> None:
        nonlocal transmit_calls
        transmit_calls += 1

    transport = SimpleNamespace(
        _outbound_stream_seq={3: 7},
        _local_tsn=11,
        _outbound_queue=[],
        _sent_queue=[],
        _transmit=transmit,
    )
    user_data = b"synthetic public data"
    publication.adopt_v1(transport, user_data)
    retirement = controller.retire_generation_v1()
    await asyncio.sleep(0)

    await _send_sctp_message_v1(
        transport,
        stream_id=3,
        pp_id=51,
        user_data=user_data,
    )

    assert transport._outbound_stream_seq == {3: 7}
    assert transport._local_tsn == 11
    assert transport._outbound_queue == []
    assert transmit_calls == 0
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    assert controller.shutdown()

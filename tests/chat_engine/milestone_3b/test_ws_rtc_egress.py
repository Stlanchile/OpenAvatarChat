from __future__ import annotations

import asyncio
import fractions
import time
from types import SimpleNamespace

import numpy as np
import pytest
from aiortc.rtcsctptransport import DataChunk
from fastrtc.utils import CloseStream
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
    _FencedRtpPayloadsV1,
    _retransmit_v1,
    _RtpPublicationV1,
    _SctpPublicationV1,
    _send_rtp_v1,
    _send_rtp_with_publication_v1,
    _send_sctp_chunk_v1,
    fenced_player_worker_decode_v1,
    send_fenced_data_channel_v1,
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
    assert await controller.shutdown_async()


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
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


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
    assert await controller.shutdown_async()


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

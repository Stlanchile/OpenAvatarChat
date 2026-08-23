from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
import weakref
from typing import TYPE_CHECKING, Dict, Optional

import numpy as np
# noinspection PyPackageRequirements
from fastrtc import (
    AsyncAudioVideoStreamHandler,
    AudioEmitType,
    VideoEmitType,
    get_current_context,
)
from loguru import logger

from chat_engine.common.client_handler_base import ClientHandlerDelegate, ClientSessionDelegate
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_signal import ChatSignal
from chat_engine.data_models.chat_signal_type import ChatSignalType, ChatSignalSourceType
from engine_utils.interval_counter import IntervalCounter
from handlers.client.ws_client.ws_message_protocol import (
    EchoHumanText,
    EchoTextPayload,
    MessageHeader,
    MessageType,
    serialize_message,
)
from chat_engine.security.work_runtime import WorkBoundItemV1
from service.rtc_service.fenced_tracks import (
    FencedRtcAudioPayloadV1,
    FencedRtcVideoPayloadV1,
)

if TYPE_CHECKING:
    from service.rtc_service.rtc_session_admission import (
        TrustedRtcSessionAdmissionV1,
    )
    from service.service_security.certificate_session_authority import (
        ConsumedSessionAdmissionV1,
    )


def _get_h264_encoder_info():
    """Get H.264 encoder info dynamically to avoid circular imports"""
    try:
        from handlers.client.rtc_client import client_handler_rtc
        return client_handler_rtc._selected_h264_encoder, client_handler_rtc._actual_h264_encoder
    except Exception:
        return "unknown", None


class RtcStream(AsyncAudioVideoStreamHandler):
    def __init__(self,
                 session_id: Optional[str],
                 expected_layout="mono",
                 input_sample_rate=16000,
                 output_sample_rate=24000,
                 output_frame_size=480,
                 fps=30,
                 stream_start_delay = 0.5,
                 ):
        super().__init__(
            expected_layout=expected_layout,
            input_sample_rate=input_sample_rate,
            output_sample_rate=output_sample_rate,
            output_frame_size=output_frame_size,
            fps=fps
        )
        self.client_handler_delegate: Optional[ClientHandlerDelegate] = None
        self.client_session_delegate: Optional[ClientSessionDelegate] = None

        self.weak_factory: Optional[weakref.ReferenceType[RtcStream]] = None

        self.session_id = session_id
        self.stream_start_delay = stream_start_delay

        self.chat_channel = None
        self.chat_channel_loop = None
        self.first_audio_emitted = False

        self.quit = asyncio.Event()
        self.last_frame_time = 0

        self.emit_counter = IntervalCounter("emit counter")

        self.start_time = None
        self.timestamp_base = self.input_sample_rate

        self.streams: Dict[str, RtcStream] = {}
        self.owns_session = False
        self.webrtc_id: str | None = None
        self.transport_id: str | None = None
        self.session_admission: ConsumedSessionAdmissionV1 | None = None
        self.trusted_rtc_admission: TrustedRtcSessionAdmissionV1 | None = None
        self._secure_admission_required_v1 = False
        self._shutdown_started = False

    def require_secure_rtc_admission_v1(self) -> None:
        """Fail closed unless copy() receives server-owned admission context."""

        self._secure_admission_required_v1 = True

    # copy is used as create_instance in fastrtc
    def copy(self, **kwargs) -> AsyncAudioVideoStreamHandler:
        try:
            if self.client_handler_delegate is None:
                raise Exception("ClientHandlerDelegate is not set.")

            new_stream = RtcStream(
                '',
                expected_layout=self.expected_layout,
                input_sample_rate=self.input_sample_rate,
                output_sample_rate=self.output_sample_rate,
                output_frame_size=self.output_frame_size,
                fps=self.fps,
                stream_start_delay=self.stream_start_delay,
            )
            new_stream.weak_factory = weakref.ref(self)
            new_stream._secure_admission_required_v1 = (
                self._secure_admission_required_v1
            )
            if self._secure_admission_required_v1:
                from service.rtc_service.rtc_session_admission import (
                    get_current_trusted_rtc_admission_v1,
                )

                trusted_admission = get_current_trusted_rtc_admission_v1()
                if trusted_admission is None:
                    raise RuntimeError("SECURE_RTC_ADMISSION_REQUIRED")
                new_stream.webrtc_id = trusted_admission.webrtc_id
                new_stream.transport_id = trusted_admission.transport_id
                new_stream.session_admission = trusted_admission.session_admission
                new_stream.trusted_rtc_admission = trusted_admission
                trusted_admission.bind_stream(new_stream)
            return new_stream
        except Exception:
            logger.opt(exception=True).error("Failed to create RTC stream.")
            raise

    async def start_up(self):
        if self.client_session_delegate is not None:
            return

        factory = self
        if self.weak_factory is not None and self.weak_factory() is not None:
            factory = self.weak_factory()

        if factory.client_handler_delegate is None:
            raise RuntimeError("ClientHandlerDelegate is not set.")

        if self._secure_admission_required_v1:
            if self.trusted_rtc_admission is None:
                raise RuntimeError("SECURE_RTC_ADMISSION_REQUIRED")
            await self.trusted_rtc_admission.attach_stream(self)
            return

        session_id = self.session_id
        if not session_id:
            try:
                session_id = get_current_context().webrtc_id
            except Exception:
                session_id = uuid.uuid4().hex

        selected_encoder, _ = _get_h264_encoder_info()
        logger.debug(f"[{session_id}] H.264 encoder: {selected_encoder}")

        if session_id in factory.streams:
            existing = factory.streams.get(session_id)
            # Cleanup stale entries left by interrupted connections.
            if existing is None or existing.client_session_delegate is None or existing.quit.is_set():
                factory.streams.pop(session_id, None)
            else:
                base_session_id = session_id
                session_id = f"{base_session_id}-{uuid.uuid4().hex[:8]}"
                logger.warning(f"Session id conflict for {base_session_id}, fallback to {session_id}")

        self.session_id = session_id
        existing_delegate = factory.client_handler_delegate.find_session_delegate(session_id)
        if existing_delegate is not None:
            self.client_session_delegate = existing_delegate
            self.owns_session = False
            logger.info(f"Reuse existing session delegate for session {session_id}")
        else:
            try:
                self.client_session_delegate = factory.client_handler_delegate.start_session(
                    session_id=session_id,
                    timestamp_base=self.input_sample_rate,
                )
                self.owns_session = True
            except RuntimeError as e:
                # Another client path (e.g. WS) may create the same session concurrently.
                if "already exists" not in str(e):
                    raise
                existing_delegate = factory.client_handler_delegate.find_session_delegate(session_id)
                if existing_delegate is None:
                    raise
                self.client_session_delegate = existing_delegate
                self.owns_session = False
                logger.info(f"Session {session_id} created concurrently, reusing existing delegate")

        factory.streams[session_id] = self

    async def emit(self) -> AudioEmitType:
        try:
            # if not self.args_set.is_set():
            # await self.wait_for_args()
            while self.client_session_delegate is None and not self.quit.is_set():
                await asyncio.sleep(0.01)
            if self.client_session_delegate is None:
                return None

            if not self.first_audio_emitted:
                self.client_session_delegate.clear_data()
                self.first_audio_emitted = True

            while not self.quit.is_set():
                queued_item = await self.client_session_delegate.get_data(
                    EngineChannelType.AUDIO
                )
                unwrap = getattr(
                    self.client_session_delegate,
                    "unwrap_output_item_v1",
                    None,
                )
                if callable(unwrap):
                    chat_data, work_item = unwrap(queued_item)
                else:
                    chat_data, work_item = queued_item, None
                if chat_data is None or chat_data.data is None:
                    if (
                        isinstance(work_item, WorkBoundItemV1)
                        and getattr(
                            self.client_session_delegate,
                            "work_runtime_v1",
                            None,
                        )
                        is not None
                    ):
                        work_item.release_once_v1(
                            self.client_session_delegate.work_runtime_v1
                        )
                    continue
                runtime = getattr(
                    self.client_session_delegate,
                    "work_runtime_v1",
                    None,
                )
                capability = getattr(
                    self.client_session_delegate,
                    "work_consumer_capability_v1",
                    None,
                )
                scope = (
                    runtime.activate_work_v1(
                        work_item.registered_work,
                        work_item.envelope_ref,
                    )
                    if runtime is not None
                    and isinstance(work_item, WorkBoundItemV1)
                    else contextlib.nullcontext()
                )
                handed_off = False
                try:
                    with scope:
                        audio_array = chat_data.data.get_main_data()
                        if audio_array is None:
                            continue

                        def commit_audio_emit() -> None:
                            sample_num = audio_array.shape[-1]
                            self.emit_counter.add_property(
                                "audio_emit",
                                sample_num / self.output_sample_rate,
                            )

                        if runtime is None or work_item is None:
                            commit_audio_emit()
                            return (
                                self.output_sample_rate,
                                audio_array,
                            )
                        else:
                            payloads: list[
                                FencedRtcAudioPayloadV1
                            ] = []
                            if runtime.perform_item_egress_if_live_v1(
                                work_item,
                                capability,
                                lambda: payloads.append(
                                    FencedRtcAudioPayloadV1(
                                        sample_rate=(
                                            self.output_sample_rate
                                        ),
                                        audio_array=audio_array,
                                        work_item_v1=work_item,
                                        work_runtime_v1=runtime,
                                        consumer_capability_v1=capability,
                                        commit_frame_v1=lambda frame: (
                                            self.emit_counter.add_property(
                                                "audio_emit",
                                                frame.samples
                                                / self.output_sample_rate,
                                            )
                                        ),
                                    )
                                ),
                            ) and payloads:
                                handed_off = True
                                return payloads[0]
                finally:
                    if (
                        runtime is not None
                        and isinstance(work_item, WorkBoundItemV1)
                        and not handed_off
                    ):
                        work_item.release_once_v1(runtime)
        except Exception as exception:
            runtime = getattr(
                self.client_session_delegate,
                "work_runtime_v1",
                None,
            )
            if runtime is None:
                logger.opt(exception=exception).error("Error in emit: ")
            else:
                logger.error("RTC_AUDIO_EMIT_FAILED")
            raise

    async def video_emit(self) -> VideoEmitType:
        try:
            if not self.first_audio_emitted:
                await asyncio.sleep(0.1)
            while self.client_session_delegate is None and not self.quit.is_set():
                await asyncio.sleep(0.01)
            if self.client_session_delegate is None:
                return None
            
            while not self.quit.is_set():
                get_data_start = time.perf_counter()
                queued_item = await self.client_session_delegate.get_data(
                    EngineChannelType.VIDEO
                )
                get_data_wait_time = time.perf_counter() - get_data_start

                _slow_video_threshold_s = 0.12
                if get_data_wait_time > _slow_video_threshold_s:
                    logger.debug(
                        f"[{self.session_id}] Slow video data retrieval: "
                        f"{get_data_wait_time:.3f}s (threshold {_slow_video_threshold_s}s)"
                    )
                
                unwrap = getattr(
                    self.client_session_delegate,
                    "unwrap_output_item_v1",
                    None,
                )
                if callable(unwrap):
                    video_frame_data, work_item = unwrap(
                        queued_item
                    )
                else:
                    video_frame_data, work_item = queued_item, None
                if video_frame_data is None or video_frame_data.data is None:
                    runtime = getattr(
                        self.client_session_delegate,
                        "work_runtime_v1",
                        None,
                    )
                    if (
                        runtime is not None
                        and isinstance(work_item, WorkBoundItemV1)
                    ):
                        work_item.release_once_v1(runtime)
                    continue
                runtime = getattr(
                    self.client_session_delegate,
                    "work_runtime_v1",
                    None,
                )
                capability = getattr(
                    self.client_session_delegate,
                    "work_consumer_capability_v1",
                    None,
                )
                scope = (
                    runtime.activate_work_v1(
                        work_item.registered_work,
                        work_item.envelope_ref,
                    )
                    if runtime is not None
                    and isinstance(work_item, WorkBoundItemV1)
                    else contextlib.nullcontext()
                )
                handed_off = False
                try:
                    with scope:
                        frame_data = (
                            video_frame_data.data
                            .get_main_data()
                            .squeeze()
                        )
                        if frame_data is None:
                            continue
                        if runtime is None or work_item is None:
                            self.emit_counter.add_property(
                                "video_emit"
                            )
                            return frame_data
                        else:
                            payloads: list[
                                FencedRtcVideoPayloadV1
                            ] = []
                            if runtime.perform_item_egress_if_live_v1(
                                work_item,
                                capability,
                                lambda: payloads.append(
                                    FencedRtcVideoPayloadV1(
                                        frame_array=frame_data,
                                        work_item_v1=work_item,
                                        work_runtime_v1=runtime,
                                        consumer_capability_v1=capability,
                                        commit_v1=lambda: (
                                            self.emit_counter.add_property(
                                                "video_emit"
                                            )
                                        ),
                                    )
                                ),
                            ) and payloads:
                                handed_off = True
                                return payloads[0]
                finally:
                    if (
                        runtime is not None
                        and isinstance(work_item, WorkBoundItemV1)
                        and not handed_off
                    ):
                        work_item.release_once_v1(runtime)
        except Exception as exception:
            runtime = getattr(
                self.client_session_delegate,
                "work_runtime_v1",
                None,
            )
            if runtime is None:
                logger.opt(exception=exception).error(
                    "Error in video_emit"
                )
            else:
                logger.error("RTC_VIDEO_EMIT_FAILED")
            raise

    async def receive(self, frame: tuple[int, np.ndarray]):
        if self.client_session_delegate is None:
            return
        scope_factory = getattr(
            self.client_session_delegate,
            "ingress_work_scope_v1",
            None,
        )
        scope = (
            scope_factory()
            if callable(scope_factory)
            else contextlib.nullcontext(None)
        )
        with scope as work_scope:
            if (
                getattr(
                    self.client_session_delegate,
                    "work_runtime_v1",
                    None,
                )
                is not None
                and work_scope is None
            ):
                return
            timestamp = self.client_session_delegate.get_timestamp()
            if timestamp[0] / timestamp[1] < self.stream_start_delay:
                return
            _, array = frame
            self.client_session_delegate.put_data(
                EngineChannelType.AUDIO,
                array,
                timestamp,
                self.input_sample_rate,
            )

    async def video_receive(self, frame):
        if self.client_session_delegate is None:
            return
        scope_factory = getattr(
            self.client_session_delegate,
            "ingress_work_scope_v1",
            None,
        )
        scope = (
            scope_factory()
            if callable(scope_factory)
            else contextlib.nullcontext(None)
        )
        with scope as work_scope:
            if (
                getattr(
                    self.client_session_delegate,
                    "work_runtime_v1",
                    None,
                )
                is not None
                and work_scope is None
            ):
                return
            timestamp = self.client_session_delegate.get_timestamp()
            if timestamp[0] / timestamp[1] < self.stream_start_delay:
                return
            self.client_session_delegate.put_data(
                EngineChannelType.VIDEO,
                frame,
                timestamp,
                self.fps,
            )

    def set_channel(self, channel):
            super().set_channel(channel)
            self.chat_channel = channel
            try:
                self.chat_channel_loop = asyncio.get_running_loop()
            except RuntimeError:
                self.chat_channel_loop = None
                
            @channel.on("message")
            def _(message):
                try:
                    message = json.loads(message)
                except Exception:  # noqa: BLE001
                    logger.debug("Ignored malformed RTC data-channel message.")
                    message = {}

                if self.client_session_delegate is None:
                    return
                scope_factory = getattr(
                    self.client_session_delegate,
                    "ingress_work_scope_v1",
                    None,
                )
                scope = (
                    scope_factory()
                    if callable(scope_factory)
                    else contextlib.nullcontext(None)
                )
                with scope as work_scope:
                    runtime = getattr(
                        self.client_session_delegate,
                        "work_runtime_v1",
                        None,
                    )
                    if runtime is not None and work_scope is None:
                        return
                    timestamp = (
                        self.client_session_delegate.get_timestamp()
                    )
                    if (
                        timestamp[0] / timestamp[1]
                        < self.stream_start_delay
                    ):
                        return
                    try:
                        message_name = message["header"]["name"]
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "Ignored malformed RTC data-channel message."
                        )
                        return

                    if message_name == "Interrupt":
                        self.client_session_delegate.emit_signal(
                            ChatSignal(
                                type=ChatSignalType.INTERRUPT,
                                source_type=ChatSignalSourceType.CLIENT,
                                source_name="rtc",
                            )
                        )
                    elif message_name == "SendHumanText":
                        self.client_session_delegate.emit_signal(
                            ChatSignal(
                                type=ChatSignalType.STREAM_BEGIN,
                                stream_type=ChatDataType.AVATAR_AUDIO,
                                source_type=ChatSignalSourceType.CLIENT,
                                source_name="rtc",
                            )
                        )
                        try:
                            text = message["payload"]["text"]
                        except Exception:  # noqa: BLE001
                            logger.debug(
                                "Ignored malformed RTC text message."
                            )
                            return
                        self.client_session_delegate.put_data(
                            EngineChannelType.TEXT,
                            text,
                            loopback=True,
                        )
                        # The secure handler dispatch creates a separately
                        # authorized RTC_EGRESS child.  Preserve the historical
                        # immediate local echo only for legacy sessions.
                        if (
                            runtime is None
                            and not hasattr(
                                self.client_session_delegate,
                                "ws_text_queue",
                            )
                        ):
                            try:
                                payload = message.get("payload", {})
                                response = EchoHumanText(
                                    header=MessageHeader(
                                        name=(
                                            MessageType.ECHO_HUMAN_TEXT
                                        ),
                                        request_id=str(uuid.uuid4()),
                                    ),
                                    payload=EchoTextPayload(
                                        stream_key=payload.get(
                                            "stream_key"
                                        ),
                                        mode="full_text",
                                        text=payload.get("text", ""),
                                        end_of_speech=payload.get(
                                            "end_of_speech",
                                            True,
                                        ),
                                        metadata=None,
                                    ),
                                )
                                self.chat_channel.send(
                                    json.dumps(
                                        serialize_message(response)
                                    )
                                )
                            except Exception:  # noqa: BLE001
                                logger.warning(
                                    "Failed to send local human text echo."
                                )
                # else:

                # channel.send(json.dumps({"type": "chat", "unique_id": unique_id, "message": message}))
          
    async def on_chat_datachannel(self, message: Dict, channel):
        # {"type":"chat",id:"标识属于同一段话", "message":"Hello, world!"}
        # unique_id = uuid.uuid4().hex
        pass

    def drain_application_egress_v1(self) -> None:
        """Drop queued application media while preserving peer teardown."""

        delegate = self.client_session_delegate
        if delegate is not None:
            drain = getattr(
                delegate,
                "drain_application_output_v1",
                None,
            )
            if callable(drain):
                drain()
        clear_fast_rtc_queue = getattr(self, "_clear_queue", None)
        if callable(clear_fast_rtc_queue):
            clear_fast_rtc_queue()

    def shutdown(self):
        if self._shutdown_started:
            return
        self._shutdown_started = True
        self.quit.set()
        factory = None
        if self.weak_factory is not None:
            factory = self.weak_factory()
        if factory is None:
            factory = self
        delegate = self.client_session_delegate
        if delegate is not None:
            try:
                delegate.clear_data()
            except Exception:  # noqa: BLE001
                logger.error("Failed to clear RTC application queues.")
        self.client_session_delegate = None
        if self.session_id in factory.streams:
            factory.streams.pop(self.session_id, None)
        if self.owns_session and factory.client_handler_delegate is not None:
            try:
                factory.client_handler_delegate.stop_session(self.session_id)
            except Exception:  # noqa: BLE001
                logger.error("Failed to stop RTC-owned session.")
        if self.trusted_rtc_admission is not None:
            try:
                self.trusted_rtc_admission.release_stream(self)
            except Exception:  # noqa: BLE001
                logger.error("Failed to release secure RTC transport.")

    async def shutdown_async(self):
        if self._shutdown_started:
            return
        self._shutdown_started = True
        self.quit.set()
        factory = None
        if self.weak_factory is not None:
            factory = self.weak_factory()
        if factory is None:
            factory = self
        delegate = self.client_session_delegate
        if delegate is not None:
            try:
                delegate.clear_data()
            except Exception:  # noqa: BLE001
                logger.error("Failed to clear RTC application queues.")
        self.client_session_delegate = None
        if self.session_id in factory.streams:
            factory.streams.pop(self.session_id, None)
        if self.owns_session and factory.client_handler_delegate is not None:
            try:
                stop_async = getattr(
                    factory.client_handler_delegate,
                    "stop_session_async",
                    None,
                )
                if callable(stop_async):
                    await stop_async(self.session_id)
                else:
                    factory.client_handler_delegate.stop_session(
                        self.session_id
                    )
            except Exception:  # noqa: BLE001
                logger.error("Failed to stop RTC-owned session.")
        if self.trusted_rtc_admission is not None:
            try:
                self.trusted_rtc_admission.release_stream(self)
            except Exception:  # noqa: BLE001
                logger.error("Failed to release secure RTC transport.")

"""FastRTC media-track adapters that retain Milestone 3 work authority.

FastRTC buffers handler output after ``RtcStream.emit()`` returns.  These
adapters keep server-owned work references attached to that internal media
queue and perform the final M2 + M3 commit immediately before an aiortc track
returns a frame for peer egress.
"""

from __future__ import annotations

import asyncio
import contextvars
import fractions
import inspect
import math
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any, cast

import av
import fastrtc.tracks as _fastrtc_tracks
import fastrtc.webrtc_connection_mixin as _fastrtc_connection
import librosa
import numpy as np
from aiortc import rtcsctptransport as _aiortc_sctp
from aiortc.contrib.media import AudioFrame
from aiortc.mediastreams import MediaStreamError
from aiortc.rtcdtlstransport import RTCDtlsTransport
from aiortc.rtcrtpsender import RTP_HISTORY_SIZE, RTCRtpSender
from aiortc.rtcsctptransport import DataChunk, RTCSctpTransport
from fastrtc.tracks import AudioCallback, VideoStreamHandler_
from fastrtc.utils import (
    AUDIO_PTIME,
    AdditionalOutputs,
    CloseStream,
    DataChannel,
    WebRTCError,
    audio_to_float32,
    create_message,
    current_channel,
    split_output,
)
from loguru import logger

from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)


@dataclass(slots=True, repr=False)
class FencedRtcAudioPayloadV1:
    """One handler-produced audio chunk awaiting FastRTC frame conversion."""

    sample_rate: int
    audio_array: np.ndarray
    work_item_v1: WorkBoundItemV1
    work_runtime_v1: SessionWorkRuntimeV1
    consumer_capability_v1: Any
    layout: str = "mono"
    commit_frame_v1: Callable[[AudioFrame], None] | None = None

    def __repr__(self) -> str:
        return "FencedRtcAudioPayloadV1(<redacted>)"


@dataclass(slots=True, repr=False)
class FencedRtcVideoPayloadV1:
    """One video array awaiting the final FastRTC track publication."""

    frame_array: np.ndarray
    work_item_v1: WorkBoundItemV1
    work_runtime_v1: SessionWorkRuntimeV1
    consumer_capability_v1: Any
    commit_v1: Callable[[], None] | None = None

    def __repr__(self) -> str:
        return "FencedRtcVideoPayloadV1(<redacted>)"


@dataclass(slots=True, repr=False)
class _FencedAudioFrameV1:
    frame: AudioFrame
    work_item_v1: WorkBoundItemV1
    work_runtime_v1: SessionWorkRuntimeV1
    consumer_capability_v1: Any
    commit_frame_v1: Callable[[AudioFrame], None] | None = None

    def __repr__(self) -> str:
        return "_FencedAudioFrameV1(<redacted>)"


@dataclass(slots=True, repr=False)
class _RtpPublicationV1:
    work_item_v1: WorkBoundItemV1
    work_runtime_v1: SessionWorkRuntimeV1
    consumer_capability_v1: Any
    owner_track_v1: Any
    commit_v1: Callable[[], None] | None = None
    owner_sender_v1: RTCRtpSender | None = dataclass_field(
        default=None,
        init=False,
        repr=False,
    )
    _complete_lock_v1: threading.Lock = dataclass_field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )
    _complete_v1: bool = dataclass_field(
        default=False,
        init=False,
        repr=False,
    )
    _initial_send_complete_v1: bool = dataclass_field(
        default=False,
        init=False,
        repr=False,
    )
    _sequence_numbers_v1: set[int] = dataclass_field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _lifetime_task_v1: asyncio.Task[None] | None = dataclass_field(
        default=None,
        init=False,
        repr=False,
    )

    def bind_sender_v1(self, sender: RTCRtpSender) -> None:
        with self._complete_lock_v1:
            if self._complete_v1:
                return
            self.owner_sender_v1 = sender
        sender._fenced_rtp_sender_v1 = True

    def _ensure_lifetime_task_v1(self) -> None:
        with self._complete_lock_v1:
            if self._complete_v1 or self._lifetime_task_v1 is not None:
                return
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            task = loop.create_task(self._release_when_cancelled_or_expired_v1())
            self._lifetime_task_v1 = task

    async def _release_when_cancelled_or_expired_v1(self) -> None:
        remaining = max(
            0.0,
            self.work_item_v1.fence.deadline_monotonic - time.monotonic(),
        )
        try:
            await self.work_item_v1.cancellation.wait_async(remaining)
        except asyncio.CancelledError:
            return
        self.release_once_v1()

    def retain_sequence_v1(self, sequence_number: int) -> None:
        sender = self.owner_sender_v1
        if sender is None:
            return
        slot = sequence_number % RTP_HISTORY_SIZE
        publications = getattr(
            sender,
            "_fenced_rtp_history_v1",
            None,
        )
        if publications is None:
            publications = {}
            sender._fenced_rtp_history_v1 = publications
        previous = publications.get(slot)
        publications[slot] = (sequence_number, self)
        with self._complete_lock_v1:
            if not self._complete_v1:
                self._sequence_numbers_v1.add(sequence_number)
        if previous is not None and previous != (sequence_number, self):
            previous_sequence, previous_publication = previous
            previous_publication.forget_sequence_v1(previous_sequence)
        self._ensure_lifetime_task_v1()

    def forget_sequence_v1(self, sequence_number: int) -> None:
        should_release = False
        with self._complete_lock_v1:
            self._sequence_numbers_v1.discard(sequence_number)
            should_release = (
                self._initial_send_complete_v1
                and not self._sequence_numbers_v1
                and not self._complete_v1
            )
        if should_release:
            self.release_once_v1()

    def mark_initial_send_complete_v1(self) -> None:
        should_release = False
        with self._complete_lock_v1:
            self._initial_send_complete_v1 = True
            should_release = not self._sequence_numbers_v1 and not self._complete_v1
        if should_release:
            self.release_once_v1()

    def release_once_v1(self) -> bool:
        lifetime_task = None
        with self._complete_lock_v1:
            if self._complete_v1:
                return False
            self._complete_v1 = True
            lifetime_task = self._lifetime_task_v1
            self._lifetime_task_v1 = None
        current_task = None
        try:
            current_task = asyncio.current_task()
        except RuntimeError:
            pass
        if (
            lifetime_task is not None
            and lifetime_task is not current_task
            and not lifetime_task.done()
        ):
            lifetime_task.cancel()
        forget = getattr(
            self.owner_track_v1,
            "_forget_rtp_publication_v1",
            None,
        )
        if callable(forget):
            forget(self)
        return self.work_item_v1.release_once_v1(self.work_runtime_v1)

    def __repr__(self) -> str:
        return "_RtpPublicationV1(<redacted>)"


_RTP_PUBLICATION_SCOPE_V1: contextvars.ContextVar[
    tuple[_RtpPublicationV1, bool, bool] | None
] = contextvars.ContextVar(
    "rtc_rtp_publication_scope_v1",
    default=None,
)


class _FencedRtpPayloadsV1(list[bytes]):
    def __init__(
        self,
        payloads: list[bytes],
        publication: _RtpPublicationV1,
    ) -> None:
        super().__init__(payloads)
        self._publication_v1 = publication

    def __iter__(self):
        payload_count = len(self)
        for index, payload in enumerate(super().__iter__()):
            token = _RTP_PUBLICATION_SCOPE_V1.set(
                (
                    self._publication_v1,
                    index == payload_count - 1,
                    True,
                )
            )
            try:
                yield payload
            finally:
                _RTP_PUBLICATION_SCOPE_V1.reset(token)


class _FencedRtpTrackMixinV1:
    def _install_pending_rtp_publication_v1(
        self,
        publication: _RtpPublicationV1,
    ) -> bool:
        if getattr(self, "_pending_rtp_publication_v1", None) is not None:
            return False
        self._pending_rtp_publication_v1 = publication
        return True

    def claim_pending_rtp_publication_v1(
        self,
    ) -> _RtpPublicationV1 | None:
        publication = getattr(
            self,
            "_pending_rtp_publication_v1",
            None,
        )
        self._pending_rtp_publication_v1 = None
        if publication is not None:
            inflight = getattr(
                self,
                "_inflight_rtp_publications_v1",
                None,
            )
            if inflight is None:
                inflight = {}
                self._inflight_rtp_publications_v1 = inflight
            inflight[id(publication)] = publication
        return publication

    def _forget_rtp_publication_v1(
        self,
        publication: _RtpPublicationV1,
    ) -> None:
        inflight = getattr(
            self,
            "_inflight_rtp_publications_v1",
            None,
        )
        if inflight is not None:
            inflight.pop(id(publication), None)
        if getattr(self, "_pending_rtp_publication_v1", None) is publication:
            self._pending_rtp_publication_v1 = None

    def _release_all_rtp_publications_v1(self) -> None:
        pending = getattr(
            self,
            "_pending_rtp_publication_v1",
            None,
        )
        if pending is not None:
            pending.release_once_v1()
        inflight = tuple(
            getattr(
                self,
                "_inflight_rtp_publications_v1",
                {},
            ).values()
        )
        for publication in inflight:
            publication.release_once_v1()

    def stop(self) -> None:
        self._release_all_rtp_publications_v1()
        super().stop()


def _release_audio_queue_entry_v1(entry: object) -> None:
    if isinstance(entry, _FencedAudioFrameV1):
        entry.work_item_v1.release_once_v1(entry.work_runtime_v1)


async def fenced_player_worker_decode_v1(
    next_frame,
    output_queue: asyncio.Queue,
    thread_quit: asyncio.Event,
    channel,
    set_additional_outputs,
    quit_on_none: bool = False,
    sample_rate: int = 48000,
    frame_size: int = int(48000 * AUDIO_PTIME),
) -> None:
    """FastRTC's decoder with exact-parent authority on every queued frame."""

    audio_samples = 0
    first_sample_rate = None
    secure_epoch = None

    def new_resampler():
        return av.AudioResampler(
            format="s16",
            layout="stereo",
            rate=sample_rate,
            frame_size=frame_size,
        )

    audio_resampler = new_resampler()
    while not thread_quit.is_set():
        fenced_payload: FencedRtcAudioPayloadV1 | None = None
        try:
            raw_output = await asyncio.wait_for(
                next_frame(),
                timeout=60,
            )
            if isinstance(raw_output, FencedRtcAudioPayloadV1):
                fenced_payload = raw_output
                parent_item = fenced_payload.work_item_v1
                runtime = fenced_payload.work_runtime_v1
                epoch = parent_item.fence.session_epoch
                if secure_epoch is not None and secure_epoch != epoch:
                    audio_resampler = new_resampler()
                    audio_samples = 0
                    first_sample_rate = None
                secure_epoch = epoch
                if not runtime.validate_work_v1(
                    parent_item.registered_work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                ):
                    audio_resampler = new_resampler()
                    audio_samples = 0
                    first_sample_rate = None
                    continue
                frame = (
                    fenced_payload.sample_rate,
                    fenced_payload.audio_array,
                    fenced_payload.layout,
                )
                outputs = None
            else:
                frame, outputs = split_output(raw_output)

            if (
                isinstance(outputs, AdditionalOutputs)
                and set_additional_outputs
                and channel
                and channel()
            ):
                set_additional_outputs(outputs)
                cast(DataChannel, channel()).send(create_message("fetch_output", []))
            if frame is None:
                if isinstance(outputs, CloseStream):
                    await output_queue.put(outputs)
                if quit_on_none:
                    await output_queue.put(None)
                    break
                continue
            if (
                not isinstance(frame, tuple)
                or len(frame) not in {2, 3}
                or not isinstance(frame[1], np.ndarray)
            ):
                raise WebRTCError("The frame must contain a sample rate and array")
            if len(frame) == 2:
                current_sample_rate, audio_array = frame
                layout = "mono"
            else:
                current_sample_rate, audio_array, layout = frame
            audio_format = "s16" if audio_array.dtype == "int16" else "fltp"
            if first_sample_rate is None:
                first_sample_rate = current_sample_rate
            if audio_format == "s16":
                audio_array = audio_to_float32(audio_array)
            if first_sample_rate != current_sample_rate:
                audio_array = librosa.resample(
                    audio_array,
                    target_sr=first_sample_rate,
                    orig_sr=current_sample_rate,
                )
            if audio_array.ndim == 1:
                audio_array = audio_array.reshape(1, -1)
            audio_frame = av.AudioFrame.from_ndarray(
                audio_array,
                format="fltp",
                layout=layout,
            )
            audio_frame.sample_rate = first_sample_rate
            for processed_frame in audio_resampler.resample(audio_frame):
                processed_frame.pts = audio_samples
                processed_frame.time_base = fractions.Fraction(
                    1,
                    sample_rate,
                )
                audio_samples += processed_frame.samples
                if fenced_payload is None:
                    await output_queue.put(processed_frame)
                    continue
                parent_item = fenced_payload.work_item_v1
                runtime = fenced_payload.work_runtime_v1
                try:
                    child_work = runtime.register_child_work_v1(
                        parent_item.registered_work,
                        WorkOperationKindV1.RTC_EGRESS,
                    )
                except WorkAdmissionDeniedV1:
                    break
                frame_item = WorkBoundItemV1(
                    payload=None,
                    registered_work=child_work,
                    envelope_ref=parent_item.envelope_ref,
                )
                queued_frame = _FencedAudioFrameV1(
                    frame=processed_frame,
                    work_item_v1=frame_item,
                    work_runtime_v1=runtime,
                    consumer_capability_v1=(fenced_payload.consumer_capability_v1),
                    commit_frame_v1=fenced_payload.commit_frame_v1,
                )
                try:
                    await output_queue.put(queued_frame)
                except BaseException:
                    frame_item.release_once_v1(runtime)
                    raise
            if isinstance(outputs, CloseStream):
                await output_queue.put(outputs)
        except TimeoutError:
            logger.warning("RTC_AUDIO_FRAME_SOURCE_TIMEOUT")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - stable payload-free media failure
            if fenced_payload is None:
                logger.error("RTC_AUDIO_FRAME_PROCESSING_FAILED")
            else:
                logger.error("RTC_FENCED_AUDIO_FRAME_PROCESSING_FAILED")
        finally:
            if fenced_payload is not None:
                fenced_payload.work_item_v1.release_once_v1(
                    fenced_payload.work_runtime_v1
                )


class FencedAudioCallbackV1(
    _FencedRtpTrackMixinV1,
    AudioCallback,
):
    """Validate each buffered audio frame at aiortc track publication."""

    def clear_queue(self) -> None:
        while not self.queue.empty():
            try:
                entry = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            _release_audio_queue_entry_v1(entry)
        self._start = None

    async def recv(self):  # type: ignore[override]
        while True:
            if self.readyState != "live":
                raise MediaStreamError
            if not self.event_handler.channel_set.is_set():
                await self.event_handler.channel_set.wait()
            if current_channel.get() != self.event_handler.channel:
                current_channel.set(self.event_handler.channel)
            await self.start()
            entry = await self.queue.get()
            if isinstance(entry, CloseStream):
                cast(DataChannel, self.channel).send(
                    create_message("end_stream", entry.msg)
                )
                self.stop()
                return None
            fenced_frame = entry if isinstance(entry, _FencedAudioFrameV1) else None
            frame = fenced_frame.frame if fenced_frame is not None else entry
            handed_to_sender = False
            try:
                data_time = frame.time
                if time.time() - self.last_timestamp > 10 * (
                    self.event_handler.output_frame_size
                    / self.event_handler.output_sample_rate
                ):
                    self._start = None
                if self._start is None:
                    self._start = time.time() - data_time
                else:
                    await asyncio.sleep(
                        max(
                            0.0,
                            self._start + data_time - time.time(),
                        )
                    )
                self.last_timestamp = time.time()
                if fenced_frame is None:
                    return frame
                publication = _RtpPublicationV1(
                    work_item_v1=fenced_frame.work_item_v1,
                    work_runtime_v1=fenced_frame.work_runtime_v1,
                    consumer_capability_v1=(fenced_frame.consumer_capability_v1),
                    owner_track_v1=self,
                    commit_v1=(
                        (
                            lambda fenced_frame=fenced_frame, frame=frame: (
                                fenced_frame.commit_frame_v1(frame)
                            )
                        )
                        if fenced_frame.commit_frame_v1 is not None
                        else None
                    ),
                )
                committed: list[bool] = []

                def hand_to_sender(
                    publication=publication,
                    committed=committed,
                ) -> None:
                    if self._install_pending_rtp_publication_v1(publication):
                        committed.append(True)

                if (
                    fenced_frame.work_runtime_v1.perform_item_egress_if_live_v1(
                        fenced_frame.work_item_v1,
                        fenced_frame.consumer_capability_v1,
                        hand_to_sender,
                    )
                    and committed
                ):
                    handed_to_sender = True
                    return frame
            finally:
                if fenced_frame is not None and not handed_to_sender:
                    fenced_frame.work_item_v1.release_once_v1(
                        fenced_frame.work_runtime_v1
                    )


class FencedVideoStreamHandlerV1(
    _FencedRtpTrackMixinV1,
    VideoStreamHandler_,
):
    """Validate video after FastRTC timing and immediately before return."""

    async def recv(self):  # type: ignore[override]
        await self.start()
        while True:
            fenced_payload: FencedRtcVideoPayloadV1 | None = None
            handed_to_sender = False
            try:
                handler = self.event_handler
                if inspect.iscoroutinefunction(handler.video_emit):
                    raw_output = await handler.video_emit()
                else:
                    raw_output = handler.video_emit()
                if isinstance(raw_output, FencedRtcVideoPayloadV1):
                    fenced_payload = raw_output
                    frame_array = raw_output.frame_array
                    outputs = None
                else:
                    frame_array, outputs = split_output(raw_output)
                if (
                    isinstance(outputs, AdditionalOutputs)
                    and self.set_additional_outputs
                    and self.channel
                ):
                    self.set_additional_outputs(outputs)
                    self.channel.send(create_message("fetch_output", []))
                if isinstance(outputs, CloseStream):
                    cast(DataChannel, self.channel).send(
                        create_message("end_stream", outputs.msg)
                    )
                    self.stop()
                    return None
                if frame_array is None:
                    return None
                new_frame = self.array_to_frame(frame_array)
                pts, time_base = await self.next_timestamp()
                new_frame.pts = pts
                new_frame.time_base = time_base
                if fenced_payload is None:
                    return new_frame
                publication = _RtpPublicationV1(
                    work_item_v1=fenced_payload.work_item_v1,
                    work_runtime_v1=fenced_payload.work_runtime_v1,
                    consumer_capability_v1=(fenced_payload.consumer_capability_v1),
                    owner_track_v1=self,
                    commit_v1=fenced_payload.commit_v1,
                )
                committed: list[bool] = []

                def hand_to_sender(
                    publication=publication,
                    committed=committed,
                ) -> None:
                    if self._install_pending_rtp_publication_v1(publication):
                        committed.append(True)

                if (
                    fenced_payload.work_runtime_v1.perform_item_egress_if_live_v1(
                        fenced_payload.work_item_v1,
                        fenced_payload.consumer_capability_v1,
                        hand_to_sender,
                    )
                    and committed
                ):
                    handed_to_sender = True
                    return new_frame
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - stable payload-free media failure
                if fenced_payload is None:
                    logger.error("RTC_VIDEO_FRAME_PROCESSING_FAILED")
                else:
                    logger.error("RTC_FENCED_VIDEO_FRAME_PROCESSING_FAILED")
            finally:
                if fenced_payload is not None and not handed_to_sender:
                    fenced_payload.work_item_v1.release_once_v1(
                        fenced_payload.work_runtime_v1
                    )


@dataclass(slots=True, repr=False)
class _SctpPublicationV1:
    """Authority retained for one reliable application data-channel message."""

    work_item_v1: WorkBoundItemV1
    work_runtime_v1: SessionWorkRuntimeV1
    consumer_capability_v1: Any
    _state_lock_v1: threading.Lock = dataclass_field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )
    _complete_v1: bool = dataclass_field(
        default=False,
        init=False,
        repr=False,
    )
    _adopted_v1: bool = dataclass_field(
        default=False,
        init=False,
        repr=False,
    )
    _send_complete_v1: bool = dataclass_field(
        default=False,
        init=False,
        repr=False,
    )
    _transport_v1: RTCSctpTransport | None = dataclass_field(
        default=None,
        init=False,
        repr=False,
    )
    _chunks_v1: list[DataChunk] = dataclass_field(
        default_factory=list,
        init=False,
        repr=False,
    )
    _lifetime_task_v1: asyncio.Task[None] | None = dataclass_field(
        default=None,
        init=False,
        repr=False,
    )

    @property
    def adopted_v1(self) -> bool:
        with self._state_lock_v1:
            return self._adopted_v1

    def adopt_v1(
        self,
        transport: RTCSctpTransport,
        user_data: bytes,
    ) -> None:
        with self._state_lock_v1:
            if self._complete_v1:
                return
            self._adopted_v1 = True
            self._transport_v1 = transport
        pending = getattr(
            transport,
            "_fenced_sctp_pending_v1",
            None,
        )
        if pending is None:
            pending = {}
            transport._fenced_sctp_pending_v1 = pending
        pending.setdefault(id(user_data), deque()).append(self)
        publications = getattr(
            transport,
            "_fenced_sctp_publications_v1",
            None,
        )
        if publications is None:
            publications = {}
            transport._fenced_sctp_publications_v1 = publications
        publications[id(self)] = self
        self._ensure_lifetime_task_v1()

    def _ensure_lifetime_task_v1(self) -> None:
        with self._state_lock_v1:
            if self._complete_v1 or self._lifetime_task_v1 is not None:
                return
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            task = loop.create_task(self._release_when_cancelled_or_expired_v1())
            self._lifetime_task_v1 = task

    async def _release_when_cancelled_or_expired_v1(self) -> None:
        remaining = max(
            0.0,
            self.work_item_v1.fence.deadline_monotonic - time.monotonic(),
        )
        try:
            await self.work_item_v1.cancellation.wait_async(remaining)
        except asyncio.CancelledError:
            return
        self.release_once_v1()

    def attach_chunk_v1(self, chunk: DataChunk) -> None:
        with self._state_lock_v1:
            if chunk not in self._chunks_v1:
                self._chunks_v1.append(chunk)
        chunk._work_publication_v1 = self

    def mark_send_complete_v1(self) -> None:
        with self._state_lock_v1:
            self._send_complete_v1 = True
        self.release_if_settled_v1()

    def release_if_settled_v1(self) -> None:
        transport = self._transport_v1
        if transport is None:
            return
        outbound = {id(chunk) for chunk in transport._outbound_queue}
        sent = {id(chunk) for chunk in transport._sent_queue}
        with self._state_lock_v1:
            settled = self._send_complete_v1 and all(
                id(chunk) not in outbound and id(chunk) not in sent
                for chunk in self._chunks_v1
            )
        if settled:
            self.release_once_v1()

    def release_once_v1(self) -> bool:
        lifetime_task = None
        transport = None
        with self._state_lock_v1:
            if self._complete_v1:
                return False
            self._complete_v1 = True
            lifetime_task = self._lifetime_task_v1
            self._lifetime_task_v1 = None
            transport = self._transport_v1
        current_task = None
        try:
            current_task = asyncio.current_task()
        except RuntimeError:
            pass
        if (
            lifetime_task is not None
            and lifetime_task is not current_task
            and not lifetime_task.done()
        ):
            lifetime_task.cancel()
        if transport is not None:
            publications = getattr(
                transport,
                "_fenced_sctp_publications_v1",
                None,
            )
            if publications is not None:
                publications.pop(id(self), None)
        return self.work_item_v1.release_once_v1(self.work_runtime_v1)

    def __repr__(self) -> str:
        return "_SctpPublicationV1(<redacted>)"


_SCTP_PUBLICATION_SCOPE_V1: contextvars.ContextVar[_SctpPublicationV1 | None] = (
    contextvars.ContextVar(
        "rtc_sctp_publication_scope_v1",
        default=None,
    )
)


_ORIGINAL_NEXT_ENCODED_FRAME_V1 = RTCRtpSender._next_encoded_frame
_ORIGINAL_RETRANSMIT_V1 = RTCRtpSender._retransmit
_ORIGINAL_SEND_RTP_V1 = RTCDtlsTransport._send_rtp
_ORIGINAL_DATA_CHANNEL_SEND_V1 = RTCSctpTransport._data_channel_send
_ORIGINAL_SCTP_SEND_V1 = RTCSctpTransport._send
_ORIGINAL_SEND_SCTP_CHUNK_V1 = RTCSctpTransport._send_chunk
_ORIGINAL_RECEIVE_SACK_V1 = RTCSctpTransport._receive_sack_chunk
_RTP_PATCH_INSTALLED_V1 = False


def _claim_sender_publication_v1(
    sender: RTCRtpSender,
) -> _RtpPublicationV1 | None:
    track = getattr(sender, "_RTCRtpSender__track", None)
    claim = getattr(
        track,
        "claim_pending_rtp_publication_v1",
        None,
    )
    return claim() if callable(claim) else None


async def _next_encoded_frame_v1(
    sender: RTCRtpSender,
    codec,
):
    try:
        encoded_frame = await _ORIGINAL_NEXT_ENCODED_FRAME_V1(
            sender,
            codec,
        )
    except BaseException:
        publication = _claim_sender_publication_v1(sender)
        if publication is not None:
            publication.release_once_v1()
        raise
    publication = _claim_sender_publication_v1(sender)
    if publication is None:
        return encoded_frame
    if encoded_frame is None:
        publication.release_once_v1()
        return None
    publication.bind_sender_v1(sender)
    encoded_frame.payloads = _FencedRtpPayloadsV1(
        encoded_frame.payloads,
        publication,
    )
    return encoded_frame


async def _send_rtp_with_publication_v1(
    send_action: Callable[[], Awaitable[Any]],
) -> bool:
    scope = _RTP_PUBLICATION_SCOPE_V1.get()
    if scope is None:
        await send_action()
        return True
    publication, is_last_payload, _retain_history = scope

    async def send_and_commit() -> None:
        await send_action()
        if is_last_payload and publication.commit_v1 is not None:
            publication.commit_v1()

    try:
        allowed = (
            await publication.work_runtime_v1.perform_item_egress_async_if_live_v1(
                publication.work_item_v1,
                publication.consumer_capability_v1,
                send_and_commit,
            )
        )
    except BaseException:
        publication.release_once_v1()
        raise
    if not allowed:
        publication.release_once_v1()
    elif is_last_payload:
        publication.mark_initial_send_complete_v1()
    return allowed


def _rtp_sequence_number_v1(data: bytes) -> int | None:
    if len(data) < 4:
        return None
    return int.from_bytes(data[2:4], "big")


def _rtp_publication_for_sequence_v1(
    sender: RTCRtpSender,
    sequence_number: int,
) -> _RtpPublicationV1 | None:
    publications = getattr(
        sender,
        "_fenced_rtp_history_v1",
        {},
    )
    entry = publications.get(sequence_number % RTP_HISTORY_SIZE)
    if entry is None or entry[0] != sequence_number:
        return None
    return entry[1]


async def _retransmit_v1(
    sender: RTCRtpSender,
    sequence_number: int,
) -> None:
    publication = _rtp_publication_for_sequence_v1(
        sender,
        sequence_number,
    )
    if publication is None:
        if getattr(sender, "_fenced_rtp_sender_v1", False):
            return
        await _ORIGINAL_RETRANSMIT_V1(sender, sequence_number)
        return
    token = _RTP_PUBLICATION_SCOPE_V1.set((publication, False, False))
    try:
        await _ORIGINAL_RETRANSMIT_V1(sender, sequence_number)
    finally:
        _RTP_PUBLICATION_SCOPE_V1.reset(token)


def send_fenced_data_channel_v1(
    channel: DataChannel,
    payload: str | bytes,
    work_item_v1: WorkBoundItemV1,
    work_runtime_v1: SessionWorkRuntimeV1,
    consumer_capability_v1: Any,
) -> bool:
    """Publish once, retaining authority through reliable SCTP completion."""

    publication = _SctpPublicationV1(
        work_item_v1=work_item_v1,
        work_runtime_v1=work_runtime_v1,
        consumer_capability_v1=consumer_capability_v1,
    )

    def enqueue_message() -> None:
        token = _SCTP_PUBLICATION_SCOPE_V1.set(publication)
        try:
            channel.send(payload)
        finally:
            _SCTP_PUBLICATION_SCOPE_V1.reset(token)

    try:
        allowed = work_runtime_v1.perform_item_egress_if_live_v1(
            work_item_v1,
            consumer_capability_v1,
            enqueue_message,
        )
    except BaseException:
        publication.release_once_v1()
        raise
    if not allowed or not publication.adopted_v1:
        publication.release_once_v1()
    return allowed


def _data_channel_send_v1(
    transport: RTCSctpTransport,
    channel,
    data,
) -> None:
    publication = _SCTP_PUBLICATION_SCOPE_V1.get()
    _ORIGINAL_DATA_CHANNEL_SEND_V1(transport, channel, data)
    if publication is None:
        return
    queued_channel, _protocol, user_data = transport._data_channel_queue[-1]
    if queued_channel is not channel:
        publication.release_once_v1()
        return
    publication.adopt_v1(transport, user_data)


def _take_sctp_publication_v1(
    transport: RTCSctpTransport,
    user_data: bytes,
) -> _SctpPublicationV1 | None:
    pending = getattr(
        transport,
        "_fenced_sctp_pending_v1",
        None,
    )
    if not pending:
        return None
    publications = pending.get(id(user_data))
    if not publications:
        return None
    publication = publications.popleft()
    if not publications:
        pending.pop(id(user_data), None)
    return publication


async def _send_sctp_message_v1(
    transport: RTCSctpTransport,
    stream_id: int,
    pp_id: int,
    user_data: bytes,
    expiry: float | None = None,
    max_retransmits: int | None = None,
    ordered: bool = True,
) -> None:
    publication = _take_sctp_publication_v1(
        transport,
        user_data,
    )
    if publication is None:
        token = _SCTP_PUBLICATION_SCOPE_V1.set(None)
        try:
            await _ORIGINAL_SCTP_SEND_V1(
                transport,
                stream_id,
                pp_id,
                user_data,
                expiry=expiry,
                max_retransmits=max_retransmits,
                ordered=ordered,
            )
        finally:
            _SCTP_PUBLICATION_SCOPE_V1.reset(token)
        return
    if not publication.work_runtime_v1.item_egress_is_allowed_v1(
        publication.work_item_v1,
        publication.consumer_capability_v1,
    ):
        publication.release_once_v1()
        return

    if ordered:
        stream_seq = transport._outbound_stream_seq.get(stream_id, 0)
    else:
        stream_seq = 0
    fragments = math.ceil(len(user_data) / _aiortc_sctp.USERDATA_MAX_LENGTH)
    pos = 0
    for fragment in range(fragments):
        chunk = DataChunk()
        chunk.flags = 0
        if not ordered:
            chunk.flags = _aiortc_sctp.SCTP_DATA_UNORDERED
        if fragment == 0:
            chunk.flags |= _aiortc_sctp.SCTP_DATA_FIRST_FRAG
        if fragment == fragments - 1:
            chunk.flags |= _aiortc_sctp.SCTP_DATA_LAST_FRAG
        chunk.tsn = transport._local_tsn
        chunk.stream_id = stream_id
        chunk.stream_seq = stream_seq
        chunk.protocol = pp_id
        chunk.user_data = user_data[pos : pos + _aiortc_sctp.USERDATA_MAX_LENGTH]
        chunk._abandoned = False
        chunk._acked = False
        chunk._book_size = len(chunk.user_data)
        chunk._expiry = expiry
        chunk._max_retransmits = max_retransmits
        chunk._misses = 0
        chunk._retransmit = False
        chunk._sent_count = 0
        chunk._sent_time = None
        publication.attach_chunk_v1(chunk)

        pos += _aiortc_sctp.USERDATA_MAX_LENGTH
        transport._local_tsn = _aiortc_sctp.tsn_plus_one(transport._local_tsn)
        transport._outbound_queue.append(chunk)

    if ordered:
        transport._outbound_stream_seq[stream_id] = _aiortc_sctp.uint16_add(
            stream_seq, 1
        )
    token = _SCTP_PUBLICATION_SCOPE_V1.set(publication)
    try:
        await transport._transmit()
    finally:
        _SCTP_PUBLICATION_SCOPE_V1.reset(token)
        publication.mark_send_complete_v1()


async def _send_sctp_chunk_v1(
    transport: RTCSctpTransport,
    chunk,
) -> None:
    publication = getattr(
        chunk,
        "_work_publication_v1",
        None,
    )
    if publication is None:
        publication = _SCTP_PUBLICATION_SCOPE_V1.get()
        if publication is not None and isinstance(chunk, DataChunk):
            publication.attach_chunk_v1(chunk)
    if publication is None or not isinstance(chunk, DataChunk):
        await _ORIGINAL_SEND_SCTP_CHUNK_V1(transport, chunk)
        return
    allowed = await publication.work_runtime_v1.perform_item_egress_async_if_live_v1(
        publication.work_item_v1,
        publication.consumer_capability_v1,
        lambda: _ORIGINAL_SEND_SCTP_CHUNK_V1(
            transport,
            chunk,
        ),
    )
    if not allowed:
        chunk._abandoned = True
        chunk._retransmit = False
        publication.release_once_v1()


async def _receive_sack_v1(
    transport: RTCSctpTransport,
    chunk,
) -> None:
    await _ORIGINAL_RECEIVE_SACK_V1(transport, chunk)
    publications = tuple(
        getattr(
            transport,
            "_fenced_sctp_publications_v1",
            {},
        ).values()
    )
    for publication in publications:
        publication.release_if_settled_v1()


async def _send_rtp_v1(
    transport: RTCDtlsTransport,
    data: bytes,
) -> None:
    scope = _RTP_PUBLICATION_SCOPE_V1.get()
    if scope is not None and scope[2]:
        sequence_number = _rtp_sequence_number_v1(data)
        if sequence_number is not None:
            scope[0].retain_sequence_v1(sequence_number)
    await _send_rtp_with_publication_v1(lambda: _ORIGINAL_SEND_RTP_V1(transport, data))


def install_fenced_fastrtc_tracks_v1() -> None:
    """Install the process-local adapters before FastRTC creates peer tracks."""

    global _RTP_PATCH_INSTALLED_V1
    if _RTP_PATCH_INSTALLED_V1:
        return
    _fastrtc_tracks.player_worker_decode = fenced_player_worker_decode_v1
    _fastrtc_connection.AudioCallback = FencedAudioCallbackV1
    _fastrtc_connection.VideoStreamHandler_ = FencedVideoStreamHandlerV1
    RTCRtpSender._next_encoded_frame = _next_encoded_frame_v1
    RTCRtpSender._retransmit = _retransmit_v1
    RTCDtlsTransport._send_rtp = _send_rtp_v1
    RTCSctpTransport._data_channel_send = _data_channel_send_v1
    RTCSctpTransport._send = _send_sctp_message_v1
    RTCSctpTransport._send_chunk = _send_sctp_chunk_v1
    RTCSctpTransport._receive_sack_chunk = _receive_sack_v1
    _RTP_PATCH_INSTALLED_V1 = True

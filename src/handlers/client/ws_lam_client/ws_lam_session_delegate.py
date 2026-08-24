"""
LAM WebSocket Session Delegate

Inherits all ws_client protocol handling from WsInputSessionDelegate.

Supports two upstream modes (set by the handler after creation):

  - ``rtc``: Audio/video upstream goes through WebRTC; this delegate only
    handles the WebSocket downstream (motion data, text echo, signals) and
    minimal upstream commands (Heartbeat, Interrupt, EndSpeech).
  - ``ws``: Pure WebSocket mode — audio input, text input, and all output
    (motion data, audio, text, signals) travel over a single WS connection.

RTC-mode specifics:
  - VIDEO output queue must exist (even if unused) to prevent a tight loop
    in RtcStream.video_emit() that would starve the event loop.
  - Audio output is NOT sent over WS; playback goes through RTC.
  - Text output uses a dedicated queue to avoid competition with the
    RTC data-channel's process_chat_history task.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Literal, Optional, Tuple, Union

import numpy as np
from loguru import logger

from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from handlers.client.ws_client.ws_input_delegate import WsInputSessionDelegate

if TYPE_CHECKING:
    from handlers.client.ws_client.ws_input_delegate import ConnectionInfo


class WsLamClientSessionDelegate(WsInputSessionDelegate):

    def __init__(self, heartbeat_timeout: float = 30.0):
        super().__init__(heartbeat_timeout=heartbeat_timeout)

        self.upstream_mode: Literal["rtc", "ws"] = "rtc"

        # RTC-mode queues (cheap to create; conditionally used at runtime).
        # VIDEO queue: prevents hot-loop in RtcStream.video_emit().
        self.output_queues[EngineChannelType.VIDEO] = asyncio.Queue()
        # Dedicated text queue: avoids RTC data-channel stealing from TEXT queue.
        self.ws_text_queue: asyncio.Queue = asyncio.Queue()

    # ------------------------------------------------------------------
    # Override put_data to echo loopback text via WebSocket
    # ------------------------------------------------------------------

    def put_data(self, modality: EngineChannelType, data: Union[np.ndarray, str],
                 timestamp: Optional[Tuple[int, int]] = None,
                 samplerate: Optional[int] = None,
                 loopback: bool = False,
                 speech_id: Optional[str] = None):
        """
        RTC-mode override for TEXT loopback.

        In RTC mode, text typed by the user enters via the RTC data channel
        and is submitted to the engine with loopback=True.  The engine will
        NOT route HUMAN_TEXT back to this handler (same-source skip), so the
        WebSocket echo would be lost.

        For TEXT with loopback we:
          1. Submit to the engine (same as parent).
          2. Put the ChatData into ws_text_queue (for WebSocket echo)
             INSTEAD of output_queues[TEXT] (which process_chat_history reads).

        In WS mode, text comes via WS SendHumanText and is handled by the
        base class directly — no loopback override needed.
        """
        if self.upstream_mode == "rtc" and loopback and modality == EngineChannelType.TEXT:
            from chat_engine.data_models.chat_data.chat_data_model import ChatData
            from chat_engine.data_models.runtime_data.data_bundle import DataBundle

            if timestamp is None:
                timestamp = self.get_timestamp()
            if self.data_submitter is None:
                return

            definition = self.input_data_definitions.get(modality)
            chat_data_type = self.modality_mapping.get(modality)
            if chat_data_type is None or definition is None:
                return

            data_bundle = DataBundle(definition)
            data_bundle.set_main_data(data)

            chat_data = ChatData(
                source="client",
                type=chat_data_type,
                data=data_bundle,
                timestamp=timestamp,
            )
            if self.work_runtime_v1 is None:
                self.data_submitter.submit(
                    chat_data,
                    finish_stream=True,
                )
                self.ws_text_queue.put_nowait(chat_data)
                return
            submit_with_egress = getattr(
                self.data_submitter,
                "submit_ingress_with_egress_item_v1",
                None,
            )
            if not callable(submit_with_egress):
                return
            item = submit_with_egress(
                chat_data,
                chat_data,
                WorkOperationKindV1.WS_EGRESS,
                finish_stream=True,
            )
            if item is not None:
                if not self.work_runtime_v1.perform_if_live_v1(
                    item.registered_work,
                    WorkValidationBoundaryV1.BEFORE_EGRESS,
                    lambda: self.ws_text_queue.put_nowait(item),
                ):
                    item.release_once_v1(self.work_runtime_v1)
            return

        super().put_data(modality, data, timestamp, samplerate, loopback, speech_id)

    # ------------------------------------------------------------------
    # Override clear_data to preserve WebSocket connections
    # ------------------------------------------------------------------

    def drain_application_output_v1(self) -> None:
        super().drain_application_output_v1()
        while not self.ws_text_queue.empty():
            try:
                queued_item = self.ws_text_queue.get_nowait()
                if (
                    self.work_runtime_v1 is not None
                    and hasattr(queued_item, "release_once_v1")
                ):
                    queued_item.release_once_v1(
                        self.work_runtime_v1
                    )
            except Exception:
                break

    def clear_data(self):
        """
        In RTC mode, RtcStream.emit() calls clear_data() on first audio
        frame.  The parent implementation clears connection_infos, which
        destroys the active WebSocket connection.  Override to only clear
        queues/buffers while preserving WS connection state.

        In WS mode there is no RtcStream, so clear_data() is only called
        from destroy_context.  Delegating to the parent is safe.
        """
        if self.upstream_mode == "rtc":
            self.drain_application_output_v1()
            self.text_buffer.clear()
            self.binary_stream_assembler.clear()
            self._active_playback_stream_keys.clear()
            self._cancelled_stream_keys.clear()
        else:
            super().clear_data()

    # ------------------------------------------------------------------
    # Override primary-connection lifecycle
    # ------------------------------------------------------------------

    async def _serve_primary_connection(self, info: ConnectionInfo) -> bool:
        """
        LAM mode primary connection.

        Task set depends on ``upstream_mode``:
          - **rtc**: text via ``_lam_ws_text_output_task`` (dedicated queue),
            no ``_ws_audio_output_task`` (audio goes through RTC).
          - **ws**: standard ``_ws_text_output_task`` and
            ``_ws_audio_output_task`` (everything over WebSocket).

        Motion data, heartbeat, signals, and input are always present.
        """
        def reset_primary_state() -> None:
            self.quit.clear()
            self.motion_welcome_sent = False
            self.motion_welcome_payload = None
            self.binary_stream_assembler.clear()
            self.subscriptions = set(self.AVAILABLE_SUBSCRIPTIONS)
            self.audio_format = "PCM"
            self.audio_sample_rate = 16000
            self.audio_channels = 1
            self._opus_encoder = None
            self._opus_decoder = None

        if self.work_runtime_v1 is None:
            reset_primary_state()
        else:
            with self._ingress_work_scope_v1() as scope:
                if (
                    scope is None
                    or not self._perform_ingress_mutation_v1(
                        reset_primary_state
                    )
                ):
                    return True

        self.primary_tasks = [
            asyncio.create_task(self._ws_input_task(info)),
            asyncio.create_task(self._ws_motion_output_task()),
            asyncio.create_task(self._heartbeat_monitor_task(info)),
            asyncio.create_task(self._ws_signal_output_task()),
        ]

        if self.upstream_mode == "rtc":
            self.primary_tasks.append(
                asyncio.create_task(self._lam_ws_text_output_task())
            )
        else:
            self.primary_tasks.append(
                asyncio.create_task(self._ws_text_output_task())
            )
            self.primary_tasks.append(
                asyncio.create_task(self._ws_audio_output_task())
            )

        try:
            await asyncio.wait(
                self.primary_tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            self.quit.set()
            if self.work_runtime_v1 is not None:
                await self._close_all_connections()
            self.primary_tasks = await self._cancel_connection_tasks_v1(
                self.primary_tasks,
                "LAM_PRIMARY_TASK_DRAIN_TIMEOUT_V1",
            )
            if self.work_runtime_v1 is None:
                await self._close_all_connections()
            self.motion_welcome_sent = False
            self.motion_welcome_payload = None
            self.binary_stream_assembler.clear()
            if self.work_runtime_v1 is None:
                logger.info(
                    f"LAM primary connection closed, "
                    f"session={self.session_id}"
                )
            else:
                logger.info("LAM_PRIMARY_CONNECTION_CLOSED_V1")
        return True

    # ------------------------------------------------------------------
    # Text output — reads from the dedicated ws_text_queue
    # ------------------------------------------------------------------

    async def _lam_ws_text_output_task(self):
        """
        Send text echo over WebSocket.

        Same logic as the parent _ws_text_output_task, but reads from
        self.ws_text_queue so that the RTC data-channel task cannot
        steal items from the shared TEXT output queue.
        """
        logger.info(f"LAM text output task started for session {self.session_id}")

        while not self.quit.is_set():
            try:
                queued_item = await asyncio.wait_for(
                    self.ws_text_queue.get(),
                    timeout=0.1,
                )
            except asyncio.TimeoutError:
                continue

            if queued_item is None:
                continue
            chat_data, work_item = self._unwrap_output_item_v1(
                queued_item
            )
            try:
                if chat_data is None or chat_data.data is None:
                    continue
                with self._work_scope_v1(work_item):
                    await self._send_text_output_v1(
                        chat_data,
                        work_item,
                    )
            except Exception:
                logger.error(
                    "LAM_WS_TEXT_OUTPUT_FAILED"
                )
                break
            finally:
                if (
                    work_item is not None
                    and self.work_runtime_v1 is not None
                ):
                    work_item.release_once_v1(
                        self.work_runtime_v1
                    )

        logger.info(f"LAM text output task ended for session {self.session_id}")

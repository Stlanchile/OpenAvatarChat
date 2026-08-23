"""
LAM WebSocket Client Handler

Supports two upstream modes controlled by the ``upstream_mode`` config field:

  - ``rtc``  (default): Audio/video upstream via WebRTC, downstream motion
    data / text / signals via the ws_client WebSocket protocol.
  - ``ws``: Pure WebSocket mode — audio, text, motion data, and signals all
    travel over a single ``/ws/session/{session_id}`` connection.

Both modes share the same asset-download route and session lifecycle.
"""
from __future__ import annotations

import os
import re
from typing import Dict, Literal, Optional, cast

import gradio
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from loguru import logger
from pydantic import BaseModel, Field

import handlers.client.rtc_client.client_handler_rtc as _rtc_module
from chat_engine.common.client_handler_base import ClientSessionDelegate
from chat_engine.common.handler_base import (
    HandlerBaseInfo,
    HandlerDataInfo,
    HandlerDetail,
)
from chat_engine.contexts.handler_context import HandlerContext
from chat_engine.contexts.session_context import SessionContext
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import (
    ChatEngineConfigModel,
    HandlerBaseConfigModel,
)
from chat_engine.data_models.chat_signal import ChatSignal
from chat_engine.data_models.chat_signal_type import ChatSignalType
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.runtime_data.data_bundle import (
    DataBundleDefinition,
    DataBundleEntry,
    VariableSize,
)
from engine_utils.directory_info import DirectoryInfo
from handlers.client.ws_client.ws_session_endpoint import (
    register_ws_session_endpoint,
)
from service.frontend_service import register_frontend
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

from .ws_lam_session_delegate import WsLamClientSessionDelegate

# ============================================================================
# Config
# ============================================================================

class WsLamClientConfigModel(_rtc_module.ClientRtcConfigModel, BaseModel):
    """LAM handler config: RTC fields + asset path + WS heartbeat."""
    asset_path: Optional[str] = Field(default=None, description="LAM asset zip path")
    heartbeat_timeout: int = Field(default=30, description="WS heartbeat timeout (seconds)")
    upstream_mode: Literal["rtc", "ws"] = Field(
        default="rtc",
        description="'rtc': WebRTC audio/video + WS data; 'ws': pure WebSocket",
    )


# ============================================================================
# Context
# ============================================================================

class WsLamClientContext(_rtc_module.ClientRtcContext):
    def __init__(self, session_id: str):
        super().__init__(session_id)
        self.config: Optional[WsLamClientConfigModel] = None
        self.client_session_delegate: Optional[WsLamClientSessionDelegate] = None


# ============================================================================
# Handler
# ============================================================================

class WsLamClientHandler(_rtc_module.ClientHandlerRtc):
    """
    LAM Client Handler

    Two upstream modes (selected by ``upstream_mode`` config):

    **rtc** (default):
      - Upstream (audio/video): WebRTC via ClientHandlerRtc
      - Downstream (motion, text, signals): /ws/session via ws_client protocol

    **ws**:
      - Upstream (audio/text): /ws/session via ws_client protocol
      - Downstream (motion, audio, text, signals): same /ws/session connection

    Asset download: /download/lam_asset/{file_name}
    """

    asset_route: str = "/download/lam_asset"

    def __init__(self):
        super().__init__()
        self.asset_dir: Optional[str] = None
        self.asset_name: Optional[str] = None

    # ------------------------------------------------------------------
    # Handler info
    # ------------------------------------------------------------------

    def get_handler_info(self) -> HandlerBaseInfo:
        return HandlerBaseInfo(
            config_model=WsLamClientConfigModel,
            client_session_delegate_class=WsLamClientSessionDelegate,
        )

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self, engine_config: ChatEngineConfigModel,
             handler_config: Optional[HandlerBaseConfigModel] = None):
        self.engine_config = engine_config
        if handler_config is None or not isinstance(handler_config, WsLamClientConfigModel):
            handler_config = WsLamClientConfigModel()
        self.handler_config = handler_config

        if handler_config.upstream_mode == "rtc":
            self.prepare_rtc_definitions()
        else:
            self._prepare_ws_definitions()

        self._resolve_asset(handler_config)
        logger.info(f"WsLamClientHandler loaded (upstream_mode={handler_config.upstream_mode})")

    def _prepare_ws_definitions(self):
        """Prepare data definitions for pure WebSocket mode (no RTC)."""
        audio_def = DataBundleDefinition()
        audio_def.add_entry(DataBundleEntry.create_audio_entry("mic_audio", 1, 16000))
        audio_def.lockdown()
        self.output_bundle_definitions[EngineChannelType.AUDIO] = audio_def

        video_def = DataBundleDefinition()
        video_def.add_entry(DataBundleEntry.create_framed_entry(
            "camera_video", [VariableSize(), VariableSize(), VariableSize(), 3], 0, 30,
        ))
        video_def.lockdown()
        self.output_bundle_definitions[EngineChannelType.VIDEO] = video_def

        text_def = DataBundleDefinition()
        text_def.add_entry(DataBundleEntry.create_text_entry("human_text"))
        text_def.lockdown()
        self.output_bundle_definitions[EngineChannelType.TEXT] = text_def

    def _resolve_asset(self, handler_config: WsLamClientConfigModel):
        asset_path = handler_config.asset_path
        if not asset_path:
            raise ValueError("WsLamClient asset_path is required.")

        candidate_paths = []
        if os.path.isabs(asset_path):
            candidate_paths.append(asset_path)
        else:
            candidate_paths.append(os.path.abspath(asset_path))
            candidate_paths.append(os.path.join(self.handler_root, asset_path))
            candidate_paths.append(os.path.join(DirectoryInfo.get_project_dir(), asset_path))

        for path in candidate_paths:
            if os.path.isfile(path):
                self.asset_dir, self.asset_name = os.path.split(path)
                break

        if self.asset_dir is None or self.asset_name is None:
            raise ValueError(f"Asset file {asset_path} not found.")

    # ------------------------------------------------------------------
    # App setup: register WS endpoint + asset route + RTC
    # ------------------------------------------------------------------

    def on_setup_app(self, app: FastAPI, ui: gradio.blocks.Block,
                     parent_block: Optional[gradio.blocks.Block] = None):
        self._register_ws_session_endpoint(app)
        self._register_asset_route(app)

        avatar_config = {
            "avatar_type": "lam",
            "avatar_assets_path": f"{self.asset_route}/{self.asset_name}",
            "ws_session_route": "/ws/session",
        }

        if self.handler_config.upstream_mode == "rtc":
            self.setup_rtc_ui(
                ui=ui,
                parent_block=parent_block,
                fastapi=app,
                avatar_config=avatar_config,
            )
            logger.info("WsLamClientHandler: WS + RTC + asset routes registered")
        else:
            def init_config_provider():
                return {
                    "chat_mode": "ws",
                    "avatar_config": avatar_config,
                    "ws_session_route": "/ws/session",
                    "track_constraints": {
                        "audio": {
                            "sampleRate": 16000,
                            "channelCount": 1,
                            "autoGainControl": False,
                            "noiseSuppression": False,
                            "echoCancellation": True,
                        }
                    },
                }
            register_frontend(
                app=app, ui=ui, parent_block=parent_block,
                init_config=init_config_provider,
            )
            logger.info("WsLamClientHandler: WS + asset routes registered (pure WS mode)")

    def _register_ws_session_endpoint(self, app: FastAPI):
        register_ws_session_endpoint(
            app,
            self.handler_delegate,
            WsLamClientSessionDelegate,
        )

    def _register_asset_route(self, app: FastAPI):
        asset_route = self.asset_route

        @app.get(asset_route + "/{file_name}")
        async def get_asset(file_name: str):
            if (
                getattr(
                    app.state,
                    "certificate_capture_enabled_v1",
                    False,
                )
                and file_name != self.asset_name
            ):
                return JSONResponse(
                    status_code=404,
                    content={"message": "File not found"},
                )
            if not re.match(r'^[a-zA-Z0-9._-]+$', file_name):
                logger.error(f"Invalid file name: {file_name}")
                return JSONResponse(status_code=400, content={"message": "Invalid file name"})

            if self.asset_dir is None:
                logger.error("LAM asset directory not resolved.")
                return JSONResponse(status_code=500, content={"message": "Asset directory unavailable"})

            file_path = os.path.join(self.asset_dir, file_name)
            if not os.path.commonprefix(
                    [os.path.abspath(file_path), os.path.abspath(self.asset_dir)]
            ) == os.path.abspath(self.asset_dir):
                logger.error(f"Path traversal attempt: {file_name}")
                return JSONResponse(status_code=403, content={"message": "Access denied"})

            if not os.path.isfile(file_path):
                logger.error(f"Failed to get lam asset file: {file_name}")
                return JSONResponse(status_code=404, content={"message": "File not found"})

            logger.info(f"Return lam asset file: {file_name}")
            return FileResponse(file_path)

    # ------------------------------------------------------------------
    # Context lifecycle
    # ------------------------------------------------------------------

    def create_context(self, session_context: SessionContext,
                       handler_config: Optional[HandlerBaseConfigModel] = None) -> HandlerContext:
        if not isinstance(handler_config, WsLamClientConfigModel):
            handler_config = WsLamClientConfigModel()
        context = WsLamClientContext(session_context.session_info.session_id)
        context.config = handler_config
        return context

    def start_context(self, session_context: SessionContext, handler_context: HandlerContext):
        pass

    def on_setup_session_delegate(self, session_context: SessionContext,
                                  handler_context: HandlerContext,
                                  session_delegate: ClientSessionDelegate):
        # Parent sets clock, data_submitter, input_data_definitions, shared_states
        super().on_setup_session_delegate(session_context, handler_context, session_delegate)

        handler_context = cast(WsLamClientContext, handler_context)
        session_delegate = cast(WsLamClientSessionDelegate, session_delegate)

        session_delegate.session_id = session_context.session_info.session_id
        session_delegate.signal_emitter = handler_context.signal_emitter
        session_delegate.heartbeat_timeout = self.handler_config.heartbeat_timeout
        session_delegate.session_history = session_context.session_history
        session_delegate.stream_manager = handler_context.stream_manager
        session_delegate.upstream_mode = self.handler_config.upstream_mode

        logger.info(
            f"WsLam session delegate setup completed for session "
            f"{session_context.session_info.session_id} (upstream_mode={self.handler_config.upstream_mode})"
        )

    # ------------------------------------------------------------------
    # Handler detail: include AVATAR_MOTION_DATA input
    # ------------------------------------------------------------------

    def get_handler_detail(self, session_context: SessionContext,
                           context: HandlerContext) -> HandlerDetail:
        detail = self.create_handler_detail(session_context, context)
        detail.inputs[ChatDataType.AVATAR_MOTION_DATA] = HandlerDataInfo(
            type=ChatDataType.AVATAR_MOTION_DATA,
            input_priority=-1,
        )
        # Ensure priority for other client-facing data types
        for data_type in (ChatDataType.AVATAR_AUDIO, ChatDataType.AVATAR_TEXT, ChatDataType.HUMAN_TEXT):
            if data_type in detail.inputs:
                detail.inputs[data_type].input_priority = -1
        return detail

    # ------------------------------------------------------------------
    # Data routing: engine -> delegate output queues
    # ------------------------------------------------------------------

    def handle(self, context: HandlerContext, inputs: ChatData,
               output_definitions: Dict[ChatDataType, HandlerDataInfo]):
        context = cast(WsLamClientContext, context)
        delegate = context.client_session_delegate
        if delegate is None:
            return

        if inputs.type.channel_type == EngineChannelType.TEXT and delegate.upstream_mode == "rtc":
            # RTC mode: route text to dedicated ws_text_queue to avoid
            # competition with the RTC data-channel's process_chat_history.
            data_queue = delegate.ws_text_queue
            logger.debug(f"Routed {inputs.type} to ws_text_queue")
        else:
            data_queue = delegate.output_queues.get(inputs.type.channel_type)
        if data_queue is None:
            return
        runtime = context.work_runtime_v1
        if runtime is None:
            data_queue.put_nowait(inputs)
        else:
            try:
                item = runtime.make_child_item_v1(
                    inputs,
                    WorkOperationKindV1.WS_EGRESS,
                )
            except WorkAdmissionDeniedV1:
                return
            if not runtime.perform_if_live_v1(
                item.registered_work,
                WorkValidationBoundaryV1.BEFORE_EGRESS,
                lambda: data_queue.put_nowait(item),
            ):
                item.release_once_v1(runtime)

    # ------------------------------------------------------------------
    # Signal routing: engine -> delegate signal queue
    # ------------------------------------------------------------------

    def on_signal(self, context: HandlerContext, signal: ChatSignal):
        logger.info(f"Received signal: {signal.type} from {signal.source_type} on stream {signal.related_stream}")
        context = cast(WsLamClientContext, context)
        if context.client_session_delegate is None:
            return

        if signal.type == ChatSignalType.INTERRUPT:
            if context.client_session_delegate._opus_encoder is not None:
                runtime = context.work_runtime_v1
                if runtime is None:
                    context.client_session_delegate._opus_encoder.reset()
                elif not runtime.perform_current_if_live_v1(
                    WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                    context.client_session_delegate._opus_encoder.reset,
                ):
                    return
                logger.debug("Opus encoder reset due to interrupt signal from engine")

        runtime = context.work_runtime_v1
        if runtime is None:
            context.client_session_delegate.signal_to_client_queue.put_nowait(
                signal
            )
            return
        try:
            item = runtime.make_child_item_v1(
                signal,
                WorkOperationKindV1.WS_EGRESS,
            )
        except WorkAdmissionDeniedV1:
            return
        if not runtime.perform_if_live_v1(
            item.registered_work,
            WorkValidationBoundaryV1.BEFORE_EGRESS,
            lambda: context.client_session_delegate
            .signal_to_client_queue.put_nowait(item),
        ):
            item.release_once_v1(runtime)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def destroy_context(self, context: HandlerContext):
        context = cast(WsLamClientContext, context)
        if context.client_session_delegate is not None:
            context.client_session_delegate.quit.set()
            context.client_session_delegate.clear_data()
        logger.info(f"Context destroyed for session {context.session_id}")

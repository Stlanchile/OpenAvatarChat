"""
WebSocket Client Handler
基于 WebSocket 的会话端口数字人交互处理器
"""
from typing import Any, Dict, Optional, cast

import gradio
from fastapi import FastAPI
from loguru import logger
from pydantic import BaseModel, Field

from chat_engine.common.client_handler_base import (
    ClientHandlerBase,
    ClientSessionDelegate,
)
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
from chat_engine.data_models.chat_stream_config import ChatStreamConfig
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.runtime_data.data_bundle import (
    DataBundleDefinition,
    DataBundleEntry,
    VariableSize,
)
from service.frontend_service import register_frontend
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

from .ws_input_delegate import WsInputSessionDelegate
from .ws_session_endpoint import register_ws_session_endpoint

# ============================================================================
# 配置模型
# ============================================================================

class WsClientConfigModel(HandlerBaseConfigModel, BaseModel):
    """WebSocket Client 配置"""
    connection_ttl: int = Field(default=900, description="最长连接时间(秒)")
    heartbeat_timeout: int = Field(default=30, description="心跳超时时间(秒)")

# ============================================================================
# Handler Context
# ============================================================================

class WsClientContext(HandlerContext):
    """WebSocket Client Context"""
    
    def __init__(self, session_id: str):
        super().__init__(session_id)
        self.config: Optional[WsClientConfigModel] = None
        self.client_session_delegate: Optional[WsInputSessionDelegate] = None

# ============================================================================
# WebSocket Client Handler
# ============================================================================

class WsClientHandler(ClientHandlerBase):
    """
    WebSocket Client Handler
    
    提供单一 WebSocket 会话端口:
    - /ws/session/{session_id}: 客户端负责输入上传与 Motion Data 下行消费
    """
    
    def __init__(self):
        super().__init__()
        self.engine_config: Optional[ChatEngineConfigModel] = None
        self.handler_config: Optional[WsClientConfigModel] = None
        
        # 数据定义
        self.input_bundle_definitions: Dict[EngineChannelType, DataBundleDefinition] = {}
        self.output_bundle_definitions: Dict[EngineChannelType, DataBundleDefinition] = {}
    
    def get_handler_info(self) -> HandlerBaseInfo:
        """获取 Handler 信息"""
        return HandlerBaseInfo(
            config_model=WsClientConfigModel,
            client_session_delegate_class=WsInputSessionDelegate,
        )
    
    def prepare_data_definitions(self):
        """准备数据定义"""
        # 输入定义 (客户端上传)
        # 音频定义
        audio_input_definition = DataBundleDefinition()
        audio_input_definition.add_entry(DataBundleEntry.create_audio_entry(
            "mic_audio",
            1,  # mono
            16000,  # 16kHz
        ))
        audio_input_definition.lockdown()
        self.input_bundle_definitions[EngineChannelType.AUDIO] = audio_input_definition
        
        # 视频定义
        video_input_definition = DataBundleDefinition()
        video_input_definition.add_entry(DataBundleEntry.create_framed_entry(
            "camera_video",
            [VariableSize(), VariableSize(), VariableSize(), 3],  # [H, W, C, 3]
            0,  # time_axis
            30  # fps
        ))
        video_input_definition.lockdown()
        self.input_bundle_definitions[EngineChannelType.VIDEO] = video_input_definition
        
        # 文本定义
        text_input_definition = DataBundleDefinition()
        text_input_definition.add_entry(DataBundleEntry.create_text_entry(
            "human_text",
        ))
        text_input_definition.lockdown()
        self.input_bundle_definitions[EngineChannelType.TEXT] = text_input_definition
        
        # 输出定义 (引擎输出给客户端)
        # 这些定义与输入定义相同,因为客户端可能需要回显
        self.output_bundle_definitions = self.input_bundle_definitions.copy()
        
        logger.info("Data definitions prepared")
    
    def load(self, engine_config: ChatEngineConfigModel, handler_config: Optional[HandlerBaseConfigModel] = None):
        """加载配置"""
        self.engine_config = engine_config
        
        if handler_config is None or not isinstance(handler_config, WsClientConfigModel):
            handler_config = WsClientConfigModel()
        
        self.handler_config = handler_config
        
        # 准备数据定义
        self.prepare_data_definitions()
        
        logger.info(f"WsClientHandler loaded with config: {self.handler_config}")
    def on_setup_app(self, app: FastAPI, ui: gradio.blocks.Block, parent_block: Optional[gradio.blocks.Block] = None):
        """设置 FastAPI 路由"""

        register_ws_session_endpoint(
            app,
            self.handler_delegate,
            WsInputSessionDelegate,
        )
        
        self.register_additional_routes(app)

        def init_config_provider():
            return self.build_frontend_init_config()

        register_frontend(
            app=app,
            ui=ui,
            parent_block=parent_block,
            init_config=init_config_provider,
        )
        logger.info("WebSocket route registered: /ws/session/{session_id}")

    def register_additional_routes(self, app: FastAPI):
        """Hook for subclasses to register additional FastAPI routes."""
        return

    def get_additional_init_config(self) -> Dict[str, Any]:
        """Hook for subclasses to extend init config payload."""
        return {}

    def build_frontend_init_config(self) -> Dict[str, Any]:
        base_config: Dict[str, Any] = {
            "chat_mode": "ws",
            "ws_session_route": "/ws/session",
            "track_constraints": {
                "audio": {
                    "sampleRate": 16000,
                    "channelCount": 1,
                    "autoGainControl": False,
                    "noiseSuppression": False,
                    "echoCancellation": True,
                }
            }
        }
        additional = self.get_additional_init_config()
        if additional:
            base_config.update(additional)
        return base_config
    
    
    def create_context(self, session_context: SessionContext,
                       handler_config: Optional[HandlerBaseConfigModel] = None) -> HandlerContext:
        """创建 Handler Context"""
        if not isinstance(handler_config, WsClientConfigModel):
            handler_config = WsClientConfigModel()
        
        context = WsClientContext(session_context.session_info.session_id)
        context.config = handler_config
        return context
    
    def start_context(self, session_context: SessionContext, handler_context: HandlerContext):
        """启动 Context"""
        pass
    
    def on_setup_session_delegate(self, session_context: SessionContext, handler_context: HandlerContext,
                                  session_delegate: ClientSessionDelegate):
        """设置会话委托"""
        handler_context = cast(WsClientContext, handler_context)
        session_delegate = cast(WsInputSessionDelegate, session_delegate)
        
        # 设置会话委托的属性
        session_delegate.session_id = session_context.session_info.session_id
        session_delegate.clock = session_context.get_clock()
        session_delegate.data_submitter = handler_context.data_submitter
        session_delegate.signal_emitter = handler_context.signal_emitter
        session_delegate.input_data_definitions = self.input_bundle_definitions
        session_delegate.shared_states = session_context.shared_states
        session_delegate.heartbeat_timeout = self.handler_config.heartbeat_timeout
        session_delegate.session_history = session_context.session_history
        session_delegate.stream_manager = handler_context.stream_manager
        session_delegate.work_runtime_v1 = (
            handler_context.work_runtime_v1
        )
        session_delegate.work_consumer_capability_v1 = (
            handler_context.work_consumer_capability_v1
        )
        
        # 保存引用
        handler_context.client_session_delegate = session_delegate
        
        logger.info(f"Session delegate setup completed for session {session_context.session_info.session_id}")
    
    def create_handler_detail(self, _session_context, _handler_context):
        """创建 Handler Detail"""
        # 输入: 引擎输出给客户端的数据
        inputs = {
            ChatDataType.AVATAR_AUDIO: HandlerDataInfo(
                type=ChatDataType.AVATAR_AUDIO,
                input_priority=-1  # 设置更高优先级，确保在 ONCE 模式的 handler 之前接收数据
            ),
            ChatDataType.AVATAR_TEXT: HandlerDataInfo(
                type=ChatDataType.AVATAR_TEXT,
                input_priority=-1  # 确保客户端能收到所有文本数据
            ),
            ChatDataType.AVATAR_MOTION_DATA: HandlerDataInfo(
                type=ChatDataType.AVATAR_MOTION_DATA,
                input_priority=-1  # 确保客户端能收到所有动作数据
            ),
            ChatDataType.HUMAN_TEXT: HandlerDataInfo(
                type=ChatDataType.HUMAN_TEXT,
                input_priority=-1  # 确保客户端能收到ASR识别的文本
            ),
        }
        
        # 输出: 客户端上传给引擎的数据
        _no_link = ChatStreamConfig(cancelable=False, auto_link_input=False)
        outputs = {
            ChatDataType.MIC_AUDIO: HandlerDataInfo(
                type=ChatDataType.MIC_AUDIO,
                definition=self.output_bundle_definitions[EngineChannelType.AUDIO],
                output_stream_config=_no_link,
            ),
            ChatDataType.CAMERA_VIDEO: HandlerDataInfo(
                type=ChatDataType.CAMERA_VIDEO,
                definition=self.output_bundle_definitions[EngineChannelType.VIDEO],
                output_stream_config=_no_link,
            ),
            ChatDataType.HUMAN_TEXT: HandlerDataInfo(
                type=ChatDataType.HUMAN_TEXT,
                definition=self.output_bundle_definitions[EngineChannelType.TEXT],
                output_stream_config=_no_link,
            ),
        }
        

        return HandlerDetail(
            inputs=inputs,
            outputs=outputs,
        )
    
    def get_handler_detail(self, session_context: SessionContext, context: HandlerContext) -> HandlerDetail:
        """获取 Handler Detail"""
        return self.create_handler_detail(session_context, context)
    
    def handle(self, context: HandlerContext, inputs: ChatData,
               output_definitions: Dict[ChatDataType, HandlerDataInfo]):
        """
        处理引擎输出的数据
        将数据路由到对应的输出队列,供 WebSocket 发送
        """
        context = cast(WsClientContext, context)
        
        if context.client_session_delegate is None:
            return
        
        # 根据数据类型路由到对应的队列
        channel_type = inputs.type.channel_type
        data_queue = context.client_session_delegate.output_queues.get(channel_type)
        
        if data_queue is not None:
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
            logger.debug(f"Routed {inputs.type} to {channel_type} queue")
    
    def on_signal(self, context: HandlerContext, signal: ChatSignal):
        """处理信号"""
        logger.info(f"Received signal: {signal.type} from {signal.source_type} on stream {signal.related_stream}")
        context = cast(WsClientContext, context)
        if context.client_session_delegate is None:
            return
        
        # 处理打断信号：重置 Opus 编码器以清空残留缓冲区
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

    def destroy_context(self, context: HandlerContext):
        """销毁 Context"""
        context = cast(WsClientContext, context)
        
        if context.client_session_delegate is not None:
            context.client_session_delegate.quit.set()
            context.client_session_delegate.clear_data()
        
        logger.info(f"Context destroyed for session {context.session_id}")

import os
import re
import time
from dataclasses import dataclass
from typing import Dict, Optional, cast
import numpy as np
from loguru import logger
from pydantic import BaseModel, Field
from abc import ABC
from chat_engine.contexts.handler_context import HandlerContext
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel, HandlerBaseConfigModel
from chat_engine.common.handler_base import HandlerBase, HandlerBaseInfo, HandlerDataInfo, HandlerDetail
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.contexts.session_context import SessionContext
from chat_engine.data_models.runtime_data.data_bundle import DataBundle, DataBundleDefinition, DataBundleEntry
from engine_utils.directory_info import DirectoryInfo
from dashscope.audio.tts_v2 import SpeechSynthesizer, ResultCallback, AudioFormat
import dashscope

from chat_engine.data_models.chat_signal_type import ChatSignalType
from chat_engine.data_models.chat_signal import ChatSignal, SignalFilterRule
from chat_engine.data_models.chat_stream import StreamKey, ChatStreamIdentity
from chat_engine.data_models.chat_stream_config import ChatStreamConfig
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)


class TTSConfig(HandlerBaseConfigModel, BaseModel):
    ref_audio_path: str = Field(default=None)
    ref_audio_text: str = Field(default=None)
    voice: str = Field(default=None)
    sample_rate: int = Field(default=24000)
    api_key: str = Field(default=os.getenv("DASHSCOPE_API_KEY"))
    model_name: str = Field(default="cosyvoice-1")


@dataclass
class BailianTTSSession:
    """Per-stream session state, isolates synthesizer for each input stream."""
    input_stream_id: ChatStreamIdentity
    output_stream_key: Optional[StreamKey] = None
    synthesizer: Optional[SpeechSynthesizer] = None
    cancelled: bool = False
    work_item_v1: Optional[WorkBoundItemV1] = None
    work_runtime_v1: Optional[SessionWorkRuntimeV1] = None

    def reset(self):
        self.cancelled = True
        had_active_synthesizer = self.synthesizer is not None
        if self.synthesizer is not None:
            try:
                self.synthesizer.streaming_cancel()
            except Exception:
                pass
            self.synthesizer = None
        if (
            not had_active_synthesizer
            and self.work_item_v1 is not None
            and self.work_runtime_v1 is not None
        ):
            self.work_item_v1.release_once_v1(self.work_runtime_v1)


class TTSContext(HandlerContext):
    def __init__(self, session_id: str):
        super().__init__(session_id)
        self.config = None
        self.api_links: Dict[StreamKey, BailianTTSSession] = {}
        self.dump_audio = False
        self.audio_dump_file = None
        self._secure_generation_v1 = None

    @classmethod
    def _create_session(cls, input_stream: ChatStreamIdentity) -> BailianTTSSession:
        return BailianTTSSession(input_stream_id=input_stream)

    def handle_text_stream(self, data: ChatData, handler: 'HandlerTTS'):
        if self.work_runtime_v1 is not None:
            self._handle_text_stream_fenced_v1(data, handler)
            return
        input_stream = data.stream_id
        input_stream_key = input_stream.key

        session = self.api_links.get(input_stream_key)
        if session is None:
            # 新的输入流到达，取消所有旧 session（同一时间只有一个合成器活跃）
            for old_key, old_session in list(self.api_links.items()):
                logger.info(f"TTS: Cancelling previous session for stream {old_key}")
                old_session.reset()
            self.api_links.clear()

            session = self._create_session(input_stream)
            self.api_links[input_stream_key] = session

            # 为新的输入流创建输出流，建立 1:1 的显式关联
            streamer = self.data_submitter.get_streamer(ChatDataType.AVATAR_AUDIO)
            output_stream_id = streamer.new_stream(
                sources=[session.input_stream_id],
                name="bailian_tts",
                config=ChatStreamConfig(cancelable=True)
            )
            session.output_stream_key = output_stream_id.key

        text = data.data.get_main_data()
        if text is not None:
            text = re.sub(r"<\|.*?\|>", "", text)

        text_end = data.is_last_data

        try:
            if not text_end:
                if session.synthesizer is None:
                    streamer = self.data_submitter.get_streamer(ChatDataType.AVATAR_AUDIO)
                    callback = CosyvoiceCallBack(
                        context=self,
                        output_definition=streamer.data_definition,
                        session=session)
                    session.synthesizer = SpeechSynthesizer(
                        model=handler.model_name, voice=handler.voice,
                        callback=callback, format=AudioFormat.PCM_24000HZ_MONO_16BIT)
                logger.info(f'streaming_call {text}')
                session.synthesizer.streaming_call(text)
            else:
                logger.info(f'streaming_call last {text}')
                if session.synthesizer is not None:
                    session.synthesizer.streaming_call(text)
                    session.synthesizer.streaming_complete()
                session.synthesizer = None
                self.api_links.pop(input_stream_key, None)
        except Exception as e:
            logger.error(e)
            session.reset()
            self.api_links.pop(input_stream_key, None)

    def _handle_text_stream_fenced_v1(
        self,
        data: ChatData,
        handler: "HandlerTTS",
    ) -> None:
        runtime = self.work_runtime_v1
        parent = self.current_work_v1()
        input_stream = data.stream_id
        if (
            runtime is None
            or parent is None
            or input_stream is None
            or input_stream.key is None
        ):
            return
        input_stream_key = input_stream.key
        generation = parent.fence.session_epoch.generation
        old_sessions: list[BailianTTSSession] = []

        if self._secure_generation_v1 != generation:
            def replace_generation() -> None:
                old_sessions.extend(self.api_links.values())
                self.api_links.clear()
                self._secure_generation_v1 = generation

            if not runtime.perform_if_live_v1(
                parent,
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                replace_generation,
            ):
                return
            for old_session in old_sessions:
                old_session.reset()

        session = self.api_links.get(input_stream_key)
        if (
            session is not None
            and (
                session.work_item_v1 is None
                or not runtime.validate_work_v1(
                    session.work_item_v1.registered_work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                )
            )
        ):
            session.reset()
            runtime.perform_if_live_v1(
                parent,
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                lambda: self.api_links.pop(input_stream_key, None),
            )
            session = None

        if session is None:
            try:
                work = runtime.register_child_work_v1(
                    parent,
                    WorkOperationKindV1.TTS_SYNTHESIS,
                )
            except WorkAdmissionDeniedV1:
                return
            work_item = WorkBoundItemV1(
                payload=None,
                registered_work=work,
                envelope_ref=self.current_work_envelope_v1(),
            )
            session = self._create_session(input_stream)
            session.work_item_v1 = work_item
            session.work_runtime_v1 = runtime
            try:
                with self.activate_work_v1(
                    work,
                    work_item.envelope_ref,
                ):
                    streamer = self.data_submitter.get_streamer(
                        ChatDataType.AVATAR_AUDIO
                    )
                    if streamer is None:
                        work_item.release_once_v1(runtime)
                        return
                    output_stream_id = streamer.new_stream(
                        sources=[session.input_stream_id],
                        name="bailian_tts",
                        config=ChatStreamConfig(cancelable=True),
                    )
                    if output_stream_id is None:
                        work_item.release_once_v1(runtime)
                        return
                    session.output_stream_key = output_stream_id.key
                    if not runtime.perform_if_live_v1(
                        work,
                        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                        lambda: self.api_links.__setitem__(
                            input_stream_key,
                            session,
                        ),
                    ):
                        work_item.release_once_v1(runtime)
                        return
            except Exception:
                work_item.release_once_v1(runtime)
                raise

        work_item = session.work_item_v1
        if work_item is None:
            return
        work = work_item.registered_work
        text = data.data.get_main_data()
        if text is not None:
            text = re.sub(r"<\|.*?\|>", "", text)
        text_end = data.is_last_data

        try:
            with self.activate_work_v1(work, work_item.envelope_ref):
                if not runtime.validate_work_v1(
                    work,
                    WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
                ):
                    return
                if not text_end:
                    if session.synthesizer is None:
                        streamer = self.data_submitter.get_streamer(
                            ChatDataType.AVATAR_AUDIO
                        )
                        if streamer is None:
                            return
                        callback = CosyvoiceCallBack(
                            context=self,
                            output_definition=streamer.data_definition,
                            session=session,
                        )
                        synthesizer = SpeechSynthesizer(
                            model=handler.model_name,
                            voice=handler.voice,
                            callback=callback,
                            format=(
                                AudioFormat.PCM_24000HZ_MONO_16BIT
                            ),
                        )
                        if not runtime.perform_if_live_v1(
                            work,
                            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                            lambda: setattr(
                                session,
                                "synthesizer",
                                synthesizer,
                            ),
                        ):
                            try:
                                synthesizer.streaming_cancel()
                            except Exception:
                                pass
                            return
                    session.synthesizer.streaming_call(text)
                else:
                    if session.synthesizer is not None:
                        session.synthesizer.streaming_call(text)
                        session.synthesizer.streaming_complete()
                    else:
                        runtime.perform_if_live_v1(
                            work,
                            WorkValidationBoundaryV1.BEFORE_COMPLETION,
                            lambda: self.api_links.pop(
                                input_stream_key,
                                None,
                            ),
                        )
                        work_item.release_once_v1(runtime)
                if not runtime.validate_work_v1(
                    work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                ):
                    return
        except Exception:
            logger.error("BAILIAN_TTS_SYNTHESIS_FAILED")
            runtime.perform_if_live_v1(
                work,
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                lambda: (
                    self.api_links.pop(input_stream_key, None)
                    if self.api_links.get(input_stream_key) is session
                    else None
                ),
            )
            session.reset()


class HandlerTTS(HandlerBase, ABC):
    def __init__(self):
        super().__init__()

        self.ref_audio_path = None
        self.ref_audio_text = None
        self.voice = None
        self.ref_audio_buffer = None
        self.sample_rate = None
        self.model_name = None
        self.api_key = None

    def get_handler_info(self) -> HandlerBaseInfo:
        return HandlerBaseInfo(
            config_model=TTSConfig,
        )

    def get_handler_detail(self, session_context: SessionContext,
                           context: HandlerContext) -> HandlerDetail:
        definition = DataBundleDefinition()
        definition.add_entry(DataBundleEntry.create_audio_entry("avatar_audio", 1, self.sample_rate))
        inputs = [
            HandlerDataInfo(type=ChatDataType.AVATAR_TEXT),
        ]
        outputs = [
            HandlerDataInfo(
                type=ChatDataType.AVATAR_AUDIO,
                definition=definition,
            )
        ]
        return HandlerDetail(
            inputs=inputs,
            outputs=outputs,
            signal_filters=[
                SignalFilterRule(ChatSignalType.STREAM_CANCEL, None, None)
            ]
        )

    def load(self, engine_config: ChatEngineConfigModel, handler_config: Optional[BaseModel] = None):
        config = cast(TTSConfig, handler_config)
        self.voice = config.voice
        self.sample_rate = config.sample_rate
        self.ref_audio_path = config.ref_audio_path
        self.ref_audio_text = config.ref_audio_text
        self.model_name = config.model_name
        if 'DASHSCOPE_API_KEY' in os.environ:
            # load API-key from environment variable DASHSCOPE_API_KEY
            dashscope.api_key = os.environ['DASHSCOPE_API_KEY']
        else:
            dashscope.api_key = config.api_key  # set API-key manually

    def create_context(self, session_context, handler_config=None):
        if not isinstance(handler_config, TTSConfig):
            handler_config = TTSConfig()
        context = TTSContext(session_context.session_info.session_id)
        if context.dump_audio:
            dump_file_path = os.path.join(DirectoryInfo.get_project_dir(), 'temp',
                                          f"dump_avatar_audio_{context.session_id}_{time.localtime().tm_hour}_{time.localtime().tm_min}.pcm")
            context.audio_dump_file = open(dump_file_path, "wb")
        return context

    def start_context(self, session_context, context: HandlerContext):
        context = cast(TTSContext, context)

    def filter_text(self, text):
        pattern = r"[^a-zA-Z0-9\u4e00-\u9fff,.\~!?，。！？ ]"  # 匹配不在范围内的字符
        filtered_text = re.sub(pattern, "", text)
        return filtered_text

    def handle(self, context: HandlerContext, inputs: ChatData,
               output_definitions: Dict[ChatDataType, HandlerDataInfo]):
        context = cast(TTSContext, context)
        if inputs.type == ChatDataType.AVATAR_TEXT:
            context.handle_text_stream(inputs, self)

    def on_signal(self, context: HandlerContext, signal: ChatSignal):
        """处理 STREAM_CANCEL 信号，终止被取消的 stream 的处理"""
        context = cast(TTSContext, context)
        if signal.type == ChatSignalType.STREAM_CANCEL and signal.related_stream:
            stream_key = signal.related_stream.key
            if stream_key is None:
                return
            if context.work_runtime_v1 is not None:
                runtime = context.work_runtime_v1
                work = context.current_work_v1()
                removed: list[BailianTTSSession] = []

                def remove_session() -> None:
                    session = context.api_links.pop(
                        stream_key,
                        None,
                    )
                    if session is not None:
                        removed.append(session)
                        return
                    for key, candidate in tuple(
                        context.api_links.items()
                    ):
                        if candidate.output_stream_key == stream_key:
                            context.api_links.pop(key, None)
                            removed.append(candidate)
                            return

                if work is not None:
                    runtime.perform_if_live_v1(
                        work,
                        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                        remove_session,
                    )
                for session in removed:
                    session.reset()
                    logger.info("TTS_SESSION_CANCELLED")
                return
            # 检查是否为我们的输入流被取消
            session = context.api_links.pop(stream_key, None)
            if session:
                logger.info(f"TTS: Cancelling session for input stream {stream_key}")
                session.reset()
                return
            # 检查是否为我们的输出流被取消（例如下游发起的打断）
            for key, session in list(context.api_links.items()):
                if session.output_stream_key == stream_key:
                    logger.info(f"TTS: Cancelling session for output stream {stream_key}")
                    session.reset()
                    context.api_links.pop(key, None)
                    return

    def quiesce_normal_work_v1(
        self,
        context: HandlerContext,
    ) -> None:
        context = cast(TTSContext, context)
        for session in tuple(context.api_links.values()):
            try:
                session.reset()
            except Exception:
                logger.warning("BAILIAN_TTS_CANCEL_FAILED")

    def clear_normal_semantic_state_v1(
        self,
        context: HandlerContext,
        generation: int,
    ) -> None:
        context = cast(TTSContext, context)
        context.api_links.clear()
        context._secure_generation_v1 = generation

    def drain_registered_work_v1(
        self,
        context: HandlerContext,
    ) -> None:
        self.quiesce_normal_work_v1(context)

    def destroy_context(self, context: HandlerContext):
        context = cast(TTSContext, context)
        logger.info('destroy context')
        self.drain_registered_work_v1(context)
        context.api_links.clear()
        if context.audio_dump_file is not None:
            try:
                context.audio_dump_file.close()
            except Exception:
                pass


class CosyvoiceCallBack(ResultCallback):
    def __init__(self, context: TTSContext, output_definition,
                 session: BailianTTSSession):
        super().__init__()
        self.context = context
        self.output_definition = output_definition
        self.session = session
        self.temp_bytes = b''
        self._finished = False

    @property
    def is_cancelled(self) -> bool:
        return self.session.cancelled

    @property
    def _work_item_v1(self) -> WorkBoundItemV1 | None:
        return self.session.work_item_v1

    @property
    def _work_runtime_v1(self) -> SessionWorkRuntimeV1 | None:
        return self.session.work_runtime_v1

    def _is_live_v1(
        self,
        boundary: WorkValidationBoundaryV1,
    ) -> bool:
        runtime = self._work_runtime_v1
        item = self._work_item_v1
        return (
            runtime is None
            or (
                item is not None
                and runtime.validate_work_v1(
                    item.registered_work,
                    boundary,
                )
            )
        )

    def _release_v1(self) -> None:
        runtime = self._work_runtime_v1
        item = self._work_item_v1
        if runtime is not None and item is not None:
            item.release_once_v1(runtime)

    def _finish_session_state_v1(self) -> None:
        runtime = self._work_runtime_v1
        item = self._work_item_v1

        def finish_state() -> None:
            self.session.synthesizer = None
            stream_key = self.session.input_stream_id.key
            if (
                stream_key is not None
                and self.context.api_links.get(stream_key)
                is self.session
            ):
                self.context.api_links.pop(stream_key, None)

        if runtime is None:
            finish_state()
        elif item is not None:
            runtime.perform_if_live_v1(
                item.registered_work,
                WorkValidationBoundaryV1.BEFORE_COMPLETION,
                finish_state,
            )

    def on_open(self) -> None:
        logger.info('TTS: WebSocket connected')

    def on_event(self, message) -> None:
        pass

    def _submit_end_frame(self) -> None:
        if self._finished:
            return
        self._finished = True
        # 如果 session 已被取消，不要提交结束帧（避免 finish 掉新的 stream）
        if self.is_cancelled:
            return
        output = DataBundle(self.output_definition)
        output.set_main_data(np.zeros(shape=(1, 240), dtype=np.float32))
        runtime = self._work_runtime_v1
        item = self._work_item_v1
        if runtime is None:
            self.context.submit_data(output, finish_stream=True)
        elif item is not None:
            with self.context.activate_work_v1(
                item.registered_work,
                item.envelope_ref,
            ):
                runtime.perform_if_live_v1(
                    item.registered_work,
                    WorkValidationBoundaryV1.BEFORE_COMPLETION,
                    lambda: self.context.submit_data(
                        output,
                        finish_stream=True,
                    ),
                )

    def on_data(self, data: bytes) -> None:
        if self.is_cancelled:
            return
        runtime = self._work_runtime_v1
        item = self._work_item_v1
        if not self._is_live_v1(
            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK
        ):
            self.temp_bytes = b""
            if runtime is not None and item is not None:
                runtime.log_late_drop_v1(
                    item.registered_work,
                    "BAILIAN_TTS_DATA",
                )
            return
        emit_bytes: list[bytes] = []

        def buffer_audio() -> None:
            self.temp_bytes += data
            if len(self.temp_bytes) > 24000:
                emit_bytes.append(self.temp_bytes)
                self.temp_bytes = b""

        if runtime is None:
            buffer_audio()
        elif item is None or not runtime.perform_if_live_v1(
            item.registered_work,
            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
            buffer_audio,
        ):
            return
        if emit_bytes:
            output_audio = np.array(np.frombuffer(emit_bytes[0], dtype=np.int16)).astype(
                np.float32
            ) / 32767
            output_audio = output_audio[np.newaxis, ...]
            output = DataBundle(self.output_definition)
            output.set_main_data(output_audio)
            if runtime is None:
                self.context.submit_data(output)
            elif item is not None:
                with self.context.activate_work_v1(
                    item.registered_work,
                    item.envelope_ref,
                ):
                    runtime.perform_if_live_v1(
                        item.registered_work,
                        WorkValidationBoundaryV1.BEFORE_EGRESS,
                        lambda: self.context.submit_data(output),
                    )

    def on_complete(self) -> None:
        try:
            if self.is_cancelled or not self._is_live_v1(
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK
            ):
                self.temp_bytes = b""
                return
            runtime = self._work_runtime_v1
            item = self._work_item_v1
            remaining: list[bytes] = []

            def take_remaining() -> None:
                if self.temp_bytes:
                    remaining.append(self.temp_bytes)
                    self.temp_bytes = b""

            if runtime is None:
                take_remaining()
            elif item is not None:
                runtime.perform_if_live_v1(
                    item.registered_work,
                    WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                    take_remaining,
                )
            if remaining:
                output_audio = np.array(
                    np.frombuffer(remaining[0], dtype=np.int16)
                ).astype(np.float32) / 32767
                output = DataBundle(self.output_definition)
                output.set_main_data(output_audio[np.newaxis, ...])
                if runtime is None:
                    self.context.submit_data(output)
                elif item is not None:
                    with self.context.activate_work_v1(
                        item.registered_work,
                        item.envelope_ref,
                    ):
                        runtime.perform_if_live_v1(
                            item.registered_work,
                            WorkValidationBoundaryV1.BEFORE_EGRESS,
                            lambda: self.context.submit_data(output),
                        )
            self._finish_session_state_v1()
            self._submit_end_frame()
            logger.info("TTS_SYNTHESIS_COMPLETE")
        finally:
            self._release_v1()

    def on_error(self, message) -> None:
        del message
        try:
            if self.is_cancelled:
                return
            if not self._is_live_v1(
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK
            ):
                return
            logger.error("BAILIAN_TTS_SERVICE_ERROR")
            self._finish_session_state_v1()
            self._submit_end_frame()
        finally:
            self._release_v1()

    def on_close(self) -> None:
        if self.is_cancelled:
            self.temp_bytes = b""
        else:
            self._finish_session_state_v1()
        logger.info("BAILIAN_TTS_TRANSPORT_CLOSED")
        self._release_v1()

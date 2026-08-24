import io
import edge_tts
import os
import re
import time
from typing import Dict, Optional, cast
import librosa
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
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

class TTSConfig(HandlerBaseConfigModel, BaseModel):
    ref_audio_path: str = Field(default=None)
    ref_audio_text: str = Field(default=None)
    voice: str = Field(default=None)
    sample_rate: int = Field(default=24000)


class TTSContext(HandlerContext):
    def __init__(self, session_id: str):
        super().__init__(session_id)
        self.config = None
        self.local_session_id = 0
        self.input_text = ''
        self.dump_audio = False
        self.audio_dump_file = None
        self._secure_generation_v1 = None


class HandlerTTS(HandlerBase, ABC):
    def __init__(self):
        super().__init__()

        self.ref_audio_path = None
        self.ref_audio_text = None
        self.voice = None
        self.ref_audio_buffer = None
        self.sample_rate = None
      

    def get_handler_info(self) -> HandlerBaseInfo:
        return HandlerBaseInfo(
            config_model=TTSConfig,
        )

    def get_handler_detail(self, session_context: SessionContext,
                           context: HandlerContext) -> HandlerDetail:
        definition = DataBundleDefinition()
        definition.add_entry(DataBundleEntry.create_audio_entry("avatar_audio", 1, self.sample_rate))
        inputs = {
            ChatDataType.AVATAR_TEXT: HandlerDataInfo(
                type=ChatDataType.AVATAR_TEXT,
            )
        }
        outputs = {
            ChatDataType.AVATAR_AUDIO: HandlerDataInfo(
                type=ChatDataType.AVATAR_AUDIO,
                definition=definition,
            )
        }
        return HandlerDetail(
            inputs=inputs, outputs=outputs,
        )

    def load(self, engine_config: ChatEngineConfigModel, handler_config: Optional[BaseModel] = None):
       config = cast(TTSConfig, handler_config)
       self.voice = config.voice
       self.sample_rate = config.sample_rate
       self.ref_audio_path = config.ref_audio_path
       self.ref_audio_text = config.ref_audio_text


    def create_context(self, session_context, handler_config=None):
        if not isinstance(handler_config, TTSConfig):
            handler_config = TTSConfig()
        context = TTSContext(session_context.session_info.session_id)
        context.input_text = ''
        if context.dump_audio:
            dump_file_path = os.path.join(DirectoryInfo.get_project_dir(), 'temp',
                                            f"dump_avatar_audio_{context.session_id}_{time.localtime().tm_hour}_{time.localtime().tm_min}.pcm")
            context.audio_dump_file = open(dump_file_path, "wb")
        return context
    
    def start_context(self, session_context, context: HandlerContext):
        context = cast(TTSContext, context)
        edge_tts.Communicate(text="测试音频启动", voice=self.voice)

    def filter_text(self, text):
        pattern = r"[^a-zA-Z0-9\u4e00-\u9fff,.\~!?，。！？ ]"  # 匹配不在范围内的字符
        filtered_text = re.sub(pattern, "", text)
        return filtered_text

    def handle(self, context: HandlerContext, inputs: ChatData,
               output_definitions: Dict[ChatDataType, HandlerDataInfo]):
        output_definition = output_definitions.get(ChatDataType.AVATAR_AUDIO).definition
        context = cast(TTSContext, context)
        if inputs.type == ChatDataType.AVATAR_TEXT:
            text = inputs.data.get_main_data()
        else:
            return
        if context.work_runtime_v1 is not None:
            self._handle_fenced_v1(
                context,
                inputs,
                text,
                output_definition,
            )
            return
        if text is not None:
            text = re.sub(r"<\|.*?\|>", "", text)
            context.input_text += self.filter_text(text)

        text_end = inputs.data.get_meta("avatar_text_end", False)
        if not text_end:
            sentences = re.split(r'(?<=[,.~!?，。！？])', context.input_text)
            if len(sentences) > 1:  # 至少有一个完整句子
                complete_sentences = sentences[:-1]  # 完整句子
                context.input_text = sentences[-1]  # 剩余的未完成部分

                # 对完整句子进行处理
                for sentence in complete_sentences:
                    if len(sentence.strip()) < 1:
                        continue
                    logger.info('current sentence' + sentence)
                    
                    communicate = edge_tts.Communicate(sentence, self.voice)
                    data = b''

                    for chunk in communicate.stream_sync():
                        if chunk['type'] == 'audio':
                            # tts_audio = chunk['data']
                            data += chunk['data']
                    
                    output_audio = librosa.load(io.BytesIO(data), sr=None)[0]
                    output_audio = output_audio[np.newaxis, ...]
                    output = DataBundle(output_definition)
                    output.set_main_data(output_audio)
                    context.submit_data(output)
        else:
            logger.info('last sentence' + context.input_text)
            if context.input_text is not None and len(context.input_text.strip()) > 0:
                    communicate = edge_tts.Communicate(context.input_text, self.voice)
                    data = b''

                    for chunk in communicate.stream_sync():
                        if chunk['type'] == 'audio':
                            # tts_audio = chunk['data']
                            data += chunk['data']
                    output_audio = librosa.load(io.BytesIO(data), sr=None)[0]
                    output_audio = output_audio[np.newaxis, ...]
                    output = DataBundle(output_definition)
                    output.set_main_data(output_audio)
                    context.submit_data(output)
            context.input_text = ''
            output = DataBundle(output_definition)
            output.set_main_data(np.zeros(shape=(1, 240), dtype=np.float32))
            context.submit_data(output, finish_stream=True)
            logger.info("speech end")

    def _handle_fenced_v1(
        self,
        context: TTSContext,
        inputs: ChatData,
        text,
        output_definition: DataBundleDefinition,
    ) -> None:
        runtime = context.work_runtime_v1
        parent = context.current_work_v1()
        if runtime is None or parent is None:
            return
        synth_texts: list[str] = []
        is_terminal = inputs.is_last_data

        def update_text_buffer() -> None:
            generation = parent.fence.session_epoch.generation
            if context._secure_generation_v1 != generation:
                context.input_text = ""
                context._secure_generation_v1 = generation
            if text is not None:
                filtered = re.sub(r"<\|.*?\|>", "", text)
                context.input_text += self.filter_text(filtered)
            if not is_terminal:
                sentences = re.split(
                    r"(?<=[,.~!?，。！？])",
                    context.input_text,
                )
                if len(sentences) > 1:
                    synth_texts.extend(
                        sentence
                        for sentence in sentences[:-1]
                        if sentence.strip()
                    )
                    context.input_text = sentences[-1]
            else:
                if context.input_text.strip():
                    synth_texts.append(context.input_text)
                context.input_text = ""

        if not runtime.perform_if_live_v1(
            parent,
            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
            update_text_buffer,
        ):
            return

        for sentence in synth_texts:
            try:
                work = runtime.register_child_work_v1(
                    parent,
                    WorkOperationKindV1.TTS_SYNTHESIS,
                )
            except WorkAdmissionDeniedV1:
                return
            try:
                with context.activate_work_v1(
                    work,
                    context.current_work_envelope_v1(),
                ):
                    if not runtime.validate_work_v1(
                        work,
                        WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
                    ):
                        continue
                    communicate = edge_tts.Communicate(
                        sentence,
                        self.voice,
                    )
                    audio_bytes = bytearray()
                    for chunk in communicate.stream_sync():
                        if not runtime.validate_work_v1(
                            work,
                            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                        ):
                            audio_bytes.clear()
                            break
                        if chunk["type"] == "audio":
                            audio_bytes.extend(chunk["data"])
                    if not audio_bytes or not runtime.validate_work_v1(
                        work,
                        WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                    ):
                        continue
                    output_audio = librosa.load(
                        io.BytesIO(bytes(audio_bytes)),
                        sr=None,
                    )[0][np.newaxis, ...]
                    output = DataBundle(output_definition)
                    output.set_main_data(output_audio)
                    runtime.perform_if_live_v1(
                        work,
                        WorkValidationBoundaryV1.BEFORE_EGRESS,
                        lambda: context.submit_data(output),
                    )
            except Exception:
                if runtime.validate_work_v1(
                    work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                ):
                    logger.error("EDGETTS_SYNTHESIS_FAILED")
            finally:
                runtime.release_work_v1(work)

        if not is_terminal:
            return
        try:
            terminal_work = runtime.register_child_work_v1(
                parent,
                WorkOperationKindV1.TTS_SYNTHESIS,
            )
        except WorkAdmissionDeniedV1:
            return
        try:
            with context.activate_work_v1(
                terminal_work,
                context.current_work_envelope_v1(),
            ):
                output = DataBundle(output_definition)
                output.set_main_data(
                    np.zeros(shape=(1, 240), dtype=np.float32)
                )
                runtime.perform_if_live_v1(
                    terminal_work,
                    WorkValidationBoundaryV1.BEFORE_COMPLETION,
                    lambda: context.submit_data(
                        output,
                        finish_stream=True,
                    ),
                )
        finally:
            runtime.release_work_v1(terminal_work)

    def clear_normal_semantic_state_v1(
        self,
        context: HandlerContext,
        generation: int,
    ) -> None:
        """Discard unfinished generic text after its generation is fenced."""

        context = cast(TTSContext, context)
        context.input_text = ""
        context._secure_generation_v1 = generation

    def destroy_context(self, context: HandlerContext):
        context = cast(TTSContext, context)
        logger.info('destroy context')

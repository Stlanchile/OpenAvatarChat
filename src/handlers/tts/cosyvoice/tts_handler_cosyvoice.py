from collections import deque
from dataclasses import dataclass, field
from torch.multiprocessing import Manager, Queue
import os
import queue
import re
import threading
import time
from typing import Dict, Optional, cast
import uuid
import numpy as np
from loguru import logger
from pydantic import BaseModel, Field
from abc import ABC
import torch
from chat_engine.contexts.handler_context import HandlerContext
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel, HandlerBaseConfigModel
from chat_engine.common.handler_base import HandlerBase, HandlerBaseInfo, HandlerDataInfo, HandlerDetail
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.contexts.session_context import SessionContext
from chat_engine.data_models.runtime_data.data_bundle import DataBundle, DataBundleDefinition, DataBundleEntry
from handlers.tts.cosyvoice.cosyvoice_processor import TTSCosyVoiceProcessor
import modelscope
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import WorkBoundItemV1

from engine_utils.directory_info import DirectoryInfo

class TTSConfig(HandlerBaseConfigModel, BaseModel):
    model_name: str = Field(default=None)
    api_key: str = Field(default=None)  # Field(default=os.getenv("DASHSCOPE_API_KEY"))
    api_url: str = Field(default=None)
    ref_audio_path: str = Field(default=None)
    ref_audio_text: str = Field(default=None)
    spk_id: str = Field(default=None)
    sample_rate: int = Field(default=24000)
    process_num: int = Field(default=1)


@dataclass
class HandlerTask:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    result_queue: queue.Queue = field(default_factory=queue.Queue)
    speech_end: bool = field(default=False)
    work_item_v1: Optional[WorkBoundItemV1] = None
    operation_ref_v1: Optional[str] = None
    cancellation_monitor_stop_v1: threading.Event = field(
        default_factory=threading.Event,
        repr=False,
    )


class TTSContext(HandlerContext):
    def __init__(self, session_id: str):
        super().__init__(session_id)
        self.config = None
        self.local_session_id = 0
        self.input_text = ''
        self.dump_audio = False
        self.audio_dump_file = None

        self.task_queue: deque[HandlerTask]
        self.task_consumer_thread = None
        self._secure_generation_v1 = None


class HandlerTTS(HandlerBase, ABC):
    def __init__(self):
        super().__init__()

        self.model_name = None
        self.api_url = None
        self.api_key = None
        self.ref_audio_path = None
        self.ref_audio_text = None
        self.spk_id = None
        self.model = None
        self.ref_audio_buffer = None
        self.sample_rate = None
        self.mp = Manager()
        self.tts_input_queue = self.mp.Queue()
        self.tts_output_queue = self.mp.Queue()
        self.cancelled_work_v1 = self.mp.dict()
        self.multi_process = []
        self.consume_thread = None
        self.task_queue_map = {}
        if torch.cuda.is_available():
            self.device = torch.device("cuda:0")
        elif torch.backends.mps.is_available():
            self.device = torch.device("mps")
        else:
            self.device = torch.device("cpu")

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
        if isinstance(handler_config, TTSConfig):  
            model_path = os.path.join(DirectoryInfo.get_models_dir(), handler_config.model_name)
            if os.path.exists(model_path):
                handler_config.model_name = model_path
            if not os.path.isabs(handler_config.model_name) and handler_config.model_name is not None:
                modelscope.snapshot_download(handler_config.model_name)

            self.sample_rate = handler_config.sample_rate      
            for i in range(handler_config.process_num):
                process = TTSCosyVoiceProcessor(self.handler_root, handler_config,
                                                self.tts_input_queue, self.tts_output_queue,
                                                self.cancelled_work_v1)
                process.start()
                self.multi_process.append(process)
            self.tts_output_queue.get()

        def consumer(task_queue_map: dict[str, deque], tts_output_queue: Queue):
            failed_workers: set[int] = set()

            def release_after_worker_failure() -> None:
                for process in self.multi_process:
                    process_id = id(process)
                    if process_id in failed_workers:
                        continue
                    try:
                        failed = (
                            process.exitcode is not None
                            and not process.is_alive()
                        )
                    except Exception:
                        failed = True
                    if not failed:
                        continue
                    failed_workers.add(process_id)
                    logger.error("COSYVOICE_WORKER_FAILED")
                    for task_deque in tuple(task_queue_map.values()):
                        for task in tuple(task_deque):
                            if task is None:
                                continue
                            if task.operation_ref_v1 is not None:
                                self.cancelled_work_v1[
                                    task.operation_ref_v1
                                ] = True
                            task.cancellation_monitor_stop_v1.set()
                            task.result_queue.put(None)

            while True:
                logger.debug(f"tts output {len(task_queue_map.keys()), tts_output_queue.qsize()}")
                output = None
                try:
                    output = tts_output_queue.get(timeout=1)
                except Exception:
                    release_after_worker_failure()
                    continue
                key = output['key']
                audio = output['tts_speech']
                session_id = output['session_id']
                taskDeque = task_queue_map.get(session_id)
                if taskDeque is None:
                    continue
                for task in taskDeque:
                    if task is not None and task.id == key:
                        task.result_queue.put(audio)
                        break
        self.consume_thread = threading.Thread(target=consumer, args=[self.task_queue_map, self.tts_output_queue])
        self.consume_thread.start()
        
    @staticmethod
    def _create_message(text: str):
        if text is None:
            return None
        msg = {"role": "user", "content": text}
        return msg

    def create_context(self, session_context, handler_config=None):
        if not isinstance(handler_config, TTSConfig):
            handler_config = TTSConfig()
        context = TTSContext(session_context.session_info.session_id)
        context.input_text = ''
        context.task_queue = deque()
        if context.dump_audio:
            dump_file_path = os.path.join(DirectoryInfo.get_project_dir(), 'temp',
                                            f"dump_avatar_audio_{context.session_id}_{time.localtime().tm_hour}_{time.localtime().tm_min}.pcm")
            context.audio_dump_file = open(dump_file_path, "wb")
        return context
    
    def start_context(self, session_context, context: HandlerContext):
        context = cast(TTSContext, context)
        output_definition = self.get_handler_detail(session_context, context).outputs.get(ChatDataType.AVATAR_AUDIO).definition

        def task_consumer(task_inner_queue: deque, callback: callable):
            def finish_task(task: HandlerTask) -> None:
                try:
                    if task_inner_queue and task_inner_queue[0] is task:
                        task_inner_queue.popleft()
                    else:
                        task_inner_queue.remove(task)
                except ValueError:
                    pass
                task.cancellation_monitor_stop_v1.set()
                runtime = context.work_runtime_v1
                work_item = task.work_item_v1
                if runtime is not None and work_item is not None:
                    work_item.release_once_v1(runtime)
                if task.operation_ref_v1 is not None:
                    self.cancelled_work_v1.pop(
                        task.operation_ref_v1,
                        None,
                    )

            try:
                while True:
                    if len(task_inner_queue) == 0:
                        time.sleep(0.03)
                        continue
                    task = task_inner_queue[0]
                    task = cast(HandlerTask, task)
                    if task is None:
                        task_inner_queue.popleft()
                        break
                    runtime = context.work_runtime_v1
                    work_item = task.work_item_v1
                    if (
                        runtime is not None
                        and work_item is not None
                        and work_item.cancellation.is_cancelled
                        and task.operation_ref_v1 is not None
                    ):
                        self.cancelled_work_v1[
                            task.operation_ref_v1
                        ] = True
                    logger.debug(f'get task audio {len(task_inner_queue), task.result_queue.qsize()}')
                    try:
                        audio = task.result_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    except Exception:
                        if task.operation_ref_v1 is not None:
                            self.cancelled_work_v1[
                                task.operation_ref_v1
                            ] = True
                        finish_task(task)
                        logger.error("COSYVOICE_OWNER_QUEUE_FAILED")
                        continue
                    if audio is None:
                        finish_task(task)
                        continue
                    try:
                        output = DataBundle(output_definition)
                        output.set_main_data(audio)
                        output_eligible = False
                        if runtime is None or work_item is None:
                            callback(
                                output,
                                finish_stream=task.speech_end,
                            )
                            output_eligible = True
                        elif runtime.validate_work_v1(
                            work_item.registered_work,
                            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                        ):
                            with context.activate_work_v1(
                                work_item.registered_work,
                                work_item.envelope_ref,
                            ):
                                output_eligible = runtime.perform_if_live_v1(
                                    work_item.registered_work,
                                    WorkValidationBoundaryV1.BEFORE_EGRESS,
                                    lambda: callback(
                                        output,
                                        finish_stream=(
                                            task.speech_end
                                        ),
                                    ),
                                )
                        if context.dump_audio and output_eligible:
                            if runtime is None or work_item is None:
                                context.audio_dump_file.write(
                                    audio.tobytes()
                                )
                            else:
                                runtime.perform_if_live_v1(
                                    work_item.registered_work,
                                    WorkValidationBoundaryV1.BEFORE_EGRESS,
                                    lambda: context.audio_dump_file.write(
                                        audio.tobytes()
                                    ),
                                )
                    except Exception:
                        if task.operation_ref_v1 is not None:
                            self.cancelled_work_v1[
                                task.operation_ref_v1
                            ] = True
                        finish_task(task)
                        logger.error("COSYVOICE_OWNER_CALLBACK_FAILED")
            finally:
                self.task_queue_map.pop(context.session_id, None)
  
        context.task_consume_thread = threading.Thread(target=task_consumer, args=[context.task_queue, context.submit_data])
        context.task_consume_thread.start()
        self.task_queue_map[context.session_id] = context.task_queue

    def _start_cancellation_monitor_v1(
        self,
        task: HandlerTask,
    ) -> None:
        item = task.work_item_v1
        operation_ref = task.operation_ref_v1
        if item is None or operation_ref is None:
            return

        def monitor() -> None:
            while not task.cancellation_monitor_stop_v1.is_set():
                if item.cancellation.wait(timeout=0.1):
                    self.cancelled_work_v1[operation_ref] = True
                    return

        threading.Thread(
            target=monitor,
            name="cosyvoice_work_cancel_v1",
            daemon=True,
        ).start()

    def filter_text(self, text):
        pattern = r"[^a-zA-Z0-9\u4e00-\u9fff,.\~!?，。！？ ]"  # 匹配不在范围内的字符
        filtered_text = re.sub(pattern, "", text)
        return filtered_text

    def handle(self, context: HandlerContext, inputs: ChatData,
               output_definitions: Dict[ChatDataType, HandlerDataInfo]):
        #output_definition = output_definitions.get(ChatDataType.AVATAR_AUDIO).definition
        context = cast(TTSContext, context)
        if inputs.type == ChatDataType.AVATAR_TEXT:
            text = inputs.data.get_main_data()
        else:
            return
        if context.work_runtime_v1 is not None:
            self._handle_fenced_v1(context, inputs, text)
            return
        if text is not None:
            text = re.sub(r"<\|.*?\|>", "", text)
            context.input_text += self.filter_text(text)

        text_end = inputs.is_last_data
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
                    task = HandlerTask()
                    tts_info = {
                        "text": sentence + '。',
                        "key": task.id,
                        "session_id": context.session_id
                    
                    }
                    self.tts_input_queue.put(tts_info)
                    context.task_queue.append(task)
        else:
            logger.info('last sentence' + context.input_text)
            if context.input_text is not None and len(context.input_text.strip()) > 0:
                task = HandlerTask()
                tts_info = {
                    "text": context.input_text,
                    "key": task.id,
                    "session_id": context.session_id
                }
                self.tts_input_queue.put(tts_info)
                context.task_queue.append(task)
            context.input_text = ''
            end_task = HandlerTask(speech_end=True)
            end_task.result_queue.put(np.zeros(shape=(1, 240), dtype=np.float32))
            end_task.result_queue.put(None)
            logger.info(f"speech end {end_task}")
            context.task_queue.append(end_task)

    def _handle_fenced_v1(
        self,
        context: TTSContext,
        inputs: ChatData,
        text,
    ) -> None:
        runtime = context.work_runtime_v1
        parent = context.current_work_v1()
        if runtime is None or parent is None:
            return
        synth_texts: list[str] = []
        text_end = inputs.is_last_data

        def update_text_buffer() -> None:
            generation = parent.fence.session_epoch.generation
            if context._secure_generation_v1 != generation:
                context.input_text = ""
                context._secure_generation_v1 = generation
            if text is not None:
                filtered = re.sub(r"<\|.*?\|>", "", text)
                context.input_text += self.filter_text(filtered)
            if not text_end:
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
            task = HandlerTask(
                work_item_v1=WorkBoundItemV1(
                    payload=None,
                    registered_work=work,
                    envelope_ref=context.current_work_envelope_v1(),
                ),
                operation_ref_v1=str(work.fence.operation_id),
            )
            tts_info = {
                "text": sentence + ("。" if not text_end else ""),
                "key": task.id,
                "session_id": context.session_id,
                "work_ref_v1": task.operation_ref_v1,
            }
            try:
                def enqueue_synthesis() -> None:
                    context.task_queue.append(task)
                    try:
                        self.tts_input_queue.put_nowait(tts_info)
                    except Exception:
                        context.task_queue.remove(task)
                        raise

                if not runtime.perform_if_live_v1(
                    work,
                    WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
                    enqueue_synthesis,
                ):
                    task.work_item_v1.release_once_v1(runtime)
                    continue
                self._start_cancellation_monitor_v1(task)
                if not runtime.validate_work_v1(
                    work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                ):
                    self.cancelled_work_v1[
                        task.operation_ref_v1
                    ] = True
            except Exception:
                try:
                    context.task_queue.remove(task)
                except ValueError:
                    pass
                task.cancellation_monitor_stop_v1.set()
                task.work_item_v1.release_once_v1(runtime)
                logger.error("COSYVOICE_QUEUE_SUBMISSION_FAILED")

        if not text_end:
            return
        try:
            terminal_work = runtime.register_child_work_v1(
                parent,
                WorkOperationKindV1.TTS_SYNTHESIS,
            )
        except WorkAdmissionDeniedV1:
            return
        terminal_item = WorkBoundItemV1(
            payload=None,
            registered_work=terminal_work,
            envelope_ref=context.current_work_envelope_v1(),
        )
        end_task = HandlerTask(
            speech_end=True,
            work_item_v1=terminal_item,
            operation_ref_v1=str(
                terminal_work.fence.operation_id
            ),
        )
        end_task.result_queue.put(
            np.zeros(shape=(1, 240), dtype=np.float32)
        )
        end_task.result_queue.put(None)
        if not runtime.perform_if_live_v1(
            terminal_work,
            WorkValidationBoundaryV1.BEFORE_COMPLETION,
            lambda: context.task_queue.append(end_task),
        ):
            terminal_item.release_once_v1(runtime)

    def quiesce_normal_work_v1(
        self,
        context: HandlerContext,
    ) -> None:
        """Cancel queued synthesis without stopping the reusable consumer."""

        context = cast(TTSContext, context)
        for task in tuple(context.task_queue):
            if task is None:
                continue
            task.cancellation_monitor_stop_v1.set()
            if task.operation_ref_v1 is not None:
                self.cancelled_work_v1[
                    task.operation_ref_v1
                ] = True

    def clear_normal_semantic_state_v1(
        self,
        context: HandlerContext,
        generation: int,
    ) -> None:
        context = cast(TTSContext, context)
        context.input_text = ""
        context.task_queue.clear()
        context._secure_generation_v1 = generation

    def drain_registered_work_v1(
        self,
        context: HandlerContext,
    ) -> None:
        context = cast(TTSContext, context)
        self.quiesce_normal_work_v1(context)
        if not context.task_queue or context.task_queue[-1] is not None:
            context.task_queue.append(None)

    def destroy_context(self, context: HandlerContext):
        context = cast(TTSContext, context)
        logger.info('destroy context')
        self.drain_registered_work_v1(context)
        if (
            context.task_consume_thread is not None
            and context.task_consume_thread is not threading.current_thread()
        ):
            context.task_consume_thread.join(timeout=2.0)
        if (
            context.task_consume_thread is not None
            and not context.task_consume_thread.is_alive()
        ):
            context.task_consume_thread = None

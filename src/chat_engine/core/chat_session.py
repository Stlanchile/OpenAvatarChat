import asyncio
import copy
import queue
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import Dict, List

from loguru import logger

from chat_engine.common.handler_base import HandlerBase
from chat_engine.common.logic_base import LogicBase
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.signal_manager import SignalManager
from chat_engine.core.stream_manager import ChatDataSubmitter, StreamManager
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import (
    ChatEngineConfigModel,
    HandlerBaseConfigModel,
    LogicBaseConfigModel,
)
from chat_engine.data_models.chat_signal import ChatSignal, SignalFilterRule
from chat_engine.data_models.chat_signal_type import ChatSignalType
from chat_engine.data_models.chat_stream_status import ChatStreamStatus
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.internal.chat_data_endpoints import DataSink
from chat_engine.data_models.internal.handler_definition_data import HandlerBaseInfo
from chat_engine.data_models.internal.handler_session_data import (
    HandlerEnv,
    HandlerRecord,
    HandlerRegistry,
)
from chat_engine.data_models.internal.logic_definition_data import LogicBaseInfo
from chat_engine.data_models.internal.logic_session_data import LogicEnv
from service.admission_notice_lite_chat_context import (
    AdmissionContextV1,
    augment_human_text_with_admission_context,
)


class ChatSession:
    input_type_mapping = {
        EngineChannelType.VIDEO: [ChatDataType.CAMERA_VIDEO],
        EngineChannelType.AUDIO: [ChatDataType.MIC_AUDIO],
        EngineChannelType.TEXT: [ChatDataType.HUMAN_TEXT]
    }

    def __init__(self, session_context: SessionContext, _engine_config: ChatEngineConfigModel):
        self.session_context = session_context
        self.signal_manager = SignalManager(self.session_context.session_clock)
        self.signal_manager.init()
        self.stream_manager = StreamManager(self.signal_manager)
        self.stream_manager.enable_debug_logging(True)
        self.data_sinks: Dict[ChatDataType, List[DataSink]] = {}
        self.handlers: Dict[str, HandlerRecord] = {}
        self._playback_begin_event_ids: Dict[str, str] = {}
        self._initialize_admission_context_state()
        self._register_playback_auto_recorder()

    def _initialize_admission_context_state(self) -> None:
        self._admission_context_lock = threading.RLock()
        self._active_admission_context: AdmissionContextV1 | None = None
        self._admission_recognition_token: object | None = None
        self._admission_context_closed = False

    @property
    def active_admission_context(self) -> AdmissionContextV1 | None:
        with self._admission_context_lock:
            return self._active_admission_context

    def try_reserve_admission_context_activation(self, token: object) -> bool:
        if token is None:
            raise ValueError("activation token is required")
        with self._admission_context_lock:
            if (
                self._admission_context_closed
                or self._active_admission_context is not None
                or self._admission_recognition_token is not None
            ):
                return False
            self._admission_recognition_token = token
            return True

    def cancel_admission_context_activation(self, token: object) -> None:
        with self._admission_context_lock:
            if self._admission_recognition_token is token:
                self._admission_recognition_token = None

    def commit_admission_context_activation(
        self,
        token: object,
        context: AdmissionContextV1,
        complete_activation: Callable[[], bool],
    ) -> bool:
        """Install context and publish completion under one session lock."""
        if type(context) is not AdmissionContextV1:
            raise TypeError("expected exact AdmissionContextV1")
        if not callable(complete_activation):
            raise TypeError("complete_activation must be callable")
        with self._admission_context_lock:
            if (
                self._admission_context_closed
                or self._admission_recognition_token is not token
                or self._active_admission_context is not None
            ):
                return False
            self._active_admission_context = context
            self._admission_recognition_token = None
            try:
                if complete_activation():
                    return True
            except Exception:
                self._active_admission_context = None
                self._admission_recognition_token = token
                raise
            self._active_admission_context = None
            self._admission_recognition_token = token
            return False

    def reset_conversation_and_admission_context(
        self,
        reset_conversation: Callable[[], bool],
    ) -> bool:
        """Reset conversation and clear context under one exact-session lock."""
        with self._admission_context_lock:
            if self._admission_context_closed or not reset_conversation():
                return False
            self._discard_pending_conversation_inputs_locked()
            self._active_admission_context = None
            self._admission_recognition_token = None
            return True

    def _discard_pending_conversation_inputs_locked(self) -> None:
        reset_types = {
            ChatDataType.MIC_AUDIO,
            ChatDataType.HUMAN_AUDIO,
            ChatDataType.HUMAN_TEXT,
        }
        for record in self.handlers.values():
            input_queue = record.env.input_queue
            if input_queue is None:
                continue
            retained = []
            while True:
                try:
                    input_data = input_queue.get_nowait()
                except (queue.Empty, asyncio.QueueEmpty):
                    break
                if input_data.type not in reset_types:
                    retained.append(input_data)
            for input_data in retained:
                input_queue.put_nowait(input_data)

    def _close_admission_context(self) -> None:
        with self._admission_context_lock:
            self._admission_context_closed = True
            self._active_admission_context = None
            self._admission_recognition_token = None

    @staticmethod
    def _is_ordinary_human_text_workflow_input(
        input_data,
        output_info,
    ) -> bool:
        return (
            input_data.type == ChatDataType.HUMAN_TEXT
            and ChatDataType.AVATAR_TEXT in output_info
        )

    def _contextualize_human_text_input_locked(self, input_data):
        context = self._active_admission_context
        if context is None or input_data.data is None:
            return input_data
        user_text = input_data.data.get_main_data()
        if not isinstance(user_text, str):
            return input_data
        contextualized_bundle = copy.deepcopy(input_data.data)
        contextualized_bundle.set_main_data(
            augment_human_text_with_admission_context(context, user_text)
        )
        return replace(input_data, data=contextualized_bundle)

    def handler_pumper(self, handler_env: HandlerEnv):
        session_context = self.session_context
        shared_states = session_context.shared_states
        input_queue = handler_env.input_queue
        handler = handler_env.handler
        context = handler_env.context
        output_info = handler_env.output_info
        # Use handler_output_info (with original type keys) if available,
        # so handler code can use its declared types even with output_type_override
        handler_visible_output_info = handler_env.handler_output_info or output_info
        if output_info is None:
            output_info = {}
        if handler_visible_output_info is None:
            handler_visible_output_info = {}
        handler.warmup_context(session_context, context)
        
        # Track stream begin events for auto history recording
        stream_begin_events: Dict[str, str] = {}  # stream_key -> event_id
        reset_serialized_types = {
            ChatDataType.MIC_AUDIO,
            ChatDataType.HUMAN_AUDIO,
            ChatDataType.HUMAN_TEXT,
        }
        
        while shared_states.active:
            self._admission_context_lock.acquire()
            try:
                input_data = input_queue.get_nowait()
            except (queue.Empty, asyncio.QueueEmpty):
                self._admission_context_lock.release()
                time.sleep(0.03)
                continue
            
            guard_held = input_data.type in reset_serialized_types
            if not guard_held:
                self._admission_context_lock.release()
            try:
                is_workflow_text = self._is_ordinary_human_text_workflow_input(
                    input_data,
                    handler_visible_output_info,
                )
                if is_workflow_text:
                    input_data = self._contextualize_human_text_input_locked(input_data)
                context.data_submitter.update_input_stream(input_data)

                # Consumer-side cancel guard: drop data from cancelled streams.
                if input_data.stream_id is not None:
                    stream_manager = getattr(context, "stream_manager", None)
                    stream = (
                        stream_manager.find_stream(input_data.stream_id)
                        if stream_manager is not None
                        else None
                    )
                    if (
                        stream is not None
                        and stream.status == ChatStreamStatus.CANCELLED
                    ):
                        continue

                if (
                    input_data.is_first_data
                    and handler.should_auto_record_history(input_data.type)
                    and input_data.stream_id is not None
                ):
                    stream_key_obj = input_data.stream_id.key
                    stream_key_str = str(stream_key_obj) if stream_key_obj else None
                    event_id = handler.on_history_record(
                        context,
                        signal_type=ChatSignalType.STREAM_BEGIN,
                        data_type=input_data.type,
                        source_stream_key=stream_key_str,
                    )
                    if event_id and stream_key_str:
                        stream_begin_events[stream_key_str] = event_id

                if (
                    handler.should_auto_record_history(input_data.type)
                    and input_data.stream_id is not None
                    and input_data.data is not None
                    and context.session_history is not None
                ):
                    try:
                        text_data = input_data.data.get_main_data()
                        if text_data and isinstance(text_data, str):
                            stream_key_obj = input_data.stream_id.key
                            stream_key_str = (
                                str(stream_key_obj) if stream_key_obj else None
                            )
                            if stream_key_str:
                                chunk_id = (
                                    f"{input_data.timestamp[0]}:{input_data.timestamp[1]}"
                                )
                                context.session_history.accumulate_stream_data(
                                    stream_key_str,
                                    text_data,
                                    chunk_id,
                                )
                    except Exception:
                        pass

                actual_type = input_data.type
                if handler_env.input_type_reverse_mapping:
                    original_type = handler_env.input_type_reverse_mapping.get(
                        actual_type
                    )
                    if original_type:
                        input_data.type = original_type

                try:
                    handler_result = handler.handle(
                        context,
                        input_data,
                        handler_visible_output_info,
                    )
                except Exception as error:
                    handler_name = (
                        handler_env.handler_info.name
                        if handler_env.handler_info
                        else "Unknown"
                    )
                    logger.opt(exception=error).error(
                        f"Handler {handler_name} raised exception during handle(), "
                        f"input type: {input_data.type}, stream: {input_data.stream_id}"
                    )
                    input_data.type = actual_type
                    continue

                input_data.type = actual_type

                if (
                    input_data.is_last_data
                    and handler.should_auto_record_history(input_data.type)
                    and input_data.stream_id is not None
                ):
                    stream_key_obj = input_data.stream_id.key
                    stream_key_str = str(stream_key_obj) if stream_key_obj else None
                    begin_event_id = (
                        stream_begin_events.pop(stream_key_str, None)
                        if stream_key_str
                        else None
                    )
                    data_content = None
                    if context.session_history is not None and stream_key_str:
                        data_content = (
                            context.session_history.finalize_stream_accumulator(
                                stream_key_str
                            )
                        )
                    if not data_content and input_data.data is not None:
                        try:
                            data_content = input_data.data.get_main_data()
                        except Exception:
                            pass
                    handler.on_history_record(
                        context,
                        signal_type=ChatSignalType.STREAM_END,
                        data_type=input_data.type,
                        data=data_content,
                        related_event_id=begin_event_id,
                        source_stream_key=stream_key_str,
                    )

                if not isinstance(handler_result, Iterable):
                    handler_result = [handler_result]
                for handler_output in handler_result:
                    if context.data_submitter is None:
                        continue
                    context.data_submitter.submit(handler_output)
            finally:
                if guard_held:
                    self._admission_context_lock.release()

    def _register_playback_auto_recorder(self):
        """Register signal listeners to auto-record CLIENT_PLAYBACK stream lifecycle to SessionHistory."""
        for signal_type in (ChatSignalType.STREAM_BEGIN, ChatSignalType.STREAM_END, ChatSignalType.STREAM_CANCEL):
            self.signal_manager.register_listener(
                listener=self._on_playback_stream_signal,
                signal_filter=SignalFilterRule(signal_type, None, ChatDataType.CLIENT_PLAYBACK),
            )

    def _on_playback_stream_signal(self, signal: ChatSignal):
        """Auto-record CLIENT_PLAYBACK stream lifecycle events to SessionHistory.
        
        Parent stream ancestry (AVATAR_AUDIO etc.) is navigable through StreamManager
        at query time — no need to denormalize into history events.
        """
        session_history = self.session_context.session_history
        if session_history is None or signal.related_stream is None:
            return
        stream_key_str = signal.related_stream.stream_key_str

        if signal.type == ChatSignalType.STREAM_BEGIN:
            event_id = session_history.create_and_add_event(
                data_type=ChatDataType.CLIENT_PLAYBACK,
                signal_type=ChatSignalType.STREAM_BEGIN,
                source_stream_key=stream_key_str,
                owner=signal.source_name,
            )
            if event_id and stream_key_str:
                self._playback_begin_event_ids[stream_key_str] = event_id
        elif signal.type in (ChatSignalType.STREAM_END, ChatSignalType.STREAM_CANCEL):
            begin_event_id = self._playback_begin_event_ids.pop(stream_key_str, None) if stream_key_str else None
            session_history.create_and_add_event(
                data_type=ChatDataType.CLIENT_PLAYBACK,
                signal_type=signal.type,
                source_stream_key=stream_key_str,
                owner=signal.source_name,
                parent_event_id=begin_event_id,
            )

    def prepare_handler(self, handler: HandlerBase, handler_info: HandlerBaseInfo,
                        handler_config: HandlerBaseConfigModel):
        handler_env = HandlerEnv(handler_info=handler_info, handler=handler, config=handler_config)
        handler_env.context = handler.create_context(self.session_context, handler_env.config)
        handler_env.context.owner = handler_info.name
        handler_env.input_queue = queue.Queue()
        io_detail = handler.get_handler_detail(self.session_context, handler_env.context)
        io_detail.validate()
        
        # Type override mappings: original_type -> actual_type
        input_type_mapping: Dict[ChatDataType, ChatDataType] = {}
        output_type_mapping: Dict[ChatDataType, ChatDataType] = {}
        
        # Apply input type overrides from configuration
        if handler_config.input_type_override:
            logger.info(f"Handler {handler_info.name}: processing input_type_override {handler_config.input_type_override}, current inputs: {list(io_detail.inputs.keys())}")
            for orig_type_name, target_type_name in handler_config.input_type_override.items():
                try:
                    orig_type = ChatDataType[orig_type_name]
                    target_type = ChatDataType[target_type_name]
                    if orig_type in io_detail.inputs:
                        input_info = io_detail.inputs.pop(orig_type)
                        input_info.type = target_type
                        io_detail.inputs[target_type] = input_info
                        input_type_mapping[orig_type] = target_type
                        logger.info(f"Handler {handler_info.name}: input type override {orig_type_name} -> {target_type_name}")
                    else:
                        logger.warning(f"Handler {handler_info.name}: input type {orig_type_name} not in handler's declared inputs, skipping override")
                except KeyError as e:
                    logger.warning(f"Handler {handler_info.name}: invalid type override - {e}")
        
        # Apply output type overrides from configuration
        # Note: We only create streamer for the target type, not the original type.
        # Handler code can still use original type names because _output_type_mapping
        # handles the translation in ChatDataSubmitter.get_streamer()
        if handler_config.output_type_override:
            for orig_type_name, target_type_name in handler_config.output_type_override.items():
                try:
                    orig_type = ChatDataType[orig_type_name]
                    target_type = ChatDataType[target_type_name]
                    if orig_type in io_detail.outputs:
                        output_info = io_detail.outputs.pop(orig_type)
                        output_info.type = target_type
                        io_detail.outputs[target_type] = output_info
                        # Record mapping so handler can use original type names via get_streamer()
                        output_type_mapping[orig_type] = target_type
                        logger.debug(f"Handler {handler_info.name}: output type override {orig_type_name} -> {target_type_name}")
                except KeyError as e:
                    logger.warning(f"Handler {handler_info.name}: invalid type override - {e}")
        
        inputs = io_detail.inputs
        for input_type, input_info in inputs.items():
            sink_list = self.data_sinks.setdefault(input_type, [])
            data_sink = DataSink(owner=handler_info.name, sink_queue=handler_env.input_queue, consume_info=input_info)
            sink_list.append(data_sink)
        handler_env.output_info = io_detail.outputs
        
        # Build reverse mapping: actual_type -> original_type
        # This allows handler code to check against its originally declared types
        if input_type_mapping:
            handler_env.input_type_reverse_mapping = {v: k for k, v in input_type_mapping.items()}

        # Build handler-visible output_info with original type keys
        # so handler code can use its declared types (e.g. HUMAN_TEXT instead of HUMAN_DUPLEX_TEXT)
        if output_type_mapping:
            output_type_reverse = {v: k for k, v in output_type_mapping.items()}
            handler_output_info = {}
            for key, value in io_detail.outputs.items():
                orig_key = output_type_reverse.get(key, key)
                handler_output_info[orig_key] = value
            handler_env.handler_output_info = handler_output_info

        handler_context = handler_env.context

        filters = io_detail.signal_filters
        if filters is None or len(filters) == 0:
            filters = [SignalFilterRule(None, None, None)]
        # TODO multiple signal filter should be merged.
        for signal_filter in filters:
            self.signal_manager.register_listener(
                listener=lambda signal: handler.on_signal(handler_env.context, signal),
                signal_filter=signal_filter
            )
        handler_context.signal_emitter = self.signal_manager.get_emitter(handler_info.name)
        handler_context.data_submitter = ChatDataSubmitter()
        # Set type mapping for override support - handlers can use original type names
        if output_type_mapping:
            handler_context.data_submitter.set_output_type_mapping(output_type_mapping)
        # Inject session history for duplex conversation support
        handler_context.session_history = self.session_context.session_history
        # Inject stream_manager so handlers can query stream graph and create lifecycle streams
        handler_context.stream_manager = self.stream_manager

        for output_type, output_data_info in handler_env.output_info.items():
            streamer = self.stream_manager.create_streamer(
                data_info=output_data_info,
                data_sinks=self.data_sinks,
                producer_name=handler_info.name,
                data_name=output_data_info.data_name,
                config=output_data_info.output_stream_config,
                )
            handler_context.data_submitter.register_streamer(streamer)
        self.handlers[handler_info.name] = HandlerRecord(env=handler_env)
        return handler_env

    def create_logic_context(self, handler_registries: List[HandlerRegistry], logic: LogicBase,
                             logic_info: LogicBaseInfo, logic_config: LogicBaseConfigModel):
        logic_env = LogicEnv(logic_info=logic_info, logic=logic, config=logic_config)
        logic_env.context = logic.create_context(handler_registries, self.session_context, logic_env.config)
        logic_env.context.owner = logic_info.name
        logic_detail = logic.get_logic_detail(self.session_context, logic_env.context)
        logic_detail.validate()
        inputs = logic_detail.inspected_streamers

    def sort_sinks(self):
        for input_type, sink_list in self.data_sinks.items():
            sink_list.sort(key=lambda x: x.consume_info)

    def start(self):
        if self.session_context.shared_states.active:
            return
        self.sort_sinks()
        self.session_context.shared_states.active = True
        for handler_name, handler_record in self.handlers.items():
            start_args = (handler_record.env,)
            handler_record.env.handler.start_context(self.session_context, handler_record.env.context)
            handler_record.pump_thread = threading.Thread(target=self.handler_pumper, args=start_args)
            handler_record.pump_thread.start()
        self.session_context.get_clock().start()

    def stop(self):
        self._close_admission_context()
        self.session_context.shared_states.active = False
        for handler_name, handler_record in self.handlers.items():
            if handler_record.pump_thread:
                handler_record.pump_thread.join()
                handler_record.pump_thread = None
            handler_record.env.handler.destroy_context(handler_record.env.context)
        self.signal_manager.shutdown()
        self.handlers.clear()
        self.session_context.cleanup()
        logger.info("chat session stopped")

    def get_timestamp(self):
        return self.session_context.get_clock().get_timestamp()

    def emit_signal(self, signal: ChatSignal):
        self.signal_manager.get_emitter("chat_session").emit(signal)

    def clear_conversation_history(self):
        """Clear visible/session history without stopping transports or handlers."""
        history = self.session_context.session_history
        if history is not None:
            history.clear()
        self._playback_begin_event_ids.clear()

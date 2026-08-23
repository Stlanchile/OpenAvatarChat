import asyncio
import queue
import threading
import time
import typing
from typing import Dict, List, Iterable

from loguru import logger

from chat_engine.core.signal_manager import SignalManager
from chat_engine.core.stream_manager import (
    ChatDataSubmitter,
    ChatDataSubmitterConsumerViewV1,
    StreamManager,
)
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_stream import ChatStreamIdentity
from chat_engine.data_models.chat_stream_status import ChatStreamStatus

from chat_engine.common.logic_base import LogicBase
from chat_engine.common.handler_base import HandlerBase

from chat_engine.data_models.internal.chat_data_endpoints import DataSink
from chat_engine.data_models.internal.handler_definition_data import HandlerBaseInfo
from chat_engine.data_models.internal.handler_session_data import HandlerRegistry, HandlerRecord, HandlerEnv
from chat_engine.data_models.internal.logic_definition_data import LogicBaseInfo
from chat_engine.data_models.internal.logic_session_data import LogicEnv

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.engine_channel_type import EngineChannelType
from chat_engine.data_models.chat_engine_config_data import (HandlerBaseConfigModel, ChatEngineConfigModel,
                                                             LogicBaseConfigModel)
from chat_engine.data_models.chat_signal import ChatSignal, SignalFilterRule
from chat_engine.data_models.chat_signal_type import ChatSignalSourceType, ChatSignalType

from chat_engine.contexts.session_context import SessionContext
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import (
    CoreRegistrarCapabilityV1,
    ConsumerCapabilityV1,
    ProducerAuthorityReferenceV1,
    ValidatedDispatchV1,
)
from chat_engine.security.envelope import SecurityClassificationV1
from chat_engine.security.history import SessionHistoryConsumerViewV1


class ChatSession:
    input_type_mapping = {
        EngineChannelType.VIDEO: [ChatDataType.CAMERA_VIDEO],
        EngineChannelType.AUDIO: [ChatDataType.MIC_AUDIO],
        EngineChannelType.TEXT: [ChatDataType.HUMAN_TEXT]
    }

    def __init__(
        self,
        session_context: SessionContext,
        _engine_config: ChatEngineConfigModel,
        *,
        _security_authority_v1: SecurityAuthorityV1 | None = None,
        _security_registrar_v1: CoreRegistrarCapabilityV1 | None = None,
    ):
        self.session_context = session_context
        self._security_authority: SecurityAuthorityV1 | None = None
        self._security_registrar_v1: (
            CoreRegistrarCapabilityV1 | None
        ) = None
        if self.session_context.secure_dispatch_enabled_v1:
            if _security_authority_v1 is None:
                (
                    self._security_authority,
                    self._security_registrar_v1,
                ) = SecurityAuthorityV1.create_v1()
            else:
                if _security_registrar_v1 is None:
                    raise RuntimeError(
                        "injected security authority requires registrar"
                    )
                self._security_authority = _security_authority_v1
                self._security_registrar_v1 = _security_registrar_v1
        elif (
            _security_authority_v1 is not None
            or _security_registrar_v1 is not None
        ):
            raise RuntimeError(
                "security authority requires a secure session"
            )
        self._history_capability: ConsumerCapabilityV1 | None = None
        self._history_producer_authority: (
            ProducerAuthorityReferenceV1 | None
        ) = None
        if self._security_authority is not None:
            self._history_capability = (
                self._security_authority
                ._issue_public_consumer_capability_v1(
                    self._security_registrar_v1
                )
            )
            if self._history_capability is None:
                raise RuntimeError("secure dispatch authority unavailable")
            self._history_producer_authority = (
                self._security_authority._issue_producer_authority_v1(
                    self._security_registrar_v1,
                    self._history_capability,
                )
            )
            if self._history_producer_authority is None:
                raise RuntimeError("secure history authority unavailable")
            self.session_context.session_history.configure_security_write_authorizer_v1(
                self._security_authority.history_writer_is_authorized_v1
            )
        self.signal_manager = SignalManager(
            self.session_context.session_clock,
            security_authority=self._security_authority,
        )
        self.signal_manager.init()
        self.stream_manager = StreamManager(
            self.signal_manager,
            security_authority=self._security_authority,
        )
        self.stream_manager.enable_debug_logging(True)
        self.data_sinks: Dict[ChatDataType, List[DataSink]] = {}
        self.handlers: Dict[str, HandlerRecord] = {}
        self._playback_begin_event_ids: Dict[str, str] = {}
        self._register_playback_auto_recorder()

    @classmethod
    def handler_pumper(
        cls,
        session_context: SessionContext,
        handler_env: HandlerEnv,
        security_authority: SecurityAuthorityV1 | None = None,
    ):
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
        
        while shared_states.active:
            try:
                queued_item = input_queue.get_nowait()
            except (queue.Empty, asyncio.QueueEmpty):
                time.sleep(0.03)
                continue

            validated_dispatch: ValidatedDispatchV1 | None = None
            history_authorized = True
            if security_authority is not None:
                # This is intentionally the first security-relevant action
                # after dequeue. No stream, history, state, type, or log path
                # may inspect the queued payload before this validation.
                capability = handler_env.consumer_capability
                if capability is None:
                    security_authority._record(
                        SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
                    )
                    continue
                validated_dispatch = (
                    security_authority.validate_dequeued_dispatch_v1(
                        queued_item,
                        capability,
                    )
                )
                if validated_dispatch is None:
                    continue
                input_data = validated_dispatch.payload
                if not isinstance(input_data, ChatData):
                    security_authority._record(
                        SecurityAuditEventCodeV1.DISPATCH_DENIED,
                        dispatch_id=validated_dispatch.dispatch_id,
                    )
                    continue
                producer_authority = handler_env.producer_authority
                if (
                    producer_authority is None
                    or not security_authority.record_dispatch_for_producer_v1(
                        producer_authority,
                        capability,
                        validated_dispatch,
                    )
                ):
                    continue

                trusted_identity = validated_dispatch.stream_ref.identity
                input_data.stream_id = ChatStreamIdentity(
                    data_type=trusted_identity.data_type,
                    builder_id=trusted_identity.builder_id,
                    stream_id=trusted_identity.stream_id,
                    name=trusted_identity.name,
                    producer_name=trusted_identity.producer_name,
                )
                input_data.type = validated_dispatch.trusted_data_type
                input_data.source = validated_dispatch.trusted_source
                handler_env.core_data_submitter.update_input_dispatch_v1(
                    validated_dispatch
                )
                history_capability = handler_env.history_capability
                history_authorized = (
                    history_capability is not None
                    and security_authority.consumer_is_authorized_v1(
                        validated_dispatch.envelope_ref,
                        history_capability,
                        audit_denial=False,
                    )
                )
            else:
                input_data = queued_item
                handler_env.core_data_submitter.update_input_stream(input_data)

            # Consumer-side cancel guard: drop data from cancelled streams.
            # The production-side guard in stream_data() blocks new data, but residual
            # data may already be in the queue from before cancel(). This check ensures
            # the handler never processes data after a stream has been cancelled.
            if input_data.stream_id is not None:
                _sm = getattr(context, 'stream_manager', None)
                if _sm is not None:
                    _stream = _sm.find_stream(input_data.stream_id)
                    if _stream is not None and _stream.status == ChatStreamStatus.CANCELLED:
                        continue

            # Auto-record STREAM_BEGIN to history
            if (input_data.is_first_data 
                and history_authorized
                and handler.should_auto_record_history(input_data.type)
                and input_data.stream_id is not None):
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
            
            # Accumulate streaming text data for TEXT types
            # Use timestamp as chunk_id for deduplication across multiple handlers
            if (handler.should_auto_record_history(input_data.type)
                and history_authorized
                and input_data.stream_id is not None
                and input_data.data is not None
                and context.session_history is not None):
                try:
                    text_data = input_data.data.get_main_data()
                    if text_data and isinstance(text_data, str):
                        stream_key_obj = input_data.stream_id.key
                        stream_key_str = str(stream_key_obj) if stream_key_obj else None
                        if stream_key_str:
                            # Use timestamp as unique chunk identifier for deduplication
                            chunk_id = f"{input_data.timestamp[0]}:{input_data.timestamp[1]}"
                            context.session_history.accumulate_stream_data(stream_key_str, text_data, chunk_id)
                except Exception:
                    pass
            
            # Map input type back to original type if there's a reverse mapping
            # This allows handler code to check against its declared input types
            actual_type = input_data.type
            if handler_env.input_type_reverse_mapping:
                original_type = handler_env.input_type_reverse_mapping.get(actual_type)
                if original_type:
                    input_data.type = original_type
            
            # 使用 try-except 包裹 handler.handle()，防止单次处理失败导致整个 pumper 线程退出
            try:
                handler_result = handler.handle(context, input_data, handler_visible_output_info)
            except Exception as e:
                if (
                    validated_dispatch is not None
                    and validated_dispatch.classification
                    is SecurityClassificationV1.CERTIFICATE_PRIVATE
                ):
                    logger.bind(
                        dispatch_id=validated_dispatch.dispatch_id
                    ).error("PRIVATE_HANDLER_FAILURE_V1")
                else:
                    handler_name = handler_env.handler_info.name if handler_env.handler_info else "Unknown"
                    logger.opt(exception=e).error(f"Handler {handler_name} raised exception during handle(), "
                                                  f"input type: {input_data.type}, stream: {input_data.stream_id}")
                # 重置 input_data.type 然后继续处理下一个数据
                input_data.type = actual_type
                continue
            
            # Restore the actual type after handle() call
            input_data.type = actual_type
            
            # Auto-record STREAM_END to history with accumulated data content
            if (input_data.is_last_data 
                and history_authorized
                and handler.should_auto_record_history(input_data.type)
                and input_data.stream_id is not None):
                stream_key_obj = input_data.stream_id.key
                stream_key_str = str(stream_key_obj) if stream_key_obj else None
                begin_event_id = stream_begin_events.pop(stream_key_str, None) if stream_key_str else None
                # Use accumulated data instead of just the last chunk
                data_content = None
                if context.session_history is not None and stream_key_str:
                    data_content = context.session_history.finalize_stream_accumulator(stream_key_str)
                # Fallback to last chunk data if no accumulator
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
                try:
                    handler_env.core_data_submitter.submit(handler_output)
                except Exception as error:
                    if (
                        validated_dispatch is not None
                        and validated_dispatch.classification
                        is SecurityClassificationV1.CERTIFICATE_PRIVATE
                    ):
                        logger.bind(
                            dispatch_id=validated_dispatch.dispatch_id
                        ).error("PRIVATE_OUTPUT_REJECTED_V1")
                    else:
                        logger.opt(exception=error).error(
                            "Handler output submission failed."
                        )

    def _register_playback_auto_recorder(self):
        """Register signal listeners to auto-record CLIENT_PLAYBACK stream lifecycle to SessionHistory."""
        for signal_type in (ChatSignalType.STREAM_BEGIN, ChatSignalType.STREAM_END, ChatSignalType.STREAM_CANCEL):
            self.signal_manager.register_listener(
                listener=self._on_playback_stream_signal,
                signal_filter=SignalFilterRule(signal_type, None, ChatDataType.CLIENT_PLAYBACK),
                consumer_capability=self._history_capability,
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
                _security_writer_v1=self._history_producer_authority,
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
                _security_writer_v1=self._history_producer_authority,
            )

    def prepare_handler(
        self,
        handler: HandlerBase,
        handler_info: HandlerBaseInfo,
        handler_config: HandlerBaseConfigModel,
        *,
        _consumer_capability_v1: ConsumerCapabilityV1 | None = None,
    ):
        if (
            self._security_authority is not None
            and self._security_registrar_v1 is None
        ):
            raise RuntimeError("secure consumer registration is closed")
        consumer_capability = _consumer_capability_v1
        if self._security_authority is not None:
            if consumer_capability is None:
                consumer_capability = (
                    self._security_authority
                    ._issue_public_consumer_capability_v1(
                        self._security_registrar_v1
                    )
                )
            if consumer_capability is None:
                raise RuntimeError("secure consumer capability unavailable")
        producer_authority: ProducerAuthorityReferenceV1 | None = None
        if self._security_authority is not None:
            producer_authority = (
                self._security_authority._issue_producer_authority_v1(
                    self._security_registrar_v1,
                    consumer_capability
                )
            )
            if producer_authority is None:
                raise RuntimeError("secure producer authority unavailable")
        handler_env = HandlerEnv(handler_info=handler_info, handler=handler, config=handler_config)
        handler_env.consumer_capability = consumer_capability
        handler_env.history_capability = self._history_capability
        handler_env.producer_authority = producer_authority
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
            data_sink = DataSink(
                owner=handler_info.name,
                sink_queue=handler_env.input_queue,
                consume_info=input_info,
                consumer_capability=consumer_capability,
            )
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
                signal_filter=signal_filter,
                consumer_capability=consumer_capability,
                producer_authority=producer_authority,
            )
        core_data_submitter = ChatDataSubmitter(
            security_authority=self._security_authority,
            producer_authority=producer_authority,
        )
        handler_env.core_data_submitter = core_data_submitter
        handler_context.signal_emitter = self.signal_manager.get_emitter(
            handler_info.name,
            producer_authority=producer_authority,
        )
        # Set type mapping for override support - handlers can use original type names
        if output_type_mapping:
            core_data_submitter.set_output_type_mapping(
                output_type_mapping
            )
        # Inject session history for duplex conversation support
        if self._security_authority is None:
            handler_context.session_history = (
                self.session_context.session_history
            )
        else:
            handler_context.session_history = SessionHistoryConsumerViewV1(
                self.session_context.session_history,
                producer_authority,
            )
        # Inject stream_manager so handlers can query stream graph and create lifecycle streams
        if self._security_authority is None:
            handler_context.stream_manager = self.stream_manager
        else:
            handler_context.stream_manager = (
                self.stream_manager.create_consumer_view_v1(
                    producer_authority
                )
            )

        for output_type, output_data_info in handler_env.output_info.items():
            streamer = self.stream_manager.create_streamer(
                data_info=output_data_info,
                data_sinks=self.data_sinks,
                producer_name=handler_info.name,
                data_name=output_data_info.data_name,
                config=output_data_info.output_stream_config,
                producer_authority=producer_authority,
            )
            core_data_submitter.register_streamer(streamer)
        if self._security_authority is None:
            handler_context.data_submitter = core_data_submitter
        else:
            handler_context.data_submitter = (
                ChatDataSubmitterConsumerViewV1(core_data_submitter)
            )
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
        # Capability/producer issuance is construction-time only. Remove the
        # registrar before any handler lifecycle code can execute.
        if (
            self._security_authority is not None
            and (
                self._security_registrar_v1 is None
                or not self._security_authority.close_registration_v1(
                    self._security_registrar_v1
                )
            )
        ):
            raise RuntimeError("secure consumer registration close failed")
        self._security_registrar_v1 = None
        self.session_context.shared_states.active = True
        for handler_name, handler_record in self.handlers.items():
            start_args = (
                self.session_context,
                handler_record.env,
                self._security_authority,
            )
            handler_record.env.handler.start_context(self.session_context, handler_record.env.context)
            handler_record.pump_thread = threading.Thread(target=self.handler_pumper, args=start_args)
            handler_record.pump_thread.start()
        self.session_context.get_clock().start()

    def stop(self):
        self.session_context.shared_states.active = False
        for handler_name, handler_record in self.handlers.items():
            if handler_record.pump_thread:
                handler_record.pump_thread.join()
                handler_record.pump_thread = None
            while True:
                try:
                    handler_record.env.input_queue.get_nowait()
                except (queue.Empty, asyncio.QueueEmpty):
                    break
            handler_record.env.handler.destroy_context(handler_record.env.context)
        self.signal_manager.shutdown()
        self.handlers.clear()
        self.data_sinks.clear()
        self._playback_begin_event_ids.clear()
        self.session_context.cleanup()
        if self._security_authority is not None:
            self.stream_manager.release_secure_state_v1()
            self._security_authority.close()
        logger.info("chat session stopped")

    def get_timestamp(self):
        return self.session_context.get_clock().get_timestamp()

    def emit_signal(self, signal: ChatSignal):
        self.signal_manager.get_emitter("chat_session").emit(signal)

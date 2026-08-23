import queue
import threading

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Dict

from chat_engine.common.handler_base import HandlerBaseInfo, HandlerBase
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import HandlerBaseConfigModel
from chat_engine.contexts.handler_context import HandlerContext
from chat_engine.data_models.internal.handler_definition_data import HandlerDataInfo

if TYPE_CHECKING:
    from chat_engine.core.stream_manager import ChatDataSubmitter
    from chat_engine.security.dispatch import (
        ConsumerCapabilityV1,
        ProducerAuthorityReferenceV1,
    )


@dataclass
class HandlerRegistry:
    base_info: Optional[HandlerBaseInfo] = field(default=None)
    handler: Optional[HandlerBase] = field(default=None)
    handler_config: Optional[HandlerBaseConfigModel] = field(default=None)

@dataclass
class HandlerEnv:
    handler_info: HandlerBaseInfo
    handler: HandlerBase
    config: HandlerBaseConfigModel
    context: Optional[HandlerContext] = None
    input_queue: Optional[queue.Queue] = None
    output_info: Optional[Dict[ChatDataType, HandlerDataInfo]] = None
    # Reverse mapping for input type override: actual_type -> original_type
    # This allows handler code to see the original type it declared
    input_type_reverse_mapping: Optional[Dict[ChatDataType, ChatDataType]] = None
    # Output info with original type keys (before override) for handler.handle() calls
    # When output_type_override is used, output_info has overridden keys for stream management,
    # while handler_output_info has original keys so handler code can use its declared types
    handler_output_info: Optional[Dict[ChatDataType, HandlerDataInfo]] = None
    # Core-issued queue authorization. Never passed to handler code.
    consumer_capability: Optional["ConsumerCapabilityV1"] = None
    history_capability: Optional["ConsumerCapabilityV1"] = None
    producer_authority: Optional["ProducerAuthorityReferenceV1"] = None
    core_data_submitter: Optional["ChatDataSubmitter"] = None


@dataclass
class HandlerRecord:
    env: HandlerEnv
    pump_thread: Optional[threading.Thread] = None

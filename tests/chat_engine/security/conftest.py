from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import numpy as np
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = PROJECT_ROOT / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from security_harness import SecurityTestHarnessV1

from chat_engine.common.handler_base import HandlerBase
from chat_engine.contexts.handler_context import HandlerContext
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.chat_session import ChatSession
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import (
    ChatEngineConfigModel,
    HandlerBaseConfigModel,
)
from chat_engine.data_models.chat_signal import ChatSignal
from chat_engine.data_models.internal.handler_definition_data import (
    ChatDataConsumeMode,
    HandlerBaseInfo,
    HandlerDataInfo,
    HandlerDetail,
)
from chat_engine.data_models.runtime_data.data_bundle import (
    DataBundle,
    DataBundleDefinition,
    DataBundleEntry,
)
from chat_engine.data_models.session_info_data import SessionInfoData
from chat_engine.security.authority import SecurityAuthorityV1


class SyntheticAdmissionV1:
    """Non-secret stand-in for the already-consumed Milestone 1 admission."""


class RecordingHandlerV1(HandlerBase):
    def __init__(
        self,
        *,
        inputs: tuple[ChatDataType, ...],
        outputs: tuple[ChatDataType, ...] = (),
        input_priority: int = 0,
        consume_mode: ChatDataConsumeMode = ChatDataConsumeMode.DEFAULT,
        mutate: Callable[[ChatData], None] | None = None,
        output_factory: (Callable[[HandlerContext, ChatData], Any] | None) = None,
        signal_action: (Callable[[HandlerContext, ChatSignal], None] | None) = None,
    ):
        super().__init__()
        self.input_types = inputs
        self.output_types = outputs
        self.input_priority = input_priority
        self.consume_mode = consume_mode
        self.mutate = mutate
        self.output_factory = output_factory
        self.signal_action = signal_action
        self.received: list[ChatData] = []
        self.signals: list[ChatSignal] = []
        self.context: HandlerContext | None = None

    def get_handler_info(self) -> HandlerBaseInfo:
        return HandlerBaseInfo(config_model=HandlerBaseConfigModel)

    def load(
        self,
        engine_config: ChatEngineConfigModel,
        handler_config: HandlerBaseConfigModel | None = None,
    ):
        return None

    def create_context(
        self,
        session_context: SessionContext,
        handler_config: HandlerBaseConfigModel | None = None,
    ) -> HandlerContext:
        self.context = HandlerContext(session_context.session_info.session_id)
        return self.context

    def warmup_context(
        self,
        session_context: SessionContext,
        handler_context: HandlerContext,
    ):
        return None

    def start_context(
        self,
        session_context: SessionContext,
        handler_context: HandlerContext,
    ):
        return None

    @staticmethod
    def _text_definition(name: str) -> DataBundleDefinition:
        definition = DataBundleDefinition()
        definition.add_entry(DataBundleEntry.create_text_entry(name))
        return definition

    def get_handler_detail(
        self,
        session_context: SessionContext,
        context: HandlerContext,
    ) -> HandlerDetail:
        return HandlerDetail(
            inputs={
                data_type: HandlerDataInfo(
                    type=data_type,
                    input_priority=self.input_priority,
                    input_consume_mode=self.consume_mode,
                )
                for data_type in self.input_types
            },
            outputs={
                data_type: HandlerDataInfo(
                    type=data_type,
                    definition=self._text_definition(data_type.value),
                )
                for data_type in self.output_types
            },
        )

    def on_signal(
        self,
        context: HandlerContext,
        signal: ChatSignal,
    ):
        self.signals.append(signal)
        if self.signal_action is not None:
            self.signal_action(context, signal)

    def handle(
        self,
        context: HandlerContext,
        inputs: ChatData,
        output_definitions: dict[ChatDataType, HandlerDataInfo],
    ):
        self.received.append(inputs)
        if self.mutate is not None:
            self.mutate(inputs)
        if self.output_factory is not None:
            return self.output_factory(context, inputs)
        return None

    def destroy_context(self, context: HandlerContext):
        return None


def make_text_chat_data(
    text: str,
    *,
    data_type: ChatDataType = ChatDataType.HUMAN_TEXT,
    metadata: dict[str, Any] | None = None,
) -> ChatData:
    definition = DataBundleDefinition()
    definition.add_entry(DataBundleEntry.create_text_entry("text"))
    bundle = DataBundle(definition)
    bundle.set_main_data(text)
    if metadata:
        bundle.metadata.update(metadata)
    return ChatData(type=data_type, data=bundle)


def make_array_chat_data(
    value: np.ndarray,
    *,
    data_type: ChatDataType = ChatDataType.CAMERA_VIDEO,
    metadata: dict[str, Any] | None = None,
) -> ChatData:
    definition = DataBundleDefinition()
    definition.add_entry(
        DataBundleEntry.create_framed_entry(
            "array",
            list(value.shape),
            0,
        )
    )
    bundle = DataBundle(definition)
    bundle.set_main_data(value)
    if metadata:
        bundle.metadata.update(metadata)
    return ChatData(type=data_type, data=bundle)


def wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float = 2.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not reached before timeout")


def prepare_handler(
    session: ChatSession,
    name: str,
    handler: RecordingHandlerV1,
    *,
    config: HandlerBaseConfigModel | None = None,
):
    info = handler.get_handler_info()
    info.name = name
    return session.prepare_handler(
        handler,
        info,
        config or HandlerBaseConfigModel(),
    )


def prepare_private_handler(
    harness: SecurityTestHarnessV1,
    name: str,
    handler: RecordingHandlerV1,
    *,
    config: HandlerBaseConfigModel | None = None,
):
    info = handler.get_handler_info()
    info.name = name
    return harness.register_private_handler(
        handler,
        info,
        config or HandlerBaseConfigModel(),
    )


@pytest.fixture
def secure_session():
    context = SessionContext(
        SessionInfoData(
            session_id=f"secure-test-{uuid4()}",
            timestamp_base=16_000,
        ),
        session_admission=SyntheticAdmissionV1(),
    )
    (
        authority,
        registrar,
        private_issuer,
    ) = SecurityAuthorityV1._create_for_test_v1()
    session = ChatSession(
        context,
        ChatEngineConfigModel(),
        _security_authority_v1=authority,
        _security_registrar_v1=registrar,
    )
    try:
        yield (
            session,
            SecurityTestHarnessV1(
                session,
                private_issuer,
            ),
        )
    finally:
        session.stop()


@pytest.fixture
def legacy_session():
    context = SessionContext(
        SessionInfoData(
            session_id=f"legacy-test-{uuid4()}",
            timestamp_base=16_000,
        )
    )
    session = ChatSession(context, ChatEngineConfigModel())
    try:
        yield session
    finally:
        session.stop()

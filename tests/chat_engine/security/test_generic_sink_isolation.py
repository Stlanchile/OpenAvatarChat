from __future__ import annotations

import numpy as np
from conftest import (
    RecordingHandlerV1,
    make_array_chat_data,
    make_text_chat_data,
    prepare_handler,
    prepare_private_handler,
    wait_until,
)

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from handlers.agent.chat_agent_handler import (
    ChatAgentConfig,
    ChatAgentHandler,
)
from handlers.agent.perception.perception_handler import (
    PerceptionConfig,
    PerceptionHandler,
)
from handlers.client.rtc_client.client_handler_rtc import (
    ClientHandlerRtc,
    ClientRtcConfigModel,
)
from handlers.client.ws_client.ws_client_handler import (
    WsClientConfigModel,
    WsClientHandler,
)
from handlers.manager.data_tool_models import DataToolConfig
from handlers.manager.handler_data_tool import HandlerDataTool
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    HandlerTTS as BailianTTSHandler,
)
from handlers.tts.bailian_tts.tts_handler_cosyvoice_bailian import (
    TTSConfig as BailianTTSConfig,
)


def test_private_canaries_never_reach_any_generic_functional_sink(
    secure_session,
):
    session, harness = secure_session
    sink_inputs = {
        "ChatAgent": (
            ChatDataType.HUMAN_TEXT,
            ChatDataType.PERCEPTION_CONTEXT,
            ChatDataType.ENVIRONMENT_EVENT,
        ),
        "Perception": (ChatDataType.CAMERA_VIDEO,),
        "HandlerDataTool": (
            ChatDataType.HUMAN_TEXT,
            ChatDataType.CAMERA_VIDEO,
            ChatDataType.AVATAR_TEXT,
            ChatDataType.AVATAR_AUDIO,
        ),
        "GenericTTS": (ChatDataType.AVATAR_TEXT,),
        "GenericWsClientOutput": (
            ChatDataType.HUMAN_TEXT,
            ChatDataType.AVATAR_TEXT,
            ChatDataType.AVATAR_AUDIO,
        ),
        "GenericRtcOutput": (
            ChatDataType.HUMAN_TEXT,
            ChatDataType.AVATAR_TEXT,
            ChatDataType.AVATAR_AUDIO,
            ChatDataType.AVATAR_VIDEO,
        ),
        "GenericWritebackMemory": (
            ChatDataType.HUMAN_TEXT,
            ChatDataType.PERCEPTION_CONTEXT,
        ),
    }
    generic_sinks = {}
    for name, inputs in sink_inputs.items():
        handler = RecordingHandlerV1(inputs=inputs)
        generic_sinks[name] = handler
        prepare_handler(session, name, handler)

    private_sink = RecordingHandlerV1(
        inputs=tuple(
            {data_type for inputs in sink_inputs.values() for data_type in inputs}
        )
    )
    prepare_private_handler(harness, "synthetic-authorized-private", private_sink)
    session.start()

    private_packets = [
        make_text_chat_data(
            "private-human-text",
            data_type=ChatDataType.HUMAN_TEXT,
        ),
        make_array_chat_data(
            np.zeros((1, 2, 3), dtype=np.uint8),
            data_type=ChatDataType.CAMERA_VIDEO,
        ),
        make_text_chat_data(
            "private-avatar-text",
            data_type=ChatDataType.AVATAR_TEXT,
        ),
        make_array_chat_data(
            np.zeros((1, 8), dtype=np.float32),
            data_type=ChatDataType.AVATAR_AUDIO,
        ),
    ]
    for packet in private_packets:
        harness.dispatch_private(packet)
    wait_until(lambda: len(private_sink.received) == len(private_packets))

    assert all(handler.received == [] for handler in generic_sinks.values())
    assert session.session_context.session_history._events == []


def test_real_handler_data_tool_gets_public_but_never_private(
    secure_session,
):
    session, harness = secure_session
    handler = HandlerDataTool()
    config = DataToolConfig()
    handler.load(ChatEngineConfigModel(), config)
    info = handler.get_handler_info()
    info.name = "real-handler-data-tool"
    session.prepare_handler(handler, info, config)
    session.start()

    harness.dispatch_public(make_text_chat_data("ordinary-manager-data"))
    wait_until(
        lambda: any(
            item.get("data", {}).get("text") == "ordinary-manager-data"
            for item in handler.data_service.get_snapshot(
                session.session_context.session_info.session_id
            )
        )
    )
    snapshot_count = len(
        handler.data_service.get_snapshot(
            session.session_context.session_info.session_id
        )
    )

    harness.dispatch_private(make_text_chat_data("private-manager-canary"))
    wait_until(lambda: bool(harness.audit_events()))

    snapshot = handler.data_service.get_snapshot(
        session.session_context.session_info.session_id
    )
    assert len(snapshot) == snapshot_count
    assert "private-manager-canary" not in repr(snapshot)


def test_real_chatagent_perception_ws_and_rtc_queues_deny_private(
    secure_session,
):
    session, harness = secure_session
    engine_config = ChatEngineConfigModel()

    handlers_and_configs = [
        ("real-chat-agent", ChatAgentHandler(), ChatAgentConfig()),
        ("real-perception", PerceptionHandler(), PerceptionConfig()),
        ("real-ws-client", WsClientHandler(), WsClientConfigModel()),
        ("real-rtc-client", ClientHandlerRtc(), ClientRtcConfigModel()),
        (
            "real-generic-tts",
            BailianTTSHandler(),
            BailianTTSConfig(),
        ),
    ]
    environments = {}
    for name, handler, config in handlers_and_configs:
        handler.load(engine_config, config)
        info = handler.get_handler_info()
        info.name = name
        environments[name] = session.prepare_handler(
            handler,
            info,
            config,
        )

    public_packets = [
        make_text_chat_data(
            "public-chat-agent",
            data_type=ChatDataType.HUMAN_TEXT,
        ),
        make_array_chat_data(
            np.zeros((1, 2, 3), dtype=np.uint8),
            data_type=ChatDataType.CAMERA_VIDEO,
        ),
        make_text_chat_data(
            "public-avatar-text",
            data_type=ChatDataType.AVATAR_TEXT,
        ),
    ]
    for packet in public_packets:
        harness.dispatch_public(packet)

    assert environments["real-chat-agent"].input_queue.qsize() >= 1
    assert environments["real-perception"].input_queue.qsize() == 1
    assert environments["real-ws-client"].input_queue.qsize() >= 1
    assert environments["real-rtc-client"].input_queue.qsize() >= 1
    assert environments["real-generic-tts"].input_queue.qsize() == 1
    for environment in environments.values():
        while not environment.input_queue.empty():
            environment.input_queue.get_nowait()

    private_packets = [
        make_text_chat_data(
            "private-chat-agent-canary",
            data_type=ChatDataType.HUMAN_TEXT,
        ),
        make_array_chat_data(
            np.ones((1, 2, 3), dtype=np.uint8),
            data_type=ChatDataType.CAMERA_VIDEO,
        ),
        make_text_chat_data(
            "private-client-tts-canary",
            data_type=ChatDataType.AVATAR_TEXT,
        ),
    ]
    for packet in private_packets:
        harness.dispatch_private(packet)

    assert all(environment.input_queue.empty() for environment in environments.values())

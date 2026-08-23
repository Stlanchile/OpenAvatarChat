from __future__ import annotations

from conftest import (
    RecordingHandlerV1,
    make_text_chat_data,
    prepare_handler,
    wait_until,
)

from chat_engine.chat_engine import ChatEngine
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from chat_engine.data_models.internal.handler_definition_data import (
    ChatDataConsumeMode,
    HandlerDataInfo,
)
from chat_engine.data_models.session_info_data import SessionInfoData


def test_disabled_session_keeps_legacy_naked_same_object_fanout(
    legacy_session,
):
    session = legacy_session
    sink_a = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    sink_b = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    env_a = prepare_handler(session, "legacy-a", sink_a)
    env_b = prepare_handler(session, "legacy-b", sink_b)
    streamer = session.stream_manager.create_streamer(
        data_info=HandlerDataInfo(type=ChatDataType.HUMAN_TEXT),
        data_sinks=session.data_sinks,
        producer_name="legacy-client",
    )

    packet = make_text_chat_data("legacy")
    streamer.stream_data(packet, finish_stream=True)

    queued_a = env_a.input_queue.get_nowait()
    queued_b = env_b.input_queue.get_nowait()
    assert queued_a is queued_b
    assert queued_a is packet


def test_disabled_session_preserves_priority_and_once_ordering(
    legacy_session,
):
    session = legacy_session
    first = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        input_priority=-1,
        consume_mode=ChatDataConsumeMode.ONCE,
    )
    second = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        input_priority=1,
    )
    env_first = prepare_handler(session, "legacy-first", first)
    env_second = prepare_handler(session, "legacy-second", second)
    session.sort_sinks()
    streamer = session.stream_manager.create_streamer(
        data_info=HandlerDataInfo(type=ChatDataType.HUMAN_TEXT),
        data_sinks=session.data_sinks,
        producer_name="legacy-client",
    )

    streamer.stream_data(make_text_chat_data("legacy-once"), finish_stream=True)

    assert env_first.input_queue.qsize() == 1
    assert env_second.input_queue.empty()


def test_disabled_public_history_and_generic_tts_input_remain_functional(
    legacy_session,
):
    session = legacy_session
    history_sink = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    tts_sink = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    prepare_handler(session, "legacy-history", history_sink)
    prepare_handler(session, "legacy-generic-tts", tts_sink)
    text_streamer = session.stream_manager.create_streamer(
        data_info=HandlerDataInfo(type=ChatDataType.HUMAN_TEXT),
        data_sinks=session.data_sinks,
        producer_name="legacy-client",
    )
    avatar_streamer = session.stream_manager.create_streamer(
        data_info=HandlerDataInfo(type=ChatDataType.AVATAR_TEXT),
        data_sinks=session.data_sinks,
        producer_name="legacy-agent",
    )
    session.start()

    text_streamer.stream_data(
        make_text_chat_data("legacy-history"),
        finish_stream=True,
    )
    avatar_streamer.stream_data(
        make_text_chat_data(
            "legacy-tts",
            data_type=ChatDataType.AVATAR_TEXT,
        ),
        finish_stream=True,
    )
    wait_until(lambda: len(history_sink.received) == len(tts_sink.received) == 1)

    assert history_sink.received[0].data.get_main_data() == "legacy-history"
    assert tts_sink.received[0].data.get_main_data() == "legacy-tts"
    assert session.session_context.session_history._events


def test_enabled_engine_cannot_create_legacy_unclassified_session():
    engine = ChatEngine()
    engine._certificate_capture_enabled_v1 = True

    try:
        engine._create_session(
            SessionInfoData(
                session_id="missing-secure-admission",
                timestamp_base=16_000,
            )
        )
    except RuntimeError as error:
        assert str(error) == (
            "secure dispatch requires authenticated session admission"
        )
    else:
        raise AssertionError("enabled engine accepted a legacy session")


def test_disabled_engine_keeps_legacy_session_creation():
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )

    session = engine._create_session(
        SessionInfoData(
            session_id="disabled-legacy-session",
            timestamp_base=16_000,
        )
    )
    try:
        assert session._security_authority is None
    finally:
        session.stop()

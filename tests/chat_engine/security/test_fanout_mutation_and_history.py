from __future__ import annotations

import numpy as np
import pytest
from conftest import (
    RecordingHandlerV1,
    make_array_chat_data,
    make_text_chat_data,
    prepare_handler,
    prepare_private_handler,
    wait_until,
)

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_signal import ChatSignal
from chat_engine.data_models.chat_signal_type import (
    ChatSignalSourceType,
    ChatSignalType,
)
from chat_engine.data_models.chat_stream import ChatStreamIdentity
from chat_engine.data_models.chat_stream_config import ChatStreamConfig
from chat_engine.data_models.internal.handler_definition_data import (
    ChatDataConsumeMode,
)
from chat_engine.security.envelope import SecurityClassificationV1


@pytest.mark.parametrize("generic_first", [True, False])
def test_priority_registration_and_once_cannot_bypass_private_policy(
    secure_session,
    generic_first,
):
    session, harness = secure_session
    generic_once = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        input_priority=-100,
        consume_mode=ChatDataConsumeMode.ONCE,
    )
    private_sink = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        input_priority=100,
    )
    registrations = [
        ("generic-once", generic_once, False),
        ("private", private_sink, True),
    ]
    if not generic_first:
        registrations.reverse()
    for name, handler, private in registrations:
        if private:
            prepare_private_handler(harness, name, handler)
        else:
            prepare_handler(session, name, handler)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-once-canary"))
    wait_until(lambda: len(private_sink.received) == 1)

    assert generic_once.received == []
    assert private_sink.received[0].data.get_main_data() == ("private-once-canary")


def test_authorized_private_once_preserves_functional_once_semantics(
    secure_session,
):
    session, harness = secure_session
    first = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        input_priority=-1,
        consume_mode=ChatDataConsumeMode.ONCE,
    )
    second = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        input_priority=1,
    )
    prepare_private_handler(harness, "first-private-once", first)
    prepare_private_handler(harness, "second-private", second)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-once"))
    wait_until(lambda: len(first.received) == 1)

    assert second.received == []


def test_each_secure_consumer_gets_isolated_mutable_state_and_read_only_array(
    secure_session,
):
    session, harness = secure_session
    mutation_results: list[str] = []

    def mutate(inputs):
        inputs.type = ChatDataType.AVATAR_TEXT
        inputs.source = "mutated-source"
        inputs.data.metadata["nested"]["value"] = "mutated"
        inputs.data.metadata["new"] = "mutated"
        definition_entry = inputs.data.definition.get_main_entry()
        definition_entry.name = "mutated-entry"
        definition_entry.shape.append(999)
        array = inputs.data.get_main_data()
        assert not array.flags.writeable
        try:
            array.flat[0] = 999
        except ValueError:
            mutation_results.append("read-only")

    sink_a = RecordingHandlerV1(
        inputs=(ChatDataType.CAMERA_VIDEO,),
        mutate=mutate,
    )
    sink_b = RecordingHandlerV1(inputs=(ChatDataType.CAMERA_VIDEO,))
    prepare_handler(session, "sink-a", sink_a)
    prepare_handler(session, "sink-b", sink_b)
    session.start()

    original = np.arange(12, dtype=np.uint8).reshape(2, 2, 3)
    harness.dispatch_public(
        make_array_chat_data(
            original,
            metadata={"nested": {"value": "original"}},
        )
    )
    wait_until(lambda: len(sink_a.received) == len(sink_b.received) == 1)

    received_b = sink_b.received[0]
    assert mutation_results == ["read-only"]
    assert received_b.type is ChatDataType.CAMERA_VIDEO
    assert received_b.source == "core_synthetic_public_v1"
    assert received_b.data.metadata == {"nested": {"value": "original"}}
    assert received_b.data.definition.get_main_entry().name == "array"
    assert received_b.data.definition.get_main_entry().shape == [2, 2, 3]
    np.testing.assert_array_equal(received_b.data.get_main_data(), original)
    assert sink_a.received[0] is not received_b
    assert sink_a.received[0].data is not received_b.data
    assert (
        harness.classification_for_stream(received_b.stream_id)
        is SecurityClassificationV1.PUBLIC_CHAT
    )


def test_private_authorized_dispatch_never_enters_generic_history(
    secure_session,
):
    session, harness = secure_session
    private_sink = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_private_handler(harness, "private-history-probe", private_sink)
    session.start()

    harness.dispatch_private(make_text_chat_data("history-private-canary"))
    wait_until(lambda: len(private_sink.received) == 1)

    history = session.session_context.session_history
    assert history._events == []
    assert history._stream_accumulators == {}
    assert history.export_for_summary() == []


def test_private_handler_cannot_write_through_context_or_raw_history(
    secure_session,
):
    session, harness = secure_session
    canary = "private-direct-history-canary"
    write_results: list[object] = []

    def attack_history(context, _inputs):
        write_results.append(context.session_history.create_and_add_event(data=canary))
        write_results.append(
            session.session_context.session_history.create_and_add_event(data=canary)
        )
        write_results.append(
            context.session_history.accumulate_stream_data(
                "forged-private-stream",
                canary,
            )
        )

    attacker = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        output_factory=attack_history,
    )
    prepare_private_handler(harness, "private-history-attacker", attacker)
    session.start()

    harness.dispatch_private(make_text_chat_data(canary))
    wait_until(lambda: len(attacker.received) == 1)

    history = session.session_context.session_history
    assert write_results == [None, None, False]
    assert history._events == []
    assert history._stream_accumulators == {}
    assert canary not in repr(history.export_for_summary())


def test_private_handler_cannot_mutate_live_generic_history_reads(
    secure_session,
):
    session, harness = secure_session
    public_text = "public-history-seed"
    private_canary = "private-history-read-mutation-canary"
    attack_enabled = False
    observed_reads = []

    def mutate_history_reads(context, _inputs):
        if not attack_enabled:
            return
        context_events = context.session_history.get_recent_events()
        raw_events = (
            session.session_context.session_history.get_recent_events()
        )
        assert context_events
        assert raw_events
        context_events[-1].data = private_canary
        raw_events[-1].data = private_canary
        observed_reads.extend((context_events[-1], raw_events[-1]))

    public_sink = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    private_attacker = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        output_factory=mutate_history_reads,
    )
    prepare_handler(session, "public-history-seeder", public_sink)
    prepare_private_handler(
        harness,
        "private-history-read-attacker",
        private_attacker,
    )
    session.start()

    harness.dispatch_public(make_text_chat_data(public_text))
    wait_until(
        lambda: (
            len(session.session_context.session_history._events) == 2
            and len(private_attacker.received) == 1
        )
    )
    attack_enabled = True
    harness.dispatch_private(make_text_chat_data(private_canary))
    wait_until(lambda: len(observed_reads) == 2)

    history = session.session_context.session_history
    assert observed_reads[0].data == private_canary
    assert observed_reads[1].data == private_canary
    assert [event.data for event in history._events] == [None, public_text]
    assert private_canary not in repr(history.export_for_summary())


def test_denied_private_dispatch_creates_no_history_or_accumulator(
    secure_session,
):
    session, harness = secure_session
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_handler(session, "generic-history-probe", generic)
    session.start()

    harness.dispatch_private(make_text_chat_data("denied-history-canary"))
    wait_until(lambda: bool(harness.audit_events()))

    history = session.session_context.session_history
    assert generic.received == []
    assert history._events == []
    assert history._stream_accumulators == {}


def test_public_history_behavior_remains_functional_in_secure_session(
    secure_session,
):
    session, harness = secure_session
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_handler(session, "public-history", generic)
    session.start()

    harness.dispatch_public(make_text_chat_data("public-history"))
    wait_until(lambda: len(session.session_context.session_history._events) == 2)

    events = session.session_context.session_history._events
    assert [event.signal_type for event in events] == [
        ChatSignalType.STREAM_BEGIN,
        ChatSignalType.STREAM_END,
    ]
    assert events[-1].data == "public-history"


def test_private_lifecycle_signal_cannot_create_playback_history(
    secure_session,
):
    session, harness = secure_session

    def open_private_playback(context, _inputs):
        streamer = context.stream_manager.create_lifecycle_streamer(
            data_type=ChatDataType.CLIENT_PLAYBACK,
            producer_name="synthetic-private-playback",
            config=ChatStreamConfig(cancelable=False),
        )
        streamer.open_stream(sources=[])
        streamer.finish_current()

    private_handler = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        output_factory=open_private_playback,
    )
    prepare_private_handler(harness, "private-playback", private_handler)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-playback-canary"))
    wait_until(lambda: len(private_handler.received) == 1)

    assert session.session_context.session_history._events == []


def test_generic_stream_inspection_cannot_enumerate_private_metadata(
    secure_session,
):
    session, harness = secure_session
    canary = "private-stream-metadata-canary"
    private_stream_ids = []

    def open_private_stream(context, _inputs):
        streamer = context.stream_manager.create_lifecycle_streamer(
            data_type=ChatDataType.CLIENT_PLAYBACK,
            producer_name="private-metadata-stream",
            config=ChatStreamConfig(cancelable=True),
        )
        private_stream_ids.append(
            streamer.open_stream(
                sources=[],
                meta={"private_canary": canary},
            )
        )

    private_handler = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        output_factory=open_private_stream,
    )
    generic_probe = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        outputs=(ChatDataType.CLIENT_PLAYBACK,),
    )
    prepare_private_handler(harness, "private-metadata-owner", private_handler)
    prepare_handler(session, "generic-stream-inspector", generic_probe)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-parent"))
    wait_until(lambda: len(private_stream_ids) == 1)

    private_views = private_handler.context.stream_manager.get_active_streams()
    assert any(view.metadata.get("private_canary") == canary for view in private_views)

    generic_manager = generic_probe.context.stream_manager
    assert all(
        canary not in repr(view.metadata)
        for view in generic_manager.get_active_streams()
    )
    audit_count = len(harness.audit_events())
    generic_probe.context.emit_signal(
        ChatSignal(
            type=ChatSignalType.STREAM_END,
            source_type=ChatSignalSourceType.HANDLER,
            related_stream=private_stream_ids[0],
            signal_data={"forged_private_source": canary},
        )
    )
    wait_until(lambda: len(harness.audit_events()) > audit_count)
    assert all(
        signal.signal_data != {"forged_private_source": canary}
        for signal in (
            *generic_probe.signals,
            *private_handler.signals,
        )
    )
    assert generic_manager.find_stream(private_stream_ids[0]) is None
    assert generic_manager.get_stream_ancestry(private_stream_ids[0]) == {
        "parents": [],
        "ancestors": [],
        "cancelable": [],
    }
    assert generic_manager.cancel_stream_chain(private_stream_ids[0]) == []
    generic_output_streamer = generic_probe.context.data_submitter.get_streamer(
        ChatDataType.CLIENT_PLAYBACK
    )
    assert generic_output_streamer.find_stream(private_stream_ids[0]) is None
    forged_identity = ChatStreamIdentity(
        data_type=ChatDataType.HUMAN_TEXT,
        builder_id=private_stream_ids[0].builder_id,
        stream_id=private_stream_ids[0].stream_id,
        name="forged-private-stream",
        producer_name="generic-stream-inspector",
    )
    assert generic_output_streamer.find_stream(forged_identity) is None
    assert generic_output_streamer.cancel_stream(forged_identity) is False
    forged_streamer = generic_manager.create_lifecycle_streamer(
        data_type=ChatDataType.CLIENT_PLAYBACK,
        producer_name="generic-forged-private-parent",
        config=ChatStreamConfig(cancelable=True),
    )
    assert (
        forged_streamer.open_stream(
            sources=[private_stream_ids[0]],
            meta={"forged": canary},
        )
        is None
    )
    assert all(
        canary not in repr(view.metadata)
        for view in generic_manager.get_active_streams()
    )

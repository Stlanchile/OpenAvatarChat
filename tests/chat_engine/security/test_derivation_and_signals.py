from __future__ import annotations

from conftest import (
    RecordingHandlerV1,
    make_text_chat_data,
    prepare_handler,
    prepare_private_handler,
    wait_until,
)

from chat_engine.core.stream_manager import SecurityStreamRejectedV1
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_engine_config_data import HandlerBaseConfigModel
from chat_engine.data_models.chat_signal import ChatSignal
from chat_engine.data_models.chat_signal_type import (
    ChatSignalSourceType,
    ChatSignalType,
)
from chat_engine.data_models.internal.handler_definition_data import (
    HandlerDataInfo,
)
from chat_engine.data_models.runtime_data.data_bundle import DataBundle
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.envelope import SecurityClassificationV1


def _derived_text(context, text: str, output_type: ChatDataType):
    streamer = context.data_submitter.get_streamer(output_type)
    bundle = DataBundle(streamer.data_definition)
    bundle.set_main_data(text)
    return bundle


def test_multi_parent_lineage_uses_most_restrictive_classification(
    secure_session,
):
    _, harness = secure_session
    public_a = harness.issue_public_envelope()
    public_b = harness.issue_public_envelope()
    private = harness.issue_private_envelope()

    public_derived = harness.derive_envelope((public_a, public_b))
    mixed_derived = harness.derive_envelope((public_a, private))
    private_derived = harness.derive_envelope((private, private))

    assert (
        harness.envelope(public_derived).classification
        is SecurityClassificationV1.PUBLIC_CHAT
    )
    assert (
        harness.envelope(mixed_derived).classification
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )
    assert (
        harness.envelope(private_derived).classification
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )
    mixed = harness.envelope(mixed_derived)
    assert mixed.lineage.parent_envelope_ids == (
        public_a.envelope_id,
        private.envelope_id,
    )


def test_private_to_requested_public_is_forced_private_and_audited(
    secure_session,
):
    _, harness = secure_session
    private = harness.issue_private_envelope()

    derived = harness.derive_envelope(
        (private,),
        requested_classification=SecurityClassificationV1.PUBLIC_CHAT,
    )

    assert (
        harness.envelope(derived).classification
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )
    assert any(
        event.code is SecurityAuditEventCodeV1.ILLEGAL_CLASSIFICATION_DOWNGRADE
        for event in harness.audit_events()
    )


def test_private_handler_output_inherits_private_and_generic_egress_is_denied(
    secure_session,
):
    session, harness = secure_session

    def output(context, _inputs):
        return _derived_text(
            context,
            "derived-private-canary",
            ChatDataType.AVATAR_TEXT,
        )

    transformer = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        outputs=(ChatDataType.AVATAR_TEXT,),
        output_factory=output,
    )
    private_sink = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    generic_egress = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    prepare_private_handler(harness, "private-transformer", transformer)
    prepare_private_handler(harness, "private-output-sink", private_sink)
    prepare_handler(session, "generic-client-egress", generic_egress)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-parent"))
    wait_until(lambda: len(private_sink.received) == 1)

    derived = private_sink.received[0]
    assert derived.data.get_main_data() == "derived-private-canary"
    assert (
        harness.classification_for_stream(derived.stream_id)
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )
    assert generic_egress.received == []


def test_handler_new_stream_and_public_metadata_cannot_erase_private_ancestry(
    secure_session,
):
    session, harness = secure_session

    def output(context, _inputs):
        streamer = context.data_submitter.get_streamer(ChatDataType.AVATAR_TEXT)
        streamer.new_stream([])
        bundle = DataBundle(streamer.data_definition)
        bundle.set_main_data("new-stream-private")
        bundle.metadata["classification"] = "PUBLIC_CHAT"
        return ChatData(
            type=ChatDataType.AVATAR_TEXT,
            source="forged-public-source",
            data=bundle,
        )

    transformer = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        outputs=(ChatDataType.AVATAR_TEXT,),
        output_factory=output,
    )
    private_sink = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    generic = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    prepare_private_handler(harness, "new-stream-transformer", transformer)
    prepare_private_handler(harness, "private-new-stream-sink", private_sink)
    prepare_handler(session, "generic-new-stream-sink", generic)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-parent"))
    wait_until(lambda: len(private_sink.received) == 1)

    assert generic.received == []
    assert (
        harness.classification_for_stream(private_sink.received[0].stream_id)
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )


def test_registry_owned_lineage_survives_handler_local_tampering(
    secure_session,
):
    session, harness = secure_session
    observations: dict[str, bool] = {}

    def output(context, _inputs):
        import chat_engine.security.authority as authority_module

        submitter = object.__getattribute__(
            context.data_submitter,
            "_ChatDataSubmitterConsumerViewV1__submitter",
        )
        observations["no_mutable_submitter_lineage"] = not hasattr(
            submitter,
            "_active_security_dispatches",
        )
        streamer_view = context.data_submitter.get_streamer(ChatDataType.AVATAR_TEXT)
        streamer = object.__getattribute__(
            streamer_view,
            "_ChatStreamerConsumerViewV1__streamer",
        )
        streamer._input_security_refs.clear()

        manager = object.__getattribute__(
            context.stream_manager,
            "_StreamManagerConsumerViewV1__manager",
        )
        authority = submitter._security_authority
        observations["producer_registry_not_reachable"] = not hasattr(
            authority,
            "_producer_authorities",
        )
        observations["raw_state_setter_not_importable"] = not hasattr(
            authority_module,
            "_set_producer_state_v1",
        )
        producer_state = authority_module._get_producer_state_v1(
            authority,
            submitter._producer_authority.producer_authority_id,
        )
        observations["producer_lineage_is_immutable"] = isinstance(
            producer_state.envelope_refs,
            tuple,
        )
        observations["registrar_removed_before_handle"] = (
            session._security_registrar_v1 is None
        )
        observations["public_capability_mint_rejected"] = (
            authority._issue_public_consumer_capability_v1(None) is None
        )
        observations["public_root_mint_rejected"] = (
            authority._issue_public_root_v1(None) is None
        )
        regenerated_registrar = authority._new_registrar_v1()
        observations["regenerated_registrar_rejected"] = (
            authority._issue_public_consumer_capability_v1(regenerated_registrar)
            is None
        )
        public_sink_capability = next(
            sink.consumer_capability
            for sink in streamer._data_sinks[ChatDataType.AVATAR_TEXT]
            if sink.owner == "lineage-generic-sink"
        )
        observations["public_producer_mint_rejected"] = (
            authority._issue_producer_authority_v1(
                None,
                public_sink_capability,
            )
            is None
        )
        try:
            manager.create_streamer(
                data_info=HandlerDataInfo(type=ChatDataType.AVATAR_TEXT),
                data_sinks=session.data_sinks,
                producer_name="handler-forged-unbound-streamer",
            )
        except SecurityStreamRejectedV1:
            observations["raw_unbound_stream_rejected"] = True

        return _derived_text(
            context,
            "registry-lineage-private",
            ChatDataType.AVATAR_TEXT,
        )

    transformer = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        outputs=(ChatDataType.AVATAR_TEXT,),
        output_factory=output,
    )
    private_sink = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    generic_sink = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    prepare_private_handler(harness, "lineage-tamper", transformer)
    prepare_private_handler(harness, "lineage-private-sink", private_sink)
    prepare_handler(session, "lineage-generic-sink", generic_sink)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-parent"))
    wait_until(lambda: len(private_sink.received) == 1)

    assert observations == {
        "no_mutable_submitter_lineage": True,
        "public_capability_mint_rejected": True,
        "public_producer_mint_rejected": True,
        "public_root_mint_rejected": True,
        "producer_registry_not_reachable": True,
        "producer_lineage_is_immutable": True,
        "regenerated_registrar_rejected": True,
        "raw_state_setter_not_importable": True,
        "registrar_removed_before_handle": True,
        "raw_unbound_stream_rejected": True,
    }
    assert generic_sink.received == []
    assert (
        harness.classification_for_stream(private_sink.received[0].stream_id)
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )


def test_type_override_changes_functional_type_but_not_private_authority(
    secure_session,
):
    session, harness = secure_session

    def output(context, inputs):
        assert inputs.type is ChatDataType.HUMAN_TEXT
        return _derived_text(
            context,
            "override-private",
            ChatDataType.AVATAR_TEXT,
        )

    transformer = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        outputs=(ChatDataType.AVATAR_TEXT,),
        output_factory=output,
    )
    config = HandlerBaseConfigModel(
        input_type_override={"HUMAN_TEXT": "CAMERA_VIDEO"},
        output_type_override={"AVATAR_TEXT": "HUMAN_TEXT"},
    )
    private_sink = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_private_handler(
        harness,
        "override-transformer",
        transformer,
        config=config,
    )
    prepare_private_handler(harness, "private-override-sink", private_sink)
    prepare_handler(session, "generic-override-sink", generic)
    session.start()

    harness.dispatch_private(
        make_text_chat_data(
            "private-override-parent",
            data_type=ChatDataType.CAMERA_VIDEO,
        )
    )
    wait_until(lambda: len(private_sink.received) == 1)

    output_data = private_sink.received[0]
    assert output_data.type is ChatDataType.HUMAN_TEXT
    assert generic.received == []
    assert (
        harness.classification_for_stream(output_data.stream_id)
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )


def test_private_derived_signal_reaches_only_private_capability(
    secure_session,
):
    session, harness = secure_session
    canary = "private-signal-canary"

    def emit_private(context, _inputs):
        context.emit_signal(
            ChatSignal(
                type=ChatSignalType.ENVIRONMENT_EVENT,
                source_type=ChatSignalSourceType.HANDLER,
                signal_data={"value": canary},
            )
        )

    emitter = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        output_factory=emit_private,
    )
    private_listener = RecordingHandlerV1(inputs=())
    generic_listener = RecordingHandlerV1(inputs=())
    prepare_private_handler(harness, "private-signal-emitter", emitter)
    prepare_private_handler(harness, "private-signal-listener", private_listener)
    prepare_handler(session, "generic-signal-listener", generic_listener)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-signal-parent"))
    wait_until(
        lambda: any(
            signal.signal_data == {"value": canary}
            for signal in private_listener.signals
        )
    )

    assert all(
        signal.signal_data != {"value": canary} for signal in generic_listener.signals
    )


def test_untrusted_signal_dictionary_cannot_manufacture_private_authority(
    secure_session,
):
    session, _ = secure_session
    generic_listener = RecordingHandlerV1(inputs=())
    env = prepare_handler(session, "generic-signal-source", generic_listener)
    session.start()

    env.context.emit_signal(
        ChatSignal(
            type=ChatSignalType.ENVIRONMENT_EVENT,
            source_type=ChatSignalSourceType.CLIENT,
            signal_data={"classification": "CERTIFICATE_PRIVATE"},
        )
    )
    wait_until(
        lambda: any(
            signal.signal_data == {"classification": "CERTIFICATE_PRIVATE"}
            for signal in generic_listener.signals
        )
    )


def test_signal_with_unknown_stream_identity_fails_closed(
    secure_session,
):
    session, harness = secure_session
    generic_listener = RecordingHandlerV1(inputs=())
    env = prepare_handler(session, "unknown-stream-signal", generic_listener)
    session.start()

    from chat_engine.data_models.chat_stream import ChatStreamIdentity

    env.context.emit_signal(
        ChatSignal(
            type=ChatSignalType.STREAM_BEGIN,
            source_type=ChatSignalSourceType.CLIENT,
            related_stream=ChatStreamIdentity(
                data_type=ChatDataType.HUMAN_TEXT,
                builder_id=999_999,
                stream_id=999_999,
            ),
            signal_data={"value": "must-not-arrive"},
        )
    )
    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.INVALID_LINEAGE
            for event in harness.audit_events()
        )
    )

    assert all(
        signal.signal_data != {"value": "must-not-arrive"}
        for signal in generic_listener.signals
    )

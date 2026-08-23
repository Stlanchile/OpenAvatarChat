from __future__ import annotations

from dataclasses import replace

from conftest import (
    RecordingHandlerV1,
    make_text_chat_data,
    prepare_handler,
    prepare_private_handler,
    wait_until,
)
from loguru import logger

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.runtime_data.data_bundle import DataBundle
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.envelope import SecurityClassificationV1


def _queued_private_dispatch(session, harness):
    handler = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    env = prepare_private_handler(harness, "private-queue-probe", handler)
    harness.dispatch_private(make_text_chat_data("queued-private-canary"))
    return handler, env, env.input_queue.get_nowait()


def test_corrupt_dispatch_authenticator_fails_closed(secure_session):
    session, harness = secure_session
    handler, env, queued = _queued_private_dispatch(session, harness)
    env.input_queue.put(replace(queued, authenticator=b"corrupt"))
    session.start()

    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.DISPATCH_DENIED
            for event in harness.audit_events()
        )
    )
    assert handler.received == []
    assert session.session_context.session_history._events == []


def test_unknown_authority_id_fails_closed(secure_session):
    session, harness = secure_session
    handler, env, queued = _queued_private_dispatch(session, harness)
    env.input_queue.put(replace(queued, authority_id="unknown-authority"))
    session.start()

    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.ENVELOPE_MISSING
            for event in harness.audit_events()
        )
    )
    assert handler.received == []


def test_invalid_lineage_digest_fails_closed(secure_session):
    session, harness = secure_session
    handler, env, queued = _queued_private_dispatch(session, harness)
    env.input_queue.put(replace(queued, trusted_lineage_digest=b"invalid-lineage"))
    session.start()

    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.INVALID_LINEAGE
            for event in harness.audit_events()
        )
    )
    assert handler.received == []


def test_missing_registered_envelope_fails_closed(secure_session):
    session, harness = secure_session
    handler, env, queued = _queued_private_dispatch(session, harness)
    harness.remove_envelope(queued.envelope_ref)
    env.input_queue.put(queued)
    session.start()

    wait_until(
        lambda: any(
            event.code
            in {
                SecurityAuditEventCodeV1.ENVELOPE_MISSING,
                SecurityAuditEventCodeV1.INVALID_LINEAGE,
            }
            for event in harness.audit_events()
        )
    )
    assert handler.received == []


def test_dispatch_bound_to_another_consumer_capability_fails_closed(
    secure_session,
):
    session, harness = secure_session
    handler_a = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    handler_b = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    env_a = prepare_private_handler(harness, "private-a", handler_a)
    env_b = prepare_private_handler(harness, "private-b", handler_b)
    harness.dispatch_private(make_text_chat_data("capability-bound"))
    queued_for_a = env_a.input_queue.get_nowait()
    env_b.input_queue.get_nowait()
    env_b.input_queue.put(queued_for_a)
    session.start()

    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
            for event in harness.audit_events()
        )
    )
    assert handler_a.received == []
    assert handler_b.received == []


def test_registry_failure_fails_closed_before_handler_or_history(
    secure_session,
):
    session, harness = secure_session
    handler, env, queued = _queued_private_dispatch(session, harness)
    env.input_queue.put(queued)
    harness.fail_registry()
    session.start()

    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.REGISTRY_FAILURE
            for event in harness.audit_events()
        )
    )
    assert handler.received == []
    assert session.session_context.session_history._events == []


def test_validation_is_first_security_relevant_action_after_dequeue(
    secure_session,
):
    session, harness = secure_session
    handler = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    env = prepare_handler(session, "first-action-probe", handler)
    calls: list[str] = []
    original = env.core_data_submitter.update_input_dispatch_v1

    def recording_update(validated):
        calls.append("update")
        return original(validated)

    env.core_data_submitter.update_input_dispatch_v1 = recording_update
    env.input_queue.put(make_text_chat_data("naked-queue-canary"))
    session.start()

    wait_until(
        lambda: any(
            event.code is SecurityAuditEventCodeV1.ENVELOPE_MISSING
            for event in harness.audit_events()
        )
    )
    assert calls == []
    assert handler.received == []
    assert session.session_context.session_history._events == []


def test_private_canary_and_exception_text_are_absent_from_logs(
    secure_session,
):
    session, harness = secure_session
    canary = "PRIVATE-CANARY-DO-NOT-LOG-71b74d"
    captured: list[str] = []
    sink_id = logger.add(lambda message: captured.append(str(message)))

    def raise_canary(_inputs):
        raise RuntimeError(canary)

    private_handler = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        mutate=raise_canary,
    )
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_private_handler(harness, "private-log-probe", private_handler)
    prepare_handler(session, "generic-log-probe", generic)
    session.start()

    try:
        harness.dispatch_private(make_text_chat_data(canary))
        wait_until(lambda: len(private_handler.received) == 1)
        wait_until(
            lambda: any("PRIVATE_HANDLER_FAILURE_V1" in line for line in captured)
        )
    finally:
        logger.remove(sink_id)

    assert generic.received == []
    assert canary not in "".join(captured)
    assert canary not in repr(harness.audit_events())


def test_private_stream_name_and_lifecycle_are_redacted_from_logs(
    secure_session,
):
    session, harness = secure_session
    canary = "PRIVATE-STREAM-NAME-CANARY-9f1b"
    captured: list[str] = []
    sink_id = logger.add(lambda message: captured.append(str(message)))

    def named_output(context, _inputs):
        streamer = context.data_submitter.get_streamer(ChatDataType.AVATAR_TEXT)
        streamer.new_stream([], name=canary)
        bundle = DataBundle(streamer.data_definition)
        bundle.set_main_data("private-derived-output")
        return bundle

    transformer = RecordingHandlerV1(
        inputs=(ChatDataType.HUMAN_TEXT,),
        outputs=(ChatDataType.AVATAR_TEXT,),
        output_factory=named_output,
    )
    private_sink = RecordingHandlerV1(inputs=(ChatDataType.AVATAR_TEXT,))
    prepare_private_handler(harness, "private-named-stream", transformer)
    prepare_private_handler(harness, "private-named-sink", private_sink)
    session.start()

    try:
        harness.dispatch_private(make_text_chat_data("private-parent"))
        wait_until(lambda: len(private_sink.received) == 1)
    finally:
        logger.remove(sink_id)

    received = private_sink.received[0]
    assert received.stream_id.name is None
    assert (
        harness.classification_for_stream(received.stream_id)
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )
    assert canary not in "".join(captured)

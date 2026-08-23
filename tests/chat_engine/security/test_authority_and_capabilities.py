from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from conftest import (
    RecordingHandlerV1,
    make_text_chat_data,
    prepare_handler,
    prepare_private_handler,
    wait_until,
)

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.dispatch import PrivateTestIssuerCapabilityV1
from chat_engine.security.envelope import (
    EgressPolicyV1,
    RetentionPolicyV1,
    SecurityClassificationV1,
)


def test_core_issues_immutable_public_and_private_envelopes(
    secure_session,
):
    _, harness = secure_session
    public_ref = harness.issue_public_envelope()
    private_ref = harness.issue_private_envelope()

    public = harness.envelope(public_ref)
    private = harness.envelope(private_ref)

    assert public.classification is SecurityClassificationV1.PUBLIC_CHAT
    assert public.egress_policy is EgressPolicyV1.GENERIC
    assert public.retention_policy is RetentionPolicyV1.LEGACY_SESSION
    assert private.classification is SecurityClassificationV1.CERTIFICATE_PRIVATE
    assert private.egress_policy is EgressPolicyV1.INTERNAL_ONLY
    assert private.retention_policy is RetentionPolicyV1.EPHEMERAL_NO_GENERIC_RETENTION
    assert public.owning_session_authority_ref
    assert public.owning_session_authority_ref == private.owning_session_authority_ref
    with pytest.raises(FrozenInstanceError):
        private.classification = SecurityClassificationV1.PUBLIC_CHAT


def test_production_session_graph_retains_no_private_test_issuer(
    secure_session,
):
    session, _ = secure_session

    assert not hasattr(session, "_private_test_issuer_v1")
    assert not any(
        isinstance(value, PrivateTestIssuerCapabilityV1)
        for value in vars(session).values()
    )
    assert not any(
        isinstance(value, PrivateTestIssuerCapabilityV1)
        for value in vars(session._security_authority).values()
    )


@pytest.mark.parametrize(
    "metadata",
    [
        {"classification": "CERTIFICATE_PRIVATE"},
        {"security_envelope": {"classification": "CERTIFICATE_PRIVATE"}},
        {"sensitive": True},
    ],
)
def test_client_or_bundle_metadata_has_no_classification_authority(
    secure_session,
    metadata,
):
    session, harness = secure_session
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_handler(session, "generic", generic)
    session.start()

    harness.dispatch_public(make_text_chat_data("ordinary-public", metadata=metadata))
    wait_until(lambda: len(generic.received) == 1)

    received = generic.received[0]
    assert (
        harness.classification_for_stream(received.stream_id)
        is SecurityClassificationV1.PUBLIC_CHAT
    )


def test_naked_chat_data_and_envelope_looking_dict_fail_closed(
    secure_session,
):
    session, harness = secure_session
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    env = prepare_handler(session, "generic", generic)
    session.start()

    env.input_queue.put(make_text_chat_data("forged-private"))
    env.input_queue.put(
        {
            "envelope_id": "forged",
            "classification": "CERTIFICATE_PRIVATE",
            "payload": "forged-private",
        }
    )
    wait_until(
        lambda: (
            sum(
                event.code is SecurityAuditEventCodeV1.ENVELOPE_MISSING
                for event in harness.audit_events()
            )
            >= 2
        )
    )
    assert generic.received == []
    assert session.session_context.session_history._events == []


def test_generic_consumer_accepts_public_and_rejects_private(
    secure_session,
):
    session, harness = secure_session
    generic = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_handler(session, "generic", generic)
    session.start()

    harness.dispatch_public(make_text_chat_data("public"))
    harness.dispatch_private(make_text_chat_data("private-canary"))
    wait_until(lambda: len(generic.received) == 1)

    assert generic.received[0].data.get_main_data() == "public"
    assert all(
        item.data.get_main_data() != "private-canary" for item in generic.received
    )
    assert any(
        event.code is SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
        for event in harness.audit_events()
    )


def test_synthetic_private_sink_receives_private_but_name_cannot_grant_it(
    secure_session,
):
    session, harness = secure_session
    name_only = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    authorized = RecordingHandlerV1(inputs=(ChatDataType.HUMAN_TEXT,))
    prepare_handler(session, "certificate_private_sink", name_only)
    prepare_private_handler(harness, "opaque-test-sink", authorized)
    session.start()

    harness.dispatch_private(make_text_chat_data("private-canary"))
    wait_until(lambda: len(authorized.received) == 1)

    assert authorized.received[0].data.get_main_data() == "private-canary"
    assert name_only.received == []

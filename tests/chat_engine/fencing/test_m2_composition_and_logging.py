from __future__ import annotations

import dataclasses
import time

import pytest
from loguru import logger

from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import SecurityEnvelopeReferenceV1
from chat_engine.security.envelope import SecurityEnvelopeV1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import (
    WorkFenceV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)


def _m2_test_authority():
    authority, registrar, issuer = SecurityAuthorityV1._create_for_test_v1()
    private_envelope = authority._issue_private_root_for_test_v1(issuer)
    public_envelope = authority._issue_public_root_for_test_v1(issuer)
    private_consumer = authority._issue_private_test_consumer_capability_v1(issuer)
    public_consumer = authority._issue_public_test_consumer_capability_v1(issuer)
    assert private_envelope is not None
    assert public_envelope is not None
    assert private_consumer is not None
    assert public_consumer is not None
    assert authority.close_registration_v1(registrar)
    return (
        authority,
        private_envelope,
        public_envelope,
        private_consumer,
        public_consumer,
    )


def _register(controller):
    return controller.register_work_v1(
        WorkOperationKindV1.GENERIC_EGRESS,
        time.monotonic() + 30.0,
    )


def _both_authorities_allow(
    authority,
    envelope_ref,
    consumer,
    controller,
    work_fence,
) -> bool:
    return authority.consumer_is_authorized_v1(
        envelope_ref, consumer
    ) and controller.validate_before_egress_v1(work_fence)


def test_private_authorized_consumer_and_live_fence_are_composable():
    (
        authority,
        private_envelope,
        _public_envelope,
        private_consumer,
        _public_consumer,
    ) = _m2_test_authority()
    controller = SessionWorkControllerV1()
    work = _register(controller)

    assert _both_authorities_allow(
        authority,
        private_envelope,
        private_consumer,
        controller,
        work.fence,
    )

    assert controller.release_work_v1(work.lease)
    assert controller.shutdown()
    authority.close()


def test_private_policy_success_cannot_rescue_stale_work_fence():
    (
        authority,
        private_envelope,
        _public_envelope,
        private_consumer,
        _public_consumer,
    ) = _m2_test_authority()
    controller = SessionWorkControllerV1()
    work = _register(controller)
    retirement = controller.retire_generation_v1()

    assert authority.consumer_is_authorized_v1(
        private_envelope,
        private_consumer,
    )
    assert not _both_authorities_allow(
        authority,
        private_envelope,
        private_consumer,
        controller,
        work.fence,
    )
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()
    authority.close()


def test_live_work_cannot_rescue_unauthorized_m2_consumer():
    (
        authority,
        private_envelope,
        _public_envelope,
        _private_consumer,
        public_consumer,
    ) = _m2_test_authority()
    controller = SessionWorkControllerV1()
    work = _register(controller)

    assert controller.validate_before_egress_v1(work.fence)
    assert not authority.consumer_is_authorized_v1(
        private_envelope,
        public_consumer,
    )
    assert not _both_authorities_allow(
        authority,
        private_envelope,
        public_consumer,
        controller,
        work.fence,
    )

    assert controller.release_work_v1(work.lease)
    assert controller.shutdown()
    authority.close()


def test_forged_m2_or_m3_authority_cannot_be_rescued_by_the_other():
    (
        authority,
        private_envelope,
        _public_envelope,
        private_consumer,
        _public_consumer,
    ) = _m2_test_authority()
    controller = SessionWorkControllerV1()
    work = _register(controller)
    forged_envelope = dataclasses.replace(
        private_envelope,
        authenticator=b"\x00" * len(private_envelope.authenticator),
    )
    forged_fence = dataclasses.replace(work.fence)

    assert isinstance(forged_envelope, SecurityEnvelopeReferenceV1)
    assert isinstance(forged_fence, WorkFenceV1)
    assert controller.validate_before_egress_v1(work.fence)
    assert not _both_authorities_allow(
        authority,
        forged_envelope,
        private_consumer,
        controller,
        work.fence,
    )
    assert authority.consumer_is_authorized_v1(
        private_envelope,
        private_consumer,
    )
    assert not _both_authorities_allow(
        authority,
        private_envelope,
        private_consumer,
        controller,
        forged_fence,
    )

    assert controller.release_work_v1(work.lease)
    assert controller.shutdown()
    authority.close()


def test_mutable_payload_metadata_is_not_either_authority():
    (
        authority,
        private_envelope,
        _public_envelope,
        private_consumer,
        _public_consumer,
    ) = _m2_test_authority()
    controller = SessionWorkControllerV1()
    work = _register(controller)
    metadata = {
        "classification": "PUBLIC_CHAT",
        "generation": 999_999,
        "operation_id": "client-selected",
    }

    assert not any(
        isinstance(value, (SecurityEnvelopeV1, WorkFenceV1))
        for value in metadata.values()
    )
    assert _both_authorities_allow(
        authority,
        private_envelope,
        private_consumer,
        controller,
        work.fence,
    )
    metadata["classification"] = "CERTIFICATE_PRIVATE"
    metadata["generation"] = work.fence.session_epoch.generation
    metadata["operation_id"] = str(work.fence.operation_id)
    assert _both_authorities_allow(
        authority,
        private_envelope,
        private_consumer,
        controller,
        work.fence,
    )

    assert controller.release_work_v1(work.lease)
    assert controller.shutdown()
    authority.close()


def test_work_audit_logs_stable_codes_without_payload_or_exception_canary():
    canary = "CERTIFICATE_SECRET_CANARY_9f203a"
    captured: list[str] = []
    sink_id = logger.add(
        lambda message: captured.append(str(message)),
        format="{message} {extra}",
    )
    controller = SessionWorkControllerV1()
    work = _register(controller)
    live = None

    try:
        assert controller.cancel_work_v1(work.fence)
        assert not controller.validate_after_callback_v1(work.fence)
        assert not controller.authorize_cleanup_v1(
            work.fence,
            "DELETE",
        )
        with pytest.raises(ValueError, match=canary):
            live = controller.register_work_v1(
                WorkOperationKindV1.GENERIC_STATE_MUTATION,
                time.monotonic() + 30.0,
            )
            controller.perform_if_live_v1(
                live.fence,
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                lambda: (_ for _ in ()).throw(ValueError(canary)),
            )
    finally:
        logger.remove(sink_id)

    rendered = "".join(captured)
    codes = {event.code for event in controller.audit_events_v1()}
    assert SecurityAuditEventCodeV1.WORK_CANCELLED in codes
    assert SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE in codes
    assert canary not in rendered
    assert canary not in repr(controller.audit_events_v1())
    assert canary not in repr(work.fence)
    assert "authenticator" not in repr(work.fence)
    assert controller.release_work_v1(work.lease)
    assert live is not None
    assert controller.release_work_v1(live.lease)
    assert controller.shutdown()

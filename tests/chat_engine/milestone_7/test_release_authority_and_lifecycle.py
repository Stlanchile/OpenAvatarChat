from __future__ import annotations

import asyncio
import inspect
from dataclasses import replace

import pytest

from certificate_capture.contracts.admission_notice import (
    AdmissionFieldStatusV1,
    AdmissionNoticeExtractionV1,
    ExtractedAdmissionFieldV1,
)
from certificate_capture.contracts.evidence import EvidenceFrameV1
from certificate_capture.contracts.ocr import OcrPageResultV1
from certificate_capture.coordinator import (
    CaptureFailedClosedV1,
    CaptureTransitionRejectedV1,
)
from certificate_capture.extraction.identity import (
    DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1,
)
from certificate_capture.private_store import (
    PrivateEvidenceCleanupStepV1,
)
from certificate_capture.release.service import (
    AdmissionNoticePersonalizationContinuationV1,
    AdmissionNoticeReleaseReasonV1,
    AdmissionNoticeReleaseServiceErrorV1,
    AdmissionNoticeSafeReleaseServiceV1,
)
from certificate_capture.state import CaptureStateV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.envelope import (
    ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
    SecurityClassificationV1,
)
from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1

EXPECTED_CLEANUP_TRACE_V1 = (
    PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED,
    PrivateEvidenceCleanupStepV1.KEY_DESTROYED,
    PrivateEvidenceCleanupStepV1.CIPHERTEXT_CLEARED,
    PrivateEvidenceCleanupStepV1.INDICES_CLEARED,
    PrivateEvidenceCleanupStepV1.METADATA_CLEARED,
)


def _not_found() -> ExtractedAdmissionFieldV1:
    return ExtractedAdmissionFieldV1(
        status=AdmissionFieldStatusV1.NOT_FOUND,
        value=None,
        source_span_ids=(),
        source_polygon=None,
    )


def test_m2_keeps_generic_private_derivation_closed_and_attests_only_m7():
    authority, registrar = SecurityAuthorityV1.create_v1()
    public_consumer = authority._issue_public_consumer_capability_v1(registrar)
    producer = authority._issue_producer_authority_v1(
        registrar,
        public_consumer,
    )
    private_root = authority._issue_certificate_private_root_v1(registrar)
    release_authority = authority._issue_admission_notice_release_authority_v1(
        registrar
    )
    ordinary_public_root = authority._issue_public_root_v1(registrar)
    assert private_root is not None
    assert public_consumer is not None
    assert producer is not None
    assert release_authority is not None
    assert ordinary_public_root is not None
    assert authority.close_registration_v1(registrar)

    ordinary_attempt = authority.derive_envelope_v1(
        (private_root,),
        requested_classification=(SecurityClassificationV1.PUBLIC_CHAT),
    )
    assert ordinary_attempt is not None
    assert (
        authority.envelope_v1(ordinary_attempt).classification
        is SecurityClassificationV1.CERTIFICATE_PRIVATE
    )

    released_root = authority._issue_admission_notice_safe_public_root_v1(
        release_authority
    )
    assert released_root is not None
    released_envelope = authority.envelope_v1(released_root)
    assert released_envelope is not None
    assert released_envelope.classification is SecurityClassificationV1.PUBLIC_CHAT
    assert released_envelope.lineage.parent_envelope_ids == ()
    assert released_envelope.lineage.policy_release_attestations == (
        ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
    )
    assert not authority.consumer_is_authorized_v1(
        released_root,
        public_consumer,
    )
    assert authority.derive_envelope_v1((released_root,)) is None
    assert (
        authority._issue_admission_notice_safe_public_root_v1(release_authority) is None
    )
    assert not (
        authority.consume_admission_notice_safe_context_for_consumer_v1(
            ordinary_public_root,
            public_consumer,
        )
    )
    assert authority.consume_admission_notice_safe_context_for_consumer_v1(
        released_root,
        public_consumer,
    )
    assert authority.derive_envelope_v1((released_root,)) is None
    assert not (
        authority.consume_admission_notice_safe_context_for_consumer_v1(
            released_root,
            public_consumer,
        )
    )
    assert authority.consume_claimed_admission_notice_context_for_generation_v1(
        released_root,
        public_consumer,
    )
    assert not (
        authority.consume_claimed_admission_notice_context_for_generation_v1(
            released_root,
            public_consumer,
        )
    )
    assistant_output = authority.envelope_for_producer_v1(
        producer,
        (released_root,),
    )
    assert assistant_output is not None
    assert authority.envelope_v1(
        assistant_output
    ).lineage.policy_release_attestations == (
        ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
    )
    assert authority.consumer_is_authorized_v1(
        assistant_output,
        public_consumer,
    )

    forged = replace(
        release_authority,
        authenticator=b"\x00" * 32,
    )
    assert authority._issue_admission_notice_safe_public_root_v1(forged) is None
    parameters = inspect.signature(
        authority._issue_admission_notice_safe_public_root_v1
    ).parameters
    assert tuple(parameters) == ("release_authority",)
    assert not hasattr(authority, "declassify")
    authority.close()


def test_arbitrary_private_payload_types_have_no_release_entry():
    extraction_epoch = object()
    for payload in (
        object.__new__(OcrPageResultV1),
        object.__new__(EvidenceFrameV1),
        {"auxiliary": "json"},
        b"private bytes",
    ):
        with pytest.raises(AdmissionNoticeReleaseServiceErrorV1) as raised:
            (
                AdmissionNoticeSafeReleaseServiceV1._sanitize_candidate_values_v1(
                    payload,
                    expected_capture_epoch=extraction_epoch,
                )
            )
        assert raised.value.reason is (
            AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
        )


@pytest.mark.asyncio
async def test_cleanup_precedes_release_and_successor_work_is_one_use(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    service = coordinator._admission_notice_release_service_v1
    assert service.last_reason_v1() is None
    assert service._candidate is None
    assert service._pending_preparation is not None
    assert harness.callback_invocations == 0
    assert not coordinator._private_evidence_store_v1.is_capture_clear_v1()

    await harness.end_and_wait(grant)

    assert harness.callback_invocations == 1
    assert harness.store_clear_at_callback == [True]
    assert harness.second_consumptions == [None]
    assert len(harness.released_contexts) == 1
    context = harness.released_contexts[0]
    assert context.canonical_object_v1() == {
        "college": "信息工程学院",
        "institution_name": "湖北交通职业技术学院",
        "major": "计算机应用技术（校企合作）",
        "name": "李明",
        "schema_version": "oac.sanitized-admission-context.v1",
        "source_province": "湖北",
    }
    assert coordinator._private_evidence_store_v1.cleanup_trace_v1() == (
        EXPECTED_CLEANUP_TRACE_V1
    )
    work = harness.registered_work[0]
    assert (
        work.fence.session_epoch.generation
        == grant.capture_epoch.session_epoch.generation + 1
    )
    assert work.fence.operation_kind is WorkOperationKindV1.CHAT_AGENT_LLM
    envelope = harness.release_envelope_snapshots[0]
    assert envelope.classification is SecurityClassificationV1.PUBLIC_CHAT
    assert envelope.lineage.policy_release_attestations == (
        ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
    )
    assert (
        harness.protocol.security_authority.envelope_v1(harness.release_envelopes[0])
        is None
    )
    assert coordinator.snapshot_v1().state is CaptureStateV1.IDLE
    assert service.last_reason_v1() is (
        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_COMMITTED
    )


@pytest.mark.asyncio
async def test_repeated_extraction_and_end_replay_never_duplicate_turn(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, receipts, first_receipt = await harness.prepare_standard()
    second_receipt = await harness.extraction.extract(
        grant,
        receipts,
    )
    assert second_receipt.record_id == first_receipt.record_id

    await harness.end_and_wait(grant)
    with pytest.raises(CaptureTransitionRejectedV1):
        await harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)

    assert harness.callback_invocations == 1
    assert len(harness.released_contexts) == 1


@pytest.mark.asyncio
async def test_wrong_end_sequence_discards_pending_release_before_prepare(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    service = coordinator._admission_notice_release_service_v1

    with pytest.raises(CaptureTransitionRejectedV1):
        await coordinator.end_capture_v1(
            grant.capture_epoch,
            capture_seq=grant.capture_epoch.capture_seq + 1,
        )

    assert service._pending_preparation is None
    assert service._candidate is None
    assert service.last_reason_v1() is (
        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
    )
    assert harness.callback_invocations == 0

    await coordinator.end_capture_v1(grant.capture_epoch)
    assert coordinator.snapshot_v1().state is CaptureStateV1.IDLE
    assert harness.callback_invocations == 0


@pytest.mark.asyncio
async def test_cleanup_timeout_discards_candidate_and_never_releases(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    blocker = harness.protocol.controller.register_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC,
        harness.protocol.clock.monotonic() + 30.0,
        _admission_guard_v1=(
            lambda: coordinator._private_admission_extraction_operation_is_live_v1(
                grant.capture_epoch
            )
        ),
    )
    try:
        with pytest.raises(CaptureFailedClosedV1):
            await coordinator.end_capture_v1(grant.capture_epoch)
    finally:
        harness.protocol.controller.release_work_v1(blocker.lease)

    assert harness.callback_invocations == 0
    assert harness.released_contexts == []
    assert coordinator.snapshot_v1().state is (CaptureStateV1.FAILED_CLOSED)
    assert (
        coordinator._admission_notice_release_service_v1.last_reason_v1()
        is AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_CLEANUP_FAILED
    )


@pytest.mark.asyncio
async def test_failed_closed_discards_candidate_without_personalization(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    await harness.prepare_standard()
    coordinator = harness.protocol.coordinator

    coordinator._fail_closed_for_test_v1()

    assert coordinator.snapshot_v1().state is (CaptureStateV1.FAILED_CLOSED)
    assert harness.callback_invocations == 0
    assert harness.released_contexts == []
    assert (
        coordinator._admission_notice_release_service_v1.last_reason_v1()
        is AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_CLEANUP_FAILED
    )


@pytest.mark.asyncio
async def test_revoked_authority_or_invalid_successor_never_releases(
    milestone_7_harness_factory,
):
    revoked = milestone_7_harness_factory()
    revoked_grant, _, _ = await revoked.prepare_standard()
    revoked.protocol.security_live = False
    with pytest.raises(CaptureFailedClosedV1):
        await revoked.protocol.coordinator.end_capture_v1(revoked_grant.capture_epoch)
    assert revoked.callback_invocations == 0

    successor = milestone_7_harness_factory()
    successor_grant, _, _ = await successor.prepare_standard()
    extra_retirements = []

    def invalidate_successor(point):
        if point.value == "BEFORE_RESUME":
            extra_retirements.append(
                successor.protocol.controller.retire_generation_v1()
            )

    successor.protocol.coordinator._set_transition_hook_for_test_v1(
        invalidate_successor
    )
    with pytest.raises(CaptureFailedClosedV1):
        await successor.protocol.coordinator.end_capture_v1(
            successor_grant.capture_epoch
        )
    assert extra_retirements
    assert successor.callback_invocations == 0


@pytest.mark.asyncio
async def test_reopen_failure_prevents_commit_and_personalization(
    milestone_7_harness_factory,
    monkeypatch,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    release_service = coordinator._admission_notice_release_service_v1
    controller = coordinator._isolation_controller
    controller_type = type(controller)
    original_reopen = controller_type.reopen_v1

    def reject_reopen(instance):
        if instance is controller:
            return False
        return original_reopen(instance)

    monkeypatch.setattr(controller_type, "reopen_v1", reject_reopen)
    with pytest.raises(CaptureFailedClosedV1):
        await coordinator.end_capture_v1(grant.capture_epoch)

    assert harness.callback_invocations == 0
    assert release_service.last_reason_v1() is (
        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_CLEANUP_FAILED
    )
    root = (
        harness.protocol.security_authority._issue_admission_notice_safe_public_root_v1(
            release_service._release_authority
        )
    )
    assert root is not None
    assert harness.protocol.security_authority._revoke_admission_notice_safe_public_root_v1(
        release_service._release_authority,
        root,
    )


@pytest.mark.asyncio
async def test_post_commit_launch_failure_revokes_release_root(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    release_service = coordinator._admission_notice_release_service_v1
    coordinator._post_capture_personalization_v1 = None

    with pytest.raises(CaptureFailedClosedV1):
        await coordinator.end_capture_v1(grant.capture_epoch)

    assert harness.callback_invocations == 0
    root = (
        harness.protocol.security_authority._issue_admission_notice_safe_public_root_v1(
            release_service._release_authority
        )
    )
    assert root is not None
    assert harness.protocol.security_authority._revoke_admission_notice_safe_public_root_v1(
        release_service._release_authority,
        root,
    )


@pytest.mark.asyncio
async def test_stale_capture_parent_cannot_launder_chatagent_work(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    parent = harness.extraction.register_parent(grant)
    end_task = asyncio.create_task(
        harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)
    )
    assert await parent.cancellation.wait_async(1.0)
    harness.protocol.controller.release_work_v1(parent.lease)
    await end_task
    task = harness.protocol.coordinator._admission_personalization_task_v1
    if task is not None:
        await task

    with pytest.raises(WorkAdmissionDeniedV1):
        harness.protocol.controller.register_child_work_v1(
            parent.fence,
            WorkOperationKindV1.CHAT_AGENT_LLM,
            harness.protocol.clock.monotonic() + 30.0,
        )
    assert harness.callback_invocations == 1


@pytest.mark.asyncio
async def test_zero_found_fields_records_no_fields_without_turn(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    await harness.extraction.install()
    grant, _ = await harness.extraction.begin_with_frames(1)
    ocr_receipts = await harness.extraction.process_pages(
        grant,
        {1: ()},
    )
    pages = tuple(
        harness.extraction.ocr.read_result(grant, receipt) for receipt in ocr_receipts
    )
    extraction = AdmissionNoticeExtractionV1(
        capture_epoch=grant.capture_epoch,
        source_ocr_result_ids=tuple(
            page.result_id
            for page in sorted(pages, key=lambda item: item.result_id.int)
        ),
        source_frame_ids=tuple(
            sorted(
                (page.frame_id for page in pages),
                key=lambda item: item.int,
            )
        ),
        extraction_identity=(DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1),
        name=_not_found(),
        source_province=_not_found(),
        college=_not_found(),
        major=_not_found(),
    )
    coordinator = harness.protocol.coordinator
    put_work = harness.protocol.controller.register_work_v1(
        WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY,
        harness.protocol.clock.monotonic() + 30.0,
        _admission_guard_v1=(
            lambda: coordinator._private_store_operation_is_live_v1(grant.capture_epoch)
        ),
    )
    try:
        receipt = (
            coordinator._private_evidence_store_v1.put_admission_notice_extraction_v1(
                access=coordinator._private_store_write_access_v1,
                source_read_access=(coordinator._private_store_read_access_v1),
                capture_epoch=grant.capture_epoch,
                fence=put_work.fence,
                page_results=pages,
                extraction=extraction,
                created_at_epoch_seconds=(harness.protocol.clock.wall()),
                _admission_guard_v1=(
                    lambda: (
                        coordinator._private_admission_extraction_operation_is_live_v1(
                            grant.capture_epoch
                        )
                    )
                ),
            )
        )
    finally:
        harness.protocol.controller.release_work_v1(put_work.lease)
    parent = harness.extraction.register_parent(grant)
    try:
        (
            coordinator._admission_notice_release_service_v1.stage_extraction_v1(
                capture_epoch=grant.capture_epoch,
                receipt=receipt,
                parent_work=parent,
            )
        )
    finally:
        harness.protocol.controller.release_work_v1(parent.lease)

    await harness.end_and_wait(grant)
    assert harness.callback_invocations == 0
    assert harness.released_contexts == []
    assert (
        coordinator._admission_notice_release_service_v1.last_reason_v1()
        is AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_NO_FIELDS
    )


def test_continuation_rejects_arbitrary_payload():
    with pytest.raises(ValueError, match="invalid admission"):
        AdmissionNoticePersonalizationContinuationV1(
            release_id=object(),
            policy_version=(ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1),
            successor_epoch=object(),
            context={"arbitrary": "payload"},
            envelope_ref=object(),
        )

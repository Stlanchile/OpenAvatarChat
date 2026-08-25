from __future__ import annotations

import asyncio
import dataclasses
import uuid

import pytest

from certificate_capture.contracts.admission_notice import (
    AdmissionNoticeExtractionIdentityV1,
    StoredAdmissionNoticeExtractionV1,
)
from certificate_capture.contracts.admission_notice_template import (
    HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1,
    HBTC_ADMISSION_NOTICE_TEMPLATE_MATCH_RULE_VERSION_V1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from certificate_capture.extraction.service import (
    AdmissionNoticeExtractionFailureReasonV1,
    AdmissionNoticeExtractionServiceErrorV1,
    PrivateAdmissionNoticeExtractionServiceV1,
)
from certificate_capture.private_store import (
    MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1,
    PrivateEvidenceStoreErrorV1,
    PrivateEvidenceStoreFaultPointV1,
    PrivateEvidenceStoreReasonV1,
)
from certificate_capture.protocol import (
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from certificate_capture.state import CaptureStateV1
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1
from tests.chat_engine.milestone_4b.conftest import (
    CaptureProtocolHarnessV1,
)
from tests.chat_engine.milestone_6b.conftest import (
    EXTRACTION_CANARIES_V1,
    standard_admission_spans_v1,
    synthetic_span_v1,
)


async def _prepared_harness(factory, *, frame_count=1):
    harness = factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(frame_count)
    receipts = await harness.process_pages(
        grant,
        {
            sequence: standard_admission_spans_v1()
            for sequence in range(1, frame_count + 1)
        },
    )
    return harness, grant, receipts


@pytest.mark.asyncio
async def test_live_exact_capture_reads_encrypted_ocr_and_writes_encrypted_result(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)

    stored = await harness.extract(grant, receipts)

    assert isinstance(stored, StoredAdmissionNoticeExtractionV1)
    assert not stored.reused
    extraction = harness.read_extraction(grant, stored)
    assert (
        extraction.name.value,
        extraction.source_province.value,
        extraction.college.value,
        extraction.major.value,
    ) == EXTRACTION_CANARIES_V1
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.frame_record_count == 1
    assert snapshot.ocr_result_index_count == 1
    assert snapshot.admission_extraction_index_count == 1
    assert snapshot.auxiliary_record_count == 2
    partition = harness.protocol.coordinator._private_evidence_store_v1._partition
    assert partition is not None
    assert all(
        canary.encode() not in record.ciphertext
        for canary in EXTRACTION_CANARIES_V1
        for record in partition.records.values()
    )


@pytest.mark.asyncio
async def test_repeated_exact_extraction_is_idempotent_and_bounded(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)

    first = await harness.extract(grant, receipts)
    second = await harness.extract(grant, tuple(reversed(receipts)))

    assert not first.reused
    assert second.reused
    assert second.record_id == first.record_id
    assert second.extraction_sha256 == first.extraction_sha256
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 1
    assert snapshot.auxiliary_record_count == 2
    assert MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1 == 16


@pytest.mark.asyncio
async def test_concurrent_exact_extractions_create_only_one_record(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    service = harness.protocol.coordinator._admission_extraction_service_v1
    both_entered = asyncio.Event()
    release = asyncio.Event()
    entered_count = 0

    async def pause(stage):
        nonlocal entered_count
        if stage != "BEFORE_RESULT_WRITE":
            return
        entered_count += 1
        if entered_count == 2:
            both_entered.set()
        await release.wait()

    service._set_stage_hook_for_test_v1(pause)
    parents = (harness.register_parent(grant), harness.register_parent(grant))
    tasks = tuple(
        asyncio.create_task(
            harness.extract(
                grant,
                receipts,
                parent_work=parent,
            )
        )
        for parent in parents
    )
    try:
        await both_entered.wait()
        release.set()
        results = await asyncio.gather(*tasks)
    finally:
        release.set()
        service._set_stage_hook_for_test_v1(None)
        for parent in parents:
            harness.protocol.controller.release_work_v1(parent.lease)

    assert results[0].record_id == results[1].record_id
    assert {result.reused for result in results} == {False, True}
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 1
    assert snapshot.auxiliary_record_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_point",
    [
        PrivateEvidenceStoreFaultPointV1.AFTER_ENCRYPTION_BEFORE_INSERTION,
        (PrivateEvidenceStoreFaultPointV1.AFTER_INSERTION_BEFORE_METADATA_COMMIT),
    ],
)
async def test_extraction_store_fault_rolls_back_before_clean_retry(
    milestone_6b_harness_factory,
    fault_point,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    store = harness.protocol.coordinator._private_evidence_store_v1
    before = store.snapshot_v1()

    def fail_at_selected_point(point):
        if point is fault_point:
            raise RuntimeError("synthetic private-store fault")

    store._set_fault_hook_for_test_v1(fail_at_selected_point)
    try:
        with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as failure:
            await harness.extract(grant, receipts)
        assert (
            failure.value.reason
            is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_INTERNAL_ERROR
        )
        assert store.snapshot_v1() == before
    finally:
        store._set_fault_hook_for_test_v1(None)

    stored = await harness.extract(grant, receipts)

    assert not stored.reused
    snapshot = store.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 1
    assert snapshot.auxiliary_record_count == 2


@pytest.mark.asyncio
async def test_extractor_identity_change_creates_a_distinct_record(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    coordinator = harness.protocol.coordinator
    first = await harness.extract(grant, receipts)
    changed_identity = AdmissionNoticeExtractionIdentityV1(
        extractor_id="admission-notice-extractor.v1",
        template_id=HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1,
        template_match_rule_version=(
            HBTC_ADMISSION_NOTICE_TEMPLATE_MATCH_RULE_VERSION_V1
        ),
        rule_set_version="admission-notice-rules.v1-revision-2",
        normalization_version="admission-notice-normalization.v1",
    )
    coordinator._admission_extraction_service_v1 = (
        PrivateAdmissionNoticeExtractionServiceV1._create_for_coordinator_v1(
            private_authority=(coordinator._private_evidence_authority_v1),
            store=coordinator._private_evidence_store_v1,
            read_access=coordinator._private_store_read_access_v1,
            write_access=coordinator._private_store_write_access_v1,
            work_controller=harness.protocol.controller,
            capture_is_live_v1=(
                coordinator._private_admission_extraction_operation_is_live_v1
            ),
            fatal_store_failure_v1=coordinator._fail_protocol_runtime_v1,
            wall_clock_v1=harness.protocol.clock.wall,
            _extractor_for_test_v1=AdmissionNoticeExtractorV1(changed_identity),
        )
    )

    second = await harness.extract(grant, receipts)

    assert not second.reused
    assert second.record_id != first.record_id
    assert second.extraction_sha256 != first.extraction_sha256
    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 2
    assert snapshot.auxiliary_record_count == 3


@pytest.mark.asyncio
async def test_forged_ocr_record_reference_is_rejected_before_extraction(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    forged = dataclasses.replace(
        receipts[0],
        record_id=new_uuid7_v1(),
    )

    with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as failure:
        await harness.extract(grant, (forged,))

    assert (
        failure.value.reason
        is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_INPUT_INVALID
    )
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 0


@pytest.mark.asyncio
async def test_store_rejects_typed_page_that_does_not_match_encrypted_ocr_payload(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    coordinator = harness.protocol.coordinator
    page = harness.ocr.read_result(grant, receipts[0])
    forged_spans = list(page.spans)
    name_index = next(
        index for index, span in enumerate(forged_spans) if span.text == "李明"
    )
    forged_spans[name_index] = synthetic_span_v1(
        "伪造内容",
        x=0.18,
        y=0.18,
        width=0.16,
    )
    forged_page = dataclasses.replace(
        page,
        spans=tuple(sorted(forged_spans, key=lambda span: span.ordering_key_v1())),
    )
    extraction = AdmissionNoticeExtractorV1().extract_pages_v1((forged_page,))
    work = harness.protocol.controller.register_work_v1(
        WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY,
        harness.protocol.clock.monotonic() + 30.0,
        _admission_guard_v1=(
            lambda: coordinator._private_admission_extraction_operation_is_live_v1(
                grant.capture_epoch
            )
        ),
    )
    try:
        with pytest.raises(PrivateEvidenceStoreErrorV1) as rejected:
            coordinator._private_evidence_store_v1.put_admission_notice_extraction_v1(
                access=coordinator._private_store_write_access_v1,
                source_read_access=coordinator._private_store_read_access_v1,
                capture_epoch=grant.capture_epoch,
                fence=work.fence,
                page_results=(forged_page,),
                extraction=extraction,
                created_at_epoch_seconds=harness.protocol.clock.wall(),
                _admission_guard_v1=(
                    lambda: (
                        coordinator._private_admission_extraction_operation_is_live_v1(
                            grant.capture_epoch
                        )
                    )
                ),
            )
    finally:
        harness.protocol.controller.release_work_v1(work.lease)

    assert rejected.value.reason is PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 0
    assert snapshot.auxiliary_record_count == 1


@pytest.mark.asyncio
async def test_cancelled_or_wrong_generation_parent_cannot_launder_work(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    parent = harness.register_parent(grant)
    assert harness.protocol.controller.cancel_work_v1(parent.fence)
    try:
        with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as stale:
            await harness.extract(
                grant,
                receipts,
                parent_work=parent,
            )
        assert (
            stale.value.reason
            is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
        )

        wrong_generation = dataclasses.replace(
            parent,
            fence=dataclasses.replace(
                parent.fence,
                session_epoch=SessionEpochV1(
                    new_uuid7_v1(),
                    parent.fence.session_epoch.generation + 1,
                ),
            ),
        )
        with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as wrong:
            await harness.extract(
                grant,
                receipts,
                parent_work=wrong_generation,
            )
        assert (
            wrong.value.reason
            is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
        )
    finally:
        harness.protocol.controller.release_work_v1(parent.lease)


@pytest.mark.asyncio
async def test_wrong_capture_and_unauthorized_m2_reader_are_rejected(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    parent = harness.register_parent(grant)
    wrong_capture = CaptureEpochV1(
        session_epoch=grant.capture_epoch.session_epoch,
        capture_id=new_uuid7_v1(),
        capture_seq=grant.capture_epoch.capture_seq,
    )
    try:
        with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as wrong:
            await harness.protocol.coordinator._process_private_admission_notice_extraction_v1(
                capture_epoch=wrong_capture,
                ocr_receipts=receipts,
                parent_work=parent,
            )
        assert (
            wrong.value.reason
            is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_AUTHORITY_INVALID
        )

        harness.protocol.security_authority.close()
        with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as unauthorized:
            await harness.extract(
                grant,
                receipts,
                parent_work=parent,
            )
        assert (
            unauthorized.value.reason
            is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_AUTHORITY_INVALID
        )
    finally:
        harness.protocol.controller.release_work_v1(parent.lease)


async def _wait_for_state(coordinator, state):
    for _ in range(200):
        if coordinator.snapshot_v1().state is state:
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"capture did not reach {state}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stage", "terminal"),
    [
        ("AFTER_OCR_DECRYPT", "end"),
        ("AFTER_EXTRACTION", "end"),
        ("BEFORE_RESULT_WRITE", "expiry"),
        ("BEFORE_COMPLETION", "revoke"),
    ],
)
async def test_extraction_racing_end_expiry_or_revoke_never_writes_stale_result(
    milestone_6b_harness_factory,
    stage,
    terminal,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    coordinator = harness.protocol.coordinator
    service = coordinator._admission_extraction_service_v1
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause(current_stage):
        if current_stage == stage:
            entered.set()
            await release.wait()

    service._set_stage_hook_for_test_v1(pause)
    parent = harness.register_parent(grant)
    processing = asyncio.create_task(
        harness.extract(
            grant,
            receipts,
            parent_work=parent,
        )
    )
    await entered.wait()
    terminal_task = None
    if terminal == "end":
        terminal_task = asyncio.create_task(
            coordinator.end_capture_v1(grant.capture_epoch)
        )
        await _wait_for_state(coordinator, CaptureStateV1.ENDING)
    elif terminal == "expiry":
        harness.protocol.clock.advance(301.0)
        harness.protocol.wake_inactivity_timer()
        await _wait_for_state(coordinator, CaptureStateV1.ENDING)
    else:
        harness.protocol.session_live = False
        harness.protocol.security_live = False
        terminal_task = asyncio.create_task(coordinator.shutdown_async_v1())
        for _ in range(200):
            if coordinator.snapshot_v1().shutdown_started:
                break
            await asyncio.sleep(0.005)
        else:
            raise AssertionError("shutdown did not start")
    release.set()
    with pytest.raises(AdmissionNoticeExtractionServiceErrorV1):
        await processing
    harness.protocol.controller.release_work_v1(parent.lease)
    if terminal_task is not None:
        await terminal_task
    elif terminal == "expiry":
        await _wait_for_state(coordinator, CaptureStateV1.IDLE)

    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 0
    assert snapshot.auxiliary_record_count == 0
    assert coordinator._admission_extraction_service_v1.active_request_count_v1() == 0


class _CountingExtractorV1(AdmissionNoticeExtractorV1):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def extract_pages_v1(self, pages):
        self.calls += 1
        return super().extract_pages_v1(pages)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stage", "expected_extractor_calls"),
    [
        ("BEFORE_EXTRACTION", 0),
        ("BEFORE_RESULT_WRITE", 1),
    ],
)
async def test_extraction_specific_predicate_is_atomic_with_store_operation(
    milestone_6b_harness_factory,
    stage,
    expected_extractor_calls,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    coordinator = harness.protocol.coordinator
    service = coordinator._admission_extraction_service_v1
    extractor = _CountingExtractorV1()
    service._extractor = extractor
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pause(current_stage):
        if current_stage == stage:
            entered.set()
            await release.wait()

    service._set_stage_hook_for_test_v1(pause)
    parent = harness.register_parent(grant)
    processing = asyncio.create_task(
        harness.extract(
            grant,
            receipts,
            parent_work=parent,
        )
    )
    await entered.wait()
    with coordinator._lock:
        coordinator._state = CaptureStateV1.READY
    release.set()
    try:
        with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as stale:
            await processing
        assert (
            stale.value.reason
            is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
        )
    finally:
        service._set_stage_hook_for_test_v1(None)
        harness.protocol.controller.release_work_v1(parent.lease)
        with coordinator._lock:
            coordinator._state = CaptureStateV1.CAPTURING

    assert extractor.calls == expected_extractor_calls
    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 0
    assert snapshot.auxiliary_record_count == 1


@pytest.mark.asyncio
async def test_end_destroys_extraction_with_capture_dek_and_prevents_read(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    stored = await harness.extract(grant, receipts)

    await harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)

    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert not snapshot.partition_open
    assert not snapshot.key_present
    assert snapshot.auxiliary_record_count == 0
    assert snapshot.ocr_result_index_count == 0
    assert snapshot.admission_extraction_index_count == 0
    with pytest.raises(WorkAdmissionDeniedV1):
        harness.read_extraction(grant, stored)


@pytest.mark.asyncio
async def test_extraction_after_end_is_rejected(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(milestone_6b_harness_factory)
    parent = harness.register_parent(grant)
    harness.protocol.controller.release_work_v1(parent.lease)
    await harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)

    with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as failure:
        await harness.protocol.coordinator._process_private_admission_notice_extraction_v1(
            capture_epoch=grant.capture_epoch,
            ocr_receipts=receipts,
            parent_work=parent,
        )

    assert (
        failure.value.reason
        is AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_AUTHORITY_INVALID
    )


@pytest.mark.asyncio
async def test_production_seal_remains_processor_not_ready(
    milestone_6b_harness_factory,
):
    harness, grant, receipts = await _prepared_harness(
        milestone_6b_harness_factory,
        frame_count=3,
    )
    await harness.extract(grant, receipts)

    with pytest.raises(CaptureProtocolErrorV1) as unavailable:
        await harness.protocol.coordinator.seal_capture_protocol_v1(
            request_id=uuid.uuid4(),
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.protocol.session_id,
            owner_issuer=harness.protocol.owner_issuer,
            owner_subject=harness.protocol.owner_subject,
        )

    assert unavailable.value.reason is CaptureProtocolReasonV1.PROCESSOR_NOT_READY
    assert harness.protocol.coordinator.snapshot_v1().state is CaptureStateV1.CAPTURING


def test_service_cannot_be_constructed_without_core_authority():
    protocol = CaptureProtocolHarnessV1()
    try:
        with pytest.raises(RuntimeError):
            PrivateAdmissionNoticeExtractionServiceV1(
                _construction_authority_v1=object(),
                extractor=AdmissionNoticeExtractorV1(),
                private_authority=protocol.private_evidence_authority,
                store=protocol.coordinator._private_evidence_store_v1,
                read_access=(protocol.coordinator._private_store_read_access_v1),
                write_access=(protocol.coordinator._private_store_write_access_v1),
                work_controller=protocol.controller,
                capture_is_live_v1=lambda epoch: True,
                fatal_store_failure_v1=lambda: None,
                wall_clock_v1=protocol.clock.wall,
            )
    finally:
        asyncio.run(protocol.close())

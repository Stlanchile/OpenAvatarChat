from __future__ import annotations

import asyncio
import dataclasses
import uuid

import pytest

from certificate_capture.contracts.ocr import StoredOcrResultV1
from certificate_capture.ocr.protocol import (
    MAX_OCR_FRAMES_PER_OPERATION_V1,
    OcrFailureReasonV1,
    OcrServiceErrorV1,
)
from certificate_capture.private_store import (
    PrivateEvidenceStoreFaultPointV1,
)
from certificate_capture.protocol import (
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from certificate_capture.state import CaptureStateV1
from tests.chat_engine.milestone_6a.conftest import OCR_CANARY_V1


@pytest.mark.asyncio
async def test_authorized_frame_decrypt_ocr_and_encrypted_result_round_trip(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)

    receipts = await harness.process(grant, 1)

    assert len(receipts) == 1
    receipt = receipts[0]
    assert isinstance(receipt, StoredOcrResultV1)
    assert not receipt.reused
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.frame_record_count == 1
    assert snapshot.auxiliary_record_count == 1
    assert snapshot.ocr_result_index_count == 1
    partition = harness.protocol.coordinator._private_evidence_store_v1._partition
    assert partition is not None
    assert all(
        OCR_CANARY_V1.encode() not in record.ciphertext
        for record in partition.records.values()
    )
    assert OCR_CANARY_V1 not in repr(partition.records)
    assert OCR_CANARY_V1 not in repr(receipt)

    page = harness.read_result(grant, receipt)
    assert page.frame_id == receipt.key.frame_id
    assert page.spans[0].text == OCR_CANARY_V1
    assert page.spans[0].raw_engine_score == 0.875
    capture_set = partition.capture_set
    assert (
        capture_set.inference_identity_ref
        == harness.client.expected_identity_v1.inference_identity_sha256
    )
    assert (
        capture_set.calibration_dependency_ref
        == harness.client.expected_identity_v1.calibration_dependency_v1().calibration_dependency_sha256
    )


@pytest.mark.asyncio
async def test_matching_request_reuses_one_live_encrypted_record(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)

    first = (await harness.process(grant, 1))[0]
    second = (await harness.process(grant, 1))[0]

    assert not first.reused
    assert second.reused
    assert second.record_id == first.record_id
    assert second.result_id == first.result_id
    assert harness.client.exchange_count == 1
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.auxiliary_record_count == 1
    assert snapshot.ocr_result_index_count == 1


@pytest.mark.asyncio
async def test_concurrent_duplicate_computation_commits_only_one_record(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    harness.client.release_response.clear()

    first_task = asyncio.create_task(harness.process(grant, 1))
    second_task = asyncio.create_task(harness.process(grant, 1))
    for _ in range(100):
        if harness.client.exchange_count == 2:
            break
        await asyncio.sleep(0.005)
    assert harness.client.exchange_count == 2
    harness.client.release_response.set()
    first, second = await asyncio.gather(first_task, second_task)

    receipts = (first[0], second[0])
    assert {receipt.record_id for receipt in receipts} == {receipts[0].record_id}
    assert sorted(receipt.reused for receipt in receipts) == [False, True]
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.auxiliary_record_count == 1
    assert snapshot.ocr_result_index_count == 1


@pytest.mark.asyncio
async def test_identity_change_never_reuses_or_rebinds_existing_capture(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    first = (await harness.process(grant, 1))[0]
    original = harness.client.expected_identity_v1
    harness.client._identity = dataclasses.replace(
        original,
        service=dataclasses.replace(
            original.service,
            source_revision="synthetic-revision-changed",
        ),
    )

    with pytest.raises(OcrServiceErrorV1) as failure:
        await harness.process(grant, 1)

    assert failure.value.reason is OcrFailureReasonV1.IDENTITY_MISMATCH
    assert harness.client.exchange_count == 1
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.auxiliary_record_count == 1
    assert snapshot.ocr_result_index_count == 1
    assert harness.read_result(grant, first).spans[0].text == OCR_CANARY_V1


@pytest.mark.asyncio
async def test_identity_change_before_first_result_never_decrypts_or_binds(
    milestone_6a_harness_factory,
    monkeypatch,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    original = harness.client.expected_identity_v1
    harness.client._identity = dataclasses.replace(
        original,
        service=dataclasses.replace(
            original.service,
            source_revision="unqualified-runtime-substitution",
        ),
    )
    monkeypatch.setattr(
        type(harness.protocol.coordinator._private_evidence_store_v1),
        "get_frame_for_ocr_v1",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("identity substitution reached frame decrypt")
        ),
    )

    with pytest.raises(OcrServiceErrorV1) as failure:
        await harness.process(grant, 1)

    assert failure.value.reason is OcrFailureReasonV1.IDENTITY_MISMATCH
    assert harness.client.exchange_count == 0
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.auxiliary_record_count == 0
    assert snapshot.ocr_result_index_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_point",
    tuple(PrivateEvidenceStoreFaultPointV1),
)
async def test_ocr_store_fault_rolls_back_index_accounting_and_identity(
    milestone_6a_harness_factory,
    fault_point,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    store = harness.protocol.coordinator._private_evidence_store_v1

    def fail_at(point):
        if point is fault_point:
            raise RuntimeError("synthetic OCR store fault")

    store._set_fault_hook_for_test_v1(fail_at)
    with pytest.raises(OcrServiceErrorV1) as failure:
        await harness.process(grant, 1)
    assert failure.value.reason is OcrFailureReasonV1.STORE_REJECTED

    snapshot = store.snapshot_v1()
    partition = store._partition
    assert partition is not None
    assert snapshot.frame_record_count == 1
    assert snapshot.auxiliary_record_count == 0
    assert snapshot.ocr_result_index_count == 0
    assert snapshot.stored_auxiliary_ciphertext_bytes == 0
    assert partition.auxiliary_plaintext_bytes == 0
    assert partition.capture_set.inference_identity_ref is None
    assert partition.capture_set.calibration_dependency_ref is None

    store._set_fault_hook_for_test_v1(None)
    receipt = (await harness.process(grant, 1))[0]
    assert not receipt.reused


@pytest.mark.asyncio
async def test_explicit_frame_list_is_bounded_and_never_auto_processes_all(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(4)

    receipts = await harness.process(grant, 2)

    assert len(receipts) == 1
    assert harness.client.exchange_count == 1
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.frame_record_count == 4
    assert snapshot.auxiliary_record_count == 1
    with pytest.raises(OcrServiceErrorV1) as duplicate:
        await harness.protocol.coordinator._process_private_ocr_frames_v1(
            capture_epoch=grant.capture_epoch,
            frame_ids=(harness.frame_ids(1)[0],) * 2,
        )
    assert duplicate.value.reason is OcrFailureReasonV1.REQUEST_REJECTED
    with pytest.raises(OcrServiceErrorV1) as too_many:
        await harness.protocol.coordinator._process_private_ocr_frames_v1(
            capture_epoch=grant.capture_epoch,
            frame_ids=harness.frame_ids(*range(1, MAX_OCR_FRAMES_PER_OPERATION_V1 + 2)),
        )
    assert too_many.value.reason is OcrFailureReasonV1.REQUEST_REJECTED


@pytest.mark.asyncio
async def test_public_status_and_seal_do_not_expose_or_publish_ocr(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(3)
    await harness.process(grant, 1)

    status = await harness.protocol.coordinator.capture_public_status_v1(
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.protocol.session_id,
        owner_issuer=harness.protocol.owner_issuer,
        owner_subject=harness.protocol.owner_subject,
    )
    assert OCR_CANARY_V1 not in repr(status)
    assert not hasattr(status, "ocr")
    request_id = uuid.uuid4()
    with pytest.raises(CaptureProtocolErrorV1) as unavailable:
        await harness.protocol.coordinator.seal_capture_protocol_v1(
            request_id=request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.protocol.session_id,
            owner_issuer=harness.protocol.owner_issuer,
            owner_subject=harness.protocol.owner_subject,
        )
    assert unavailable.value.reason is CaptureProtocolReasonV1.PROCESSOR_NOT_READY
    assert harness.protocol.coordinator.snapshot_v1().state is CaptureStateV1.CAPTURING


@pytest.mark.asyncio
async def test_missing_sidecar_is_internal_ocr_unavailable_only(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    grant, _ = await harness.begin_with_frames(1)

    with pytest.raises(OcrServiceErrorV1) as unavailable:
        await harness.protocol.coordinator._process_private_ocr_frames_v1(
            capture_epoch=grant.capture_epoch,
            frame_ids=harness.frame_ids(1),
        )

    assert unavailable.value.reason is OcrFailureReasonV1.OCR_UNAVAILABLE
    assert harness.protocol.coordinator.snapshot_v1().state is CaptureStateV1.CAPTURING

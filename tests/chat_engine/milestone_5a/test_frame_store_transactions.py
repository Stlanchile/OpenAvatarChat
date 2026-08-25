from __future__ import annotations

import asyncio
import gc
import hashlib
import weakref
from dataclasses import fields

import pytest

from certificate_capture.contracts.evidence import (
    CaptureSetV1,
    EvidenceFrameV1,
)
from certificate_capture.private_codec import (
    PRIVATE_CODEC_OVERHEAD_BYTES_V1,
)
from certificate_capture.private_store import (
    AES_GCM_TAG_BYTES_V1,
    EncryptedRecordV1,
    PrivateEvidenceStoreFaultPointV1,
)
from certificate_capture.protocol import (
    MAX_CAPTURE_FRAMES_V1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from certificate_capture.state import CaptureStateV1
from tests.chat_engine.milestone_5a.conftest import synthetic_jpeg_v1


class WeakBytearrayV1(bytearray):
    pass


@pytest.mark.asyncio
async def test_first_frame_is_ciphertext_only_and_evidence_contracts_are_exact(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1(color=(90, 80, 70))
    expected = bytes(encoded)

    result = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    partition = store._partition
    assert partition is not None
    evidence_record = coordinator._frame_records_v1[1]
    evidence = evidence_record.evidence_frame
    encrypted = partition.records[evidence.encrypted_record_ref]

    assert result.state is CaptureStateV1.CAPTURING
    assert isinstance(evidence, EvidenceFrameV1)
    assert isinstance(partition.capture_set, CaptureSetV1)
    assert isinstance(encrypted, EncryptedRecordV1)
    assert {field.name for field in fields(evidence)} == {
        "frame_id",
        "frame_seq",
        "received_at_epoch_seconds",
        "encoded_size",
        "canonical_width",
        "canonical_height",
        "sha256",
        "capture_epoch",
        "encrypted_record_ref",
        "schema_version",
    }
    assert {field.name for field in fields(partition.capture_set)} == {
        "capture_epoch",
        "profile_id",
        "capture_created_at_epoch_seconds",
        "capture_window",
        "frame_record_ids",
        "inference_identity_ref",
        "calibration_dependency_ref",
        "schema_version",
    }
    assert evidence.capture_epoch is grant.capture_epoch
    assert partition.capture_set.capture_epoch is grant.capture_epoch
    assert partition.capture_set.frame_record_ids == (
        evidence.frame_id,
    )
    assert partition.capture_set.capture_set_sha256 == hashlib.sha256(
        partition.capture_set.canonical_json_v1()
    ).hexdigest()
    assert evidence.evidence_frame_sha256 == hashlib.sha256(
        evidence.canonical_json_v1()
    ).hexdigest()
    assert (
        partition.capture_set.canonical_json_v1()
        == partition.capture_set.canonical_json_v1()
    )
    assert encrypted.ciphertext != expected
    assert expected not in encrypted.ciphertext
    assert not isinstance(encrypted.ciphertext, bytearray)
    assert all(
        "plaintext" not in field.name or field.name == "plaintext_length"
        for field in fields(encrypted)
    )
    snapshot = store.snapshot_v1()
    assert snapshot.accepted_plaintext_encoded_bytes == len(expected)
    assert snapshot.stored_frame_ciphertext_bytes == (
        len(expected)
        + PRIVATE_CODEC_OVERHEAD_BYTES_V1
        + AES_GCM_TAG_BYTES_V1
    )


@pytest.mark.asyncio
async def test_authorized_internal_read_returns_exact_request_local_jpeg(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1(color=(1, 44, 99))
    expected = bytes(encoded)
    await harness.upload(grant, frame_seq=1, encoded_frame=encoded)

    assert harness.read_frame(grant, 1) == expected
    partition = (
        harness.protocol.coordinator._private_evidence_store_v1._partition
    )
    assert partition is not None
    assert all(
        value != expected
        for value in (
            getattr(partition, field.name)
            for field in fields(partition)
        )
        if isinstance(value, bytes)
    )


@pytest.mark.asyncio
async def test_successful_commit_releases_request_plaintext_reference(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = WeakBytearrayV1(synthetic_jpeg_v1())
    reference = weakref.ref(encoded)

    await harness.upload(grant, frame_seq=1, encoded_frame=encoded)
    del encoded
    gc.collect()

    assert reference() is None


@pytest.mark.asyncio
async def test_same_sequence_retry_reuses_frame_record_nonce_and_accounting(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()

    first = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    first_evidence = coordinator._frame_records_v1[1].evidence_frame
    partition = store._partition
    assert partition is not None
    first_record = partition.records[first_evidence.encrypted_record_ref]
    first_snapshot = store.snapshot_v1()
    store._set_fault_hook_for_test_v1(
        lambda point: (_ for _ in ()).throw(
            AssertionError(f"retry reached encryption: {point.value}")
        )
    )

    retry = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )

    assert retry == first
    assert coordinator._frame_records_v1[1].evidence_frame is first_evidence
    assert store.snapshot_v1() == first_snapshot
    assert (
        partition.records[first_evidence.encrypted_record_ref]
        is first_record
    )


@pytest.mark.asyncio
async def test_sequence_conflict_creates_no_private_store_mutation(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(color=(1, 2, 3)),
    )
    store = harness.protocol.coordinator._private_evidence_store_v1
    before = store.snapshot_v1()

    with pytest.raises(CaptureProtocolErrorV1) as conflict:
        await harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=synthetic_jpeg_v1(color=(4, 5, 6)),
        )

    assert (
        conflict.value.reason
        is CaptureProtocolReasonV1.FRAME_SEQUENCE_CONFLICT
    )
    assert store.snapshot_v1() == before


@pytest.mark.asyncio
async def test_multiple_frames_have_unique_server_ids_nonces_and_ordered_set(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    for frame_seq in range(1, MAX_CAPTURE_FRAMES_V1 + 1):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(
                color=(frame_seq, frame_seq + 1, frame_seq + 2)
            ),
        )
    coordinator = harness.protocol.coordinator
    partition = coordinator._private_evidence_store_v1._partition
    assert partition is not None
    evidence = [
        coordinator._frame_records_v1[frame_seq].evidence_frame
        for frame_seq in range(1, MAX_CAPTURE_FRAMES_V1 + 1)
    ]
    records = [
        partition.records[item.encrypted_record_ref]
        for item in evidence
    ]

    assert len({item.frame_id for item in evidence}) == MAX_CAPTURE_FRAMES_V1
    assert (
        len({item.encrypted_record_ref for item in evidence})
        == MAX_CAPTURE_FRAMES_V1
    )
    assert len({record.nonce for record in records}) == MAX_CAPTURE_FRAMES_V1
    assert partition.capture_set.frame_record_ids == tuple(
        item.frame_id for item in evidence
    )
    assert coordinator._private_evidence_store_v1.snapshot_v1().frame_record_count == (
        MAX_CAPTURE_FRAMES_V1
    )

    with pytest.raises(CaptureProtocolErrorV1):
        await harness.upload(
            grant,
            frame_seq=MAX_CAPTURE_FRAMES_V1 + 1,
            encoded_frame=synthetic_jpeg_v1(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_point",
    tuple(PrivateEvidenceStoreFaultPointV1),
)
async def test_store_boundary_failure_rolls_back_frame_acceptance(
    milestone_5a_harness_factory,
    fault_point,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1

    def fail_at(point):
        if point is fault_point:
            raise RuntimeError("synthetic store boundary failure")

    store._set_fault_hook_for_test_v1(fail_at)
    with pytest.raises(CaptureProtocolErrorV1) as failure:
        await harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=synthetic_jpeg_v1(),
        )

    assert (
        failure.value.reason
        is CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
    )
    assert coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    assert coordinator._frame_records_v1 == {}
    assert coordinator._accepted_frame_bytes_v1 == 0
    snapshot = store.snapshot_v1()
    assert snapshot.frame_record_count == 0
    assert snapshot.accepted_plaintext_encoded_bytes == 0
    assert snapshot.stored_frame_ciphertext_bytes == 0
    partition = store._partition
    assert partition is not None
    nonce_counter_after_failure = partition.nonce_counter
    store._set_fault_hook_for_test_v1(None)
    accepted = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    assert accepted.accepted_frame_count == 1
    evidence = coordinator._frame_records_v1[1].evidence_frame
    accepted_record = partition.records[evidence.encrypted_record_ref]
    assert int.from_bytes(accepted_record.nonce, "big") == (
        nonce_counter_after_failure + 1
    )
    if fault_point in {
        PrivateEvidenceStoreFaultPointV1
        .AFTER_ENCRYPTION_BEFORE_INSERTION,
        PrivateEvidenceStoreFaultPointV1
        .AFTER_INSERTION_BEFORE_METADATA_COMMIT,
    }:
        assert nonce_counter_after_failure > 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_point",
    tuple(PrivateEvidenceStoreFaultPointV1),
)
async def test_cancellation_at_store_boundaries_leaves_frame_fully_absent(
    milestone_5a_harness_factory,
    fault_point,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1

    def cancel_at(point):
        if point is fault_point:
            raise asyncio.CancelledError

    store._set_fault_hook_for_test_v1(cancel_at)
    with pytest.raises(asyncio.CancelledError):
        await harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=synthetic_jpeg_v1(),
        )

    assert coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    assert coordinator._frame_records_v1 == {}
    assert store.snapshot_v1().frame_record_count == 0


@pytest.mark.asyncio
async def test_metadata_commit_failure_removes_new_encrypted_record(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    coordinator._set_frame_metadata_commit_hook_for_test_v1(
        lambda: (_ for _ in ()).throw(
            RuntimeError("synthetic metadata commit failure")
        )
    )

    with pytest.raises(CaptureProtocolErrorV1) as failure:
        await harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=synthetic_jpeg_v1(),
        )

    assert (
        failure.value.reason
        is CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
    )
    assert coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    assert coordinator._frame_records_v1 == {}
    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.frame_record_count == 0
    assert snapshot.stored_frame_ciphertext_bytes == 0
    coordinator._set_frame_metadata_commit_hook_for_test_v1(None)
    accepted = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    assert accepted.accepted_frame_count == 1


@pytest.mark.asyncio
async def test_two_concurrent_frame_commits_are_both_exactly_once(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    first, second = await asyncio.gather(
        harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=synthetic_jpeg_v1(color=(31, 32, 33)),
        ),
        harness.upload(
            grant,
            frame_seq=2,
            encoded_frame=synthetic_jpeg_v1(color=(41, 42, 43)),
        ),
    )
    coordinator = harness.protocol.coordinator
    partition = coordinator._private_evidence_store_v1._partition
    assert partition is not None

    assert {first.frame_seq, second.frame_seq} == {1, 2}
    assert set(coordinator._frame_records_v1) == {1, 2}
    assert partition.capture_set.frame_record_ids == tuple(
        coordinator._frame_records_v1[frame_seq].evidence_frame.frame_id
        for frame_seq in (1, 2)
    )
    assert len({record.nonce for record in partition.records.values()}) == 2

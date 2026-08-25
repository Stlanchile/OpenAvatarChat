from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import replace

import pytest

from certificate_capture.contracts.common import canonical_json_bytes_v1
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.private_authority import (
    PrivateEvidenceAccessKindV1,
    PrivateEvidenceAccessV1,
)
from certificate_capture.private_codec import PrivateEvidenceRecordTypeV1
from certificate_capture.private_store import (
    AES_256_KEY_BYTES_V1,
    AES_GCM_NONCE_BYTES_V1,
    EncryptedRecordV1,
    PrivateEvidenceStoreErrorV1,
    PrivateEvidenceStoreReasonV1,
)
from certificate_capture.state import CaptureStateV1
from chat_engine.security.envelope import (
    EgressPolicyV1,
    SecurityClassificationV1,
)
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import new_uuid7_v1
from tests.chat_engine.milestone_5a.conftest import synthetic_jpeg_v1


def _live_record_v1(harness, frame_seq: int = 1):
    coordinator = harness.protocol.coordinator
    evidence = coordinator._frame_records_v1[frame_seq].evidence_frame
    partition = coordinator._private_evidence_store_v1._partition
    assert partition is not None
    return partition, evidence, partition.records[evidence.encrypted_record_ref]


@pytest.mark.asyncio
async def test_aes_256_gcm_contract_and_many_record_nonce_uniqueness(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    for frame_seq in range(1, 9):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(
                color=(frame_seq, frame_seq + 10, frame_seq + 20)
            ),
        )
    partition = (
        harness.protocol.coordinator._private_evidence_store_v1._partition
    )
    assert partition is not None
    records = tuple(partition.records.values())
    first_evidence = (
        harness.protocol.coordinator._frame_records_v1[1].evidence_frame
    )
    aad = json.loads(
        harness.protocol.coordinator._private_evidence_store_v1._aad_v1(
            grant.capture_epoch,
            first_evidence.encrypted_record_ref,
            PrivateEvidenceRecordTypeV1.FRAME_JPEG,
        )
    )

    assert AES_256_KEY_BYTES_V1 == 32
    assert AES_GCM_NONCE_BYTES_V1 == 12
    assert len({record.nonce for record in records}) == len(records)
    assert all(len(record.nonce) == 12 for record in records)
    assert all(isinstance(record, EncryptedRecordV1) for record in records)
    assert aad == {
        "aad_schema_version": "oac.private-evidence-aad.v1",
        "capture_id": str(grant.capture_epoch.capture_id),
        "capture_seq": grant.capture_epoch.capture_seq,
        "codec_schema_version": "oac.private-evidence-codec.v1",
        "record_id": str(first_evidence.encrypted_record_ref),
        "record_type": "FRAME_JPEG",
        "schema_version": "oac.encrypted-record.v1",
        "session_generation": (
            grant.capture_epoch.session_epoch.generation
        ),
        "session_instance_id": str(
            grant.capture_epoch.session_epoch.session_instance_id
        ),
    }
    for frame_seq in range(1, 9):
        assert harness.read_frame(grant, frame_seq).startswith(b"\xff\xd8")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper_kind",
    (
        "nonce",
        "ciphertext",
        "tag",
        "truncated",
        "aad_record_id",
        "record_type",
        "wrong_key",
        "missing_key",
    ),
)
async def test_tamper_and_missing_key_never_return_plaintext_and_fail_closed(
    milestone_5a_harness_factory,
    tamper_kind,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1(color=(9, 8, 7))
    await harness.upload(grant, frame_seq=1, encoded_frame=encoded)
    coordinator = harness.protocol.coordinator
    partition, evidence, record = _live_record_v1(harness)

    if tamper_kind == "nonce":
        replacement = replace(
            record,
            nonce=bytes((record.nonce[0] ^ 1,)) + record.nonce[1:],
        )
    elif tamper_kind == "ciphertext":
        replacement = replace(
            record,
            ciphertext=bytes((record.ciphertext[0] ^ 1,))
            + record.ciphertext[1:],
        )
    elif tamper_kind == "tag":
        replacement = replace(
            record,
            ciphertext=record.ciphertext[:-1]
            + bytes((record.ciphertext[-1] ^ 1,)),
        )
    elif tamper_kind == "truncated":
        truncated = record.ciphertext[:-1]
        replacement = replace(
            record,
            ciphertext=truncated,
            plaintext_length=len(truncated) - 16,
        )
    elif tamper_kind == "aad_record_id":
        replacement = replace(record, record_id=new_uuid7_v1())
    elif tamper_kind == "record_type":
        replacement = replace(
            record,
            record_type=(
                PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON
            ),
        )
    elif tamper_kind == "wrong_key":
        coordinator._private_evidence_store_v1._key_authority._key = (
            secrets.token_bytes(AES_256_KEY_BYTES_V1)
        )
        replacement = record
    else:
        assert coordinator._private_evidence_store_v1._key_authority.destroy_v1(
            grant.capture_epoch
        )
        replacement = record
    partition.records[evidence.encrypted_record_ref] = replacement
    read_work = harness.register_read(grant.capture_epoch)
    try:
        with pytest.raises(PrivateEvidenceStoreErrorV1) as failure:
            coordinator._read_private_frame_for_test_v1(
                capture_epoch=grant.capture_epoch,
                frame_id=evidence.frame_id,
                registered_work=read_work,
                access=coordinator._private_store_read_access_v1,
            )
    finally:
        harness.protocol.controller.release_work_v1(read_work.lease)

    assert failure.value.reason in {
        PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE,
        PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE,
        PrivateEvidenceStoreReasonV1.RECORD_TYPE_MISMATCH,
    }
    assert bytes(encoded) not in str(failure.value).encode()
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert coordinator._private_evidence_store_v1.is_capture_clear_v1()


@pytest.mark.asyncio
@pytest.mark.parametrize("whole_record_swap", (False, True))
async def test_cross_frame_aad_or_complete_record_swap_fails_closed(
    milestone_5a_harness_factory,
    whole_record_swap,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(color=(1, 1, 1)),
    )
    await harness.upload(
        grant,
        frame_seq=2,
        encoded_frame=synthetic_jpeg_v1(color=(2, 2, 2)),
    )
    coordinator = harness.protocol.coordinator
    partition, first_evidence, first = _live_record_v1(harness, 1)
    _, _, second = _live_record_v1(harness, 2)
    if whole_record_swap:
        replacement = second
    else:
        replacement = replace(
            first,
            nonce=second.nonce,
            ciphertext=second.ciphertext,
            plaintext_length=second.plaintext_length,
        )
    partition.records[first_evidence.encrypted_record_ref] = replacement

    work = harness.register_read(grant.capture_epoch)
    try:
        with pytest.raises(PrivateEvidenceStoreErrorV1) as failure:
            coordinator._read_private_frame_for_test_v1(
                capture_epoch=grant.capture_epoch,
                frame_id=first_evidence.frame_id,
                registered_work=work,
                access=coordinator._private_store_read_access_v1,
            )
    finally:
        harness.protocol.controller.release_work_v1(work.lease)

    assert (
        failure.value.reason
        is PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
    )
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED


@pytest.mark.asyncio
async def test_complete_auxiliary_record_swap_is_rejected(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    write_work = harness.register_auxiliary(grant.capture_epoch)
    try:
        first_id = store.put_record_v1(
            access=coordinator._private_store_write_access_v1,
            capture_epoch=grant.capture_epoch,
            fence=write_work.fence,
            canonical_json_payload=canonical_json_bytes_v1(
                {"record": 1, "schema_version": "synthetic.v1"}
            ),
            created_at_epoch_seconds=harness.protocol.clock.wall(),
        )
        second_id = store.put_record_v1(
            access=coordinator._private_store_write_access_v1,
            capture_epoch=grant.capture_epoch,
            fence=write_work.fence,
            canonical_json_payload=canonical_json_bytes_v1(
                {"record": 2, "schema_version": "synthetic.v1"}
            ),
            created_at_epoch_seconds=harness.protocol.clock.wall(),
        )
    finally:
        harness.protocol.controller.release_work_v1(write_work.lease)
    partition = store._partition
    assert partition is not None
    partition.records[first_id] = partition.records[second_id]
    read_work = harness.register_read(grant.capture_epoch)
    try:
        with pytest.raises(PrivateEvidenceStoreErrorV1) as failure:
            store.get_record_v1(
                access=coordinator._private_store_read_access_v1,
                capture_epoch=grant.capture_epoch,
                fence=read_work.fence,
                record_id=first_id,
                expected_record_type=(
                    PrivateEvidenceRecordTypeV1
                    .AUXILIARY_CANONICAL_JSON
                ),
            )
    finally:
        harness.protocol.controller.release_work_v1(read_work.lease)

    assert (
        failure.value.reason
        is PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
    )


@pytest.mark.asyncio
async def test_cross_capture_ciphertext_swap_uses_unrelated_new_key(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    first_grant = await harness.begin()
    await harness.upload(
        first_grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(color=(3, 3, 3)),
    )
    _, _, stale_record = _live_record_v1(harness)
    await harness.protocol.coordinator.end_capture_v1(
        first_grant.capture_epoch
    )

    second_grant = await harness.begin(control_seq=2)
    await harness.upload(
        second_grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(color=(4, 4, 4)),
    )
    coordinator = harness.protocol.coordinator
    partition, evidence, current_record = _live_record_v1(harness)
    partition.records[evidence.encrypted_record_ref] = replace(
        current_record,
        nonce=stale_record.nonce,
        ciphertext=stale_record.ciphertext,
        plaintext_length=stale_record.plaintext_length,
    )

    work = harness.register_read(second_grant.capture_epoch)
    try:
        with pytest.raises(PrivateEvidenceStoreErrorV1) as failure:
            coordinator._read_private_frame_for_test_v1(
                capture_epoch=second_grant.capture_epoch,
                frame_id=evidence.frame_id,
                registered_work=work,
                access=coordinator._private_store_read_access_v1,
            )
    finally:
        harness.protocol.controller.release_work_v1(work.lease)

    assert (
        failure.value.reason
        is PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
    )


@pytest.mark.asyncio
async def test_store_requires_exact_m2_access_exact_capture_and_live_m3_fence(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()
    await harness.upload(grant, frame_seq=1, encoded_frame=encoded)
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    evidence = coordinator._frame_records_v1[1].evidence_frame
    read_access = coordinator._private_store_read_access_v1

    work = harness.register_read(grant.capture_epoch)
    assert (
        coordinator._read_private_frame_for_test_v1(
            capture_epoch=grant.capture_epoch,
            frame_id=evidence.frame_id,
            registered_work=work,
            access=read_access,
        )
        == bytes(encoded)
    )

    forged_access = PrivateEvidenceAccessV1(
        authority_id=read_access.authority_id,
        access_id=read_access.access_id,
        kind=read_access.kind,
    )
    wrong_capture = CaptureEpochV1(
        session_epoch=grant.capture_epoch.session_epoch,
        capture_id=new_uuid7_v1(),
        capture_seq=grant.capture_epoch.capture_seq,
    )
    wrong_session_capture = CaptureEpochV1(
        session_epoch=SessionEpochV1(new_uuid7_v1(), 1),
        capture_id=new_uuid7_v1(),
        capture_seq=1,
    )
    wrong_generation_capture = CaptureEpochV1(
        session_epoch=SessionEpochV1(
            grant.capture_epoch.session_epoch.session_instance_id,
            grant.capture_epoch.session_epoch.generation + 1,
        ),
        capture_id=grant.capture_epoch.capture_id,
        capture_seq=grant.capture_epoch.capture_seq,
    )
    for access, capture_epoch in (
        (forged_access, grant.capture_epoch),
        (coordinator._private_store_write_access_v1, grant.capture_epoch),
        (grant.capture_capability, grant.capture_epoch),
        (read_access, wrong_capture),
        (read_access, wrong_session_capture),
        (read_access, wrong_generation_capture),
    ):
        with pytest.raises(PrivateEvidenceStoreErrorV1):
            store.get_frame_v1(
                access=access,
                capture_epoch=capture_epoch,
                fence=work.fence,
                frame_id=evidence.frame_id,
            )
    harness.protocol.controller.release_work_v1(work.lease)

    stale_work = harness.register_read(grant.capture_epoch)
    harness.protocol.controller.release_work_v1(stale_work.lease)
    with pytest.raises(PrivateEvidenceStoreErrorV1):
        store.get_frame_v1(
            access=read_access,
            capture_epoch=grant.capture_epoch,
            fence=stale_work.fence,
            frame_id=evidence.frame_id,
        )
    await coordinator.end_capture_v1(grant.capture_epoch)
    with pytest.raises(PrivateEvidenceStoreErrorV1):
        store.get_frame_v1(
            access=read_access,
            capture_epoch=grant.capture_epoch,
            fence=stale_work.fence,
            frame_id=evidence.frame_id,
        )


def test_private_m2_registration_is_narrow_and_not_generic():
    from certificate_capture.private_authority import (
        PrivateEvidenceAuthorityV1,
    )
    from chat_engine.security.authority import SecurityAuthorityV1

    authority, registrar = SecurityAuthorityV1.create_v1()
    private = PrivateEvidenceAuthorityV1._create_for_session_v1(
        security_authority=authority,
        registrar=registrar,
    )
    try:
        capability = private._consumer_capability
        assert capability.allowed_classifications == frozenset(
            {SecurityClassificationV1.CERTIFICATE_PRIVATE}
        )
        assert capability.allowed_egress_policies == frozenset(
            {EgressPolicyV1.INTERNAL_ONLY}
        )
        assert (
            private._access_for_core_v1(
                PrivateEvidenceAccessKindV1.READ
            )
            is not private._access_for_core_v1(
                PrivateEvidenceAccessKindV1.WRITE
            )
        )
    finally:
        private.close_v1()
        authority.close()


@pytest.mark.asyncio
async def test_bounded_auxiliary_record_put_read_delete_and_capacity(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    work = harness.register_auxiliary(grant.capture_epoch)
    record_ids: list[uuid.UUID] = []
    try:
        for index in range(16):
            payload = canonical_json_bytes_v1(
                {
                    "index": index,
                    "schema_version": "synthetic-auxiliary.v1",
                }
            )
            record_ids.append(
                store.put_record_v1(
                    access=coordinator._private_store_write_access_v1,
                    capture_epoch=grant.capture_epoch,
                    fence=work.fence,
                    canonical_json_payload=payload,
                    created_at_epoch_seconds=harness.protocol.clock.wall(),
                )
            )
        with pytest.raises(PrivateEvidenceStoreErrorV1) as full:
            store.put_record_v1(
                access=coordinator._private_store_write_access_v1,
                capture_epoch=grant.capture_epoch,
                fence=work.fence,
                canonical_json_payload=canonical_json_bytes_v1(
                    {
                        "index": 17,
                        "schema_version": "synthetic-auxiliary.v1",
                    }
                ),
                created_at_epoch_seconds=harness.protocol.clock.wall(),
            )
        assert (
            full.value.reason
            is PrivateEvidenceStoreReasonV1.CAPACITY_EXCEEDED
        )
    finally:
        harness.protocol.controller.release_work_v1(work.lease)

    read_work = harness.register_read(grant.capture_epoch)
    try:
        payload = store.get_record_v1(
            access=coordinator._private_store_read_access_v1,
            capture_epoch=grant.capture_epoch,
            fence=read_work.fence,
            record_id=record_ids[0],
            expected_record_type=(
                PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON
            ),
        )
        assert b'"index":0' in payload
    finally:
        harness.protocol.controller.release_work_v1(read_work.lease)

    delete_work = harness.register_auxiliary(grant.capture_epoch)
    try:
        assert store.delete_record_v1(
            access=coordinator._private_store_delete_access_v1,
            capture_epoch=grant.capture_epoch,
            fence=delete_work.fence,
            record_id=record_ids[0],
        )
    finally:
        harness.protocol.controller.release_work_v1(delete_work.lease)


@pytest.mark.asyncio
async def test_concurrent_store_operation_slots_are_strictly_bounded(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()
    await harness.upload(grant, frame_seq=1, encoded_frame=encoded)
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    evidence = coordinator._frame_records_v1[1].evidence_frame
    work = harness.register_read(grant.capture_epoch)
    acquired = [
        store._operation_slots.acquire(blocking=False)
        for _ in range(4)
    ]
    try:
        assert acquired == [True, True, True, True]
        with pytest.raises(PrivateEvidenceStoreErrorV1) as busy:
            store.get_frame_v1(
                access=coordinator._private_store_read_access_v1,
                capture_epoch=grant.capture_epoch,
                fence=work.fence,
                frame_id=evidence.frame_id,
            )
        assert (
            busy.value.reason
            is PrivateEvidenceStoreReasonV1.OPERATION_BUSY
        )
    finally:
        for was_acquired in acquired:
            if was_acquired:
                store._operation_slots.release()
        harness.protocol.controller.release_work_v1(work.lease)

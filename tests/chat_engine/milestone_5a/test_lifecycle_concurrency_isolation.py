from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import replace

import pytest
from loguru import logger

from certificate_capture.coordinator import CaptureFailedClosedV1
from certificate_capture.frame_ingress import validate_private_jpeg_v1
from certificate_capture.private_authority import (
    PrivateEvidenceAccessKindV1,
)
from certificate_capture.private_store import (
    PrivateEvidenceCleanupStepV1,
    PrivateEvidenceStoreErrorV1,
    PrivateEvidenceStoreV1,
)
from certificate_capture.protocol import CaptureProtocolErrorV1
from certificate_capture.state import CaptureStateV1
from chat_engine.security.ids import new_uuid7_v1
from tests.chat_engine.milestone_4b.test_isolation_cleanup_and_smoke import (
    ChatAgentHandler,
    ChatData,
    HandlerDataTool,
    HandlerTTS,
    PerceptionHandler,
    RtcStream,
    SessionHistory,
    SignalManager,
    StreamManager,
    WorkingMemory,
    WsClientHandler,
)
from tests.chat_engine.milestone_5a.conftest import synthetic_jpeg_v1

EXPECTED_CLEANUP_TRACE_V1 = (
    PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED,
    PrivateEvidenceCleanupStepV1.KEY_DESTROYED,
    PrivateEvidenceCleanupStepV1.CIPHERTEXT_CLEARED,
    PrivateEvidenceCleanupStepV1.INDICES_CLEARED,
    PrivateEvidenceCleanupStepV1.METADATA_CLEARED,
)


async def _wait_for_state_v1(coordinator, state: CaptureStateV1) -> None:
    deadline = time.monotonic() + 2.0
    while coordinator.snapshot_v1().state is not state:
        if time.monotonic() >= deadline:
            raise AssertionError(f"capture did not reach {state.value}")
        await asyncio.sleep(0.005)


def _assert_private_cleanup_v1(harness) -> None:
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    assert store.is_capture_clear_v1()
    assert store.cleanup_trace_v1() == EXPECTED_CLEANUP_TRACE_V1
    assert coordinator._frame_records_v1 == {}
    assert coordinator._unique_frame_digests_v1 == set()
    assert coordinator._accepted_frame_bytes_v1 == 0
    assert coordinator._profile_id_v1 is None


@pytest.mark.asyncio
async def test_end_capture_destroys_key_first_and_denies_every_late_operation(
    milestone_5a_harness_factory,
    monkeypatch,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()
    await harness.upload(grant, frame_seq=1, encoded_frame=encoded)
    coordinator = harness.protocol.coordinator
    store = coordinator._private_evidence_store_v1
    evidence = coordinator._frame_records_v1[1].evidence_frame
    stale_read = harness.register_read(grant.capture_epoch)
    harness.protocol.controller.release_work_v1(stale_read.lease)
    cleanup_fences = []
    original_destroy = PrivateEvidenceStoreV1.destroy_capture_v1

    def observe_destroy(self, **kwargs):
        if self is store:
            cleanup_fences.append(kwargs["cleanup_fence"])
        return original_destroy(self, **kwargs)

    monkeypatch.setattr(
        PrivateEvidenceStoreV1,
        "destroy_capture_v1",
        observe_destroy,
    )

    await coordinator.end_capture_v1(grant.capture_epoch)

    _assert_private_cleanup_v1(harness)
    assert coordinator.snapshot_v1().state is CaptureStateV1.IDLE
    with pytest.raises(PrivateEvidenceStoreErrorV1):
        store.get_frame_v1(
            access=coordinator._private_store_read_access_v1,
            capture_epoch=grant.capture_epoch,
            fence=stale_read.fence,
            frame_id=evidence.frame_id,
        )
    assert len(cleanup_fences) == 1
    assert store.destroy_capture_v1(
        access=coordinator._private_store_cleanup_access_v1,
        capture_epoch=grant.capture_epoch,
        cleanup_fence=cleanup_fences[0],
    )
    assert not store.destroy_capture_v1(
        access=coordinator._private_store_cleanup_access_v1,
        capture_epoch=grant.capture_epoch,
        cleanup_fence=replace(
            cleanup_fences[0],
            cleanup_id=new_uuid7_v1(),
        ),
    )
    assert store.cleanup_trace_v1() == EXPECTED_CLEANUP_TRACE_V1


@pytest.mark.asyncio
async def test_inactivity_expiry_uses_same_key_first_cleanup(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )

    harness.protocol.clock.advance(301)
    harness.protocol.wake_inactivity_timer()
    await _wait_for_state_v1(
        harness.protocol.coordinator,
        CaptureStateV1.IDLE,
    )

    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_end_after_m2_revocation_still_uses_cleanup_only_authority(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    coordinator = harness.protocol.coordinator
    harness.protocol.security_authority.close()

    ended = await coordinator.end_capture_v1(grant.capture_epoch)

    assert ended.state is CaptureStateV1.IDLE
    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_store_cleanup_invariant_failure_retries_only_fail_closed(
    milestone_5a_harness_factory,
    monkeypatch,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    coordinator = harness.protocol.coordinator
    key_authority = (
        coordinator._private_evidence_store_v1._key_authority
    )
    key_authority_type = type(key_authority)
    original_destroy = key_authority_type.destroy_v1
    attempts = 0

    def fail_once(self, capture_epoch):
        nonlocal attempts
        if self is key_authority:
            attempts += 1
            if attempts == 1:
                return False
        return original_destroy(self, capture_epoch)

    monkeypatch.setattr(
        key_authority_type,
        "destroy_v1",
        fail_once,
    )

    with pytest.raises(CaptureFailedClosedV1):
        await coordinator.end_capture_v1(grant.capture_epoch)

    assert attempts == 2
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_kind",
    (
        "failed_closed",
        "shutdown",
        "session_disconnect",
        "session_revoke",
        "session_replacement",
    ),
)
async def test_emergency_terminal_paths_are_idempotent_key_first_erasure(
    milestone_5a_harness_factory,
    terminal_kind,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    coordinator = harness.protocol.coordinator

    if terminal_kind == "failed_closed":
        coordinator._fail_closed_for_test_v1()
    else:
        if terminal_kind in {"session_revoke", "session_replacement"}:
            harness.protocol.session_live = False
        assert await coordinator.shutdown_async_v1()
    await asyncio.sleep(0)

    _assert_private_cleanup_v1(harness)
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert await coordinator.shutdown_async_v1()
    assert coordinator._private_evidence_store_v1.is_capture_clear_v1()


@pytest.mark.asyncio
async def test_write_losing_to_end_cannot_leave_ciphertext_or_metadata(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory(cleanup_timeout_seconds=1.0)
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    encoded = synthetic_jpeg_v1()
    validated = validate_private_jpeg_v1(encoded)
    permit = await coordinator.admit_frame_upload_v1(
        capture_id=grant.capture_epoch.capture_id,
        frame_seq=1,
        capture_capability=grant.capture_capability,
        session_id=harness.protocol.session_id,
        owner_issuer=harness.protocol.owner_issuer,
        owner_subject=harness.protocol.owner_subject,
    )
    ending = asyncio.create_task(
        coordinator.end_capture_v1(grant.capture_epoch)
    )
    await _wait_for_state_v1(coordinator, CaptureStateV1.ENDING)

    with pytest.raises(CaptureProtocolErrorV1):
        await coordinator.commit_frame_upload_v1(
            permit,
            validated,
            encoded,
        )
    coordinator.release_frame_upload_permit_v1(permit)
    await ending

    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_read_losing_to_end_is_denied_and_end_waits_for_lease_release(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory(cleanup_timeout_seconds=1.0)
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    coordinator = harness.protocol.coordinator
    evidence = coordinator._frame_records_v1[1].evidence_frame
    work = harness.register_read(grant.capture_epoch)
    ending = asyncio.create_task(
        coordinator.end_capture_v1(grant.capture_epoch)
    )
    await _wait_for_state_v1(coordinator, CaptureStateV1.ENDING)

    with pytest.raises(PrivateEvidenceStoreErrorV1):
        coordinator._read_private_frame_for_test_v1(
            capture_epoch=grant.capture_epoch,
            frame_id=evidence.frame_id,
            registered_work=work,
            access=coordinator._private_store_read_access_v1,
        )
    assert not ending.done()
    harness.protocol.controller.release_work_v1(work.lease)
    await ending

    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_write_and_read_losing_to_expiry_are_denied_without_resurrection(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory(cleanup_timeout_seconds=1.0)
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    coordinator = harness.protocol.coordinator
    evidence = coordinator._frame_records_v1[1].evidence_frame
    read_work = harness.register_read(grant.capture_epoch)
    late_encoded = synthetic_jpeg_v1(color=(8, 7, 6))
    late_validated = validate_private_jpeg_v1(late_encoded)
    late_permit = await coordinator.admit_frame_upload_v1(
        capture_id=grant.capture_epoch.capture_id,
        frame_seq=2,
        capture_capability=grant.capture_capability,
        session_id=harness.protocol.session_id,
        owner_issuer=harness.protocol.owner_issuer,
        owner_subject=harness.protocol.owner_subject,
    )
    harness.protocol.clock.advance(301)
    harness.protocol.wake_inactivity_timer()
    await _wait_for_state_v1(coordinator, CaptureStateV1.ENDING)

    with pytest.raises(PrivateEvidenceStoreErrorV1):
        coordinator._read_private_frame_for_test_v1(
            capture_epoch=grant.capture_epoch,
            frame_id=evidence.frame_id,
            registered_work=read_work,
            access=coordinator._private_store_read_access_v1,
        )
    with pytest.raises(CaptureProtocolErrorV1):
        await coordinator.commit_frame_upload_v1(
            late_permit,
            late_validated,
            late_encoded,
        )
    harness.protocol.controller.release_work_v1(read_work.lease)
    coordinator.release_frame_upload_permit_v1(late_permit)
    await _wait_for_state_v1(coordinator, CaptureStateV1.IDLE)

    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_shutdown_cancels_late_write_and_cannot_resurrect_partition(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    coordinator = harness.protocol.coordinator
    encoded = synthetic_jpeg_v1()
    validated = validate_private_jpeg_v1(encoded)
    permit = await coordinator.admit_frame_upload_v1(
        capture_id=grant.capture_epoch.capture_id,
        frame_seq=1,
        capture_capability=grant.capture_capability,
        session_id=harness.protocol.session_id,
        owner_issuer=harness.protocol.owner_issuer,
        owner_subject=harness.protocol.owner_subject,
    )

    harness.protocol.session_live = False
    shutdown = asyncio.create_task(coordinator.shutdown_async_v1())
    await asyncio.sleep(0)
    coordinator.release_frame_upload_permit_v1(permit)
    assert await shutdown
    with pytest.raises(CaptureProtocolErrorV1):
        await coordinator.commit_frame_upload_v1(
            permit,
            validated,
            encoded,
        )

    _assert_private_cleanup_v1(harness)
    assert coordinator._private_evidence_store_v1.snapshot_v1().partition_open is False


@pytest.mark.asyncio
async def test_read_losing_to_session_revoke_is_denied_before_cleanup_ack(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory(cleanup_timeout_seconds=1.0)
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    coordinator = harness.protocol.coordinator
    evidence = coordinator._frame_records_v1[1].evidence_frame
    read_work = harness.register_read(grant.capture_epoch)
    harness.protocol.session_live = False
    shutdown = asyncio.create_task(coordinator.shutdown_async_v1())
    await asyncio.sleep(0)

    with pytest.raises(PrivateEvidenceStoreErrorV1):
        coordinator._read_private_frame_for_test_v1(
            capture_epoch=grant.capture_epoch,
            frame_id=evidence.frame_id,
            registered_work=read_work,
            access=coordinator._private_store_read_access_v1,
        )
    harness.protocol.controller.release_work_v1(read_work.lease)
    assert await shutdown

    _assert_private_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_frame_canary_never_reaches_generic_paths_or_logs(
    milestone_5a_harness_factory,
    caplog,
    monkeypatch,
):
    calls: list[str] = []

    def deny(name):
        def denied(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"private evidence reached {name}")

        return denied

    instrumented = (
        (ChatData, "__init__", "ChatData"),
        (StreamManager, "create_streamer", "StreamManager"),
        (SignalManager, "enqueue_signal_v1", "SignalManager"),
        (PerceptionHandler, "handle", "Perception"),
        (ChatAgentHandler, "handle", "ChatAgent"),
        (HandlerDataTool, "handle", "HandlerDataTool"),
        (SessionHistory, "add_event", "SessionHistory"),
        (
            SessionHistory,
            "accumulate_stream_data",
            "SessionHistoryAccumulator",
        ),
        (WorkingMemory, "add_turn", "WorkingMemory"),
        (HandlerTTS, "handle", "generic TTS"),
        (WsClientHandler, "handle", "WS generic output"),
        (RtcStream, "emit", "RTC audio output"),
        (RtcStream, "video_emit", "RTC video output"),
    )
    for owner, method, name in instrumented:
        monkeypatch.setattr(owner, method, deny(name))

    harness = milestone_5a_harness_factory()
    grant = await harness.begin()
    canary = b"M5A_PRIVATE_FRAME_CANARY_6dca1f"
    encoded = synthetic_jpeg_v1()
    insert_at = max(2, len(encoded) - 2)
    # JPEG application metadata segment with a valid bounded private canary.
    segment = b"\xff\xef" + (len(canary) + 2).to_bytes(2, "big") + canary
    encoded[insert_at:insert_at] = segment
    validated = validate_private_jpeg_v1(encoded)
    assert validated.encoded_size == len(encoded)

    caplog.set_level(logging.DEBUG)
    loguru_messages: list[str] = []
    loguru_sink = logger.add(
        lambda message: loguru_messages.append(str(message))
    )
    try:
        await harness.upload(grant, frame_seq=1, encoded_frame=encoded)
        assert harness.read_frame(grant, 1) == bytes(encoded)
        coordinator = harness.protocol.coordinator
        partition = coordinator._private_evidence_store_v1._partition
        assert partition is not None
        evidence = coordinator._frame_records_v1[1].evidence_frame
        encrypted = partition.records[evidence.encrypted_record_ref]
        assert canary not in encrypted.ciphertext
        await coordinator.end_capture_v1(grant.capture_epoch)
    finally:
        logger.remove(loguru_sink)

    assert canary.decode() not in caplog.text
    assert canary.decode() not in "".join(loguru_messages)
    assert coordinator._private_evidence_store_v1.is_capture_clear_v1()
    assert calls == []


@pytest.mark.asyncio
async def test_non_normative_crypto_performance_smoke(
    milestone_5a_harness_factory,
):
    harness = milestone_5a_harness_factory(cleanup_timeout_seconds=2.0)
    grant = await harness.begin()
    frame = synthetic_jpeg_v1(
        width=1920,
        height=1080,
        quality=95,
    )

    started = time.perf_counter()
    await harness.upload(grant, frame_seq=1, encoded_frame=frame)
    encrypt_seconds = time.perf_counter() - started

    started = time.perf_counter()
    assert harness.read_frame(grant, 1) == bytes(frame)
    decrypt_seconds = time.perf_counter() - started

    started = time.perf_counter()
    for frame_seq in range(2, 9):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(
                width=1920,
                height=1080,
                color=(frame_seq, frame_seq, frame_seq),
                quality=95,
            ),
        )
    populate_seconds = time.perf_counter() - started

    coordinator = harness.protocol.coordinator
    started = time.perf_counter()
    for _ in range(100):
        assert coordinator._private_evidence_authority_v1.authorizes_v1(
            coordinator._private_store_read_access_v1,
            PrivateEvidenceAccessKindV1.READ,
            audit_denial=False,
        )
    authority_seconds = time.perf_counter() - started

    started = time.perf_counter()
    await coordinator.end_capture_v1(grant.capture_epoch)
    destruction_seconds = time.perf_counter() - started

    assert all(
        value >= 0.0
        for value in (
            encrypt_seconds,
            decrypt_seconds,
            populate_seconds,
            destruction_seconds,
            authority_seconds,
        )
    )
    print(
        "MILESTONE_5A_PERFORMANCE_SMOKE",
        {
            "synthetic_1080p_jpeg_bytes": len(frame),
            "encrypt_and_commit_ms": encrypt_seconds * 1_000,
            "decrypt_ms": decrypt_seconds * 1_000,
            "populate_remaining_7_ms": populate_seconds * 1_000,
            "estimated_populate_8_ms": (
                encrypt_seconds + populate_seconds
            )
            * 1_000,
            "destroy_and_resume_ms": destruction_seconds * 1_000,
            "store_authority_validation_us": (
                authority_seconds / 100
            )
            * 1_000_000,
        },
    )
    _assert_private_cleanup_v1(harness)

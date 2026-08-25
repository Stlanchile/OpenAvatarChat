from __future__ import annotations

import asyncio

import pytest

from certificate_capture.ocr.protocol import (
    OcrFailureReasonV1,
    OcrServiceErrorV1,
)
from certificate_capture.state import CaptureStateV1
from chat_engine.security.session_work_controller import WorkAdmissionDeniedV1
from tests.chat_engine.milestone_4b.conftest import (
    CaptureProtocolHarnessV1,
)


async def _wait_for_state_v1(coordinator, expected) -> None:
    for _ in range(200):
        if coordinator.snapshot_v1().state is expected:
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"capture never reached {expected}")


def _assert_ocr_cleanup_v1(harness) -> None:
    coordinator = harness.protocol.coordinator
    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert not snapshot.partition_open
    assert not snapshot.key_present
    assert snapshot.frame_record_count == 0
    assert snapshot.auxiliary_record_count == 0
    assert snapshot.ocr_result_index_count == 0
    service = coordinator._ocr_service_v1
    assert service is not None
    assert service.active_request_count_v1() == 0
    assert not coordinator._frame_records_v1


@pytest.mark.asyncio
async def test_ocr_start_racing_end_is_cancelled_and_cleanup_waits_for_release(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory(
        protocol=CaptureProtocolHarnessV1(cleanup_timeout_seconds=1.0)
    )
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    harness.client.release_response.clear()
    processing = asyncio.create_task(harness.process(grant, 1))
    await harness.client.jpeg_released.wait()

    ending = asyncio.create_task(
        harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)
    )
    await _wait_for_state_v1(
        harness.protocol.coordinator,
        CaptureStateV1.ENDING,
    )
    with pytest.raises(OcrServiceErrorV1) as cancelled:
        await processing
    assert cancelled.value.reason in {
        OcrFailureReasonV1.CANCELLED,
        OcrFailureReasonV1.WORK_RETIRED,
    }
    await ending

    assert harness.protocol.coordinator.snapshot_v1().state is CaptureStateV1.IDLE
    _assert_ocr_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_end_cancels_ocr_only_after_releasing_coordinator_lock(
    milestone_6a_harness_factory,
    monkeypatch,
):
    harness = milestone_6a_harness_factory(
        protocol=CaptureProtocolHarnessV1(cleanup_timeout_seconds=1.0)
    )
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    coordinator = harness.protocol.coordinator
    controller = harness.protocol.controller
    lock_states: list[bool] = []
    original_cancel = type(controller).cancel_work_v1

    def cancel_with_lock_check(instance, fence):
        if instance is controller:
            lock_states.append(coordinator._lock._is_owned())
        return original_cancel(instance, fence)

    monkeypatch.setattr(
        type(controller),
        "cancel_work_v1",
        cancel_with_lock_check,
    )
    harness.client.release_response.clear()
    processing = asyncio.create_task(harness.process(grant, 1))
    await harness.client.jpeg_released.wait()

    ending = asyncio.create_task(coordinator.end_capture_v1(grant.capture_epoch))
    with pytest.raises(OcrServiceErrorV1):
        await processing
    await ending

    assert lock_states
    assert not any(lock_states)
    _assert_ocr_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_ocr_response_racing_end_is_discarded_before_parse_or_write(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory(
        protocol=CaptureProtocolHarnessV1(cleanup_timeout_seconds=1.0)
    )
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    ending: asyncio.Task | None = None

    async def begin_end_before_return() -> None:
        nonlocal ending
        ending = asyncio.create_task(
            harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)
        )
        await _wait_for_state_v1(
            harness.protocol.coordinator,
            CaptureStateV1.ENDING,
        )

    harness.client.before_return = begin_end_before_return
    with pytest.raises(OcrServiceErrorV1) as retired:
        await harness.process(grant, 1)
    assert retired.value.reason is OcrFailureReasonV1.WORK_RETIRED
    assert ending is not None
    await ending
    _assert_ocr_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_ocr_start_racing_inactivity_expiry_cannot_commit(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory(
        protocol=CaptureProtocolHarnessV1(cleanup_timeout_seconds=1.0)
    )
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    harness.client.release_response.clear()
    processing = asyncio.create_task(harness.process(grant, 1))
    await harness.client.jpeg_released.wait()

    harness.protocol.clock.advance(301)
    harness.protocol.wake_inactivity_timer()
    await _wait_for_state_v1(
        harness.protocol.coordinator,
        CaptureStateV1.ENDING,
    )
    with pytest.raises(OcrServiceErrorV1):
        await processing
    await _wait_for_state_v1(
        harness.protocol.coordinator,
        CaptureStateV1.IDLE,
    )
    _assert_ocr_cleanup_v1(harness)


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_kind", ["revoke", "replacement"])
async def test_ocr_response_racing_session_retirement_never_writes(
    milestone_6a_harness_factory,
    terminal_kind,
):
    harness = milestone_6a_harness_factory(
        protocol=CaptureProtocolHarnessV1(cleanup_timeout_seconds=1.0)
    )
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    shutdown: asyncio.Task | None = None

    async def retire_before_return() -> None:
        nonlocal shutdown
        harness.protocol.session_live = False
        if terminal_kind == "revoke":
            harness.protocol.security_live = False
        shutdown = asyncio.create_task(harness.protocol.coordinator.shutdown_async_v1())
        for _ in range(200):
            if harness.protocol.coordinator.snapshot_v1().shutdown_started:
                return
            await asyncio.sleep(0.005)
        raise AssertionError("shutdown did not start")

    harness.client.before_return = retire_before_return
    with pytest.raises(OcrServiceErrorV1):
        await harness.process(grant, 1)
    assert shutdown is not None
    assert await shutdown
    _assert_ocr_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_sidecar_crash_releases_work_and_capture_remains_retryable(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)

    async def crash(request, jpeg_buffer, cancellation):
        del request, cancellation
        jpeg_buffer.clear()
        raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_FAILED)

    harness.client.exchange_v1 = crash
    with pytest.raises(OcrServiceErrorV1) as failed:
        await harness.process(grant, 1)
    assert failed.value.reason is OcrFailureReasonV1.OCR_FAILED
    assert harness.protocol.coordinator.snapshot_v1().state is CaptureStateV1.CAPTURING
    service = harness.protocol.coordinator._ocr_service_v1
    assert service is not None
    assert service.active_request_count_v1() == 0
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.auxiliary_record_count == 0
    assert snapshot.ocr_result_index_count == 0


@pytest.mark.asyncio
async def test_closed_store_between_response_and_write_cannot_be_repopulated(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    coordinator = harness.protocol.coordinator

    async def close_admission_before_return() -> None:
        assert coordinator._private_evidence_store_v1._close_capture_admission_for_owner_v1(
            access=coordinator._private_store_cleanup_access_v1,
            capture_epoch=grant.capture_epoch,
        )

    harness.client.before_return = close_admission_before_return
    with pytest.raises(OcrServiceErrorV1) as rejected:
        await harness.process(grant, 1)
    assert rejected.value.reason in {
        OcrFailureReasonV1.STORE_REJECTED,
        OcrFailureReasonV1.WORK_RETIRED,
    }
    snapshot = coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.auxiliary_record_count == 0
    assert snapshot.ocr_result_index_count == 0
    await coordinator.end_capture_v1(grant.capture_epoch)
    _assert_ocr_cleanup_v1(harness)


@pytest.mark.asyncio
async def test_completed_result_is_erased_on_end_and_cannot_be_read_afterward(
    milestone_6a_harness_factory,
):
    harness = milestone_6a_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    receipt = (await harness.process(grant, 1))[0]

    await harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)

    _assert_ocr_cleanup_v1(harness)
    with pytest.raises(WorkAdmissionDeniedV1):
        harness.read_result(grant, receipt)

from __future__ import annotations

import asyncio
import uuid

import pytest

from certificate_capture.frame_ingress import validate_private_jpeg_v1
from certificate_capture.protocol import (
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from certificate_capture.state import (
    CaptureStateV1,
    CaptureTransitionPointV1,
)
from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1
from tests.chat_engine.milestone_4b.test_protocol_lifecycle import (
    BlockingMockProcessorV1,
    ImmediateMockProcessorV1,
)


async def _wait_for_state_v1(coordinator, state: CaptureStateV1) -> None:
    for _ in range(500):
        if coordinator.snapshot_v1().state is state:
            return
        await asyncio.sleep(0.001)
    raise AssertionError(f"coordinator did not reach {state.value}")


def _cancel_created_coroutine_before_start_v1(
    monkeypatch,
    coroutine_name: str,
) -> None:
    original_create_task = asyncio.create_task

    def create_and_cancel_selected(coroutine, *args, **kwargs):
        task = original_create_task(coroutine, *args, **kwargs)
        code = getattr(coroutine, "cr_code", None)
        if getattr(code, "co_name", None) == coroutine_name:
            task.cancel()
        return task

    monkeypatch.setattr(asyncio, "create_task", create_and_cancel_selected)


@pytest.mark.asyncio
async def test_only_new_frames_and_valid_seals_reset_inactivity(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    initial = harness.coordinator._inactivity_deadline_monotonic_v1
    assert initial is not None

    harness.clock.advance(10)
    await harness.coordinator.capture_public_status_v1(
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    assert harness.coordinator._inactivity_deadline_monotonic_v1 == initial

    first_frame = synthetic_jpeg_v1(color=(1, 2, 3))
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=first_frame,
    )
    after_frame = harness.coordinator._inactivity_deadline_monotonic_v1
    assert after_frame is not None and after_frame > initial

    harness.clock.advance(10)
    with pytest.raises(CaptureProtocolErrorV1):
        await harness.upload(
            grant,
            frame_seq=1,
            encoded_frame=synthetic_jpeg_v1(color=(9, 8, 7)),
        )
    assert harness.coordinator._inactivity_deadline_monotonic_v1 == after_frame

    harness.clock.advance(10)
    await harness.coordinator.seal_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    after_seal = harness.coordinator._inactivity_deadline_monotonic_v1
    assert after_seal is not None and after_seal > after_frame

    harness.clock.advance(10)
    with pytest.raises(CaptureProtocolErrorV1):
        await harness.coordinator.capture_public_status_v1(
            capture_id=grant.capture_epoch.capture_id,
            capture_capability="ccp1_" + "A" * 43,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert harness.coordinator._inactivity_deadline_monotonic_v1 == after_seal


@pytest.mark.asyncio
async def test_expiry_invalidates_capability_and_resumes_only_after_cleanup(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    before_resume = asyncio.Event()
    allow_resume = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_RESUME:
            before_resume.set()
            await allow_resume.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    harness.clock.advance(301)
    harness.wake_inactivity_timer()
    await asyncio.wait_for(before_resume.wait(), timeout=1)

    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ENDING
    assert harness.gate.is_open_v1() is False
    assert harness.coordinator._active_capture_capability_v1 is None
    assert harness.coordinator._frame_records_v1 == {}

    allow_resume.set()
    await _wait_for_state_v1(harness.coordinator, CaptureStateV1.IDLE)
    assert harness.gate.is_open_v1() is True
    with pytest.raises(CaptureProtocolErrorV1) as gone:
        await harness.coordinator.capture_public_status_v1(
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert gone.value.reason is CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED


@pytest.mark.asyncio
async def test_expired_callback_cannot_end_a_later_capture(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    first = await harness.begin()
    harness.clock.advance(301)
    harness.wake_inactivity_timer()
    await _wait_for_state_v1(harness.coordinator, CaptureStateV1.IDLE)

    second = await harness.begin(control_seq=2)
    await harness.coordinator._expire_capture_if_current_v1(
        first.capture_epoch
    )

    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    assert harness.coordinator._capture_epoch is second.capture_epoch


@pytest.mark.asyncio
async def test_control_request_observing_expiry_cleans_before_new_begin(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    first = await harness.begin()
    harness.clock.advance(301)

    second = await harness.begin(control_seq=2)

    assert first.capture_epoch is not second.capture_epoch
    assert second.capture_epoch.capture_seq == 2
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    assert harness.gate.is_open_v1() is False


@pytest.mark.asyncio
async def test_expired_capability_cannot_replay_seal_or_end_tombstone(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    seal_request_id = uuid.uuid4()
    await harness.coordinator.seal_capture_protocol_v1(
        request_id=seal_request_id,
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    harness.clock.advance(301)

    with pytest.raises(CaptureProtocolErrorV1) as expired_seal:
        await harness.coordinator.seal_capture_protocol_v1(
            request_id=seal_request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert (
        expired_seal.value.reason
        is CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
    )
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.IDLE

    second = await harness.begin(control_seq=3)
    end_request_id = uuid.uuid4()
    await harness.coordinator.end_capture_protocol_v1(
        request_id=end_request_id,
        control_seq=4,
        capture_id=second.capture_epoch.capture_id,
        capture_capability=second.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    harness.clock.advance(601)
    with pytest.raises(CaptureProtocolErrorV1) as expired_end:
        await harness.coordinator.end_capture_protocol_v1(
            request_id=end_request_id,
            control_seq=4,
            capture_id=second.capture_epoch.capture_id,
            capture_capability=second.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert (
        expired_end.value.reason
        is CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
    )


@pytest.mark.asyncio
async def test_end_waits_for_inflight_upload_work_and_never_reopens_early(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory(cleanup_timeout_seconds=1.0)
    grant = await harness.begin()
    permit = await harness.coordinator.admit_frame_upload_v1(
        capture_id=grant.capture_epoch.capture_id,
        frame_seq=1,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )

    end_task = asyncio.create_task(
        harness.coordinator.end_capture_protocol_v1(
            request_id=uuid.uuid4(),
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    )
    await _wait_for_state_v1(harness.coordinator, CaptureStateV1.ENDING)
    assert end_task.done() is False
    assert permit.registered_work.cancellation.is_cancelled is True
    assert harness.gate.is_open_v1() is False

    harness.coordinator.release_frame_upload_permit_v1(permit)
    result = await asyncio.wait_for(end_task, timeout=1)
    assert result.state is CaptureStateV1.IDLE
    assert harness.gate.is_open_v1() is True


@pytest.mark.asyncio
async def test_two_same_sequence_uploads_serialize_to_one_record(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()
    validated = validate_private_jpeg_v1(encoded)
    first_permit, second_permit = await asyncio.gather(
        harness.coordinator.admit_frame_upload_v1(
            capture_id=grant.capture_epoch.capture_id,
            frame_seq=1,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        ),
        harness.coordinator.admit_frame_upload_v1(
            capture_id=grant.capture_epoch.capture_id,
            frame_seq=1,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        ),
    )
    try:
        first, second = await asyncio.gather(
            harness.coordinator.commit_frame_upload_v1(
                first_permit,
                validated,
                encoded,
            ),
            harness.coordinator.commit_frame_upload_v1(
                second_permit,
                validated,
                encoded,
            ),
        )
    finally:
        harness.coordinator.release_frame_upload_permit_v1(first_permit)
        harness.coordinator.release_frame_upload_permit_v1(second_permit)

    assert first == second
    assert first.accepted_frame_count == 1
    assert len(harness.coordinator._frame_records_v1) == 1


@pytest.mark.asyncio
async def test_upload_commit_loses_to_atomic_seal_and_cannot_mutate_build(
    capture_protocol_harness_factory,
):
    processor = BlockingMockProcessorV1()
    harness = capture_protocol_harness_factory(processor=processor)
    grant = await harness.begin()
    for frame_seq, color in enumerate(
        ((11, 12, 13), (21, 22, 23), (31, 32, 33)),
        start=1,
    ):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(color=color),
        )
    permit = await harness.coordinator.admit_frame_upload_v1(
        capture_id=grant.capture_epoch.capture_id,
        frame_seq=4,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    encoded = synthetic_jpeg_v1(color=(41, 42, 43))
    validated = validate_private_jpeg_v1(encoded)

    seal = await harness.coordinator.seal_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    try:
        with pytest.raises(CaptureProtocolErrorV1):
            await harness.coordinator.commit_frame_upload_v1(
                permit,
                validated,
                encoded,
            )
    finally:
        harness.coordinator.release_frame_upload_permit_v1(permit)

    assert seal.capture_state is CaptureStateV1.BUILDING_ASSERTIONS
    assert len(harness.coordinator._frame_records_v1) == 3
    processor.release.set()


@pytest.mark.asyncio
async def test_timer_cancelled_before_first_instruction_fails_begin_closed(
    capture_protocol_harness_factory,
    monkeypatch,
):
    harness = capture_protocol_harness_factory()
    _cancel_created_coroutine_before_start_v1(
        monkeypatch,
        "_run_inactivity_timer_v1",
    )

    with pytest.raises(CaptureProtocolErrorV1) as failed:
        await asyncio.wait_for(harness.begin(), timeout=1)

    assert (
        failed.value.reason
        is CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
    )
    assert harness.coordinator.snapshot_v1().state is (
        CaptureStateV1.FAILED_CLOSED
    )
    assert harness.coordinator._control_lock_v1.locked() is False
    assert harness.coordinator._operation_lock.locked() is False
    assert harness.controller.snapshot_v1().unreleased_work_by_generation == ()


@pytest.mark.asyncio
async def test_processor_cancelled_before_first_instruction_fails_seal_closed(
    capture_protocol_harness_factory,
    monkeypatch,
):
    processor = ImmediateMockProcessorV1()
    harness = capture_protocol_harness_factory(processor=processor)
    grant = await harness.begin()
    for frame_seq, color in enumerate(
        ((10, 11, 12), (20, 21, 22), (30, 31, 32)),
        start=1,
    ):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(color=color),
        )
    _cancel_created_coroutine_before_start_v1(
        monkeypatch,
        "_run_mock_processor_v1",
    )

    with pytest.raises(CaptureProtocolErrorV1) as failed:
        await asyncio.wait_for(
            harness.coordinator.seal_capture_protocol_v1(
                request_id=uuid.uuid4(),
                control_seq=2,
                capture_id=grant.capture_epoch.capture_id,
                capture_capability=grant.capture_capability,
                session_id=harness.session_id,
                owner_issuer=harness.owner_issuer,
                owner_subject=harness.owner_subject,
            ),
            timeout=1,
        )

    assert (
        failed.value.reason
        is CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED
    )
    assert processor.calls == 0
    assert harness.coordinator.snapshot_v1().state is (
        CaptureStateV1.FAILED_CLOSED
    )
    assert harness.coordinator._control_lock_v1.locked() is False
    assert harness.coordinator._operation_lock.locked() is False
    for _ in range(100):
        if not harness.controller.snapshot_v1().unreleased_work_by_generation:
            break
        await asyncio.sleep(0)
    assert harness.controller.snapshot_v1().unreleased_work_by_generation == ()

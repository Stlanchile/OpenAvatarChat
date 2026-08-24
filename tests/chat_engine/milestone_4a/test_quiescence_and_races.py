from __future__ import annotations

import asyncio

import pytest

from certificate_capture.coordinator import (
    CaptureFailedClosedV1,
    CaptureTransitionRejectedV1,
)
from certificate_capture.state import (
    CaptureStateV1,
    CaptureTransitionPointV1,
)
from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1


async def _wait_for_state(coordinator, state: CaptureStateV1) -> None:
    for _ in range(200):
        if coordinator.snapshot_v1().state is state:
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"coordinator did not reach {state.value}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("lane", "kind"),
    [
        ("perception", WorkOperationKindV1.PERCEPTION_INFERENCE),
        ("llm_stream", WorkOperationKindV1.CHAT_AGENT_LLM),
        ("tool", WorkOperationKindV1.TOOL_EXECUTION),
        ("cosyvoice", WorkOperationKindV1.TTS_SYNTHESIS),
        ("edge_tts", WorkOperationKindV1.TTS_SYNTHESIS),
        ("bailian_tts", WorkOperationKindV1.TTS_SYNTHESIS),
        ("ws_egress", WorkOperationKindV1.WS_EGRESS),
        ("rtc_audio", WorkOperationKindV1.RTC_EGRESS),
        ("rtc_video", WorkOperationKindV1.RTC_EGRESS),
        ("rtc_data", WorkOperationKindV1.RTC_EGRESS),
        ("rtc_retransmission", WorkOperationKindV1.RTC_EGRESS),
    ],
)
async def test_armed_waits_for_each_required_old_generation_lane(
    capture_harness_factory,
    lane,
    kind,
):
    del lane
    harness = capture_harness_factory()
    work = harness.runtime.register_root_work_v1(kind)

    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await _wait_for_state(
        harness.coordinator,
        CaptureStateV1.QUIESCING,
    )

    assert not begin.done()
    assert work.cancellation.is_cancelled
    assert harness.coordinator.snapshot_v1().state is not CaptureStateV1.ARMED

    assert harness.runtime.release_work_v1(work)
    capture_epoch = await begin
    assert capture_epoch.session_epoch.generation == 2
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    await harness.coordinator.end_capture_v1(capture_epoch)


@pytest.mark.asyncio
async def test_armed_waits_for_multiple_subsystems_simultaneously(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    kinds = (
        WorkOperationKindV1.PERCEPTION_INFERENCE,
        WorkOperationKindV1.CHAT_AGENT_LLM,
        WorkOperationKindV1.TOOL_EXECUTION,
        WorkOperationKindV1.TTS_SYNTHESIS,
        WorkOperationKindV1.WS_EGRESS,
        WorkOperationKindV1.RTC_EGRESS,
    )
    work = [harness.runtime.register_root_work_v1(kind) for kind in kinds]
    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await _wait_for_state(
        harness.coordinator,
        CaptureStateV1.QUIESCING,
    )

    for item in work[:-1]:
        assert harness.runtime.release_work_v1(item)
    await asyncio.sleep(0.02)
    assert not begin.done()
    assert harness.runtime.release_work_v1(work[-1])

    capture_epoch = await begin
    assert harness.controller.snapshot_v1().unreleased_work_by_generation == ()
    await harness.coordinator.end_capture_v1(capture_epoch)


@pytest.mark.asyncio
async def test_begin_quiescence_timeout_fails_closed_and_never_arms(
    capture_harness_factory,
):
    harness = capture_harness_factory(cleanup_timeout_seconds=0.05)
    work = harness.runtime.register_root_work_v1(WorkOperationKindV1.TOOL_EXECUTION)

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    assert failure.value.reason_code == "QUIESCENCE_TIMEOUT"
    status = harness.coordinator.snapshot_v1()
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert not status.normal_application_admission_open
    assert not status.quiescence_complete
    assert harness.termination_requests == 1
    assert work.cancellation.is_cancelled
    harness.runtime.release_work_v1(work)


@pytest.mark.asyncio
async def test_quiescence_participant_failure_cannot_ack_success(
    capture_harness_factory,
):
    harness = capture_harness_factory(
        cleanup_timeout_seconds=0.05,
        drain_error=True,
    )

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    assert failure.value.reason_code == "QUIESCENCE_TIMEOUT"
    cleanup_states = harness.controller.snapshot_v1().retired_cleanup_states
    assert cleanup_states[-1][1].value == "TIMED_OUT"
    assert cleanup_states[-1][3] == 0
    assert not harness.gate.is_open_v1()


@pytest.mark.asyncio
async def test_semantic_cleanup_failure_prevents_armed(
    capture_harness_factory,
):
    harness = capture_harness_factory(semantic_error=True)

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    assert failure.value.reason_code == "SEMANTIC_CLEANUP_FAILED"
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not harness.gate.is_open_v1()
    assert harness.termination_requests == 1


@pytest.mark.asyncio
async def test_end_waits_for_capture_generation_cleanup_before_reopen(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    capture_work = harness.controller.register_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC,
        harness.controller._now_v1() + 10,
    )

    ending = asyncio.create_task(harness.coordinator.end_capture_v1(capture_epoch))
    await _wait_for_state(
        harness.coordinator,
        CaptureStateV1.ENDING,
    )
    await asyncio.sleep(0.02)
    assert not ending.done()
    assert capture_work.cancellation.is_cancelled
    assert not harness.gate.is_open_v1()

    assert harness.controller.release_work_v1(capture_work.lease)
    status = await ending
    assert status.state is CaptureStateV1.IDLE
    assert status.normal_application_admission_open


@pytest.mark.asyncio
async def test_end_cleanup_timeout_never_reopens_normal_mode(
    capture_harness_factory,
):
    harness = capture_harness_factory(cleanup_timeout_seconds=0.05)
    capture_epoch = await harness.coordinator.begin_capture_v1()
    capture_work = harness.controller.register_work_v1(
        WorkOperationKindV1.TTS_SYNTHESIS,
        harness.controller._now_v1() + 10,
    )

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.end_capture_v1(capture_epoch)

    assert failure.value.reason_code == "CLEANUP_TIMEOUT"
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not harness.gate.is_open_v1()
    assert harness.termination_requests == 1
    harness.controller.release_work_v1(capture_work.lease)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "point",
    [
        CaptureTransitionPointV1.AFTER_ENTERING,
        CaptureTransitionPointV1.BEFORE_BEGIN_RETIREMENT,
        CaptureTransitionPointV1.AFTER_BEGIN_RETIREMENT,
        CaptureTransitionPointV1.AFTER_QUIESCING,
    ],
)
async def test_end_supersedes_begin_without_generation_laundering(
    capture_harness_factory,
    point,
):
    harness = capture_harness_factory()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(observed: CaptureTransitionPointV1) -> None:
        if observed is point:
            reached.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await reached.wait()
    capture_seq = harness.coordinator.snapshot_v1().capture_seq
    end = asyncio.create_task(
        harness.coordinator.end_capture_v1(capture_seq=capture_seq)
    )
    await asyncio.sleep(0)
    release.set()

    begin_outcome = await asyncio.gather(
        begin,
        return_exceptions=True,
    )
    status = await end

    assert isinstance(
        begin_outcome[0],
        CaptureTransitionRejectedV1,
    )
    assert begin_outcome[0].reason_code == "STALE_TRANSITION"
    assert status.state is CaptureStateV1.IDLE
    assert status.normal_application_admission_open
    expected_generation = (
        2
        if point
        in {
            CaptureTransitionPointV1.AFTER_ENTERING,
            CaptureTransitionPointV1.BEFORE_BEGIN_RETIREMENT,
        }
        else 3
    )
    assert status.session_generation == expected_generation


@pytest.mark.asyncio
async def test_repeated_end_while_ending_is_deterministically_busy(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENDING:
            reached.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    first = asyncio.create_task(harness.coordinator.end_capture_v1(capture_epoch))
    await reached.wait()
    with pytest.raises(CaptureTransitionRejectedV1) as begin_while_ending:
        await harness.coordinator.begin_capture_v1()
    assert begin_while_ending.value.reason_code == "CAPTURE_BUSY"
    with pytest.raises(CaptureTransitionRejectedV1) as repeated:
        await harness.coordinator.end_capture_v1(capture_epoch)
    assert repeated.value.reason_code == "CAPTURE_BUSY"
    release.set()
    assert (await first).state is CaptureStateV1.IDLE


@pytest.mark.asyncio
async def test_end_racing_normal_input_keeps_admission_closed_until_complete(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_RESUME:
            reached.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    end = asyncio.create_task(harness.coordinator.end_capture_v1(capture_epoch))
    await reached.wait()

    with pytest.raises(WorkAdmissionDeniedV1):
        harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
    release.set()
    assert (await end).state is CaptureStateV1.IDLE

    fresh = harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
    assert fresh.fence.session_epoch.generation == 3
    assert harness.runtime.release_work_v1(fresh)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "point",
    [
        CaptureTransitionPointV1.BEFORE_BEGIN_RETIREMENT,
        CaptureTransitionPointV1.AFTER_BEGIN_RETIREMENT,
    ],
)
async def test_cancelled_begin_relinquishes_cleanup_participant(
    capture_harness_factory,
    point,
):
    harness = capture_harness_factory()
    reached = asyncio.Event()
    blocker = asyncio.Event()

    async def hook(observed: CaptureTransitionPointV1) -> None:
        if observed is point:
            reached.set()
            await blocker.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await reached.wait()
    begin.cancel()

    with pytest.raises(asyncio.CancelledError):
        await begin
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not harness.gate.is_open_v1()
    assert harness.coordinator.snapshot_v1().failure_reason_code.value == (
        "INTERNAL_FAILURE"
    )
    assert not harness.controller._cleanup_tokens
    assert all(
        outstanding_cleanup == 0
        for (
            _generation,
            _state,
            _outstanding_work,
            outstanding_cleanup,
        ) in harness.controller.snapshot_v1().retired_cleanup_states
    )


@pytest.mark.asyncio
async def test_cancelled_end_after_retirement_relinquishes_cleanup_participant(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    reached = asyncio.Event()
    blocker = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_END_RETIREMENT:
            reached.set()
            await blocker.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    ending = asyncio.create_task(harness.coordinator.end_capture_v1(capture_epoch))
    await reached.wait()
    ending.cancel()

    with pytest.raises(asyncio.CancelledError):
        await ending
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not harness.gate.is_open_v1()
    assert not harness.controller._cleanup_tokens
    assert all(
        outstanding_cleanup == 0
        for (
            _generation,
            _state,
            _outstanding_work,
            outstanding_cleanup,
        ) in harness.controller.snapshot_v1().retired_cleanup_states
    )

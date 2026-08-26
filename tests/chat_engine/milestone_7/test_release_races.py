from __future__ import annotations

import asyncio

import pytest

from certificate_capture.coordinator import (
    CaptureFailedClosedV1,
    CaptureTransitionRejectedV1,
)
from certificate_capture.release.service import (
    AdmissionNoticeReleaseReasonV1,
)
from certificate_capture.state import (
    CaptureStateV1,
    CaptureTransitionPointV1,
)


@pytest.mark.asyncio
async def test_end_builds_private_candidate_before_cleanup_transition(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    coordinator = harness.protocol.coordinator
    release_service = coordinator._admission_notice_release_service_v1
    grant, _, _ = await harness.prepare_standard()
    observed = []

    def inspect_after_ending(point):
        if point is CaptureTransitionPointV1.AFTER_ENDING:
            observed.append(
                (
                    release_service._candidate is not None,
                    release_service._pending_preparation is None,
                    coordinator._private_evidence_store_v1.cleanup_trace_v1(),
                )
            )

    coordinator._set_transition_hook_for_test_v1(inspect_after_ending)
    await harness.end_and_wait(grant)

    assert coordinator.snapshot_v1().state is CaptureStateV1.IDLE
    assert observed
    assert observed[0][0:2] == (True, True)
    assert observed[0][2]
    assert harness.callback_invocations == 1


@pytest.mark.asyncio
async def test_release_commit_requires_open_fresh_normal_generation(
    milestone_7_harness_factory,
    monkeypatch,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    release_service = coordinator._admission_notice_release_service_v1
    service_type = type(release_service)
    original_commit = service_type.commit_after_cleanup_v1
    observed = []

    def inspect_commit(instance, **kwargs):
        if instance is release_service:
            observed.append(
                (
                    coordinator._isolation_view.is_open_v1(),
                    harness.protocol.controller.current_epoch_v1()
                    is kwargs["successor_epoch"],
                    coordinator._private_evidence_store_v1.is_capture_clear_v1(),
                )
            )
        return original_commit(instance, **kwargs)

    monkeypatch.setattr(
        service_type,
        "commit_after_cleanup_v1",
        inspect_commit,
    )
    await harness.end_and_wait(grant)

    assert observed == [(True, True, True)]
    assert harness.callback_invocations == 1


@pytest.mark.asyncio
async def test_duplicate_end_during_cleanup_cannot_erase_bound_candidate(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    grant, _, _ = await harness.prepare_standard()
    coordinator = harness.protocol.coordinator
    release_service = coordinator._admission_notice_release_service_v1
    after_ending = asyncio.Event()
    allow_cleanup = asyncio.Event()

    async def pause_after_claim(point):
        if point is CaptureTransitionPointV1.AFTER_ENDING:
            after_ending.set()
            await allow_cleanup.wait()

    coordinator._set_transition_hook_for_test_v1(pause_after_claim)
    first_end = asyncio.create_task(coordinator.end_capture_v1(grant.capture_epoch))
    await asyncio.wait_for(after_ending.wait(), 1.0)

    with pytest.raises(CaptureTransitionRejectedV1):
        await coordinator.end_capture_v1(grant.capture_epoch)

    assert release_service._candidate is not None
    assert release_service._bound_transition_id is not None
    allow_cleanup.set()
    await first_end
    task = coordinator._admission_personalization_task_v1
    if task is not None:
        await task

    assert harness.callback_invocations == 1
    assert len(harness.released_contexts) == 1


@pytest.mark.asyncio
async def test_prepare_rejects_revoked_or_expired_authority(
    milestone_7_harness_factory,
):
    revoked = milestone_7_harness_factory()
    revoked_grant, _, _ = await revoked.prepare_standard()
    revoked.protocol.security_authority.close()
    revoked.protocol.security_live = False
    with pytest.raises(CaptureFailedClosedV1):
        await revoked.protocol.coordinator.end_capture_v1(revoked_grant.capture_epoch)
    assert (
        revoked.protocol.coordinator._admission_notice_release_service_v1.last_reason_v1()
    ) is (AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID)
    assert revoked.callback_invocations == 0

    expired = milestone_7_harness_factory()
    expired_grant, _, _ = await expired.prepare_standard()
    expired.protocol.clock.advance((15.0 * 60.0) + 1.0)
    await expired.end_and_wait(expired_grant)
    assert (
        expired.protocol.coordinator._admission_notice_release_service_v1.last_reason_v1()
    ) is (AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE)
    assert expired.callback_invocations == 0


@pytest.mark.asyncio
async def test_fresh_chatagent_registration_racing_next_capture_is_fenced(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    harness.callback_gate.clear()
    grant, _, _ = await harness.prepare_standard()
    await harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)
    await asyncio.wait_for(harness.callback_started.wait(), 1.0)
    work = harness.registered_work[0]

    begin_task = asyncio.create_task(harness.protocol.coordinator.begin_capture_v1())
    assert await work.cancellation.wait_async(1.0)
    harness.callback_gate.set()
    next_capture = await begin_task

    assert harness.callback_invocations == 1
    assert len(harness.released_contexts) == 1
    assert work.cancellation.is_cancelled
    assert next_capture.session_epoch.generation == (
        work.fence.session_epoch.generation + 1
    )
    await harness.protocol.coordinator.end_capture_v1(next_capture)


@pytest.mark.asyncio
async def test_committed_generation_racing_shutdown_is_not_replayed(
    milestone_7_harness_factory,
):
    harness = milestone_7_harness_factory()
    harness.callback_gate.clear()
    grant, _, _ = await harness.prepare_standard()
    await harness.protocol.coordinator.end_capture_v1(grant.capture_epoch)
    await asyncio.wait_for(harness.callback_started.wait(), 1.0)
    work = harness.registered_work[0]

    shutdown_task = asyncio.create_task(
        harness.protocol.coordinator.shutdown_async_v1(_retire_work_controller_v1=True)
    )
    assert await work.cancellation.wait_async(1.0)
    harness.callback_gate.set()
    assert await shutdown_task

    assert harness.callback_invocations == 1
    assert len(harness.released_contexts) == 1
    assert harness.second_consumptions == [None]
    assert work.cancellation.is_cancelled

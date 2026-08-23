from __future__ import annotations

import asyncio
import dataclasses
import threading

import pytest

from chat_engine.security.cleanup_fence import (
    CleanupActionV1,
    RetiredGenerationCleanupStateV1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    COMPLETED_CLEANUP_TOMBSTONES_V1,
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
    WorkControllerFailureReasonV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1


def _register_work(controller, fake_clock):
    return controller.register_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC,
        fake_clock() + 60.0,
    )


def test_work_fence_and_cleanup_fence_are_non_interchangeable(
    controller,
    fake_clock,
):
    work = _register_work(controller, fake_clock)
    retirement = controller.retire_generation_v1()
    new_generation_work = _register_work(controller, fake_clock)

    assert not controller.authorize_cleanup_v1(
        work.fence,
        CleanupActionV1.DELETE,
    )
    assert controller.validate_at_admission_v1(new_generation_work.fence)
    assert not controller.authorize_cleanup_v1(
        new_generation_work.fence,
        CleanupActionV1.DELETE,
    )
    assert controller.authorize_cleanup_v1(
        retirement.cleanup_fence,
        CleanupActionV1.DELETE,
    )
    assert not controller.validate_at_admission_v1(retirement.cleanup_fence)
    assert not controller.validate_before_state_mutation_v1(retirement.cleanup_fence)
    assert not controller.validate_before_egress_v1(retirement.cleanup_fence)
    assert not hasattr(retirement.cleanup_fence, "to_work_fence")

    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.release_work_v1(new_generation_work.lease)
    assert not controller.authorize_cleanup_v1(
        retirement.cleanup_fence,
        CleanupActionV1.DELETE,
    )


def test_cleanup_fence_is_canonical_and_exactly_generation_scoped(
    controller,
):
    token = controller.register_cleanup_participant_v1()
    retirement = controller.retire_generation_v1()
    fence = retirement.cleanup_fence

    wrong_id = dataclasses.replace(fence, cleanup_id=new_uuid7_v1())
    wrong_generation = dataclasses.replace(
        fence,
        retired_generation=fence.retired_generation + 1,
    )
    reconstructed = dataclasses.replace(fence)

    assert controller.authorize_cleanup_v1(fence, CleanupActionV1.PURGE)
    assert not controller.authorize_cleanup_v1(
        wrong_id,
        CleanupActionV1.PURGE,
    )
    assert not controller.authorize_cleanup_v1(
        wrong_generation,
        CleanupActionV1.PURGE,
    )
    assert not controller.authorize_cleanup_v1(
        reconstructed,
        CleanupActionV1.PURGE,
    )

    controller.retire_generation_v1()
    controller.retire_generation_v1()
    assert controller.authorize_cleanup_v1(fence, CleanupActionV1.PURGE)
    assert controller.release_cleanup_v1(fence, token)
    assert controller.wait_for_cleanup_v1(fence)
    assert not controller.authorize_cleanup_v1(
        fence,
        CleanupActionV1.ACK_CLEANUP,
    )


def test_cross_session_cleanup_fence_reuse_is_denied():
    first = SessionWorkControllerV1()
    second = SessionWorkControllerV1()
    token = first.register_cleanup_participant_v1()
    retirement = first.retire_generation_v1()

    assert not second.authorize_cleanup_v1(
        retirement.cleanup_fence,
        CleanupActionV1.DELETE,
    )
    assert first.release_cleanup_v1(retirement.cleanup_fence, token)
    assert first.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert first.shutdown()
    assert second.shutdown()


def test_one_work_token_closes_barrier_only_after_release(
    controller,
    fake_clock,
):
    work = _register_work(controller, fake_clock)
    retirement = controller.retire_generation_v1()

    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.state is RetiredGenerationCleanupStateV1.PENDING
    assert status.outstanding_work_tokens == 1
    assert status.outstanding_cleanup_tokens == 0

    assert not controller.release_work_v1(dataclasses.replace(work.lease))
    unchanged = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert unchanged is not None
    assert unchanged.outstanding_work_tokens == 1
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.state is RetiredGenerationCleanupStateV1.COMPLETE
    assert status.outstanding_work_tokens == 0


def test_many_work_tokens_release_concurrently_exactly_once(
    controller,
    fake_clock,
):
    work_items = [_register_work(controller, fake_clock) for _ in range(64)]
    retirement = controller.retire_generation_v1()
    results: list[bool] = []
    result_lock = threading.Lock()

    def release(lease):
        released = controller.release_work_v1(lease)
        with result_lock:
            results.append(released)

    threads = [
        threading.Thread(target=release, args=(work.lease,)) for work in work_items
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2.0)

    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == len(work_items)
    assert all(results)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert not controller.release_work_v1(work_items[0].lease)
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.outstanding_work_tokens == 0


def test_cleanup_participant_registered_before_retirement_acks_after(
    controller,
):
    token = controller.register_cleanup_participant_v1()
    retirement = controller.retire_generation_v1()

    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.outstanding_cleanup_tokens == 1
    assert controller.release_cleanup_v1(
        retirement.cleanup_fence,
        token,
        action=CleanupActionV1.ACK_CLEANUP,
    )
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert not controller.release_cleanup_v1(
        retirement.cleanup_fence,
        token,
    )


def test_mixed_barrier_completes_only_after_work_and_participant_release(
    controller,
    fake_clock,
):
    work = _register_work(controller, fake_clock)
    token = controller.register_cleanup_participant_v1()
    retirement = controller.retire_generation_v1()

    assert controller.release_work_v1(work.lease)
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.state is RetiredGenerationCleanupStateV1.PENDING
    assert status.outstanding_work_tokens == 0
    assert status.outstanding_cleanup_tokens == 1

    assert controller.release_cleanup_v1(retirement.cleanup_fence, token)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)


def test_wrong_generation_token_cannot_close_another_barrier(
    controller,
):
    generation_one_token = controller.register_cleanup_participant_v1()
    generation_one = controller.retire_generation_v1()
    generation_two_token = controller.register_cleanup_participant_v1()

    assert not controller.release_cleanup_v1(
        generation_one.cleanup_fence,
        generation_two_token,
    )
    status = controller.cleanup_status_v1(generation_one.cleanup_fence)
    assert status is not None
    assert status.outstanding_cleanup_tokens == 1

    assert controller.release_cleanup_v1(
        generation_one.cleanup_fence,
        generation_one_token,
    )
    assert controller.wait_for_cleanup_v1(generation_one.cleanup_fence)
    assert controller.withdraw_cleanup_participant_v1(generation_two_token)


def test_unknown_and_reconstructed_tokens_fail_closed_without_decrement(
    controller,
):
    token = controller.register_cleanup_participant_v1()
    retirement = controller.retire_generation_v1()
    reconstructed = dataclasses.replace(token)

    assert not controller.release_cleanup_v1(
        retirement.cleanup_fence,
        reconstructed,
    )
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.outstanding_cleanup_tokens == 1
    assert controller.release_cleanup_v1(retirement.cleanup_fence, token)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)


def test_forgotten_token_timeout_fail_closes_session(
    fake_clock,
):
    controller = SessionWorkControllerV1._create_for_test_v1(
        monotonic_clock=fake_clock,
        cleanup_timeout_seconds=10.0,
    )
    token = controller.register_cleanup_participant_v1()
    retirement = controller.retire_generation_v1()
    fake_clock.advance(10.0)

    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.state is RetiredGenerationCleanupStateV1.TIMED_OUT
    assert (
        controller.failure_reason_v1() is WorkControllerFailureReasonV1.CLEANUP_TIMEOUT
    )
    assert not controller.is_usable_v1()
    assert not controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    with pytest.raises(WorkAdmissionDeniedV1):
        controller.register_work_v1(
            WorkOperationKindV1.GENERIC_ASYNC,
            fake_clock() + 30.0,
        )

    assert controller.authorize_cleanup_v1(
        retirement.cleanup_fence,
        CleanupActionV1.DELETE,
    )
    assert not controller.authorize_cleanup_v1(
        retirement.cleanup_fence,
        CleanupActionV1.ACK_CLEANUP,
    )
    assert controller.release_cleanup_v1(
        retirement.cleanup_fence,
        token,
        action=CleanupActionV1.RELEASE,
    )
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.state is RetiredGenerationCleanupStateV1.TIMED_OUT


def test_non_cancellable_work_can_release_late_without_reviving_cleanup(
    fake_clock,
):
    controller = SessionWorkControllerV1._create_for_test_v1(
        monotonic_clock=fake_clock,
        cleanup_timeout_seconds=5.0,
    )
    work = _register_work(controller, fake_clock)
    retirement = controller.retire_generation_v1()
    fake_clock.advance(5.0)

    assert not controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.release_work_v1(work.lease)
    assert not controller.validate_after_callback_v1(work.fence)
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.state is RetiredGenerationCleanupStateV1.TIMED_OUT
    assert status.outstanding_work_tokens == 0


@pytest.mark.asyncio
async def test_async_cleanup_wait_releases_lock_between_polls(controller):
    token = controller.register_cleanup_participant_v1()
    retirement = controller.retire_generation_v1()
    waiter = asyncio.create_task(
        controller.wait_for_cleanup_async_v1(retirement.cleanup_fence)
    )

    await asyncio.sleep(0)
    assert controller.release_cleanup_v1(retirement.cleanup_fence, token)
    assert await waiter


@pytest.mark.asyncio
async def test_started_async_wait_survives_completed_tombstone_eviction():
    controller = SessionWorkControllerV1()
    token = controller.register_cleanup_participant_v1()
    first = controller.retire_generation_v1()
    waiter = asyncio.create_task(
        controller.wait_for_cleanup_async_v1(first.cleanup_fence)
    )
    await asyncio.sleep(0)

    assert controller.release_cleanup_v1(first.cleanup_fence, token)
    for _ in range(COMPLETED_CLEANUP_TOMBSTONES_V1 + 1):
        controller.retire_generation_v1()

    assert controller.cleanup_status_v1(first.cleanup_fence) is None
    assert await waiter


def test_completed_history_and_released_work_are_compacted():
    controller = SessionWorkControllerV1()
    first_cleanup_fence = None
    latest_cleanup_fence = None

    for _ in range(COMPLETED_CLEANUP_TOMBSTONES_V1 + 32):
        work = controller.register_work_v1(
            WorkOperationKindV1.GENERIC_ASYNC,
            10**12,
        )
        assert controller.release_work_v1(work.lease)
        retirement = controller.retire_generation_v1()
        if first_cleanup_fence is None:
            first_cleanup_fence = retirement.cleanup_fence
        latest_cleanup_fence = retirement.cleanup_fence

    snapshot = controller.snapshot_v1()
    assert snapshot.unreleased_work_by_generation == ()
    assert len(snapshot.retired_cleanup_states) == COMPLETED_CLEANUP_TOMBSTONES_V1
    assert first_cleanup_fence is not None
    assert controller.cleanup_status_v1(first_cleanup_fence) is None
    assert latest_cleanup_fence is not None
    latest = controller.cleanup_status_v1(latest_cleanup_fence)
    assert latest is not None
    assert latest.state is RetiredGenerationCleanupStateV1.COMPLETE

    current = controller.register_work_v1(
        WorkOperationKindV1.GENERIC_STATE_MUTATION,
        10**12,
    )
    assert controller.validate_before_state_mutation_v1(current.fence)
    assert controller.release_work_v1(current.lease)

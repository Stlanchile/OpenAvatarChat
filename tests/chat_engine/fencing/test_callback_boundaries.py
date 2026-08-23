from __future__ import annotations

import asyncio
import threading

import pytest

from chat_engine.security.session_work_controller import (
    ControllerTransitionPointV1,
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

VALIDATORS = (
    "validate_before_external_call_v1",
    "validate_after_callback_v1",
    "validate_before_state_mutation_v1",
    "validate_before_private_store_write_v1",
    "validate_before_egress_v1",
)

PROTECTED_BOUNDARIES = (
    WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
    WorkValidationBoundaryV1.BEFORE_EGRESS,
)


def _register(controller, fake_clock):
    return controller.register_work_v1(
        WorkOperationKindV1.GENERIC_EXTERNAL_CALL,
        fake_clock() + 60.0,
    )


def _attempt_protected_side_effects(controller, fence):
    side_effects = []
    for boundary in PROTECTED_BOUNDARIES:
        controller.perform_if_live_v1(
            fence,
            boundary,
            lambda boundary=boundary: side_effects.append(boundary),
        )
    return side_effects


def test_completion_before_retirement_passes_every_boundary(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)

    for validator_name in VALIDATORS:
        assert getattr(controller, validator_name)(work.fence)
    assert _attempt_protected_side_effects(
        controller,
        work.fence,
    ) == list(PROTECTED_BOUNDARIES)


def test_non_cancellable_return_immediately_after_retirement_has_zero_effects(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    external_call_started = controller.validate_before_external_call_v1(work.fence)
    retirement = controller.retire_generation_v1()

    assert external_call_started
    assert work.cancellation.is_cancelled
    assert not controller.validate_after_callback_v1(work.fence)
    assert _attempt_protected_side_effects(controller, work.fence) == []
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)


def test_long_late_callback_stays_side_effect_ineligible(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    retirement = controller.retire_generation_v1()
    fake_clock.advance(10_000.0)

    for validator_name in VALIDATORS:
        assert not getattr(controller, validator_name)(work.fence)
    assert _attempt_protected_side_effects(controller, work.fence) == []
    assert controller.release_work_v1(work.lease)
    assert not controller.wait_for_cleanup_v1(retirement.cleanup_fence)


def test_cancel_release_and_shutdown_each_block_late_callbacks(
    controller,
    fake_clock,
):
    cancelled = _register(controller, fake_clock)
    assert controller.cancel_work_v1(cancelled.fence)
    assert not controller.validate_after_callback_v1(cancelled.fence)
    assert _attempt_protected_side_effects(controller, cancelled.fence) == []
    assert controller.release_work_v1(cancelled.lease)

    released = _register(controller, fake_clock)
    assert controller.release_work_v1(released.lease)
    assert not controller.validate_after_callback_v1(released.fence)
    assert _attempt_protected_side_effects(controller, released.fence) == []

    shutdown_work = _register(controller, fake_clock)

    def release_after_cancel():
        assert shutdown_work.cancellation.wait(1.0)
        assert controller.release_work_v1(shutdown_work.lease)

    worker = threading.Thread(target=release_after_cancel)
    worker.start()
    assert controller.shutdown()
    worker.join(timeout=1.0)
    assert not worker.is_alive()
    assert not controller.validate_after_callback_v1(shutdown_work.fence)
    assert (
        _attempt_protected_side_effects(
            controller,
            shutdown_work.fence,
        )
        == []
    )


def test_protected_action_winning_lock_completes_before_retirement_publication(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    action_entered = threading.Event()
    allow_action = threading.Event()
    side_effects = []
    action_result = []
    retirement_result = []

    def action():
        action_entered.set()
        assert allow_action.wait(1.0)
        side_effects.append("mutation-before-retirement")

    action_thread = threading.Thread(
        target=lambda: action_result.append(
            controller.perform_if_live_v1(
                work.fence,
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                action,
            )
        )
    )
    action_thread.start()
    assert action_entered.wait(1.0)

    retire_thread = threading.Thread(
        target=lambda: retirement_result.append(controller.retire_generation_v1())
    )
    retire_thread.start()
    allow_action.set()
    action_thread.join(timeout=1.0)
    retire_thread.join(timeout=1.0)

    assert action_result == [True]
    assert side_effects == ["mutation-before-retirement"]
    assert not controller.validate_after_callback_v1(work.fence)
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement_result[0].cleanup_fence)


def test_retirement_winning_lock_blocks_exactly_racing_protected_action(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    retirement_locked = threading.Event()
    allow_retirement = threading.Event()
    side_effects = []
    action_result = []

    def hook(point):
        if point is ControllerTransitionPointV1.RETIREMENT_BEFORE_PUBLICATION:
            retirement_locked.set()
            assert allow_retirement.wait(1.0)

    controller._set_transition_hook_for_test_v1(hook)
    retire_thread = threading.Thread(target=controller.retire_generation_v1)
    retire_thread.start()
    assert retirement_locked.wait(1.0)

    action_thread = threading.Thread(
        target=lambda: action_result.append(
            controller.perform_if_live_v1(
                work.fence,
                WorkValidationBoundaryV1.BEFORE_EGRESS,
                lambda: side_effects.append("late-egress"),
            )
        )
    )
    action_thread.start()
    assert action_thread.is_alive()
    allow_retirement.set()
    retire_thread.join(timeout=1.0)
    action_thread.join(timeout=1.0)

    assert action_result == [False]
    assert side_effects == []


@pytest.mark.asyncio
async def test_async_cooperative_waiter_is_woken_by_retirement(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    waiter = asyncio.create_task(work.cancellation.wait_async(max_wait_seconds=1.0))
    await asyncio.sleep(0)

    controller.retire_generation_v1()

    assert await waiter
    assert not controller.validate_after_callback_v1(work.fence)


def test_protected_action_cannot_reenter_retirement_or_release(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    side_effects = []

    def action():
        with pytest.raises(WorkAdmissionDeniedV1):
            controller.retire_generation_v1()
        with pytest.raises(WorkAdmissionDeniedV1):
            controller.release_work_v1(work.lease)
        side_effects.append("still-current")

    assert controller.perform_if_live_v1(
        work.fence,
        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        action,
    )
    assert side_effects == ["still-current"]
    assert controller.current_epoch_v1().generation == 1
    assert controller.validate_after_callback_v1(work.fence)

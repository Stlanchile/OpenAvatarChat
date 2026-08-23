from __future__ import annotations

import threading
import time

from chat_engine.security.session_work_controller import (
    ControllerTransitionPointV1,
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1


def _spawn(target):
    errors: list[BaseException] = []

    def guarded_target():
        try:
            target()
        except Exception as error:  # noqa: BLE001 - surfaced in parent thread
            errors.append(error)

    thread = threading.Thread(target=guarded_target)
    thread.start()
    return thread, errors


def _join(thread, errors):
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    if errors:
        raise errors[0]


def _deadline() -> float:
    return time.monotonic() + 30.0


def test_registration_paused_before_lock_belongs_entirely_to_new_generation():
    controller = SessionWorkControllerV1()
    reached = threading.Event()
    release = threading.Event()
    result = []

    def hook(point):
        if point is ControllerTransitionPointV1.BEFORE_REGISTRATION_LOCK:
            reached.set()
            assert release.wait(2.0)

    controller._set_transition_hook_for_test_v1(hook)
    worker, errors = _spawn(
        lambda: result.append(
            controller.register_work_v1(
                WorkOperationKindV1.GENERIC_ASYNC,
                _deadline(),
            )
        )
    )
    assert reached.wait(1.0)

    retirement = controller.retire_generation_v1()
    release.set()
    _join(worker, errors)

    work = result[0]
    assert work.fence.session_epoch == retirement.new_epoch
    assert controller.validate_at_admission_v1(work.fence)
    assert controller.snapshot_v1().unreleased_work_by_generation == ((2, 1),)


def test_registration_holding_lock_commits_old_generation_before_retirement():
    controller = SessionWorkControllerV1()
    registration_locked = threading.Event()
    allow_registration = threading.Event()
    retirement_done = threading.Event()
    work_result = []
    retirement_result = []

    def hook(point):
        if point is ControllerTransitionPointV1.REGISTRATION_LOCKED:
            registration_locked.set()
            assert allow_registration.wait(2.0)

    controller._set_transition_hook_for_test_v1(hook)
    worker, worker_errors = _spawn(
        lambda: work_result.append(
            controller.register_work_v1(
                WorkOperationKindV1.GENERIC_ASYNC,
                _deadline(),
            )
        )
    )
    assert registration_locked.wait(1.0)

    def retire():
        retirement_result.append(controller.retire_generation_v1())
        retirement_done.set()

    retire_thread, retire_errors = _spawn(retire)
    assert not retirement_done.wait(0.05)
    allow_registration.set()
    _join(worker, worker_errors)
    _join(retire_thread, retire_errors)

    work = work_result[0]
    retirement = retirement_result[0]
    assert work.fence.session_epoch.generation == 1
    assert work.cancellation.is_cancelled
    assert not controller.validate_after_callback_v1(work.fence)
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 1),)
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)


def test_registration_paused_immediately_after_commit_is_retired_as_one_unit():
    controller = SessionWorkControllerV1()
    committed = threading.Event()
    allow_return = threading.Event()
    work_result = []

    def hook(point):
        if point is ControllerTransitionPointV1.AFTER_REGISTRATION:
            committed.set()
            assert allow_return.wait(2.0)

    controller._set_transition_hook_for_test_v1(hook)
    worker, errors = _spawn(
        lambda: work_result.append(
            controller.register_work_v1(
                WorkOperationKindV1.GENERIC_EXTERNAL_CALL,
                _deadline(),
            )
        )
    )
    assert committed.wait(1.0)
    retirement = controller.retire_generation_v1()
    allow_return.set()
    _join(worker, errors)

    work = work_result[0]
    assert work.fence.session_epoch.generation == 1
    assert work.cancellation.is_cancelled
    assert controller.snapshot_v1().unreleased_work_by_generation == ((1, 1),)
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)


def test_registration_waiting_before_retirement_publication_enters_new_epoch():
    controller = SessionWorkControllerV1()
    retirement_locked = threading.Event()
    allow_publication = threading.Event()
    registration_done = threading.Event()
    work_result = []
    retirement_result = []

    def hook(point):
        if point is ControllerTransitionPointV1.RETIREMENT_BEFORE_PUBLICATION:
            retirement_locked.set()
            assert allow_publication.wait(2.0)

    controller._set_transition_hook_for_test_v1(hook)
    retire_thread, retire_errors = _spawn(
        lambda: retirement_result.append(controller.retire_generation_v1())
    )
    assert retirement_locked.wait(1.0)

    def register():
        work_result.append(
            controller.register_work_v1(
                WorkOperationKindV1.GENERIC_STATE_MUTATION,
                _deadline(),
            )
        )
        registration_done.set()

    worker, worker_errors = _spawn(register)
    assert not registration_done.wait(0.05)
    allow_publication.set()
    _join(retire_thread, retire_errors)
    _join(worker, worker_errors)

    work = work_result[0]
    assert work.fence.session_epoch == retirement_result[0].new_epoch
    assert controller.validate_before_state_mutation_v1(work.fence)
    assert controller.snapshot_v1().unreleased_work_by_generation == ((2, 1),)


def test_registration_after_retirement_publication_uses_new_generation():
    controller = SessionWorkControllerV1()
    published = threading.Event()
    allow_retire_return = threading.Event()
    retirement_result = []

    def hook(point):
        if point is ControllerTransitionPointV1.AFTER_RETIREMENT_PUBLICATION:
            published.set()
            assert allow_retire_return.wait(2.0)

    controller._set_transition_hook_for_test_v1(hook)
    retire_thread, retire_errors = _spawn(
        lambda: retirement_result.append(controller.retire_generation_v1())
    )
    assert published.wait(1.0)

    work = controller.register_work_v1(
        WorkOperationKindV1.GENERIC_EGRESS,
        _deadline(),
    )
    allow_retire_return.set()
    _join(retire_thread, retire_errors)

    assert work.fence.session_epoch == retirement_result[0].new_epoch
    assert controller.validate_before_egress_v1(work.fence)
    assert controller.snapshot_v1().unreleased_work_by_generation == ((2, 1),)

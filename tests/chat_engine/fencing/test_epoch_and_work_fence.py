from __future__ import annotations

import dataclasses
import inspect
import uuid

import pytest

import chat_engine.security.session_work_controller as controller_module
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import UINT64_MAX_V1, new_uuid7_v1
from chat_engine.security.session_work_controller import (
    SessionGenerationOverflowV1,
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
    WorkControllerFailureReasonV1,
)
from chat_engine.security.work_fence import (
    WorkFenceV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)


def _register(controller, fake_clock, kind=WorkOperationKindV1.GENERIC_ASYNC):
    return controller.register_work_v1(kind, fake_clock() + 30.0)


def test_initial_epoch_is_server_minted_uuid7_generation_one():
    first = SessionWorkControllerV1()
    second = SessionWorkControllerV1()

    first_epoch = first.current_epoch_v1()
    second_epoch = second.current_epoch_v1()

    assert first_epoch.generation == 1
    assert first_epoch.session_instance_id.version == 7
    assert first_epoch.session_instance_id.variant == uuid.RFC_4122
    assert first_epoch.session_instance_id != second_epoch.session_instance_id
    assert first.shutdown()
    assert second.shutdown()


def test_uuid7_layout_uses_rfc_variant_and_unique_random_values():
    values = {new_uuid7_v1() for _ in range(256)}

    assert len(values) == 256
    assert all(value.version == 7 for value in values)
    assert all(value.variant == uuid.RFC_4122 for value in values)


def test_operation_and_lease_ids_are_server_generated_unique_uuid7(
    controller,
    fake_clock,
):
    work_items = [_register(controller, fake_clock) for _ in range(128)]
    operation_ids = {work.fence.operation_id for work in work_items}
    token_ids = {work.lease.token_id for work in work_items}

    assert len(operation_ids) == 128
    assert len(token_ids) == 128
    assert all(value.version == 7 for value in operation_ids | token_ids)
    assert all(controller.release_work_v1(work.lease) for work in work_items)


def test_generations_increase_monotonically_and_old_epochs_never_return(
    controller,
):
    observed = [controller.current_epoch_v1()]
    for _ in range(4):
        observed.append(controller.retire_generation_v1().new_epoch)

    assert [epoch.generation for epoch in observed] == [1, 2, 3, 4, 5]
    assert len({epoch.session_instance_id for epoch in observed}) == 1
    assert observed == sorted(observed, key=lambda epoch: epoch.generation)


def test_generation_overflow_fails_closed_without_wrap():
    controller = SessionWorkControllerV1._create_for_test_v1()
    controller._set_generation_for_test_v1(UINT64_MAX_V1)

    with pytest.raises(
        SessionGenerationOverflowV1,
        match="session generation exhausted",
    ):
        controller.retire_generation_v1()

    snapshot = controller.snapshot_v1()
    assert snapshot.current_epoch.generation == UINT64_MAX_V1
    assert snapshot.failed
    assert not snapshot.active
    assert not snapshot.admission_open
    assert snapshot.failure_reason is WorkControllerFailureReasonV1.GENERATION_OVERFLOW
    with pytest.raises(WorkAdmissionDeniedV1):
        controller.register_work_v1(
            WorkOperationKindV1.GENERIC_ASYNC,
            10**12,
        )


def test_internal_identifier_failure_during_registration_fails_closed(
    monkeypatch,
):
    controller = SessionWorkControllerV1()
    monkeypatch.setattr(
        controller_module,
        "new_uuid7_v1",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic secret")),
    )

    with pytest.raises(
        WorkAdmissionDeniedV1,
        match="secure work registration failed",
    ):
        controller.register_work_v1(
            WorkOperationKindV1.GENERIC_ASYNC,
            10**12,
        )

    snapshot = controller.snapshot_v1()
    assert snapshot.failed
    assert not snapshot.active
    assert (
        snapshot.failure_reason
        is WorkControllerFailureReasonV1.INTERNAL_AUTHORITY_FAILURE
    )


def test_internal_retirement_failure_cancels_existing_work(
    monkeypatch,
    fake_clock,
):
    controller = SessionWorkControllerV1._create_for_test_v1(monotonic_clock=fake_clock)
    work = _register(controller, fake_clock)
    monkeypatch.setattr(
        controller_module,
        "new_uuid7_v1",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic secret")),
    )

    with pytest.raises(
        WorkAdmissionDeniedV1,
        match="generation retirement failed",
    ):
        controller.retire_generation_v1()

    assert work.cancellation.is_cancelled
    assert not controller.validate_after_callback_v1(work.fence)
    assert controller.snapshot_v1().failed


def test_callers_cannot_select_epoch_or_generation(controller, fake_clock):
    parameters = inspect.signature(controller.register_work_v1).parameters
    assert "session_epoch" not in parameters
    assert "generation" not in parameters

    with pytest.raises(TypeError):
        controller.register_work_v1(
            WorkOperationKindV1.GENERIC_ASYNC,
            fake_clock() + 10,
            generation=99,
        )

    epoch = controller.current_epoch_v1()
    forged_value = SessionEpochV1(
        epoch.session_instance_id,
        epoch.generation,
    )
    assert forged_value == epoch
    assert forged_value is not epoch
    assert not hasattr(controller, "validate_epoch_v1")


def test_all_central_boundary_predicates_accept_one_live_fence(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)

    assert controller.validate_at_admission_v1(work.fence)
    assert controller.validate_at_dequeue_v1(work.fence)
    assert controller.validate_before_external_call_v1(work.fence)
    assert controller.validate_after_callback_v1(work.fence)
    assert controller.validate_before_state_mutation_v1(work.fence)
    assert controller.validate_before_private_store_write_v1(work.fence)
    assert controller.validate_before_egress_v1(work.fence)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda fence, other: dataclasses.replace(
            fence,
            session_epoch=other.current_epoch_v1(),
        ),
        lambda fence, _other: dataclasses.replace(
            fence,
            session_epoch=SessionEpochV1(
                fence.session_epoch.session_instance_id,
                fence.session_epoch.generation + 1,
            ),
        ),
        lambda fence, _other: dataclasses.replace(
            fence,
            operation_id=new_uuid7_v1(),
        ),
        lambda fence, _other: dataclasses.replace(
            fence,
            operation_kind=WorkOperationKindV1.GENERIC_EGRESS,
        ),
        lambda fence, _other: dataclasses.replace(
            fence,
            authenticator=b"\x00" * len(fence.authenticator),
        ),
    ],
    ids=[
        "wrong-session",
        "wrong-generation",
        "unknown-operation",
        "wrong-operation-kind",
        "wrong-authenticator",
    ],
)
def test_forged_or_reconstructed_fence_fields_have_no_authority(
    controller,
    fake_clock,
    mutator,
):
    other = SessionWorkControllerV1()
    work = _register(controller, fake_clock)
    forged = mutator(work.fence, other)

    assert isinstance(forged, WorkFenceV1)
    assert forged is not work.fence
    assert not controller.validate_at_admission_v1(forged)
    assert controller.validate_at_admission_v1(work.fence)
    assert other.shutdown()


def test_exact_reconstruction_of_live_fence_is_not_authority(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    reconstructed = WorkFenceV1(
        **{
            field.name: getattr(work.fence, field.name)
            for field in dataclasses.fields(WorkFenceV1)
        }
    )

    assert reconstructed == work.fence
    assert reconstructed is not work.fence
    assert not controller.validate_at_dequeue_v1(reconstructed)
    assert controller.validate_at_dequeue_v1(work.fence)


def test_cancelled_expired_and_released_work_are_permanently_invalid(
    controller,
    fake_clock,
):
    cancelled = _register(controller, fake_clock)
    assert controller.cancel_work_v1(cancelled.fence)
    assert cancelled.cancellation.is_cancelled
    assert not controller.validate_after_callback_v1(cancelled.fence)

    expired = _register(controller, fake_clock)
    fake_clock.advance(31.0)
    assert not controller.validate_before_state_mutation_v1(expired.fence)
    assert expired.cancellation.is_cancelled

    released = controller.register_work_v1(
        WorkOperationKindV1.GENERIC_STATE_MUTATION,
        fake_clock() + 30.0,
    )
    assert controller.release_work_v1(released.lease)
    assert not controller.validate_before_state_mutation_v1(released.fence)


def test_monotonic_deadline_boundary_is_fail_closed(controller, fake_clock):
    work = controller.register_work_v1(
        WorkOperationKindV1.GENERIC_STATE_MUTATION,
        fake_clock() + 1.0,
    )
    effects = []

    fake_clock.advance(0.999)
    assert controller.perform_if_live_v1(
        work.fence,
        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        lambda: effects.append("before-deadline"),
    )
    fake_clock.advance(0.001)
    assert not controller.perform_if_live_v1(
        work.fence,
        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        lambda: effects.append("at-deadline"),
    )
    assert effects == ["before-deadline"]
    assert work.cancellation.is_cancelled


def test_stale_fence_never_revives_after_more_generation_increments(
    controller,
    fake_clock,
):
    work = _register(controller, fake_clock)
    first_retirement = controller.retire_generation_v1()

    assert work.cancellation.is_cancelled
    assert not controller.validate_after_callback_v1(work.fence)
    assert controller.release_work_v1(work.lease)
    assert controller.wait_for_cleanup_v1(first_retirement.cleanup_fence)

    for _ in range(5):
        controller.retire_generation_v1()
        assert not controller.validate_before_egress_v1(work.fence)

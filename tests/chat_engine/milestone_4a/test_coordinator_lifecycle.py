from __future__ import annotations

import asyncio
import uuid
from dataclasses import FrozenInstanceError

import pytest

from certificate_capture.coordinator import (
    CaptureCoordinatorV1,
    CaptureFailedClosedV1,
    CaptureTransitionRejectedV1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.state import (
    CaptureStateV1,
    CaptureTransitionPointV1,
)
from chat_engine.security.audit_events import SecurityAuditEventCodeV1
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import UINT64_MAX_V1, new_uuid7_v1


def test_capture_state_schema_is_exact_and_has_no_later_outcome_states():
    assert [state.value for state in CaptureStateV1] == [
        "IDLE",
        "ENTERING",
        "QUIESCING",
        "ARMED",
        "CAPTURING",
        "BUILDING_ASSERTIONS",
        "READY",
        "ENDING",
        "FAILED_CLOSED",
    ]
    assert "ANSWERING" not in CaptureStateV1.__members__
    assert "NEEDS_RECAPTURE" not in CaptureStateV1.__members__


def test_capture_epoch_schema_is_frozen_redacted_and_uuid7():
    epoch = CaptureEpochV1(
        session_epoch=SessionEpochV1(new_uuid7_v1(), 7),
        capture_id=new_uuid7_v1(),
        capture_seq=9,
    )

    assert epoch.capture_id.version == 7
    assert epoch.capture_seq == 9
    assert "capture_id=<opaque>" in repr(epoch)
    with pytest.raises(FrozenInstanceError):
        epoch.capture_seq = 10
    with pytest.raises(ValueError):
        CaptureEpochV1(
            session_epoch=epoch.session_epoch,
            capture_id=uuid.uuid4(),
            capture_seq=1,
        )
    with pytest.raises(ValueError):
        CaptureEpochV1(
            session_epoch=epoch.session_epoch,
            capture_id=new_uuid7_v1(),
            capture_seq=0,
        )


def test_direct_coordinator_construction_is_denied(capture_harness_factory):
    harness = capture_harness_factory()
    with pytest.raises(RuntimeError, match="construction denied"):
        CaptureCoordinatorV1(
            _construction_authority_v1=object(),
            work_controller=harness.controller,
            isolation_controller=object(),
            isolation_view=harness.gate,
            private_evidence_authority_v1=(
                harness.private_evidence_authority
            ),
            feature_enabled_v1=lambda: True,
            security_authority_usable_v1=lambda: True,
            session_live_action_v1=lambda action: True,
            quiescence_drain_v1=lambda epoch: None,
            semantic_cleanup_v1=lambda epoch: None,
            failure_terminator_v1=None,
        )


@pytest.mark.asyncio
async def test_complete_4a_legal_cycle_and_generation_publication_is_not_armed(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    observed: list[tuple[CaptureTransitionPointV1, CaptureStateV1, int, bool]] = []

    async def hook(point: CaptureTransitionPointV1) -> None:
        status = harness.coordinator.snapshot_v1()
        observed.append(
            (
                point,
                status.state,
                status.session_generation,
                status.quiescence_complete,
            )
        )

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    capture_epoch = await harness.coordinator.begin_capture_v1()

    assert observed[:4] == [
        (
            CaptureTransitionPointV1.AFTER_ENTERING,
            CaptureStateV1.ENTERING,
            1,
            False,
        ),
        (
            CaptureTransitionPointV1.BEFORE_BEGIN_RETIREMENT,
            CaptureStateV1.ENTERING,
            1,
            False,
        ),
        (
            CaptureTransitionPointV1.AFTER_BEGIN_RETIREMENT,
            CaptureStateV1.ENTERING,
            2,
            False,
        ),
        (
            CaptureTransitionPointV1.AFTER_QUIESCING,
            CaptureStateV1.QUIESCING,
            2,
            False,
        ),
    ]
    before_armed = next(
        item for item in observed if item[0] is CaptureTransitionPointV1.BEFORE_ARMED
    )
    assert before_armed[1:] == (CaptureStateV1.QUIESCING, 2, True)
    armed = harness.coordinator.snapshot_v1()
    assert armed.state is CaptureStateV1.ARMED
    assert armed.session_generation == 2
    assert armed.quiescence_complete
    assert not armed.normal_application_admission_open
    assert capture_epoch.session_epoch.generation == 2

    status = await harness.coordinator.end_capture_v1(capture_epoch)

    assert status.state is CaptureStateV1.IDLE
    assert status.session_generation == 3
    assert status.capture_id is None
    assert status.capture_seq == 1
    assert status.normal_application_admission_open
    assert not status.quiescence_complete
    assert harness.drain_generations == [2, 3]
    assert harness.semantic_generations == [2, 3]


@pytest.mark.asyncio
async def test_transition_audit_events_are_value_free(capture_harness_factory):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    await harness.coordinator.end_capture_v1(capture_epoch)

    events = harness.coordinator.audit_events_v1()
    assert [event.code for event in events] == [
        SecurityAuditEventCodeV1.CAPTURE_ENTERING,
        SecurityAuditEventCodeV1.CAPTURE_QUIESCING,
        SecurityAuditEventCodeV1.CAPTURE_ARMED,
        SecurityAuditEventCodeV1.CAPTURE_ENDING,
        SecurityAuditEventCodeV1.CAPTURE_RESUMED,
    ]
    assert all(event.envelope_id is None for event in events)
    assert all(event.consumer_capability_id is None for event in events)
    assert all(event.dispatch_id is None for event in events)


@pytest.mark.asyncio
async def test_end_idle_double_begin_and_begin_armed_are_rejected(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    with pytest.raises(CaptureTransitionRejectedV1) as idle_end:
        await harness.coordinator.end_capture_v1(capture_seq=0)
    assert idle_end.value.reason_code == "INVALID_STATE"

    entered = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENTERING:
            entered.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    first = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await entered.wait()
    with pytest.raises(CaptureTransitionRejectedV1) as duplicate:
        await harness.coordinator.begin_capture_v1()
    assert duplicate.value.reason_code == "CAPTURE_BUSY"
    release.set()
    capture_epoch = await first

    with pytest.raises(CaptureTransitionRejectedV1) as armed_begin:
        await harness.coordinator.begin_capture_v1()
    assert armed_begin.value.reason_code == "CAPTURE_BUSY"
    await harness.coordinator.end_capture_v1(capture_epoch)


@pytest.mark.asyncio
async def test_capture_epoch_identity_and_sequence_are_canonical(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    forged_equal = CaptureEpochV1(
        session_epoch=capture_epoch.session_epoch,
        capture_id=capture_epoch.capture_id,
        capture_seq=capture_epoch.capture_seq,
    )

    with pytest.raises(CaptureTransitionRejectedV1) as forged:
        await harness.coordinator.end_capture_v1(forged_equal)
    assert forged.value.reason_code == "CAPTURE_EPOCH_MISMATCH"
    with pytest.raises(CaptureTransitionRejectedV1) as mismatch:
        await harness.coordinator.end_capture_v1(
            capture_epoch,
            capture_seq=capture_epoch.capture_seq + 1,
        )
    assert mismatch.value.reason_code == "CAPTURE_SEQUENCE_MISMATCH"

    await harness.coordinator.end_capture_v1(capture_epoch)


@pytest.mark.asyncio
async def test_begin_begin_race_creates_one_capture_and_one_retirement(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENTERING:
            entered.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    first = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await entered.wait()
    second = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await asyncio.sleep(0)
    release.set()
    outcomes = await asyncio.gather(first, second, return_exceptions=True)

    epochs = [item for item in outcomes if isinstance(item, CaptureEpochV1)]
    rejected = [
        item for item in outcomes if isinstance(item, CaptureTransitionRejectedV1)
    ]
    assert len(epochs) == 1
    assert len(rejected) == 1
    assert rejected[0].reason_code == "CAPTURE_BUSY"
    assert harness.coordinator.snapshot_v1().session_generation == 2
    await harness.coordinator.end_capture_v1(epochs[0])


@pytest.mark.asyncio
async def test_capture_sequence_overflow_fails_closed_without_wraparound(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    harness.coordinator._set_capture_sequence_for_test_v1(UINT64_MAX_V1)

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    status = harness.coordinator.snapshot_v1()
    assert failure.value.reason_code == "CAPTURE_SEQUENCE_OVERFLOW"
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert status.capture_seq == UINT64_MAX_V1
    assert not status.normal_application_admission_open
    assert harness.termination_requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("precondition", "reason_code"),
    [
        ("feature_enabled", "FEATURE_DISABLED"),
        ("security_live", "SECURITY_AUTHORITY_UNAVAILABLE"),
        ("session_live", "SESSION_AUTHORITY_UNAVAILABLE"),
    ],
)
async def test_security_precondition_loss_fails_closed_before_begin_mutation(
    capture_harness_factory,
    precondition,
    reason_code,
):
    harness = capture_harness_factory()
    setattr(harness, precondition, False)

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    status = harness.coordinator.snapshot_v1()
    assert failure.value.reason_code == reason_code
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert status.capture_seq == 0
    assert status.capture_id is None
    assert status.session_generation == 1
    assert not status.normal_application_admission_open
    assert harness.termination_requests == 1


@pytest.mark.asyncio
async def test_unusable_work_controller_fails_closed_before_begin(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    assert harness.controller.shutdown()

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    status = harness.coordinator.snapshot_v1()
    assert failure.value.reason_code == "WORK_CONTROLLER_UNAVAILABLE"
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert status.capture_seq == 0
    assert not status.normal_application_admission_open
    assert harness.termination_requests == 1


@pytest.mark.asyncio
async def test_session_authority_loss_before_end_stays_failed_closed(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    harness.session_live = False

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.end_capture_v1(capture_epoch)

    status = harness.coordinator.snapshot_v1()
    assert failure.value.reason_code == "SESSION_AUTHORITY_UNAVAILABLE"
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert not status.normal_application_admission_open
    assert harness.termination_requests == 1


@pytest.mark.asyncio
async def test_repeated_capture_cycles_are_monotonic_and_isolated(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    first = await harness.coordinator.begin_capture_v1()
    await harness.coordinator.end_capture_v1(first)
    second = await harness.coordinator.begin_capture_v1()
    await harness.coordinator.end_capture_v1(second)

    assert first.capture_id != second.capture_id
    assert (first.capture_seq, second.capture_seq) == (1, 2)
    assert (
        first.session_epoch.generation,
        second.session_epoch.generation,
    ) == (2, 4)
    status = harness.coordinator.snapshot_v1()
    assert status.state is CaptureStateV1.IDLE
    assert status.session_generation == 5
    isolation = harness.gate.snapshot_v1()
    assert isolation.close_count == 2
    assert isolation.reopen_count == 2
    assert harness.controller.snapshot_v1().unreleased_work_by_generation == ()


@pytest.mark.asyncio
async def test_unexpected_generation_change_is_not_laundered(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    advanced = False

    async def hook(point: CaptureTransitionPointV1) -> None:
        nonlocal advanced
        if point is CaptureTransitionPointV1.AFTER_ENTERING and not advanced:
            advanced = True
            harness.controller.retire_generation_v1()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    with pytest.raises(CaptureFailedClosedV1) as failure:
        await harness.coordinator.begin_capture_v1()

    assert failure.value.reason_code == "GENERATION_MISMATCH"
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not harness.gate.is_open_v1()


@pytest.mark.asyncio
async def test_status_snapshot_contains_only_control_plane_fields(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    status = harness.coordinator.snapshot_v1()

    assert set(status.__dataclass_fields__) == {
        "state",
        "capture_id",
        "capture_seq",
        "session_generation",
        "transition_id",
        "transition_kind",
        "transition_phase",
        "failure_reason_code",
        "normal_application_admission_open",
        "quiescence_complete",
        "shutdown_started",
        "destroyed",
    }
    assert "principal" not in repr(status).lower()
    assert "capability" not in repr(status).lower()
    assert status.capture_id == capture_epoch.capture_id
    await harness.coordinator.end_capture_v1(capture_epoch)

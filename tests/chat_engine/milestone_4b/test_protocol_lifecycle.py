from __future__ import annotations

import asyncio
import base64
import uuid
from dataclasses import fields

import pytest

from certificate_capture.coordinator import CaptureCoordinatorV1
from certificate_capture.protocol import (
    MAX_CAPTURE_ENCODED_BYTES_V1,
    MAX_CAPTURE_FRAMES_V1,
    MAX_CONTROL_MUTATIONS_PER_SESSION_V1,
    MAX_ENCODED_FRAME_BYTES_V1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
    SealOutcomeV1,
    SealReasonCodeV1,
)
from certificate_capture.state import CaptureStateV1
from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1
from tests.chat_engine.milestone_4b.test_frame_ingress import (
    _with_exact_metadata_size_v1,
)


class ImmediateMockProcessorV1:
    def __init__(self) -> None:
        self.calls = 0
        self.inputs: list[object] = []

    async def process_capture_v1(self, processing_input) -> None:
        self.calls += 1
        self.inputs.append(processing_input)
        await asyncio.sleep(0)


class BlockingMockProcessorV1:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0

    async def process_capture_v1(self, processing_input) -> None:
        self.calls += 1
        self.started.set()
        await self.release.wait()


@pytest.mark.asyncio
async def test_begin_replay_is_deterministic_and_returns_only_after_armed(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    request_id = uuid.uuid4()

    first = await harness.begin(
        request_id=request_id,
        control_seq=1,
    )
    replay = await harness.begin(
        request_id=request_id,
        control_seq=1,
    )

    assert first == replay
    assert first.capture_capability == replay.capture_capability
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ARMED
    assert harness.gate.is_open_v1() is False
    assert harness.coordinator._replay_ledger_v1.snapshot_v1() == (1, 1)


@pytest.mark.asyncio
async def test_begin_replay_cannot_reemit_capability_after_failed_closed(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    request_id = uuid.uuid4()
    await harness.begin(request_id=request_id)
    harness.coordinator._fail_closed_for_test_v1()

    with pytest.raises(CaptureProtocolErrorV1) as denied:
        await harness.begin(request_id=request_id)

    assert (
        denied.value.reason
        is CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
    )
    assert harness.coordinator.snapshot_v1().state is (
        CaptureStateV1.FAILED_CLOSED
    )


@pytest.mark.asyncio
async def test_capture_capability_has_256_bits_and_only_digest_is_active(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = grant.capture_capability.removeprefix("ccp1_")
    entropy = base64.urlsafe_b64decode(encoded + "=")
    active = harness.coordinator._active_capture_capability_v1

    assert len(entropy) == 32
    assert active is not None
    assert {field.name for field in fields(active)} == {
        "binding",
        "capability_digest",
    }
    assert len(active.capability_digest) == 32
    assert active.capability_digest != entropy
    assert grant.capture_capability not in repr(active)


@pytest.mark.asyncio
async def test_begin_request_id_content_conflict_and_control_sequence_rules(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    request_id = uuid.uuid4()
    grant = await harness.begin(request_id=request_id)

    with pytest.raises(CaptureProtocolErrorV1) as changed:
        await harness.begin(
            request_id=request_id,
            profile_id="changed-profile",
        )
    assert (
        changed.value.reason
        is CaptureProtocolReasonV1.IDEMPOTENCY_CONFLICT
    )

    with pytest.raises(CaptureProtocolErrorV1) as gap:
        await harness.begin(control_seq=3)
    assert gap.value.reason is CaptureProtocolReasonV1.CONTROL_SEQUENCE_GAP

    active_request_id = uuid.uuid4()
    with pytest.raises(CaptureProtocolErrorV1) as active:
        await harness.begin(
            request_id=active_request_id,
            control_seq=2,
        )
    assert active.value.reason is CaptureProtocolReasonV1.CAPTURE_BUSY

    with pytest.raises(CaptureProtocolErrorV1) as stale:
        await harness.begin(
            request_id=active_request_id,
            control_seq=2,
        )
    assert stale.value.reason is CaptureProtocolReasonV1.CAPTURE_BUSY

    await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=synthetic_jpeg_v1(),
    )
    with pytest.raises(CaptureProtocolErrorV1) as changed_operation:
        await harness.coordinator.seal_capture_protocol_v1(
            request_id=active_request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert (
        changed_operation.value.reason
        is CaptureProtocolReasonV1.IDEMPOTENCY_CONFLICT
    )


@pytest.mark.asyncio
async def test_capture_id_is_part_of_seal_and_end_replay_identity(
    capture_protocol_harness_factory,
):
    processor = ImmediateMockProcessorV1()
    harness = capture_protocol_harness_factory(processor=processor)
    grant = await harness.begin()
    for frame_seq, color in enumerate(
        ((1, 2, 3), (4, 5, 6), (7, 8, 9)),
        start=1,
    ):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(color=color),
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
    with pytest.raises(CaptureProtocolErrorV1) as changed_seal:
        await harness.coordinator.seal_capture_protocol_v1(
            request_id=seal_request_id,
            control_seq=2,
            capture_id=uuid.uuid4(),
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert (
        changed_seal.value.reason
        is CaptureProtocolReasonV1.IDEMPOTENCY_CONFLICT
    )

    end_request_id = uuid.uuid4()
    await harness.coordinator.end_capture_protocol_v1(
        request_id=end_request_id,
        control_seq=3,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    with pytest.raises(CaptureProtocolErrorV1) as changed_end:
        await harness.coordinator.end_capture_protocol_v1(
            request_id=end_request_id,
            control_seq=3,
            capture_id=uuid.uuid4(),
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert (
        changed_end.value.reason
        is CaptureProtocolReasonV1.IDEMPOTENCY_CONFLICT
    )


@pytest.mark.asyncio
async def test_replay_window_cannot_exhaust_mandatory_end(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    next_control_seq = 2
    for _ in range(MAX_CONTROL_MUTATIONS_PER_SESSION_V1 + 4):
        with pytest.raises(CaptureProtocolErrorV1) as busy:
            await harness.begin(control_seq=next_control_seq)
        assert busy.value.reason is CaptureProtocolReasonV1.CAPTURE_BUSY
        next_control_seq += 1

    end_request_id = uuid.uuid4()
    ended = await harness.coordinator.end_capture_protocol_v1(
        request_id=end_request_id,
        control_seq=next_control_seq,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    replay = await harness.coordinator.end_capture_protocol_v1(
        request_id=end_request_id,
        control_seq=next_control_seq,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )

    assert ended == replay
    assert ended.state is CaptureStateV1.IDLE
    assert harness.coordinator._replay_ledger_v1.snapshot_v1() == (
        next_control_seq,
        1,
    )
    next_grant = await harness.begin(control_seq=next_control_seq + 1)
    assert next_grant.capture_epoch.capture_seq == 2


@pytest.mark.asyncio
async def test_cancelled_begin_records_committed_grant_for_exact_retry(
    capture_protocol_harness_factory,
    monkeypatch,
):
    harness = capture_protocol_harness_factory()
    request_id = uuid.uuid4()
    committed = asyncio.Event()
    release = asyncio.Event()
    original = CaptureCoordinatorV1._activate_protocol_capture_v1

    async def pause_after_commit(self, **kwargs):
        result = await original(self, **kwargs)
        committed.set()
        await release.wait()
        return result

    monkeypatch.setattr(
        CaptureCoordinatorV1,
        "_activate_protocol_capture_v1",
        pause_after_commit,
    )
    begin_task = asyncio.create_task(
        harness.begin(request_id=request_id, control_seq=1)
    )
    await asyncio.wait_for(committed.wait(), timeout=1)
    begin_task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await begin_task

    replay = await harness.begin(request_id=request_id, control_seq=1)
    assert replay.capture_epoch is harness.coordinator._capture_epoch
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.ARMED


@pytest.mark.asyncio
async def test_cancelled_seal_records_build_started_for_exact_retry(
    capture_protocol_harness_factory,
    monkeypatch,
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
    request_id = uuid.uuid4()
    committed = asyncio.Event()
    release = asyncio.Event()
    original = CaptureCoordinatorV1._execute_seal_attempt_v1

    async def pause_after_commit(self, capture_epoch):
        result = await original(self, capture_epoch)
        committed.set()
        await release.wait()
        return result

    monkeypatch.setattr(
        CaptureCoordinatorV1,
        "_execute_seal_attempt_v1",
        pause_after_commit,
    )
    seal_task = asyncio.create_task(
        harness.coordinator.seal_capture_protocol_v1(
            request_id=request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    )
    await asyncio.wait_for(committed.wait(), timeout=1)
    seal_task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await seal_task

    replay = await harness.coordinator.seal_capture_protocol_v1(
        request_id=request_id,
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    assert replay.outcome is SealOutcomeV1.BUILD_STARTED
    assert processor.calls == 1
    processor.release.set()


@pytest.mark.asyncio
async def test_cancelled_end_records_idle_result_for_exact_retry(
    capture_protocol_harness_factory,
    monkeypatch,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    request_id = uuid.uuid4()
    committed = asyncio.Event()
    release = asyncio.Event()
    original = CaptureCoordinatorV1.end_capture_v1

    async def pause_after_commit(self, *args, **kwargs):
        result = await original(self, *args, **kwargs)
        committed.set()
        await release.wait()
        return result

    monkeypatch.setattr(
        CaptureCoordinatorV1,
        "end_capture_v1",
        pause_after_commit,
    )
    end_task = asyncio.create_task(
        harness.coordinator.end_capture_protocol_v1(
            request_id=request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    )
    await asyncio.wait_for(committed.wait(), timeout=1)
    end_task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await end_task

    replay = await harness.coordinator.end_capture_protocol_v1(
        request_id=request_id,
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    assert replay.state is CaptureStateV1.IDLE
    assert harness.gate.is_open_v1() is True


@pytest.mark.asyncio
async def test_begin_requires_six_minutes_of_session_authority(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()

    with pytest.raises(CaptureProtocolErrorV1) as rejected:
        await harness.begin(remaining_seconds=359.999)

    assert (
        rejected.value.reason
        is CaptureProtocolReasonV1.SESSION_LIFETIME_INSUFFICIENT
    )
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.IDLE
    assert harness.gate.is_open_v1() is True


@pytest.mark.asyncio
async def test_first_frame_activates_capturing_and_same_hash_retry_is_exact(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()

    first = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )
    deadline = harness.coordinator._inactivity_deadline_monotonic_v1
    retry = await harness.upload(
        grant,
        frame_seq=1,
        encoded_frame=encoded,
    )

    assert first == retry
    assert first.state is CaptureStateV1.CAPTURING
    assert first.accepted_frame_count == 1
    assert first.total_accepted_bytes == len(encoded)
    assert harness.coordinator._inactivity_deadline_monotonic_v1 == deadline


@pytest.mark.asyncio
async def test_same_sequence_different_hash_conflicts_without_replacement(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    first = synthetic_jpeg_v1(color=(1, 2, 3))
    replacement = synthetic_jpeg_v1(color=(9, 8, 7))
    accepted = await harness.upload(
        grant,
        frame_seq=2,
        encoded_frame=first,
    )

    with pytest.raises(CaptureProtocolErrorV1) as conflict:
        await harness.upload(
            grant,
            frame_seq=2,
            encoded_frame=replacement,
        )

    assert (
        conflict.value.reason
        is CaptureProtocolReasonV1.FRAME_SEQUENCE_CONFLICT
    )
    status = await harness.coordinator.capture_public_status_v1(
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    assert status.accepted_frame_count == 1
    assert status.total_accepted_bytes == accepted.encoded_size


@pytest.mark.asyncio
async def test_duplicate_bytes_on_distinct_sequences_do_not_create_groups(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()

    for frame_seq in range(1, 4):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=encoded,
        )

    seal = await harness.coordinator.seal_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )

    assert seal.outcome is SealOutcomeV1.NEEDS_RECAPTURE
    assert seal.capture_state is CaptureStateV1.CAPTURING
    assert seal.accepted_frame_count == 3
    assert seal.independent_correlation_groups == 1
    assert seal.reason_codes == (
        SealReasonCodeV1.TOO_FEW_UNIQUE_FRAMES,
    )


@pytest.mark.asyncio
async def test_needs_recapture_sets_restart_only_when_all_slots_are_used(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    encoded = synthetic_jpeg_v1()

    for frame_seq in range(1, MAX_CAPTURE_FRAMES_V1 + 1):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=encoded,
        )

    seal = await harness.coordinator.seal_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )

    assert seal.outcome is SealOutcomeV1.NEEDS_RECAPTURE
    assert seal.remaining_frame_slots == 0
    assert seal.restart_required is True
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.CAPTURING


@pytest.mark.asyncio
async def test_eight_exact_two_mib_frames_reach_but_never_exceed_aggregate_bound(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()

    for frame_seq in range(1, MAX_CAPTURE_FRAMES_V1 + 1):
        encoded = _with_exact_metadata_size_v1(
            synthetic_jpeg_v1(color=(frame_seq, frame_seq + 1, frame_seq + 2)),
            MAX_ENCODED_FRAME_BYTES_V1,
        )
        result = await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=encoded,
        )

    assert result.accepted_frame_count == MAX_CAPTURE_FRAMES_V1
    assert result.total_accepted_bytes == MAX_CAPTURE_ENCODED_BYTES_V1
    assert harness.coordinator._accepted_frame_bytes_v1 == (
        MAX_CAPTURE_ENCODED_BYTES_V1
    )


@pytest.mark.asyncio
async def test_production_seal_fails_closed_without_publishing_fake_ready(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    grant = await harness.begin()
    for frame_seq, color in enumerate(
        ((1, 2, 3), (4, 5, 6), (7, 8, 9)),
        start=1,
    ):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(color=color),
        )

    request_id = uuid.uuid4()
    with pytest.raises(CaptureProtocolErrorV1) as unavailable:
        await harness.coordinator.seal_capture_protocol_v1(
            request_id=request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert (
        unavailable.value.reason
        is CaptureProtocolReasonV1.PROCESSOR_NOT_READY
    )
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.CAPTURING

    with pytest.raises(CaptureProtocolErrorV1) as replay:
        await harness.coordinator.seal_capture_protocol_v1(
            request_id=request_id,
            control_seq=2,
            capture_id=grant.capture_epoch.capture_id,
            capture_capability=grant.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )
    assert replay.value.reason is CaptureProtocolReasonV1.PROCESSOR_NOT_READY


@pytest.mark.asyncio
async def test_constructor_injected_mock_exercises_atomic_build_and_ready(
    capture_protocol_harness_factory,
):
    processor = BlockingMockProcessorV1()
    harness = capture_protocol_harness_factory(processor=processor)
    grant = await harness.begin()
    for frame_seq, color in enumerate(
        ((10, 20, 30), (40, 50, 60), (70, 80, 90)),
        start=1,
    ):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(color=color),
        )

    request_id = uuid.uuid4()
    seal = await harness.coordinator.seal_capture_protocol_v1(
        request_id=request_id,
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    replay = await harness.coordinator.seal_capture_protocol_v1(
        request_id=request_id,
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    await asyncio.wait_for(processor.started.wait(), timeout=1)

    assert seal == replay
    assert seal.outcome is SealOutcomeV1.BUILD_STARTED
    assert processor.calls == 1
    assert harness.coordinator.snapshot_v1().state is (
        CaptureStateV1.BUILDING_ASSERTIONS
    )
    with pytest.raises(CaptureProtocolErrorV1):
        await harness.upload(
            grant,
            frame_seq=4,
            encoded_frame=synthetic_jpeg_v1(color=(1, 1, 1)),
        )

    processor.release.set()
    for _ in range(100):
        if harness.coordinator.snapshot_v1().state is CaptureStateV1.READY:
            break
        await asyncio.sleep(0.001)
    assert harness.coordinator.snapshot_v1().state is CaptureStateV1.READY


@pytest.mark.asyncio
async def test_end_interrupts_build_and_clears_every_capture_private_record(
    capture_protocol_harness_factory,
):
    processor = BlockingMockProcessorV1()
    harness = capture_protocol_harness_factory(processor=processor)
    grant = await harness.begin()
    for frame_seq, color in enumerate(
        ((2, 3, 4), (5, 6, 7), (8, 9, 10)),
        start=1,
    ):
        await harness.upload(
            grant,
            frame_seq=frame_seq,
            encoded_frame=synthetic_jpeg_v1(color=color),
        )
    await harness.coordinator.seal_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    await asyncio.wait_for(processor.started.wait(), timeout=1)

    end_request_id = uuid.uuid4()
    result = await harness.coordinator.end_capture_protocol_v1(
        request_id=end_request_id,
        control_seq=3,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    replay = await harness.coordinator.end_capture_protocol_v1(
        request_id=end_request_id,
        control_seq=3,
        capture_id=grant.capture_epoch.capture_id,
        capture_capability=grant.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )

    assert result == replay
    assert result.state is CaptureStateV1.IDLE
    assert harness.gate.is_open_v1() is True
    assert harness.coordinator._private_capture_is_clear_locked_v1()
    assert harness.coordinator._frame_records_v1 == {}
    assert harness.coordinator._unique_frame_digests_v1 == set()
    assert harness.coordinator._active_capture_capability_v1 is None
    assert harness.coordinator._inactivity_task_v1 is None
    assert harness.coordinator._processor_task_v1 is None

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
async def test_capture_capability_is_bound_to_capture_session_owner_and_epoch(
    capture_protocol_harness_factory,
):
    first = capture_protocol_harness_factory()
    second = capture_protocol_harness_factory(
        session_id="cs1_second-session",
        owner_subject="second-owner",
    )
    first_grant = await first.begin()
    second_grant = await second.begin()

    attempts = (
        {
            "capture_id": first_grant.capture_epoch.capture_id,
            "capture_capability": "ccp1_" + "A" * 43,
            "session_id": first.session_id,
            "owner_issuer": first.owner_issuer,
            "owner_subject": first.owner_subject,
        },
        {
            "capture_id": first_grant.capture_epoch.capture_id,
            "capture_capability": second_grant.capture_capability,
            "session_id": first.session_id,
            "owner_issuer": first.owner_issuer,
            "owner_subject": first.owner_subject,
        },
        {
            "capture_id": first_grant.capture_epoch.capture_id,
            "capture_capability": first_grant.capture_capability,
            "session_id": first.session_id,
            "owner_issuer": first.owner_issuer,
            "owner_subject": "wrong-owner",
        },
    )
    for attempt in attempts:
        with pytest.raises(CaptureProtocolErrorV1) as denied:
            await first.coordinator.capture_public_status_v1(**attempt)
        assert (
            denied.value.reason
            is CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
        )


@pytest.mark.asyncio
async def test_ended_capture_capability_cannot_authorize_later_capture(
    capture_protocol_harness_factory,
):
    harness = capture_protocol_harness_factory()
    first = await harness.begin()
    await harness.coordinator.end_capture_protocol_v1(
        request_id=uuid.uuid4(),
        control_seq=2,
        capture_id=first.capture_epoch.capture_id,
        capture_capability=first.capture_capability,
        session_id=harness.session_id,
        owner_issuer=harness.owner_issuer,
        owner_subject=harness.owner_subject,
    )
    second = await harness.begin(control_seq=3)

    with pytest.raises(CaptureProtocolErrorV1) as stale:
        await harness.coordinator.capture_public_status_v1(
            capture_id=second.capture_epoch.capture_id,
            capture_capability=first.capture_capability,
            session_id=harness.session_id,
            owner_issuer=harness.owner_issuer,
            owner_subject=harness.owner_subject,
        )

    assert stale.value.reason is CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED

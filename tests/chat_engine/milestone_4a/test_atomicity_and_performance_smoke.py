from __future__ import annotations

import asyncio
import threading
import time

import pytest

from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.state import (
    CaptureTransitionPointV1,
)
from chat_engine.security.session_work_controller import (
    ControllerTransitionPointV1,
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1


def test_registration_started_before_mode_close_is_retired_not_laundered(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    registration_locked = threading.Event()
    release_registration = threading.Event()
    first_registration = True

    def controller_hook(point: ControllerTransitionPointV1) -> None:
        nonlocal first_registration
        if (
            point is ControllerTransitionPointV1.REGISTRATION_LOCKED
            and first_registration
        ):
            first_registration = False
            registration_locked.set()
            release_registration.wait(timeout=1)

    harness.controller._set_transition_hook_for_test_v1(controller_hook)
    registered = []
    begin_outcome = []

    def register_input() -> None:
        registered.append(
            harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
        )

    def begin_capture() -> None:
        begin_outcome.append(asyncio.run(harness.coordinator.begin_capture_v1()))

    registration_thread = threading.Thread(target=register_input)
    begin_thread = threading.Thread(target=begin_capture)
    registration_thread.start()
    assert registration_locked.wait(timeout=1)
    begin_thread.start()
    release_registration.set()
    registration_thread.join(timeout=1)
    assert registered

    for _ in range(100):
        if registered[0].cancellation.is_cancelled:
            break
        time.sleep(0.005)
    assert registered[0].cancellation.is_cancelled
    assert harness.runtime.release_work_v1(registered[0])
    begin_thread.join(timeout=1)

    assert not begin_thread.is_alive()
    assert isinstance(begin_outcome[0], CaptureEpochV1)
    assert registered[0].fence.session_epoch.generation == 1
    assert begin_outcome[0].session_epoch.generation == 2


@pytest.mark.asyncio
async def test_registration_after_mode_close_is_dropped_without_queueing(
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
    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await asyncio.wait_for(entered.wait(), timeout=1)

    with pytest.raises(WorkAdmissionDeniedV1):
        harness.runtime.register_root_work_v1(WorkOperationKindV1.GENERIC_ASYNC)
    release.set()
    outcome = await asyncio.wait_for(begin, timeout=1)

    assert isinstance(outcome, CaptureEpochV1)
    assert harness.controller.snapshot_v1().unreleased_work_by_generation == ()


@pytest.mark.asyncio
async def test_capture_transition_performance_smoke(
    capture_harness_factory,
    record_property,
):
    harness = capture_harness_factory()

    started = time.perf_counter()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    begin_empty_seconds = time.perf_counter() - started

    started = time.perf_counter()
    await harness.coordinator.end_capture_v1(capture_epoch)
    end_empty_seconds = time.perf_counter() - started

    representative = harness.runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )

    async def release_representative() -> None:
        assert await representative.cancellation.wait_async(1)
        await asyncio.sleep(0.005)
        harness.runtime.release_work_v1(representative)

    release_task = asyncio.create_task(release_representative())
    started = time.perf_counter()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    begin_representative_seconds = time.perf_counter() - started
    await release_task
    await harness.coordinator.end_capture_v1(capture_epoch)

    cycle_started = time.perf_counter()
    for _ in range(5):
        epoch = await harness.coordinator.begin_capture_v1()
        await harness.coordinator.end_capture_v1(epoch)
    repeated_cycles_seconds = time.perf_counter() - cycle_started

    check_started = time.perf_counter()
    for _ in range(50_000):
        assert harness.gate.is_open_v1()
    gate_check_seconds = time.perf_counter() - check_started
    gate_check_nanoseconds = gate_check_seconds * 1_000_000_000 / 50_000

    measurements = {
        "begin_empty_seconds": begin_empty_seconds,
        "begin_representative_seconds": begin_representative_seconds,
        "end_empty_seconds": end_empty_seconds,
        "five_cycles_seconds": repeated_cycles_seconds,
        "gate_check_nanoseconds": gate_check_nanoseconds,
    }
    for name, value in measurements.items():
        record_property(name, value)
        assert value >= 0
    print(f"MILESTONE_4A_PERFORMANCE_SMOKE {measurements}")

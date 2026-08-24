from __future__ import annotations

import time

import pytest

from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)


def _average_microseconds(start_ns: int, count: int) -> float:
    return (time.perf_counter_ns() - start_ns) / count / 1_000


def test_production_fence_adapter_performance_smoke():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )
    samples: dict[str, float] = {}

    count = 1_000
    started = time.perf_counter_ns()
    for _ in range(count):
        work = runtime.register_child_work_v1(
            parent,
            WorkOperationKindV1.PERCEPTION_INFERENCE,
        )
        assert runtime.validate_work_v1(
            work,
            WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
        )
        assert runtime.release_work_v1(work)
    samples["perception_schedule_us"] = _average_microseconds(
        started,
        count,
    )

    count = 20_000
    started = time.perf_counter_ns()
    for _ in range(count):
        assert runtime.validate_work_v1(
            parent,
            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
        )
    samples["llm_chunk_validate_us"] = _average_microseconds(
        started,
        count,
    )

    count = 1_000
    started = time.perf_counter_ns()
    for _ in range(count):
        work = runtime.register_child_work_v1(
            parent,
            WorkOperationKindV1.TOOL_EXECUTION,
        )
        assert runtime.validate_work_v1(
            work,
            WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
        )
        assert runtime.release_work_v1(work)
    samples["tool_register_validate_us"] = _average_microseconds(
        started,
        count,
    )

    tts_work = runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.TTS_SYNTHESIS,
    )
    count = 10_000
    started = time.perf_counter_ns()
    for _ in range(count):
        assert runtime.perform_if_live_v1(
            tts_work,
            WorkValidationBoundaryV1.BEFORE_EGRESS,
            lambda: None,
        )
    samples["tts_queue_egress_us"] = _average_microseconds(
        started,
        count,
    )
    assert runtime.release_work_v1(tts_work)

    for kind, name in (
        (WorkOperationKindV1.WS_EGRESS, "ws_egress_us"),
        (WorkOperationKindV1.RTC_EGRESS, "rtc_egress_us"),
    ):
        work = runtime.register_child_work_v1(parent, kind)
        item = WorkBoundItemV1(payload=None, registered_work=work)
        count = 10_000
        started = time.perf_counter_ns()
        for _ in range(count):
            assert runtime.perform_item_egress_if_live_v1(
                item,
                None,
                lambda: None,
            )
        samples[name] = _average_microseconds(started, count)
        assert item.release_once_v1(runtime)

    print(f"M3B_PERF_SMOKE {samples}")
    # Diagnostic guardrails only, intentionally far above expected local
    # measurements and not normative Milestone 10 thresholds.
    assert all(value < 2_000 for value in samples.values())
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_awaited_ws_egress_performance_smoke():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    work = runtime.register_root_work_v1(
        WorkOperationKindV1.WS_EGRESS
    )
    item = WorkBoundItemV1(payload=None, registered_work=work)

    async def immediate_send() -> None:
        return

    count = 500
    started = time.perf_counter_ns()
    for _ in range(count):
        assert await runtime.perform_item_egress_async_if_live_v1(
            item,
            None,
            immediate_send,
            lambda: None,
        )
    average_us = _average_microseconds(started, count)

    print(f"M3B_ASYNC_WS_EGRESS_US {average_us:.3f}")
    assert average_us < 5_000
    assert item.release_once_v1(runtime)
    assert await controller.shutdown_async()

from __future__ import annotations

import json
import time

from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1


def test_work_controller_performance_smoke():
    controller = SessionWorkControllerV1()
    item_count = 1000
    deadline = time.monotonic() + 60.0

    started = time.perf_counter()
    work_items = [
        controller.register_work_v1(
            WorkOperationKindV1.GENERIC_ASYNC,
            deadline,
        )
        for _ in range(item_count)
    ]
    registration_seconds = time.perf_counter() - started

    started = time.perf_counter()
    validation_results = [
        controller.validate_before_state_mutation_v1(work.fence) for work in work_items
    ]
    validation_seconds = time.perf_counter() - started

    started = time.perf_counter()
    retirement = controller.retire_generation_v1()
    retirement_seconds = time.perf_counter() - started

    started = time.perf_counter()
    release_results = [controller.release_work_v1(work.lease) for work in work_items]
    release_seconds = time.perf_counter() - started

    observations = {
        "items": item_count,
        "registration_total_seconds": round(registration_seconds, 6),
        "registration_microseconds_per_item": round(
            registration_seconds * 1_000_000 / item_count,
            2,
        ),
        "validation_total_seconds": round(validation_seconds, 6),
        "validation_microseconds_per_item": round(
            validation_seconds * 1_000_000 / item_count,
            2,
        ),
        "retirement_total_seconds": round(retirement_seconds, 6),
        "retirement_microseconds_per_item": round(
            retirement_seconds * 1_000_000 / item_count,
            2,
        ),
        "release_total_seconds": round(release_seconds, 6),
        "release_microseconds_per_item": round(
            release_seconds * 1_000_000 / item_count,
            2,
        ),
    }
    print("WORK_FENCE_PERF_SMOKE " + json.dumps(observations))

    assert all(validation_results)
    assert all(release_results)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert registration_seconds > 0
    assert validation_seconds > 0
    assert retirement_seconds > 0
    assert release_seconds > 0
    assert controller.shutdown()

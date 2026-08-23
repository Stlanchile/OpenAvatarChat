from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import numpy as np
from loguru import logger

from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)
from handlers.agent.perception.perception_handler import (
    PerceptionContext,
    PerceptionHandler,
)
from handlers.agent.perception.vision_model_interface import (
    AsyncPerceptionManager,
    VisionModelInterface,
)


class _BlockingVisionModel(VisionModelInterface):
    def __init__(self, result) -> None:
        self.result = result
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def generate_perception(self, frames, round_id=0):
        del frames, round_id
        self.calls += 1
        self.started.set()
        self.release.wait(timeout=5)
        return self.result

    def detect_events(self, frame, previous_frame=None):
        del frame, previous_frame
        return []


class _RaisingVisionModel(VisionModelInterface):
    def generate_perception(self, frames, round_id=0):
        del frames, round_id
        raise RuntimeError("SYNTHETIC_PERCEPTION_CANARY")

    def detect_events(self, frame, previous_frame=None):
        del frame, previous_frame
        return []


def _work_pair():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    child = runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.PERCEPTION_INFERENCE,
    )
    item = WorkBoundItemV1(payload=None, registered_work=child)
    return controller, runtime, parent, item


def _wait_for_manager(manager: AsyncPerceptionManager) -> None:
    deadline = time.monotonic() + 5
    while manager.current_pending_count and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.current_pending_count == 0


def test_retire_before_perception_submission_denies_executor_work():
    model = _BlockingVisionModel(object())
    manager = AsyncPerceptionManager(model, max_workers=1)
    controller, runtime, parent, item = _work_pair()
    retirement = controller.retire_generation_v1()

    assert not manager.submit_task(
        1,
        [np.zeros((2, 2, 3), dtype=np.uint8)],
        work_runtime_v1=runtime,
        work_item_v1=item,
    )
    assert model.calls == 0
    assert item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    manager.shutdown(wait=False)
    assert controller.shutdown()


def test_late_perception_callback_drops_result_releases_and_redacts_log():
    canary = "STALE_PERCEPTION_SEMANTIC_CANARY"
    model = _BlockingVisionModel(canary)
    callbacks: list[object] = []
    manager = AsyncPerceptionManager(
        model,
        max_workers=1,
        on_result_callback=lambda _round, result, _item: callbacks.append(
            result
        ),
    )
    controller, runtime, parent, item = _work_pair()
    captured: list[str] = []
    sink = logger.add(
        lambda message: captured.append(str(message)),
        format="{message} {extra}",
    )
    try:
        assert manager.submit_task(
            1,
            [np.zeros((2, 2, 3), dtype=np.uint8)],
            work_runtime_v1=runtime,
            work_item_v1=item,
        )
        assert model.started.wait(timeout=2)
        retirement = controller.retire_generation_v1()
        model.release.set()
        _wait_for_manager(manager)
    finally:
        logger.remove(sink)

    assert callbacks == []
    assert manager.total_completed == 0
    assert canary not in "".join(captured)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    manager.shutdown(wait=False)
    assert controller.shutdown()


def test_perception_exception_path_releases_work_exactly_once():
    manager = AsyncPerceptionManager(
        _RaisingVisionModel(),
        max_workers=1,
    )
    controller, runtime, parent, item = _work_pair()

    assert manager.submit_task(
        1,
        [np.zeros((2, 2, 3), dtype=np.uint8)],
        work_runtime_v1=runtime,
        work_item_v1=item,
    )
    _wait_for_manager(manager)

    assert manager.total_completed == 1
    assert manager.last_sent_round == 1
    assert not item.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    manager.shutdown(wait=False)
    assert controller.shutdown()


def test_perception_disabled_mode_preserves_legacy_async_result():
    result = object()
    model = _BlockingVisionModel(result)
    model.release.set()
    callbacks: list[object] = []
    manager = AsyncPerceptionManager(
        model,
        max_workers=1,
        on_result_callback=lambda _round, value, _item: callbacks.append(
            value
        ),
    )

    assert manager.submit_task(
        1,
        [np.zeros((2, 2, 3), dtype=np.uint8)],
    )
    _wait_for_manager(manager)

    assert callbacks == [result]
    assert manager.total_completed == 1
    assert manager.last_sent_round == 1
    manager.shutdown(wait=False)


def test_perception_callback_and_retirement_are_serialized():
    result = object()
    model = _BlockingVisionModel(result)
    callback_entered = threading.Event()
    callback_release = threading.Event()
    callbacks: list[object] = []

    def callback(_round, value, _item) -> None:
        callback_entered.set()
        callback_release.wait(timeout=5)
        callbacks.append(value)

    manager = AsyncPerceptionManager(
        model,
        max_workers=1,
        on_result_callback=callback,
    )
    controller, runtime, parent, item = _work_pair()
    assert manager.submit_task(
        1,
        [np.zeros((2, 2, 3), dtype=np.uint8)],
        work_runtime_v1=runtime,
        work_item_v1=item,
    )
    assert model.started.wait(timeout=2)
    model.release.set()
    assert callback_entered.wait(timeout=2)

    retirement_holder = []
    retirement_thread = threading.Thread(
        target=lambda: retirement_holder.append(
            controller.retire_generation_v1()
        )
    )
    retirement_thread.start()
    time.sleep(0.05)
    assert retirement_thread.is_alive()
    callback_release.set()
    retirement_thread.join(timeout=2)
    assert not retirement_thread.is_alive()
    _wait_for_manager(manager)

    assert callbacks == [result]
    assert runtime.release_work_v1(parent)
    retirement = retirement_holder[0]
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    manager.shutdown(wait=False)
    assert controller.shutdown()


def test_perception_heartbeat_releases_and_cannot_mutate_after_retire():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    context = PerceptionContext("session")
    context.work_runtime_v1 = runtime
    context.last_frame_time = time.time() - 60
    context.frame_stall_threshold = 0
    handler = PerceptionHandler()
    handler.start_context(SimpleNamespace(), context)

    retirement = controller.retire_generation_v1()

    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    assert not context.frame_stall_warned
    handler.destroy_context(context)
    assert controller.shutdown()

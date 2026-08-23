from __future__ import annotations

import asyncio
import queue
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from chat_engine.chat_engine import ChatEngine
from chat_engine.core.chat_session import ChatSession
from chat_engine.core.signal_manager import SignalManager
from chat_engine.core.stream_manager import ChatDataSubmitter
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)
from service.service_security.certificate_session_control import (
    CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
    _retire_application_session_v1,
)


@pytest.mark.parametrize("retire_after", range(5))
def test_llm_tool_llm_tts_egress_chain_cannot_cross_retirement(
    retire_after: int,
):
    kinds = [
        WorkOperationKindV1.CHAT_AGENT_LLM,
        WorkOperationKindV1.TOOL_EXECUTION,
        WorkOperationKindV1.CHAT_AGENT_LLM,
        WorkOperationKindV1.TTS_SYNTHESIS,
        WorkOperationKindV1.WS_EGRESS,
        WorkOperationKindV1.RTC_EGRESS,
    ]
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    works = [runtime.register_root_work_v1(kinds[0])]
    for kind in kinds[1 : retire_after + 1]:
        works.append(
            runtime.register_child_work_v1(works[-1], kind)
        )

    retirement = controller.retire_generation_v1()
    with pytest.raises(WorkAdmissionDeniedV1):
        runtime.register_child_work_v1(
            works[-1],
            kinds[retire_after + 1],
        )

    for work in reversed(works):
        assert runtime.release_work_v1(work)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    current = runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )
    assert current.fence.session_epoch == retirement.new_epoch
    assert runtime.release_work_v1(current)
    assert controller.shutdown()


def test_stale_active_ingress_scope_cannot_register_new_current_root():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    submitter = ChatDataSubmitter(work_runtime_v1=runtime)
    stale = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    retirement = controller.retire_generation_v1()

    with runtime.activate_work_v1(stale):
        assert submitter.submit_ingress_v1(None) is None

    snapshot = controller.snapshot_v1()
    assert snapshot.unreleased_work_by_generation == ((1, 1),)
    assert runtime.release_work_v1(stale)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_control_plane_lifecycle_bridge_is_awaited():
    app = FastAPI()
    calls: list[str] = []

    class _Lifecycle:
        async def retire_secure_session_v1(self, session_id: str) -> None:
            calls.append(f"start:{session_id}")
            await asyncio.sleep(0)
            calls.append(f"done:{session_id}")

    setattr(
        app.state,
        CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
        _Lifecycle(),
    )

    await _retire_application_session_v1(app, "opaque-session")

    assert calls == [
        "start:opaque-session",
        "done:opaque-session",
    ]


@pytest.mark.asyncio
async def test_control_plane_missing_lifecycle_bridge_fails_closed():
    app = FastAPI()

    with pytest.raises(
        RuntimeError,
        match="secure session lifecycle unavailable",
    ):
        await _retire_application_session_v1(
            app,
            "opaque-session",
        )


@pytest.mark.asyncio
async def test_chat_engine_retirement_orders_work_before_transport():
    engine = ChatEngine()
    order: list[str] = []

    async def stop_session(session_id: str) -> None:
        order.append(f"work:{session_id}")

    async def teardown(session_id: str) -> None:
        order.append(f"transport:{session_id}")

    engine.stop_session_async = stop_session
    engine._teardown_session_transports_v1 = teardown

    await engine.retire_secure_session_v1("opaque-session")

    assert order == [
        "work:opaque-session",
        "transport:opaque-session",
    ]


@pytest.mark.asyncio
async def test_combined_shutdown_cancels_all_subsystem_work_and_waits_release():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    kinds = [
        WorkOperationKindV1.PERCEPTION_INFERENCE,
        WorkOperationKindV1.CHAT_AGENT_LLM,
        WorkOperationKindV1.TOOL_EXECUTION,
        WorkOperationKindV1.TTS_SYNTHESIS,
        WorkOperationKindV1.RTC_EGRESS,
    ]
    works = [runtime.register_root_work_v1(kind) for kind in kinds]
    released: list[WorkOperationKindV1] = []

    def wait_and_release(work) -> None:
        assert work.cancellation.wait(timeout=3)
        released.append(work.fence.operation_kind)
        runtime.release_work_v1(work)

    threads = [
        threading.Thread(target=wait_and_release, args=(work,))
        for work in works
    ]
    for thread in threads:
        thread.start()

    ws_work = runtime.register_root_work_v1(
        WorkOperationKindV1.WS_EGRESS
    )
    ws_started = asyncio.Event()

    async def blocked_send() -> None:
        ws_started.set()
        await asyncio.Future()

    async def own_ws_send() -> bool:
        try:
            return await controller.perform_if_live_async_v1(
                ws_work.fence,
                WorkValidationBoundaryV1.BEFORE_EGRESS,
                blocked_send,
            )
        finally:
            runtime.release_work_v1(ws_work)

    ws_task = asyncio.create_task(own_ws_send())
    await ws_started.wait()
    started = time.monotonic()
    assert await controller.shutdown_async()
    elapsed = time.monotonic() - started

    assert not await ws_task
    for thread in threads:
        thread.join(timeout=2)
        assert not thread.is_alive()
    assert set(released) == set(kinds)
    assert elapsed < 3.0


def test_chat_session_shutdown_hook_drains_queued_work_before_wait():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    handler_work = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    delegate_work = runtime.register_root_work_v1(
        WorkOperationKindV1.WS_EGRESS
    )
    signal_work = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    handler_item = WorkBoundItemV1(
        payload=None,
        registered_work=handler_work,
    )
    delegate_item = WorkBoundItemV1(
        payload=None,
        registered_work=delegate_work,
    )
    signal_item = WorkBoundItemV1(
        payload=None,
        registered_work=signal_work,
    )
    handler_queue: queue.Queue = queue.Queue()
    handler_queue.put(SimpleNamespace(work_item_v1=handler_item))

    class _Delegate:
        def drain_application_output_v1(self) -> None:
            delegate_item.release_once_v1(runtime)

    session = object.__new__(ChatSession)
    session._work_runtime_v1 = runtime
    session.session_context = SimpleNamespace(
        shared_states=SimpleNamespace(active=True)
    )
    session.handlers = {
        "handler": SimpleNamespace(
            env=SimpleNamespace(
                input_queue=handler_queue,
                handler=SimpleNamespace(),
                context=SimpleNamespace(
                    client_session_delegate=_Delegate()
                ),
            )
        )
    }
    session.signal_manager = SignalManager(
        SimpleNamespace(),
        work_runtime_v1=runtime,
    )
    session.signal_manager.signal_queue.put(signal_item)

    assert controller.shutdown(
        session._prepare_retired_work_cleanup_v1
    )

    assert not session.session_context.shared_states.active
    assert handler_queue.empty()
    assert session.signal_manager.signal_queue.empty()
    assert not handler_item.release_once_v1(runtime)
    assert not delegate_item.release_once_v1(runtime)
    assert not signal_item.release_once_v1(runtime)

from __future__ import annotations

import asyncio
import queue
import threading
import time
from types import SimpleNamespace

import pytest

from chat_engine.chat_engine import ChatEngine
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.chat_session import ChatSession
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from chat_engine.data_models.session_info_data import SessionInfoData
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
    WorkControllerFailureReasonV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)


class SyntheticAdmissionV1:
    """Non-secret stand-in for a consumed Milestone 1 admission."""


def _register(controller):
    return controller.register_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC,
        time.monotonic() + 30.0,
    )


def _secure_session(
    session_id: str,
    *,
    work_controller: SessionWorkControllerV1 | None = None,
) -> ChatSession:
    context = SessionContext(
        SessionInfoData(session_id=session_id, timestamp_base=16_000),
        session_admission=SyntheticAdmissionV1(),
    )
    return ChatSession(
        context,
        ChatEngineConfigModel(),
        _work_controller_v1=work_controller,
    )


def test_clean_controller_shutdown_is_bounded_and_idempotent():
    controller = SessionWorkControllerV1()

    assert controller.shutdown()
    snapshot = controller.snapshot_v1()
    assert snapshot.shutdown_started
    assert snapshot.shutdown_complete
    assert snapshot.destroyed
    assert not snapshot.active
    assert not snapshot.admission_open
    assert controller.shutdown()


def test_shutdown_cancels_cooperative_work_and_waits_for_release():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    work = _register(controller)
    released = threading.Event()

    def cooperative_worker():
        assert work.cancellation.wait(1.0)
        assert controller.release_work_v1(work.lease)
        released.set()

    worker = threading.Thread(target=cooperative_worker)
    worker.start()

    assert controller.shutdown()
    worker.join(timeout=1.0)
    assert released.is_set()
    assert not worker.is_alive()
    assert not controller.validate_after_callback_v1(work.fence)


def test_shutdown_waits_for_delayed_non_cancellable_work():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    work = _register(controller)

    def delayed_worker():
        assert work.cancellation.wait(1.0)
        time.sleep(0.03)
        assert controller.release_work_v1(work.lease)

    worker = threading.Thread(target=delayed_worker)
    worker.start()
    started = time.monotonic()
    result = controller.shutdown()
    elapsed = time.monotonic() - started
    worker.join(timeout=1.0)

    assert result
    assert elapsed >= 0.02
    assert elapsed < 0.5
    assert not worker.is_alive()


def test_shutdown_with_forgotten_token_times_out_and_stays_failed():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.05
    )
    work = _register(controller)
    started = time.monotonic()

    assert not controller.shutdown()
    elapsed = time.monotonic() - started

    assert 0.04 <= elapsed < 0.5
    assert work.cancellation.is_cancelled
    assert (
        controller.failure_reason_v1() is WorkControllerFailureReasonV1.CLEANUP_TIMEOUT
    )
    assert not controller.shutdown()
    assert not controller.release_work_v1(work.lease)


@pytest.mark.asyncio
async def test_async_shutdown_uses_one_deadline_for_barrier_and_cleanup():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.1
    )
    awaited_work = _register(controller)
    forgotten_work = _register(controller)
    entered = asyncio.Event()

    async def delayed_cancel() -> None:
        entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await asyncio.sleep(0.06)

    action_task = asyncio.create_task(
        controller.perform_if_live_async_v1(
            awaited_work.fence,
            WorkValidationBoundaryV1.BEFORE_EGRESS,
            delayed_cancel,
            lambda: None,
        )
    )
    await entered.wait()
    started = time.monotonic()

    assert not await controller.shutdown_async()
    elapsed = time.monotonic() - started

    assert not await action_task
    assert 0.08 <= elapsed < 0.14
    assert forgotten_work.cancellation.is_cancelled
    assert (
        controller.failure_reason_v1()
        is WorkControllerFailureReasonV1.CLEANUP_TIMEOUT
    )


def test_no_admission_after_shutdown_begins():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    work = _register(controller)
    result = []

    shutdown_thread = threading.Thread(
        target=lambda: result.append(controller.shutdown())
    )
    shutdown_thread.start()
    assert work.cancellation.wait(1.0)

    with pytest.raises(WorkAdmissionDeniedV1):
        _register(controller)
    assert controller.release_work_v1(work.lease)
    shutdown_thread.join(timeout=1.0)
    assert result == [True]


def test_concurrent_shutdown_calls_return_same_result():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    work = _register(controller)
    results: list[bool] = []
    results_lock = threading.Lock()

    def shutdown():
        result = controller.shutdown()
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=shutdown) for _ in range(8)]
    for thread in threads:
        thread.start()
    assert work.cancellation.wait(1.0)
    assert controller.release_work_v1(work.lease)
    for thread in threads:
        thread.join(timeout=1.0)

    assert all(not thread.is_alive() for thread in threads)
    assert results == [True] * 8


@pytest.mark.asyncio
async def test_async_shutdown_does_not_block_event_loop():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    work = _register(controller)
    shutdown_task = asyncio.create_task(controller.shutdown_async())

    assert await work.cancellation.wait_async(max_wait_seconds=1.0)
    await asyncio.sleep(0)
    assert controller.release_work_v1(work.lease)
    assert await shutdown_task


@pytest.mark.asyncio
async def test_cancelled_async_shutdown_owner_fails_closed_and_unwedges():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=1.0
    )
    work = _register(controller)
    shutdown_task = asyncio.create_task(controller.shutdown_async())

    assert await work.cancellation.wait_async(max_wait_seconds=1.0)
    shutdown_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await shutdown_task

    snapshot = controller.snapshot_v1()
    assert snapshot.shutdown_started
    assert snapshot.shutdown_complete
    assert snapshot.destroyed
    assert snapshot.failed
    assert (
        snapshot.failure_reason
        is WorkControllerFailureReasonV1.INTERNAL_AUTHORITY_FAILURE
    )
    assert not controller.shutdown()
    assert not await asyncio.wait_for(controller.shutdown_async(), timeout=0.2)
    assert not controller.release_work_v1(work.lease)


def test_secure_session_owns_controller_while_legacy_session_does_not():
    secure = _secure_session("secure-controller-owner")
    legacy = ChatSession(
        SessionContext(
            SessionInfoData(
                session_id="legacy-no-controller",
                timestamp_base=16_000,
            )
        ),
        ChatEngineConfigModel(),
    )
    try:
        assert secure._work_controller_v1 is not None
        assert secure._work_controller_v1.current_epoch_v1().generation == 1
        assert legacy._work_controller_v1 is None
    finally:
        secure.stop()
        legacy.stop()


def test_runtime_session_replacement_gets_new_instance_authority():
    first = _secure_session("same-transport-session-id")
    first_instance = first._work_controller_v1.current_epoch_v1().session_instance_id
    first.stop()

    second = _secure_session("same-transport-session-id")
    try:
        second_instance = (
            second._work_controller_v1.current_epoch_v1().session_instance_id
        )
        assert second_instance != first_instance
    finally:
        second.stop()


def test_one_controller_cannot_be_attached_to_two_secure_sessions():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.2
    )
    first = _secure_session(
        "first-controller-owner",
        work_controller=controller,
    )
    try:
        with pytest.raises(
            RuntimeError,
            match="secure work controller unavailable",
        ):
            _secure_session(
                "second-controller-owner",
                work_controller=controller,
            )
        assert controller.is_usable_v1()
    finally:
        first.stop()


@pytest.mark.asyncio
async def test_async_chat_session_stop_allows_cooperative_release():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.2
    )
    session = _secure_session(
        "async-cooperative-session-stop",
        work_controller=controller,
    )
    work = _register(controller)

    async def cooperative_release():
        assert await work.cancellation.wait_async(max_wait_seconds=1.0)
        assert controller.release_work_v1(work.lease)

    worker = asyncio.create_task(cooperative_release())
    await session.stop_async()
    await worker

    snapshot = controller.snapshot_v1()
    assert snapshot.destroyed
    assert not snapshot.failed
    assert snapshot.failure_reason is None


@pytest.mark.asyncio
async def test_concurrent_sync_and_async_session_stop_finalize_once():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    session = _secure_session(
        "single-flight-session-stop",
        work_controller=controller,
    )
    work = _register(controller)
    destroy_calls = 0
    signal_shutdown_calls = 0

    class SyntheticHandlerV1:
        def destroy_context(self, _context):
            nonlocal destroy_calls
            destroy_calls += 1

    session.handlers["synthetic"] = SimpleNamespace(
        pump_thread=None,
        env=SimpleNamespace(
            input_queue=queue.Queue(),
            handler=SyntheticHandlerV1(),
            context=object(),
        ),
    )
    original_signal_shutdown = session.signal_manager.shutdown

    def counted_signal_shutdown(timeout=None):
        nonlocal signal_shutdown_calls
        signal_shutdown_calls += 1
        return original_signal_shutdown(timeout=timeout)

    session.signal_manager.shutdown = counted_signal_shutdown
    async_stop = asyncio.create_task(session.stop_async())
    assert await work.cancellation.wait_async(max_wait_seconds=1.0)

    sync_stop = threading.Thread(target=session.stop)
    sync_stop.start()
    await asyncio.sleep(0)
    assert controller.release_work_v1(work.lease)
    await async_stop
    sync_stop.join(timeout=1.0)

    assert not sync_stop.is_alive()
    assert destroy_calls == 1
    assert signal_shutdown_calls == 1
    assert session._stop_complete_event_v1.is_set()


@pytest.mark.asyncio
async def test_sync_secure_session_stop_is_rejected_on_running_loop():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    session = _secure_session(
        "reject-blocking-loop-stop",
        work_controller=controller,
    )
    work = _register(controller)

    with pytest.raises(
        RuntimeError,
        match=r"requires await stop_async\(\)",
    ):
        session.stop()

    assert controller.validate_at_admission_v1(work.fence)
    assert controller.release_work_v1(work.lease)
    await session.stop_async()
    assert session._stop_complete_event_v1.is_set()


def test_chat_session_stop_runs_bounded_controller_cleanup():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.05
    )
    session = _secure_session(
        "secure-session-forgotten-work",
        work_controller=controller,
    )
    work = _register(controller)
    started = time.monotonic()

    session.stop()
    elapsed = time.monotonic() - started

    # SignalManager's pre-existing polling thread may add up to 0.5 seconds.
    assert 0.04 <= elapsed < 1.0
    assert work.cancellation.is_cancelled
    assert controller.snapshot_v1().destroyed
    assert (
        controller.failure_reason_v1() is WorkControllerFailureReasonV1.CLEANUP_TIMEOUT
    )


def test_engine_shutdown_stops_and_removes_secure_sessions():
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    session = engine._create_session(
        SessionInfoData(
            session_id="engine-owned-secure-session",
            timestamp_base=16_000,
        ),
        session_admission=SyntheticAdmissionV1(),
    )
    controller = session._work_controller_v1
    assert controller is not None

    engine.shutdown()

    assert "engine-owned-secure-session" not in engine.sessions
    assert controller.snapshot_v1().destroyed


@pytest.mark.asyncio
async def test_async_engine_shutdown_allows_session_cooperative_release():
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    session = engine._create_session(
        SessionInfoData(
            session_id="async-engine-secure-session",
            timestamp_base=16_000,
        ),
        session_admission=SyntheticAdmissionV1(),
    )
    controller = session._work_controller_v1
    assert controller is not None
    work = _register(controller)

    async def cooperative_release():
        assert await work.cancellation.wait_async(max_wait_seconds=1.0)
        assert controller.release_work_v1(work.lease)

    worker = asyncio.create_task(cooperative_release())
    await engine.shutdown_async()
    await worker

    assert "async-engine-secure-session" not in engine.sessions
    assert controller.snapshot_v1().destroyed
    assert controller.failure_reason_v1() is None


@pytest.mark.asyncio
async def test_engine_serializes_stop_and_same_id_replacement():
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    session_id = "serialized-engine-session"
    session = engine._create_session(
        SessionInfoData(
            session_id=session_id,
            timestamp_base=16_000,
        ),
        session_admission=SyntheticAdmissionV1(),
    )
    controller = session._work_controller_v1
    assert controller is not None
    work = _register(controller)
    async_stop = asyncio.create_task(engine.stop_session_async(session_id))
    assert await work.cancellation.wait_async(max_wait_seconds=1.0)

    sync_stop = threading.Thread(
        target=engine.stop_session,
        args=(session_id,),
    )
    sync_stop.start()
    await asyncio.sleep(0.02)
    assert sync_stop.is_alive()
    with pytest.raises(RuntimeError, match="already exists"):
        engine._create_session(
            SessionInfoData(
                session_id=session_id,
                timestamp_base=16_001,
            ),
            session_admission=SyntheticAdmissionV1(),
        )

    assert controller.release_work_v1(work.lease)
    await async_stop
    sync_stop.join(timeout=1.0)
    assert not sync_stop.is_alive()
    replacement = engine._create_session(
        SessionInfoData(
            session_id=session_id,
            timestamp_base=16_002,
        ),
        session_admission=SyntheticAdmissionV1(),
    )
    try:
        assert replacement is not session
        assert replacement._work_controller_v1 is not controller
    finally:
        await engine.stop_session_async(session_id)


@pytest.mark.asyncio
async def test_engine_shutdown_joins_existing_sync_session_stop():
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    session_id = "shutdown-joins-sync-stop"
    session = engine._create_session(
        SessionInfoData(
            session_id=session_id,
            timestamp_base=16_000,
        ),
        session_admission=SyntheticAdmissionV1(),
    )
    controller = session._work_controller_v1
    assert controller is not None
    work = _register(controller)
    manager_destroy_states: list[tuple[bool, bool]] = []

    def record_manager_destroy():
        manager_destroy_states.append(
            (
                session._stop_complete_event_v1.is_set(),
                session_id not in engine.sessions,
            )
        )

    engine.logic_manager.destroy = record_manager_destroy
    engine.handler_manager.destroy = record_manager_destroy
    stop_thread = threading.Thread(
        target=engine.stop_session,
        args=(session_id,),
    )
    stop_thread.start()
    assert await work.cancellation.wait_async(max_wait_seconds=1.0)

    shutdown_task = asyncio.create_task(engine.shutdown_async())
    await asyncio.sleep(0.02)
    assert not shutdown_task.done()
    assert manager_destroy_states == []

    assert controller.release_work_v1(work.lease)
    await shutdown_task
    stop_thread.join(timeout=1.0)

    assert not stop_thread.is_alive()
    assert manager_destroy_states == [(True, True), (True, True)]


@pytest.mark.asyncio
async def test_stuck_handler_is_quarantined_until_later_engine_reap():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.05
    )
    session_id = "quarantined-handler-session"
    session = _secure_session(
        session_id,
        work_controller=controller,
    )
    handler_entered = threading.Event()
    handler_release = threading.Event()
    context_destroyed = threading.Event()

    def blocking_handler() -> None:
        handler_entered.set()
        handler_release.wait()

    class SyntheticHandlerV1:
        @staticmethod
        def destroy_context(_context) -> None:
            context_destroyed.set()

    pump_thread = threading.Thread(target=blocking_handler)
    pump_thread.start()
    assert handler_entered.wait(timeout=1.0)
    session.handlers["blocking"] = SimpleNamespace(
        pump_thread=pump_thread,
        env=SimpleNamespace(
            input_queue=queue.Queue(),
            handler=SyntheticHandlerV1(),
            context=object(),
        ),
    )

    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    engine.sessions[session_id] = session
    manager_destroy_calls: list[str] = []
    engine.logic_manager.destroy = lambda: manager_destroy_calls.append(
        "logic"
    )
    engine.handler_manager.destroy = lambda: manager_destroy_calls.append(
        "handler"
    )

    started = time.monotonic()
    assert not await engine.shutdown_async()
    elapsed = time.monotonic() - started

    assert elapsed < 0.2
    assert session_id in engine.sessions
    assert not session.is_fully_quiesced_v1()
    assert not context_destroyed.is_set()
    assert manager_destroy_calls == []
    with pytest.raises(RuntimeError, match="already exists"):
        engine._create_session(
            SessionInfoData(
                session_id=session_id,
                timestamp_base=16_001,
            ),
            session_admission=SyntheticAdmissionV1(),
        )

    handler_release.set()
    pump_thread.join(timeout=1.0)
    assert not pump_thread.is_alive()
    assert await engine.shutdown_async()

    assert context_destroyed.is_set()
    assert session_id not in engine.sessions
    assert manager_destroy_calls == ["logic", "handler"]


@pytest.mark.asyncio
async def test_stuck_transport_blocks_manager_teardown_and_same_id_reuse():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.05
    )
    session_id = "quarantined-transport-session"
    session = _secure_session(
        session_id,
        work_controller=controller,
    )
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    engine.sessions[session_id] = session
    transport_released = False

    async def teardown_transport(
        _session_id: str,
        _deadline_monotonic=None,
    ) -> bool:
        return transport_released

    engine._teardown_session_transports_v1 = teardown_transport
    manager_destroy_calls: list[str] = []
    engine.logic_manager.destroy = lambda: manager_destroy_calls.append(
        "logic"
    )
    engine.handler_manager.destroy = lambda: manager_destroy_calls.append(
        "handler"
    )

    assert not await engine.shutdown_async()
    assert session_id in engine.sessions
    assert manager_destroy_calls == []
    with pytest.raises(RuntimeError, match="already exists"):
        engine._create_session(
            SessionInfoData(
                session_id=session_id,
                timestamp_base=16_001,
            ),
            session_admission=SyntheticAdmissionV1(),
        )

    transport_released = True
    assert await engine.shutdown_async()
    assert session_id not in engine.sessions
    assert manager_destroy_calls == ["logic", "handler"]


@pytest.mark.asyncio
async def test_timed_out_transport_teardown_task_is_reused_not_duplicated():
    engine = ChatEngine()
    session_id = "retained-transport-teardown-task"
    teardown_started = asyncio.Event()
    teardown_release = asyncio.Event()
    teardown_calls = 0

    class CancellationResistantTransportV1:
        primary_tasks = ()
        _quarantined_connection_tasks_v1 = ()

        async def retire_transport_async_v1(self) -> None:
            nonlocal teardown_calls
            teardown_calls += 1
            teardown_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                while not teardown_release.is_set():
                    try:
                        await asyncio.shield(
                            teardown_release.wait()
                        )
                    except asyncio.CancelledError:
                        continue

    target = CancellationResistantTransportV1()
    engine._quarantined_transports_v1[session_id] = [
        ("delegate", target)
    ]

    assert not await engine._teardown_session_transports_v1(
        session_id,
        time.monotonic() + 0.02,
    )
    await teardown_started.wait()
    assert teardown_calls == 1
    assert session_id in engine._quarantined_transports_v1
    assert engine._transport_teardown_tasks_v1
    assert session_id in engine._transport_teardown_session_locks_v1

    assert not await engine._teardown_session_transports_v1(
        session_id,
        time.monotonic() + 0.02,
    )
    assert teardown_calls == 1

    teardown_release.set()
    tracked_task = next(
        iter(engine._transport_teardown_tasks_v1.values())
    )
    await asyncio.wait_for(
        asyncio.shield(tracked_task),
        timeout=1,
    )
    assert await engine._teardown_session_transports_v1(
        session_id,
        time.monotonic() + 0.1,
    )

    assert teardown_calls == 1
    assert session_id not in engine._quarantined_transports_v1
    assert engine._transport_teardown_tasks_v1 == {}
    assert engine._transport_teardown_session_locks_v1 == {}


def test_timed_out_sync_transport_teardown_thread_is_not_duplicated():
    engine = ChatEngine()
    session_id = "retained-sync-transport-teardown-thread"
    teardown_started = threading.Event()
    teardown_release = threading.Event()
    teardown_calls = 0

    class BlockingTransportV1:
        def __init__(self) -> None:
            self.quit = threading.Event()
            self.primary_tasks = ()
            self._quarantined_connection_tasks_v1 = ()

        def clear_data(self) -> None:
            nonlocal teardown_calls
            teardown_calls += 1
            teardown_started.set()
            teardown_release.wait()

    target = BlockingTransportV1()
    engine._quarantined_transports_v1[session_id] = [
        ("delegate", target)
    ]

    assert not engine._teardown_session_transports_sync_v1(
        session_id,
        time.monotonic() + 0.02,
    )
    assert teardown_started.wait(timeout=1)
    assert teardown_calls == 1
    assert engine._transport_teardown_threads_v1
    assert session_id in engine._transport_teardown_session_locks_v1

    assert not engine._teardown_session_transports_sync_v1(
        session_id,
        time.monotonic() + 0.02,
    )
    assert teardown_calls == 1

    teardown_release.set()
    tracked_thread, _failed = next(
        iter(engine._transport_teardown_threads_v1.values())
    )
    tracked_thread.join(timeout=1)
    assert not tracked_thread.is_alive()
    assert engine._teardown_session_transports_sync_v1(
        session_id,
        time.monotonic() + 0.1,
    )

    assert teardown_calls == 1
    assert engine._transport_teardown_threads_v1 == {}
    assert engine._transport_teardown_session_locks_v1 == {}


@pytest.mark.asyncio
async def test_async_transport_owner_rejects_concurrent_sync_duplicate():
    engine = ChatEngine()
    session_id = "async-owned-cross-mode-transport"
    teardown_started = asyncio.Event()
    teardown_release = asyncio.Event()
    async_calls = 0
    sync_calls = 0

    class CrossModeTransportV1:
        primary_tasks = ()
        _quarantined_connection_tasks_v1 = ()
        quit = threading.Event()

        async def retire_transport_async_v1(self) -> None:
            nonlocal async_calls
            async_calls += 1
            teardown_started.set()
            await teardown_release.wait()

        def clear_data(self) -> None:
            nonlocal sync_calls
            sync_calls += 1

    target = CrossModeTransportV1()
    engine._quarantined_transports_v1[session_id] = [
        ("delegate", target)
    ]
    async_owner = asyncio.create_task(
        engine._teardown_session_transports_v1(
            session_id,
            time.monotonic() + 1,
        )
    )
    await teardown_started.wait()

    assert not engine._teardown_session_transports_sync_v1(
        session_id,
        time.monotonic() + 0.1,
    )
    assert async_calls == 1
    assert sync_calls == 0
    teardown_release.set()
    assert await async_owner

    assert async_calls == 1
    assert sync_calls == 0


@pytest.mark.asyncio
async def test_sync_transport_owner_rejects_concurrent_async_duplicate():
    engine = ChatEngine()
    session_id = "sync-owned-cross-mode-transport"
    teardown_started = threading.Event()
    teardown_release = threading.Event()
    async_calls = 0
    sync_calls = 0
    sync_results: list[bool] = []

    class CrossModeTransportV1:
        primary_tasks = ()
        _quarantined_connection_tasks_v1 = ()

        def __init__(self) -> None:
            self.quit = threading.Event()

        async def retire_transport_async_v1(self) -> None:
            nonlocal async_calls
            async_calls += 1

        def clear_data(self) -> None:
            nonlocal sync_calls
            sync_calls += 1
            teardown_started.set()
            teardown_release.wait()

    target = CrossModeTransportV1()
    engine._quarantined_transports_v1[session_id] = [
        ("delegate", target)
    ]

    def run_sync_owner() -> None:
        sync_results.append(
            engine._teardown_session_transports_sync_v1(
                session_id,
                time.monotonic() + 1,
            )
        )

    sync_owner = threading.Thread(target=run_sync_owner)
    sync_owner.start()
    assert teardown_started.wait(timeout=1)

    assert not await engine._teardown_session_transports_v1(
        session_id,
        time.monotonic() + 0.1,
    )
    assert sync_calls == 1
    assert async_calls == 0
    teardown_release.set()
    sync_owner.join(timeout=1)

    assert not sync_owner.is_alive()
    assert sync_results == [True]
    assert sync_calls == 1
    assert async_calls == 0


@pytest.mark.asyncio
async def test_manager_shutdown_stays_blocked_by_cross_mode_transport_owner():
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    session_id = "cross-mode-manager-transport-owner"
    session = _secure_session(
        session_id,
        work_controller=controller,
    )
    engine = ChatEngine()
    engine.engine_config = ChatEngineConfigModel(
        handler_configs={},
        logic_configs={},
    )
    engine._certificate_capture_enabled_v1 = True
    engine.sessions[session_id] = session
    manager_destroy_calls: list[str] = []
    engine.logic_manager.destroy = lambda: manager_destroy_calls.append(
        "logic"
    )
    engine.handler_manager.destroy = lambda: manager_destroy_calls.append(
        "handler"
    )
    teardown_started = asyncio.Event()
    teardown_release = asyncio.Event()
    teardown_calls = 0

    class StubbornTransportV1:
        primary_tasks = ()
        _quarantined_connection_tasks_v1 = ()

        async def retire_transport_async_v1(self) -> None:
            nonlocal teardown_calls
            teardown_calls += 1
            teardown_started.set()
            await teardown_release.wait()

    target = StubbornTransportV1()
    engine._quarantined_transports_v1[session_id] = [
        ("delegate", target)
    ]
    async_retirement = asyncio.create_task(
        engine.retire_secure_session_v1(session_id)
    )
    await teardown_started.wait()

    engine.retire_secure_session_sync_v1(session_id)
    assert not engine.shutdown()
    assert manager_destroy_calls == []
    assert session_id in engine._transport_retirement_ids_v1
    assert teardown_calls == 1

    teardown_release.set()
    await async_retirement
    assert await engine.shutdown_async()

    assert teardown_calls == 1
    assert manager_destroy_calls == ["logic", "handler"]


@pytest.mark.asyncio
async def test_completed_transport_claims_do_not_accumulate_by_session():
    engine = ChatEngine()

    for index in range(32):
        session_id = f"completed-transport-claim-{index}"
        if index % 2:
            assert engine._teardown_session_transports_sync_v1(
                session_id,
                time.monotonic() + 0.1,
            )
        else:
            assert await engine._teardown_session_transports_v1(
                session_id,
                time.monotonic() + 0.1,
            )

    assert engine._transport_teardown_session_locks_v1 == {}


def test_unusable_injected_controller_fails_secure_session_creation():
    controller = SessionWorkControllerV1()
    assert controller.shutdown()
    context = SessionContext(
        SessionInfoData(
            session_id="broken-controller",
            timestamp_base=16_000,
        ),
        session_admission=SyntheticAdmissionV1(),
    )

    with pytest.raises(
        RuntimeError,
        match="secure work controller unavailable",
    ):
        ChatSession(
            context,
            ChatEngineConfigModel(),
            _work_controller_v1=controller,
        )


def test_legacy_session_rejects_injected_secure_controller():
    controller = SessionWorkControllerV1()
    context = SessionContext(
        SessionInfoData(
            session_id="legacy-injected-controller",
            timestamp_base=16_000,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="work controller requires a secure session",
    ):
        ChatSession(
            context,
            ChatEngineConfigModel(),
            _work_controller_v1=controller,
        )
    assert controller.shutdown()

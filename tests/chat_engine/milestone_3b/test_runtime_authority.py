from __future__ import annotations

import asyncio
import time

import pytest

from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
    WorkControllerFailureReasonV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)


def _register(
    controller: SessionWorkControllerV1,
    kind: WorkOperationKindV1 = WorkOperationKindV1.GENERIC_ASYNC,
):
    return controller.register_work_v1(
        kind,
        time.monotonic() + 30.0,
    )


def test_milestone_3b_operation_kinds_are_closed_and_certificate_free():
    expected = {
        "PERCEPTION_INFERENCE",
        "CHAT_AGENT_LLM",
        "CHAT_AGENT_PROACTIVE",
        "TOOL_EXECUTION",
        "TTS_SYNTHESIS",
        "WS_EGRESS",
        "RTC_EGRESS",
    }
    names = {kind.name for kind in WorkOperationKindV1}

    assert expected <= names
    assert not {
        "OCR",
        "CAPTURE",
        "QUERY",
        "CERTIFICATE_SPEECH",
        "BARCODE",
        "DOCUMENT_NUMBER",
    } & names


def test_child_registration_cannot_launder_retired_parent_generation():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = _register(controller)
    retirement = controller.retire_generation_v1()

    with pytest.raises(WorkAdmissionDeniedV1):
        runtime.register_child_work_v1(
            parent,
            WorkOperationKindV1.TOOL_EXECUTION,
        )

    current = runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )
    assert current.fence.session_epoch == retirement.new_epoch
    assert current.fence.session_epoch != parent.fence.session_epoch
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert runtime.release_work_v1(current)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_work_scope_is_task_local_not_event_loop_thread_local():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    first = _register(controller)
    second = _register(controller)
    both_active = asyncio.Event()
    observations: dict[str, object] = {}
    entered = 0
    entered_lock = asyncio.Lock()

    async def observe(name: str, work) -> None:
        nonlocal entered
        with runtime.activate_work_v1(work):
            async with entered_lock:
                entered += 1
                if entered == 2:
                    both_active.set()
            await both_active.wait()
            await asyncio.sleep(0)
            observations[name] = runtime.current_work_v1()

    await asyncio.gather(
        observe("first", first),
        observe("second", second),
    )

    assert observations == {"first": first, "second": second}
    assert runtime.current_work_v1() is None
    assert runtime.release_work_v1(first)
    assert runtime.release_work_v1(second)
    assert controller.shutdown()


@pytest.mark.asyncio
async def test_awaited_ws_send_is_cancelled_before_retirement_publication():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    work = _register(controller, WorkOperationKindV1.WS_EGRESS)
    item = WorkBoundItemV1(payload=b"public", registered_work=work)
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    sent: list[bytes] = []

    async def blocked_send() -> None:
        entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        sent.append(b"public")

    send_task = asyncio.create_task(
        runtime.perform_item_egress_async_if_live_v1(
            item,
            None,
            blocked_send,
            lambda: None,
        )
    )
    await entered.wait()
    retirement = await controller.retire_generation_async_v1()

    assert not await send_task
    assert cancelled.is_set()
    assert sent == []
    assert retirement.new_epoch.generation == 2
    assert item.release_once_v1(runtime)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
async def test_cancellation_resistant_egress_is_quarantined_before_resume():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    work = _register(controller, WorkOperationKindV1.WS_EGRESS)
    item = WorkBoundItemV1(payload=b"public", registered_work=work)
    entered = asyncio.Event()
    quarantined = asyncio.Event()
    transport_open = True
    sent: list[bytes] = []

    async def stubborn_send() -> None:
        entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await quarantined.wait()
        if transport_open:
            sent.append(b"public")

    def abort_transport() -> None:
        nonlocal transport_open
        transport_open = False
        quarantined.set()

    send_task = asyncio.create_task(
        runtime.perform_item_egress_async_if_live_v1(
            item,
            None,
            stubborn_send,
            abort_transport,
        )
    )
    await entered.wait()
    retirement = await controller.retire_generation_async_v1()

    assert not await send_task
    assert quarantined.is_set()
    assert sent == []
    assert (
        controller.failure_reason_v1()
        is WorkControllerFailureReasonV1.EGRESS_TRANSPORT_ABORTED
    )
    with pytest.raises(WorkAdmissionDeniedV1):
        runtime.register_root_work_v1(
            WorkOperationKindV1.CHAT_AGENT_LLM
        )
    assert item.release_once_v1(runtime)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
async def test_sync_retirement_rejects_event_loop_deadlock_with_active_send():
    controller = SessionWorkControllerV1()
    work = _register(controller, WorkOperationKindV1.WS_EGRESS)
    entered = asyncio.Event()

    async def blocked_send() -> None:
        entered.set()
        await asyncio.Future()

    task = asyncio.create_task(
        controller.perform_if_live_async_v1(
            work.fence,
            WorkValidationBoundaryV1.BEFORE_EGRESS,
            blocked_send,
            lambda: None,
        )
    )
    await entered.wait()

    with pytest.raises(
        WorkAdmissionDeniedV1,
        match="retire_generation_async_v1",
    ):
        controller.retire_generation_v1()

    retirement = await controller.retire_generation_async_v1()
    assert not await task
    assert controller.release_work_v1(work.lease)
    assert await controller.wait_for_cleanup_async_v1(
        retirement.cleanup_fence
    )
    assert not await controller.shutdown_async()


@pytest.mark.asyncio
async def test_m2_authorization_cannot_be_rescued_by_live_async_fence():
    authority, registrar, issuer = SecurityAuthorityV1._create_for_test_v1()
    private_envelope = authority._issue_private_root_for_test_v1(issuer)
    public_consumer = (
        authority._issue_public_test_consumer_capability_v1(issuer)
    )
    assert private_envelope is not None
    assert public_consumer is not None
    assert authority.close_registration_v1(registrar)

    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller, authority)
    work = _register(controller, WorkOperationKindV1.WS_EGRESS)
    item = WorkBoundItemV1(
        payload=b"private",
        registered_work=work,
        envelope_ref=private_envelope,
    )
    sends: list[bytes] = []

    async def send() -> None:
        sends.append(b"private")

    assert not await runtime.perform_item_egress_async_if_live_v1(
        item,
        public_consumer,
        send,
        lambda: None,
    )
    assert sends == []
    assert item.release_once_v1(runtime)
    assert await controller.shutdown_async()
    authority.close()

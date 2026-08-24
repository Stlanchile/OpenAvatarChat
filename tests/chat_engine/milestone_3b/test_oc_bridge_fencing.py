from __future__ import annotations

import time
from types import SimpleNamespace

from loguru import logger

from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import SessionWorkRuntimeV1
from handlers.agent.chat_agent_handler import (
    ChatAgentConfig,
    ChatAgentContext,
    ChatAgentHandler,
    OcBridgeConfig,
    ProactiveConfig,
)
from handlers.agent.oc_bridge.oc_channel_client import (
    OcReplyMessage,
    OcReplyQueue,
)
from handlers.agent.oc_bridge.oc_reply_bridge import OcReplyBridge
from handlers.agent.oc_bridge.pending_confirmations import (
    PendingConfirmationsManager,
)
from handlers.agent.oc_bridge.task_notification_queue import (
    TaskNotification,
    TaskNotificationQueue,
)
from handlers.agent.tools.base_tool import BaseTool, ToolResult
from handlers.agent.tools.spawn_agent import SpawnAgentTool
from handlers.agent.tools.tool_registry import ToolRegistry


class _Channel:
    def __init__(self, *, send_result=None) -> None:
        self.reply_queue = OcReplyQueue()
        self.send_result = send_result or {"ok": True}
        self.sent: list[dict] = []

    def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return dict(self.send_result)


class _Wake:
    def __init__(self) -> None:
        self.set_calls = 0
        self._set = False

    def set(self) -> None:
        self.set_calls += 1
        self._set = True

    def clear(self) -> None:
        self._set = False

    def is_set(self) -> bool:
        return self._set


class _NestedTool(BaseTool):
    def __init__(
        self,
        runtime: SessionWorkRuntimeV1,
        controller: SessionWorkControllerV1,
    ) -> None:
        self.runtime = runtime
        self.controller = controller
        self.observed_kind = None
        self.retirement = None

    @property
    def name(self) -> str:
        return "synthetic_nested"

    @property
    def description(self) -> str:
        return "Synthetic nested tool"

    @property
    def parameters(self) -> dict:
        return {"type": "object", "properties": {}}

    def execute(self, args: dict) -> ToolResult:
        del args
        work = self.runtime.current_work_v1()
        self.observed_kind = (
            work.fence.operation_kind if work is not None else None
        )
        self.retirement = self.controller.retire_generation_v1()
        return ToolResult(
            success=True,
            data={"content": "STALE_NESTED_TOOL_CANARY"},
        )


def _secure_bridge():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.TOOL_EXECUTION
    )
    channel = _Channel()
    task_queue = TaskNotificationQueue()
    pending_mgr = PendingConfirmationsManager()
    wake = _Wake()
    bridge = OcReplyBridge.register(
        channel_client=channel,
        session_id="synthetic-session",
        task_queue=task_queue,
        pending_mgr=pending_mgr,
        proactive_wake=wake,
        work_runtime_v1=runtime,
    )
    assert bridge is not None
    return (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        wake,
        bridge,
    )


def test_secure_oc_callback_after_retirement_is_release_only_and_redacted():
    (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        wake,
        bridge,
    ) = _secure_bridge()
    pending = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=True,
    )
    assert pending is not None
    canary = "STALE_OC_PRIVATE_CANARY"
    logs: list[str] = []
    sink = logger.add(lambda message: logs.append(str(message)), level="DEBUG")
    try:
        channel.reply_queue.push(
            OcReplyMessage(
                "synthetic-session",
                canary,
                time.time(),
                correlation_id="ocw1_unknown",
            )
        )
        retirement = controller.retire_generation_v1()
        channel.reply_queue.push(
            OcReplyMessage(
                "synthetic-session",
                canary,
                time.time(),
                correlation_id=pending.correlation_id,
                status="completed",
            )
        )
    finally:
        logger.remove(sink)

    assert bridge.pending_count_v1() == 0
    assert task_queue.size == 0
    assert wake.set_calls == 0
    assert canary not in "".join(logs)
    assert not pending.work_item_v1.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_secure_oc_live_callback_routes_once_and_releases_child():
    (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        wake,
        bridge,
    ) = _secure_bridge()
    pending = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=True,
    )
    assert pending is not None
    reply = OcReplyMessage(
        "synthetic-session",
        "synthetic public result",
        time.time(),
        correlation_id=pending.correlation_id,
        status="completed",
    )

    channel.reply_queue.push(reply)
    channel.reply_queue.push(reply)

    assert bridge.pending_count_v1() == 0
    assert task_queue.size == 1
    assert wake.set_calls == 0
    assert not pending.work_item_v1.release_once_v1(runtime)
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_secure_oc_synchronous_replies_cannot_cross_correlations():
    (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        _wake,
        bridge,
    ) = _secure_bridge()
    first = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=False,
    )
    second = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=False,
    )
    assert first is not None
    assert second is not None

    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            "second",
            time.time(),
            correlation_id=second.correlation_id,
            status="completed",
        )
    )
    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            "first",
            time.time(),
            correlation_id=first.correlation_id,
            status="completed",
        )
    )

    assert bridge.wait_for_reply_v1(second, 0).text == "second"
    assert bridge.wait_for_reply_v1(first, 0).text == "first"
    assert task_queue.size == 0
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_secure_oc_progress_retains_work_until_terminal_callback():
    (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        _wake,
        bridge,
    ) = _secure_bridge()
    pending = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=True,
    )
    assert pending is not None

    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            "synthetic progress",
            time.time(),
            correlation_id=pending.correlation_id,
            status="progress",
        )
    )

    assert bridge.pending_count_v1() == 1
    assert task_queue.size == 1
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ((1, 2),)
    )

    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            "synthetic completion",
            time.time(),
            correlation_id=pending.correlation_id,
            status="completed",
        )
    )

    assert bridge.pending_count_v1() == 0
    assert task_queue.size == 2
    assert not pending.work_item_v1.release_once_v1(runtime)
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ((1, 1),)
    )
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_secure_oc_progress_then_retirement_drops_late_terminal_semantics():
    (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        _wake,
        bridge,
    ) = _secure_bridge()
    pending = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=True,
    )
    assert pending is not None
    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            "synthetic progress",
            time.time(),
            correlation_id=pending.correlation_id,
            status="progress",
        )
    )
    retirement = controller.retire_generation_v1()
    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            "STALE_OC_TERMINAL_CANARY",
            time.time(),
            correlation_id=pending.correlation_id,
            status="completed",
        )
    )

    assert bridge.pending_count_v1() == 0
    assert task_queue.size == 1
    assert all(
        notification.result_summary != "STALE_OC_TERMINAL_CANARY"
        for notification in task_queue.peek()
    )
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_secure_generation_reset_discards_deferred_oc_semantics():
    (
        controller,
        runtime,
        parent,
        channel,
        task_queue,
        wake,
        bridge,
    ) = _secure_bridge()
    pending = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=True,
    )
    assert pending is not None
    channel.reply_queue.push(
        OcReplyMessage(
            "synthetic-session",
            (
                "Exec approval required\n"
                "ID: abcdef12\n"
                "Command: `synthetic-public-command`"
            ),
            time.time(),
            correlation_id=pending.correlation_id,
            status="completed",
        )
    )
    assert task_queue.size == 1
    assert bridge._pending_mgr.has_pending()
    retirement = controller.retire_generation_v1()
    current = runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )
    context = ChatAgentContext("synthetic-session")
    context.task_queue = task_queue
    context.pending_confirmations = bridge._pending_mgr
    context.oc_reply_bridge = bridge
    context._proactive_wake = wake

    assert runtime.perform_if_live_v1(
        current,
        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        lambda: ChatAgentHandler._reset_generation_state_v1(
            context,
            current.fence.session_epoch.generation,
        ),
    )

    assert task_queue.size == 0
    assert not context.pending_confirmations.has_pending()
    assert task_queue.format_for_prompt() == ""
    assert not wake.is_set()
    task_queue.push(
        TaskNotification(
            task_id="current-generation",
            status="progress",
            result_summary="synthetic current result",
        )
    )
    context.pending_confirmations.upsert(
        [
            {
                "id": "current-generation",
                "status": "pending",
            }
        ]
    )
    wake.set()
    assert runtime.perform_if_live_v1(
        current,
        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        lambda: ChatAgentHandler._reset_generation_state_v1(
            context,
            current.fence.session_epoch.generation,
        ),
    )
    assert task_queue.size == 1
    assert context.pending_confirmations.has_pending()
    assert wake.is_set()
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert runtime.release_work_v1(current)
    assert controller.shutdown()


def test_secure_spawn_agent_registers_before_send_and_send_error_releases():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.TOOL_EXECUTION
    )
    channel = _Channel(send_result={"error": "synthetic failure"})
    bridge = OcReplyBridge.register(
        channel_client=channel,
        session_id="synthetic-session",
        task_queue=TaskNotificationQueue(),
        pending_mgr=PendingConfirmationsManager(),
        proactive_wake=_Wake(),
        work_runtime_v1=runtime,
    )
    assert bridge is not None
    tool = SpawnAgentTool(
        oc_channel_client=channel,
        oac_session_id="synthetic-session",
        work_runtime_v1=runtime,
        oc_reply_bridge=bridge,
    )

    with runtime.activate_work_v1(parent, None):
        result = tool.execute(
            {
                "subagent_type": "oc_delegate",
                "prompt": "synthetic public task",
                "run_background": True,
            }
        )

    assert not result.success
    assert len(channel.sent) == 1
    assert channel.sent[0]["correlation_id"].startswith("ocw1_")
    assert bridge.pending_count_v1() == 0
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ((1, 1),)
    )
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_secure_stale_spawn_agent_cannot_launder_to_current_generation():
    (
        controller,
        runtime,
        parent,
        channel,
        _task_queue,
        _wake,
        bridge,
    ) = _secure_bridge()
    retirement = controller.retire_generation_v1()
    tool = SpawnAgentTool(
        oc_channel_client=channel,
        oac_session_id="synthetic-session",
        work_runtime_v1=runtime,
        oc_reply_bridge=bridge,
    )

    with runtime.activate_work_v1(parent, None):
        result = tool.execute(
            {
                "subagent_type": "oc_delegate",
                "prompt": "synthetic public task",
                "run_background": True,
            }
        )

    assert not result.success
    assert channel.sent == []
    assert bridge.pending_count_v1() == 0
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_secure_local_spawn_registers_each_llm_round_before_model_call():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.TOOL_EXECUTION
    )
    observed_kinds = []

    def create_completion(**_kwargs):
        work = runtime.current_work_v1()
        observed_kinds.append(
            work.fence.operation_kind if work is not None else None
        )
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="stop",
                    message=SimpleNamespace(
                        content="synthetic public result",
                        tool_calls=[],
                    ),
                )
            ]
        )

    llm_client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=create_completion)
        )
    )
    tool = SpawnAgentTool(
        llm_client=llm_client,
        work_runtime_v1=runtime,
    )

    with runtime.activate_work_v1(parent, None):
        result = tool.execute(
            {
                "subagent_type": "explore",
                "prompt": "synthetic public task",
                "run_background": False,
            }
        )

    assert result.success
    assert result.data["content"] == "synthetic public result"
    assert observed_kinds == [WorkOperationKindV1.CHAT_AGENT_LLM]
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ((1, 1),)
    )
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_secure_local_spawn_nested_tool_cannot_continue_after_retirement():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.TOOL_EXECUTION
    )
    registry = ToolRegistry()
    nested_tool = _NestedTool(runtime, controller)
    registry.register(nested_tool)
    observed_llm_kinds = []

    def create_completion(**_kwargs):
        work = runtime.current_work_v1()
        observed_llm_kinds.append(
            work.fence.operation_kind if work is not None else None
        )
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="tool_calls",
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[
                            SimpleNamespace(
                                id="synthetic-call",
                                function=SimpleNamespace(
                                    name="synthetic_nested",
                                    arguments="{}",
                                ),
                            )
                        ],
                    ),
                )
            ]
        )

    llm_client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=create_completion)
        )
    )
    tool = SpawnAgentTool(
        llm_client=llm_client,
        tool_registry=registry,
        work_runtime_v1=runtime,
    )
    logs: list[str] = []
    sink = logger.add(lambda message: logs.append(str(message)))
    try:
        with runtime.activate_work_v1(parent, None):
            result = tool.execute(
                {
                    "subagent_type": "explore",
                    "prompt": "synthetic public task",
                    "run_background": False,
                }
            )
    finally:
        logger.remove(sink)

    assert not result.success
    assert observed_llm_kinds == [WorkOperationKindV1.CHAT_AGENT_LLM]
    assert nested_tool.observed_kind is WorkOperationKindV1.TOOL_EXECUTION
    assert nested_tool.retirement is not None
    assert "STALE_NESTED_TOOL_CANARY" not in "".join(logs)
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ((1, 1),)
    )
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(
        nested_tool.retirement.cleanup_fence
    )
    assert controller.shutdown()


def test_secure_oc_pending_request_releases_at_its_work_deadline(
    monkeypatch,
):
    (
        controller,
        runtime,
        parent,
        _channel,
        _task_queue,
        _wake,
        bridge,
    ) = _secure_bridge()
    monkeypatch.setattr(
        SessionWorkRuntimeV1,
        "deadline_for_kind_v1",
        staticmethod(lambda _kind: time.monotonic() + 0.03),
    )
    pending = bridge.begin_request_v1(
        parent,
        None,
        route_to_notifications=True,
    )
    assert pending is not None

    wait_deadline = time.monotonic() + 1.0
    while (
        bridge.pending_count_v1() != 0
        and time.monotonic() < wait_deadline
    ):
        time.sleep(0.005)

    assert bridge.pending_count_v1() == 0
    assert pending.terminal_event.is_set()
    assert not pending.work_item_v1.release_once_v1(runtime)
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ((1, 1),)
    )
    assert runtime.release_work_v1(parent)
    assert controller.shutdown()


def test_legacy_oc_reply_routing_remains_session_keyed():
    channel = _Channel()
    task_queue = TaskNotificationQueue()
    bridge = OcReplyBridge.register(
        channel_client=channel,
        session_id="legacy-session",
        task_queue=task_queue,
        pending_mgr=PendingConfirmationsManager(),
        proactive_wake=_Wake(),
    )
    assert bridge is not None

    channel.reply_queue.push(
        OcReplyMessage(
            "legacy-session",
            "legacy public result",
            time.time(),
        )
    )

    assert task_queue.size == 1
    assert (
        channel.reply_queue.wait_for_reply(
            "legacy-session",
            timeout=0,
        ).text
        == "legacy public result"
    )


def test_secure_oc_initialization_waits_for_injected_work_runtime(
    monkeypatch,
):
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    context = ChatAgentContext("synthetic-session")
    context.config = ChatAgentConfig(
        oc_bridge=OcBridgeConfig(enabled=True),
        proactive=ProactiveConfig(enabled=False),
    )
    context._oc_bridge_init_pending_v1 = True
    context.work_runtime_v1 = runtime
    handler = ChatAgentHandler()
    observed_work = []

    def record_init(target_context) -> None:
        observed_work.append(
            target_context.work_runtime_v1.current_work_v1()
        )

    monkeypatch.setattr(handler, "_init_oc_bridge", record_init)

    handler.start_context(object(), context)

    assert len(observed_work) == 1
    assert observed_work[0] is not None
    assert (
        observed_work[0].fence.operation_kind
        is WorkOperationKindV1.GENERIC_EXTERNAL_CALL
    )
    assert not context._oc_bridge_init_pending_v1
    assert (
        controller.snapshot_v1().unreleased_work_by_generation
        == ()
    )
    assert controller.shutdown()

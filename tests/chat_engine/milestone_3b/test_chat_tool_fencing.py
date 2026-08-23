from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from loguru import logger

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.runtime_data.data_bundle import (
    DataBundleDefinition,
    DataBundleEntry,
)
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1
from chat_engine.security.work_runtime import SessionWorkRuntimeV1
from handlers.agent.agent_data_models import EnvironmentEvent
from handlers.agent.chat_agent_handler import (
    ChatAgentConfig,
    ChatAgentContext,
    ChatAgentHandler,
)
from handlers.agent.memory.session_memory_manager import (
    MemoryConfig,
    SessionMemoryManager,
)
from handlers.agent.tools.base_tool import BaseTool, ToolResult
from handlers.agent.tools.tool_registry import ToolRegistry


class _BlockingTool(BaseTool):
    def __init__(self, *, raises: bool = False) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.raises = raises

    @property
    def name(self) -> str:
        return "blocking_tool"

    @property
    def description(self) -> str:
        return "synthetic"

    @property
    def parameters(self) -> dict:
        return {"type": "object", "properties": {}}

    def execute(self, args) -> ToolResult:
        del args
        self.started.set()
        self.release.wait(timeout=5)
        if self.raises:
            raise RuntimeError("STALE_TOOL_RESULT_CANARY")
        return ToolResult(success=True, data={"value": "stale"})


class _RecordingStreamer:
    def __init__(self) -> None:
        self.values: list[str] = []
        self.emitted = threading.Event()

    def stream_data(self, output, finish_stream=None) -> None:
        del finish_stream
        self.values.append(output.get_main_data())
        self.emitted.set()


class _BlockingResponse:
    def __init__(self) -> None:
        self.allow_second = threading.Event()
        self.closed = threading.Event()

    @staticmethod
    def _chunk(content: str):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        content=content,
                        tool_calls=None,
                    )
                )
            ]
        )

    def __iter__(self):
        yield self._chunk("first")
        self.allow_second.wait(timeout=5)
        yield self._chunk("STALE_CHUNK_CANARY")

    def close(self) -> None:
        self.closed.set()
        self.allow_second.set()


class _ImmediateResponse:
    @staticmethod
    def _chunk(content: str):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        content=content,
                        tool_calls=None,
                    )
                )
            ]
        )

    def __iter__(self):
        yield self._chunk("public-one")
        yield self._chunk("public-two")

    def close(self) -> None:
        return


class _ToolCallResponse:
    def __iter__(self):
        tool_delta = SimpleNamespace(
            index=0,
            id="call-1",
            function=SimpleNamespace(
                name="blocking_tool",
                arguments="{}",
            ),
        )
        yield SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        content=None,
                        tool_calls=[tool_delta],
                    )
                )
            ]
        )

    def close(self) -> None:
        return


class _FakeCompletions:
    def __init__(self) -> None:
        self.calls = 0

    def create(self, **kwargs):
        del kwargs
        self.calls += 1
        return _ToolCallResponse()


class _BlockingCompactCompletions:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def create(self, **kwargs):
        del kwargs
        self.started.set()
        self.release.wait(timeout=5)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="<summary>stale summary</summary>"
                    )
                )
            ]
        )


def _runtime_pair():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    parent = runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )
    return controller, runtime, parent


def _text_definition() -> DataBundleDefinition:
    definition = DataBundleDefinition()
    definition.add_entry(DataBundleEntry.create_text_entry("avatar_text"))
    definition.lockdown()
    return definition


def test_tool_retirement_discards_result_and_blocks_post_tool_continuation():
    controller, runtime, parent = _runtime_pair()
    context = ChatAgentContext("session")
    context.config = ChatAgentConfig()
    context.work_runtime_v1 = runtime
    context.active_stream_keys.add("stream")
    tool = _BlockingTool()
    registry = ToolRegistry()
    registry.register(tool)
    context.tool_registry = registry
    completions = _FakeCompletions()
    context.llm_client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )
    handler = ChatAgentHandler()
    streamer = _RecordingStreamer()
    messages: list[dict] = [{"role": "user", "content": "public"}]
    result_holder = []

    def run_loop() -> None:
        with runtime.activate_work_v1(parent):
            result_holder.append(
                handler._agent_loop(
                    context,
                    messages,
                    _text_definition(),
                    streamer,
                    "stream",
                    work_v1=parent,
                )
            )

    thread = threading.Thread(target=run_loop)
    thread.start()
    assert tool.started.wait(timeout=2)
    retirement = controller.retire_generation_v1()
    status = controller.cleanup_status_v1(retirement.cleanup_fence)
    assert status is not None
    assert status.outstanding_work_tokens >= 2
    tool.release.set()
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert result_holder == [None]
    assert completions.calls == 1
    assert not any(message.get("role") == "tool" for message in messages)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_stale_tool_exception_is_redacted_and_returns_no_result():
    controller, runtime, parent = _runtime_pair()
    tool = _BlockingTool(raises=True)
    registry = ToolRegistry()
    registry.register(tool)
    child = runtime.register_child_work_v1(
        parent,
        WorkOperationKindV1.TOOL_EXECUTION,
    )
    result_holder = []
    captured: list[str] = []
    sink = logger.add(
        lambda message: captured.append(str(message)),
        format="{message} {extra}",
    )

    def execute() -> None:
        try:
            result_holder.append(
                registry.execute(
                    tool.name,
                    {},
                    _work_runtime_v1=runtime,
                    _registered_work_v1=child,
                )
            )
        finally:
            runtime.release_work_v1(child)

    try:
        thread = threading.Thread(target=execute)
        thread.start()
        assert tool.started.wait(timeout=2)
        retirement = controller.retire_generation_v1()
        tool.release.set()
        thread.join(timeout=3)
    finally:
        logger.remove(sink)

    assert result_holder == [None]
    assert "STALE_TOOL_RESULT_CANARY" not in "".join(captured)
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_streaming_chunk_after_retirement_is_closed_and_not_emitted():
    controller, runtime, work = _runtime_pair()
    context = ChatAgentContext("session")
    context.work_runtime_v1 = runtime
    context.active_stream_keys.add("stream")
    handler = ChatAgentHandler()
    streamer = _RecordingStreamer()
    response = _BlockingResponse()
    result_holder = []

    def stream() -> None:
        with runtime.activate_work_v1(work):
            result_holder.append(
                handler._stream_response(
                    context,
                    response,
                    _text_definition(),
                    streamer,
                    "stream",
                    work_v1=work,
                )
            )

    thread = threading.Thread(target=stream)
    thread.start()
    assert streamer.emitted.wait(timeout=2)
    retirement = controller.retire_generation_v1()
    response.allow_second.set()
    thread.join(timeout=3)

    assert not thread.is_alive()
    full_text, tool_calls, cancelled = result_holder[0]
    assert cancelled
    assert full_text == ""
    assert tool_calls == []
    assert streamer.values == ["first"]
    assert response.closed.is_set()
    assert runtime.release_work_v1(work)
    assert controller.wait_for_cleanup_v1(retirement.cleanup_fence)
    assert controller.shutdown()


def test_chat_and_tool_disabled_mode_preserve_legacy_behavior():
    context = ChatAgentContext("legacy")
    context.active_stream_keys.add("stream")
    handler = ChatAgentHandler()
    streamer = _RecordingStreamer()

    full_text, tool_calls, cancelled = handler._stream_response(
        context,
        _ImmediateResponse(),
        _text_definition(),
        streamer,
        "stream",
    )

    tool = _BlockingTool()
    tool.release.set()
    registry = ToolRegistry()
    registry.register(tool)
    tool_result = registry.execute(tool.name, {})

    assert not cancelled
    assert full_text == "public-onepublic-two"
    assert tool_calls == []
    assert streamer.values == ["public-one", "public-two"]
    assert tool_result is not None
    assert tool_result.success


def test_successor_generation_public_chat_streams_with_live_fence():
    controller, runtime, retired_work = _runtime_pair()
    retirement = controller.retire_generation_v1()
    assert runtime.release_work_v1(retired_work)
    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    current_work = runtime.register_root_work_v1(
        WorkOperationKindV1.CHAT_AGENT_LLM
    )
    context = ChatAgentContext("secure-public")
    context.work_runtime_v1 = runtime
    context.active_stream_keys.add("stream")
    handler = ChatAgentHandler()
    streamer = _RecordingStreamer()

    with runtime.activate_work_v1(current_work):
        full_text, tool_calls, cancelled = handler._stream_response(
            context,
            _ImmediateResponse(),
            _text_definition(),
            streamer,
            "stream",
            work_v1=current_work,
        )

    assert not cancelled
    assert full_text == "public-onepublic-two"
    assert tool_calls == []
    assert streamer.values == ["public-one", "public-two"]
    assert runtime.release_work_v1(current_work)
    assert controller.shutdown()


def test_proactive_idle_loop_cannot_launder_into_successor_generation():
    controller = SessionWorkControllerV1()
    runtime = SessionWorkRuntimeV1(controller)
    context = ChatAgentContext("session")
    context.config = ChatAgentConfig()
    context.work_runtime_v1 = runtime
    handler = ChatAgentHandler()
    handler.start_context(SimpleNamespace(), context)

    deadline = time.monotonic() + 2
    while (
        not controller.snapshot_v1().unreleased_work_by_generation
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    retirement = controller.retire_generation_v1()
    deadline = time.monotonic() + 2
    while (
        controller.snapshot_v1().unreleased_work_by_generation
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)

    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    time.sleep(0.2)
    assert controller.snapshot_v1().unreleased_work_by_generation == ()

    current_ingress = runtime.register_root_work_v1(
        WorkOperationKindV1.GENERIC_ASYNC
    )
    handler._refresh_idle_lifecycle_from_ingress_v1(
        context,
        current_ingress,
    )
    snapshot = controller.snapshot_v1()
    assert dict(snapshot.unreleased_work_by_generation)[2] >= 2

    handler.destroy_context(context)
    assert runtime.release_work_v1(current_ingress)
    assert controller.shutdown()


def test_pending_event_continuation_after_retirement_keeps_state_unchanged():
    controller, runtime, parent = _runtime_pair()
    context = ChatAgentContext("session")
    context.config = ChatAgentConfig()
    context.work_runtime_v1 = runtime
    context.output_definitions = {
        ChatDataType.AVATAR_TEXT: SimpleNamespace()
    }
    event = EnvironmentEvent(
        event_type="waving",
        description="synthetic public event",
        timestamp=time.time(),
    )
    context.pending_events.append(event)
    handler = ChatAgentHandler()
    retirement = controller.retire_generation_v1()

    handler._process_pending_events(
        context,
        parent_work_v1=parent,
    )

    assert context.pending_events == [event]
    assert controller.snapshot_v1().unreleased_work_by_generation == (
        (1, 1),
    )
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    assert controller.shutdown()


def test_compaction_return_after_retirement_cannot_mutate_memory():
    controller, runtime, parent = _runtime_pair()
    memory = SessionMemoryManager(
        MemoryConfig(
            compact_threshold=2,
            compact_keep_recent=1,
            compact_save_transcript=False,
        )
    )
    memory.record_user_input("one")
    memory.record_assistant_response("two")
    memory.record_user_input("three")
    completions = _BlockingCompactCompletions()
    context = ChatAgentContext("session")
    context.config = ChatAgentConfig()
    context.work_runtime_v1 = runtime
    context.memory = memory
    context.llm_client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )
    handler = ChatAgentHandler()

    compact_thread = threading.Thread(
        target=lambda: handler._check_compact(
            context,
            work_v1=parent,
        )
    )
    compact_thread.start()
    assert completions.started.wait(timeout=2)
    retirement = controller.retire_generation_v1()
    completions.release.set()
    compact_thread.join(timeout=3)

    assert not compact_thread.is_alive()
    assert memory.turn_count == 3
    assert "stale summary" not in memory.working_memory.get_full_transcript()
    assert runtime.release_work_v1(parent)
    assert controller.wait_for_cleanup_v1(
        retirement.cleanup_fence
    )
    memory.destroy()
    assert controller.shutdown()

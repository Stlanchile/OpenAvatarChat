"""
SpawnAgentTool — unified entry point for spawning sub-agents.

LLM decides when to spawn a sub-agent, which type, and whether it runs async.
Supports two backends:
  - local: fork independent messages[], run LLM loop, return summary
  - oc: delegate to OpenClaw via oac-bridge HTTP channel, return result
"""

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from loguru import logger

from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import SessionWorkRuntimeV1
from handlers.agent.tools.base_tool import BaseTool, ToolResult

if TYPE_CHECKING:
    from handlers.agent.oc_bridge.oc_reply_bridge import OcReplyBridge


@dataclass
class AgentDef:
    """Definition of a sub-agent type (data-driven)."""
    name: str
    when_to_use: str
    model: str = "qwen-turbo"
    system_prompt: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    async_default: bool = True
    backend: str = "local"  # "local" | "oc" | "auto"
    max_rounds: int = 3


DEFAULT_AGENT_DEFS: Dict[str, AgentDef] = {
    "explore": AgentDef(
        name="explore",
        when_to_use="搜索、分析、理解信息，只读操作。适合需要查找记忆或理解上下文的场景。",
        model="qwen-turbo",
        system_prompt="你是一个信息搜索和分析助手。请搜索相关信息并给出精炼的分析摘要。",
        allowed_tools=["memory_search"],
        async_default=True,
        backend="local",
        max_rounds=3,
    ),
    "analyst": AgentDef(
        name="analyst",
        when_to_use="多步推理分析，整理报告。适合需要综合多个信息源进行分析的场景。",
        model="qwen-plus",
        system_prompt="你是一个分析助手。请综合分析提供的信息，输出结构化的分析报告。",
        allowed_tools=["memory_search"],
        async_default=True,
        backend="local",
        max_rounds=5,
    ),
    "oc_delegate": AgentDef(
        name="oc_delegate",
        when_to_use="需要 OpenClaw 完整 agent 能力的复杂后台任务。如文件操作、代码执行、定时任务管理等。",
        model="",
        system_prompt="",
        allowed_tools=[],
        async_default=True,
        backend="oc",
        max_rounds=1,
    ),
}


class SpawnAgentTool(BaseTool):
    """Unified tool for spawning sub-agents of different types."""

    def __init__(
        self,
        agent_defs: Optional[Dict[str, AgentDef]] = None,
        llm_client=None,
        oc_channel_client=None,
        tool_registry=None,
        oac_session_id: str = "",
        work_runtime_v1: SessionWorkRuntimeV1 | None = None,
        oc_reply_bridge: "OcReplyBridge | None" = None,
    ):
        self._agent_defs = agent_defs or DEFAULT_AGENT_DEFS
        self._llm_client = llm_client
        self._oc_channel_client = oc_channel_client
        self._tool_registry = tool_registry
        self._oac_session_id = oac_session_id
        self._work_runtime_v1 = work_runtime_v1
        self._oc_reply_bridge = oc_reply_bridge

    @property
    def name(self) -> str:
        return "spawn_agent"

    @property
    def description(self) -> str:
        type_descs = []
        for name, defn in self._agent_defs.items():
            type_descs.append(f"  - {name}: {defn.when_to_use}")
        types_str = "\n".join(type_descs)
        return (
            f"创建一个子 Agent 来处理独立任务。子 Agent 有自己的上下文，"
            f"完成后只返回结果摘要。"
            f"当用户要求设置提醒、创建/修改/取消日程、安排后台任务、执行多步骤功能操作时，"
            f"应优先使用本工具把任务交给 OpenClaw，而不是直接口头声称“已完成”。"
            f"\n\n可用的 agent 类型：\n{types_str}"
        )

    @property
    def parameters(self) -> dict:
        type_names = list(self._agent_defs.keys())
        return {
            "type": "object",
            "properties": {
                "subagent_type": {
                    "type": "string",
                    "enum": type_names,
                    "description": "子 Agent 类型",
                },
                "prompt": {
                    "type": "string",
                    "description": "交给子 Agent 的任务描述",
                },
                "run_background": {
                    "type": "boolean",
                    "description": "是否异步执行（默认 true）",
                },
            },
            "required": ["subagent_type", "prompt"],
        }

    def execute(self, args: Dict[str, Any]) -> ToolResult:
        agent_type = args.get("subagent_type", "explore")
        prompt = args.get("prompt", "")
        run_bg = args.get("run_background", True)

        if not prompt:
            return ToolResult(success=False, error="prompt is required")

        agent_def = self._agent_defs.get(agent_type)
        if not agent_def:
            return ToolResult(
                success=False,
                error=f"Unknown agent type: {agent_type}. "
                      f"Available: {list(self._agent_defs.keys())}",
            )

        backend = agent_def.backend
        if backend == "auto":
            backend = "oc" if self._oc_channel_client else "local"

        logger.info(
            f"[SpawnAgent] Spawning '{agent_type}' (backend={backend}, bg={run_bg})"
        )

        if backend == "oc":
            return self._execute_oc(agent_def, prompt, run_bg)
        return self._execute_local(agent_def, prompt, run_bg)

    def _execute_local(
        self, agent_def: AgentDef, prompt: str, run_bg: bool
    ) -> ToolResult:
        """Run a local sub-agent with its own messages and LLM loop."""
        if not self._llm_client:
            return ToolResult(success=False, error="No LLM client for local agent")

        start = time.time()
        messages = [
            {"role": "system", "content": agent_def.system_prompt or "你是一个助手。"},
            {"role": "user", "content": prompt},
        ]

        runtime = self._work_runtime_v1
        parent_work = runtime.current_work_v1() if runtime is not None else None
        envelope_ref = (
            runtime.current_envelope_ref_v1()
            if runtime is not None
            else None
        )
        if runtime is not None and parent_work is None:
            return ToolResult(
                success=False,
                error="local sub-agent work authority unavailable",
            )

        final_text = ""
        for round_idx in range(agent_def.max_rounds):
            llm_work = None
            try:
                if runtime is not None:
                    if (
                        parent_work is None
                        or not runtime.validate_work_v1(
                            parent_work,
                            WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
                        )
                    ):
                        return ToolResult(
                            success=False,
                            error="local sub-agent work retired",
                        )
                    try:
                        llm_work = runtime.register_child_work_v1(
                            parent_work,
                            WorkOperationKindV1.CHAT_AGENT_LLM,
                        )
                    except WorkAdmissionDeniedV1:
                        return ToolResult(
                            success=False,
                            error="local sub-agent work admission denied",
                        )

                if runtime is None or llm_work is None:
                    resp = self._llm_client.chat.completions.create(
                        model=agent_def.model,
                        messages=messages,
                        tools=self._build_tool_specs(
                            agent_def.allowed_tools
                        ),
                    )
                else:
                    with runtime.activate_work_v1(
                        llm_work,
                        envelope_ref,
                    ):
                        if not runtime.validate_work_v1(
                            llm_work,
                            WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
                        ):
                            return ToolResult(
                                success=False,
                                error="local sub-agent work retired",
                            )
                        resp = self._llm_client.chat.completions.create(
                            model=agent_def.model,
                            messages=messages,
                            tools=self._build_tool_specs(
                                agent_def.allowed_tools
                            ),
                        )
                        if not runtime.validate_work_v1(
                            llm_work,
                            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                        ):
                            return ToolResult(
                                success=False,
                                error="local sub-agent work retired",
                            )

                choice = resp.choices[0]

                if choice.finish_reason == "stop":
                    final_text = choice.message.content or ""
                    break

                if choice.message.tool_calls:
                    if runtime is None:
                        messages.append(choice.message)
                    elif llm_work is None or not runtime.perform_if_live_v1(
                        llm_work,
                        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                        lambda: messages.append(choice.message),
                    ):
                        return ToolResult(
                            success=False,
                            error="local sub-agent work retired",
                        )
                    for tc in choice.message.tool_calls:
                        fn = tc.function
                        tool_args = (
                            json.loads(fn.arguments)
                            if fn.arguments
                            else {}
                        )
                        if runtime is None:
                            tool = (
                                self._tool_registry.get(fn.name)
                                if self._tool_registry
                                else None
                            )
                            if tool:
                                result = tool.execute(tool_args)
                            else:
                                result = None
                        else:
                            if (
                                llm_work is None
                                or not runtime.validate_work_v1(
                                    llm_work,
                                    WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
                                )
                            ):
                                return ToolResult(
                                    success=False,
                                    error="local sub-agent work retired",
                                )
                            if self._tool_registry is None:
                                result = None
                            else:
                                try:
                                    tool_work = (
                                        runtime.register_child_work_v1(
                                            llm_work,
                                            WorkOperationKindV1.TOOL_EXECUTION,
                                        )
                                    )
                                except WorkAdmissionDeniedV1:
                                    return ToolResult(
                                        success=False,
                                        error=(
                                            "local sub-agent tool "
                                            "admission denied"
                                        ),
                                    )
                                try:
                                    with runtime.activate_work_v1(
                                        tool_work,
                                        envelope_ref,
                                    ):
                                        result = self._tool_registry.execute(
                                            fn.name,
                                            tool_args,
                                            _work_runtime_v1=runtime,
                                            _registered_work_v1=tool_work,
                                        )
                                finally:
                                    runtime.release_work_v1(tool_work)
                                if result is None:
                                    return ToolResult(
                                        success=False,
                                        error="local sub-agent work retired",
                                    )

                        tool_message = {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": (
                                result.to_content_str()
                                if result is not None
                                else '{"error": "no tool registry"}'
                            ),
                        }
                        if runtime is None:
                            messages.append(tool_message)
                        elif (
                            llm_work is None
                            or not runtime.perform_if_live_v1(
                                llm_work,
                                WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
                                lambda: messages.append(tool_message),
                            )
                        ):
                            return ToolResult(
                                success=False,
                                error="local sub-agent work retired",
                            )
            except Exception as error:
                if self._work_runtime_v1 is None:
                    logger.error(
                        f"[SpawnAgent] local agent round "
                        f"{round_idx} failed: {error}"
                    )
                else:
                    logger.error("LOCAL_SUBAGENT_ROUND_FAILED_V1")
                break
            finally:
                if runtime is not None and llm_work is not None:
                    runtime.release_work_v1(llm_work)

        duration = time.time() - start
        if runtime is None:
            logger.info(
                f"[SpawnAgent] local agent '{agent_def.name}' done in "
                f"{duration:.1f}s, result: {len(final_text)} chars"
            )
        else:
            if parent_work is None or not runtime.validate_work_v1(
                parent_work,
                WorkValidationBoundaryV1.BEFORE_COMPLETION,
            ):
                return ToolResult(
                    success=False,
                    error="local sub-agent work retired",
                )
            logger.info("LOCAL_SUBAGENT_COMPLETED_V1")

        return ToolResult(
            success=True,
            data={
                "content": final_text or "(子 Agent 未返回内容)",
                "agent_type": agent_def.name,
                "backend": "local",
                "duration_ms": int(duration * 1000),
            },
        )

    def _execute_oc(
        self, agent_def: AgentDef, prompt: str, run_bg: bool
    ) -> ToolResult:
        """Delegate to OpenClaw via oac-bridge HTTP channel."""
        if not self._oc_channel_client:
            return ToolResult(success=False, error="OC channel client not available")
        if not self._oac_session_id:
            return ToolResult(success=False, error="No OAC session ID configured")

        start = time.time()
        runtime = self._work_runtime_v1
        bridge = self._oc_reply_bridge
        pending = None
        if runtime is not None:
            parent = runtime.current_work_v1()
            if parent is None or bridge is None:
                return ToolResult(
                    success=False,
                    error="OC secure work authority unavailable",
                )
            pending = bridge.begin_request_v1(
                parent,
                runtime.current_envelope_ref_v1(),
                route_to_notifications=run_bg,
            )
            if pending is None:
                return ToolResult(
                    success=False,
                    error="OC secure work admission denied",
                )
            child_work = pending.work_item_v1.registered_work
            if not runtime.validate_work_v1(
                child_work,
                WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
            ):
                bridge.cancel_request_v1(pending)
                return ToolResult(
                    success=False,
                    error="OC secure work admission denied",
                )

        if runtime is None or pending is None:
            result = self._oc_channel_client.send_message(
                oac_session_id=self._oac_session_id,
                text=prompt,
                sender_name="OAC Agent",
            )
        else:
            with runtime.activate_work_v1(
                pending.work_item_v1.registered_work,
                pending.work_item_v1.envelope_ref,
            ):
                result = self._oc_channel_client.send_message(
                    oac_session_id=self._oac_session_id,
                    text=prompt,
                    sender_name="OAC Agent",
                    correlation_id=pending.correlation_id,
                )
            if not runtime.validate_work_v1(
                pending.work_item_v1.registered_work,
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
            ) and not pending.terminal_event.is_set():
                return ToolResult(
                    success=False,
                    error="OC secure work retired",
                )

        if "error" in result:
            if pending is not None and bridge is not None:
                bridge.cancel_request_v1(pending)
            return ToolResult(success=False, error=result["error"])

        if run_bg:
            duration = time.time() - start
            result_data = {
                "status": "submitted_async",
                "content": (
                    "任务已通过 OAC Bridge 渠道提交给 OpenClaw 处理，"
                    "完成后会通知你。"
                ),
                "agent_type": agent_def.name,
                "backend": "oc_channel",
                "duration_ms": int(duration * 1000),
            }
            if runtime is None:
                result_data["oac_session_id"] = self._oac_session_id
            return ToolResult(
                success=True,
                data=result_data,
            )

        if pending is None or bridge is None:
            reply_msg = self._oc_channel_client.reply_queue.wait_for_reply(
                self._oac_session_id,
                timeout=60.0,
            )
        else:
            reply_msg = None
            wait_deadline = time.monotonic() + 60.0
            while time.monotonic() < wait_deadline:
                reply_msg = bridge.wait_for_reply_v1(
                    pending,
                    timeout=min(
                        0.1,
                        wait_deadline - time.monotonic(),
                    ),
                )
                if reply_msg is not None:
                    break
                if pending.work_item_v1.cancellation.is_cancelled:
                    return ToolResult(
                        success=False,
                        error="OC secure work retired",
                    )
            if reply_msg is None:
                bridge.cancel_request_v1(pending)
        duration = time.time() - start

        reply_text = reply_msg.text if reply_msg else ""
        result_data = {
            "content": reply_text or "OC 已接收任务（暂无即时结果）",
            "agent_type": agent_def.name,
            "backend": "oc_channel",
            "duration_ms": int(duration * 1000),
        }
        if runtime is None:
            result_data["oac_session_id"] = self._oac_session_id
        return ToolResult(
            success=True,
            data=result_data,
        )

    def _build_tool_specs(self, allowed_tools: List[str]) -> Optional[List[dict]]:
        if not allowed_tools or not self._tool_registry:
            return None
        specs = []
        for tool_name in allowed_tools:
            tool = self._tool_registry.get(tool_name)
            if tool:
                specs.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    },
                })
        return specs if specs else None

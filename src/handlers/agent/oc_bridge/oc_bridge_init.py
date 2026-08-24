"""
OC Bridge initialisation — creates all OC-related components on a
``ChatAgentContext`` and kicks off the background MCP connection thread.

Extracted from ``ChatAgentHandler._init_oc_bridge`` so the main agent
file stays free of OC wiring details.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from loguru import logger

from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

if TYPE_CHECKING:
    from handlers.agent.chat_agent_handler import ChatAgentContext


def init_oc_bridge(context: "ChatAgentContext") -> None:
    """Initialise every OC Bridge component on *context*.

    1. PersonaSnapshot / TaskQueue / TaskMirror / PendingConfirmations (instant)
    2. OC Channel Client (HTTP) + reply bridge
    3. Plugin Tools MCP (background thread, non-blocking)
    """
    if context.work_runtime_v1 is not None:
        _init_secure_oc_bridge_v1(context)
        return

    oc_cfg = context.config.oc_bridge

    # ── Instant components (no network) ──
    from handlers.agent.oc_bridge.persona_snapshot_mgr import PersonaSnapshotManager
    from handlers.agent.oc_bridge.task_notification_queue import TaskNotificationQueue
    from handlers.agent.oc_bridge.task_mirror import TaskMirror
    from handlers.agent.oc_bridge.pending_confirmations import PendingConfirmationsManager

    context.persona_mgr = PersonaSnapshotManager(
        refresh_interval=oc_cfg.persona_refresh_interval,
        local_default=context.config.persona_snapshot,
    )
    context.task_queue = TaskNotificationQueue()
    context.task_mirror = TaskMirror(mirror_path=oc_cfg.task_mirror_path)
    context.pending_confirmations = PendingConfirmationsManager()

    # ── OC Channel Client (oac-bridge HTTP channel) ──
    from handlers.agent.oc_bridge.oc_channel_client import OcChannelClient
    context.oc_channel_client = OcChannelClient(
        gateway_url=oc_cfg.gateway_http_url,
        webhook_path=oc_cfg.webhook_path,
        token=oc_cfg.token,
        callback_port=oc_cfg.callback_port,
    )
    if context.oc_channel_client.start():
        logger.info(
            f"[ChatAgent] OC Channel Client started "
            f"(callback: {context.oc_channel_client.callback_url})"
        )
        from handlers.agent.oc_bridge.oc_reply_bridge import OcReplyBridge
        context.oc_reply_bridge = OcReplyBridge.register(
            channel_client=context.oc_channel_client,
            session_id=context.session_id,
            task_queue=context.task_queue,
            pending_mgr=context.pending_confirmations,
            proactive_wake=context._proactive_wake,
        )
    else:
        logger.warning("[ChatAgent] OC Channel Client failed to start")
        context.oc_channel_client = None

    # ── Plugin Tools MCP (background thread) ──
    from handlers.agent.oc_bridge.mcp_client import OcMcpClient
    context.oc_mcp_client = OcMcpClient(
        plugin_tools_cmd=oc_cfg.plugin_tools_cmd,
    )

    def _connect_and_register():
        try:
            connected = context.oc_mcp_client.start()
            if connected:
                logger.info("[ChatAgent] OC MCP Client connected (background)")
                if context.persona_mgr:
                    context.persona_mgr.set_mcp_client(context.oc_mcp_client)
                from handlers.agent.oc_bridge.oc_tools import register_oc_tools
                register_oc_tools(context.tool_registry, context.oc_mcp_client)
                _register_oc_tools(context)
            else:
                logger.warning(
                    "[ChatAgent] OC MCP Client failed to connect, degrading gracefully"
                )
        except Exception as e:
            logger.warning(f"[ChatAgent] OC Bridge MCP init failed: {e}")

    t = threading.Thread(
        target=_connect_and_register,
        daemon=True,
        name=f"oc-mcp-init-{context.session_id}",
    )
    t.start()
    logger.info("[ChatAgent] OC Bridge MCP connecting in background (non-blocking)")


def _init_secure_oc_bridge_v1(context: "ChatAgentContext") -> None:
    """Initialize OC only under exact-generation server-owned work."""

    runtime = context.work_runtime_v1
    parent = context.current_work_v1()
    if runtime is None or parent is None:
        logger.error("OC_SECURE_INIT_AUTHORITY_UNAVAILABLE_V1")
        return
    oc_cfg = context.config.oc_bridge

    from handlers.agent.oc_bridge.pending_confirmations import (
        PendingConfirmationsManager,
    )
    from handlers.agent.oc_bridge.persona_snapshot_mgr import (
        PersonaSnapshotManager,
    )
    from handlers.agent.oc_bridge.task_mirror import TaskMirror
    from handlers.agent.oc_bridge.task_notification_queue import (
        TaskNotificationQueue,
    )

    persona_mgr = PersonaSnapshotManager(
        refresh_interval=oc_cfg.persona_refresh_interval,
        local_default=context.config.persona_snapshot,
    )
    task_queue = TaskNotificationQueue()
    task_mirror = TaskMirror(mirror_path=oc_cfg.task_mirror_path)
    pending_confirmations = PendingConfirmationsManager()

    def install_local_components() -> None:
        context.persona_mgr = persona_mgr
        context.task_queue = task_queue
        context.task_mirror = task_mirror
        context.pending_confirmations = pending_confirmations

    if not runtime.perform_if_live_v1(
        parent,
        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        install_local_components,
    ):
        return

    from handlers.agent.oc_bridge.oc_channel_client import (
        OcChannelClient,
    )

    channel_client = OcChannelClient(
        gateway_url=oc_cfg.gateway_http_url,
        webhook_path=oc_cfg.webhook_path,
        token=oc_cfg.token,
        callback_port=oc_cfg.callback_port,
    )
    channel_client.reply_queue.require_registered_correlation_v1()
    if not runtime.validate_work_v1(
        parent,
        WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
    ):
        return
    channel_started = channel_client.start()
    if (
        not channel_started
        or not runtime.validate_work_v1(
            parent,
            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
        )
    ):
        if channel_started:
            channel_client.stop()
        logger.warning("OC_SECURE_CHANNEL_START_FAILED_V1")
        return

    from handlers.agent.oc_bridge.oc_reply_bridge import OcReplyBridge

    reply_bridge = OcReplyBridge.register(
        channel_client=channel_client,
        session_id=context.session_id,
        task_queue=task_queue,
        pending_mgr=pending_confirmations,
        proactive_wake=context._proactive_wake,
        work_runtime_v1=runtime,
    )

    def install_channel() -> None:
        context.oc_channel_client = channel_client
        context.oc_reply_bridge = reply_bridge

    if (
        reply_bridge is None
        or not runtime.perform_if_live_v1(
            parent,
            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
            install_channel,
        )
    ):
        if reply_bridge is not None:
            reply_bridge.close_v1()
        channel_client.stop()
        return

    from handlers.agent.oc_bridge.mcp_client import OcMcpClient

    mcp_client = OcMcpClient(
        plugin_tools_cmd=oc_cfg.plugin_tools_cmd,
    )
    try:
        mcp_work = runtime.register_child_work_v1(
            parent,
            WorkOperationKindV1.GENERIC_EXTERNAL_CALL,
        )
    except WorkAdmissionDeniedV1:
        return

    def connect_and_register() -> None:
        try:
            with context.activate_work_v1(mcp_work, None):
                if not runtime.validate_work_v1(
                    mcp_work,
                    WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
                ):
                    return
                connected = mcp_client.start()
                if (
                    not connected
                    or not runtime.validate_work_v1(
                        mcp_work,
                        WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                    )
                ):
                    if connected:
                        mcp_client.stop()
                    return

                def install_mcp_tools() -> None:
                    context.oc_mcp_client = mcp_client
                    if context.persona_mgr:
                        context.persona_mgr.set_mcp_client(mcp_client)
                    from handlers.agent.oc_bridge.oc_tools import (
                        register_oc_tools,
                    )
                    register_oc_tools(context.tool_registry, mcp_client)
                    _register_oc_tools(context)

                if not runtime.perform_if_live_v1(
                    mcp_work,
                    WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                    install_mcp_tools,
                ):
                    mcp_client.stop()
        except Exception:
            logger.warning("OC_SECURE_MCP_INIT_FAILED_V1")
        finally:
            runtime.release_work_v1(mcp_work)

    init_thread = threading.Thread(
        target=connect_and_register,
        daemon=True,
        name="oc_mcp_init_v1",
    )

    def install_init_thread() -> None:
        context._oc_mcp_init_thread_v1 = init_thread

    if not runtime.perform_if_live_v1(
        mcp_work,
        WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
        install_init_thread,
    ):
        runtime.release_work_v1(mcp_work)
        return
    init_thread.start()
    logger.info("OC_SECURE_MCP_INIT_STARTED_V1")


def _register_oc_tools(context: "ChatAgentContext") -> None:
    """Register OC-specific agent tools (SpawnAgent, ExecApprove, PendingConfirmations)."""
    from handlers.agent.tools.spawn_agent import SpawnAgentTool
    context.tool_registry.register(SpawnAgentTool(
        llm_client=context.llm_client,
        oc_channel_client=context.oc_channel_client,
        tool_registry=context.tool_registry,
        oac_session_id=context.session_id,
        work_runtime_v1=context.work_runtime_v1,
        oc_reply_bridge=context.oc_reply_bridge,
    ))
    from handlers.agent.tools.exec_approve import ExecApproveTool
    context.tool_registry.register(ExecApproveTool(
        oc_channel_client=context.oc_channel_client,
        oac_session_id=context.session_id,
        pending_mgr=context.pending_confirmations,
        work_runtime_v1=context.work_runtime_v1,
    ))
    from handlers.agent.tools.pending_confirmations_tool import PendingConfirmationsTool
    context.tool_registry.register(PendingConfirmationsTool(
        manager=context.pending_confirmations,
        work_runtime_v1=context.work_runtime_v1,
    ))

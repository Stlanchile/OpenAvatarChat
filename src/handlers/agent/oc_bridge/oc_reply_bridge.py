"""
OcReplyBridge — routes incoming OC replies (via oac-bridge HTTP callback)
into the agent's TaskNotificationQueue, handling exec-approval parsing,
duplicate detection, external resolution, and proactive-wake signalling.

Extracted from chat_agent_handler._register_oc_reply_bridge to keep the
main agent file free of OC-specific parsing logic.
"""

import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Set

from loguru import logger

from chat_engine.security.dispatch import SecurityEnvelopeReferenceV1
from chat_engine.security.session_work_controller import (
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    RegisteredWorkV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)
from chat_engine.security.work_runtime import (
    SessionWorkRuntimeV1,
    WorkBoundItemV1,
)
from handlers.agent.oc_bridge.oc_channel_client import OcChannelClient, OcReplyMessage
from handlers.agent.oc_bridge.pending_confirmations import PendingConfirmationsManager
from handlers.agent.oc_bridge.task_notification_queue import (
    TaskNotification,
    TaskNotificationQueue,
)

# ── Regex patterns for OC reply parsing ──

# Pattern A: OC agent text — "/approve <id> <decision>"
_APPROVAL_CMD_RE = re.compile(
    r"/approve\s+([0-9a-f]{6,})\s+(allow-once|allow-always|deny)"
)
_PENDING_CMD_RE = re.compile(
    r"Pending command:\s*```\w*\s*\n(.+?)\n```", re.DOTALL
)

# Pattern B: OC forwarder text — "Exec approval required\nID: <full-uuid>\nCommand: `...`"
_FORWARDER_RE = re.compile(
    r"Exec approval required\s*\nID:\s*([0-9a-f-]{8,})"
)
_FORWARDER_CMD_RE = re.compile(
    r"Command:\s*`([^`]+)`"
)

# Bare resolution echo from OC (e.g. Web UI click)
_APPROVAL_RESOLVE_RE = re.compile(
    r"^/approve\s+([0-9a-f]{6,})\s+(allow-once|allow-always|deny)\s*$"
)


def parse_exec_approval(text: str) -> Optional[dict]:
    """Extract structured approval info from either OC reply format.

    Returns ``{"approval_id": str, "command": str}`` or ``None``.
    """
    # Try Pattern A (OC agent text)
    m = _APPROVAL_CMD_RE.search(text)
    if m:
        approval_id = m.group(1)
        cmd_match = _PENDING_CMD_RE.search(text)
        command = cmd_match.group(1).strip() if cmd_match else "(unknown)"
        return {"approval_id": approval_id, "command": command}

    # Try Pattern B (OC forwarder text)
    m = _FORWARDER_RE.search(text)
    if m:
        full_id = m.group(1)
        approval_id = full_id[:8] if len(full_id) > 8 else full_id
        cmd_match = _FORWARDER_CMD_RE.search(text)
        command = cmd_match.group(1).strip() if cmd_match else "(unknown)"
        return {"approval_id": approval_id, "command": command}

    return None


def format_approval_notification(info: dict) -> str:
    """Build an agent-readable notification for an exec approval request."""
    return (
        f"[exec-approval-needed]\n"
        f"OpenClaw 后台需要你的批准才能执行以下命令：\n"
        f"  命令: {info['command']}\n"
        f"  approval_id: {info['approval_id']}\n"
        f"请向用户简要说明要执行的命令内容，并告知三种选项：\n"
        f"  1. 同意（仅这次）→ decision=\"allow-once\"\n"
        f"  2. 始终同意（后续同类不再询问）→ decision=\"allow-always\"\n"
        f"  3. 拒绝 → decision=\"deny\"\n"
        f"若同一任务已有多次类似审批，应主动建议用户选择\"始终同意\"。\n"
        f"得到用户回答后立即调用 exec_approve 工具。"
    )


def try_handle_external_resolution(
    text: str,
    pending_mgr: Optional[PendingConfirmationsManager],
) -> bool:
    """If *text* is a bare ``/approve <id> <decision>`` echoed by OC
    (i.e. the approval was resolved externally via Web UI / another
    channel), mark the pending item as resolved and signal the caller
    to drop the message.  Returns ``True`` if handled."""
    m = _APPROVAL_RESOLVE_RE.match(text.strip())
    if not m:
        return False
    aid = m.group(1)
    decision = m.group(2)
    if pending_mgr:
        resolved_status = "denied" if decision == "deny" else "confirmed"
        try:
            pending_mgr.upsert([{"id": aid, "status": resolved_status}])
            logger.info("OC_EXTERNAL_APPROVAL_RESOLVED_V1")
        except Exception:
            logger.warning("OC_EXTERNAL_APPROVAL_RESOLUTION_FAILED_V1")
    return True


@dataclass(slots=True, repr=False)
class OcPendingRequestV1:
    """Server-owned correlation to one exact-generation child work item."""

    correlation_id: str
    work_item_v1: WorkBoundItemV1
    route_to_notifications: bool
    reply_event: threading.Event = field(default_factory=threading.Event)
    terminal_event: threading.Event = field(default_factory=threading.Event)
    reply: OcReplyMessage | None = None
    deadline_timer_v1: threading.Timer | None = field(
        default=None,
        repr=False,
    )
    callback_lock_v1: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )

    def __repr__(self) -> str:
        return "OcPendingRequestV1(<redacted>)"


class OcReplyBridge:
    """Stateful bridge that routes OcReplyQueue messages into a
    TaskNotificationQueue, with exec-approval awareness."""

    def __init__(
        self,
        task_queue: TaskNotificationQueue,
        pending_mgr: Optional[PendingConfirmationsManager],
        proactive_wake: threading.Event,
        channel_client: OcChannelClient,
        work_runtime_v1: SessionWorkRuntimeV1 | None = None,
    ):
        self._task_queue = task_queue
        self._pending_mgr = pending_mgr
        self._proactive_wake = proactive_wake
        self._channel_client = channel_client
        self._work_runtime_v1 = work_runtime_v1
        self._seen_approval_ids: Set[str] = set()
        self._pending_lock_v1 = threading.Lock()
        self._pending_v1: dict[str, OcPendingRequestV1] = {}

    def begin_request_v1(
        self,
        parent_work_v1: RegisteredWorkV1,
        envelope_ref_v1: SecurityEnvelopeReferenceV1 | None,
        *,
        route_to_notifications: bool,
    ) -> OcPendingRequestV1 | None:
        runtime = self._work_runtime_v1
        if runtime is None or not runtime.validate_work_v1(
            parent_work_v1,
            WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
        ):
            return None
        try:
            child_work = runtime.register_child_work_v1(
                parent_work_v1,
                WorkOperationKindV1.TOOL_EXECUTION,
            )
        except WorkAdmissionDeniedV1:
            return None
        pending = OcPendingRequestV1(
            correlation_id=(
                "ocw1_" + secrets.token_urlsafe(18)
            ),
            work_item_v1=WorkBoundItemV1(
                payload=None,
                registered_work=child_work,
                envelope_ref=envelope_ref_v1,
            ),
            route_to_notifications=route_to_notifications,
        )

        def install_pending() -> None:
            with self._pending_lock_v1:
                self._pending_v1[pending.correlation_id] = pending
            self._channel_client.reply_queue.register_callback(
                pending.correlation_id,
                self.handle_reply,
            )

        if not runtime.perform_if_live_v1(
            child_work,
            WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
            install_pending,
        ):
            pending.work_item_v1.release_once_v1(runtime)
            return None
        deadline_timer = threading.Timer(
            max(
                0.0,
                child_work.fence.deadline_monotonic - time.monotonic(),
            ),
            self.cancel_request_v1,
            args=(pending,),
        )
        deadline_timer.daemon = True
        with self._pending_lock_v1:
            if self._pending_v1.get(pending.correlation_id) is pending:
                pending.deadline_timer_v1 = deadline_timer
                deadline_timer.start()
        return pending

    def cancel_request_v1(
        self,
        pending: OcPendingRequestV1,
    ) -> None:
        removed = False
        with pending.callback_lock_v1:
            with self._pending_lock_v1:
                canonical = self._pending_v1.get(
                    pending.correlation_id
                )
                if canonical is pending:
                    self._pending_v1.pop(
                        pending.correlation_id,
                        None,
                    )
                    removed = True
        if not removed:
            return
        pending.terminal_event.set()
        pending.reply_event.set()
        if pending.deadline_timer_v1 is not None:
            pending.deadline_timer_v1.cancel()
        self._channel_client.reply_queue.unregister_callback(
            pending.correlation_id
        )
        runtime = self._work_runtime_v1
        if runtime is not None:
            pending.work_item_v1.release_once_v1(runtime)

    @staticmethod
    def wait_for_reply_v1(
        pending: OcPendingRequestV1,
        timeout: float,
    ) -> OcReplyMessage | None:
        pending.reply_event.wait(timeout=timeout)
        return pending.reply

    def pending_count_v1(self) -> int:
        with self._pending_lock_v1:
            return len(self._pending_v1)

    def reset_generation_state_v1(self) -> None:
        """Discard only deferred semantic state, not running work leases."""

        self._seen_approval_ids.clear()

    def close_v1(self) -> None:
        with self._pending_lock_v1:
            pending_items = tuple(self._pending_v1.values())
        for pending in pending_items:
            self.cancel_request_v1(pending)

    def _route_reply_v1(self, msg: OcReplyMessage) -> None:
        if self._task_queue is None:
            return

        if try_handle_external_resolution(msg.text, self._pending_mgr):
            return

        approval_info = parse_exec_approval(msg.text)
        if approval_info:
            aid = approval_info["approval_id"]
            if aid in self._seen_approval_ids:
                logger.debug("OC_DUPLICATE_APPROVAL_DROPPED_V1")
                return
            self._seen_approval_ids.add(aid)
            summary = format_approval_notification(approval_info)
            status = "approval_needed"
            task_id = f"exec-approval-{approval_info['approval_id']}"
            merge_key = f"approval-{approval_info['approval_id']}"
            if self._pending_mgr:
                try:
                    self._pending_mgr.upsert([{
                        "id": approval_info["approval_id"],
                        "text": f"exec: {approval_info['command'][:60]}",
                        "status": "pending",
                    }])
                except Exception:
                    logger.warning("OC_PENDING_CONFIRMATION_UPDATE_FAILED_V1")
        else:
            summary = msg.text
            status = (
                msg.status
                if msg.status in {"progress", "completed", "failed"}
                else "progress"
            )
            reply_key = (
                msg.correlation_id
                if self._work_runtime_v1 is not None
                else msg.oac_session_id
            )
            task_id = f"oc-reply-{reply_key}"
            merge_key = reply_key

        notification = TaskNotification(
            task_id=task_id,
            status=status,
            result_summary=summary,
            timestamp=msg.timestamp,
            merge_key=merge_key,
        )
        self._task_queue.push(notification)
        logger.info("OC_REPLY_ROUTED_V1")

        if status == "approval_needed":
            self._proactive_wake.set()
            logger.info("OC_PROACTIVE_WAKE_SET_V1")

    def handle_reply(self, msg: OcReplyMessage) -> bool:
        """Route a callback only through its server-owned pending work."""

        runtime = self._work_runtime_v1
        if runtime is None:
            self._route_reply_v1(msg)
            return False
        correlation_id = msg.correlation_id
        if not correlation_id:
            logger.info("LATE_CALLBACK_DROPPED OC_REPLY_MISSING")
            return True
        with self._pending_lock_v1:
            pending = self._pending_v1.get(correlation_id)
        if pending is None:
            logger.info("LATE_CALLBACK_DROPPED OC_REPLY_UNKNOWN")
            return True
        with pending.callback_lock_v1:
            with self._pending_lock_v1:
                if self._pending_v1.get(correlation_id) is not pending:
                    logger.info("LATE_CALLBACK_DROPPED OC_REPLY_UNKNOWN")
                    return True

            callback_status = msg.status
            if callback_status not in {
                "progress",
                "completed",
                "failed",
            }:
                logger.info(
                    "LATE_CALLBACK_DROPPED OC_REPLY_STATUS_INVALID"
                )
                return True
            terminal = callback_status in {"completed", "failed"}
            work = pending.work_item_v1.registered_work
            live = runtime.validate_work_v1(
                work,
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
            )
            try:
                if live:
                    def deliver_reply() -> None:
                        if pending.route_to_notifications:
                            self._route_reply_v1(msg)
                        elif terminal:
                            pending.reply = msg
                            pending.reply_event.set()
                        if terminal:
                            pending.terminal_event.set()

                    if not runtime.perform_if_live_v1(
                        work,
                        WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
                        deliver_reply,
                    ):
                        runtime.log_late_drop_v1(
                            work,
                            "OC_REPLY_MUTATION_RACE",
                        )
                else:
                    runtime.log_late_drop_v1(
                        work,
                        "OC_REPLY_AFTER_RETIREMENT",
                    )
                return True
            finally:
                if terminal:
                    with self._pending_lock_v1:
                        if (
                            self._pending_v1.get(correlation_id)
                            is pending
                        ):
                            self._pending_v1.pop(
                                correlation_id,
                                None,
                            )
                    self._channel_client.reply_queue.unregister_callback(
                        correlation_id
                    )
                    pending.terminal_event.set()
                    pending.reply_event.set()
                    if pending.deadline_timer_v1 is not None:
                        pending.deadline_timer_v1.cancel()
                    pending.work_item_v1.release_once_v1(runtime)

    @staticmethod
    def register(
        channel_client: Optional[OcChannelClient],
        session_id: str,
        task_queue: TaskNotificationQueue,
        pending_mgr: Optional[PendingConfirmationsManager],
        proactive_wake: threading.Event,
        work_runtime_v1: SessionWorkRuntimeV1 | None = None,
    ) -> Optional["OcReplyBridge"]:
        """Create an OcReplyBridge and register it on the channel client.

        Returns the bridge instance (or ``None`` if *channel_client* is not
        available).
        """
        if not channel_client:
            return None

        bridge = OcReplyBridge(
            task_queue,
            pending_mgr,
            proactive_wake,
            channel_client,
            work_runtime_v1,
        )
        if work_runtime_v1 is not None:
            channel_client.reply_queue.require_registered_correlation_v1()
            logger.info("OC_SECURE_REPLY_BRIDGE_READY_V1")
            return bridge

        channel_client.reply_queue.register_callback(
            session_id, bridge.handle_reply
        )
        prefixed_key = f"oac-bridge:{session_id}"
        channel_client.reply_queue.register_callback(
            prefixed_key, bridge.handle_reply
        )
        logger.info("OC_LEGACY_REPLY_BRIDGE_READY_V1")
        return bridge

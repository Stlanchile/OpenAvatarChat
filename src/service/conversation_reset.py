"""Conversation-only reset for one exact live ChatSession."""

from __future__ import annotations

from chat_engine.core.chat_session import ChatSession
from handlers.agent.chat_agent_handler import ChatAgentContext, ChatAgentHandler


def reset_exact_chat_session_conversation(session: ChatSession) -> bool:
    """Reset prompt/history state while preserving the session and transports."""
    if not isinstance(session, ChatSession):
        raise TypeError("expected ChatSession")
    matches = [
        record.env
        for record in session.handlers.values()
        if isinstance(record.env.handler, ChatAgentHandler)
        and isinstance(record.env.context, ChatAgentContext)
    ]
    if len(matches) != 1:
        return False
    handler_env = matches[0]
    return handler_env.handler.reset_conversation(
        handler_env.context,
        clear_session_history=session.clear_conversation_history,
    )


__all__ = ["reset_exact_chat_session_conversation"]

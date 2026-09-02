"""Conversation-only reset for one exact live ChatSession."""

from __future__ import annotations

from typing import TYPE_CHECKING

from chat_engine.core.chat_session import ChatSession
from handlers.agent.chat_agent_handler import ChatAgentContext, ChatAgentHandler

if TYPE_CHECKING:
    from handlers.llm.openai_compatible.llm_handler_openai_compatible import (
        HandlerLLM,
        LLMContext,
    )


def _reset_openai_compatible_conversation(
    session: ChatSession,
    handler: HandlerLLM,
    context: LLMContext,
) -> bool:
    del handler
    if context.active_stream_keys:
        return False
    context.input_texts = ""
    context.output_texts = ""
    context.current_image = None
    if context.history is not None:
        context.history.message_history.clear()
    session.clear_conversation_history()
    return True


def reset_exact_chat_session_conversation(session: ChatSession) -> bool:
    """Reset prompt/history state while preserving the session and transports."""
    if not isinstance(session, ChatSession):
        raise TypeError("expected ChatSession")

    def reset_conversation() -> bool:
        chat_agent_matches = [
            record.env
            for record in session.handlers.values()
            if isinstance(record.env.handler, ChatAgentHandler)
            and isinstance(record.env.context, ChatAgentContext)
        ]
        if len(chat_agent_matches) == 1:
            handler_env = chat_agent_matches[0]
            return handler_env.handler.reset_conversation(
                handler_env.context,
                clear_session_history=session.clear_conversation_history,
            )
        if chat_agent_matches:
            return False

        from handlers.llm.openai_compatible.llm_handler_openai_compatible import (
            HandlerLLM,
            LLMContext,
        )

        llm_matches = [
            record.env
            for record in session.handlers.values()
            if isinstance(record.env.handler, HandlerLLM)
            and isinstance(record.env.context, LLMContext)
        ]
        if len(llm_matches) != 1:
            return False
        handler_env = llm_matches[0]
        return _reset_openai_compatible_conversation(
            session,
            handler_env.handler,
            handler_env.context,
        )

    return session.reset_conversation_and_admission_context(reset_conversation)


__all__ = ["reset_exact_chat_session_conversation"]

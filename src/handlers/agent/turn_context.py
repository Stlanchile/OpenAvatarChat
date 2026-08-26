"""Strongly typed, ephemeral ChatAgent turn attachments."""

from __future__ import annotations

from dataclasses import dataclass

from certificate_capture.contracts.admission_notice_release import (
    SanitizedAdmissionContextV1,
)

CHAT_AGENT_TURN_CONTEXT_SCHEMA_VERSION_V1 = "oac.chat-agent-turn-context.v1"


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class ChatAgentTurnContextV1:
    """The sole M7 attachment; it is never serialized into session state."""

    sanitized_admission_notice: SanitizedAdmissionContextV1
    schema_version: str = CHAT_AGENT_TURN_CONTEXT_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if (
            self.schema_version != CHAT_AGENT_TURN_CONTEXT_SCHEMA_VERSION_V1
            or type(self.sanitized_admission_notice) is not SanitizedAdmissionContextV1
        ):
            raise ValueError("invalid ChatAgent turn context")

    def __repr__(self) -> str:
        return (
            "ChatAgentTurnContextV1("
            f"schema_version={self.schema_version!r}, "
            "sanitized_admission_notice=<ephemeral>)"
        )


__all__ = [
    "CHAT_AGENT_TURN_CONTEXT_SCHEMA_VERSION_V1",
    "ChatAgentTurnContextV1",
]

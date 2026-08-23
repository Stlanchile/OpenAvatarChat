"""Immutable core-issued session epoch values."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from chat_engine.security.ids import UINT64_MAX_V1


@dataclass(frozen=True, slots=True, repr=False)
class SessionEpochV1:
    """Identity and monotonic generation for one runtime session instance.

    This value describes an epoch; it is not, by itself, authorization.
    SessionWorkControllerV1 accepts only its own registered WorkFenceV1
    references as temporal authority.
    """

    session_instance_id: uuid.UUID
    generation: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.session_instance_id, uuid.UUID)
            or self.session_instance_id.version != 7
            or self.session_instance_id.variant != uuid.RFC_4122
        ):
            raise ValueError("session_instance_id must be an RFC 9562 UUIDv7")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= UINT64_MAX_V1
        ):
            raise ValueError("generation must be a non-zero uint64")

    def __repr__(self) -> str:
        return (
            "SessionEpochV1("
            "session_instance_id=<opaque>, "
            f"generation={self.generation})"
        )

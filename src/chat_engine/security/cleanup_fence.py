"""Narrow cleanup authority for exactly one retired session generation."""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from enum import Enum

from chat_engine.security.epochs import SessionEpochV1


class CleanupActionV1(str, Enum):
    """The only semantic actions a cleanup fence may authorize."""

    CANCEL = "CANCEL"
    PURGE = "PURGE"
    DELETE = "DELETE"
    RELEASE = "RELEASE"
    CLOSE = "CLOSE"
    ACK_CLEANUP = "ACK_CLEANUP"


class RetiredGenerationCleanupStateV1(str, Enum):
    PENDING = "PENDING"
    COMPLETE = "COMPLETE"
    TIMED_OUT = "TIMED_OUT"


@dataclass(frozen=True, slots=True, repr=False)
class RetiredGenerationCleanupFenceV1:
    """Authenticated cleanup-only reference for one retired generation."""

    authority_id: str
    session_instance_id: uuid.UUID
    retired_generation: int
    cleanup_id: uuid.UUID
    deadline_monotonic: float
    authenticator: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.session_instance_id, uuid.UUID):
            raise TypeError("session_instance_id must be a UUID")
        if not isinstance(self.cleanup_id, uuid.UUID):
            raise TypeError("cleanup_id must be a UUID")
        if (
            isinstance(self.retired_generation, bool)
            or not isinstance(self.retired_generation, int)
            or self.retired_generation < 1
        ):
            raise ValueError("retired_generation must be positive")
        if (
            isinstance(self.deadline_monotonic, bool)
            or not isinstance(self.deadline_monotonic, (int, float))
            or not math.isfinite(self.deadline_monotonic)
        ):
            raise ValueError("deadline_monotonic must be finite")

    def __repr__(self) -> str:
        return "RetiredGenerationCleanupFenceV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class CleanupTokenV1:
    """Single-release lease for a registered cleanup participant."""

    authority_id: str
    session_epoch: SessionEpochV1
    token_id: uuid.UUID
    authenticator: bytes

    def __repr__(self) -> str:
        return "CleanupTokenV1(<opaque>)"


@dataclass(frozen=True, slots=True)
class GenerationRetirementV1:
    new_epoch: SessionEpochV1
    cleanup_fence: RetiredGenerationCleanupFenceV1


@dataclass(frozen=True, slots=True)
class RetiredGenerationCleanupStatusV1:
    retired_generation: int
    cleanup_id: uuid.UUID
    state: RetiredGenerationCleanupStateV1
    outstanding_work_tokens: int
    outstanding_cleanup_tokens: int
    deadline_monotonic: float

"""Immutable server-issued capture epoch values."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import UINT64_MAX_V1


@dataclass(frozen=True, slots=True, repr=False)
class CaptureEpochV1:
    """One capture identity bound to one exact session generation.

    The value is descriptive authority, not a bearer capability. Coordinator
    mutation seams accept only their own canonical instance.
    """

    session_epoch: SessionEpochV1
    capture_id: uuid.UUID
    capture_seq: int

    def __post_init__(self) -> None:
        if not isinstance(self.session_epoch, SessionEpochV1):
            raise TypeError("session_epoch must be SessionEpochV1")
        if (
            not isinstance(self.capture_id, uuid.UUID)
            or self.capture_id.version != 7
            or self.capture_id.variant != uuid.RFC_4122
        ):
            raise ValueError("capture_id must be an RFC 9562 UUIDv7")
        if (
            isinstance(self.capture_seq, bool)
            or not isinstance(self.capture_seq, int)
            or not 1 <= self.capture_seq <= UINT64_MAX_V1
        ):
            raise ValueError("capture_seq must be a non-zero uint64")

    def __repr__(self) -> str:
        return (
            "CaptureEpochV1("
            f"session_generation={self.session_epoch.generation}, "
            "capture_id=<opaque>, "
            f"capture_seq={self.capture_seq})"
        )


__all__ = ["CaptureEpochV1"]

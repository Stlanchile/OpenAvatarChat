"""Strict external models for the private Milestone 4B HTTP API."""

from __future__ import annotations

import uuid
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from certificate_capture.protocol import SealOutcomeV1, SealReasonCodeV1
from certificate_capture.state import CaptureStateV1
from chat_engine.security.ids import UINT64_MAX_V1

OpaqueProfileIdV1 = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        strict=True,
    ),
]


class _StrictRequestV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )

    request_id: uuid.UUID
    control_seq: int = Field(ge=1, le=UINT64_MAX_V1, strict=True)

    @field_validator("request_id", mode="before")
    @classmethod
    def _canonical_request_id_v1(cls, value: object) -> object:
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError("request_id must be a canonical UUID")
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError):
            raise ValueError("request_id must be a canonical UUID") from None
        if (
            str(parsed) != value
            or parsed.variant != uuid.RFC_4122
            or parsed.version not in {4, 7}
        ):
            raise ValueError("request_id must be UUIDv4 or UUIDv7")
        return parsed


class BeginCaptureRequestV1(_StrictRequestV1):
    profile_id: OpaqueProfileIdV1


class SealCaptureRequestV1(_StrictRequestV1):
    pass


class EndCaptureRequestV1(_StrictRequestV1):
    pass


class BeginCaptureResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    capture_id: uuid.UUID
    capture_seq: int
    session_generation: int
    state: CaptureStateV1
    capture_capability: str = Field(repr=False)
    expires_at_epoch_seconds: float


class FrameUploadResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    capture_id: uuid.UUID
    capture_seq: int
    frame_seq: int
    state: CaptureStateV1
    encoded_size: int
    decoded_width: int
    decoded_height: int
    accepted_frame_count: int
    remaining_frame_slots: int
    total_accepted_bytes: int


class SealResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    seal_attempt_seq: int
    outcome: SealOutcomeV1
    capture_state: CaptureStateV1
    accepted_frame_count: int
    independent_correlation_groups: int
    remaining_frame_slots: int
    reason_codes: tuple[SealReasonCodeV1, ...]
    restart_required: bool


class CaptureStatusResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    capture_id: uuid.UUID
    capture_seq: int
    state: CaptureStateV1
    accepted_frame_count: int
    remaining_frame_slots: int
    total_accepted_bytes: int
    independent_correlation_groups: int
    inactivity_expires_at_epoch_seconds: float
    last_seal_outcome: SealOutcomeV1 | None = None
    reason_codes: tuple[SealReasonCodeV1, ...] = ()
    restart_required: bool = False


class EndCaptureResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    capture_id: uuid.UUID
    capture_seq: int
    session_generation: int
    state: CaptureStateV1


__all__ = [
    "BeginCaptureRequestV1",
    "BeginCaptureResponseV1",
    "CaptureStatusResponseV1",
    "EndCaptureRequestV1",
    "EndCaptureResponseV1",
    "FrameUploadResponseV1",
    "SealCaptureRequestV1",
    "SealResponseV1",
]

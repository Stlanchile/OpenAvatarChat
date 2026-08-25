"""Private Milestone 4B protocol values with no certificate-derived payloads."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum

from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.state import CaptureStateV1
from chat_engine.security.work_fence import RegisteredWorkV1

MAX_ENCODED_FRAME_BYTES_V1 = 2 * 1024 * 1024
MAX_CAPTURE_FRAMES_V1 = 8
MAX_CAPTURE_ENCODED_BYTES_V1 = 16 * 1024 * 1024
MAX_DECODED_FRAME_PIXELS_V1 = 2_073_600
MAX_DECODED_FRAME_LONG_EDGE_V1 = 1920
MAX_DECODED_FRAME_SHORT_EDGE_V1 = 1080
FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1 = 5.0
CAPTURE_INACTIVITY_SECONDS_V1 = 5 * 60
CAPTURE_BEGIN_MINIMUM_SESSION_REMAINING_SECONDS_V1 = 6 * 60
MAX_CONCURRENT_UPLOADS_PER_CAPTURE_V1 = 2
MAX_OUTSTANDING_CONTROL_MUTATIONS_V1 = 4
MAX_CONTROL_MUTATIONS_PER_SESSION_V1 = 64
MINIMUM_MOCK_UNIQUE_FRAMES_V1 = 3


class CaptureProtocolReasonV1(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_PROFILE = "UNSUPPORTED_PROFILE"
    SESSION_LIFETIME_INSUFFICIENT = "SESSION_LIFETIME_INSUFFICIENT"
    CAPTURE_ACCESS_DENIED = "CAPTURE_ACCESS_DENIED"
    CAPTURE_BUSY = "CAPTURE_BUSY"
    CAPTURE_STATE_INVALID = "CAPTURE_STATE_INVALID"
    CAPTURE_EXPIRED = "CAPTURE_EXPIRED"
    CONTROL_SEQUENCE_STALE = "CONTROL_SEQUENCE_STALE"
    CONTROL_SEQUENCE_GAP = "CONTROL_SEQUENCE_GAP"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    CONTROL_CAPACITY_EXCEEDED = "CONTROL_CAPACITY_EXCEEDED"
    CONTROL_BUSY = "CONTROL_BUSY"
    UPLOAD_BUSY = "UPLOAD_BUSY"
    FRAME_SEQUENCE_INVALID = "FRAME_SEQUENCE_INVALID"
    FRAME_SEQUENCE_CONFLICT = "FRAME_SEQUENCE_CONFLICT"
    FRAME_LIMIT_REACHED = "FRAME_LIMIT_REACHED"
    CAPTURE_BYTE_LIMIT_REACHED = "CAPTURE_BYTE_LIMIT_REACHED"
    JPEG_REQUIRED = "JPEG_REQUIRED"
    FRAME_TOO_LARGE = "FRAME_TOO_LARGE"
    JPEG_INVALID = "JPEG_INVALID"
    JPEG_DIMENSIONS_EXCEEDED = "JPEG_DIMENSIONS_EXCEEDED"
    FRAME_BODY_UNAVAILABLE = "FRAME_BODY_UNAVAILABLE"
    PROCESSOR_NOT_READY = "PROCESSOR_NOT_READY"
    CAPTURE_FAILED_CLOSED = "CAPTURE_FAILED_CLOSED"
    CAPTURE_OPERATION_FAILED = "CAPTURE_OPERATION_FAILED"


class CaptureProtocolErrorV1(RuntimeError):
    """Stable value-free protocol failure used below the HTTP boundary."""

    __slots__ = ("reason", "reason_code")

    def __init__(self, reason: CaptureProtocolReasonV1) -> None:
        self.reason = reason
        self.reason_code = reason.value
        super().__init__(f"certificate capture operation failed ({reason.value})")


class SealOutcomeV1(str, Enum):
    BUILD_STARTED = "BUILD_STARTED"
    NEEDS_RECAPTURE = "NEEDS_RECAPTURE"


class SealReasonCodeV1(str, Enum):
    TOO_FEW_UNIQUE_FRAMES = "TOO_FEW_UNIQUE_FRAMES"
    BLUR = "BLUR"
    GLARE = "GLARE"
    CROP = "CROP"
    SKEW = "SKEW"
    DUPLICATE_DOMINANCE = "DUPLICATE_DOMINANCE"
    DOCUMENT_NOT_DETECTED = "DOCUMENT_NOT_DETECTED"


@dataclass(frozen=True, slots=True, repr=False)
class BeginCaptureGrantV1:
    capture_epoch: CaptureEpochV1
    capture_capability: str
    expires_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "BeginCaptureGrantV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FrameUploadPermitV1:
    permit_id: uuid.UUID
    capture_epoch: CaptureEpochV1
    frame_seq: int
    registered_work: RegisteredWorkV1

    def __repr__(self) -> str:
        return "FrameUploadPermitV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedJpegFrameV1:
    encoded_size: int
    decoded_width: int
    decoded_height: int
    sha256_digest: bytes

    def __repr__(self) -> str:
        return "ValidatedJpegFrameV1(<private-metadata>)"


@dataclass(frozen=True, slots=True)
class FrameUploadResultV1:
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


@dataclass(frozen=True, slots=True)
class SealResultV1:
    seal_attempt_seq: int
    outcome: SealOutcomeV1
    capture_state: CaptureStateV1
    accepted_frame_count: int
    independent_correlation_groups: int
    remaining_frame_slots: int
    reason_codes: tuple[SealReasonCodeV1, ...]
    restart_required: bool


@dataclass(frozen=True, slots=True)
class CapturePublicStatusV1:
    capture_id: uuid.UUID
    capture_seq: int
    state: CaptureStateV1
    accepted_frame_count: int
    remaining_frame_slots: int
    total_accepted_bytes: int
    independent_correlation_groups: int
    inactivity_expires_at_epoch_seconds: float
    last_seal_outcome: SealOutcomeV1 | None
    reason_codes: tuple[SealReasonCodeV1, ...]
    restart_required: bool


@dataclass(frozen=True, slots=True)
class EndCaptureResultV1:
    capture_id: uuid.UUID
    capture_seq: int
    session_generation: int
    state: CaptureStateV1


@dataclass(frozen=True, slots=True)
class MockProcessingInputV1:
    """Non-image lifecycle input accepted only by a constructor-injected test double."""

    capture_seq: int
    accepted_frame_count: int
    independent_correlation_groups: int


__all__ = [
    "CAPTURE_BEGIN_MINIMUM_SESSION_REMAINING_SECONDS_V1",
    "CAPTURE_INACTIVITY_SECONDS_V1",
    "FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1",
    "MAX_CAPTURE_ENCODED_BYTES_V1",
    "MAX_CAPTURE_FRAMES_V1",
    "MAX_CONCURRENT_UPLOADS_PER_CAPTURE_V1",
    "MAX_CONTROL_MUTATIONS_PER_SESSION_V1",
    "MAX_DECODED_FRAME_LONG_EDGE_V1",
    "MAX_DECODED_FRAME_PIXELS_V1",
    "MAX_DECODED_FRAME_SHORT_EDGE_V1",
    "MAX_ENCODED_FRAME_BYTES_V1",
    "MAX_OUTSTANDING_CONTROL_MUTATIONS_V1",
    "MINIMUM_MOCK_UNIQUE_FRAMES_V1",
    "BeginCaptureGrantV1",
    "CaptureProtocolErrorV1",
    "CaptureProtocolReasonV1",
    "CapturePublicStatusV1",
    "EndCaptureResultV1",
    "FrameUploadPermitV1",
    "FrameUploadResultV1",
    "MockProcessingInputV1",
    "SealOutcomeV1",
    "SealReasonCodeV1",
    "SealResultV1",
    "ValidatedJpegFrameV1",
]

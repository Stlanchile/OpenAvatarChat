from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class RecognitionStateLiteV1(str, Enum):
    CREATED = "CREATED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class RecognitionErrorReasonLiteV1(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_IMAGE = "INVALID_IMAGE"
    IMAGE_TOO_LARGE = "IMAGE_TOO_LARGE"
    IMAGE_DIMENSIONS_UNSUPPORTED = "IMAGE_DIMENSIONS_UNSUPPORTED"
    TOO_MANY_FRAMES = "TOO_MANY_FRAMES"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    SERVICE_BUSY = "SERVICE_BUSY"
    RECOGNITION_ALREADY_ACTIVE = "RECOGNITION_ALREADY_ACTIVE"
    RECOGNITION_NOT_FOUND = "RECOGNITION_NOT_FOUND"
    RECOGNITION_CANCELLED = "RECOGNITION_CANCELLED"
    RECOGNITION_EXPIRED = "RECOGNITION_EXPIRED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class RecognitionJobContextLiteV1:
    recognition_id: str
    expires_at_monotonic: float
    cancel_event: asyncio.Event = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ValidatedAdmissionFrameLiteV1:
    frame_index: int
    jpeg_bytes: bytes = field(repr=False)
    encoded_size: int
    width: int
    height: int
    exif_orientation: int = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.jpeg_bytes) is not bytes:
            raise TypeError("jpeg_bytes must be immutable bytes")
        if not 1 <= self.frame_index <= 3:
            raise ValueError("frame_index must be between 1 and 3")
        if self.encoded_size != len(self.jpeg_bytes) or self.encoded_size < 1:
            raise ValueError("encoded_size must match non-empty jpeg_bytes")
        if self.width < 1 or self.height < 1:
            raise ValueError("logical dimensions must be positive")
        if self.exif_orientation not in range(1, 9):
            raise ValueError("exif_orientation must be between 1 and 8")


class RecognitionProcessorLiteV1(Protocol):
    async def process(
        self,
        context: RecognitionJobContextLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> None:
        """Process one bounded tuple of validated L2 JPEG frames."""


@dataclass(frozen=True, slots=True)
class RecognitionJobLiteV1:
    recognition_id: str
    owning_session_id: str = field(repr=False)
    state: RecognitionStateLiteV1
    created_at_monotonic: float
    expires_at_monotonic: float
    reason: RecognitionErrorReasonLiteV1 | None = None


class AdmissionNoticeLiteError(Exception):
    def __init__(self, reason: RecognitionErrorReasonLiteV1):
        super().__init__(reason.value)
        self.reason = reason

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

MAX_OCR_SPANS_PER_FRAME_LITE_V1 = 128
MAX_OCR_CHARACTERS_PER_SPAN_LITE_V1 = 512
MAX_OCR_UTF8_BYTES_PER_SPAN_LITE_V1 = 2_048
MAX_OCR_AGGREGATE_CHARACTERS_PER_FRAME_LITE_V1 = 8_192
MAX_OCR_AGGREGATE_UTF8_BYTES_PER_FRAME_LITE_V1 = 32_768
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


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
    UNSUPPORTED_NOTICE = "UNSUPPORTED_NOTICE"
    INSUFFICIENT_NOTICE = "INSUFFICIENT_NOTICE"
    MAJOR_NOT_RECOGNIZED = "MAJOR_NOT_RECOGNIZED"
    AMBIGUOUS_NOTICE = "AMBIGUOUS_NOTICE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class RecognitionJobContextLiteV1:
    recognition_id: str
    expires_at_monotonic: float
    cancel_event: asyncio.Event = field(repr=False, compare=False)
    session_is_current: Callable[[], bool] = field(
        default=lambda: True,
        repr=False,
        compare=False,
    )


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


@dataclass(frozen=True, slots=True)
class OcrSpanLiteV1:
    text: str
    polygon: tuple[
        tuple[float, float],
        tuple[float, float],
        tuple[float, float],
        tuple[float, float],
    ]
    score: float

    def __post_init__(self) -> None:
        if type(self.text) is not str or not self.text:
            raise ValueError("OCR span text must be a non-empty string")
        if self.text != self.text.strip() or "\x00" in self.text:
            raise ValueError("OCR span text must have transport whitespace stripped")
        try:
            encoded_text = self.text.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("OCR span text must be valid UTF-8") from None
        if (
            len(self.text) > MAX_OCR_CHARACTERS_PER_SPAN_LITE_V1
            or len(encoded_text) > MAX_OCR_UTF8_BYTES_PER_SPAN_LITE_V1
        ):
            raise ValueError("OCR span text exceeds the bounded contract")

        if type(self.polygon) is not tuple or len(self.polygon) != 4:
            raise ValueError("OCR span polygon must contain exactly four points")
        for point in self.polygon:
            if type(point) is not tuple or len(point) != 2:
                raise ValueError("OCR span polygon points must be coordinate pairs")
            for coordinate in point:
                if (
                    isinstance(coordinate, bool)
                    or not isinstance(coordinate, (int, float))
                    or not math.isfinite(coordinate)
                    or not 0.0 <= coordinate <= 1.0
                ):
                    raise ValueError(
                        "OCR span polygon coordinates must be finite and normalized"
                    )

        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, (int, float))
            or not math.isfinite(self.score)
            or not 0.0 <= self.score <= 1.0
        ):
            raise ValueError("OCR recognition score must be finite and in [0, 1]")


@dataclass(frozen=True, slots=True)
class OcrFrameLiteV1:
    frame_index: int
    spans: tuple[OcrSpanLiteV1, ...]

    def __post_init__(self) -> None:
        if type(self.frame_index) is not int or not 1 <= self.frame_index <= 3:
            raise ValueError("OCR frame index must be between 1 and 3")
        if type(self.spans) is not tuple or any(
            not isinstance(span, OcrSpanLiteV1) for span in self.spans
        ):
            raise TypeError("OCR frame spans must be an immutable typed tuple")
        if len(self.spans) > MAX_OCR_SPANS_PER_FRAME_LITE_V1:
            raise ValueError("OCR frame contains too many spans")
        if (
            sum(len(span.text) for span in self.spans)
            > MAX_OCR_AGGREGATE_CHARACTERS_PER_FRAME_LITE_V1
            or sum(len(span.text.encode("utf-8")) for span in self.spans)
            > MAX_OCR_AGGREGATE_UTF8_BYTES_PER_FRAME_LITE_V1
        ):
            raise ValueError("OCR frame text exceeds the aggregate bound")


@dataclass(frozen=True, slots=True)
class OcrBatchLiteV1:
    frames: tuple[OcrFrameLiteV1, ...]

    def __post_init__(self) -> None:
        if (
            type(self.frames) is not tuple
            or not 1 <= len(self.frames) <= 3
            or any(not isinstance(frame, OcrFrameLiteV1) for frame in self.frames)
        ):
            raise TypeError("OCR batch frames must be a bounded immutable typed tuple")
        indices = tuple(frame.frame_index for frame in self.frames)
        if indices != tuple(range(1, len(self.frames) + 1)):
            raise ValueError("OCR batch frame indices must be unique and contiguous")


@dataclass(frozen=True, slots=True)
class OcrRuntimeIdentityLiteV1:
    backend: str
    device: str
    thread_count: int
    paddle_version: str
    paddleocr_version: str
    paddlex_version: str
    model_manifest_sha256: str

    def __post_init__(self) -> None:
        if self.backend != "paddle_static" or self.device != "cpu":
            raise ValueError("OCR runtime identity must name the fixed CPU backend")
        if type(self.thread_count) is not int or not 1 <= self.thread_count <= 64:
            raise ValueError("OCR runtime thread count is invalid")
        for version in (
            self.paddle_version,
            self.paddleocr_version,
            self.paddlex_version,
        ):
            if type(version) is not str or not version or len(version) > 64:
                raise ValueError("OCR runtime package version is invalid")
        if (
            type(self.model_manifest_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.model_manifest_sha256) is None
        ):
            raise ValueError("OCR runtime manifest hash is invalid")


class RecognitionProcessorLiteV1(Protocol):
    async def process(
        self,
        context: RecognitionJobContextLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> object:
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

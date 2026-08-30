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


class RecognitionProcessorLiteV1(Protocol):
    async def process(self, context: RecognitionJobContextLiteV1) -> None:
        """Complete one payload-free L1 control-plane operation."""


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

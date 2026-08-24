"""Non-sensitive, stable audit events for core security enforcement."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum

from loguru import logger


class SecurityAuditEventCodeV1(str, Enum):
    DISPATCH_DENIED = "DISPATCH_DENIED"
    ENVELOPE_MISSING = "ENVELOPE_MISSING"
    CONSUMER_NOT_AUTHORIZED = "CONSUMER_NOT_AUTHORIZED"
    ILLEGAL_CLASSIFICATION_DOWNGRADE = "ILLEGAL_CLASSIFICATION_DOWNGRADE"
    INVALID_LINEAGE = "INVALID_LINEAGE"
    PRIVATE_EGRESS_DENIED = "PRIVATE_EGRESS_DENIED"
    REGISTRY_FAILURE = "REGISTRY_FAILURE"
    WORK_ADMISSION_DENIED = "WORK_ADMISSION_DENIED"
    STALE_WORK_FENCE = "STALE_WORK_FENCE"
    WORK_CANCELLED = "WORK_CANCELLED"
    WORK_DEADLINE_EXPIRED = "WORK_DEADLINE_EXPIRED"
    GENERATION_RETIRED = "GENERATION_RETIRED"
    GENERATION_OVERFLOW = "GENERATION_OVERFLOW"
    CLEANUP_TIMEOUT = "CLEANUP_TIMEOUT"
    INVALID_CLEANUP_FENCE = "INVALID_CLEANUP_FENCE"
    WORK_TOKEN_INVARIANT_VIOLATION = "WORK_TOKEN_INVARIANT_VIOLATION"
    CAPTURE_ENTERING = "CAPTURE_ENTERING"
    CAPTURE_QUIESCING = "CAPTURE_QUIESCING"
    CAPTURE_ARMED = "CAPTURE_ARMED"
    CAPTURE_ENDING = "CAPTURE_ENDING"
    CAPTURE_FAILED_CLOSED = "CAPTURE_FAILED_CLOSED"
    CAPTURE_RESUMED = "CAPTURE_RESUMED"
    CAPTURE_TRANSITION_REJECTED = "CAPTURE_TRANSITION_REJECTED"
    CAPTURE_QUIESCENCE_TIMEOUT = "CAPTURE_QUIESCENCE_TIMEOUT"
    CAPTURE_CLEANUP_TIMEOUT = "CAPTURE_CLEANUP_TIMEOUT"


@dataclass(frozen=True, slots=True)
class SecurityAuditEventV1:
    """Value-free audit record containing opaque core identifiers only."""

    code: SecurityAuditEventCodeV1
    recorded_at_monotonic: float
    envelope_id: str | None = None
    consumer_capability_id: str | None = None
    dispatch_id: str | None = None


class CoreSecurityAuditV1:
    """Small session-local audit buffer plus stable redacted log events."""

    def __init__(self, max_events: int = 1024):
        self._events: deque[SecurityAuditEventV1] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def record(
        self,
        code: SecurityAuditEventCodeV1,
        *,
        envelope_id: str | None = None,
        consumer_capability_id: str | None = None,
        dispatch_id: str | None = None,
    ) -> SecurityAuditEventV1:
        event = SecurityAuditEventV1(
            code=code,
            recorded_at_monotonic=time.monotonic(),
            envelope_id=envelope_id,
            consumer_capability_id=consumer_capability_id,
            dispatch_id=dispatch_id,
        )
        with self._lock:
            self._events.append(event)
        logger.bind(
            security_event_code=code.value,
            envelope_id=envelope_id,
            consumer_capability_id=consumer_capability_id,
            dispatch_id=dispatch_id,
        ).warning("SECURITY_ENFORCEMENT_V1")
        return event

    def snapshot(self) -> tuple[SecurityAuditEventV1, ...]:
        with self._lock:
            return tuple(self._events)

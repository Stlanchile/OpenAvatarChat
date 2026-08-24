"""Non-sensitive internal CaptureCoordinator status snapshots."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from certificate_capture.state import (
    CaptureFailureReasonV1,
    CaptureStateV1,
    CaptureTransitionKindV1,
    CaptureTransitionPhaseV1,
)


@dataclass(frozen=True, slots=True)
class CaptureStatusV1:
    state: CaptureStateV1
    capture_id: uuid.UUID | None
    capture_seq: int
    session_generation: int
    transition_id: uuid.UUID | None
    transition_kind: CaptureTransitionKindV1 | None
    transition_phase: CaptureTransitionPhaseV1 | None
    failure_reason_code: CaptureFailureReasonV1 | None
    normal_application_admission_open: bool
    quiescence_complete: bool
    shutdown_started: bool
    destroyed: bool


__all__ = ["CaptureStatusV1"]

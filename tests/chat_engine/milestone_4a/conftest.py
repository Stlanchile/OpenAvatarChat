from __future__ import annotations

import threading
from dataclasses import dataclass, field

import pytest

from certificate_capture.coordinator import CaptureCoordinatorV1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_runtime import SessionWorkRuntimeV1


@dataclass
class CaptureHarnessV1:
    cleanup_timeout_seconds: float = 0.25
    feature_enabled: bool = True
    security_live: bool = True
    session_live: bool = True
    drain_error: bool = False
    semantic_error: bool = False
    drain_generations: list[int] = field(default_factory=list)
    semantic_generations: list[int] = field(default_factory=list)
    termination_requests: int = 0

    def __post_init__(self) -> None:
        self._live_lock = threading.Lock()
        self.controller = SessionWorkControllerV1._create_for_test_v1(
            cleanup_timeout_seconds=self.cleanup_timeout_seconds,
        )
        self.coordinator, self.gate = CaptureCoordinatorV1._create_for_session_v1(
            work_controller=self.controller,
            feature_enabled_v1=lambda: self.feature_enabled,
            security_authority_usable_v1=lambda: self.security_live,
            session_live_action_v1=self.perform_if_session_live,
            quiescence_drain_v1=self.drain,
            semantic_cleanup_v1=self.clear_semantics,
            failure_terminator_v1=self.request_termination,
        )
        self.runtime = SessionWorkRuntimeV1(
            self.controller,
            normal_application_admission=self.gate,
        )

    def perform_if_session_live(self, action) -> bool:
        with self._live_lock:
            if not self.session_live:
                return False
            action()
            return True

    def drain(self, new_epoch) -> None:
        self.drain_generations.append(new_epoch.generation)
        if self.drain_error:
            raise RuntimeError("synthetic drain failure")

    def clear_semantics(self, new_epoch) -> None:
        self.semantic_generations.append(new_epoch.generation)
        if self.semantic_error:
            raise RuntimeError("synthetic semantic failure")

    def request_termination(self) -> None:
        self.termination_requests += 1


@pytest.fixture
def capture_harness_factory():
    created: list[CaptureHarnessV1] = []

    def create(**kwargs) -> CaptureHarnessV1:
        harness = CaptureHarnessV1(**kwargs)
        created.append(harness)
        return harness

    yield create

    for harness in created:
        harness.coordinator._start_shutdown_v1()

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = PROJECT_ROOT / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)


class FakeMonotonicV1:
    def __init__(self, initial: float = 1000.0):
        self._value = initial
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._value

    def advance(self, seconds: float) -> float:
        with self._lock:
            self._value += seconds
            return self._value


@pytest.fixture
def fake_clock():
    return FakeMonotonicV1()


@pytest.fixture
def controller(fake_clock):
    return SessionWorkControllerV1._create_for_test_v1(
        monotonic_clock=fake_clock,
        cleanup_timeout_seconds=10.0,
    )

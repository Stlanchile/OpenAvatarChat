from __future__ import annotations

import io
import threading
import time
import uuid
from dataclasses import dataclass, field

import pytest_asyncio
from PIL import Image

from certificate_capture.coordinator import CaptureCoordinatorV1
from certificate_capture.frame_ingress import validate_private_jpeg_v1
from certificate_capture.private_authority import (
    PrivateEvidenceAuthorityV1,
)
from certificate_capture.protocol import BeginCaptureGrantV1
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)


@dataclass
class ManualClockV1:
    epoch_seconds: float = 2_000_000_000.0
    monotonic_seconds: float = 10_000.0
    _real_started: float = field(
        default_factory=time.monotonic,
        init=False,
        repr=False,
    )

    def wall(self) -> float:
        return self.epoch_seconds

    def monotonic(self) -> float:
        return self.monotonic_seconds + (
            time.monotonic() - self._real_started
        )

    def advance(self, seconds: float) -> None:
        self.epoch_seconds += seconds
        self.monotonic_seconds += seconds


@dataclass
class CaptureProtocolHarnessV1:
    processor: object | None = None
    cleanup_timeout_seconds: float = 0.25
    clock: ManualClockV1 = field(default_factory=ManualClockV1)
    session_live: bool = True
    security_live: bool = True
    feature_enabled: bool = True
    termination_requests: int = 0

    session_id: str = "cs1_test-session"
    owner_issuer: str = "https://issuer.example.test"
    owner_subject: str = "owner"

    def __post_init__(self) -> None:
        self._live_lock = threading.Lock()
        self.controller = SessionWorkControllerV1._create_for_test_v1(
            monotonic_clock=self.clock.monotonic,
            cleanup_timeout_seconds=self.cleanup_timeout_seconds,
        )
        self.security_authority, self.security_registrar = (
            SecurityAuthorityV1.create_v1()
        )
        self.private_evidence_authority = (
            PrivateEvidenceAuthorityV1._create_for_session_v1(
                security_authority=self.security_authority,
                registrar=self.security_registrar,
            )
        )
        self.coordinator, self.gate = (
            CaptureCoordinatorV1._create_for_session_v1(
                work_controller=self.controller,
                private_evidence_authority_v1=(
                    self.private_evidence_authority
                ),
                feature_enabled_v1=lambda: self.feature_enabled,
                security_authority_usable_v1=lambda: self.security_live,
                session_live_action_v1=self.perform_if_session_live,
                quiescence_drain_v1=lambda epoch: None,
                semantic_cleanup_v1=lambda epoch: None,
                failure_terminator_v1=self.request_termination,
                _test_processor_v1=self.processor,
                _wall_clock_for_test_v1=self.clock.wall,
                _monotonic_clock_for_test_v1=self.clock.monotonic,
            )
        )

    def perform_if_session_live(self, action) -> bool:
        with self._live_lock:
            if not self.session_live:
                return False
            action()
            return True

    def request_termination(self) -> None:
        self.termination_requests += 1

    async def begin(
        self,
        *,
        request_id: uuid.UUID | None = None,
        control_seq: int = 1,
        profile_id: str = "mock-no-profile-v1",
        remaining_seconds: float = 600.0,
    ) -> BeginCaptureGrantV1:
        return await self.coordinator.begin_capture_protocol_v1(
            request_id=request_id or uuid.uuid4(),
            control_seq=control_seq,
            profile_id=profile_id,
            session_id=self.session_id,
            owner_issuer=self.owner_issuer,
            owner_subject=self.owner_subject,
            session_expires_at_epoch_seconds=(
                self.clock.wall() + remaining_seconds
            ),
        )

    async def upload(
        self,
        grant: BeginCaptureGrantV1,
        *,
        frame_seq: int,
        encoded_frame: bytearray,
    ):
        validated = validate_private_jpeg_v1(encoded_frame)
        permit = await self.coordinator.admit_frame_upload_v1(
            capture_id=grant.capture_epoch.capture_id,
            frame_seq=frame_seq,
            capture_capability=grant.capture_capability,
            session_id=self.session_id,
            owner_issuer=self.owner_issuer,
            owner_subject=self.owner_subject,
        )
        try:
            return await self.coordinator.commit_frame_upload_v1(
                permit,
                validated,
                encoded_frame,
            )
        finally:
            self.coordinator.release_frame_upload_permit_v1(permit)

    def wake_inactivity_timer(self) -> None:
        event = self.coordinator._inactivity_event_v1
        if event is not None:
            event.set()

    async def close(self) -> None:
        await self.coordinator.shutdown_async_v1()
        await self.controller.shutdown_async()
        self.security_authority.close()


def synthetic_jpeg_v1(
    *,
    width: int = 96,
    height: int = 64,
    color: tuple[int, int, int] = (12, 34, 56),
    orientation: int | None = None,
    quality: int = 90,
) -> bytearray:
    output = io.BytesIO()
    image = Image.new("RGB", (width, height), color)
    exif = Image.Exif()
    if orientation is not None:
        exif[274] = orientation
    image.save(
        output,
        format="JPEG",
        quality=quality,
        exif=exif if orientation is not None else b"",
    )
    image.close()
    return bytearray(output.getvalue())


@pytest_asyncio.fixture
async def capture_protocol_harness_factory():
    created: list[CaptureProtocolHarnessV1] = []

    def create(**kwargs) -> CaptureProtocolHarnessV1:
        harness = CaptureProtocolHarnessV1(**kwargs)
        created.append(harness)
        return harness

    yield create

    for harness in created:
        await harness.close()

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest_asyncio

from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    OcrPointV1,
    OcrSpanV1,
    StoredOcrResultV1,
)
from certificate_capture.ocr.client import OcrTimeoutsV1
from certificate_capture.ocr.protocol import (
    OCR_FRAME_PREFIX_BYTES_V1,
    OcrFailureReasonV1,
    OcrHealthStatusV1,
    OcrRequestV1,
    OcrServiceErrorV1,
    encode_ocr_response_frame_v1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.work_fence import WorkOperationKindV1
from tests.chat_engine.milestone_4b.conftest import (
    CaptureProtocolHarnessV1,
    synthetic_jpeg_v1,
)
from tests.chat_engine.milestone_5a.conftest import (
    SYNTHETIC_SHA256_C_V1,
    synthetic_inference_identity_v1,
)

OCR_CANARY_V1 = "M6A_PRIVATE_OCR_CANARY_录取通知"


class SyntheticOcrClientV1:
    def __init__(self, *, text: str = OCR_CANARY_V1) -> None:
        self._identity = synthetic_inference_identity_v1()
        self._qualification_sha256 = SYNTHETIC_SHA256_C_V1
        self.text = text
        self.exchange_count = 0
        self.health_count = 0
        self.closed = False
        self.entered = asyncio.Event()
        self.jpeg_released = asyncio.Event()
        self.release_response = asyncio.Event()
        self.release_response.set()
        self.cancelled_operations: list[object] = []
        self.last_request: OcrRequestV1 | None = None
        self.response_factory = None
        self.before_return = None

    @property
    def expected_identity_v1(self):
        return self._identity

    @property
    def expected_qualification_record_sha256_v1(self) -> str:
        return self._qualification_sha256

    @property
    def work_fence_timeout_seconds_v1(self) -> float:
        return OcrTimeoutsV1().work_fence_timeout_seconds_v1

    async def health_v1(self) -> OcrHealthStatusV1:
        if self.closed:
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
        self.health_count += 1
        return OcrHealthStatusV1(
            request_id=new_uuid7_v1(),
            identity=self._identity,
            qualification_record_sha256=self._qualification_sha256,
            processing_timeout_seconds=30.0,
        )

    def _page_result(self, request: OcrRequestV1) -> OcrPageResultV1:
        span = OcrSpanV1(
            span_id=new_uuid7_v1(),
            text=self.text,
            polygon=(
                OcrPointV1(0.1, 0.1),
                OcrPointV1(0.9, 0.1),
                OcrPointV1(0.9, 0.2),
                OcrPointV1(0.1, 0.2),
            ),
            raw_engine_score=0.875,
        )
        return OcrPageResultV1(
            result_id=new_uuid7_v1(),
            capture_epoch=request.capture_epoch,
            frame_id=request.frame_id,
            inference_identity_sha256=(self._identity.inference_identity_sha256),
            preprocessing_identity=self._identity.preprocessing,
            spans=(span,),
        )

    async def exchange_v1(
        self,
        request,
        jpeg_buffer,
        cancellation,
    ) -> bytes:
        self.exchange_count += 1
        self.last_request = request
        self.entered.set()
        assert jpeg_buffer
        jpeg_buffer.clear()
        self.jpeg_released.set()
        response_wait = asyncio.create_task(self.release_response.wait())
        cancellation_wait = asyncio.create_task(cancellation.wait_async())
        try:
            done, _ = await asyncio.wait(
                {response_wait, cancellation_wait},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if (
                cancellation_wait in done
                and cancellation_wait.result()
                and response_wait not in done
            ):
                raise OcrServiceErrorV1(OcrFailureReasonV1.CANCELLED)
        finally:
            response_wait.cancel()
            cancellation_wait.cancel()
        page_result = (
            self.response_factory(request)
            if self.response_factory is not None
            else self._page_result(request)
        )
        if self.before_return is not None:
            await self.before_return()
        frame = encode_ocr_response_frame_v1(
            request=request,
            result=page_result,
        )
        return frame[OCR_FRAME_PREFIX_BYTES_V1:]

    async def cancel_operation_v1(self, operation_id) -> None:
        self.cancelled_operations.append(operation_id)

    async def close_v1(self) -> None:
        self.closed = True


@dataclass
class Milestone6AHarnessV1:
    protocol: CaptureProtocolHarnessV1 = field(default_factory=CaptureProtocolHarnessV1)
    client: SyntheticOcrClientV1 = field(default_factory=SyntheticOcrClientV1)

    async def install(self) -> None:
        await self.protocol.coordinator._install_private_ocr_service_v1(self.client)

    async def begin_with_frames(self, count: int = 1):
        grant = await self.protocol.begin()
        uploads = []
        for frame_seq in range(1, count + 1):
            uploads.append(
                await self.protocol.upload(
                    grant,
                    frame_seq=frame_seq,
                    encoded_frame=synthetic_jpeg_v1(color=(10 * frame_seq, 20, 30)),
                )
            )
        return grant, tuple(uploads)

    def frame_ids(self, *frame_sequences: int):
        coordinator = self.protocol.coordinator
        return tuple(
            coordinator._frame_records_v1[frame_seq].evidence_frame.frame_id
            for frame_seq in frame_sequences
        )

    async def process(self, grant, *frame_sequences: int):
        return await self.protocol.coordinator._process_private_ocr_frames_v1(
            capture_epoch=grant.capture_epoch,
            frame_ids=self.frame_ids(*frame_sequences),
        )

    def read_result(
        self,
        grant,
        receipt: StoredOcrResultV1,
    ) -> OcrPageResultV1:
        coordinator = self.protocol.coordinator
        work = self.protocol.controller.register_work_v1(
            WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
            self.protocol.clock.monotonic() + 30.0,
            _admission_guard_v1=(
                lambda: coordinator._private_store_operation_is_live_v1(
                    grant.capture_epoch
                )
            ),
        )
        try:
            result = coordinator._read_private_ocr_result_for_test_v1(
                capture_epoch=grant.capture_epoch,
                receipt=receipt,
                registered_work=work,
                access=coordinator._private_store_read_access_v1,
            )
            assert isinstance(result, OcrPageResultV1)
            return result
        finally:
            self.protocol.controller.release_work_v1(work.lease)

    async def close(self) -> None:
        await self.protocol.close()


@pytest_asyncio.fixture
async def milestone_6a_harness_factory():
    created: list[Milestone6AHarnessV1] = []

    def create(**kwargs) -> Milestone6AHarnessV1:
        harness = Milestone6AHarnessV1(**kwargs)
        created.append(harness)
        return harness

    yield create

    for harness in created:
        await harness.close()


__all__ = [
    "OCR_CANARY_V1",
    "Milestone6AHarnessV1",
    "SyntheticOcrClientV1",
]

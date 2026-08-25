from __future__ import annotations

from dataclasses import dataclass, field

import pytest_asyncio

from certificate_capture.contracts.admission_notice import (
    AdmissionNoticeExtractionV1,
    StoredAdmissionNoticeExtractionV1,
)
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    OcrPointV1,
    OcrSpanV1,
    StoredOcrResultV1,
)
from certificate_capture.epochs import CaptureEpochV1
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.work_fence import WorkOperationKindV1
from tests.chat_engine.milestone_5a.conftest import (
    synthetic_inference_identity_v1,
)
from tests.chat_engine.milestone_6a.conftest import (
    Milestone6AHarnessV1,
)

EXTRACTION_CANARIES_V1 = (
    "李明",
    "湖北",
    "信息工程学院",
    "计算机应用技术（校企合作）",
)


def synthetic_capture_epoch_v1() -> CaptureEpochV1:
    return CaptureEpochV1(
        session_epoch=SessionEpochV1(new_uuid7_v1(), 1),
        capture_id=new_uuid7_v1(),
        capture_seq=1,
    )


def synthetic_span_v1(
    text: str,
    *,
    x: float,
    y: float,
    width: float,
    height: float = 0.035,
    raw_engine_score: float | None = 0.90,
) -> OcrSpanV1:
    return OcrSpanV1(
        span_id=new_uuid7_v1(),
        text=text,
        polygon=(
            OcrPointV1(x, y),
            OcrPointV1(x + width, y),
            OcrPointV1(x + width, y + height),
            OcrPointV1(x, y + height),
        ),
        raw_engine_score=raw_engine_score,
    )


def standard_admission_spans_v1(
    *,
    name: str = "李明",
    province: str = "湖北",
    college: str = "信息工程学院",
    major: str = "计算机应用技术（校企合作）",
) -> tuple[OcrSpanV1, ...]:
    return (
        synthetic_span_v1(name, x=0.18, y=0.18, width=0.08),
        synthetic_span_v1("同学", x=0.27, y=0.181, width=0.08),
        synthetic_span_v1("：", x=0.355, y=0.18, width=0.015),
        synthetic_span_v1("经", x=0.12, y=0.30, width=0.025),
        synthetic_span_v1(province, x=0.15, y=0.301, width=0.07),
        synthetic_span_v1(
            "省（市、自治区）高等学校招生委员会",
            x=0.225,
            y=0.30,
            width=0.61,
        ),
        synthetic_span_v1(
            "批准，你被录取到我校",
            x=0.12,
            y=0.40,
            width=0.35,
        ),
        synthetic_span_v1(
            college,
            x=0.48,
            y=0.401,
            width=0.25,
        ),
        synthetic_span_v1(
            major,
            x=0.12,
            y=0.50,
            width=0.48,
        ),
        synthetic_span_v1(
            "专业学习",
            x=0.61,
            y=0.501,
            width=0.16,
        ),
    )


def synthetic_page_v1(
    spans: tuple[OcrSpanV1, ...],
    *,
    capture_epoch: CaptureEpochV1 | None = None,
    frame_id=None,
    result_id=None,
) -> OcrPageResultV1:
    identity = synthetic_inference_identity_v1()
    return OcrPageResultV1(
        result_id=result_id or new_uuid7_v1(),
        capture_epoch=capture_epoch or synthetic_capture_epoch_v1(),
        frame_id=frame_id or new_uuid7_v1(),
        inference_identity_sha256=identity.inference_identity_sha256,
        preprocessing_identity=identity.preprocessing,
        spans=tuple(sorted(spans, key=OcrSpanV1.ordering_key_v1)),
    )


@dataclass
class Milestone6BHarnessV1:
    ocr: Milestone6AHarnessV1 = field(default_factory=Milestone6AHarnessV1)

    @property
    def protocol(self):
        return self.ocr.protocol

    async def install(self) -> None:
        await self.ocr.install()

    async def begin_with_frames(self, count: int = 1):
        return await self.ocr.begin_with_frames(count)

    async def process_pages(
        self,
        grant,
        page_spans_by_frame_seq: dict[int, tuple[OcrSpanV1, ...]],
    ) -> tuple[StoredOcrResultV1, ...]:
        frame_ids = {
            frame_seq: self.ocr.frame_ids(frame_seq)[0]
            for frame_seq in page_spans_by_frame_seq
        }

        def response(request):
            frame_seq = next(
                sequence
                for sequence, frame_id in frame_ids.items()
                if frame_id == request.frame_id
            )
            return synthetic_page_v1(
                page_spans_by_frame_seq[frame_seq],
                capture_epoch=request.capture_epoch,
                frame_id=request.frame_id,
            )

        self.ocr.client.response_factory = response
        return await self.ocr.process(
            grant,
            *page_spans_by_frame_seq,
        )

    def register_parent(self, grant):
        coordinator = self.protocol.coordinator
        return self.protocol.controller.register_work_v1(
            WorkOperationKindV1.OCR_INFERENCE,
            self.protocol.clock.monotonic() + 30.0,
            _admission_guard_v1=(
                lambda: coordinator._private_admission_extraction_operation_is_live_v1(
                    grant.capture_epoch
                )
            ),
        )

    async def extract(
        self,
        grant,
        receipts: tuple[StoredOcrResultV1, ...],
        *,
        parent_work=None,
    ) -> StoredAdmissionNoticeExtractionV1:
        owned_parent = parent_work is None
        parent = parent_work or self.register_parent(grant)
        try:
            return await self.protocol.coordinator._process_private_admission_notice_extraction_v1(
                capture_epoch=grant.capture_epoch,
                ocr_receipts=receipts,
                parent_work=parent,
            )
        finally:
            if owned_parent:
                self.protocol.controller.release_work_v1(parent.lease)

    def read_extraction(
        self,
        grant,
        receipt: StoredAdmissionNoticeExtractionV1,
    ) -> AdmissionNoticeExtractionV1:
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
            return coordinator._read_private_admission_extraction_for_test_v1(
                capture_epoch=grant.capture_epoch,
                receipt=receipt,
                registered_work=work,
                access=coordinator._private_store_read_access_v1,
            )
        finally:
            self.protocol.controller.release_work_v1(work.lease)

    async def close(self) -> None:
        await self.ocr.close()


@pytest_asyncio.fixture
async def milestone_6b_harness_factory():
    created: list[Milestone6BHarnessV1] = []

    def create(**kwargs) -> Milestone6BHarnessV1:
        harness = Milestone6BHarnessV1(**kwargs)
        created.append(harness)
        return harness

    yield create

    for harness in created:
        await harness.close()


__all__ = [
    "EXTRACTION_CANARIES_V1",
    "Milestone6BHarnessV1",
    "standard_admission_spans_v1",
    "synthetic_capture_epoch_v1",
    "synthetic_page_v1",
    "synthetic_span_v1",
]

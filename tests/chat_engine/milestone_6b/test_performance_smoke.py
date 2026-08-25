from __future__ import annotations

import time

import pytest

from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from certificate_capture.extraction.reading_order import (
    reconstruct_reading_order_v1,
)
from chat_engine.security.ids import new_uuid7_v1
from tests.chat_engine.milestone_6b.conftest import (
    standard_admission_spans_v1,
    synthetic_capture_epoch_v1,
    synthetic_page_v1,
)


@pytest.mark.asyncio
async def test_non_normative_m6b_performance_smoke(
    milestone_6b_harness_factory,
):
    capture_epoch = synthetic_capture_epoch_v1()
    pages = tuple(
        synthetic_page_v1(
            standard_admission_spans_v1(),
            capture_epoch=capture_epoch,
            frame_id=new_uuid7_v1(),
        )
        for _ in range(3)
    )
    extractor = AdmissionNoticeExtractorV1()
    iterations = 100

    started = time.perf_counter()
    for _ in range(iterations):
        reconstruct_reading_order_v1(pages[0].spans)
    reading_order_ms = (time.perf_counter() - started) * 1000.0 / iterations

    started = time.perf_counter()
    for _ in range(iterations):
        extractor.extract_pages_v1((pages[0],))
    one_page_ms = (time.perf_counter() - started) * 1000.0 / iterations

    started = time.perf_counter()
    for _ in range(iterations):
        extractor.extract_pages_v1(pages)
    three_page_ms = (time.perf_counter() - started) * 1000.0 / iterations

    harness = milestone_6b_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    receipts = await harness.process_pages(
        grant,
        {1: standard_admission_spans_v1()},
    )
    started = time.perf_counter()
    stored = await harness.extract(grant, receipts)
    end_to_end_ms = (time.perf_counter() - started) * 1000.0
    assert harness.read_extraction(grant, stored).name.value == "李明"

    measurements = {
        "encrypted_read_extract_write_ms": round(end_to_end_ms, 3),
        "one_page_extraction_ms": round(one_page_ms, 3),
        "reading_order_ms": round(reading_order_ms, 3),
        "three_page_extraction_ms": round(three_page_ms, 3),
    }
    print(f"M6B_PERF_NON_NORMATIVE {measurements}")

    assert reading_order_ms < 100.0
    assert one_page_ms < 250.0
    assert three_page_ms < 750.0
    assert end_to_end_ms < 1000.0

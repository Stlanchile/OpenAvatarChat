from __future__ import annotations

import time

from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from chat_engine.security.ids import new_uuid7_v1
from tests.chat_engine.milestone_6b.conftest import (
    standard_admission_spans_v1,
    synthetic_capture_epoch_v1,
    synthetic_page_v1,
)


def test_non_normative_m6c_template_and_extraction_performance_smoke():
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
        extractor.match_pages_v1((pages[0],))
    template_check_ms = (time.perf_counter() - started) * 1000.0 / iterations

    started = time.perf_counter()
    for _ in range(iterations):
        extractor.extract_pages_v1((pages[0],))
    compatibility_and_one_page_ms = (
        (time.perf_counter() - started) * 1000.0 / iterations
    )

    started = time.perf_counter()
    for _ in range(iterations):
        extractor.extract_pages_v1(pages)
    compatibility_and_three_page_ms = (
        (time.perf_counter() - started) * 1000.0 / iterations
    )

    measurements = {
        "compatibility_and_one_page_ms": round(
            compatibility_and_one_page_ms,
            3,
        ),
        "compatibility_and_three_page_ms": round(
            compatibility_and_three_page_ms,
            3,
        ),
        "template_check_ms": round(template_check_ms, 3),
    }
    print(f"M6C_PERF_NON_NORMATIVE {measurements}")

    assert template_check_ms < 100.0
    assert compatibility_and_one_page_ms < 300.0
    assert compatibility_and_three_page_ms < 900.0

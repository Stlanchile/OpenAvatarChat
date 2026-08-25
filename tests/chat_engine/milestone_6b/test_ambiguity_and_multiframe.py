from __future__ import annotations

import dataclasses

import pytest

from certificate_capture.contracts.admission_notice import (
    AdmissionFieldStatusV1,
)
from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from chat_engine.security.ids import new_uuid7_v1
from tests.chat_engine.milestone_6b.conftest import (
    standard_admission_spans_v1,
    synthetic_capture_epoch_v1,
    synthetic_page_v1,
    synthetic_span_v1,
)


def _extract(spans):
    return AdmissionNoticeExtractorV1().extract_pages_v1(
        (synthetic_page_v1(tuple(spans)),)
    )


@pytest.mark.parametrize(
    ("field_name", "extra_spans"),
    [
        (
            "name",
            (
                synthetic_span_v1(
                    "王强 同学：",
                    x=0.18,
                    y=0.24,
                    width=0.20,
                ),
            ),
        ),
        (
            "source_province",
            (
                synthetic_span_v1(
                    "经 湖南 省（市、自治区）高等学校招生委员会批准",
                    x=0.10,
                    y=0.23,
                    width=0.78,
                ),
            ),
        ),
        (
            "college",
            (
                synthetic_span_v1(
                    "批准，你被录取到我校 航空工程学院",
                    x=0.10,
                    y=0.46,
                    width=0.65,
                ),
            ),
        ),
        (
            "major",
            (
                synthetic_span_v1(
                    "人工智能技术 专业学习",
                    x=0.10,
                    y=0.58,
                    width=0.48,
                ),
            ),
        ),
    ],
)
def test_two_equally_qualified_candidates_are_ambiguous_without_value(
    field_name,
    extra_spans,
):
    result = _extract(standard_admission_spans_v1() + extra_spans)

    field = getattr(result, field_name)
    assert field.status is AdmissionFieldStatusV1.AMBIGUOUS
    assert field.value is None
    assert field.source_span_ids == ()
    assert field.source_polygon is None


def _page(
    *,
    capture_epoch,
    frame_id,
    name="李明",
    province="湖北",
    college="信息工程学院",
    major="计算机应用技术（校企合作）",
    spans=None,
):
    return synthetic_page_v1(
        spans
        or standard_admission_spans_v1(
            name=name,
            province=province,
            college=college,
            major=major,
        ),
        capture_epoch=capture_epoch,
        frame_id=frame_id,
    )


def test_multiframe_same_value_is_found_without_probability_fusion():
    capture_epoch = synthetic_capture_epoch_v1()
    first = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    second = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )

    result = AdmissionNoticeExtractorV1().extract_pages_v1((second, first))

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"
    assert result.name.source_polygon is None
    assert len(result.source_frame_ids) == 2


def test_multiframe_one_found_and_one_missing_stays_found():
    capture_epoch = synthetic_capture_epoch_v1()
    found = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    missing_spans = tuple(
        span for span in standard_admission_spans_v1() if "同学" not in span.text
    )
    missing = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
        spans=missing_spans,
    )

    result = AdmissionNoticeExtractorV1().extract_pages_v1((missing, found))

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"
    assert result.name.source_polygon is not None


@pytest.mark.parametrize(
    ("field_name", "overrides"),
    [
        ("name", {"name": "王强"}),
        ("source_province", {"province": "湖南"}),
        ("college", {"college": "航空工程学院"}),
        ("major", {"major": "人工智能技术"}),
    ],
)
def test_multiframe_conflicting_values_are_ambiguous(
    field_name,
    overrides,
):
    capture_epoch = synthetic_capture_epoch_v1()
    first = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    second = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
        **overrides,
    )

    result = AdmissionNoticeExtractorV1().extract_pages_v1((first, second))

    field = getattr(result, field_name)
    assert field.status is AdmissionFieldStatusV1.AMBIGUOUS
    assert field.value is None


def test_nonqualifying_raw_engine_score_does_not_conflict_with_clear_value():
    capture_epoch = synthetic_capture_epoch_v1()
    clear = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    low_score_spans = list(standard_admission_spans_v1(name="王强"))
    low_score_spans[:3] = [
        dataclasses.replace(span, raw_engine_score=0.10) for span in low_score_spans[:3]
    ]
    low_score = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
        spans=tuple(low_score_spans),
    )

    result = AdmissionNoticeExtractorV1().extract_pages_v1((low_score, clear))

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"


def test_input_frame_order_cannot_resolve_conflict():
    capture_epoch = synthetic_capture_epoch_v1()
    first = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
        name="李明",
    )
    second = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
        name="王强",
    )
    extractor = AdmissionNoticeExtractorV1()

    forward = extractor.extract_pages_v1((first, second))
    reverse = extractor.extract_pages_v1((second, first))

    assert forward.name == reverse.name
    assert forward.canonical_json_v1() == reverse.canonical_json_v1()


def test_duplicate_frame_or_cross_page_span_identity_is_rejected():
    capture_epoch = synthetic_capture_epoch_v1()
    shared_frame_id = new_uuid7_v1()
    first = _page(
        capture_epoch=capture_epoch,
        frame_id=shared_frame_id,
    )
    duplicate_frame = _page(
        capture_epoch=capture_epoch,
        frame_id=shared_frame_id,
    )
    with pytest.raises(ValueError):
        AdmissionNoticeExtractorV1().extract_pages_v1((first, duplicate_frame))

    second_spans = list(standard_admission_spans_v1())
    second_spans[0] = dataclasses.replace(
        second_spans[0],
        span_id=first.spans[0].span_id,
    )
    duplicate_span = _page(
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
        spans=tuple(second_spans),
    )
    with pytest.raises(ValueError):
        AdmissionNoticeExtractorV1().extract_pages_v1((first, duplicate_span))

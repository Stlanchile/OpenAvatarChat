from __future__ import annotations

import dataclasses

import pytest

from certificate_capture.contracts.admission_notice import (
    ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1,
    EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1,
    AdmissionFieldStatusV1,
    ExtractedAdmissionFieldV1,
    admission_notice_extraction_from_canonical_json_v1,
)
from certificate_capture.contracts.ocr import OcrPointV1, OcrSpanV1
from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from certificate_capture.extraction.identity import (
    ADMISSION_NOTICE_EXTRACTOR_ID_V1,
    ADMISSION_NOTICE_NORMALIZATION_VERSION_V1,
    ADMISSION_NOTICE_RULE_SET_VERSION_V1,
)
from certificate_capture.extraction.reading_order import (
    reconstruct_reading_order_v1,
)
from tests.chat_engine.milestone_6b.conftest import (
    standard_admission_spans_v1,
    synthetic_page_v1,
    synthetic_span_v1,
)


def _extract(spans):
    page = synthetic_page_v1(tuple(spans))
    return AdmissionNoticeExtractorV1().extract_pages_v1((page,))


def _status_values(result):
    return tuple(
        (field.status, field.value)
        for field in (
            result.name,
            result.source_province,
            result.college,
            result.major,
        )
    )


def test_exact_minimal_contract_and_identity_are_versioned_and_immutable():
    result = _extract(standard_admission_spans_v1())

    assert result.schema_version == ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1
    assert result.name.schema_version == EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1
    assert result.extraction_identity.extractor_id == ADMISSION_NOTICE_EXTRACTOR_ID_V1
    assert (
        result.extraction_identity.rule_set_version
        == ADMISSION_NOTICE_RULE_SET_VERSION_V1
    )
    assert (
        result.extraction_identity.normalization_version
        == ADMISSION_NOTICE_NORMALIZATION_VERSION_V1
    )
    assert not hasattr(result, "confidence")
    assert not hasattr(result.name, "confidence")
    assert set(result.canonical_object_v1()) == {
        "capture_epoch",
        "college",
        "extraction_identity",
        "major",
        "name",
        "schema_version",
        "source_frame_ids",
        "source_ocr_result_ids",
        "source_province",
    }
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.name.value = "篡改"


def test_all_four_fields_found_with_exact_source_provenance_and_round_trip():
    page = synthetic_page_v1(standard_admission_spans_v1())
    result = AdmissionNoticeExtractorV1().extract_pages_v1((page,))

    assert _status_values(result) == (
        (AdmissionFieldStatusV1.FOUND, "李明"),
        (AdmissionFieldStatusV1.FOUND, "湖北"),
        (AdmissionFieldStatusV1.FOUND, "信息工程学院"),
        (
            AdmissionFieldStatusV1.FOUND,
            "计算机应用技术（校企合作）",
        ),
    )
    live_span_ids = {span.span_id for span in page.spans}
    for field in (
        result.name,
        result.source_province,
        result.college,
        result.major,
    ):
        assert set(field.source_span_ids) <= live_span_ids
        assert field.source_polygon is not None
    decoded = admission_notice_extraction_from_canonical_json_v1(
        result.canonical_json_v1(),
        expected_capture_epoch=page.capture_epoch,
    )
    assert decoded == result
    assert result.extraction_sha256 == decoded.extraction_sha256


@pytest.mark.parametrize("separator", ["", " "])
@pytest.mark.parametrize("salutation", ["同学：", "同学:", "同学"])
def test_name_in_same_span_and_allowlisted_punctuation_variations(
    salutation,
    separator,
):
    spans = list(standard_admission_spans_v1())
    spans[:3] = [
        synthetic_span_v1(
            f"李明{separator}{salutation}",
            x=0.18,
            y=0.18,
            width=0.20,
        )
    ]

    result = _extract(spans)

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"


def test_same_span_salutation_word_is_not_a_name():
    spans = list(standard_admission_spans_v1())
    spans[:3] = [
        synthetic_span_v1(
            "欢迎同学：",
            x=0.18,
            y=0.18,
            width=0.20,
        )
    ]

    result = _extract(spans)

    assert result.name.status is AdmissionFieldStatusV1.NOT_FOUND


def test_name_split_across_neighboring_spans_with_minor_vertical_offset():
    result = _extract(standard_admission_spans_v1())

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"
    assert len(result.name.source_span_ids) == 1


def test_province_phrase_split_across_three_nearby_lines():
    spans = list(standard_admission_spans_v1())
    spans[3:7] = [
        synthetic_span_v1(
            "经 湖北 省（市、自治区）高等学校",
            x=0.12,
            y=0.29,
            width=0.62,
        ),
        synthetic_span_v1(
            "招生委员会",
            x=0.12,
            y=0.36,
            width=0.20,
        ),
        synthetic_span_v1(
            "批准，你被录取到我校",
            x=0.12,
            y=0.43,
            width=0.35,
        ),
    ]
    spans[6] = synthetic_span_v1(
        "信息工程学院",
        x=0.48,
        y=0.431,
        width=0.25,
    )

    result = _extract(spans)

    assert result.source_province.status is AdmissionFieldStatusV1.FOUND
    assert result.source_province.value == "湖北"
    assert result.college.status is AdmissionFieldStatusV1.FOUND


@pytest.mark.parametrize(
    ("college_anchor", "college"),
    [
        (
            synthetic_span_v1(
                "批准，你被录取到我校 信息工程学院",
                x=0.12,
                y=0.40,
                width=0.62,
            ),
            None,
        ),
        (
            synthetic_span_v1(
                "批准，你被录取到我校",
                x=0.12,
                y=0.40,
                width=0.35,
            ),
            synthetic_span_v1(
                "航空工程系",
                x=0.12,
                y=0.46,
                width=0.25,
            ),
        ),
        (
            synthetic_span_v1(
                "批准，你被录取到我校",
                x=0.12,
                y=0.40,
                width=0.35,
            ),
            synthetic_span_v1(
                "博雅书院",
                x=0.12,
                y=0.46,
                width=0.20,
            ),
        ),
    ],
)
def test_college_same_line_or_next_line_with_approved_unit_forms(
    college_anchor,
    college,
):
    spans = list(standard_admission_spans_v1())
    spans[6:8] = [college_anchor] if college is None else [college_anchor, college]

    result = _extract(spans)

    assert result.college.status is AdmissionFieldStatusV1.FOUND
    expected = "信息工程学院" if college is None else college.text
    assert result.college.value == expected


@pytest.mark.parametrize(
    "major",
    [
        "机电一体化技术（中俄合作办学）",
        "机电一体化技术(中俄合作办学)",
        "智能制造-实验班",
        "艺术设计·数字媒体方向",
    ],
)
def test_major_preserves_meaningful_internal_punctuation(major):
    spans = list(standard_admission_spans_v1())
    spans[-2] = synthetic_span_v1(
        major,
        x=0.12,
        y=0.50,
        width=0.48,
    )

    result = _extract(spans)

    assert result.major.status is AdmissionFieldStatusV1.FOUND
    assert result.major.value == major


def test_long_major_wrapped_across_two_adjacent_lines():
    spans = list(standard_admission_spans_v1())
    spans[-2:] = [
        synthetic_span_v1(
            "智能制造装备技术（",
            x=0.12,
            y=0.49,
            width=0.36,
        ),
        synthetic_span_v1(
            "中俄合作办学实验班）",
            x=0.12,
            y=0.56,
            width=0.42,
        ),
        synthetic_span_v1(
            "专业学习",
            x=0.55,
            y=0.561,
            width=0.16,
        ),
    ]

    result = _extract(spans)

    assert result.major.status is AdmissionFieldStatusV1.FOUND
    assert result.major.value == "智能制造装备技术（中俄合作办学实验班）"


def test_nearby_unrelated_line_is_not_prepended_to_clear_major():
    spans = list(standard_admission_spans_v1())
    spans.append(
        synthetic_span_v1(
            "注意事项",
            x=0.12,
            y=0.45,
            width=0.16,
        )
    )

    result = _extract(spans)

    assert result.major.status is AdmissionFieldStatusV1.FOUND
    assert result.major.value == "计算机应用技术（校企合作）"


def test_long_aligned_unrelated_line_is_not_prepended_to_short_clear_major():
    spans = list(standard_admission_spans_v1())
    spans[-2:] = [
        synthetic_span_v1(
            "护理学",
            x=0.12,
            y=0.50,
            width=0.12,
        ),
        synthetic_span_v1(
            "专业学习",
            x=0.25,
            y=0.501,
            width=0.16,
        ),
    ]
    spans.append(
        synthetic_span_v1(
            "注意事项请认真阅读",
            x=0.12,
            y=0.45,
            width=0.30,
        )
    )

    result = _extract(spans)

    assert result.major.status is AdmissionFieldStatusV1.FOUND
    assert result.major.value == "护理学"


def test_shuffled_input_to_reading_order_is_identical():
    spans = standard_admission_spans_v1()
    shuffled = [spans[index] for index in (7, 0, 9, 2, 5, 1, 8, 4, 6, 3)]

    first = reconstruct_reading_order_v1(tuple(spans))
    second = reconstruct_reading_order_v1(tuple(shuffled))

    first_text = tuple(
        tuple(run.mapped_text_v1().text for run in line.runs) for line in first.lines
    )
    second_text = tuple(
        tuple(run.mapped_text_v1().text for run in line.runs) for line in second.lines
    )
    assert second_text == first_text


@pytest.mark.parametrize(
    ("missing", "expected_statuses"),
    [
        (
            "name",
            (
                AdmissionFieldStatusV1.NOT_FOUND,
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.FOUND,
            ),
        ),
        (
            "province",
            (
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.NOT_FOUND,
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.FOUND,
            ),
        ),
        (
            "college",
            (
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.NOT_FOUND,
                AdmissionFieldStatusV1.FOUND,
            ),
        ),
        (
            "major",
            (
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.FOUND,
                AdmissionFieldStatusV1.NOT_FOUND,
            ),
        ),
    ],
)
def test_each_missing_field_abstains_without_failing_other_fields(
    missing,
    expected_statuses,
):
    spans = list(standard_admission_spans_v1())
    if missing == "name":
        spans = [span for span in spans if "同学" not in span.text]
    elif missing == "province":
        spans = [span for span in spans if "招生委员会" not in span.text]
    elif missing == "college":
        spans[6] = synthetic_span_v1(
            "批准，",
            x=0.12,
            y=0.40,
            width=0.08,
        )
    else:
        spans = [span for span in spans if "专业学习" not in span.text]

    result = _extract(spans)

    assert (
        tuple(
            field.status
            for field in (
                result.name,
                result.source_province,
                result.college,
                result.major,
            )
        )
        == expected_statuses
    )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("name", "赵" * 33),
        ("source_province", "虚构省份名称" * 3),
        ("college", f"{'超长文本' * 43}学院"),
        ("major", "超长专业" * 65),
    ],
)
def test_excessive_field_candidates_never_become_found(
    field_name,
    replacement,
):
    spans = list(standard_admission_spans_v1())
    if field_name == "name":
        spans[0] = synthetic_span_v1(
            replacement,
            x=0.01,
            y=0.18,
            width=0.25,
        )
    elif field_name == "source_province":
        spans[4] = synthetic_span_v1(
            replacement,
            x=0.15,
            y=0.301,
            width=0.07,
        )
    elif field_name == "college":
        spans[7] = synthetic_span_v1(
            replacement,
            x=0.48,
            y=0.401,
            width=0.45,
        )
    else:
        spans[8] = synthetic_span_v1(
            replacement,
            x=0.01,
            y=0.50,
            width=0.58,
        )

    result = _extract(spans)

    assert getattr(result, field_name).status is not AdmissionFieldStatusV1.FOUND


def test_empty_and_paragraph_sized_candidates_abstain():
    spans = list(standard_admission_spans_v1())
    spans[:3] = [synthetic_span_v1("同学：", x=0.18, y=0.18, width=0.10)]
    spans[-2] = synthetic_span_v1(
        "这是一整段说明文字。请认真阅读后办理相关手续。" * 6,
        x=0.01,
        y=0.50,
        width=0.85,
    )

    result = _extract(spans)

    assert result.name.status is AdmissionFieldStatusV1.NOT_FOUND
    assert result.major.status is AdmissionFieldStatusV1.NOT_FOUND


def test_control_characters_and_out_of_range_polygons_are_rejected_by_m6a():
    with pytest.raises(ValueError):
        synthetic_span_v1(
            "李\u0000明",
            x=0.1,
            y=0.1,
            width=0.1,
        )
    with pytest.raises(ValueError):
        OcrPointV1(1.01, 0.5)
    with pytest.raises(ValueError):
        ExtractedAdmissionFieldV1(
            status=AdmissionFieldStatusV1.FOUND,
            value="李\u200b明",
            source_span_ids=(
                synthetic_span_v1(
                    "李明",
                    x=0.1,
                    y=0.1,
                    width=0.1,
                ).span_id,
            ),
            source_polygon=None,
        )


def test_distant_same_line_anchor_does_not_bridge_large_geometry_gap():
    spans = list(standard_admission_spans_v1())
    spans[:3] = [
        synthetic_span_v1("李明", x=0.10, y=0.18, width=0.08),
        synthetic_span_v1("同学", x=0.72, y=0.181, width=0.08),
    ]

    result = _extract(spans)

    assert result.name.status is AdmissionFieldStatusV1.NOT_FOUND


def test_overlapping_polygons_and_reversed_span_order_remain_deterministic():
    spans = list(standard_admission_spans_v1())
    spans[:3] = [
        synthetic_span_v1("李明", x=0.18, y=0.18, width=0.11),
        synthetic_span_v1("同学：", x=0.265, y=0.179, width=0.11),
    ]
    page = synthetic_page_v1(tuple(reversed(spans)))

    result = AdmissionNoticeExtractorV1().extract_pages_v1((page,))

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"


def test_footer_and_header_same_words_do_not_create_false_candidates():
    spans = list(standard_admission_spans_v1())
    spans.extend(
        [
            synthetic_span_v1(
                "欢迎同学报到",
                x=0.10,
                y=0.03,
                width=0.30,
            ),
            synthetic_span_v1(
                "王强 同学：",
                x=0.15,
                y=0.91,
                width=0.25,
            ),
            synthetic_span_v1(
                "学校学院专业省招生介绍",
                x=0.10,
                y=0.94,
                width=0.55,
            ),
        ]
    )

    result = _extract(spans)

    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"


def test_degenerate_geometry_is_non_qualifying_without_page_failure():
    spans = list(standard_admission_spans_v1())
    degenerate = OcrSpanV1(
        span_id=spans[0].span_id,
        text=spans[0].text,
        polygon=(
            OcrPointV1(0.2, 0.2),
            OcrPointV1(0.2, 0.2),
            OcrPointV1(0.2, 0.2),
            OcrPointV1(0.2, 0.2),
        ),
        raw_engine_score=0.9,
    )
    spans[0] = degenerate

    result = _extract(spans)

    assert result.name.status is AdmissionFieldStatusV1.NOT_FOUND


def test_result_contains_no_raw_full_page_transcript():
    spans = list(standard_admission_spans_v1())
    canary = "这是一段不属于任何字段的完整页面私密文本"
    spans.append(
        synthetic_span_v1(
            canary,
            x=0.10,
            y=0.75,
            width=0.65,
        )
    )

    result = _extract(spans)

    assert canary not in result.canonical_json_v1().decode("utf-8")

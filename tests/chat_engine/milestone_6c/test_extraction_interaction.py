from __future__ import annotations

import dataclasses

import pytest

from certificate_capture.contracts.admission_notice import (
    AdmissionFieldStatusV1,
    AdmissionNoticeExtractionV1,
)
from certificate_capture.contracts.admission_notice_template import (
    HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1,
    HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1,
    HBTC_ADMISSION_NOTICE_TEMPLATE_MATCH_RULE_VERSION_V1,
    HBTC_ADMISSION_NOTICE_TEMPLATE_V1,
    AdmissionNoticeTemplateMatchStatusV1,
)
from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from certificate_capture.extraction.hbtc_admission_notice import (
    AdmissionNoticeTemplateCompatibilityErrorV1,
)
from certificate_capture.extraction.identity import (
    DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1,
)
from certificate_capture.extraction.service import (
    AdmissionNoticeExtractionFailureReasonV1,
    AdmissionNoticeExtractionServiceErrorV1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.work_fence import WorkOperationKindV1
from tests.chat_engine.milestone_6b.conftest import (
    standard_admission_spans_v1,
    synthetic_capture_epoch_v1,
    synthetic_page_v1,
    synthetic_span_v1,
)


def _without_text(spans, text):
    return tuple(span for span in spans if text not in span.text)


def _wrong_institution_spans(
    institution_name="湖南交通职业技术学院",
):
    return tuple(
        synthetic_span_v1(
            institution_name,
            x=0.24,
            y=0.055,
            width=0.52,
            height=0.045,
        )
        if span.text == HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
        else span
        for span in standard_admission_spans_v1()
    )


def _missing_institution_spans():
    return tuple(
        span
        for span in standard_admission_spans_v1()
        if span.text != HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
    )


def _insufficient_body_spans():
    spans = _without_text(standard_admission_spans_v1(), "高等学校招生委员会")
    return _without_text(spans, "你被录取到我校")


def test_matched_template_runs_existing_exact_four_field_extraction():
    page = synthetic_page_v1(standard_admission_spans_v1())
    extractor = AdmissionNoticeExtractorV1()

    match = extractor.match_pages_v1((page,))
    result = extractor.extract_pages_v1((page,))

    assert match.status is AdmissionNoticeTemplateMatchStatusV1.MATCHED
    assert (
        result.name.value,
        result.source_province.value,
        result.college.value,
        result.major.value,
    ) == (
        "李明",
        "湖北",
        "信息工程学院",
        "计算机应用技术（校企合作）",
    )


@pytest.mark.parametrize(
    ("spans", "expected_status"),
    [
        (
            _wrong_institution_spans(),
            AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED,
        ),
        (
            _missing_institution_spans(),
            AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT,
        ),
        (
            _insufficient_body_spans(),
            AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT,
        ),
    ],
)
def test_nonmatching_template_never_produces_answerable_fields(
    spans,
    expected_status,
):
    extractor = AdmissionNoticeExtractorV1()
    page = synthetic_page_v1(spans)

    assert extractor.match_pages_v1((page,)).status is expected_status
    with pytest.raises(AdmissionNoticeTemplateCompatibilityErrorV1) as rejected:
        extractor.extract_pages_v1((page,))
    assert rejected.value.status is expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("spans", "expected_reason"),
    [
        (
            _wrong_institution_spans(),
            AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_TEMPLATE_NOT_MATCHED,
        ),
        (
            _missing_institution_spans(),
            AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_TEMPLATE_INSUFFICIENT,
        ),
        (
            _insufficient_body_spans(),
            AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_TEMPLATE_INSUFFICIENT,
        ),
    ],
)
async def test_private_service_rejection_creates_no_extraction_record(
    milestone_6b_harness_factory,
    spans,
    expected_reason,
):
    harness = milestone_6b_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    receipts = await harness.process_pages(grant, {1: spans})

    with pytest.raises(AdmissionNoticeExtractionServiceErrorV1) as rejected:
        await harness.extract(grant, receipts)

    assert rejected.value.reason is expected_reason
    snapshot = harness.protocol.coordinator._private_evidence_store_v1.snapshot_v1()
    assert snapshot.admission_extraction_index_count == 0
    assert snapshot.ocr_result_index_count == 1
    assert snapshot.auxiliary_record_count == 1


@pytest.mark.asyncio
async def test_encrypted_result_identity_is_bound_to_capture_profile(
    milestone_6b_harness_factory,
):
    harness = milestone_6b_harness_factory()
    await harness.install()
    grant, _ = await harness.begin_with_frames(1)
    receipts = await harness.process_pages(
        grant,
        {1: standard_admission_spans_v1()},
    )

    stored = await harness.extract(grant, receipts)
    extraction = harness.read_extraction(grant, stored)
    partition = harness.protocol.coordinator._private_evidence_store_v1._partition

    assert partition is not None
    assert (
        partition.capture_set.profile_id
        == extraction.extraction_identity.template_id
        == HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
    )
    assert not hasattr(extraction, "template_match")


def test_trusted_institution_is_separate_from_the_four_ocr_semantic_fields():
    semantic_fields = {
        "name",
        "source_province",
        "college",
        "major",
    }
    extraction_fields = set(AdmissionNoticeExtractionV1.__dataclass_fields__)

    assert semantic_fields <= extraction_fields
    assert (
        not {
            "institution",
            "issuer",
            "school_name",
            "template_id",
        }
        & extraction_fields
    )
    assert (
        HBTC_ADMISSION_NOTICE_TEMPLATE_V1.institution_name
        == HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
    )
    assert (
        DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1.template_id
        == HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
    )


def test_matching_does_not_change_existing_ambiguity_behavior():
    spans = standard_admission_spans_v1() + (
        synthetic_span_v1(
            "王强 同学：",
            x=0.18,
            y=0.24,
            width=0.20,
        ),
    )

    result = AdmissionNoticeExtractorV1().extract_pages_v1((synthetic_page_v1(spans),))

    assert result.name.status is AdmissionFieldStatusV1.AMBIGUOUS
    assert result.name.value is None
    assert result.source_province.status is AdmissionFieldStatusV1.FOUND


def test_one_matched_page_establishes_multiframe_compatibility():
    capture_epoch = synthetic_capture_epoch_v1()
    matched = synthetic_page_v1(
        standard_admission_spans_v1(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    missing_title = synthetic_page_v1(
        _missing_institution_spans(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    extractor = AdmissionNoticeExtractorV1()

    match = extractor.match_pages_v1((missing_title, matched))
    result = extractor.extract_pages_v1((missing_title, matched))

    assert match.status is AdmissionNoticeTemplateMatchStatusV1.MATCHED
    assert result.name.status is AdmissionFieldStatusV1.FOUND
    assert result.name.value == "李明"


def test_insufficient_page_cannot_supply_fields_to_a_matched_page():
    capture_epoch = synthetic_capture_epoch_v1()
    identity_only = synthetic_page_v1(
        (
            synthetic_span_v1(
                HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1,
                x=0.24,
                y=0.055,
                width=0.52,
                height=0.045,
            ),
            synthetic_span_v1("同学：", x=0.16, y=0.20, width=0.10),
            synthetic_span_v1(
                "经火星省（市、自治区）高等学校招生委员会",
                x=0.14,
                y=0.32,
                width=0.72,
            ),
            synthetic_span_v1(
                "批准，你被录取到我校",
                x=0.12,
                y=0.43,
                width=0.35,
            ),
        ),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    field_only = synthetic_page_v1(
        _missing_institution_spans(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    extractor = AdmissionNoticeExtractorV1()

    assert (
        extractor.match_pages_v1((identity_only,)).status
        is AdmissionNoticeTemplateMatchStatusV1.MATCHED
    )
    assert (
        extractor.match_pages_v1((field_only,)).status
        is AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT
    )
    result = extractor.extract_pages_v1((field_only, identity_only))

    assert result.name.status is AdmissionFieldStatusV1.NOT_FOUND
    assert result.source_province.status is AdmissionFieldStatusV1.NOT_FOUND
    assert result.college.status is AdmissionFieldStatusV1.NOT_FOUND
    assert result.major.status is AdmissionFieldStatusV1.NOT_FOUND


@pytest.mark.parametrize("reverse", (False, True))
def test_wrong_school_evidence_conflicts_independent_of_frame_order(reverse):
    capture_epoch = synthetic_capture_epoch_v1()
    matched = synthetic_page_v1(
        standard_admission_spans_v1(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    wrong = synthetic_page_v1(
        _wrong_institution_spans(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    pages = (wrong, matched) if reverse else (matched, wrong)
    extractor = AdmissionNoticeExtractorV1()

    match = extractor.match_pages_v1(pages)

    assert match.status is AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED
    with pytest.raises(AdmissionNoticeTemplateCompatibilityErrorV1):
        extractor.extract_pages_v1(pages)


@pytest.mark.parametrize(
    "wrong_institution",
    (
        "湖北交通职业技术学院附属学院",
        "北京大学",
        "湖南交通职业技术学院录取通知书",
        "湖南交通职业技术学院招生章程",
        "湖南交通职业技术学院2026",
    ),
)
@pytest.mark.parametrize("reverse", (False, True))
def test_nested_or_short_wrong_school_conflicts_with_matched_page(
    wrong_institution,
    reverse,
):
    capture_epoch = synthetic_capture_epoch_v1()
    matched = synthetic_page_v1(
        standard_admission_spans_v1(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    wrong = synthetic_page_v1(
        _wrong_institution_spans(wrong_institution),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    extractor = AdmissionNoticeExtractorV1()
    pages = (wrong, matched) if reverse else (matched, wrong)

    match = extractor.match_pages_v1(pages)

    assert match.status is AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED
    with pytest.raises(AdmissionNoticeTemplateCompatibilityErrorV1):
        extractor.extract_pages_v1(pages)


def test_identical_repeated_pages_add_no_template_match_weight():
    capture_epoch = synthetic_capture_epoch_v1()
    first = synthetic_page_v1(
        standard_admission_spans_v1(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    second = synthetic_page_v1(
        standard_admission_spans_v1(),
        capture_epoch=capture_epoch,
        frame_id=new_uuid7_v1(),
    )
    extractor = AdmissionNoticeExtractorV1()

    single = extractor.match_pages_v1((first,))
    repeated = extractor.match_pages_v1((second, first))

    assert repeated.status is single.status
    assert repeated.matched_anchor_ids == single.matched_anchor_ids


def test_template_identity_and_rule_version_are_in_extraction_reuse_identity():
    identity = DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1
    changed_rule = dataclasses.replace(
        identity,
        template_match_rule_version="hbtc-admission-notice-template-match.v2",
    )

    assert identity.template_id == HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
    assert (
        identity.template_match_rule_version
        == HBTC_ADMISSION_NOTICE_TEMPLATE_MATCH_RULE_VERSION_V1
    )
    assert identity.extraction_identity_sha256 != (
        changed_rule.extraction_identity_sha256
    )
    with pytest.raises(ValueError):
        AdmissionNoticeExtractorV1(changed_rule)


def test_template_check_reuses_existing_extraction_operation_kind():
    operation_names = {kind.name for kind in WorkOperationKindV1}

    assert "ADMISSION_NOTICE_EXTRACTION" in operation_names
    assert (
        not {
            "ADMISSION_NOTICE_TEMPLATE_MATCH",
            "TEMPLATE_COMPATIBILITY",
            "TEMPLATE_MATCH",
        }
        & operation_names
    )

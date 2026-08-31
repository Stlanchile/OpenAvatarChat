from __future__ import annotations

import asyncio
import dataclasses
import random
import time
from pathlib import Path

import pytest
from loguru import logger

from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    OcrBatchLiteV1,
    OcrFrameLiteV1,
    OcrSpanLiteV1,
    RecognitionErrorReasonLiteV1,
    RecognitionJobContextLiteV1,
    RecognitionStateLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.admission_notice_lite_major_catalog import (
    SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1,
    canonical_supported_major_lite_v1,
    normalize_supported_major_candidate_lite_v1,
)
from service.admission_notice_lite_ocr import AdmissionNoticeOcrProcessorLiteV1
from service.admission_notice_lite_processor import (
    AdmissionNoticeSemanticProcessorLiteV1,
)
from service.admission_notice_lite_semantics import (
    MIN_RAW_OCR_SCORE_LITE_V1,
    AdmissionNoticeResultLiteV1,
    AdmissionNoticeTemplateStatusLiteV1,
    match_admission_notice_template_lite_v1,
    recognize_admission_notice_semantics,
)
from service.admission_notice_lite_service import AdmissionNoticeLiteService
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APPROVED_MANIFEST = "1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b"


def _span(
    text: str,
    y: float,
    *,
    x: float = 0.12,
    width: float = 0.76,
    height: float = 0.04,
    score: float = 0.90,
) -> OcrSpanLiteV1:
    return OcrSpanLiteV1(
        text=text,
        polygon=(
            (x, y),
            (x + width, y),
            (x + width, y + height),
            (x, y + height),
        ),
        score=score,
    )


def _notice_spans(
    major: str = "智能交通技术",
    *,
    institution: str | None = "湖北交通职业技术学院",
    college: str | None = "交通信息学院",
    name: str | None = "张三",
    province_sentence: str | None = ("经湖北省（市、自治区）高等学校招生委员会批准"),
    title_y: float = 0.04,
    title_score: float = 0.90,
) -> list[OcrSpanLiteV1]:
    spans: list[OcrSpanLiteV1] = []
    if institution is not None:
        spans.append(_span(institution, title_y, score=title_score))
    if name is not None:
        spans.append(_span(f"{name} 同学", 0.18))
    if province_sentence is not None:
        spans.append(_span(province_sentence, 0.34))
    college_text = "" if college is None else college
    spans.append(
        _span(
            f"你被录取到我校{college_text}{major}专业学习",
            0.52,
        )
    )
    return spans


def _frame(
    frame_index: int = 1,
    major: str = "智能交通技术",
    **kwargs,
) -> OcrFrameLiteV1:
    return OcrFrameLiteV1(
        frame_index=frame_index,
        spans=tuple(_notice_spans(major, **kwargs)),
    )


def _batch(*frames: OcrFrameLiteV1) -> OcrBatchLiteV1:
    return OcrBatchLiteV1(frames=tuple(frames))


def _reason(batch: OcrBatchLiteV1) -> RecognitionErrorReasonLiteV1:
    with pytest.raises(AdmissionNoticeLiteError) as failure:
        recognize_admission_notice_semantics(batch)
    return failure.value.reason


@pytest.mark.parametrize("major", SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1)
def test_every_closed_catalog_major_returns_its_exact_canonical_value(
    major: str,
) -> None:
    result = recognize_admission_notice_semantics(_batch(_frame(major=major)))
    assert result.major == major


@pytest.mark.parametrize(
    ("source", "canonical"),
    (
        ("计算机网络技术（3+2）", "计算机网络技术(3+2)"),
        ("计算机网络技术( 3 + 2 )", "计算机网络技术(3+2)"),
        ("计算机网络技术（３＋２）", "计算机网络技术(3+2)"),
        (
            "智能交通技术（ 专本联合培养 ）",
            "智能交通技术(专本联合培养)",
        ),
        ("电子商务（３ ＋ ２）", "电子商务(3+2)"),
    ),
)
def test_major_structural_normalization_is_closed(
    source: str,
    canonical: str,
) -> None:
    assert normalize_supported_major_candidate_lite_v1(source) == canonical
    assert canonical_supported_major_lite_v1(source) == canonical
    assert (
        recognize_admission_notice_semantics(_batch(_frame(major=source))).major
        == canonical
    )


@pytest.mark.parametrize(
    "source",
    (
        "人工智熊技术应用",
        "计算机应用技术",
        "智能交通技术(未知方向)",
        "智能交通技术(专本联合培",
        "计算机网络技术(3+2)实验班",
        "人工 智能技术应用",
    ),
)
def test_unknown_or_incomplete_major_is_never_corrected_or_truncated(
    source: str,
) -> None:
    assert canonical_supported_major_lite_v1(source) is None
    assert _reason(_batch(_frame(major=source))) is (
        RecognitionErrorReasonLiteV1.MAJOR_NOT_RECOGNIZED
    )


@pytest.mark.parametrize(
    ("base", "qualified"),
    (
        ("计算机网络技术", "计算机网络技术(3+2)"),
        ("智能交通技术", "智能交通技术(专本联合培养)"),
    ),
)
def test_prefix_families_never_silently_downgrade(
    base: str,
    qualified: str,
) -> None:
    assert (
        recognize_admission_notice_semantics(_batch(_frame(major=base))).major == base
    )
    assert (
        recognize_admission_notice_semantics(_batch(_frame(major=qualified))).major
        == qualified
    )
    assert _reason(_batch(_frame(1, base), _frame(2, qualified))) is (
        RecognitionErrorReasonLiteV1.AMBIGUOUS_NOTICE
    )


@pytest.mark.parametrize(
    "major_parts",
    (
        ("计算机网络技术", "（3+2）"),
        ("智能交通技术", "（专本联合培养）"),
    ),
)
def test_wrapped_qualifier_is_kept_with_the_base(
    major_parts: tuple[str, str],
) -> None:
    spans = _notice_spans("")
    spans[-1] = _span(
        f"你被录取到我校交通信息学院{major_parts[0]}",
        0.50,
    )
    spans.append(_span(f"{major_parts[1]}专业学习", 0.57))
    result = recognize_admission_notice_semantics(
        _batch(OcrFrameLiteV1(1, tuple(spans)))
    )
    assert result.major == canonical_supported_major_lite_v1("".join(major_parts))


def test_same_line_split_major_and_randomized_input_order_are_geometry_stable() -> None:
    spans = _notice_spans("")
    spans.pop()
    spans.extend(
        (
            _span("你被录取到我校", 0.52, x=0.10, width=0.20),
            _span("交通信息学院", 0.521, x=0.305, width=0.18),
            _span("计算机网络技术", 0.519, x=0.49, width=0.20),
            _span("（３＋２）", 0.522, x=0.695, width=0.09),
            _span("专业学习", 0.520, x=0.79, width=0.10),
        )
    )
    expected = recognize_admission_notice_semantics(
        _batch(OcrFrameLiteV1(1, tuple(spans)))
    )
    random.Random(20260831).shuffle(spans)
    actual = recognize_admission_notice_semantics(
        _batch(OcrFrameLiteV1(1, tuple(spans)))
    )
    assert actual == expected
    assert actual.major == "计算机网络技术(3+2)"


def test_split_title_is_joined_only_by_related_upper_geometry() -> None:
    spans = _notice_spans(institution=None)
    spans.extend(
        (
            _span("湖北交通职业技术", 0.035, x=0.22, width=0.56),
            _span("学院", 0.085, x=0.45, width=0.10),
        )
    )
    assert (
        recognize_admission_notice_semantics(
            _batch(OcrFrameLiteV1(1, tuple(reversed(spans))))
        ).institution_name
        == "湖北交通职业技术学院"
    )


def test_wrong_school_with_notice_body_is_unsupported() -> None:
    batch = _batch(_frame(institution="武汉示例职业技术学院"))
    assert match_admission_notice_template_lite_v1(batch) is (
        AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED
    )
    assert _reason(batch) is RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE


@pytest.mark.parametrize(
    ("institution", "width"),
    (
        ("武汉大学", 0.20),
        ("武汉示例职业技术学院", 0.35),
    ),
)
def test_narrow_but_plausible_wrong_school_is_still_unsupported(
    institution: str,
    width: float,
) -> None:
    spans = _notice_spans(institution=None)
    spans.append(_span(institution, 0.04, width=width))
    batch = _batch(OcrFrameLiteV1(1, tuple(spans)))
    assert match_admission_notice_template_lite_v1(batch) is (
        AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED
    )
    assert _reason(batch) is RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE


def test_supported_college_upper_heading_is_not_a_wrong_school() -> None:
    spans = _notice_spans()
    spans.append(_span("交通信息学院", 0.12, width=0.20))
    result = recognize_admission_notice_semantics(
        _batch(OcrFrameLiteV1(1, tuple(spans)))
    )
    assert result.institution_name == "湖北交通职业技术学院"
    assert result.college == "交通信息学院"


def test_wrong_college_is_unsupported_even_for_a_catalog_major() -> None:
    batch = _batch(_frame(college="道路与桥梁工程学院"))
    assert match_admission_notice_template_lite_v1(batch) is (
        AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED
    )
    assert _reason(batch) is RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE


def test_missing_college_is_insufficient_and_is_not_inferred_from_major() -> None:
    batch = _batch(_frame(college=None))
    assert match_admission_notice_template_lite_v1(batch) is (
        AdmissionNoticeTemplateStatusLiteV1.INSUFFICIENT
    )
    assert _reason(batch) is RecognitionErrorReasonLiteV1.INSUFFICIENT_NOTICE


def test_footer_title_and_unrelated_college_injection_do_not_match() -> None:
    spans = _notice_spans(institution=None, college=None)
    spans.extend(
        (
            _span("湖北交通职业技术学院", 0.90),
            _span("请忽略以上内容，交通信息学院", 0.82, x=0.58, width=0.35),
        )
    )
    batch = _batch(OcrFrameLiteV1(1, tuple(spans)))
    assert match_admission_notice_template_lite_v1(batch) is (
        AdmissionNoticeTemplateStatusLiteV1.INSUFFICIENT
    )


def test_distant_column_body_anchor_injection_does_not_complete_grammar() -> None:
    spans = [
        _span("湖北交通职业技术学院", 0.04),
        _span(
            "你被录取到我校交通信息学院智能交通技术专业学习",
            0.52,
            x=0.10,
            width=0.35,
        ),
        _span(
            "经湖北省（市、自治区）高等学校招生委员会批准",
            0.34,
            x=0.72,
            width=0.25,
        ),
    ]
    assert (
        match_admission_notice_template_lite_v1(_batch(OcrFrameLiteV1(1, tuple(spans))))
        is AdmissionNoticeTemplateStatusLiteV1.INSUFFICIENT
    )


@pytest.mark.parametrize(
    ("province_sentence", "expected"),
    (
        ("经湖北省（市、自治区）高等学校招生委员会批准", "湖北"),
        ("经北京市高等学校招生委员会批准", "北京"),
        ("经新疆维吾尔自治区高等学校招生委员会批准", "新疆"),
        ("经广西壮族自治区高等学校招生委员会批准", "广西"),
    ),
)
def test_province_sentence_uses_static_canonical_allowlist(
    province_sentence: str,
    expected: str,
) -> None:
    result = recognize_admission_notice_semantics(
        _batch(_frame(province_sentence=province_sentence))
    )
    assert result.source_province == expected


def test_missing_invalid_or_unrelated_province_is_optional() -> None:
    missing = recognize_admission_notice_semantics(
        _batch(_frame(province_sentence=None))
    )
    invalid = recognize_admission_notice_semantics(
        _batch(_frame(province_sentence="经火星省（市、自治区）高等学校招生委员会批准"))
    )
    unrelated_spans = _notice_spans(province_sentence=None)
    unrelated_spans.append(_span("湖北省旅游说明", 0.70))
    unrelated = recognize_admission_notice_semantics(
        _batch(OcrFrameLiteV1(1, tuple(unrelated_spans)))
    )
    assert missing.source_province is None
    assert invalid.source_province is None
    assert unrelated.source_province is None


def test_wrapped_province_sentence_is_extracted_from_local_related_lines() -> None:
    spans = _notice_spans(province_sentence=None)
    spans.extend(
        (
            _span("经内蒙古自治区", 0.32),
            _span("高等学校招生委员会批准", 0.38),
        )
    )
    result = recognize_admission_notice_semantics(
        _batch(OcrFrameLiteV1(1, tuple(spans)))
    )
    assert result.source_province == "内蒙古"


@pytest.mark.parametrize("name", ("李雷", "欧阳娜娜", "阿依努尔·艾山"))
def test_name_same_span_is_optional_but_bounded(name: str) -> None:
    assert recognize_admission_notice_semantics(_batch(_frame(name=name))).name == name


def test_name_in_adjacent_same_line_span_is_extracted() -> None:
    spans = _notice_spans(name=None)
    spans.extend(
        (
            _span("王小明", 0.18, x=0.18, width=0.12),
            _span("同学", 0.181, x=0.305, width=0.08),
        )
    )
    assert (
        recognize_admission_notice_semantics(
            _batch(OcrFrameLiteV1(1, tuple(spans)))
        ).name
        == "王小明"
    )


@pytest.mark.parametrize("salutation", (None, "██", "欢迎新生", "有关同学"))
def test_unreadable_or_non_name_salutation_does_not_block_major(
    salutation: str | None,
) -> None:
    result = recognize_admission_notice_semantics(_batch(_frame(name=salutation)))
    assert result.name is None
    assert result.major == "智能交通技术"


def test_optional_name_and_province_conflicts_are_omitted_without_majority_vote() -> (
    None
):
    result = recognize_admission_notice_semantics(
        _batch(
            _frame(1, name="张三"),
            _frame(
                2,
                name="李四",
                province_sentence="经北京市高等学校招生委员会批准",
            ),
        )
    )
    assert result.name is None
    assert result.source_province is None
    assert result.major == "智能交通技术"


def test_multiframe_template_policy_is_per_page_and_order_independent() -> None:
    matched = _frame(1)
    insufficient = OcrFrameLiteV1(
        2,
        (_span("普通说明", 0.40),),
    )
    assert (
        recognize_admission_notice_semantics(_batch(matched, insufficient)).major
        == "智能交通技术"
    )

    same_first = recognize_admission_notice_semantics(_batch(_frame(1), _frame(2)))
    same_second = recognize_admission_notice_semantics(_batch(_frame(1), _frame(2)))
    assert same_first == same_second


def test_explicit_wrong_college_frame_dominates_a_matched_frame() -> None:
    assert (
        _reason(
            _batch(
                _frame(1),
                _frame(2, college="汽车工程学院"),
            )
        )
        is RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE
    )


def test_all_insufficient_frames_return_insufficient_notice() -> None:
    batch = _batch(
        OcrFrameLiteV1(1, (_span("普通文本", 0.30),)),
        OcrFrameLiteV1(2, (_span("另一个普通文本", 0.40),)),
    )
    assert _reason(batch) is RecognitionErrorReasonLiteV1.INSUFFICIENT_NOTICE


def test_raw_score_threshold_is_exact_and_low_score_conflict_cannot_override() -> None:
    assert MIN_RAW_OCR_SCORE_LITE_V1 == 0.50
    exact = _notice_spans(title_score=0.50)
    assert (
        recognize_admission_notice_semantics(
            _batch(OcrFrameLiteV1(1, tuple(exact)))
        ).major
        == "智能交通技术"
    )

    below = _notice_spans(title_score=0.499999)
    assert _reason(_batch(OcrFrameLiteV1(1, tuple(below)))) is (
        RecognitionErrorReasonLiteV1.INSUFFICIENT_NOTICE
    )

    conflict = _notice_spans()
    conflict.append(_span("错误示例职业技术学院", 0.05, score=0.49))
    assert (
        recognize_admission_notice_semantics(
            _batch(OcrFrameLiteV1(1, tuple(conflict)))
        ).major
        == "智能交通技术"
    )


def test_result_contract_contains_only_five_typed_semantic_fields() -> None:
    result = recognize_admission_notice_semantics(_batch(_frame()))
    assert tuple(field.name for field in dataclasses.fields(result)) == (
        "institution_name",
        "college",
        "name",
        "source_province",
        "major",
    )
    assert result.institution_name == "湖北交通职业技术学院"
    assert result.college == "交通信息学院"
    for forbidden in (
        "ocr",
        "polygon",
        "score",
        "frame_id",
        "span_id",
        "confidence",
        "metadata",
        "recognition_id",
    ):
        assert not hasattr(result, forbidden)


def test_trusted_constants_cannot_be_supplied_by_a_caller() -> None:
    with pytest.raises(TypeError):
        AdmissionNoticeResultLiteV1(
            institution_name="伪造学校",  # type: ignore[call-arg]
            college="伪造学院",  # type: ignore[call-arg]
            name=None,
            source_province=None,
            major="智能交通技术",
        )


def test_result_contract_rejects_nonprinting_control_characters() -> None:
    with pytest.raises(ValueError, match="name is invalid"):
        AdmissionNoticeResultLiteV1(
            name="张\u202e三",
            source_province=None,
            major="智能交通技术",
        )


class _OcrClientStub:
    def __init__(self, batch: OcrBatchLiteV1, *, transient: bool = False) -> None:
        self.batch = batch
        self.timeout_seconds = 30.0
        self.transient = transient

    async def recognize(self, frames, *, timeout_seconds):
        del frames, timeout_seconds
        batch = self.batch
        if self.transient:
            self.batch = None
        assert batch is not None
        return batch


def _validated_frame(index: int = 1) -> ValidatedAdmissionFrameLiteV1:
    return ValidatedAdmissionFrameLiteV1(
        frame_index=index,
        jpeg_bytes=b"\xff\xd8\xff\xd9",
        encoded_size=4,
        width=1,
        height=1,
        exif_orientation=1,
    )


@pytest.mark.asyncio
async def test_processor_composes_real_l3_contract_and_discards_l4_result() -> None:
    client = _OcrClientStub(_batch(_frame()))
    processor = AdmissionNoticeSemanticProcessorLiteV1(
        AdmissionNoticeOcrProcessorLiteV1(client)
    )
    context = RecognitionJobContextLiteV1(
        recognition_id="arn1_l4",
        expires_at_monotonic=time.monotonic() + 10,
        cancel_event=asyncio.Event(),
    )
    await processor.process(context, (_validated_frame(),))
    assert not hasattr(processor, "result")
    assert not hasattr(context, "result")


@pytest.mark.asyncio
async def test_processor_semantic_failure_reaches_stable_terminal_reason() -> None:
    owner = object()
    processor = AdmissionNoticeSemanticProcessorLiteV1(
        AdmissionNoticeOcrProcessorLiteV1(
            _OcrClientStub(_batch(_frame(college="汽车工程学院")))
        )
    )
    service = AdmissionNoticeLiteService(
        config=AdmissionNoticeLiteFeatureConfigV1(enabled=True),
        session_lookup=lambda value: owner if value == "owner" else None,
        processor=processor,
    )
    permit = await service.begin_ingestion("owner")
    try:
        created = await service.create_recognition(permit, (_validated_frame(),))
    finally:
        service.release_ingestion(permit)
    try:
        for _ in range(200):
            terminal = await service.get_recognition(
                "owner",
                created.recognition_id,
            )
            if terminal.state not in {
                RecognitionStateLiteV1.CREATED,
                RecognitionStateLiteV1.PROCESSING,
            }:
                break
            await asyncio.sleep(0)
        assert terminal.state is RecognitionStateLiteV1.FAILED
        assert terminal.reason is RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE
        assert dataclasses.asdict(terminal).keys() == {
            "recognition_id",
            "owning_session_id",
            "state",
            "created_at_monotonic",
            "expires_at_monotonic",
            "reason",
        }
        assert not hasattr(terminal, "major")
        assert not hasattr(terminal, "name")
        assert not hasattr(terminal, "ocr")
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_ocr_and_semantic_values_never_enter_l4_logs() -> None:
    canary_name = "隐私姓名甲"
    canary_major = "智能交通技术(专本联合培养)"
    batch = _batch(_frame(name=canary_name, major=canary_major))
    processor = AdmissionNoticeSemanticProcessorLiteV1(
        AdmissionNoticeOcrProcessorLiteV1(_OcrClientStub(batch))
    )
    context = RecognitionJobContextLiteV1(
        recognition_id="arn1_privacy",
        expires_at_monotonic=time.monotonic() + 10,
        cancel_event=asyncio.Event(),
    )
    messages: list[str] = []
    sink = logger.add(messages.append, format="{message}")
    try:
        await processor.process(context, (_validated_frame(),))
    finally:
        logger.remove(sink)
    rendered = "\n".join(messages)
    assert canary_name not in rendered
    assert canary_major not in rendered
    assert "湖北交通职业技术学院" not in rendered
    assert "交通信息学院" not in rendered


@pytest.mark.asyncio
async def test_retained_semantic_failure_task_has_no_ocr_or_jpeg_traceback_data() -> (
    None
):
    canary_name = "隐私姓名乙"
    canary_major = "计算机网络技术(3+2)"
    jpeg_canary = b"\xff\xd8private-jpeg-canary\xff\xd9"
    processor = AdmissionNoticeSemanticProcessorLiteV1(
        AdmissionNoticeOcrProcessorLiteV1(
            _OcrClientStub(
                _batch(
                    _frame(
                        name=canary_name,
                        major=canary_major,
                        college="汽车工程学院",
                    )
                ),
                transient=True,
            )
        )
    )
    owner = object()
    service = AdmissionNoticeLiteService(
        config=AdmissionNoticeLiteFeatureConfigV1(enabled=True),
        session_lookup=lambda value: owner if value == "owner" else None,
        processor=processor,
    )
    frame = ValidatedAdmissionFrameLiteV1(
        frame_index=1,
        jpeg_bytes=jpeg_canary,
        encoded_size=len(jpeg_canary),
        width=1,
        height=1,
        exif_orientation=1,
    )
    permit = await service.begin_ingestion("owner")
    try:
        created = await service.create_recognition(permit, (frame,))
    finally:
        service.release_ingestion(permit)
    try:
        for _ in range(200):
            terminal = await service.get_recognition("owner", created.recognition_id)
            if terminal.state is RecognitionStateLiteV1.FAILED:
                break
            await asyncio.sleep(0)
        runtime = service._jobs[created.recognition_id]
        assert runtime.frames == ()
        task = runtime.processor_task
        assert task is not None and task.done()
        exception = task.exception()
        assert isinstance(exception, AdmissionNoticeLiteError)
        assert exception.__context__ is None
        traceback = exception.__traceback__
        while traceback is not None:
            locals_text = repr(traceback.tb_frame.f_locals)
            assert canary_name not in locals_text
            assert canary_major not in locals_text
            assert "private-jpeg-canary" not in locals_text
            assert traceback.tb_frame.f_locals.get("frames") in (None, ())
            assert "batch" not in traceback.tb_frame.f_locals
            traceback = traceback.tb_next
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_unexpected_semantic_failure_traceback_is_also_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_processor as processor_module

    canary_text = "unexpected-private-ocr-canary"
    jpeg_canary = b"\xff\xd8unexpected-private-jpeg-canary\xff\xd9"
    batch = OcrBatchLiteV1(
        frames=(
            OcrFrameLiteV1(
                1,
                (_span(canary_text, 0.40),),
            ),
        )
    )

    def fail_after_receiving_batch(received: OcrBatchLiteV1):
        assert canary_text in repr(received)
        raise ValueError("synthetic semantic implementation fault")

    monkeypatch.setattr(
        processor_module,
        "recognize_admission_notice_semantics",
        fail_after_receiving_batch,
    )
    processor = AdmissionNoticeSemanticProcessorLiteV1(
        AdmissionNoticeOcrProcessorLiteV1(
            _OcrClientStub(batch, transient=True),
        )
    )
    owner = object()
    service = AdmissionNoticeLiteService(
        config=AdmissionNoticeLiteFeatureConfigV1(enabled=True),
        session_lookup=lambda value: owner if value == "owner" else None,
        processor=processor,
    )
    frame = ValidatedAdmissionFrameLiteV1(
        frame_index=1,
        jpeg_bytes=jpeg_canary,
        encoded_size=len(jpeg_canary),
        width=1,
        height=1,
        exif_orientation=1,
    )
    permit = await service.begin_ingestion("owner")
    try:
        created = await service.create_recognition(permit, (frame,))
    finally:
        service.release_ingestion(permit)
    try:
        for _ in range(200):
            terminal = await service.get_recognition("owner", created.recognition_id)
            if terminal.state is RecognitionStateLiteV1.FAILED:
                break
            await asyncio.sleep(0)
        assert terminal.reason is RecognitionErrorReasonLiteV1.INTERNAL_ERROR
        task = service._jobs[created.recognition_id].processor_task
        assert task is not None and task.done()
        exception = task.exception()
        assert isinstance(exception, AdmissionNoticeLiteError)
        assert exception.__context__ is None
        traceback = exception.__traceback__
        while traceback is not None:
            locals_text = repr(traceback.tb_frame.f_locals)
            assert canary_text not in locals_text
            assert "unexpected-private-jpeg-canary" not in locals_text
            assert traceback.tb_frame.f_locals.get("frames") in (None, ())
            assert "batch" not in traceback.tb_frame.f_locals
            traceback = traceback.tb_next
    finally:
        await service.shutdown()


def test_l4_source_has_no_forbidden_architecture_or_scope() -> None:
    l4_paths = (
        PROJECT_ROOT / "src/service/admission_notice_lite_semantics.py",
        PROJECT_ROOT / "src/service/admission_notice_lite_major_catalog.py",
        PROJECT_ROOT / "src/service/admission_notice_lite_processor.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in l4_paths).lower()
    for forbidden in (
        "certificate_capture",
        "securityenvelope",
        "workfence",
        "capturecoordinator",
        "aes-gcm",
        "aesgcm",
        "privateevidencestore",
        "chatagent",
        "chat_agent",
        "workingmemory",
        "chatdata",
        "paddle",
        "fastapi",
        "student roster",
        "spreadsheet",
        "barcode",
        "rapidfuzz",
        "jieba",
        "pypinyin",
        "levenshtein",
        "authenticity verifier",
    ):
        assert forbidden not in source


def test_l3_approved_manifest_and_runtime_source_are_unchanged() -> None:
    gate = (
        PROJECT_ROOT / "src/service/admission_notice_lite_ocr_qualification.py"
    ).read_text(encoding="utf-8")
    ocr_source = (PROJECT_ROOT / "src/service/admission_notice_lite_ocr.py").read_text(
        encoding="utf-8"
    )
    assert APPROVED_MANIFEST in gate
    assert 'QUALIFIED_OCR_BACKEND_LITE_V1 = "paddle_static"' in ocr_source
    assert 'QUALIFIED_OCR_DEVICE_LITE_V1 = "cpu"' in ocr_source
    assert "QUALIFIED_OCR_THREAD_COUNT_LITE_V1 = 2" in ocr_source
    assert 'QUALIFIED_PADDLE_VERSION_LITE_V1 = "3.3.0"' in ocr_source
    assert 'QUALIFIED_PADDLEOCR_VERSION_LITE_V1 = "3.7.0"' in ocr_source
    assert 'QUALIFIED_PADDLEX_VERSION_LITE_V1 = "3.7.2"' in ocr_source


@pytest.mark.parametrize("frame_count", (1, 2, 3))
def test_semantic_performance_smoke_is_bounded(frame_count: int) -> None:
    batch = _batch(*(_frame(index) for index in range(1, frame_count + 1)))
    started = time.perf_counter()
    for _ in range(50):
        result = recognize_admission_notice_semantics(batch)
        assert result.major == "智能交通技术"
    average_ms = (time.perf_counter() - started) * 1000.0 / 50
    assert average_ms < 100.0

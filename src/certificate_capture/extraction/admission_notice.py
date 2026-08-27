"""Small deterministic extractor for the V1 admission-notice layout."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from certificate_capture.contracts.admission_notice import (
    MAX_ADMISSION_COLLEGE_CODEPOINTS_V1,
    MAX_ADMISSION_MAJOR_CODEPOINTS_V1,
    MAX_ADMISSION_NAME_CODEPOINTS_V1,
    MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1,
    MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1,
    AdmissionFieldStatusV1,
    AdmissionNoticeExtractionIdentityV1,
    AdmissionNoticeExtractionV1,
    ExtractedAdmissionFieldV1,
)
from certificate_capture.contracts.admission_notice_template import (
    AdmissionNoticeTemplateMatchStatusV1,
    AdmissionNoticeTemplateMatchV1,
)
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    OcrPointV1,
    OcrSpanV1,
)
from certificate_capture.extraction.hbtc_admission_notice import (
    COLLEGE_ANCHOR_V1,
    MAJOR_END_ANCHOR_V1,
    MIN_RAW_ENGINE_SCORE_FOR_EXTRACTION_V1,
    NAME_ANCHOR_V1,
    AdmissionNoticeTemplateCompatibilityErrorV1,
    HbtcAdmissionNoticeTemplateMatcherV1,
)
from certificate_capture.extraction.identity import (
    DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1,
)
from certificate_capture.extraction.normalization import (
    contains_forbidden_control_v1,
    is_han_character_v1,
    normalize_candidate_whitespace_v1,
)
from certificate_capture.extraction.reading_order import (
    MappedTextV1,
    ReadingOrderV1,
    TextRunV1,
    forward_run_paths_v1,
    source_polygon_for_spans_v1,
    span_geometry_v1,
)

NAME_REGION_MIN_Y_V1 = 0.08
NAME_REGION_MAX_Y_V1 = 0.48
PROVINCE_REGION_MIN_Y_V1 = 0.12
PROVINCE_REGION_MAX_Y_V1 = 0.72
COLLEGE_REGION_MIN_Y_V1 = 0.18
COLLEGE_REGION_MAX_Y_V1 = 0.82
MAJOR_REGION_MIN_Y_V1 = 0.18
MAJOR_REGION_MAX_Y_V1 = 0.84

APPROVAL_ANCHOR_V1 = "批准"

_PROVINCE_COMMITTEE_SUFFIXES_V1 = (
    "省(市、自治区)高等学校招生委员会",
    "省市自治区高等学校招生委员会",
    "自治区高等学校招生委员会",
    "省高等学校招生委员会",
    "市高等学校招生委员会",
)

# This is a field-specific sanity allowlist, not a general division ontology.
_PROVINCE_LEVEL_NAMES_V1 = frozenset(
    {
        "北京",
        "天津",
        "河北",
        "山西",
        "内蒙古",
        "辽宁",
        "吉林",
        "黑龙江",
        "上海",
        "江苏",
        "浙江",
        "安徽",
        "福建",
        "江西",
        "山东",
        "河南",
        "湖北",
        "湖南",
        "广东",
        "广西",
        "海南",
        "重庆",
        "四川",
        "贵州",
        "云南",
        "西藏",
        "陕西",
        "甘肃",
        "青海",
        "宁夏",
        "新疆",
        "台湾",
        "香港",
        "澳门",
    }
)

_ACADEMIC_UNIT_SUFFIXES_V1 = (
    "教学部",
    "研究院",
    "学院",
    "书院",
    "学部",
    "中心",
    "大类",
    "系",
    "部",
)

_NON_NAME_SALUTATION_FRAGMENTS_V1 = frozenset(
    {
        "亲爱",
        "亲爱的",
        "全体",
        "各位",
        "尊敬",
        "新生",
        "欢迎",
        "诸位",
    }
)
_STRUCTURAL_CHARACTERS_V1 = frozenset({":", "：", ",", "，", "。", ";", "；", "、"})
_MAJOR_PUNCTUATION_V1 = frozenset(
    {"（", "）", "(", ")", "-", "－", "·", "•", "＋", "+"}
)


@dataclass(frozen=True, slots=True)
class _CandidateV1:
    value: str
    source_spans: tuple[OcrSpanV1, ...]
    source_polygon: tuple[OcrPointV1, ...] | None
    source_result_id: uuid.UUID
    source_frame_id: uuid.UUID
    occurrence_key: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _PageFieldDecisionV1:
    status: AdmissionFieldStatusV1
    candidate: _CandidateV1 | None = None


@dataclass(frozen=True, slots=True)
class _PageDecisionsV1:
    name: _PageFieldDecisionV1
    source_province: _PageFieldDecisionV1
    college: _PageFieldDecisionV1
    major: _PageFieldDecisionV1


def _sorted_spans_v1(
    spans: tuple[OcrSpanV1, ...],
) -> tuple[OcrSpanV1, ...]:
    by_id = {span.span_id: span for span in spans}
    return tuple(
        by_id[span_id] for span_id in sorted(by_id, key=lambda value: value.int)
    )


def _scores_qualify_v1(spans: tuple[OcrSpanV1, ...]) -> bool:
    return all(
        span.raw_engine_score is None
        or span.raw_engine_score >= MIN_RAW_ENGINE_SCORE_FOR_EXTRACTION_V1
        for span in spans
    )


def _trim_structural_bounds_v1(
    mapped: MappedTextV1,
    start: int,
    end: int,
) -> tuple[int, int]:
    while (
        start < end
        and mapped.characters[start].source_character in _STRUCTURAL_CHARACTERS_V1
    ):
        start += 1
    while (
        end > start
        and mapped.characters[end - 1].source_character in _STRUCTURAL_CHARACTERS_V1
    ):
        end -= 1
    return start, end


def _only_structural_v1(value: str) -> bool:
    return all(character in _STRUCTURAL_CHARACTERS_V1 for character in value)


def _name_is_valid_v1(value: str) -> bool:
    maximum_length = 8 if "·" in value else 4
    if (
        not 2 <= len(value) <= min(MAX_ADMISSION_NAME_CODEPOINTS_V1, maximum_length)
        or contains_forbidden_control_v1(value)
        or value[0] == "·"
        or value[-1] == "·"
        or "··" in value
        or any(fragment in value for fragment in _NON_NAME_SALUTATION_FRAGMENTS_V1)
    ):
        return False
    return all(
        is_han_character_v1(character) or character == "·" for character in value
    )


def _province_is_valid_v1(value: str) -> bool:
    return bool(
        1 <= len(value) <= MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1
        and value in _PROVINCE_LEVEL_NAMES_V1
        and not contains_forbidden_control_v1(value)
    )


def _balanced_parentheses_v1(value: str) -> bool:
    stack: list[str] = []
    closing = {"）": "（", ")": "("}
    for character in value:
        if character in {"（", "("}:
            stack.append(character)
        elif character in closing and (not stack or stack.pop() != closing[character]):
            return False
    return not stack


def _common_field_characters_are_valid_v1(value: str) -> bool:
    return all(
        is_han_character_v1(character)
        or (character.isascii() and character.isalnum())
        or character == " "
        or character in _MAJOR_PUNCTUATION_V1
        for character in value
    )


def _academic_suffix_v1(value: str) -> str | None:
    return next(
        (
            suffix
            for suffix in _ACADEMIC_UNIT_SUFFIXES_V1
            if value.endswith(suffix) and len(value) > len(suffix)
        ),
        None,
    )


def _college_is_valid_v1(value: str) -> bool:
    return bool(
        1 < len(value) <= MAX_ADMISSION_COLLEGE_CODEPOINTS_V1
        and len(value) <= 64
        and not contains_forbidden_control_v1(value)
        and _common_field_characters_are_valid_v1(value)
        and any(is_han_character_v1(character) for character in value)
        and _academic_suffix_v1(value) is not None
        and not any(
            anchor in value
            for anchor in (
                NAME_ANCHOR_V1,
                "招生委员会",
                "录取到我校",
                APPROVAL_ANCHOR_V1,
                MAJOR_END_ANCHOR_V1,
            )
        )
    )


def _major_is_valid_v1(value: str) -> bool:
    return bool(
        1 < len(value) <= MAX_ADMISSION_MAJOR_CODEPOINTS_V1
        and not contains_forbidden_control_v1(value)
        and _common_field_characters_are_valid_v1(value)
        and any(is_han_character_v1(character) for character in value)
        and _balanced_parentheses_v1(value)
        and not any(
            anchor in value
            for anchor in (
                NAME_ANCHOR_V1,
                "招生委员会",
                "录取到我校",
                APPROVAL_ANCHOR_V1,
                MAJOR_END_ANCHOR_V1,
            )
        )
    )


def _major_fragment_is_valid_v1(value: str) -> bool:
    return bool(
        value
        and len(value) <= MAX_ADMISSION_MAJOR_CODEPOINTS_V1
        and not contains_forbidden_control_v1(value)
        and _common_field_characters_are_valid_v1(value)
        and any(is_han_character_v1(character) for character in value)
        and not any(
            anchor in value
            for anchor in (
                NAME_ANCHOR_V1,
                "招生委员会",
                "录取到我校",
                APPROVAL_ANCHOR_V1,
                MAJOR_END_ANCHOR_V1,
            )
        )
    )


def _candidate_v1(
    *,
    page: OcrPageResultV1,
    mapped: MappedTextV1,
    start: int,
    end: int,
    anchor_start: int,
    anchor_end: int,
    validator,
) -> _CandidateV1 | None:
    start, end = _trim_structural_bounds_v1(mapped, start, end)
    if start >= end:
        return None
    value = normalize_candidate_whitespace_v1(mapped.source_value_v1(start, end))
    if not validator(value):
        return None
    source_spans = _sorted_spans_v1(mapped.source_spans_v1(start, end))
    authority_spans = _sorted_spans_v1(
        mapped.source_spans_v1(
            min(start, anchor_start),
            max(end, anchor_end),
        )
    )
    if (
        not source_spans
        or len(source_spans) > MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1
        or not _scores_qualify_v1(authority_spans)
    ):
        return None
    anchor_spans = mapped.source_spans_v1(anchor_start, anchor_end)
    return _CandidateV1(
        value=value,
        source_spans=source_spans,
        source_polygon=source_polygon_for_spans_v1(source_spans),
        source_result_id=page.result_id,
        source_frame_id=page.frame_id,
        occurrence_key=(
            page.result_id,
            tuple(span.span_id for span in source_spans),
            tuple(span.span_id for span in anchor_spans),
            start,
            end,
            anchor_start,
            anchor_end,
        ),
    )


def _decision_from_candidates_v1(
    candidates: list[_CandidateV1],
) -> _PageFieldDecisionV1:
    unique: dict[tuple[object, ...], _CandidateV1] = {
        candidate.occurrence_key: candidate for candidate in candidates
    }
    if not unique:
        return _PageFieldDecisionV1(AdmissionFieldStatusV1.NOT_FOUND)
    if len(unique) != 1:
        return _PageFieldDecisionV1(AdmissionFieldStatusV1.AMBIGUOUS)
    return _PageFieldDecisionV1(
        AdmissionFieldStatusV1.FOUND,
        next(iter(unique.values())),
    )


def _direct_gap_is_bounded_v1(
    mapped: MappedTextV1,
    candidate_end: int,
    anchor_start: int,
) -> bool:
    if candidate_end <= 0 or anchor_start >= len(mapped.characters):
        return False
    candidate_span = mapped.characters[candidate_end - 1].span
    anchor_span = mapped.characters[anchor_start].span
    if candidate_span is anchor_span:
        return True
    candidate_geometry = span_geometry_v1(candidate_span)
    anchor_geometry = span_geometry_v1(anchor_span)
    if candidate_geometry is None or anchor_geometry is None:
        return False
    gap = anchor_geometry.min_x - candidate_geometry.max_x
    return gap <= max(
        0.045,
        1.25 * max(candidate_geometry.height, anchor_geometry.height),
    )


def _has_source_boundary_v1(
    mapped: MappedTextV1,
    candidate_end: int,
    anchor_start: int,
) -> bool:
    if candidate_end <= 0 or anchor_start >= len(mapped.characters):
        return False
    candidate_character = mapped.characters[candidate_end - 1]
    anchor_character = mapped.characters[anchor_start]
    if candidate_character.span is not anchor_character.span:
        return True
    between = candidate_character.span.text[
        candidate_character.source_offset + 1 : anchor_character.source_offset
    ]
    return any(character.isspace() for character in between)


def _name_candidates_v1(
    page: OcrPageResultV1,
    reading: ReadingOrderV1,
) -> list[_CandidateV1]:
    candidates: list[_CandidateV1] = []
    for line in reading.lines:
        if not NAME_REGION_MIN_Y_V1 <= line.center_y <= NAME_REGION_MAX_Y_V1:
            continue
        for run in line.runs:
            mapped = run.mapped_text_v1()
            for anchor_start in mapped.occurrences_v1(NAME_ANCHOR_V1):
                anchor_end = anchor_start + len(NAME_ANCHOR_V1)
                candidate_start = anchor_start
                while candidate_start > 0:
                    character = mapped.characters[candidate_start - 1].source_character
                    if not (is_han_character_v1(character) or character == "·"):
                        break
                    candidate_start -= 1
                prefix = mapped.text[:candidate_start]
                suffix = mapped.text[anchor_end:]
                if (
                    (prefix and not _only_structural_v1(prefix))
                    or (suffix and not _only_structural_v1(suffix))
                    or not _direct_gap_is_bounded_v1(
                        mapped,
                        anchor_start,
                        anchor_start,
                    )
                ):
                    continue
                candidate = _candidate_v1(
                    page=page,
                    mapped=mapped,
                    start=candidate_start,
                    end=anchor_start,
                    anchor_start=anchor_start,
                    anchor_end=anchor_end,
                    validator=_name_is_valid_v1,
                )
                if candidate is not None:
                    candidates.append(candidate)
    return candidates


def _province_candidates_v1(
    page: OcrPageResultV1,
    reading: ReadingOrderV1,
) -> list[_CandidateV1]:
    candidates: list[_CandidateV1] = []
    for line in reading.lines:
        if not (PROVINCE_REGION_MIN_Y_V1 <= line.center_y <= PROVINCE_REGION_MAX_Y_V1):
            continue
        for run in line.runs:
            first_mapped = run.mapped_text_v1()
            if "经" not in first_mapped.text:
                continue
            for path in forward_run_paths_v1(
                reading,
                run,
                maximum_lines=3,
            ):
                mapped = MappedTextV1.from_runs_v1(path)
                for start_anchor in mapped.occurrences_v1("经"):
                    if start_anchor > 0 and not _only_structural_v1(
                        mapped.text[:start_anchor]
                    ):
                        continue
                    candidate_start = start_anchor + 1
                    for suffix in _PROVINCE_COMMITTEE_SUFFIXES_V1:
                        suffix_start = mapped.text.find(
                            suffix,
                            candidate_start,
                        )
                        if suffix_start < 0:
                            continue
                        committee_end = suffix_start + len(suffix)
                        approval_start = mapped.text.find(
                            APPROVAL_ANCHOR_V1,
                            committee_end,
                        )
                        if (
                            approval_start < committee_end
                            or approval_start - committee_end > 8
                            or (
                                mapped.text[committee_end:approval_start]
                                and not _only_structural_v1(
                                    mapped.text[committee_end:approval_start]
                                )
                            )
                        ):
                            continue
                        candidate = _candidate_v1(
                            page=page,
                            mapped=mapped,
                            start=candidate_start,
                            end=suffix_start,
                            anchor_start=start_anchor,
                            anchor_end=approval_start + len(APPROVAL_ANCHOR_V1),
                            validator=_province_is_valid_v1,
                        )
                        if candidate is not None:
                            candidates.append(candidate)
    return candidates


def _college_end_v1(text: str, start: int, end: int) -> int | None:
    value = text[start:end]
    major_anchor = value.find(MAJOR_END_ANCHOR_V1)
    search_end = len(value) if major_anchor < 0 else major_anchor
    bounded = value[:search_end]
    suffix_ends: list[int] = []
    for suffix in _ACADEMIC_UNIT_SUFFIXES_V1:
        position = bounded.find(suffix)
        while position >= 0:
            if position > 0:
                suffix_ends.append(position + len(suffix))
            position = bounded.find(suffix, position + 1)
    if not suffix_ends:
        return None
    return start + min(suffix_ends)


def _college_candidates_in_mapped_v1(
    *,
    page: OcrPageResultV1,
    mapped: MappedTextV1,
    candidate_start: int,
    anchor_start: int,
    anchor_end: int,
) -> list[_CandidateV1]:
    candidate_end = _college_end_v1(
        mapped.text,
        candidate_start,
        len(mapped.text),
    )
    if candidate_end is None:
        return []
    candidate = _candidate_v1(
        page=page,
        mapped=mapped,
        start=candidate_start,
        end=candidate_end,
        anchor_start=anchor_start,
        anchor_end=anchor_end,
        validator=_college_is_valid_v1,
    )
    return [] if candidate is None else [candidate]


def _college_candidates_v1(
    page: OcrPageResultV1,
    reading: ReadingOrderV1,
) -> list[_CandidateV1]:
    candidates: list[_CandidateV1] = []
    for line in reading.lines:
        if not (COLLEGE_REGION_MIN_Y_V1 <= line.center_y <= COLLEGE_REGION_MAX_Y_V1):
            continue
        for run in line.runs:
            mapped = run.mapped_text_v1()
            for anchor_start in mapped.occurrences_v1(COLLEGE_ANCHOR_V1):
                anchor_end = anchor_start + len(COLLEGE_ANCHOR_V1)
                prefix = mapped.text[:anchor_start]
                stripped_prefix = prefix.strip("".join(_STRUCTURAL_CHARACTERS_V1))
                if stripped_prefix and not stripped_prefix.endswith(APPROVAL_ANCHOR_V1):
                    continue
                same_line = _college_candidates_in_mapped_v1(
                    page=page,
                    mapped=mapped,
                    candidate_start=anchor_end,
                    anchor_start=anchor_start,
                    anchor_end=anchor_end,
                )
                if same_line:
                    candidates.extend(same_line)
                    continue
                if mapped.text[anchor_end:] and not _only_structural_v1(
                    mapped.text[anchor_end:]
                ):
                    continue
                for next_run in reading.related_runs_v1(
                    run,
                    run.line_index + 1,
                ):
                    combined = MappedTextV1.from_runs_v1((run, next_run))
                    candidates.extend(
                        _college_candidates_in_mapped_v1(
                            page=page,
                            mapped=combined,
                            candidate_start=anchor_end,
                            anchor_start=anchor_start,
                            anchor_end=anchor_end,
                        )
                    )
    return candidates


def _major_start_after_college_v1(
    text: str,
    end: int,
) -> int | None:
    college_anchor_start = text.rfind(COLLEGE_ANCHOR_V1, 0, end)
    if college_anchor_start < 0:
        return None
    after_anchor = college_anchor_start + len(COLLEGE_ANCHOR_V1)
    college_end = _college_end_v1(text, after_anchor, end)
    return college_end


def _major_candidates_v1(
    page: OcrPageResultV1,
    reading: ReadingOrderV1,
) -> list[_CandidateV1]:
    candidates: list[_CandidateV1] = []
    for line in reading.lines:
        if not MAJOR_REGION_MIN_Y_V1 <= line.center_y <= MAJOR_REGION_MAX_Y_V1:
            continue
        for run in line.runs:
            current = run.mapped_text_v1()
            for anchor_start in current.occurrences_v1(MAJOR_END_ANCHOR_V1):
                anchor_end = anchor_start + len(MAJOR_END_ANCHOR_V1)
                if current.text[anchor_end:] and not _only_structural_v1(
                    current.text[anchor_end:]
                ):
                    continue
                current_start = (
                    _major_start_after_college_v1(
                        current.text,
                        anchor_start,
                    )
                    or 0
                )
                current_candidate = normalize_candidate_whitespace_v1(
                    current.source_value_v1(
                        current_start,
                        anchor_start,
                    )
                )
                previous_runs = reading.related_runs_v1(
                    run,
                    run.line_index - 1,
                )
                eligible_previous: list[tuple[TextRunV1, MappedTextV1]] = []
                for previous in previous_runs:
                    previous_mapped = previous.mapped_text_v1()
                    previous_value = normalize_candidate_whitespace_v1(
                        previous_mapped.source_value_v1(
                            0,
                            len(previous_mapped.characters),
                        )
                    )
                    if (
                        _college_is_valid_v1(previous_value)
                        or COLLEGE_ANCHOR_V1 in previous_mapped.text
                        or MAJOR_END_ANCHOR_V1 in previous_mapped.text
                        or not _major_fragment_is_valid_v1(previous_value)
                    ):
                        continue
                    eligible_previous.append((previous, previous_mapped))
                combined_candidates: list[tuple[MappedTextV1, int, int, int, int]] = []
                current_is_valid = _major_is_valid_v1(current_candidate)
                if current_is_valid:
                    combined_candidates.append(
                        (
                            current,
                            current_start,
                            anchor_start,
                            anchor_start,
                            anchor_end,
                        )
                    )
                elif eligible_previous:
                    for previous, previous_mapped in eligible_previous:
                        combined = MappedTextV1.from_runs_v1((previous, run))
                        offset = len(previous_mapped.characters)
                        combined_candidates.append(
                            (
                                combined,
                                0,
                                offset + anchor_start,
                                offset + anchor_start,
                                offset + anchor_end,
                            )
                        )
                for (
                    mapped,
                    candidate_start,
                    candidate_end,
                    combined_anchor_start,
                    combined_anchor_end,
                ) in combined_candidates:
                    if not _has_source_boundary_v1(
                        mapped,
                        candidate_end,
                        combined_anchor_start,
                    ):
                        continue
                    candidate = _candidate_v1(
                        page=page,
                        mapped=mapped,
                        start=candidate_start,
                        end=candidate_end,
                        anchor_start=combined_anchor_start,
                        anchor_end=combined_anchor_end,
                        validator=_major_is_valid_v1,
                    )
                    if candidate is not None:
                        candidates.append(candidate)
    return candidates


def _page_decisions_v1(
    page: OcrPageResultV1,
    reading: ReadingOrderV1,
) -> _PageDecisionsV1:
    return _PageDecisionsV1(
        name=_decision_from_candidates_v1(_name_candidates_v1(page, reading)),
        source_province=_decision_from_candidates_v1(
            _province_candidates_v1(page, reading)
        ),
        college=_decision_from_candidates_v1(_college_candidates_v1(page, reading)),
        major=_decision_from_candidates_v1(_major_candidates_v1(page, reading)),
    )


def _empty_field_v1(
    status: AdmissionFieldStatusV1,
) -> ExtractedAdmissionFieldV1:
    return ExtractedAdmissionFieldV1(
        status=status,
        value=None,
        source_span_ids=(),
        source_polygon=None,
    )


def _aggregate_field_v1(
    decisions: tuple[_PageFieldDecisionV1, ...],
) -> ExtractedAdmissionFieldV1:
    if any(
        decision.status is AdmissionFieldStatusV1.AMBIGUOUS for decision in decisions
    ):
        return _empty_field_v1(AdmissionFieldStatusV1.AMBIGUOUS)
    candidates = tuple(
        decision.candidate
        for decision in decisions
        if decision.status is AdmissionFieldStatusV1.FOUND
        and decision.candidate is not None
    )
    if not candidates:
        return _empty_field_v1(AdmissionFieldStatusV1.NOT_FOUND)
    values = {candidate.value for candidate in candidates}
    if len(values) != 1:
        return _empty_field_v1(AdmissionFieldStatusV1.AMBIGUOUS)
    spans = _sorted_spans_v1(
        tuple(span for candidate in candidates for span in candidate.source_spans)
    )
    if len(spans) > MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1:
        return _empty_field_v1(AdmissionFieldStatusV1.AMBIGUOUS)
    polygon = candidates[0].source_polygon if len(candidates) == 1 else None
    return ExtractedAdmissionFieldV1(
        status=AdmissionFieldStatusV1.FOUND,
        value=next(iter(values)),
        source_span_ids=tuple(span.span_id for span in spans),
        source_polygon=polygon,
    )


class AdmissionNoticeExtractorV1:
    """Backend-independent deterministic extractor over validated M6A pages."""

    __slots__ = ("_identity", "_template_matcher")

    def __init__(
        self,
        identity: AdmissionNoticeExtractionIdentityV1 = (
            DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1
        ),
    ) -> None:
        if not isinstance(identity, AdmissionNoticeExtractionIdentityV1):
            raise TypeError("identity must be AdmissionNoticeExtractionIdentityV1")
        if identity != DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1:
            raise ValueError("extraction identity is unsupported")
        self._identity = identity
        self._template_matcher = HbtcAdmissionNoticeTemplateMatcherV1()

    @property
    def identity_v1(self) -> AdmissionNoticeExtractionIdentityV1:
        return self._identity

    def match_pages_v1(
        self,
        pages: tuple[OcrPageResultV1, ...],
    ) -> AdmissionNoticeTemplateMatchV1:
        return self._template_matcher.match_pages_v1(pages)

    def extract_pages_v1(
        self,
        pages: tuple[OcrPageResultV1, ...],
    ) -> AdmissionNoticeExtractionV1:
        (
            template_match,
            ordered,
            matched_page_readings,
        ) = self._template_matcher._match_and_select_page_readings_v1(
            pages,
        )
        if template_match.status is not AdmissionNoticeTemplateMatchStatusV1.MATCHED:
            raise AdmissionNoticeTemplateCompatibilityErrorV1(template_match.status)
        capture_epoch = ordered[0].capture_epoch
        decisions = tuple(
            _page_decisions_v1(page, reading) for page, reading in matched_page_readings
        )
        return AdmissionNoticeExtractionV1(
            capture_epoch=capture_epoch,
            source_ocr_result_ids=tuple(
                sorted(
                    (page.result_id for page in ordered),
                    key=lambda value: value.int,
                )
            ),
            source_frame_ids=tuple(
                sorted(
                    (page.frame_id for page in ordered),
                    key=lambda value: value.int,
                )
            ),
            extraction_identity=self._identity,
            name=_aggregate_field_v1(tuple(decision.name for decision in decisions)),
            source_province=_aggregate_field_v1(
                tuple(decision.source_province for decision in decisions)
            ),
            college=_aggregate_field_v1(
                tuple(decision.college for decision in decisions)
            ),
            major=_aggregate_field_v1(tuple(decision.major for decision in decisions)),
        )

    def __repr__(self) -> str:
        return (
            f"AdmissionNoticeExtractorV1(extractor_id={self._identity.extractor_id!r})"
        )


__all__ = [
    "APPROVAL_ANCHOR_V1",
    "COLLEGE_ANCHOR_V1",
    "MAJOR_END_ANCHOR_V1",
    "MIN_RAW_ENGINE_SCORE_FOR_EXTRACTION_V1",
    "NAME_ANCHOR_V1",
    "AdmissionNoticeExtractorV1",
]

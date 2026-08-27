"""Deterministic compatibility matcher for the single HBTC V1 template."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from certificate_capture.contracts.admission_notice import (
    MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
)
from certificate_capture.contracts.admission_notice_template import (
    ADMISSION_BODY_ANCHOR_ID_V1,
    ADMISSION_COMMITTEE_ANCHOR_ID_V1,
    ADMISSION_NOTICE_BODY_ANCHOR_IDS_V1,
    ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1,
    HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1,
    HBTC_ADMISSION_NOTICE_TEMPLATE_V1,
    INSTITUTION_HEADING_ANCHOR_ID_V1,
    MAJOR_STUDY_ANCHOR_ID_V1,
    MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1,
    STUDENT_SALUTATION_ANCHOR_ID_V1,
    AdmissionNoticeTemplateMatchStatusV1,
    AdmissionNoticeTemplateMatchV1,
    AdmissionNoticeTemplateV1,
)
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
)
from certificate_capture.extraction.normalization import (
    is_han_character_v1,
)
from certificate_capture.extraction.reading_order import (
    MappedTextV1,
    ReadingOrderV1,
    forward_run_paths_v1,
    reconstruct_reading_order_v1,
    source_polygon_for_spans_v1,
    span_geometry_v1,
)

MIN_RAW_ENGINE_SCORE_FOR_EXTRACTION_V1 = 0.50

NAME_ANCHOR_V1 = "同学"
COMMITTEE_ANCHOR_V1 = "高等学校招生委员会"
COLLEGE_ANCHOR_V1 = "你被录取到我校"
MAJOR_END_ANCHOR_V1 = "专业学习"

TITLE_REGION_MAX_Y_V1 = 0.20
TITLE_MIN_WIDTH_V1 = 0.16
TITLE_CENTER_X_MIN_V1 = 0.15
TITLE_CENTER_X_MAX_V1 = 0.85
CONFLICTING_TITLE_MIN_WIDTH_V1 = 0.36
MAX_BODY_ANCHOR_OCCURRENCES_PER_ID_V1 = 16
MAX_ADMISSION_TO_MAJOR_HORIZONTAL_GAP_V1 = 0.18

_TITLE_SURROUNDING_PUNCTUATION_V1 = ":,.;，。：；"
_INSTITUTION_HEADING_SUFFIXES_V1 = (
    "职业技术学院",
    "大学",
    "学院",
    "学校",
    "分校",
)
_STRONG_INSTITUTION_HEADING_SUFFIXES_V1 = ("职业技术学院", "大学")
_TRUSTED_INSTITUTION_NESTING_MODIFIERS_V1 = ("附属", "分校")
_BODY_STRUCTURAL_CHARACTERS_V1 = frozenset({":", ",", ".", ";", "。", "；", "、"})
_PROVINCE_COMMITTEE_PREFIXES_V1 = (
    "省(市、自治区)",
    "省市自治区",
    "自治区",
    "省",
    "市",
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
_MAJOR_PUNCTUATION_V1 = frozenset({"(", ")", "-", "－", "·", "•", "＋", "+"})


@dataclass(frozen=True, slots=True)
class _HeadingCandidateV1:
    text: str
    span_ids: tuple[uuid.UUID, ...]
    start_key: tuple[object, ...]
    end_key: tuple[object, ...]
    max_y: float
    width: float


@dataclass(frozen=True, slots=True)
class _BodyAnchorRuleV1:
    anchor_id: str
    text: str
    minimum_center_y: float
    maximum_center_y: float
    maximum_lines: int


@dataclass(frozen=True, slots=True)
class _AnchorOccurrenceV1:
    anchor_id: str
    start_key: tuple[object, ...]
    end_key: tuple[object, ...]
    identity_key: tuple[object, ...]
    min_x: float
    max_x: float


@dataclass(frozen=True, slots=True)
class _AnchorPathStateV1:
    anchor_ids: tuple[str, ...]
    last: _AnchorOccurrenceV1 | None
    anchor_line_indices: frozenset[int]


_BODY_ANCHOR_RULES_V1 = (
    _BodyAnchorRuleV1(
        STUDENT_SALUTATION_ANCHOR_ID_V1,
        NAME_ANCHOR_V1,
        0.12,
        0.46,
        1,
    ),
    _BodyAnchorRuleV1(
        ADMISSION_COMMITTEE_ANCHOR_ID_V1,
        COMMITTEE_ANCHOR_V1,
        0.20,
        0.60,
        3,
    ),
    _BodyAnchorRuleV1(
        ADMISSION_BODY_ANCHOR_ID_V1,
        COLLEGE_ANCHOR_V1,
        0.28,
        0.70,
        2,
    ),
    _BodyAnchorRuleV1(
        MAJOR_STUDY_ANCHOR_ID_V1,
        MAJOR_END_ANCHOR_V1,
        0.38,
        0.78,
        2,
    ),
)


def ordered_admission_notice_pages_v1(
    pages: tuple[OcrPageResultV1, ...],
) -> tuple[OcrPageResultV1, ...]:
    """Validate and order the bounded M6A inputs without using frame order."""

    if (
        not isinstance(pages, tuple)
        or not 1 <= len(pages) <= MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1
        or not all(isinstance(page, OcrPageResultV1) for page in pages)
    ):
        raise ValueError("admission extraction input is invalid")
    ordered = tuple(sorted(pages, key=lambda page: page.result_id.int))
    capture_epoch = ordered[0].capture_epoch
    if (
        any(page.capture_epoch is not capture_epoch for page in ordered)
        or len({page.result_id for page in ordered}) != len(ordered)
        or len({page.frame_id for page in ordered}) != len(ordered)
    ):
        raise ValueError("admission extraction input is invalid")
    all_span_ids = tuple(span.span_id for page in ordered for span in page.spans)
    if len(set(all_span_ids)) != len(all_span_ids):
        raise ValueError("admission extraction span identity is invalid")
    return ordered


def _mapped_position_key_v1(
    mapped: MappedTextV1,
    index: int,
    *,
    after_character: bool,
) -> tuple[object, ...]:
    character = mapped.characters[index]
    geometry = span_geometry_v1(character.span)
    if geometry is None:
        raise ValueError("anchor geometry is invalid")
    text_length = max(1, len(character.span.text))
    source_offset = character.source_offset + int(after_character)
    approximate_x = geometry.min_x + geometry.width * (source_offset / text_length)
    return (
        character.line_index,
        approximate_x,
        character.span.span_id.int,
        source_offset,
    )


def _heading_candidate_v1(
    mapped: MappedTextV1,
) -> _HeadingCandidateV1 | None:
    if not mapped.characters:
        return None
    spans = mapped.source_spans_v1(0, len(mapped.characters))
    polygon = source_polygon_for_spans_v1(spans)
    if polygon is None:
        return None
    min_x = polygon[0].x
    max_x = polygon[2].x
    max_y = polygon[2].y
    width = max_x - min_x
    center_x = (min_x + max_x) / 2.0
    if (
        max_y > TITLE_REGION_MAX_Y_V1
        or width < TITLE_MIN_WIDTH_V1
        or not TITLE_CENTER_X_MIN_V1 <= center_x <= TITLE_CENTER_X_MAX_V1
    ):
        return None
    text = mapped.text.strip(_TITLE_SURROUNDING_PUNCTUATION_V1)
    if not text:
        return None
    return _HeadingCandidateV1(
        text=text,
        span_ids=tuple(
            sorted(
                (span.span_id for span in spans),
                key=lambda value: value.int,
            )
        ),
        start_key=_mapped_position_key_v1(
            mapped,
            0,
            after_character=False,
        ),
        end_key=_mapped_position_key_v1(
            mapped,
            len(mapped.characters) - 1,
            after_character=True,
        ),
        max_y=max_y,
        width=width,
    )


def _heading_candidates_v1(
    reading: ReadingOrderV1,
) -> tuple[_HeadingCandidateV1, ...]:
    candidates: dict[
        tuple[str, tuple[uuid.UUID, ...]],
        _HeadingCandidateV1,
    ] = {}
    for line in reading.lines:
        for run in line.runs:
            candidate = _heading_candidate_v1(run.mapped_text_v1())
            if candidate is not None:
                candidates[(candidate.text, candidate.span_ids)] = candidate
            for related in reading.related_runs_v1(
                run,
                run.line_index + 1,
            ):
                related_candidate = _heading_candidate_v1(related.mapped_text_v1())
                combined = _heading_candidate_v1(
                    MappedTextV1.from_runs_v1((run, related))
                )
                if (
                    candidate is not None
                    and candidate.text == HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
                ) or (
                    related_candidate is not None
                    and related_candidate.text
                    == HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
                ):
                    if (
                        combined is not None
                        and _has_nested_trusted_institution_modifier_v1(combined.text)
                    ):
                        candidates[(combined.text, combined.span_ids)] = combined
                    continue
                if combined is not None:
                    candidates[(combined.text, combined.span_ids)] = combined
    return tuple(
        sorted(
            candidates.values(),
            key=lambda item: (
                item.start_key,
                item.end_key,
                item.text,
                tuple(span_id.int for span_id in item.span_ids),
            ),
        )
    )


def _has_nested_trusted_institution_modifier_v1(text: str) -> bool:
    index = text.find(HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1)
    if index < 0:
        return False
    before = text[:index]
    after = text[index + len(HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1) :]
    return bool(
        any(
            before.endswith(modifier) or after.startswith(modifier)
            for modifier in _TRUSTED_INSTITUTION_NESTING_MODIFIERS_V1
        )
    )


def _institution_suffix_end_positions_v1(text: str) -> frozenset[int]:
    positions: set[int] = set()
    for suffix in _INSTITUTION_HEADING_SUFFIXES_V1:
        start = 0
        while True:
            index = text.find(suffix, start)
            if index < 0:
                break
            if index > 0 and any(
                is_han_character_v1(character) for character in text[:index]
            ):
                positions.add(index + len(suffix))
            start = index + 1
    return frozenset(positions)


def _trusted_institution_end_positions_v1(text: str) -> frozenset[int]:
    positions: set[int] = set()
    start = 0
    while True:
        index = text.find(HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1, start)
        if index < 0:
            break
        positions.add(index + len(HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1))
        start = index + 1
    return frozenset(positions)


def _looks_like_different_institution_v1(
    heading: _HeadingCandidateV1,
) -> bool:
    if len(heading.text) > 48 or heading.max_y > TITLE_REGION_MAX_Y_V1:
        return False
    suffix_ends = _institution_suffix_end_positions_v1(heading.text)
    trusted_ends = _trusted_institution_end_positions_v1(heading.text)
    conflicting_ends = suffix_ends - trusted_ends
    if not conflicting_ends:
        return False
    has_strong_institution_form = any(
        any(
            heading.text.endswith(suffix, 0, end)
            for suffix in _STRONG_INSTITUTION_HEADING_SUFFIXES_V1
        )
        for end in conflicting_ends
    )
    has_nested_trusted_name = bool(
        trusted_ends and any(end > min(trusted_ends) for end in conflicting_ends)
    )
    return bool(
        heading.width >= CONFLICTING_TITLE_MIN_WIDTH_V1
        or has_strong_institution_form
        or has_nested_trusted_name
    )


def _only_body_structural_v1(text: str) -> bool:
    return all(character in _BODY_STRUCTURAL_CHARACTERS_V1 for character in text)


def _name_fragment_is_valid_v1(text: str) -> bool:
    maximum_length = 8 if "·" in text else 4
    return bool(
        2 <= len(text) <= maximum_length
        and text[0] != "·"
        and text[-1] != "·"
        and "··" not in text
        and not any(fragment in text for fragment in _NON_NAME_SALUTATION_FRAGMENTS_V1)
        and all(
            is_han_character_v1(character) or character == "·" for character in text
        )
    )


def _salutation_anchor_context_v1(
    mapped: MappedTextV1,
    start: int,
    end: int,
) -> bool:
    if not _only_body_structural_v1(mapped.text[end:]):
        return False
    if start == 0:
        return True
    candidate_start = start
    while candidate_start > 0 and (
        is_han_character_v1(mapped.text[candidate_start - 1])
        or mapped.text[candidate_start - 1] == "·"
    ):
        candidate_start -= 1
    return bool(
        _name_fragment_is_valid_v1(mapped.text[candidate_start:start])
        and _only_body_structural_v1(mapped.text[:candidate_start])
    )


def _committee_anchor_context_v1(
    mapped: MappedTextV1,
    start: int,
) -> bool:
    prefix = mapped.text[:start].rstrip("".join(_BODY_STRUCTURAL_CHARACTERS_V1))
    for committee_prefix in _PROVINCE_COMMITTEE_PREFIXES_V1:
        if not prefix.endswith(committee_prefix):
            continue
        before_prefix = prefix[: -len(committee_prefix)]
        start_anchor = before_prefix.rfind("经")
        if start_anchor < 0:
            continue
        province = before_prefix[start_anchor + 1 :]
        if (
            1 <= len(province) <= 4
            and all(is_han_character_v1(character) for character in province)
            and _only_body_structural_v1(before_prefix[:start_anchor])
        ):
            return True
    return False


def _admission_anchor_context_v1(
    mapped: MappedTextV1,
    start: int,
) -> bool:
    prefix = mapped.text[:start].rstrip("".join(_BODY_STRUCTURAL_CHARACTERS_V1))
    return prefix.endswith("批准")


def _source_boundary_before_v1(
    mapped: MappedTextV1,
    start: int,
) -> bool:
    if start <= 0:
        return False
    previous = mapped.characters[start - 1]
    current = mapped.characters[start]
    return bool(
        previous.span is not current.span
        or current.source_space_before
        or current.line_break_before
    )


def _major_fragment_is_valid_v1(text: str) -> bool:
    stack: list[str] = []
    for character in text:
        if character == "(":
            stack.append(character)
        elif character == ")" and (not stack or stack.pop() != "("):
            return False
    return bool(
        not stack
        and 2 <= len(text) <= 64
        and any(is_han_character_v1(character) for character in text)
        and all(
            is_han_character_v1(character)
            or (character.isascii() and character.isalnum())
            or character in _MAJOR_PUNCTUATION_V1
            for character in text
        )
        and not any(
            anchor in text
            for anchor in (
                NAME_ANCHOR_V1,
                "招生委员会",
                "录取到我校",
                "批准",
                MAJOR_END_ANCHOR_V1,
            )
        )
    )


def _major_anchor_context_v1(
    mapped: MappedTextV1,
    start: int,
    end: int,
) -> bool:
    if not _only_body_structural_v1(
        mapped.text[end:]
    ) or not _source_boundary_before_v1(mapped, start):
        return False
    candidate_start = start
    while candidate_start > 0 and (
        is_han_character_v1(mapped.text[candidate_start - 1])
        or (
            mapped.text[candidate_start - 1].isascii()
            and mapped.text[candidate_start - 1].isalnum()
        )
        or mapped.text[candidate_start - 1] in _MAJOR_PUNCTUATION_V1
    ):
        candidate_start -= 1
    return _major_fragment_is_valid_v1(mapped.text[candidate_start:start])


def _body_anchor_context_is_valid_v1(
    rule: _BodyAnchorRuleV1,
    mapped: MappedTextV1,
    start: int,
    end: int,
) -> bool:
    if rule.anchor_id == STUDENT_SALUTATION_ANCHOR_ID_V1:
        return _salutation_anchor_context_v1(mapped, start, end)
    if rule.anchor_id == ADMISSION_COMMITTEE_ANCHOR_ID_V1:
        return _committee_anchor_context_v1(mapped, start)
    if rule.anchor_id == ADMISSION_BODY_ANCHOR_ID_V1:
        return _admission_anchor_context_v1(mapped, start)
    if rule.anchor_id == MAJOR_STUDY_ANCHOR_ID_V1:
        return _major_anchor_context_v1(mapped, start, end)
    raise ValueError("unsupported admission-notice body anchor")


def _body_anchor_occurrences_v1(
    reading: ReadingOrderV1,
    rule: _BodyAnchorRuleV1,
    *,
    after_heading: tuple[object, ...],
) -> tuple[_AnchorOccurrenceV1, ...]:
    occurrences: dict[tuple[object, ...], _AnchorOccurrenceV1] = {}
    for line in reading.lines:
        for run in line.runs:
            for path in forward_run_paths_v1(
                reading,
                run,
                maximum_lines=rule.maximum_lines,
            ):
                mapped = MappedTextV1.from_runs_v1(path)
                for start in mapped.occurrences_v1(rule.text):
                    end = start + len(rule.text)
                    if not _body_anchor_context_is_valid_v1(
                        rule,
                        mapped,
                        start,
                        end,
                    ):
                        continue
                    spans = mapped.source_spans_v1(start, end)
                    polygon = source_polygon_for_spans_v1(spans)
                    if polygon is None:
                        continue
                    center_y = (polygon[0].y + polygon[2].y) / 2.0
                    if not (rule.minimum_center_y <= center_y <= rule.maximum_center_y):
                        continue
                    start_key = _mapped_position_key_v1(
                        mapped,
                        start,
                        after_character=False,
                    )
                    end_key = _mapped_position_key_v1(
                        mapped,
                        end - 1,
                        after_character=True,
                    )
                    if start_key <= after_heading:
                        continue
                    identity_key = (
                        mapped.characters[start].span.span_id,
                        mapped.characters[start].source_offset,
                        mapped.characters[end - 1].span.span_id,
                        mapped.characters[end - 1].source_offset,
                    )
                    occurrences[identity_key] = _AnchorOccurrenceV1(
                        anchor_id=rule.anchor_id,
                        start_key=start_key,
                        end_key=end_key,
                        identity_key=identity_key,
                        min_x=polygon[0].x,
                        max_x=polygon[2].x,
                    )
    return tuple(
        sorted(
            occurrences.values(),
            key=lambda item: (
                item.start_key,
                item.end_key,
                item.identity_key,
            ),
        )[:MAX_BODY_ANCHOR_OCCURRENCES_PER_ID_V1]
    )


def _body_signature_v1(
    reading: ReadingOrderV1,
    heading: _HeadingCandidateV1,
) -> tuple[str, ...]:
    states: dict[
        tuple[tuple[str, ...], frozenset[int] | None],
        _AnchorPathStateV1,
    ] = {((), frozenset()): _AnchorPathStateV1((), None, frozenset())}
    for rule in _BODY_ANCHOR_RULES_V1:
        occurrences = _body_anchor_occurrences_v1(
            reading,
            rule,
            after_heading=heading.end_key,
        )
        next_states = dict(states)
        for state in states.values():
            for occurrence in occurrences:
                if state.last is not None and (
                    occurrence.start_key <= state.last.end_key
                    or not _body_anchor_transition_is_compatible_v1(
                        state.last,
                        occurrence,
                    )
                ):
                    continue
                anchor_ids = state.anchor_ids + (rule.anchor_id,)
                start_line_index = int(occurrence.start_key[0])
                anchor_line_indices = state.anchor_line_indices | {start_line_index}
                state_key = (
                    anchor_ids,
                    (
                        None
                        if len(anchor_line_indices)
                        >= MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1
                        else anchor_line_indices
                    ),
                )
                existing = next_states.get(state_key)
                if (
                    existing is None
                    or existing.last is None
                    or occurrence.end_key < existing.last.end_key
                ):
                    next_states[state_key] = _AnchorPathStateV1(
                        anchor_ids,
                        occurrence,
                        anchor_line_indices,
                    )
        states = next_states
    eligible = tuple(
        state
        for state in states.values()
        if (
            len(state.anchor_ids) < MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1
            or len(state.anchor_line_indices)
            >= MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1
        )
    )
    return max(
        eligible,
        key=lambda state: (
            len(state.anchor_ids),
            tuple(
                anchor_id in state.anchor_ids
                for anchor_id in ADMISSION_NOTICE_BODY_ANCHOR_IDS_V1
            ),
        ),
    ).anchor_ids


def _body_anchor_transition_is_compatible_v1(
    previous: _AnchorOccurrenceV1,
    current: _AnchorOccurrenceV1,
) -> bool:
    horizontal_gap = max(
        0.0,
        current.min_x - previous.max_x,
        previous.min_x - current.max_x,
    )
    if horizontal_gap == 0.0:
        return True
    return bool(
        previous.anchor_id == ADMISSION_BODY_ANCHOR_ID_V1
        and current.anchor_id == MAJOR_STUDY_ANCHOR_ID_V1
        and horizontal_gap <= MAX_ADMISSION_TO_MAJOR_HORIZONTAL_GAP_V1
    )


def _matched_anchor_order_v1(
    anchor_ids: set[str],
) -> tuple[str, ...]:
    return tuple(
        anchor_id
        for anchor_id in ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1
        if anchor_id in anchor_ids
    )


def _match_reading_v1(
    reading: ReadingOrderV1,
) -> AdmissionNoticeTemplateMatchV1:
    headings = _heading_candidates_v1(reading)
    supported = tuple(
        heading
        for heading in headings
        if heading.text == HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
    )
    supported_span_sets = tuple(frozenset(heading.span_ids) for heading in supported)
    has_conflicting_heading = any(
        _looks_like_different_institution_v1(heading)
        and not any(
            frozenset(heading.span_ids) <= supported_span_set
            for supported_span_set in supported_span_sets
        )
        for heading in headings
    )
    if has_conflicting_heading:
        return AdmissionNoticeTemplateMatchV1(
            status=AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED,
            matched_anchor_ids=(),
        )
    if not supported:
        return AdmissionNoticeTemplateMatchV1(
            status=AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT,
            matched_anchor_ids=(),
        )
    body_ids = max(
        (_body_signature_v1(reading, heading) for heading in supported),
        key=lambda anchor_ids: (
            len(anchor_ids),
            tuple(
                anchor_id in anchor_ids
                for anchor_id in ADMISSION_NOTICE_BODY_ANCHOR_IDS_V1
            ),
        ),
    )
    matched_anchor_ids = (
        INSTITUTION_HEADING_ANCHOR_ID_V1,
        *body_ids,
    )
    status = (
        AdmissionNoticeTemplateMatchStatusV1.MATCHED
        if len(body_ids) >= MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1
        else AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT
    )
    return AdmissionNoticeTemplateMatchV1(
        status=status,
        matched_anchor_ids=matched_anchor_ids,
    )


class HbtcAdmissionNoticeTemplateMatcherV1:
    """Exact deterministic matcher for 湖北交通职业技术学院 notices only."""

    __slots__ = ()

    @property
    def template_v1(self) -> AdmissionNoticeTemplateV1:
        return HBTC_ADMISSION_NOTICE_TEMPLATE_V1

    def match_pages_v1(
        self,
        pages: tuple[OcrPageResultV1, ...],
    ) -> AdmissionNoticeTemplateMatchV1:
        match, _, _ = self._match_and_select_page_readings_v1(pages)
        return match

    def match_and_select_pages_v1(
        self,
        pages: tuple[OcrPageResultV1, ...],
    ) -> tuple[
        AdmissionNoticeTemplateMatchV1,
        tuple[OcrPageResultV1, ...],
    ]:
        """Return the capture match and only individually matched source pages."""

        match, _, matched_page_readings = self._match_and_select_page_readings_v1(pages)
        return match, tuple(page for page, _ in matched_page_readings)

    def _match_and_select_page_readings_v1(
        self,
        pages: tuple[OcrPageResultV1, ...],
    ) -> tuple[
        AdmissionNoticeTemplateMatchV1,
        tuple[OcrPageResultV1, ...],
        tuple[tuple[OcrPageResultV1, ReadingOrderV1], ...],
    ]:
        """Match once and retain stack-local readings for semantic extraction."""

        ordered = ordered_admission_notice_pages_v1(pages)
        page_evaluations: list[
            tuple[
                OcrPageResultV1,
                ReadingOrderV1,
                AdmissionNoticeTemplateMatchV1,
            ]
        ] = []
        for page in ordered:
            reading = reconstruct_reading_order_v1(page.spans)
            page_evaluations.append(
                (
                    page,
                    reading,
                    _match_reading_v1(reading),
                )
            )
        page_matches = tuple(match for _, _, match in page_evaluations)
        if any(
            match.status is AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED
            for match in page_matches
        ):
            return (
                AdmissionNoticeTemplateMatchV1(
                    status=AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED,
                    matched_anchor_ids=(),
                ),
                ordered,
                (),
            )
        matched_pairs = tuple(
            (page, reading, match)
            for page, reading, match in page_evaluations
            if match.status is AdmissionNoticeTemplateMatchStatusV1.MATCHED
        )
        if matched_pairs:
            return (
                AdmissionNoticeTemplateMatchV1(
                    status=AdmissionNoticeTemplateMatchStatusV1.MATCHED,
                    matched_anchor_ids=_matched_anchor_order_v1(
                        {
                            anchor_id
                            for _, _, match in matched_pairs
                            for anchor_id in match.matched_anchor_ids
                        }
                    ),
                ),
                ordered,
                tuple((page, reading) for page, reading, _ in matched_pairs),
            )
        strongest = max(
            page_matches,
            key=lambda match: (
                len(match.matched_anchor_ids),
                tuple(
                    anchor_id in match.matched_anchor_ids
                    for anchor_id in ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1
                ),
            ),
        )
        return (
            AdmissionNoticeTemplateMatchV1(
                status=AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT,
                matched_anchor_ids=strongest.matched_anchor_ids,
            ),
            ordered,
            (),
        )


class AdmissionNoticeTemplateCompatibilityErrorV1(ValueError):
    """Stable value-free rejection before semantic field extraction."""

    __slots__ = ("status",)

    def __init__(self, status: AdmissionNoticeTemplateMatchStatusV1) -> None:
        if not isinstance(status, AdmissionNoticeTemplateMatchStatusV1):
            raise TypeError("status must be AdmissionNoticeTemplateMatchStatusV1")
        if status is AdmissionNoticeTemplateMatchStatusV1.MATCHED:
            raise ValueError("MATCHED is not a compatibility rejection")
        self.status = status
        super().__init__("admission-notice template compatibility check did not match")


__all__ = [
    "COLLEGE_ANCHOR_V1",
    "COMMITTEE_ANCHOR_V1",
    "MAJOR_END_ANCHOR_V1",
    "MIN_RAW_ENGINE_SCORE_FOR_EXTRACTION_V1",
    "NAME_ANCHOR_V1",
    "AdmissionNoticeTemplateCompatibilityErrorV1",
    "HbtcAdmissionNoticeTemplateMatcherV1",
    "ordered_admission_notice_pages_v1",
]

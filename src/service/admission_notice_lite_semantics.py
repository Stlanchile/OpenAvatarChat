"""Deterministic L4 semantics for the single supported admission-notice family."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, cast

from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    OcrBatchLiteV1,
    OcrFrameLiteV1,
    OcrSpanLiteV1,
    RecognitionErrorReasonLiteV1,
)
from service.admission_notice_lite_major_catalog import (
    SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1,
    SupportedTrafficInformationMajorLiteV1,
    canonical_supported_major_lite_v1,
    normalize_supported_major_candidate_lite_v1,
)

INSTITUTION_NAME_LITE_V1 = "湖北交通职业技术学院"
COLLEGE_NAME_LITE_V1 = "交通信息学院"
MIN_RAW_OCR_SCORE_LITE_V1 = 0.50

_TITLE_REGION_MAX_Y = 0.22
_TITLE_MIN_WIDTH = 0.16
_TITLE_CENTER_X_MIN = 0.15
_TITLE_CENTER_X_MAX = 0.85
_SAME_LINE_MIN_VERTICAL_OVERLAP = 0.35
_SAME_LINE_MAX_CENTER_OFFSET = 0.012
_MAX_LOCAL_HORIZONTAL_GAP = 0.055
_MAX_ADJACENT_LINE_GAP = 0.080
_MAX_ADJACENT_LEFT_OFFSET = 0.180
_MAX_FORWARD_PATHS = 16
_MAX_ANCHOR_OCCURRENCES = 16
_MAX_ADMISSION_TO_MAJOR_HORIZONTAL_GAP = 0.18

_NAME_ANCHOR = "同学"
_COMMITTEE_ANCHOR = "高等学校招生委员会"
_ADMISSION_ANCHOR = "你被录取到我校"
_MAJOR_END_ANCHOR = "专业学习"
_APPROVAL_ANCHOR = "批准"
_STRUCTURAL_PUNCTUATION = frozenset(":：,，.。;；、")
_TITLE_PUNCTUATION = ":：,，.。;；"
_MAJOR_SOURCE_PUNCTUATION = frozenset("()（）+-＋－·•")
_INSTITUTION_SUFFIXES = ("职业技术学院", "大学", "学院", "学校")
_NON_NAME_FRAGMENTS = frozenset(
    {
        "亲爱",
        "亲爱的",
        "全体",
        "各位",
        "尊敬",
        "新生",
        "欢迎",
        "诸位",
        "有关",
        "请",
    }
)
_PROVINCE_COMMITTEE_SUFFIXES = (
    "省(市、自治区)高等学校招生委员会",
    "省市自治区高等学校招生委员会",
    "自治区高等学校招生委员会",
    "省高等学校招生委员会",
    "市高等学校招生委员会",
)
_PROVINCE_CANONICAL = {
    "北京": "北京",
    "天津": "天津",
    "河北": "河北",
    "山西": "山西",
    "内蒙古": "内蒙古",
    "辽宁": "辽宁",
    "吉林": "吉林",
    "黑龙江": "黑龙江",
    "上海": "上海",
    "江苏": "江苏",
    "浙江": "浙江",
    "安徽": "安徽",
    "福建": "福建",
    "江西": "江西",
    "山东": "山东",
    "河南": "河南",
    "湖北": "湖北",
    "湖南": "湖南",
    "广东": "广东",
    "广西": "广西",
    "广西壮族": "广西",
    "海南": "海南",
    "重庆": "重庆",
    "四川": "四川",
    "贵州": "贵州",
    "云南": "云南",
    "西藏": "西藏",
    "陕西": "陕西",
    "甘肃": "甘肃",
    "青海": "青海",
    "宁夏": "宁夏",
    "宁夏回族": "宁夏",
    "新疆": "新疆",
    "新疆维吾尔": "新疆",
    "台湾": "台湾",
    "香港": "香港",
    "澳门": "澳门",
}


class AdmissionNoticeTemplateStatusLiteV1(str, Enum):
    """Closed layout/content compatibility result; not an authenticity result."""

    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass(frozen=True, slots=True, kw_only=True)
class AdmissionNoticeResultLiteV1:
    """Transient L4 result with two trusted constants and three OCR-derived fields."""

    institution_name: Literal["湖北交通职业技术学院"] = field(
        default=INSTITUTION_NAME_LITE_V1,
        init=False,
    )
    college: Literal["交通信息学院"] = field(
        default=COLLEGE_NAME_LITE_V1,
        init=False,
    )
    name: str | None
    source_province: str | None
    major: SupportedTrafficInformationMajorLiteV1

    def __post_init__(self) -> None:
        if (
            self.institution_name != INSTITUTION_NAME_LITE_V1
            or self.college != COLLEGE_NAME_LITE_V1
        ):
            raise ValueError("trusted admission-notice constants are invalid")
        if self.name is not None and (
            type(self.name) is not str
            or not 1 <= len(self.name) <= 32
            or _contains_forbidden_control(self.name)
        ):
            raise ValueError("admission-notice name is invalid")
        if self.source_province is not None and (
            type(self.source_province) is not str
            or not 1 <= len(self.source_province) <= 16
            or _contains_forbidden_control(self.source_province)
        ):
            raise ValueError("admission-notice source province is invalid")
        if self.major not in SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1:
            raise ValueError("admission-notice major is unsupported")


class _FieldStatus(str, Enum):
    FOUND = "FOUND"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True, slots=True)
class _Geometry:
    span: OcrSpanLiteV1
    min_x: float
    min_y: float
    max_x: float
    max_y: float
    center_x: float
    center_y: float
    width: float
    height: float


@dataclass(frozen=True, slots=True)
class _MappedCharacter:
    source: str
    geometry: _Geometry
    line_index: int
    source_offset: int
    source_space_before: bool
    line_break_before: bool


@dataclass(frozen=True, slots=True)
class _MappedText:
    text: str
    characters: tuple[_MappedCharacter, ...]

    @classmethod
    def from_runs(cls, runs: tuple[_Run, ...]) -> _MappedText:
        mapped: list[_MappedCharacter] = []
        previous_line: int | None = None
        for run in runs:
            for geometry in run.spans:
                pending_space = False
                for offset, character in enumerate(geometry.span.text):
                    if character.isspace():
                        pending_space = bool(mapped)
                        continue
                    mapped.append(
                        _MappedCharacter(
                            source=character,
                            geometry=geometry,
                            line_index=run.line_index,
                            source_offset=offset,
                            source_space_before=pending_space,
                            line_break_before=(
                                previous_line is not None
                                and previous_line != run.line_index
                                and (
                                    not mapped
                                    or mapped[-1].line_index != run.line_index
                                )
                            ),
                        )
                    )
                    pending_space = False
                    previous_line = run.line_index
        return cls(
            text="".join(_canonical_anchor_character(item.source) for item in mapped),
            characters=tuple(mapped),
        )

    def occurrences(self, anchor: str) -> tuple[int, ...]:
        starts: list[int] = []
        offset = 0
        while True:
            position = self.text.find(anchor, offset)
            if position < 0:
                return tuple(starts)
            starts.append(position)
            offset = position + 1

    def source_value(self, start: int, end: int) -> str:
        pieces: list[str] = []
        for item in self.characters[start:end]:
            if pieces and item.source_space_before:
                pieces.append(" ")
            pieces.append(item.source)
        return "".join(pieces)


@dataclass(frozen=True, slots=True)
class _Run:
    line_index: int
    spans: tuple[_Geometry, ...]
    min_x: float
    min_y: float
    max_x: float
    max_y: float

    @property
    def center_y(self) -> float:
        return (self.min_y + self.max_y) / 2.0

    def mapped(self) -> _MappedText:
        return _MappedText.from_runs((self,))


@dataclass(frozen=True, slots=True)
class _Line:
    line_index: int
    runs: tuple[_Run, ...]
    min_x: float
    min_y: float
    max_x: float
    max_y: float

    @property
    def height(self) -> float:
        return self.max_y - self.min_y


@dataclass(frozen=True, slots=True)
class _Reading:
    lines: tuple[_Line, ...]

    def related_runs(self, source: _Run, target_line_index: int) -> tuple[_Run, ...]:
        if abs(target_line_index - source.line_index) != 1:
            return ()
        lower = min(source.line_index, target_line_index)
        upper = max(source.line_index, target_line_index)
        if not 0 <= lower < upper < len(self.lines):
            return ()
        first = self.lines[lower]
        second = self.lines[upper]
        gap = max(0.0, second.min_y - first.max_y)
        if gap > max(
            _MAX_ADJACENT_LINE_GAP,
            1.5 * max(first.height, second.height),
        ):
            return ()
        related = []
        for run in self.lines[target_line_index].runs:
            overlap = min(source.max_x, run.max_x) - max(source.min_x, run.min_x)
            if overlap > 0.0 or abs(source.min_x - run.min_x) <= (
                _MAX_ADJACENT_LEFT_OFFSET
            ):
                related.append(run)
        return tuple(
            sorted(
                related,
                key=lambda run: (
                    abs(source.min_x - run.min_x),
                    run.min_x,
                    run.max_x,
                    _run_identity(run),
                ),
            )
        )


@dataclass(frozen=True, slots=True)
class _AnchorRule:
    anchor_id: str
    text: str
    min_y: float
    max_y: float
    maximum_lines: int


@dataclass(frozen=True, slots=True)
class _AnchorOccurrence:
    anchor_id: str
    start_key: tuple[object, ...]
    end_key: tuple[object, ...]
    identity: tuple[object, ...]
    line_index: int
    min_x: float
    max_x: float


@dataclass(frozen=True, slots=True)
class _FrameEvaluation:
    frame: OcrFrameLiteV1
    reading: _Reading
    status: AdmissionNoticeTemplateStatusLiteV1


@dataclass(frozen=True, slots=True)
class _FieldDecision:
    status: _FieldStatus
    value: str | None = None


@dataclass(frozen=True, slots=True)
class _FrameFields:
    name: _FieldDecision
    source_province: _FieldDecision
    major: _FieldDecision


_BODY_RULES = (
    _AnchorRule("student", _NAME_ANCHOR, 0.12, 0.46, 1),
    _AnchorRule("committee", _COMMITTEE_ANCHOR, 0.20, 0.62, 3),
    _AnchorRule("admission", _ADMISSION_ANCHOR, 0.28, 0.72, 3),
    _AnchorRule("major", _MAJOR_END_ANCHOR, 0.36, 0.84, 3),
)


def _contains_forbidden_control(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _canonical_anchor_character(character: str) -> str:
    return {
        "（": "(",
        "）": ")",
    }.get(character, character)


def _is_han(character: str) -> bool:
    codepoint = ord(character)
    return bool(
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x20000 <= codepoint <= 0x2EBEF
    )


def _geometry(span: OcrSpanLiteV1) -> _Geometry | None:
    xs = tuple(point[0] for point in span.polygon)
    ys = tuple(point[1] for point in span.polygon)
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    width = max_x - min_x
    height = max_y - min_y
    if width <= 1e-6 or height <= 1e-6:
        return None
    return _Geometry(
        span=span,
        min_x=min_x,
        min_y=min_y,
        max_x=max_x,
        max_y=max_y,
        center_x=(min_x + max_x) / 2.0,
        center_y=(min_y + max_y) / 2.0,
        width=width,
        height=height,
    )


def _geometry_identity(geometry: _Geometry) -> tuple[object, ...]:
    return (
        geometry.min_x,
        geometry.min_y,
        geometry.max_x,
        geometry.max_y,
        geometry.span.text,
        geometry.span.score,
        geometry.span.polygon,
    )


def _run_identity(run: _Run) -> tuple[object, ...]:
    return tuple(_geometry_identity(item) for item in run.spans)


def _vertical_overlap_ratio(first: _Geometry, second: _Geometry) -> float:
    overlap = min(first.max_y, second.max_y) - max(first.min_y, second.min_y)
    if overlap <= 0.0:
        return 0.0
    return overlap / min(first.height, second.height)


def _same_line(geometry: _Geometry, group: list[_Geometry]) -> bool:
    representative = min(
        group,
        key=lambda item: (
            abs(item.center_y - geometry.center_y),
            item.min_x,
            _geometry_identity(item),
        ),
    )
    return bool(
        _vertical_overlap_ratio(geometry, representative)
        >= _SAME_LINE_MIN_VERTICAL_OVERLAP
        or abs(geometry.center_y - representative.center_y)
        <= max(
            _SAME_LINE_MAX_CENTER_OFFSET,
            0.60 * max(geometry.height, representative.height),
        )
    )


def _runs_for_line(
    line_index: int,
    geometries: tuple[_Geometry, ...],
) -> tuple[_Run, ...]:
    ordered = tuple(
        sorted(
            geometries,
            key=lambda item: (
                item.min_x,
                item.center_y,
                item.max_x,
                _geometry_identity(item),
            ),
        )
    )
    groups: list[list[_Geometry]] = []
    for geometry in ordered:
        if not groups:
            groups.append([geometry])
            continue
        previous = groups[-1][-1]
        horizontal_gap = geometry.min_x - previous.max_x
        local_gap = max(
            _MAX_LOCAL_HORIZONTAL_GAP,
            1.25 * max(previous.height, geometry.height),
        )
        if horizontal_gap > local_gap:
            groups.append([geometry])
        else:
            groups[-1].append(geometry)
    return tuple(
        _Run(
            line_index=line_index,
            spans=tuple(group),
            min_x=min(item.min_x for item in group),
            min_y=min(item.min_y for item in group),
            max_x=max(item.max_x for item in group),
            max_y=max(item.max_y for item in group),
        )
        for group in groups
    )


def reconstruct_admission_notice_reading_order_lite_v1(
    spans: tuple[OcrSpanLiteV1, ...],
) -> _Reading:
    """Build bounded visual lines independently of the input span sequence."""

    if type(spans) is not tuple or any(
        not isinstance(span, OcrSpanLiteV1) for span in spans
    ):
        raise TypeError("reading-order input must be an OCR span tuple")
    geometries = [
        geometry
        for span in spans
        if span.score >= MIN_RAW_OCR_SCORE_LITE_V1
        and (geometry := _geometry(span)) is not None
    ]
    geometries.sort(
        key=lambda item: (
            item.center_y,
            item.min_y,
            item.min_x,
            item.max_y,
            item.max_x,
            _geometry_identity(item),
        )
    )
    groups: list[list[_Geometry]] = []
    for geometry in geometries:
        candidates: list[tuple[float, int]] = []
        for index, group in enumerate(groups):
            if _same_line(geometry, group):
                center = sum(item.center_y for item in group) / len(group)
                candidates.append((abs(center - geometry.center_y), index))
        if not candidates:
            groups.append([geometry])
        else:
            _, selected = min(candidates)
            groups[selected].append(geometry)
    groups.sort(
        key=lambda group: (
            sum(item.center_y for item in group) / len(group),
            min(item.min_y for item in group),
            min(item.min_x for item in group),
            tuple(sorted(_geometry_identity(item) for item in group)),
        )
    )
    lines = []
    for line_index, group in enumerate(groups):
        group_tuple = tuple(group)
        lines.append(
            _Line(
                line_index=line_index,
                runs=_runs_for_line(line_index, group_tuple),
                min_x=min(item.min_x for item in group_tuple),
                min_y=min(item.min_y for item in group_tuple),
                max_x=max(item.max_x for item in group_tuple),
                max_y=max(item.max_y for item in group_tuple),
            )
        )
    return _Reading(tuple(lines))


def _forward_paths(
    reading: _Reading,
    start: _Run,
    *,
    maximum_lines: int,
) -> tuple[tuple[_Run, ...], ...]:
    paths: list[tuple[_Run, ...]] = [(start,)]
    frontier: list[tuple[_Run, ...]] = [(start,)]
    while frontier and len(paths) < _MAX_FORWARD_PATHS:
        path = frontier.pop(0)
        if len(path) >= maximum_lines:
            continue
        for related in reading.related_runs(path[-1], path[-1].line_index + 1):
            extended = path + (related,)
            paths.append(extended)
            frontier.append(extended)
            if len(paths) >= _MAX_FORWARD_PATHS:
                break
    return tuple(paths)


def _mapped_position_key(
    mapped: _MappedText,
    index: int,
    *,
    after: bool,
) -> tuple[object, ...]:
    item = mapped.characters[index]
    source_length = max(1, len(item.geometry.span.text))
    offset = item.source_offset + int(after)
    approximate_x = item.geometry.min_x + item.geometry.width * (offset / source_length)
    return (
        item.line_index,
        approximate_x,
        _geometry_identity(item.geometry),
        offset,
    )


def _mapped_bounds(
    mapped: _MappedText,
    start: int,
    end: int,
) -> tuple[float, float, float, float]:
    items = mapped.characters[start:end]
    return (
        min(item.geometry.min_x for item in items),
        min(item.geometry.min_y for item in items),
        max(item.geometry.max_x for item in items),
        max(item.geometry.max_y for item in items),
    )


def _title_evidence(reading: _Reading) -> tuple[bool, bool]:
    supported = False
    conflicting = False
    for line in reading.lines:
        for run in line.runs:
            for path in _forward_paths(reading, run, maximum_lines=2):
                mapped = _MappedText.from_runs(path)
                text = mapped.text.strip(_TITLE_PUNCTUATION)
                if not text or len(text) > 48:
                    continue
                min_x = min(item.min_x for item in path)
                max_x = max(item.max_x for item in path)
                max_y = max(item.max_y for item in path)
                center_x = (min_x + max_x) / 2.0
                plausible = bool(
                    max_y <= _TITLE_REGION_MAX_Y
                    and max_x - min_x >= _TITLE_MIN_WIDTH
                    and _TITLE_CENTER_X_MIN <= center_x <= _TITLE_CENTER_X_MAX
                )
                if not plausible:
                    continue
                if text == INSTITUTION_NAME_LITE_V1:
                    supported = True
                elif (
                    text != COLLEGE_NAME_LITE_V1
                    and max_x - min_x >= _TITLE_MIN_WIDTH
                    and any(
                        text.endswith(suffix) and len(text) > len(suffix)
                        for suffix in _INSTITUTION_SUFFIXES
                    )
                    and INSTITUTION_NAME_LITE_V1 not in text
                ):
                    conflicting = True
    return supported, conflicting


def _only_structural(text: str) -> bool:
    return all(character in _STRUCTURAL_PUNCTUATION for character in text)


def _name_is_valid(value: str) -> bool:
    return bool(
        1 <= len(value) <= 32
        and value[0] != "·"
        and value[-1] != "·"
        and "··" not in value
        and not any(fragment in value for fragment in _NON_NAME_FRAGMENTS)
        and all(_is_han(character) or character == "·" for character in value)
        and not _contains_forbidden_control(value)
    )


def _salutation_context(mapped: _MappedText, start: int, end: int) -> bool:
    if mapped.text[end:] and not _only_structural(mapped.text[end:]):
        return False
    candidate_start = start
    while candidate_start > 0 and (
        _is_han(mapped.text[candidate_start - 1])
        or mapped.text[candidate_start - 1] == "·"
    ):
        candidate_start -= 1
    prefix = mapped.text[:candidate_start]
    candidate = mapped.text[candidate_start:start]
    return bool(
        (not prefix or _only_structural(prefix))
        and (not candidate or _name_is_valid(candidate))
    )


def _committee_parts(mapped: _MappedText, anchor_start: int) -> tuple[int, int] | None:
    prefix = mapped.text[:anchor_start].rstrip("".join(_STRUCTURAL_PUNCTUATION))
    for suffix in _PROVINCE_COMMITTEE_SUFFIXES:
        if not prefix.endswith(suffix.removesuffix(_COMMITTEE_ANCHOR)):
            continue
        suffix_without_anchor = suffix.removesuffix(_COMMITTEE_ANCHOR)
        before_suffix = prefix[: -len(suffix_without_anchor)]
        start = before_suffix.rfind("经")
        if start < 0 or (
            before_suffix[:start] and not _only_structural(before_suffix[:start])
        ):
            continue
        province_start = start + 1
        if 1 <= anchor_start - province_start <= 24:
            return province_start, anchor_start - len(suffix_without_anchor)
    return None


def _admission_context(mapped: _MappedText, start: int) -> bool:
    prefix = mapped.text[:start].rstrip("".join(_STRUCTURAL_PUNCTUATION))
    return bool(not prefix or prefix.endswith(_APPROVAL_ANCHOR))


def _major_source_character(character: str) -> bool:
    return bool(
        _is_han(character)
        or (character.isascii() and character.isalnum())
        or character in _MAJOR_SOURCE_PUNCTUATION
    )


def _raw_major_candidate(mapped: _MappedText, anchor_start: int) -> str | None:
    college_end = mapped.text.rfind(COLLEGE_NAME_LITE_V1, 0, anchor_start)
    if college_end >= 0:
        candidate_start = college_end + len(COLLEGE_NAME_LITE_V1)
    else:
        candidate_start = anchor_start
        while candidate_start > 0 and _major_source_character(
            mapped.characters[candidate_start - 1].source
        ):
            candidate_start -= 1
    while (
        candidate_start < anchor_start
        and mapped.characters[candidate_start].source in _STRUCTURAL_PUNCTUATION
    ):
        candidate_start += 1
    if candidate_start >= anchor_start:
        return None
    candidate = mapped.source_value(candidate_start, anchor_start).strip()
    return candidate if 1 <= len(candidate) <= 64 else None


def _major_context(mapped: _MappedText, start: int, end: int) -> bool:
    if mapped.text[end:] and not _only_structural(mapped.text[end:]):
        return False
    candidate = _raw_major_candidate(mapped, start)
    if candidate is None:
        return False
    normalized = normalize_supported_major_candidate_lite_v1(candidate)
    return bool(
        any(_is_han(character) for character in normalized)
        and all(
            _major_source_character(character) or character.isspace()
            for character in normalized
        )
    )


def _anchor_context(
    rule: _AnchorRule,
    mapped: _MappedText,
    start: int,
    end: int,
) -> bool:
    if rule.anchor_id == "student":
        return _salutation_context(mapped, start, end)
    if rule.anchor_id == "committee":
        return _committee_parts(mapped, start) is not None
    if rule.anchor_id == "admission":
        return _admission_context(mapped, start)
    if rule.anchor_id == "major":
        return _major_context(mapped, start, end)
    raise ValueError("unknown body anchor")


def _anchor_occurrences(
    reading: _Reading,
    rule: _AnchorRule,
) -> tuple[_AnchorOccurrence, ...]:
    occurrences: dict[tuple[object, ...], _AnchorOccurrence] = {}
    for line in reading.lines:
        for run in line.runs:
            for path in _forward_paths(
                reading,
                run,
                maximum_lines=rule.maximum_lines,
            ):
                mapped = _MappedText.from_runs(path)
                for start in mapped.occurrences(rule.text):
                    end = start + len(rule.text)
                    if not _anchor_context(rule, mapped, start, end):
                        continue
                    min_x, min_y, max_x, max_y = _mapped_bounds(mapped, start, end)
                    center_y = (min_y + max_y) / 2.0
                    if not rule.min_y <= center_y <= rule.max_y:
                        continue
                    start_key = _mapped_position_key(mapped, start, after=False)
                    end_key = _mapped_position_key(mapped, end - 1, after=True)
                    identity = (rule.anchor_id, start_key, end_key)
                    occurrences[identity] = _AnchorOccurrence(
                        anchor_id=rule.anchor_id,
                        start_key=start_key,
                        end_key=end_key,
                        identity=identity,
                        line_index=int(start_key[0]),
                        min_x=min_x,
                        max_x=max_x,
                    )
    return tuple(
        sorted(
            occurrences.values(),
            key=lambda item: (item.start_key, item.end_key, item.identity),
        )[:_MAX_ANCHOR_OCCURRENCES]
    )


def _transition_is_compatible(
    previous: _AnchorOccurrence,
    current: _AnchorOccurrence,
) -> bool:
    if current.start_key <= previous.end_key:
        return False
    gap = max(
        0.0,
        current.min_x - previous.max_x,
        previous.min_x - current.max_x,
    )
    return bool(
        gap == 0.0
        or (
            previous.anchor_id == "admission"
            and current.anchor_id == "major"
            and gap <= _MAX_ADMISSION_TO_MAJOR_HORIZONTAL_GAP
        )
    )


def _best_body_sequence(reading: _Reading) -> tuple[_AnchorOccurrence, ...]:
    states: list[tuple[_AnchorOccurrence, ...]] = [()]
    for rule in _BODY_RULES:
        occurrences = _anchor_occurrences(reading, rule)
        next_states = list(states)
        for state in states:
            for occurrence in occurrences:
                if state and not _transition_is_compatible(state[-1], occurrence):
                    continue
                next_states.append(state + (occurrence,))
        deduplicated = {
            tuple(item.identity for item in state): state for state in next_states
        }
        states = list(deduplicated.values())
    return max(
        states,
        key=lambda state: (
            len(state),
            len({item.line_index for item in state}),
            tuple(item.anchor_id for item in state),
        ),
    )


def _college_evidence(reading: _Reading) -> tuple[bool, bool]:
    supported = False
    conflicting = False
    for line in reading.lines:
        if not 0.26 <= (line.min_y + line.max_y) / 2.0 <= 0.76:
            continue
        for run in line.runs:
            for path in _forward_paths(reading, run, maximum_lines=3):
                mapped = _MappedText.from_runs(path)
                for anchor_start in mapped.occurrences(_ADMISSION_ANCHOR):
                    anchor_end = anchor_start + len(_ADMISSION_ANCHOR)
                    if not _admission_context(mapped, anchor_start):
                        continue
                    boundary = mapped.text.find(_MAJOR_END_ANCHOR, anchor_end)
                    search_end = len(mapped.text) if boundary < 0 else boundary
                    college_end = mapped.text.find("学院", anchor_end, search_end)
                    if college_end < 0:
                        continue
                    college_end += len("学院")
                    candidate_start = anchor_end
                    while (
                        candidate_start < college_end
                        and mapped.text[candidate_start] in _STRUCTURAL_PUNCTUATION
                    ):
                        candidate_start += 1
                    candidate = mapped.text[candidate_start:college_end]
                    if not (
                        len("学院") < len(candidate) <= 32
                        and all(
                            _is_han(character)
                            or (character.isascii() and character.isalnum())
                            for character in candidate
                        )
                    ):
                        continue
                    if candidate == COLLEGE_NAME_LITE_V1:
                        supported = True
                    else:
                        conflicting = True
    return supported, conflicting


def _evaluate_frame(frame: OcrFrameLiteV1) -> _FrameEvaluation:
    reading = reconstruct_admission_notice_reading_order_lite_v1(frame.spans)
    supported_title, conflicting_title = _title_evidence(reading)
    supported_college, conflicting_college = _college_evidence(reading)
    sequence = _best_body_sequence(reading)
    body_count = len(sequence)
    distinct_body_lines = len({item.line_index for item in sequence})
    notice_like = body_count >= 2
    if notice_like and (conflicting_title or conflicting_college):
        status = AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED
    elif (
        supported_title
        and supported_college
        and body_count >= 3
        and distinct_body_lines >= 2
    ):
        status = AdmissionNoticeTemplateStatusLiteV1.MATCHED
    else:
        status = AdmissionNoticeTemplateStatusLiteV1.INSUFFICIENT
    return _FrameEvaluation(frame=frame, reading=reading, status=status)


def match_admission_notice_template_lite_v1(
    batch: OcrBatchLiteV1,
) -> AdmissionNoticeTemplateStatusLiteV1:
    if not isinstance(batch, OcrBatchLiteV1):
        raise TypeError("semantic input must be OcrBatchLiteV1")
    statuses = tuple(_evaluate_frame(frame).status for frame in batch.frames)
    if AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED in statuses:
        return AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED
    if AdmissionNoticeTemplateStatusLiteV1.MATCHED in statuses:
        return AdmissionNoticeTemplateStatusLiteV1.MATCHED
    return AdmissionNoticeTemplateStatusLiteV1.INSUFFICIENT


def _decision(values: list[str], *, saw_invalid: bool = False) -> _FieldDecision:
    unique = set(values)
    if len(unique) > 1 or (unique and saw_invalid):
        return _FieldDecision(_FieldStatus.AMBIGUOUS)
    if not unique:
        return _FieldDecision(_FieldStatus.NOT_FOUND)
    return _FieldDecision(_FieldStatus.FOUND, unique.pop())


def _name_decision(reading: _Reading) -> _FieldDecision:
    values: list[str] = []
    for line in reading.lines:
        center_y = (line.min_y + line.max_y) / 2.0
        if not 0.08 <= center_y <= 0.48:
            continue
        for run in line.runs:
            mapped = run.mapped()
            for anchor_start in mapped.occurrences(_NAME_ANCHOR):
                anchor_end = anchor_start + len(_NAME_ANCHOR)
                if mapped.text[anchor_end:] and not _only_structural(
                    mapped.text[anchor_end:]
                ):
                    continue
                candidate_start = anchor_start
                while candidate_start > 0 and (
                    _is_han(mapped.text[candidate_start - 1])
                    or mapped.text[candidate_start - 1] == "·"
                ):
                    candidate_start -= 1
                if mapped.text[:candidate_start] and not _only_structural(
                    mapped.text[:candidate_start]
                ):
                    continue
                candidate = mapped.source_value(candidate_start, anchor_start).strip()
                if _name_is_valid(candidate):
                    values.append(candidate)
    return _decision(values)


def _province_decision(reading: _Reading) -> _FieldDecision:
    values: list[str] = []
    for line in reading.lines:
        center_y = (line.min_y + line.max_y) / 2.0
        if not 0.12 <= center_y <= 0.72:
            continue
        for run in line.runs:
            for path in _forward_paths(reading, run, maximum_lines=3):
                mapped = _MappedText.from_runs(path)
                for anchor_start in mapped.occurrences(_COMMITTEE_ANCHOR):
                    parts = _committee_parts(mapped, anchor_start)
                    if parts is None:
                        continue
                    province_start, province_end = parts
                    committee_end = anchor_start + len(_COMMITTEE_ANCHOR)
                    approval_start = mapped.text.find(
                        _APPROVAL_ANCHOR,
                        committee_end,
                    )
                    if (
                        approval_start < committee_end
                        or approval_start - committee_end > 8
                        or (
                            mapped.text[committee_end:approval_start]
                            and not _only_structural(
                                mapped.text[committee_end:approval_start]
                            )
                        )
                    ):
                        continue
                    raw = mapped.text[province_start:province_end]
                    canonical = _PROVINCE_CANONICAL.get(raw)
                    if canonical is not None:
                        values.append(canonical)
    return _decision(values)


def _major_decision(reading: _Reading) -> _FieldDecision:
    values: list[str] = []
    invalid_occurrences: set[tuple[object, ...]] = set()
    valid_occurrences: set[tuple[object, ...]] = set()
    for line in reading.lines:
        center_y = (line.min_y + line.max_y) / 2.0
        if not 0.18 <= center_y <= 0.84:
            continue
        for run in line.runs:
            for path in _forward_paths(reading, run, maximum_lines=3):
                mapped = _MappedText.from_runs(path)
                for anchor_start in mapped.occurrences(_MAJOR_END_ANCHOR):
                    anchor_end = anchor_start + len(_MAJOR_END_ANCHOR)
                    occurrence = (
                        _mapped_position_key(mapped, anchor_start, after=False),
                        _mapped_position_key(mapped, anchor_end - 1, after=True),
                    )
                    candidate = _raw_major_candidate(mapped, anchor_start)
                    canonical = (
                        canonical_supported_major_lite_v1(candidate)
                        if candidate is not None
                        else None
                    )
                    if canonical is None:
                        invalid_occurrences.add(occurrence)
                    else:
                        valid_occurrences.add(occurrence)
                        values.append(canonical)
    materially_invalid = bool(invalid_occurrences - valid_occurrences)
    return _decision(values, saw_invalid=materially_invalid)


def _extract_frame_fields(evaluation: _FrameEvaluation) -> _FrameFields:
    return _FrameFields(
        name=_name_decision(evaluation.reading),
        source_province=_province_decision(evaluation.reading),
        major=_major_decision(evaluation.reading),
    )


def _merge(decisions: tuple[_FieldDecision, ...]) -> _FieldDecision:
    if any(decision.status is _FieldStatus.AMBIGUOUS for decision in decisions):
        return _FieldDecision(_FieldStatus.AMBIGUOUS)
    values = {
        decision.value
        for decision in decisions
        if decision.status is _FieldStatus.FOUND and decision.value is not None
    }
    if len(values) > 1:
        return _FieldDecision(_FieldStatus.AMBIGUOUS)
    if not values:
        return _FieldDecision(_FieldStatus.NOT_FOUND)
    return _FieldDecision(_FieldStatus.FOUND, values.pop())


def recognize_admission_notice_semantics(
    batch: OcrBatchLiteV1,
) -> AdmissionNoticeResultLiteV1:
    """Recognize one fixed HBTC Traffic Information admission-notice family."""

    if not isinstance(batch, OcrBatchLiteV1):
        raise TypeError("semantic input must be OcrBatchLiteV1")
    evaluations = tuple(_evaluate_frame(frame) for frame in batch.frames)
    if any(
        evaluation.status is AdmissionNoticeTemplateStatusLiteV1.NOT_MATCHED
        for evaluation in evaluations
    ):
        raise AdmissionNoticeLiteError(RecognitionErrorReasonLiteV1.UNSUPPORTED_NOTICE)
    matched = tuple(
        evaluation
        for evaluation in evaluations
        if evaluation.status is AdmissionNoticeTemplateStatusLiteV1.MATCHED
    )
    if not matched:
        raise AdmissionNoticeLiteError(RecognitionErrorReasonLiteV1.INSUFFICIENT_NOTICE)
    fields = tuple(_extract_frame_fields(evaluation) for evaluation in matched)
    major = _merge(tuple(item.major for item in fields))
    if major.status is _FieldStatus.AMBIGUOUS:
        raise AdmissionNoticeLiteError(RecognitionErrorReasonLiteV1.AMBIGUOUS_NOTICE)
    if major.status is not _FieldStatus.FOUND or major.value is None:
        raise AdmissionNoticeLiteError(
            RecognitionErrorReasonLiteV1.MAJOR_NOT_RECOGNIZED
        )
    name = _merge(tuple(item.name for item in fields))
    province = _merge(tuple(item.source_province for item in fields))
    return AdmissionNoticeResultLiteV1(
        name=name.value if name.status is _FieldStatus.FOUND else None,
        source_province=(
            province.value if province.status is _FieldStatus.FOUND else None
        ),
        major=cast(SupportedTrafficInformationMajorLiteV1, major.value),
    )


__all__ = [
    "COLLEGE_NAME_LITE_V1",
    "INSTITUTION_NAME_LITE_V1",
    "MIN_RAW_OCR_SCORE_LITE_V1",
    "AdmissionNoticeResultLiteV1",
    "AdmissionNoticeTemplateStatusLiteV1",
    "match_admission_notice_template_lite_v1",
    "recognize_admission_notice_semantics",
    "reconstruct_admission_notice_reading_order_lite_v1",
]

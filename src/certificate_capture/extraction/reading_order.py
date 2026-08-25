"""Deterministic bounded reading-order reconstruction for Chinese notices."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from certificate_capture.contracts.ocr import (
    OcrPointV1,
    OcrSpanV1,
)
from certificate_capture.extraction.normalization import (
    canonical_anchor_character_v1,
    is_unicode_whitespace_v1,
)

MIN_GEOMETRY_EXTENT_V1 = 1e-6
SAME_LINE_MIN_VERTICAL_OVERLAP_RATIO_V1 = 0.35
SAME_LINE_MAX_CENTER_OFFSET_V1 = 0.012
MAX_LOCAL_HORIZONTAL_GAP_V1 = 0.055
MAX_ADJACENT_LINE_GAP_V1 = 0.080
MAX_ADJACENT_LEFT_OFFSET_V1 = 0.180


@dataclass(frozen=True, slots=True)
class SpanGeometryV1:
    span: OcrSpanV1
    min_x: float
    min_y: float
    max_x: float
    max_y: float
    center_x: float
    center_y: float
    width: float
    height: float


@dataclass(frozen=True, slots=True)
class MappedCharacterV1:
    anchor_character: str
    source_character: str
    span: OcrSpanV1
    line_index: int
    source_offset: int
    source_space_before: bool
    line_break_before: bool


@dataclass(frozen=True, slots=True)
class MappedTextV1:
    """Compact anchor text with a trace to exact source characters/spans."""

    text: str
    characters: tuple[MappedCharacterV1, ...]

    @classmethod
    def from_runs_v1(
        cls,
        runs: tuple[TextRunV1, ...],
    ) -> MappedTextV1:
        mapped: list[MappedCharacterV1] = []
        previous_line: int | None = None
        for run in runs:
            for geometry in run.spans:
                pending_space = False
                for offset, character in enumerate(geometry.span.text):
                    if is_unicode_whitespace_v1(character):
                        pending_space = bool(mapped)
                        continue
                    mapped.append(
                        MappedCharacterV1(
                            anchor_character=(canonical_anchor_character_v1(character)),
                            source_character=character,
                            span=geometry.span,
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
            text="".join(item.anchor_character for item in mapped),
            characters=tuple(mapped),
        )

    def occurrences_v1(self, anchor: str) -> tuple[int, ...]:
        if not anchor:
            return ()
        starts: list[int] = []
        offset = 0
        while True:
            position = self.text.find(anchor, offset)
            if position < 0:
                return tuple(starts)
            starts.append(position)
            offset = position + 1

    def source_value_v1(self, start: int, end: int) -> str:
        if not 0 <= start <= end <= len(self.characters):
            raise ValueError("mapped text slice is invalid")
        pieces: list[str] = []
        previous: MappedCharacterV1 | None = None
        for item in self.characters[start:end]:
            if (
                pieces
                and item.source_space_before
                and previous is not None
                and previous.source_character.isascii()
                and previous.source_character.isalnum()
                and item.source_character.isascii()
                and item.source_character.isalnum()
            ):
                pieces.append(" ")
            pieces.append(item.source_character)
            previous = item
        return "".join(pieces)

    def source_spans_v1(
        self,
        start: int,
        end: int,
    ) -> tuple[OcrSpanV1, ...]:
        if not 0 <= start <= end <= len(self.characters):
            raise ValueError("mapped text slice is invalid")
        by_id: dict[uuid.UUID, OcrSpanV1] = {}
        for item in self.characters[start:end]:
            by_id[item.span.span_id] = item.span
        return tuple(
            by_id[span_id] for span_id in sorted(by_id, key=lambda value: value.int)
        )


@dataclass(frozen=True, slots=True)
class TextRunV1:
    line_index: int
    spans: tuple[SpanGeometryV1, ...]
    min_x: float
    min_y: float
    max_x: float
    max_y: float

    @property
    def center_y(self) -> float:
        return (self.min_y + self.max_y) / 2.0

    def mapped_text_v1(self) -> MappedTextV1:
        return MappedTextV1.from_runs_v1((self,))


@dataclass(frozen=True, slots=True)
class VisualLineV1:
    line_index: int
    runs: tuple[TextRunV1, ...]
    min_x: float
    min_y: float
    max_x: float
    max_y: float

    @property
    def height(self) -> float:
        return self.max_y - self.min_y

    @property
    def center_y(self) -> float:
        return (self.min_y + self.max_y) / 2.0


@dataclass(frozen=True, slots=True)
class ReadingOrderV1:
    """A page split into visual lines and bounded horizontal text runs."""

    lines: tuple[VisualLineV1, ...]

    def line_v1(self, line_index: int) -> VisualLineV1 | None:
        if not 0 <= line_index < len(self.lines):
            return None
        return self.lines[line_index]

    def lines_are_adjacent_v1(
        self,
        first_index: int,
        second_index: int,
    ) -> bool:
        if second_index != first_index + 1:
            return False
        first = self.line_v1(first_index)
        second = self.line_v1(second_index)
        if first is None or second is None:
            return False
        gap = max(0.0, second.min_y - first.max_y)
        return gap <= max(
            MAX_ADJACENT_LINE_GAP_V1,
            1.5 * max(first.height, second.height),
        )

    def related_runs_v1(
        self,
        source: TextRunV1,
        target_line_index: int,
    ) -> tuple[TextRunV1, ...]:
        if abs(target_line_index - source.line_index) != 1:
            return ()
        lower = min(source.line_index, target_line_index)
        upper = max(source.line_index, target_line_index)
        if not self.lines_are_adjacent_v1(lower, upper):
            return ()
        target = self.line_v1(target_line_index)
        if target is None:
            return ()
        related: list[TextRunV1] = []
        for run in target.runs:
            overlap = min(source.max_x, run.max_x) - max(
                source.min_x,
                run.min_x,
            )
            if (
                overlap > 0.0
                or abs(source.min_x - run.min_x) <= MAX_ADJACENT_LEFT_OFFSET_V1
            ):
                related.append(run)
        return tuple(
            sorted(
                related,
                key=lambda run: (
                    abs(source.min_x - run.min_x),
                    run.min_x,
                    run.max_x,
                ),
            )
        )


def span_geometry_v1(span: OcrSpanV1) -> SpanGeometryV1 | None:
    if not isinstance(span, OcrSpanV1):
        raise TypeError("reading-order input must contain OcrSpanV1")
    xs = tuple(point.x for point in span.polygon)
    ys = tuple(point.y for point in span.polygon)
    min_x = min(xs)
    max_x = max(xs)
    min_y = min(ys)
    max_y = max(ys)
    width = max_x - min_x
    height = max_y - min_y
    if width <= MIN_GEOMETRY_EXTENT_V1 or height <= MIN_GEOMETRY_EXTENT_V1:
        return None
    return SpanGeometryV1(
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


def source_polygon_for_spans_v1(
    spans: tuple[OcrSpanV1, ...],
) -> tuple[OcrPointV1, ...] | None:
    geometries = tuple(
        geometry for span in spans if (geometry := span_geometry_v1(span)) is not None
    )
    if not geometries:
        return None
    min_x = min(geometry.min_x for geometry in geometries)
    max_x = max(geometry.max_x for geometry in geometries)
    min_y = min(geometry.min_y for geometry in geometries)
    max_y = max(geometry.max_y for geometry in geometries)
    if min_x >= max_x or min_y >= max_y:
        return None
    return (
        OcrPointV1(min_x, min_y),
        OcrPointV1(max_x, min_y),
        OcrPointV1(max_x, max_y),
        OcrPointV1(min_x, max_y),
    )


def _vertical_overlap_ratio_v1(
    first: SpanGeometryV1,
    second: SpanGeometryV1,
) -> float:
    overlap = min(first.max_y, second.max_y) - max(
        first.min_y,
        second.min_y,
    )
    if overlap <= 0:
        return 0.0
    return overlap / min(first.height, second.height)


def _same_visual_line_v1(
    geometry: SpanGeometryV1,
    line_items: list[SpanGeometryV1],
) -> bool:
    representative = min(
        line_items,
        key=lambda item: (
            abs(item.center_y - geometry.center_y),
            item.min_x,
            item.span.span_id.int,
        ),
    )
    return bool(
        _vertical_overlap_ratio_v1(geometry, representative)
        >= SAME_LINE_MIN_VERTICAL_OVERLAP_RATIO_V1
        or abs(geometry.center_y - representative.center_y)
        <= max(
            SAME_LINE_MAX_CENTER_OFFSET_V1,
            0.60 * max(geometry.height, representative.height),
        )
    )


def _runs_for_line_v1(
    line_index: int,
    geometries: tuple[SpanGeometryV1, ...],
) -> tuple[TextRunV1, ...]:
    ordered = tuple(
        sorted(
            geometries,
            key=lambda item: (
                item.min_x,
                item.center_y,
                item.max_x,
                item.span.span_id.int,
            ),
        )
    )
    groups: list[list[SpanGeometryV1]] = []
    for geometry in ordered:
        if not groups:
            groups.append([geometry])
            continue
        previous = groups[-1][-1]
        horizontal_gap = geometry.min_x - previous.max_x
        local_gap = max(
            MAX_LOCAL_HORIZONTAL_GAP_V1,
            1.25 * max(previous.height, geometry.height),
        )
        if horizontal_gap > local_gap:
            groups.append([geometry])
        else:
            groups[-1].append(geometry)
    return tuple(
        TextRunV1(
            line_index=line_index,
            spans=tuple(group),
            min_x=min(item.min_x for item in group),
            min_y=min(item.min_y for item in group),
            max_x=max(item.max_x for item in group),
            max_y=max(item.max_y for item in group),
        )
        for group in groups
    )


def reconstruct_reading_order_v1(
    spans: tuple[OcrSpanV1, ...],
) -> ReadingOrderV1:
    """Reconstruct local lines independently of caller span order."""

    if not isinstance(spans, tuple):
        raise TypeError("reading-order spans must be an immutable tuple")
    geometries = [
        geometry for span in spans if (geometry := span_geometry_v1(span)) is not None
    ]
    geometries.sort(
        key=lambda item: (
            item.center_y,
            item.min_y,
            item.min_x,
            item.max_y,
            item.max_x,
            item.span.span_id.int,
        )
    )
    line_groups: list[list[SpanGeometryV1]] = []
    for geometry in geometries:
        candidates: list[tuple[float, int]] = []
        for index, group in enumerate(line_groups):
            if _same_visual_line_v1(geometry, group):
                group_center = sum(item.center_y for item in group) / len(group)
                candidates.append((abs(group_center - geometry.center_y), index))
        if not candidates:
            line_groups.append([geometry])
            continue
        _, selected = min(candidates)
        line_groups[selected].append(geometry)

    line_groups.sort(
        key=lambda group: (
            sum(item.center_y for item in group) / len(group),
            min(item.min_y for item in group),
            min(item.min_x for item in group),
        )
    )
    lines: list[VisualLineV1] = []
    for line_index, group in enumerate(line_groups):
        group_tuple = tuple(group)
        lines.append(
            VisualLineV1(
                line_index=line_index,
                runs=_runs_for_line_v1(line_index, group_tuple),
                min_x=min(item.min_x for item in group_tuple),
                min_y=min(item.min_y for item in group_tuple),
                max_x=max(item.max_x for item in group_tuple),
                max_y=max(item.max_y for item in group_tuple),
            )
        )
    return ReadingOrderV1(lines=tuple(lines))


__all__ = [
    "MAX_ADJACENT_LEFT_OFFSET_V1",
    "MAX_ADJACENT_LINE_GAP_V1",
    "MAX_LOCAL_HORIZONTAL_GAP_V1",
    "MappedCharacterV1",
    "MappedTextV1",
    "ReadingOrderV1",
    "SpanGeometryV1",
    "TextRunV1",
    "VisualLineV1",
    "reconstruct_reading_order_v1",
    "source_polygon_for_spans_v1",
    "span_geometry_v1",
]

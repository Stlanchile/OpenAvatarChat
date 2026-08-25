"""Strict private admission-notice extraction contracts for Milestone 6B."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

from certificate_capture.contracts.common import (
    canonical_json_bytes_v1,
    capture_epoch_object_v1,
    require_sha256_hex_v1,
    require_text_v1,
    require_uuid7_v1,
)
from certificate_capture.contracts.ocr import OcrPointV1
from certificate_capture.epochs import CaptureEpochV1

ADMISSION_NOTICE_EXTRACTION_IDENTITY_SCHEMA_VERSION_V1 = (
    "oac.admission-notice-extraction-identity.v1"
)
ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1 = "oac.admission-notice-extraction.v1"
EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1 = "oac.extracted-admission-field.v1"

MAX_ADMISSION_NOTICE_EXTRACTION_CANONICAL_JSON_BYTES_V1 = 16 * 1024
MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1 = 3
MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1 = 32
MAX_ADMISSION_NOTICE_JSON_NESTING_DEPTH_V1 = 10

MAX_ADMISSION_NAME_CODEPOINTS_V1 = 32
MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1 = 16
MAX_ADMISSION_COLLEGE_CODEPOINTS_V1 = 128
MAX_ADMISSION_MAJOR_CODEPOINTS_V1 = 256

_IDENTITY_COMPONENT_V1 = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")


class AdmissionFieldStatusV1(str, Enum):
    """Closed deterministic field status vocabulary."""

    FOUND = "FOUND"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_FOUND = "NOT_FOUND"


def _require_identity_component_v1(name: str, value: object) -> str:
    text = require_text_v1(name, value, maximum_utf8_bytes=128)
    if _IDENTITY_COMPONENT_V1.fullmatch(text) is None:
        raise ValueError(f"{name} is invalid")
    return text


def _require_no_control_characters_v1(name: str, value: str) -> None:
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError(f"{name} contains a control character")


def _require_sorted_uuid7_tuple_v1(
    name: str,
    value: object,
    *,
    minimum_items: int,
    maximum_items: int,
) -> tuple[uuid.UUID, ...]:
    if not isinstance(value, tuple) or not minimum_items <= len(value) <= maximum_items:
        raise ValueError(f"{name} has an invalid item count")
    normalized = tuple(require_uuid7_v1(f"{name} item", item) for item in value)
    if len(set(normalized)) != len(normalized) or normalized != tuple(
        sorted(normalized, key=lambda item: item.int)
    ):
        raise ValueError(f"{name} must be sorted and unique")
    return normalized


def _require_source_polygon_v1(
    value: object,
) -> tuple[OcrPointV1, ...] | None:
    if value is None:
        return None
    if (
        not isinstance(value, tuple)
        or len(value) != 4
        or not all(isinstance(point, OcrPointV1) for point in value)
    ):
        raise ValueError("source_polygon must be one normalized rectangle")
    min_x = min(point.x for point in value)
    max_x = max(point.x for point in value)
    min_y = min(point.y for point in value)
    max_y = max(point.y for point in value)
    expected = (
        OcrPointV1(min_x, min_y),
        OcrPointV1(max_x, min_y),
        OcrPointV1(max_x, max_y),
        OcrPointV1(min_x, max_y),
    )
    if value != expected or min_x >= max_x or min_y >= max_y:
        raise ValueError("source_polygon must be one normalized rectangle")
    return value


@dataclass(frozen=True, slots=True)
class AdmissionNoticeExtractionIdentityV1:
    """Versioned identity for deterministic extraction behavior."""

    extractor_id: str
    rule_set_version: str
    normalization_version: str
    schema_version: str = ADMISSION_NOTICE_EXTRACTION_IDENTITY_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ADMISSION_NOTICE_EXTRACTION_IDENTITY_SCHEMA_VERSION_V1
        ):
            raise ValueError("unsupported extraction identity schema")
        _require_identity_component_v1("extractor_id", self.extractor_id)
        _require_identity_component_v1(
            "rule_set_version",
            self.rule_set_version,
        )
        _require_identity_component_v1(
            "normalization_version",
            self.normalization_version,
        )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "extractor_id": self.extractor_id,
            "normalization_version": self.normalization_version,
            "rule_set_version": self.rule_set_version,
            "schema_version": self.schema_version,
        }

    @property
    def extraction_identity_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes_v1(self.canonical_object_v1())
        ).hexdigest()


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class ExtractedAdmissionFieldV1:
    """One deterministic field decision with bounded source provenance."""

    status: AdmissionFieldStatusV1
    value: str | None
    source_span_ids: tuple[uuid.UUID, ...]
    source_polygon: tuple[OcrPointV1, ...] | None
    schema_version: str = EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1:
            raise ValueError("unsupported extracted-field schema")
        if not isinstance(self.status, AdmissionFieldStatusV1):
            raise TypeError("status must be AdmissionFieldStatusV1")
        if self.status is AdmissionFieldStatusV1.FOUND:
            value = require_text_v1(
                "extracted field value",
                self.value,
                maximum_utf8_bytes=4 * MAX_ADMISSION_MAJOR_CODEPOINTS_V1,
            )
            if len(value) > MAX_ADMISSION_MAJOR_CODEPOINTS_V1:
                raise ValueError("extracted field value exceeds its bound")
            _require_no_control_characters_v1(
                "extracted field value",
                value,
            )
            _require_sorted_uuid7_tuple_v1(
                "source_span_ids",
                self.source_span_ids,
                minimum_items=1,
                maximum_items=(MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1),
            )
            _require_source_polygon_v1(self.source_polygon)
            return
        if (
            self.value is not None
            or self.source_span_ids != ()
            or self.source_polygon is not None
        ):
            raise ValueError("non-FOUND fields must not carry answerable content")

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_polygon": (
                None
                if self.source_polygon is None
                else [point.canonical_object_v1() for point in self.source_polygon]
            ),
            "source_span_ids": [str(span_id) for span_id in self.source_span_ids],
            "status": self.status.value,
            "value": self.value,
        }

    def __repr__(self) -> str:
        return (
            "ExtractedAdmissionFieldV1("
            f"status={self.status.value!r}, value=<redacted>, "
            "source_span_ids=<opaque>, source_polygon=<private>)"
        )


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class AdmissionNoticeExtractionV1:
    """Minimal deterministic four-field admission-notice result."""

    capture_epoch: CaptureEpochV1
    source_ocr_result_ids: tuple[uuid.UUID, ...]
    source_frame_ids: tuple[uuid.UUID, ...]
    extraction_identity: AdmissionNoticeExtractionIdentityV1
    name: ExtractedAdmissionFieldV1
    source_province: ExtractedAdmissionFieldV1
    college: ExtractedAdmissionFieldV1
    major: ExtractedAdmissionFieldV1
    schema_version: str = ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1:
            raise ValueError("unsupported admission extraction schema")
        if not isinstance(self.capture_epoch, CaptureEpochV1):
            raise TypeError("capture_epoch must be CaptureEpochV1")
        _require_sorted_uuid7_tuple_v1(
            "source_ocr_result_ids",
            self.source_ocr_result_ids,
            minimum_items=1,
            maximum_items=MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
        )
        _require_sorted_uuid7_tuple_v1(
            "source_frame_ids",
            self.source_frame_ids,
            minimum_items=1,
            maximum_items=MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
        )
        if len(self.source_frame_ids) != len(self.source_ocr_result_ids):
            raise ValueError("source OCR/frame identity cardinality mismatch")
        if not isinstance(
            self.extraction_identity,
            AdmissionNoticeExtractionIdentityV1,
        ):
            raise TypeError(
                "extraction_identity must be AdmissionNoticeExtractionIdentityV1"
            )
        field_bounds = (
            ("name", self.name, MAX_ADMISSION_NAME_CODEPOINTS_V1),
            (
                "source_province",
                self.source_province,
                MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1,
            ),
            ("college", self.college, MAX_ADMISSION_COLLEGE_CODEPOINTS_V1),
            ("major", self.major, MAX_ADMISSION_MAJOR_CODEPOINTS_V1),
        )
        for field_name, field, maximum in field_bounds:
            if not isinstance(field, ExtractedAdmissionFieldV1):
                raise TypeError(f"{field_name} must be ExtractedAdmissionFieldV1")
            if field.value is not None and len(field.value) > maximum:
                raise ValueError(f"{field_name} exceeds its field bound")
        if (
            len(canonical_json_bytes_v1(self.canonical_object_v1()))
            > MAX_ADMISSION_NOTICE_EXTRACTION_CANONICAL_JSON_BYTES_V1
        ):
            raise ValueError("admission extraction exceeds its byte bound")

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "capture_epoch": capture_epoch_object_v1(self.capture_epoch),
            "college": self.college.canonical_object_v1(),
            "extraction_identity": (self.extraction_identity.canonical_object_v1()),
            "major": self.major.canonical_object_v1(),
            "name": self.name.canonical_object_v1(),
            "schema_version": self.schema_version,
            "source_frame_ids": [str(frame_id) for frame_id in self.source_frame_ids],
            "source_ocr_result_ids": [
                str(result_id) for result_id in self.source_ocr_result_ids
            ],
            "source_province": (self.source_province.canonical_object_v1()),
        }

    def canonical_json_v1(self) -> bytes:
        return canonical_json_bytes_v1(self.canonical_object_v1())

    @property
    def extraction_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json_v1()).hexdigest()

    def __repr__(self) -> str:
        statuses = (
            self.name.status.value,
            self.source_province.status.value,
            self.college.status.value,
            self.major.status.value,
        )
        return (
            "AdmissionNoticeExtractionV1("
            f"schema_version={self.schema_version!r}, "
            f"capture_seq={self.capture_epoch.capture_seq}, "
            f"field_statuses={statuses!r}, "
            "source_ids=<opaque>, values=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class AdmissionNoticeExtractionStorageKeyV1:
    """Plaintext-free bounded idempotency key within one capture."""

    source_ocr_result_ids: tuple[uuid.UUID, ...]
    extraction_identity_sha256: str

    def __post_init__(self) -> None:
        _require_sorted_uuid7_tuple_v1(
            "source_ocr_result_ids",
            self.source_ocr_result_ids,
            minimum_items=1,
            maximum_items=MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
        )
        require_sha256_hex_v1(
            "extraction_identity_sha256",
            self.extraction_identity_sha256,
        )


@dataclass(frozen=True, slots=True, repr=False)
class StoredAdmissionNoticeExtractionV1:
    """Opaque receipt for one encrypted admission extraction."""

    record_id: uuid.UUID
    extraction_sha256: str
    key: AdmissionNoticeExtractionStorageKeyV1
    reused: bool

    def __post_init__(self) -> None:
        require_uuid7_v1("record_id", self.record_id)
        require_sha256_hex_v1(
            "extraction_sha256",
            self.extraction_sha256,
        )
        if not isinstance(self.key, AdmissionNoticeExtractionStorageKeyV1):
            raise TypeError("key must be AdmissionNoticeExtractionStorageKeyV1")
        if not isinstance(self.reused, bool):
            raise TypeError("reused must be boolean")

    def __repr__(self) -> str:
        return "StoredAdmissionNoticeExtractionV1(<opaque-encrypted-result>)"


def _reject_json_constant_v1(value: str) -> Any:
    raise ValueError(value)


def _unique_json_object_v1(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _require_bounded_json_depth_v1(payload: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_ADMISSION_NOTICE_JSON_NESTING_DEPTH_V1:
                raise ValueError("admission extraction nesting bound exceeded")
        elif byte in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise ValueError("admission extraction JSON is invalid")
    if depth != 0 or in_string or escaped:
        raise ValueError("admission extraction JSON is invalid")


def _require_exact_fields_v1(
    value: object,
    expected: frozenset[str],
    *,
    name: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} has an invalid schema")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} has an invalid schema")
    return value


def _uuid7_from_wire_v1(name: str, value: object) -> uuid.UUID:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a UUIDv7 string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ValueError(f"{name} must be a UUIDv7 string") from None
    return require_uuid7_v1(name, parsed)


def _uuid7_tuple_from_wire_v1(
    name: str,
    value: object,
    *,
    maximum_items: int,
) -> tuple[uuid.UUID, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        raise ValueError(f"{name} has an invalid item count")
    return tuple(_uuid7_from_wire_v1(f"{name} item", item) for item in value)


def _identity_from_object_v1(
    value: object,
) -> AdmissionNoticeExtractionIdentityV1:
    item = _require_exact_fields_v1(
        value,
        frozenset(
            {
                "extractor_id",
                "normalization_version",
                "rule_set_version",
                "schema_version",
            }
        ),
        name="admission extraction identity",
    )
    return AdmissionNoticeExtractionIdentityV1(
        schema_version=item["schema_version"],
        extractor_id=item["extractor_id"],
        rule_set_version=item["rule_set_version"],
        normalization_version=item["normalization_version"],
    )


def _source_polygon_from_wire_v1(
    value: object,
) -> tuple[OcrPointV1, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("source polygon is invalid")
    points: list[OcrPointV1] = []
    for point in value:
        if not isinstance(point, list) or len(point) != 2:
            raise ValueError("source polygon point is invalid")
        points.append(OcrPointV1(x=point[0], y=point[1]))
    return tuple(points)


def _field_from_object_v1(value: object) -> ExtractedAdmissionFieldV1:
    item = _require_exact_fields_v1(
        value,
        frozenset(
            {
                "schema_version",
                "source_polygon",
                "source_span_ids",
                "status",
                "value",
            }
        ),
        name="extracted admission field",
    )
    try:
        status = AdmissionFieldStatusV1(item["status"])
    except (TypeError, ValueError):
        raise ValueError("extracted admission field status is invalid") from None
    source_ids_value = item["source_span_ids"]
    if not isinstance(source_ids_value, list) or len(source_ids_value) > (
        MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1
    ):
        raise ValueError("source span IDs are invalid")
    return ExtractedAdmissionFieldV1(
        schema_version=item["schema_version"],
        status=status,
        value=item["value"],
        source_span_ids=tuple(
            _uuid7_from_wire_v1("source span ID", span_id)
            for span_id in source_ids_value
        ),
        source_polygon=_source_polygon_from_wire_v1(item["source_polygon"]),
    )


def admission_notice_extraction_from_object_v1(
    value: object,
    *,
    expected_capture_epoch: CaptureEpochV1,
) -> AdmissionNoticeExtractionV1:
    item = _require_exact_fields_v1(
        value,
        frozenset(
            {
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
        ),
        name="admission notice extraction",
    )
    if not isinstance(expected_capture_epoch, CaptureEpochV1):
        raise TypeError("expected_capture_epoch must be CaptureEpochV1")
    if item["capture_epoch"] != capture_epoch_object_v1(expected_capture_epoch):
        raise ValueError("admission extraction capture epoch mismatch")
    return AdmissionNoticeExtractionV1(
        schema_version=item["schema_version"],
        capture_epoch=expected_capture_epoch,
        source_ocr_result_ids=_uuid7_tuple_from_wire_v1(
            "source OCR result IDs",
            item["source_ocr_result_ids"],
            maximum_items=MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
        ),
        source_frame_ids=_uuid7_tuple_from_wire_v1(
            "source frame IDs",
            item["source_frame_ids"],
            maximum_items=MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
        ),
        extraction_identity=_identity_from_object_v1(item["extraction_identity"]),
        name=_field_from_object_v1(item["name"]),
        source_province=_field_from_object_v1(item["source_province"]),
        college=_field_from_object_v1(item["college"]),
        major=_field_from_object_v1(item["major"]),
    )


def admission_notice_extraction_from_canonical_json_v1(
    payload: bytes,
    *,
    expected_capture_epoch: CaptureEpochV1,
) -> AdmissionNoticeExtractionV1:
    if (
        not isinstance(payload, bytes)
        or not 0
        < len(payload)
        <= MAX_ADMISSION_NOTICE_EXTRACTION_CANONICAL_JSON_BYTES_V1
    ):
        raise ValueError("admission extraction JSON size bound exceeded")
    _require_bounded_json_depth_v1(payload)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object_v1,
            parse_constant=_reject_json_constant_v1,
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise ValueError("admission extraction JSON is invalid") from None
    if not isinstance(value, dict):
        raise TypeError("admission extraction JSON must be an object")
    if canonical_json_bytes_v1(value) != payload:
        raise ValueError("admission extraction is not canonical JSON")
    return admission_notice_extraction_from_object_v1(
        value,
        expected_capture_epoch=expected_capture_epoch,
    )


__all__ = [
    "ADMISSION_NOTICE_EXTRACTION_IDENTITY_SCHEMA_VERSION_V1",
    "ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1",
    "EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1",
    "MAX_ADMISSION_COLLEGE_CODEPOINTS_V1",
    "MAX_ADMISSION_MAJOR_CODEPOINTS_V1",
    "MAX_ADMISSION_NAME_CODEPOINTS_V1",
    "MAX_ADMISSION_NOTICE_EXTRACTION_CANONICAL_JSON_BYTES_V1",
    "MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1",
    "MAX_ADMISSION_NOTICE_SOURCE_SPANS_PER_FIELD_V1",
    "MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1",
    "AdmissionFieldStatusV1",
    "AdmissionNoticeExtractionIdentityV1",
    "AdmissionNoticeExtractionStorageKeyV1",
    "AdmissionNoticeExtractionV1",
    "ExtractedAdmissionFieldV1",
    "StoredAdmissionNoticeExtractionV1",
    "admission_notice_extraction_from_canonical_json_v1",
    "admission_notice_extraction_from_object_v1",
]

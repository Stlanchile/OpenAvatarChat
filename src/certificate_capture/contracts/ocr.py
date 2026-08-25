"""Strict certificate-private OCR result contracts for Milestone 6A."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any

from certificate_capture.contracts.common import (
    canonical_json_bytes_v1,
    capture_epoch_object_v1,
    require_sha256_hex_v1,
    require_text_v1,
    require_uuid7_v1,
)
from certificate_capture.contracts.inference import ProcessingIdentityV1
from certificate_capture.epochs import CaptureEpochV1

OCR_PAGE_RESULT_SCHEMA_VERSION_V1 = "oac.ocr-page-result.v1"
OCR_SPAN_SCHEMA_VERSION_V1 = "oac.ocr-span.v1"

MAX_OCR_SPANS_PER_PAGE_V1 = 128
MAX_OCR_POLYGON_POINTS_V1 = 4
MAX_OCR_CHARACTERS_PER_SPAN_V1 = 512
MAX_OCR_UTF8_BYTES_PER_SPAN_V1 = 2 * 1024
MAX_OCR_AGGREGATE_CHARACTERS_V1 = 8 * 1024
MAX_OCR_AGGREGATE_UTF8_BYTES_V1 = 32 * 1024
MAX_OCR_RESULT_CANONICAL_JSON_BYTES_V1 = 48 * 1024
MAX_OCR_JSON_NESTING_DEPTH_V1 = 12


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
    """Reject excessive JSON nesting before invoking the JSON decoder."""

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
            if depth > MAX_OCR_JSON_NESTING_DEPTH_V1:
                raise ValueError("OCR JSON nesting bound exceeded")
        elif byte in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise ValueError("OCR JSON structure is invalid")
    if depth != 0 or in_string or escaped:
        raise ValueError("OCR JSON structure is invalid")


def decode_strict_ocr_json_object_v1(
    payload: bytes,
    *,
    maximum_bytes: int,
) -> dict[str, Any]:
    """Decode one bounded UTF-8 JSON object with duplicate/NaN rejection."""

    if not isinstance(payload, bytes) or not 0 < len(payload) <= maximum_bytes:
        raise ValueError("OCR JSON size bound exceeded")
    _require_bounded_json_depth_v1(payload)
    try:
        decoded = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object_v1,
            parse_constant=_reject_json_constant_v1,
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise ValueError("OCR JSON is invalid") from None
    if not isinstance(decoded, dict):
        raise TypeError("OCR JSON must be an object")
    return decoded


def _uuid7_from_wire_v1(name: str, value: object) -> uuid.UUID:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a UUIDv7 string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ValueError(f"{name} must be a UUIDv7 string") from None
    return require_uuid7_v1(name, parsed)


def _processing_identity_from_object_v1(
    value: object,
) -> ProcessingIdentityV1:
    item = _require_exact_fields_v1(
        value,
        frozenset(
            {
                "configuration_sha256",
                "implementation_version",
                "source_sha256",
            }
        ),
        name="preprocessing identity",
    )
    return ProcessingIdentityV1(
        implementation_version=item["implementation_version"],
        source_sha256=item["source_sha256"],
        configuration_sha256=item["configuration_sha256"],
    )


def processing_identity_sha256_v1(
    identity: ProcessingIdentityV1,
) -> str:
    if not isinstance(identity, ProcessingIdentityV1):
        raise TypeError("identity must be ProcessingIdentityV1")
    return hashlib.sha256(
        canonical_json_bytes_v1(identity.canonical_object_v1())
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class OcrPointV1:
    """One normalized point in the canonical frame coordinate system."""

    x: float
    y: float

    def __post_init__(self) -> None:
        for name, value in (("x", self.x), ("y", self.y)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.0 <= float(value) <= 1.0
            ):
                raise ValueError(f"OCR polygon {name} must be finite and normalized")
            object.__setattr__(self, name, float(value))

    def canonical_object_v1(self) -> list[float]:
        return [self.x, self.y]


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class OcrSpanV1:
    """Exact OCR text and source quadrilateral.

    ``raw_engine_score`` is an engine score. It is not a calibrated
    probability and must not be presented as a probability of correctness.
    """

    span_id: uuid.UUID
    text: str
    polygon: tuple[OcrPointV1, ...]
    raw_engine_score: float | None = None
    schema_version: str = OCR_SPAN_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != OCR_SPAN_SCHEMA_VERSION_V1:
            raise ValueError("unsupported OcrSpanV1 schema version")
        require_uuid7_v1("span_id", self.span_id)
        text = require_text_v1(
            "OCR span text",
            self.text,
            maximum_utf8_bytes=MAX_OCR_UTF8_BYTES_PER_SPAN_V1,
        )
        if len(text) > MAX_OCR_CHARACTERS_PER_SPAN_V1:
            raise ValueError("OCR span text exceeds its character bound")
        if any(unicodedata.category(character) == "Cc" for character in text):
            raise ValueError("OCR span text contains a control character")
        if (
            not isinstance(self.polygon, tuple)
            or len(self.polygon) != MAX_OCR_POLYGON_POINTS_V1
            or not all(isinstance(point, OcrPointV1) for point in self.polygon)
        ):
            raise ValueError("OCR span polygon must be one four-point tuple")
        if self.raw_engine_score is not None:
            score = self.raw_engine_score
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
                or not 0.0 <= float(score) <= 1.0
            ):
                raise ValueError("raw engine score must be finite and normalized")
            object.__setattr__(self, "raw_engine_score", float(score))

    def ordering_key_v1(self) -> tuple[object, ...]:
        xs = tuple(point.x for point in self.polygon)
        ys = tuple(point.y for point in self.polygon)
        return (
            min(ys),
            min(xs),
            max(ys),
            max(xs),
            self.text,
            (self.raw_engine_score if self.raw_engine_score is not None else -1.0),
        )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "polygon": [point.canonical_object_v1() for point in self.polygon],
            "raw_engine_score": self.raw_engine_score,
            "schema_version": self.schema_version,
            "span_id": str(self.span_id),
            "text": self.text,
        }

    def __repr__(self) -> str:
        return (
            "OcrSpanV1("
            f"schema_version={self.schema_version!r}, "
            "span_id=<opaque>, text=<redacted>, polygon=<private>)"
        )


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class OcrPageResultV1:
    """One strictly bounded OCR page result with no inferred field semantics."""

    result_id: uuid.UUID
    capture_epoch: CaptureEpochV1
    frame_id: uuid.UUID
    inference_identity_sha256: str
    preprocessing_identity: ProcessingIdentityV1
    spans: tuple[OcrSpanV1, ...]
    schema_version: str = OCR_PAGE_RESULT_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != OCR_PAGE_RESULT_SCHEMA_VERSION_V1:
            raise ValueError("unsupported OcrPageResultV1 schema version")
        require_uuid7_v1("result_id", self.result_id)
        require_uuid7_v1("frame_id", self.frame_id)
        if not isinstance(self.capture_epoch, CaptureEpochV1):
            raise TypeError("capture_epoch must be CaptureEpochV1")
        require_sha256_hex_v1(
            "inference_identity_sha256",
            self.inference_identity_sha256,
        )
        if not isinstance(self.preprocessing_identity, ProcessingIdentityV1):
            raise TypeError("preprocessing_identity must be ProcessingIdentityV1")
        if (
            not isinstance(self.spans, tuple)
            or len(self.spans) > MAX_OCR_SPANS_PER_PAGE_V1
            or not all(isinstance(span, OcrSpanV1) for span in self.spans)
        ):
            raise ValueError("OCR page spans exceed their immutable bound")
        if len({span.span_id for span in self.spans}) != len(self.spans):
            raise ValueError("OCR span IDs must be unique")
        if self.spans != tuple(sorted(self.spans, key=OcrSpanV1.ordering_key_v1)):
            raise ValueError("OCR spans must use deterministic reading order")
        aggregate_characters = sum(len(span.text) for span in self.spans)
        aggregate_utf8_bytes = sum(
            len(span.text.encode("utf-8", errors="strict")) for span in self.spans
        )
        if (
            aggregate_characters > MAX_OCR_AGGREGATE_CHARACTERS_V1
            or aggregate_utf8_bytes > MAX_OCR_AGGREGATE_UTF8_BYTES_V1
        ):
            raise ValueError("OCR page recognized text exceeds its aggregate bound")
        if (
            len(canonical_json_bytes_v1(self.canonical_object_v1()))
            > MAX_OCR_RESULT_CANONICAL_JSON_BYTES_V1
        ):
            raise ValueError("OCR page canonical result exceeds its byte bound")

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "capture_epoch": capture_epoch_object_v1(self.capture_epoch),
            "frame_id": str(self.frame_id),
            "inference_identity_sha256": self.inference_identity_sha256,
            "preprocessing_identity": (
                self.preprocessing_identity.canonical_object_v1()
            ),
            "result_id": str(self.result_id),
            "schema_version": self.schema_version,
            "spans": [span.canonical_object_v1() for span in self.spans],
        }

    def canonical_json_v1(self) -> bytes:
        return canonical_json_bytes_v1(self.canonical_object_v1())

    @property
    def preprocessing_identity_sha256(self) -> str:
        return processing_identity_sha256_v1(self.preprocessing_identity)

    def __repr__(self) -> str:
        return (
            "OcrPageResultV1("
            f"schema_version={self.schema_version!r}, "
            f"capture_seq={self.capture_epoch.capture_seq}, "
            f"span_count={len(self.spans)}, "
            "result_id=<opaque>, frame_id=<opaque>, spans=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class OcrResultStorageKeyV1:
    """Bounded plaintext-free idempotency key within one capture partition."""

    frame_id: uuid.UUID
    inference_identity_sha256: str
    preprocessing_identity_sha256: str

    def __post_init__(self) -> None:
        require_uuid7_v1("frame_id", self.frame_id)
        require_sha256_hex_v1(
            "inference_identity_sha256",
            self.inference_identity_sha256,
        )
        require_sha256_hex_v1(
            "preprocessing_identity_sha256",
            self.preprocessing_identity_sha256,
        )


@dataclass(frozen=True, slots=True, repr=False)
class StoredOcrResultV1:
    """Opaque receipt for one encrypted OCR auxiliary record."""

    record_id: uuid.UUID
    result_id: uuid.UUID
    key: OcrResultStorageKeyV1
    reused: bool

    def __post_init__(self) -> None:
        require_uuid7_v1("record_id", self.record_id)
        require_uuid7_v1("result_id", self.result_id)
        if not isinstance(self.key, OcrResultStorageKeyV1):
            raise TypeError("key must be OcrResultStorageKeyV1")
        if not isinstance(self.reused, bool):
            raise TypeError("reused must be boolean")

    def __repr__(self) -> str:
        return "StoredOcrResultV1(<opaque-encrypted-result>)"


def ocr_span_from_object_v1(value: object) -> OcrSpanV1:
    item = _require_exact_fields_v1(
        value,
        frozenset(
            {
                "polygon",
                "raw_engine_score",
                "schema_version",
                "span_id",
                "text",
            }
        ),
        name="OCR span",
    )
    polygon_value = item["polygon"]
    if (
        not isinstance(polygon_value, list)
        or len(polygon_value) != MAX_OCR_POLYGON_POINTS_V1
    ):
        raise ValueError("OCR span polygon is invalid")
    points: list[OcrPointV1] = []
    for point in polygon_value:
        if not isinstance(point, list) or len(point) != 2:
            raise ValueError("OCR span polygon point is invalid")
        points.append(OcrPointV1(x=point[0], y=point[1]))
    return OcrSpanV1(
        schema_version=item["schema_version"],
        span_id=_uuid7_from_wire_v1("span_id", item["span_id"]),
        text=item["text"],
        polygon=tuple(points),
        raw_engine_score=item["raw_engine_score"],
    )


def ocr_page_result_from_object_v1(
    value: object,
    *,
    expected_capture_epoch: CaptureEpochV1,
) -> OcrPageResultV1:
    item = _require_exact_fields_v1(
        value,
        frozenset(
            {
                "capture_epoch",
                "frame_id",
                "inference_identity_sha256",
                "preprocessing_identity",
                "result_id",
                "schema_version",
                "spans",
            }
        ),
        name="OCR page result",
    )
    if not isinstance(expected_capture_epoch, CaptureEpochV1):
        raise TypeError("expected_capture_epoch must be CaptureEpochV1")
    if item["capture_epoch"] != capture_epoch_object_v1(expected_capture_epoch):
        raise ValueError("OCR result capture epoch mismatch")
    spans_value = item["spans"]
    if (
        not isinstance(spans_value, list)
        or len(spans_value) > MAX_OCR_SPANS_PER_PAGE_V1
    ):
        raise ValueError("OCR result span count exceeded")
    return OcrPageResultV1(
        schema_version=item["schema_version"],
        result_id=_uuid7_from_wire_v1("result_id", item["result_id"]),
        capture_epoch=expected_capture_epoch,
        frame_id=_uuid7_from_wire_v1("frame_id", item["frame_id"]),
        inference_identity_sha256=item["inference_identity_sha256"],
        preprocessing_identity=_processing_identity_from_object_v1(
            item["preprocessing_identity"]
        ),
        spans=tuple(ocr_span_from_object_v1(span) for span in spans_value),
    )


def ocr_page_result_from_canonical_json_v1(
    payload: bytes,
    *,
    expected_capture_epoch: CaptureEpochV1,
) -> OcrPageResultV1:
    value = decode_strict_ocr_json_object_v1(
        payload,
        maximum_bytes=MAX_OCR_RESULT_CANONICAL_JSON_BYTES_V1,
    )
    if canonical_json_bytes_v1(value) != payload:
        raise ValueError("OCR result is not canonical JSON")
    return ocr_page_result_from_object_v1(
        value,
        expected_capture_epoch=expected_capture_epoch,
    )


__all__ = [
    "MAX_OCR_AGGREGATE_CHARACTERS_V1",
    "MAX_OCR_AGGREGATE_UTF8_BYTES_V1",
    "MAX_OCR_CHARACTERS_PER_SPAN_V1",
    "MAX_OCR_JSON_NESTING_DEPTH_V1",
    "MAX_OCR_POLYGON_POINTS_V1",
    "MAX_OCR_RESULT_CANONICAL_JSON_BYTES_V1",
    "MAX_OCR_SPANS_PER_PAGE_V1",
    "MAX_OCR_UTF8_BYTES_PER_SPAN_V1",
    "OCR_PAGE_RESULT_SCHEMA_VERSION_V1",
    "OCR_SPAN_SCHEMA_VERSION_V1",
    "OcrPageResultV1",
    "OcrPointV1",
    "OcrResultStorageKeyV1",
    "OcrSpanV1",
    "StoredOcrResultV1",
    "decode_strict_ocr_json_object_v1",
    "ocr_page_result_from_canonical_json_v1",
    "ocr_page_result_from_object_v1",
    "ocr_span_from_object_v1",
    "processing_identity_sha256_v1",
]

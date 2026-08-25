"""Sidecar-local copy of the bounded private UDS wire contract."""

from __future__ import annotations

import json
import math
import secrets
import struct
import time
import uuid
from typing import Any

OCR_UDS_PROTOCOL_VERSION_V1 = "oac.private-ocr-uds.v1"
OCR_REQUEST_SCHEMA_VERSION_V1 = "oac.ocr-request.v1"
OCR_RESPONSE_SCHEMA_VERSION_V1 = "oac.ocr-response.v1"
OCR_HEALTH_REQUEST_SCHEMA_VERSION_V1 = "oac.ocr-health-request.v1"
OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1 = "oac.ocr-health-response.v1"
OCR_CANCEL_REQUEST_SCHEMA_VERSION_V1 = "oac.ocr-cancel-request.v1"
OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1 = "oac.ocr-error-response.v1"

OCR_REQUEST_MAGIC_V1 = b"OACOCRQ1"
OCR_RESPONSE_MAGIC_V1 = b"OACOCRR1"
OCR_FRAME_PREFIX_V1 = struct.Struct("!8sII")
OCR_FRAME_PREFIX_BYTES_V1 = OCR_FRAME_PREFIX_V1.size

MAX_OCR_REQUEST_METADATA_BYTES_V1 = 8 * 1024
MAX_OCR_RESPONSE_BYTES_V1 = 64 * 1024
MAX_OCR_JPEG_BYTES_V1 = 2 * 1024 * 1024
MAX_OCR_JSON_NESTING_DEPTH_V1 = 12


class SidecarProtocolErrorV1(ValueError):
    """Value-free protocol rejection."""


def canonical_json_bytes_v1(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _reject_constant_v1(value: str) -> Any:
    raise ValueError(value)


def _unique_object_v1(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _bounded_depth_v1(payload: bytes) -> None:
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
                raise SidecarProtocolErrorV1("protocol rejected")
        elif byte in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise SidecarProtocolErrorV1("protocol rejected")
    if depth != 0 or in_string or escaped:
        raise SidecarProtocolErrorV1("protocol rejected")


def strict_json_object_v1(
    payload: bytes,
    *,
    maximum_bytes: int,
) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= maximum_bytes:
        raise SidecarProtocolErrorV1("protocol rejected")
    _bounded_depth_v1(payload)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object_v1,
            parse_constant=_reject_constant_v1,
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise SidecarProtocolErrorV1("protocol rejected") from None
    if not isinstance(value, dict):
        raise SidecarProtocolErrorV1("protocol rejected")
    return value


def exact_object_v1(
    value: object,
    fields: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SidecarProtocolErrorV1("protocol rejected")
    return value


def require_uuid7_text_v1(value: object) -> str:
    if not isinstance(value, str):
        raise SidecarProtocolErrorV1("protocol rejected")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise SidecarProtocolErrorV1("protocol rejected") from None
    if parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        raise SidecarProtocolErrorV1("protocol rejected")
    return value


def require_sha256_v1(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SidecarProtocolErrorV1("protocol rejected")
    return value


def new_uuid7_v1() -> str:
    unix_ms = time.time_ns() // 1_000_000
    random_bits = secrets.randbits(74)
    random_a = random_bits >> 62
    random_b = random_bits & ((1 << 62) - 1)
    value = (unix_ms << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    return str(uuid.UUID(int=value))


def unpack_request_prefix_v1(prefix: bytes) -> tuple[int, int]:
    if not isinstance(prefix, bytes) or len(prefix) != OCR_FRAME_PREFIX_BYTES_V1:
        raise SidecarProtocolErrorV1("protocol rejected")
    try:
        magic, metadata_length, payload_length = OCR_FRAME_PREFIX_V1.unpack(prefix)
    except struct.error:
        raise SidecarProtocolErrorV1("protocol rejected") from None
    if (
        magic != OCR_REQUEST_MAGIC_V1
        or not 0 < metadata_length <= MAX_OCR_REQUEST_METADATA_BYTES_V1
        or payload_length > MAX_OCR_JPEG_BYTES_V1
    ):
        raise SidecarProtocolErrorV1("protocol rejected")
    return metadata_length, payload_length


def parse_ocr_request_v1(
    value: object,
    *,
    declared_payload_length: int,
) -> dict[str, Any]:
    item = exact_object_v1(
        value,
        frozenset(
            {
                "canonical_height",
                "canonical_width",
                "capture_epoch",
                "frame_id",
                "inference_identity_expected",
                "jpeg_length",
                "operation",
                "operation_id",
                "preprocessing_identity_sha256_expected",
                "protocol_version",
                "request_id",
                "schema_version",
            }
        ),
    )
    if (
        item["operation"] != "OCR"
        or item["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or item["schema_version"] != OCR_REQUEST_SCHEMA_VERSION_V1
        or item["jpeg_length"] != declared_payload_length
        or not 0 < declared_payload_length <= MAX_OCR_JPEG_BYTES_V1
    ):
        raise SidecarProtocolErrorV1("protocol rejected")
    require_uuid7_text_v1(item["request_id"])
    require_uuid7_text_v1(item["frame_id"])
    require_uuid7_text_v1(item["operation_id"])
    require_sha256_v1(item["inference_identity_expected"])
    require_sha256_v1(item["preprocessing_identity_sha256_expected"])
    capture_epoch = exact_object_v1(
        item["capture_epoch"],
        frozenset({"capture_id", "capture_seq", "session_epoch"}),
    )
    require_uuid7_text_v1(capture_epoch["capture_id"])
    session_epoch = exact_object_v1(
        capture_epoch["session_epoch"],
        frozenset({"generation", "session_instance_id"}),
    )
    require_uuid7_text_v1(session_epoch["session_instance_id"])
    for value_item in (
        capture_epoch["capture_seq"],
        session_epoch["generation"],
        item["canonical_width"],
        item["canonical_height"],
    ):
        if (
            isinstance(value_item, bool)
            or not isinstance(value_item, int)
            or value_item <= 0
        ):
            raise SidecarProtocolErrorV1("protocol rejected")
    return item


def parse_health_request_v1(value: object, payload_length: int) -> str:
    item = exact_object_v1(
        value,
        frozenset(
            {
                "operation",
                "protocol_version",
                "request_id",
                "schema_version",
            }
        ),
    )
    if (
        payload_length != 0
        or item["operation"] != "HEALTH"
        or item["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or item["schema_version"] != OCR_HEALTH_REQUEST_SCHEMA_VERSION_V1
    ):
        raise SidecarProtocolErrorV1("protocol rejected")
    return require_uuid7_text_v1(item["request_id"])


def parse_cancel_request_v1(
    value: object,
    payload_length: int,
) -> tuple[str, str]:
    item = exact_object_v1(
        value,
        frozenset(
            {
                "operation",
                "operation_id",
                "protocol_version",
                "request_id",
                "schema_version",
            }
        ),
    )
    if (
        payload_length != 0
        or item["operation"] != "CANCEL"
        or item["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or item["schema_version"] != OCR_CANCEL_REQUEST_SCHEMA_VERSION_V1
    ):
        raise SidecarProtocolErrorV1("protocol rejected")
    return (
        require_uuid7_text_v1(item["request_id"]),
        require_uuid7_text_v1(item["operation_id"]),
    )


def response_frame_v1(value: dict[str, object]) -> bytes:
    payload = canonical_json_bytes_v1(value)
    if not 0 < len(payload) <= MAX_OCR_RESPONSE_BYTES_V1:
        raise SidecarProtocolErrorV1("response rejected")
    return (
        OCR_FRAME_PREFIX_V1.pack(
            OCR_RESPONSE_MAGIC_V1,
            len(payload),
            0,
        )
        + payload
    )


def error_response_v1(
    *,
    request_id: str | None,
    reason_code: str,
) -> bytes:
    if request_id is not None:
        require_uuid7_text_v1(request_id)
    return response_frame_v1(
        {
            "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
            "reason_code": reason_code,
            "request_id": request_id,
            "schema_version": OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1,
        }
    )


def require_finite_normalized_v1(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0.0 <= float(value) <= 1.0
    ):
        raise SidecarProtocolErrorV1("result rejected")
    return float(value)


__all__ = [
    "MAX_OCR_JPEG_BYTES_V1",
    "MAX_OCR_REQUEST_METADATA_BYTES_V1",
    "MAX_OCR_RESPONSE_BYTES_V1",
    "OCR_CANCEL_REQUEST_SCHEMA_VERSION_V1",
    "OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1",
    "OCR_FRAME_PREFIX_BYTES_V1",
    "OCR_HEALTH_REQUEST_SCHEMA_VERSION_V1",
    "OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1",
    "OCR_REQUEST_SCHEMA_VERSION_V1",
    "OCR_RESPONSE_SCHEMA_VERSION_V1",
    "OCR_UDS_PROTOCOL_VERSION_V1",
    "SidecarProtocolErrorV1",
    "canonical_json_bytes_v1",
    "error_response_v1",
    "exact_object_v1",
    "new_uuid7_v1",
    "parse_cancel_request_v1",
    "parse_health_request_v1",
    "parse_ocr_request_v1",
    "require_finite_normalized_v1",
    "require_sha256_v1",
    "response_frame_v1",
    "strict_json_object_v1",
    "unpack_request_prefix_v1",
]

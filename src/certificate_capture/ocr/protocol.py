"""Bounded versioned framing for the certificate-private OCR UDS."""

from __future__ import annotations

import math
import struct
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

from certificate_capture.contracts.common import (
    canonical_json_bytes_v1,
    capture_epoch_object_v1,
    require_sha256_hex_v1,
    require_uuid7_v1,
)
from certificate_capture.contracts.inference import InferenceIdentityV1
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    decode_strict_ocr_json_object_v1,
    ocr_page_result_from_object_v1,
    processing_identity_sha256_v1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.ocr.identity import (
    inference_identity_from_object_v1,
)
from certificate_capture.protocol import MAX_ENCODED_FRAME_BYTES_V1

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
MAX_OCR_FRAMES_PER_OPERATION_V1 = 3


class OcrFailureReasonV1(str, Enum):
    OCR_UNAVAILABLE = "OCR_UNAVAILABLE"
    SOCKET_REJECTED = "SOCKET_REJECTED"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    WRITE_TIMEOUT = "WRITE_TIMEOUT"
    PROCESSING_TIMEOUT = "PROCESSING_TIMEOUT"
    RESPONSE_TIMEOUT = "RESPONSE_TIMEOUT"
    PROTOCOL_REJECTED = "PROTOCOL_REJECTED"
    REQUEST_REJECTED = "REQUEST_REJECTED"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    CORRELATION_MISMATCH = "CORRELATION_MISMATCH"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    OCR_FAILED = "OCR_FAILED"
    WORK_RETIRED = "WORK_RETIRED"
    STORE_REJECTED = "STORE_REJECTED"
    CANCELLED = "CANCELLED"


class OcrServiceErrorV1(RuntimeError):
    """Stable payload-free OCR operational failure."""

    __slots__ = ("reason", "reason_code")

    def __init__(self, reason: OcrFailureReasonV1) -> None:
        self.reason = reason
        self.reason_code = reason.value
        super().__init__(f"private OCR operation failed ({reason.value})")


def _exact_object_v1(
    value: object,
    fields: frozenset[str],
    name: str,
    *,
    reason: OcrFailureReasonV1 = OcrFailureReasonV1.PROTOCOL_REJECTED,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OcrServiceErrorV1(reason)
    return value


def _uuid7_from_wire_v1(value: object) -> uuid.UUID:
    if not isinstance(value, str):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED)
    try:
        parsed = uuid.UUID(value)
        return require_uuid7_v1("OCR correlation ID", parsed)
    except (ValueError, TypeError, AttributeError):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED) from None


def unpack_frame_prefix_v1(
    prefix: bytes,
    *,
    expected_magic: bytes,
    maximum_metadata_bytes: int,
    maximum_payload_bytes: int,
) -> tuple[int, int]:
    if (
        not isinstance(prefix, bytes)
        or len(prefix) != OCR_FRAME_PREFIX_BYTES_V1
        or not isinstance(expected_magic, bytes)
        or len(expected_magic) != 8
    ):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED)
    try:
        magic, metadata_length, payload_length = OCR_FRAME_PREFIX_V1.unpack(prefix)
    except struct.error:
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED) from None
    if (
        magic != expected_magic
        or not 0 < metadata_length <= maximum_metadata_bytes
        or payload_length > maximum_payload_bytes
    ):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED)
    return metadata_length, payload_length


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class OcrRequestV1:
    request_id: uuid.UUID
    frame_id: uuid.UUID
    capture_epoch: CaptureEpochV1
    operation_id: uuid.UUID
    inference_identity_expected: str
    preprocessing_identity_sha256_expected: str
    canonical_width: int
    canonical_height: int
    jpeg_length: int
    schema_version: str = OCR_REQUEST_SCHEMA_VERSION_V1
    protocol_version: str = OCR_UDS_PROTOCOL_VERSION_V1

    def __post_init__(self) -> None:
        for name, value in (
            ("request_id", self.request_id),
            ("frame_id", self.frame_id),
            ("operation_id", self.operation_id),
        ):
            require_uuid7_v1(name, value)
        if not isinstance(self.capture_epoch, CaptureEpochV1):
            raise TypeError("capture_epoch must be CaptureEpochV1")
        require_sha256_hex_v1(
            "inference_identity_expected",
            self.inference_identity_expected,
        )
        require_sha256_hex_v1(
            "preprocessing_identity_sha256_expected",
            self.preprocessing_identity_sha256_expected,
        )
        for name, value in (
            ("canonical_width", self.canonical_width),
            ("canonical_height", self.canonical_height),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > 1_000_000
            ):
                raise ValueError(f"{name} must be a bounded positive integer")
        if (
            isinstance(self.jpeg_length, bool)
            or not isinstance(self.jpeg_length, int)
            or not 0 < self.jpeg_length <= MAX_ENCODED_FRAME_BYTES_V1
        ):
            raise ValueError("jpeg_length exceeds the OCR request bound")
        if self.schema_version != OCR_REQUEST_SCHEMA_VERSION_V1:
            raise ValueError("unsupported OCR request schema")
        if self.protocol_version != OCR_UDS_PROTOCOL_VERSION_V1:
            raise ValueError("unsupported OCR UDS protocol")

    def canonical_metadata_object_v1(self) -> dict[str, object]:
        return {
            "canonical_height": self.canonical_height,
            "canonical_width": self.canonical_width,
            "capture_epoch": capture_epoch_object_v1(self.capture_epoch),
            "frame_id": str(self.frame_id),
            "inference_identity_expected": (self.inference_identity_expected),
            "jpeg_length": self.jpeg_length,
            "operation": "OCR",
            "operation_id": str(self.operation_id),
            "preprocessing_identity_sha256_expected": (
                self.preprocessing_identity_sha256_expected
            ),
            "protocol_version": self.protocol_version,
            "request_id": str(self.request_id),
            "schema_version": self.schema_version,
        }

    def canonical_metadata_json_v1(self) -> bytes:
        payload = canonical_json_bytes_v1(self.canonical_metadata_object_v1())
        if len(payload) > MAX_OCR_REQUEST_METADATA_BYTES_V1:
            raise ValueError("OCR request metadata exceeds its byte bound")
        return payload

    def frame_prefix_and_metadata_v1(self) -> bytes:
        metadata = self.canonical_metadata_json_v1()
        return (
            OCR_FRAME_PREFIX_V1.pack(
                OCR_REQUEST_MAGIC_V1,
                len(metadata),
                self.jpeg_length,
            )
            + metadata
        )

    def __repr__(self) -> str:
        return (
            "OcrRequestV1("
            f"capture_seq={self.capture_epoch.capture_seq}, "
            f"jpeg_length={self.jpeg_length}, correlations=<opaque>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OcrHealthRequestV1:
    request_id: uuid.UUID
    schema_version: str = OCR_HEALTH_REQUEST_SCHEMA_VERSION_V1
    protocol_version: str = OCR_UDS_PROTOCOL_VERSION_V1

    def __post_init__(self) -> None:
        require_uuid7_v1("request_id", self.request_id)
        if self.schema_version != OCR_HEALTH_REQUEST_SCHEMA_VERSION_V1:
            raise ValueError("unsupported OCR health request schema")
        if self.protocol_version != OCR_UDS_PROTOCOL_VERSION_V1:
            raise ValueError("unsupported OCR UDS protocol")

    def frame_v1(self) -> bytes:
        metadata = canonical_json_bytes_v1(
            {
                "operation": "HEALTH",
                "protocol_version": self.protocol_version,
                "request_id": str(self.request_id),
                "schema_version": self.schema_version,
            }
        )
        return (
            OCR_FRAME_PREFIX_V1.pack(
                OCR_REQUEST_MAGIC_V1,
                len(metadata),
                0,
            )
            + metadata
        )


@dataclass(frozen=True, slots=True, repr=False)
class OcrCancelRequestV1:
    request_id: uuid.UUID
    operation_id: uuid.UUID
    schema_version: str = OCR_CANCEL_REQUEST_SCHEMA_VERSION_V1
    protocol_version: str = OCR_UDS_PROTOCOL_VERSION_V1

    def __post_init__(self) -> None:
        require_uuid7_v1("request_id", self.request_id)
        require_uuid7_v1("operation_id", self.operation_id)
        if self.schema_version != OCR_CANCEL_REQUEST_SCHEMA_VERSION_V1:
            raise ValueError("unsupported OCR cancel request schema")
        if self.protocol_version != OCR_UDS_PROTOCOL_VERSION_V1:
            raise ValueError("unsupported OCR UDS protocol")

    def frame_v1(self) -> bytes:
        metadata = canonical_json_bytes_v1(
            {
                "operation": "CANCEL",
                "operation_id": str(self.operation_id),
                "protocol_version": self.protocol_version,
                "request_id": str(self.request_id),
                "schema_version": self.schema_version,
            }
        )
        return (
            OCR_FRAME_PREFIX_V1.pack(
                OCR_REQUEST_MAGIC_V1,
                len(metadata),
                0,
            )
            + metadata
        )


@dataclass(frozen=True, slots=True, repr=False)
class OcrHealthStatusV1:
    request_id: uuid.UUID
    identity: InferenceIdentityV1
    qualification_record_sha256: str
    processing_timeout_seconds: float

    def __post_init__(self) -> None:
        require_uuid7_v1("request_id", self.request_id)
        if not isinstance(self.identity, InferenceIdentityV1):
            raise TypeError("identity must be InferenceIdentityV1")
        require_sha256_hex_v1(
            "qualification_record_sha256",
            self.qualification_record_sha256,
        )
        if (
            isinstance(self.processing_timeout_seconds, bool)
            or not isinstance(
                self.processing_timeout_seconds,
                (int, float),
            )
            or not math.isfinite(self.processing_timeout_seconds)
            or not 1.0 <= float(self.processing_timeout_seconds) <= 300.0
        ):
            raise ValueError("OCR processing timeout identity is invalid")
        object.__setattr__(
            self,
            "processing_timeout_seconds",
            float(self.processing_timeout_seconds),
        )

    def __repr__(self) -> str:
        return "OcrHealthStatusV1(<verified-cpu-identity>)"


def parse_ocr_request_metadata_v1(
    metadata: bytes,
    *,
    declared_jpeg_length: int,
    expected_capture_epoch: CaptureEpochV1 | None = None,
) -> dict[str, Any]:
    """Strict sidecar-facing request validation helper."""

    try:
        value = decode_strict_ocr_json_object_v1(
            metadata,
            maximum_bytes=MAX_OCR_REQUEST_METADATA_BYTES_V1,
        )
    except (TypeError, ValueError):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED) from None
    item = _exact_object_v1(
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
        "OCR request",
    )
    if (
        item["operation"] != "OCR"
        or item["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or item["schema_version"] != OCR_REQUEST_SCHEMA_VERSION_V1
        or item["jpeg_length"] != declared_jpeg_length
        or not 0 < declared_jpeg_length <= MAX_ENCODED_FRAME_BYTES_V1
    ):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED)
    _uuid7_from_wire_v1(item["request_id"])
    _uuid7_from_wire_v1(item["frame_id"])
    _uuid7_from_wire_v1(item["operation_id"])
    try:
        require_sha256_hex_v1(
            "inference_identity_expected",
            item["inference_identity_expected"],
        )
        require_sha256_hex_v1(
            "preprocessing_identity_sha256_expected",
            item["preprocessing_identity_sha256_expected"],
        )
    except (TypeError, ValueError):
        raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED) from None
    if expected_capture_epoch is not None and item[
        "capture_epoch"
    ] != capture_epoch_object_v1(expected_capture_epoch):
        raise OcrServiceErrorV1(OcrFailureReasonV1.CORRELATION_MISMATCH)
    for dimension_name in ("canonical_width", "canonical_height"):
        dimension = item[dimension_name]
        if (
            isinstance(dimension, bool)
            or not isinstance(dimension, int)
            or not 0 < dimension <= 1_000_000
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.PROTOCOL_REJECTED)
    return item


def encode_ocr_response_frame_v1(
    *,
    request: OcrRequestV1,
    result: OcrPageResultV1,
) -> bytes:
    if (
        result.capture_epoch is not request.capture_epoch
        or result.frame_id != request.frame_id
    ):
        raise ValueError("OCR response binding mismatch")
    payload = canonical_json_bytes_v1(
        {
            "operation": "OCR",
            "operation_id": str(request.operation_id),
            "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
            "request_id": str(request.request_id),
            "result": result.canonical_object_v1(),
            "schema_version": OCR_RESPONSE_SCHEMA_VERSION_V1,
        }
    )
    if len(payload) > MAX_OCR_RESPONSE_BYTES_V1:
        raise ValueError("OCR response exceeds its byte bound")
    return (
        OCR_FRAME_PREFIX_V1.pack(
            OCR_RESPONSE_MAGIC_V1,
            len(payload),
            0,
        )
        + payload
    )


def encode_ocr_error_frame_v1(
    *,
    request_id: uuid.UUID | None,
    reason: OcrFailureReasonV1,
) -> bytes:
    if request_id is not None:
        require_uuid7_v1("request_id", request_id)
    if not isinstance(reason, OcrFailureReasonV1):
        raise TypeError("reason must be OcrFailureReasonV1")
    payload = canonical_json_bytes_v1(
        {
            "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
            "reason_code": reason.value,
            "request_id": (str(request_id) if request_id is not None else None),
            "schema_version": OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1,
        }
    )
    return (
        OCR_FRAME_PREFIX_V1.pack(
            OCR_RESPONSE_MAGIC_V1,
            len(payload),
            0,
        )
        + payload
    )


def parse_ocr_response_payload_v1(
    payload: bytes,
    *,
    request: OcrRequestV1,
) -> OcrPageResultV1:
    try:
        value = decode_strict_ocr_json_object_v1(
            payload,
            maximum_bytes=MAX_OCR_RESPONSE_BYTES_V1,
        )
    except ValueError:
        raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
    if value.get("schema_version") == OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1:
        error = _exact_object_v1(
            value,
            frozenset(
                {
                    "protocol_version",
                    "reason_code",
                    "request_id",
                    "schema_version",
                }
            ),
            "OCR error response",
            reason=OcrFailureReasonV1.MALFORMED_RESPONSE,
        )
        if error["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1 or error[
            "request_id"
        ] != str(request.request_id):
            raise OcrServiceErrorV1(OcrFailureReasonV1.CORRELATION_MISMATCH)
        try:
            reason = OcrFailureReasonV1(error["reason_code"])
        except (ValueError, TypeError):
            raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
        raise OcrServiceErrorV1(reason)
    item = _exact_object_v1(
        value,
        frozenset(
            {
                "operation",
                "operation_id",
                "protocol_version",
                "request_id",
                "result",
                "schema_version",
            }
        ),
        "OCR response",
        reason=OcrFailureReasonV1.MALFORMED_RESPONSE,
    )
    if (
        item["operation"] != "OCR"
        or item["schema_version"] != OCR_RESPONSE_SCHEMA_VERSION_V1
        or item["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or item["request_id"] != str(request.request_id)
        or item["operation_id"] != str(request.operation_id)
    ):
        raise OcrServiceErrorV1(OcrFailureReasonV1.CORRELATION_MISMATCH)
    try:
        result = ocr_page_result_from_object_v1(
            item["result"],
            expected_capture_epoch=request.capture_epoch,
        )
    except (TypeError, ValueError):
        raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
    if result.frame_id != request.frame_id:
        raise OcrServiceErrorV1(OcrFailureReasonV1.CORRELATION_MISMATCH)
    if (
        result.inference_identity_sha256 != request.inference_identity_expected
        or processing_identity_sha256_v1(result.preprocessing_identity)
        != request.preprocessing_identity_sha256_expected
    ):
        raise OcrServiceErrorV1(OcrFailureReasonV1.IDENTITY_MISMATCH)
    return result


def parse_health_response_payload_v1(
    payload: bytes,
    *,
    request_id: uuid.UUID,
) -> OcrHealthStatusV1:
    try:
        value = decode_strict_ocr_json_object_v1(
            payload,
            maximum_bytes=MAX_OCR_RESPONSE_BYTES_V1,
        )
    except (TypeError, ValueError):
        raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
    if value.get("schema_version") == OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1:
        error = _exact_object_v1(
            value,
            frozenset(
                {
                    "protocol_version",
                    "reason_code",
                    "request_id",
                    "schema_version",
                }
            ),
            "OCR health error response",
            reason=OcrFailureReasonV1.MALFORMED_RESPONSE,
        )
        if error["request_id"] != str(request_id):
            raise OcrServiceErrorV1(OcrFailureReasonV1.CORRELATION_MISMATCH)
        raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
    item = _exact_object_v1(
        value,
        frozenset(
            {
                "healthy",
                "inference_identity",
                "processing_timeout_seconds",
                "protocol_version",
                "qualification_record_sha256",
                "request_id",
                "schema_version",
            }
        ),
        "OCR health response",
        reason=OcrFailureReasonV1.MALFORMED_RESPONSE,
    )
    if (
        item["healthy"] is not True
        or item["protocol_version"] != OCR_UDS_PROTOCOL_VERSION_V1
        or item["schema_version"] != OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1
        or item["request_id"] != str(request_id)
    ):
        raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
    try:
        identity = inference_identity_from_object_v1(item["inference_identity"])
        return OcrHealthStatusV1(
            request_id=request_id,
            identity=identity,
            qualification_record_sha256=(item["qualification_record_sha256"]),
            processing_timeout_seconds=item["processing_timeout_seconds"],
        )
    except (TypeError, ValueError):
        raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None


__all__ = [
    "MAX_OCR_FRAMES_PER_OPERATION_V1",
    "MAX_OCR_REQUEST_METADATA_BYTES_V1",
    "MAX_OCR_RESPONSE_BYTES_V1",
    "OCR_CANCEL_REQUEST_SCHEMA_VERSION_V1",
    "OCR_ERROR_RESPONSE_SCHEMA_VERSION_V1",
    "OCR_FRAME_PREFIX_BYTES_V1",
    "OCR_FRAME_PREFIX_V1",
    "OCR_HEALTH_REQUEST_SCHEMA_VERSION_V1",
    "OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1",
    "OCR_REQUEST_MAGIC_V1",
    "OCR_REQUEST_SCHEMA_VERSION_V1",
    "OCR_RESPONSE_MAGIC_V1",
    "OCR_RESPONSE_SCHEMA_VERSION_V1",
    "OCR_UDS_PROTOCOL_VERSION_V1",
    "OcrCancelRequestV1",
    "OcrFailureReasonV1",
    "OcrHealthRequestV1",
    "OcrHealthStatusV1",
    "OcrRequestV1",
    "OcrServiceErrorV1",
    "encode_ocr_error_frame_v1",
    "encode_ocr_response_frame_v1",
    "parse_health_response_payload_v1",
    "parse_ocr_request_metadata_v1",
    "parse_ocr_response_payload_v1",
    "unpack_frame_prefix_v1",
]

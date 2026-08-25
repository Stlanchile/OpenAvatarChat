"""Versioned, bounded plaintext codec used immediately before encryption."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from certificate_capture.contracts.common import canonical_json_bytes_v1
from certificate_capture.protocol import MAX_ENCODED_FRAME_BYTES_V1

PRIVATE_CODEC_SCHEMA_VERSION_V1 = "oac.private-evidence-codec.v1"
MAX_AUXILIARY_CANONICAL_JSON_BYTES_V1 = 64 * 1024

_PRIVATE_CODEC_MAGIC_V1 = b"OACPEV1\x00"
_PRIVATE_CODEC_LENGTH_BYTES_V1 = 8
PRIVATE_CODEC_OVERHEAD_BYTES_V1 = (
    len(_PRIVATE_CODEC_MAGIC_V1) + 1 + _PRIVATE_CODEC_LENGTH_BYTES_V1
)


class PrivateEvidenceRecordTypeV1(str, Enum):
    FRAME_JPEG = "FRAME_JPEG"
    AUXILIARY_CANONICAL_JSON = "AUXILIARY_CANONICAL_JSON"


_RECORD_TYPE_CODE_V1 = {
    PrivateEvidenceRecordTypeV1.FRAME_JPEG: 1,
    PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON: 2,
}
_CODE_RECORD_TYPE_V1 = {
    code: record_type for record_type, code in _RECORD_TYPE_CODE_V1.items()
}


class PrivateCodecErrorV1(ValueError):
    """Stable value-free codec rejection."""


def encode_private_record_v1(
    record_type: PrivateEvidenceRecordTypeV1,
    payload: bytes | bytearray | memoryview,
) -> bytes:
    """Encode one closed record type without transcoding its payload."""

    if not isinstance(record_type, PrivateEvidenceRecordTypeV1):
        raise PrivateCodecErrorV1("private evidence codec rejected a record")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise PrivateCodecErrorV1("private evidence codec rejected a record")
    payload_view = memoryview(payload)
    try:
        payload_length = payload_view.nbytes
        if record_type is PrivateEvidenceRecordTypeV1.FRAME_JPEG:
            if not 0 < payload_length <= MAX_ENCODED_FRAME_BYTES_V1:
                raise PrivateCodecErrorV1(
                    "private evidence codec rejected a record"
                )
        else:
            if not 0 < payload_length <= MAX_AUXILIARY_CANONICAL_JSON_BYTES_V1:
                raise PrivateCodecErrorV1(
                    "private evidence codec rejected a record"
                )
            _require_canonical_json_object_v1(bytes(payload_view))
        header = (
            _PRIVATE_CODEC_MAGIC_V1
            + bytes((_RECORD_TYPE_CODE_V1[record_type],))
            + payload_length.to_bytes(
                _PRIVATE_CODEC_LENGTH_BYTES_V1,
                "big",
            )
        )
        return header + payload_view
    except PrivateCodecErrorV1:
        raise
    except (BufferError, OverflowError, TypeError, ValueError):
        raise PrivateCodecErrorV1(
            "private evidence codec rejected a record"
        ) from None
    finally:
        payload_view.release()


def decode_private_record_v1(
    expected_record_type: PrivateEvidenceRecordTypeV1,
    encoded: bytes,
) -> bytes:
    """Strictly decode one known codec version and exact record type."""

    if (
        not isinstance(expected_record_type, PrivateEvidenceRecordTypeV1)
        or not isinstance(encoded, bytes)
        or len(encoded) <= PRIVATE_CODEC_OVERHEAD_BYTES_V1
        or not encoded.startswith(_PRIVATE_CODEC_MAGIC_V1)
    ):
        raise PrivateCodecErrorV1("private evidence codec rejected a record")
    type_offset = len(_PRIVATE_CODEC_MAGIC_V1)
    encoded_type = _CODE_RECORD_TYPE_V1.get(encoded[type_offset])
    if encoded_type is not expected_record_type:
        raise PrivateCodecErrorV1("private evidence codec rejected a record")
    length_offset = type_offset + 1
    payload_offset = length_offset + _PRIVATE_CODEC_LENGTH_BYTES_V1
    declared_length = int.from_bytes(
        encoded[length_offset:payload_offset],
        "big",
    )
    if declared_length != len(encoded) - payload_offset:
        raise PrivateCodecErrorV1("private evidence codec rejected a record")
    payload = encoded[payload_offset:]
    if expected_record_type is PrivateEvidenceRecordTypeV1.FRAME_JPEG:
        if not 0 < len(payload) <= MAX_ENCODED_FRAME_BYTES_V1:
            raise PrivateCodecErrorV1(
                "private evidence codec rejected a record"
            )
    else:
        if not 0 < len(payload) <= MAX_AUXILIARY_CANONICAL_JSON_BYTES_V1:
            raise PrivateCodecErrorV1(
                "private evidence codec rejected a record"
            )
        _require_canonical_json_object_v1(payload)
    return payload


def _reject_json_constant_v1(value: str) -> Any:
    raise ValueError(value)


def _unique_json_object_v1(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _require_canonical_json_object_v1(payload: bytes) -> None:
    try:
        decoded_text = payload.decode("utf-8", errors="strict")
        decoded = json.loads(
            decoded_text,
            object_pairs_hook=_unique_json_object_v1,
            parse_constant=_reject_json_constant_v1,
        )
        if not isinstance(decoded, dict):
            raise TypeError("canonical auxiliary record must be an object")
        if canonical_json_bytes_v1(decoded) != payload:
            raise ValueError("auxiliary record is not canonical")
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise PrivateCodecErrorV1(
            "private evidence codec rejected a record"
        ) from None


__all__ = [
    "MAX_AUXILIARY_CANONICAL_JSON_BYTES_V1",
    "PRIVATE_CODEC_OVERHEAD_BYTES_V1",
    "PRIVATE_CODEC_SCHEMA_VERSION_V1",
    "PrivateCodecErrorV1",
    "PrivateEvidenceRecordTypeV1",
    "decode_private_record_v1",
    "encode_private_record_v1",
]

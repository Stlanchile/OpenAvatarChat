"""Strict canonical-value helpers shared by certificate-private contracts."""

from __future__ import annotations

import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

_SHA256_HEX_V1 = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json_bytes_v1(value: object) -> bytes:
    """Encode a typed object using the repository's deterministic JSON profile.

    The Base V1 specification requires deterministic canonical JSON but does
    not name RFC 8785/JCS. This profile therefore fixes UTF-8, sorted object
    keys, compact separators, finite JSON numbers, and caller-canonicalized
    semantic arrays.
    """

    _validate_canonical_value_v1(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _validate_canonical_value_v1(value: object) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON numbers must be finite")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            _validate_canonical_value_v1(item)
        return
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        for item in value:
            _validate_canonical_value_v1(item)
        return
    raise TypeError("unsupported canonical JSON value")


def require_text_v1(
    name: str,
    value: object,
    *,
    maximum_utf8_bytes: int = 512,
) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError(f"{name} must be valid UTF-8 text") from None
    if len(encoded) > maximum_utf8_bytes:
        raise ValueError(f"{name} exceeds its bounded size")
    return value


def require_optional_text_v1(
    name: str,
    value: object,
    *,
    maximum_utf8_bytes: int = 512,
) -> str | None:
    if value is None:
        return None
    return require_text_v1(
        name,
        value,
        maximum_utf8_bytes=maximum_utf8_bytes,
    )


def require_sha256_hex_v1(name: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_HEX_V1.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hex value")
    return value


def require_epoch_seconds_v1(name: str, value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} must be finite non-negative epoch seconds")
    return float(value)


def require_uuid7_v1(name: str, value: object) -> uuid.UUID:
    if (
        not isinstance(value, uuid.UUID)
        or value.version != 7
        or value.variant != uuid.RFC_4122
    ):
        raise ValueError(f"{name} must be an RFC 9562 UUIDv7")
    return value


def sorted_unique_text_v1(
    name: str,
    values: object,
    *,
    maximum_items: int = 256,
    maximum_item_utf8_bytes: int = 512,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be an immutable tuple")
    if len(values) > maximum_items:
        raise ValueError(f"{name} exceeds its bounded item count")
    normalized = tuple(
        require_text_v1(
            f"{name} item",
            item,
            maximum_utf8_bytes=maximum_item_utf8_bytes,
        )
        for item in values
    )
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{name} must not contain duplicates")
    return tuple(sorted(normalized))


def capture_epoch_object_v1(capture_epoch: Any) -> dict[str, object]:
    """Return the explicit canonical CaptureEpochV1 projection."""

    from certificate_capture.epochs import CaptureEpochV1

    if not isinstance(capture_epoch, CaptureEpochV1):
        raise TypeError("capture_epoch must be CaptureEpochV1")
    return {
        "capture_id": str(capture_epoch.capture_id),
        "capture_seq": capture_epoch.capture_seq,
        "session_epoch": {
            "generation": capture_epoch.session_epoch.generation,
            "session_instance_id": str(
                capture_epoch.session_epoch.session_instance_id
            ),
        },
    }


__all__ = [
    "canonical_json_bytes_v1",
    "capture_epoch_object_v1",
    "require_epoch_seconds_v1",
    "require_optional_text_v1",
    "require_sha256_hex_v1",
    "require_text_v1",
    "require_uuid7_v1",
    "sorted_unique_text_v1",
]

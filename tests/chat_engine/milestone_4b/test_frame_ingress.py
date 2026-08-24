from __future__ import annotations

import pytest

from certificate_capture.frame_ingress import validate_private_jpeg_v1
from certificate_capture.protocol import (
    MAX_ENCODED_FRAME_BYTES_V1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1


def _with_exact_metadata_size_v1(
    encoded: bytearray,
    target_size: int,
) -> bytearray:
    delta = target_size - len(encoded)
    if delta < 4:
        raise ValueError("target needs room for a JPEG metadata segment")
    segment_count = (delta + 65_536) // 65_537
    while 4 * segment_count > delta:
        segment_count -= 1
    payload_remaining = delta - 4 * segment_count
    segments = bytearray()
    for index in range(segment_count):
        slots_left = segment_count - index - 1
        payload_size = min(
            65_533,
            payload_remaining,
        )
        if payload_remaining - payload_size > 65_533 * slots_left:
            payload_size = payload_remaining - 65_533 * slots_left
        segments.extend(b"\xff\xfe")
        segments.extend((payload_size + 2).to_bytes(2, "big"))
        segments.extend(b"M" * payload_size)
        payload_remaining -= payload_size
    assert payload_remaining == 0
    output = encoded[:2] + segments + encoded[2:]
    assert len(output) == target_size
    return output


def _replace_sof_dimensions_v1(
    encoded: bytearray,
    *,
    width: int,
    height: int,
) -> bytearray:
    output = bytearray(encoded)
    for marker in (b"\xff\xc0", b"\xff\xc1", b"\xff\xc2"):
        offset = output.find(marker)
        if offset >= 0:
            output[offset + 5 : offset + 7] = height.to_bytes(2, "big")
            output[offset + 7 : offset + 9] = width.to_bytes(2, "big")
            return output
    raise AssertionError("synthetic JPEG has no supported SOF marker")


@pytest.mark.parametrize(
    ("width", "height"),
    (
        (1920, 1080),
        (1080, 1920),
        (640, 480),
        (480, 640),
    ),
)
def test_landscape_portrait_and_exact_dimension_boundaries(width, height):
    encoded = synthetic_jpeg_v1(width=width, height=height)

    validated = validate_private_jpeg_v1(encoded)

    assert validated.decoded_width == width
    assert validated.decoded_height == height
    assert validated.encoded_size == len(encoded)
    assert len(validated.sha256_digest) == 32


@pytest.mark.parametrize(
    ("width", "height"),
    (
        (1921, 1080),
        (1080, 1921),
        (1920, 1081),
        (1081, 1920),
        (1440, 1440),
    ),
)
def test_oversized_or_pathological_dimensions_are_rejected(width, height):
    encoded = synthetic_jpeg_v1(width=width, height=height)

    with pytest.raises(CaptureProtocolErrorV1) as rejected:
        validate_private_jpeg_v1(encoded)

    assert (
        rejected.value.reason
        is CaptureProtocolReasonV1.JPEG_DIMENSIONS_EXCEEDED
    )


def test_exact_two_mibibyte_encoded_boundary_is_accepted():
    encoded = _with_exact_metadata_size_v1(
        synthetic_jpeg_v1(),
        MAX_ENCODED_FRAME_BYTES_V1,
    )

    validated = validate_private_jpeg_v1(encoded)

    assert validated.encoded_size == MAX_ENCODED_FRAME_BYTES_V1


def test_over_two_mibibytes_is_rejected_before_decode():
    encoded = _with_exact_metadata_size_v1(
        synthetic_jpeg_v1(),
        MAX_ENCODED_FRAME_BYTES_V1 + 1,
    )

    with pytest.raises(CaptureProtocolErrorV1) as rejected:
        validate_private_jpeg_v1(encoded)

    assert rejected.value.reason is CaptureProtocolReasonV1.JPEG_INVALID


@pytest.mark.parametrize(
    "encoded",
    (
        bytearray(b"not-a-jpeg"),
        bytearray(b"\xff\xd8\xff\xd9"),
        synthetic_jpeg_v1()[:-2],
        synthetic_jpeg_v1() + b"trailing-container-data",
    ),
)
def test_non_jpeg_malformed_truncated_and_trailing_content_are_rejected(
    encoded,
):
    with pytest.raises(CaptureProtocolErrorV1) as rejected:
        validate_private_jpeg_v1(bytearray(encoded))

    assert rejected.value.reason is CaptureProtocolReasonV1.JPEG_INVALID


def test_decompression_bomb_header_is_rejected_without_pixel_allocation():
    encoded = _replace_sof_dimensions_v1(
        synthetic_jpeg_v1(),
        width=50_000,
        height=50_000,
    )

    with pytest.raises(CaptureProtocolErrorV1) as rejected:
        validate_private_jpeg_v1(encoded)

    assert rejected.value.reason in {
        CaptureProtocolReasonV1.JPEG_INVALID,
        CaptureProtocolReasonV1.JPEG_DIMENSIONS_EXCEEDED,
    }


def test_orientation_is_applied_but_other_metadata_is_discarded():
    encoded = synthetic_jpeg_v1(
        width=120,
        height=80,
        orientation=6,
    )
    metadata_heavy = _with_exact_metadata_size_v1(encoded, 256 * 1024)

    validated = validate_private_jpeg_v1(metadata_heavy)

    assert validated.decoded_width == 80
    assert validated.decoded_height == 120
    assert not hasattr(validated, "exif")
    assert not hasattr(validated, "comment")


def test_invalid_orientation_metadata_fails_closed():
    encoded = synthetic_jpeg_v1(
        width=120,
        height=80,
        orientation=9,
    )

    with pytest.raises(CaptureProtocolErrorV1) as rejected:
        validate_private_jpeg_v1(encoded)

    assert rejected.value.reason is CaptureProtocolReasonV1.JPEG_INVALID

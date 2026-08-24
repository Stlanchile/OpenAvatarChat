"""Bounded private JPEG request ingestion and strict decode validation."""

from __future__ import annotations

import asyncio
import hashlib
import io
import warnings
from collections.abc import Callable

from fastapi import Request
from PIL import Image, ImageFile, ImageOps, UnidentifiedImageError
from starlette.requests import ClientDisconnect

from certificate_capture.protocol import (
    FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1,
    MAX_DECODED_FRAME_LONG_EDGE_V1,
    MAX_DECODED_FRAME_PIXELS_V1,
    MAX_DECODED_FRAME_SHORT_EDGE_V1,
    MAX_ENCODED_FRAME_BYTES_V1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
    ValidatedJpegFrameV1,
)


def validate_private_jpeg_headers_v1(request: Request) -> None:
    content_types = request.headers.getlist("Content-Type")
    if (
        len(content_types) != 1
        or content_types[0].partition(";")[0].strip().casefold()
        != "image/jpeg"
    ):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_REQUIRED
        )

    content_lengths = request.headers.getlist("Content-Length")
    if len(content_lengths) > 1:
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.INVALID_REQUEST
        )
    if not content_lengths:
        return
    raw_length = content_lengths[0]
    if (
        not raw_length
        or len(raw_length) > 10
        or not raw_length.isascii()
        or not raw_length.isdecimal()
    ):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.INVALID_REQUEST
        )
    content_length = int(raw_length, 10)
    if content_length > MAX_ENCODED_FRAME_BYTES_V1:
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.FRAME_TOO_LARGE
        )


async def read_bounded_private_jpeg_v1(
    request: Request,
    *,
    cancelled_v1: Callable[[], bool] | None = None,
) -> bytearray:
    """Read at most 2 MiB and release partial bytes on every failure."""

    body = bytearray()
    try:
        async with asyncio.timeout(FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1):
            async for chunk in request.stream():
                if cancelled_v1 is not None and cancelled_v1():
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                    )
                if not isinstance(chunk, bytes):
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.FRAME_BODY_UNAVAILABLE
                    )
                if len(body) + len(chunk) > MAX_ENCODED_FRAME_BYTES_V1:
                    raise CaptureProtocolErrorV1(
                        CaptureProtocolReasonV1.FRAME_TOO_LARGE
                    )
                body.extend(chunk)
            if cancelled_v1 is not None and cancelled_v1():
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
    except asyncio.CancelledError:
        body.clear()
        raise
    except CaptureProtocolErrorV1:
        body.clear()
        raise
    except (TimeoutError, ClientDisconnect):
        body.clear()
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.FRAME_BODY_UNAVAILABLE
        ) from None
    except Exception:  # noqa: BLE001 - value-free transport failure
        body.clear()
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.FRAME_BODY_UNAVAILABLE
        ) from None
    if not body:
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_INVALID
        )
    return body


def validate_private_jpeg_v1(
    encoded_frame: bytearray,
) -> ValidatedJpegFrameV1:
    """Strictly decode a bounded JPEG and retain only private metadata."""

    if (
        not isinstance(encoded_frame, bytearray)
        or not encoded_frame
        or len(encoded_frame) > MAX_ENCODED_FRAME_BYTES_V1
    ):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_INVALID
        )
    if not _strict_jpeg_container_v1(encoded_frame):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_INVALID
        )
    # Fail closed if another component globally enabled Pillow's permissive
    # truncated-image mode. Milestone 4B never mutates this process-global flag.
    if ImageFile.LOAD_TRUNCATED_IMAGES:
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_INVALID
        )

    width = 0
    height = 0
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(
                io.BytesIO(encoded_frame),
                formats=("JPEG",),
            ) as image:
                if image.format != "JPEG":
                    raise ValueError
                _validate_dimensions_v1(*image.size)
                orientation = image.getexif().get(274, 1)
                if (
                    isinstance(orientation, bool)
                    or not isinstance(orientation, int)
                    or orientation not in range(1, 9)
                ):
                    raise ValueError
                image.verify()

            with Image.open(
                io.BytesIO(encoded_frame),
                formats=("JPEG",),
            ) as decoded:
                if decoded.format != "JPEG":
                    raise ValueError
                _validate_dimensions_v1(*decoded.size)
                if decoded.mode not in {"L", "RGB", "CMYK"}:
                    raise ValueError
                decoded.load()
                ImageOps.exif_transpose(decoded, in_place=True)
                width, height = decoded.size
                _validate_dimensions_v1(width, height)
    except CaptureProtocolErrorV1:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        SyntaxError,
        ValueError,
        OSError,
        EOFError,
        TypeError,
        OverflowError,
    ):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_INVALID
        ) from None
    except Exception:  # noqa: BLE001 - decoder errors stay input-independent
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_INVALID
        ) from None

    return ValidatedJpegFrameV1(
        encoded_size=len(encoded_frame),
        decoded_width=width,
        decoded_height=height,
        sha256_digest=hashlib.sha256(encoded_frame).digest(),
    )


def _validate_dimensions_v1(width: int, height: int) -> None:
    if (
        isinstance(width, bool)
        or isinstance(height, bool)
        or not isinstance(width, int)
        or not isinstance(height, int)
        or width <= 0
        or height <= 0
    ):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_DIMENSIONS_EXCEEDED
        )
    long_edge = max(width, height)
    short_edge = min(width, height)
    if (
        long_edge > MAX_DECODED_FRAME_LONG_EDGE_V1
        or short_edge > MAX_DECODED_FRAME_SHORT_EDGE_V1
        or width * height > MAX_DECODED_FRAME_PIXELS_V1
    ):
        raise CaptureProtocolErrorV1(
            CaptureProtocolReasonV1.JPEG_DIMENSIONS_EXCEEDED
        )


def _strict_jpeg_container_v1(data: bytearray) -> bool:
    """Require one structurally complete JPEG ending exactly at EOI."""

    size = len(data)
    if size < 4 or data[0:2] != b"\xff\xd8":
        return False
    offset = 2
    saw_scan = False
    in_scan = False

    while offset < size:
        if in_scan:
            while offset < size:
                if data[offset] != 0xFF:
                    offset += 1
                    continue
                marker_start = offset
                offset += 1
                while offset < size and data[offset] == 0xFF:
                    offset += 1
                if offset >= size:
                    return False
                marker = data[offset]
                if marker == 0x00:
                    offset += 1
                    continue
                if 0xD0 <= marker <= 0xD7:
                    offset += 1
                    continue
                offset = marker_start
                in_scan = False
                break
            if in_scan:
                return False

        if offset >= size or data[offset] != 0xFF:
            return False
        offset += 1
        while offset < size and data[offset] == 0xFF:
            offset += 1
        if offset >= size:
            return False
        marker = data[offset]
        offset += 1

        if marker == 0xD9:
            return saw_scan and offset == size
        if marker in {0x00, 0xD8}:
            return False
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > size:
            return False
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2:
            return False
        segment_end = offset + segment_length
        if segment_end > size:
            return False
        if marker == 0xDA:
            saw_scan = True
            in_scan = True
        offset = segment_end
    return False


__all__ = [
    "FRAME_UPLOAD_READ_TIMEOUT_SECONDS_V1",
    "ValidatedJpegFrameV1",
    "read_bounded_private_jpeg_v1",
    "validate_private_jpeg_headers_v1",
    "validate_private_jpeg_v1",
]

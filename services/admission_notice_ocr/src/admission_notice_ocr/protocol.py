from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = 1
REQUEST_MAGIC = b"ANLQ"
RESPONSE_MAGIC = b"ANLR"
MAX_HEADER_BYTES = 8 * 1024
MAX_JPEG_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOTAL_REQUEST_BYTES = MAX_HEADER_BYTES + 3 * (4 + MAX_JPEG_BYTES)
MAX_FRAMES = 3
MAX_LONG_EDGE = 1_920
MAX_SHORT_EDGE = 1_080
MAX_PIXELS = 2_073_600
REQUEST_READ_TIMEOUT_SECONDS = 5.0

FRAME_PREFIX = struct.Struct(">I")
MESSAGE_PREFIX = struct.Struct(">4sBI")


class ErrorCode(str, Enum):
    OCR_SERVICE_UNAVAILABLE = "OCR_SERVICE_UNAVAILABLE"
    OCR_PROTOCOL_ERROR = "OCR_PROTOCOL_ERROR"
    OCR_TIMEOUT = "OCR_TIMEOUT"
    OCR_RUNTIME_ERROR = "OCR_RUNTIME_ERROR"
    OCR_RESULT_INVALID = "OCR_RESULT_INVALID"


class ProtocolError(Exception):
    def __init__(self, code: ErrorCode = ErrorCode.OCR_PROTOCOL_ERROR):
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class FrameRequest:
    frame_index: int
    encoded_size: int
    logical_width: int
    logical_height: int
    exif_orientation: int
    jpeg_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class Request:
    operation: str
    frames: tuple[FrameRequest, ...] = ()


def _reject_json_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _exact_keys(value: dict[str, Any], expected: set[str]) -> bool:
    return set(value) == expected and all(type(key) is str for key in value)


def _decode_header(payload: bytes) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ProtocolError() from None
    if type(value) is not dict:
        raise ProtocolError()
    return value


def _strict_int(value: Any, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtocolError()
    return value


def _parse_ocr_metadata(header: dict[str, Any]) -> tuple[dict[str, int], ...]:
    if not _exact_keys(
        header,
        {"schema_version", "operation", "frame_count", "frames"},
    ):
        raise ProtocolError()
    frame_count = _strict_int(header["frame_count"], minimum=1, maximum=MAX_FRAMES)
    frame_values = header["frames"]
    if type(frame_values) is not list or len(frame_values) != frame_count:
        raise ProtocolError()

    metadata: list[dict[str, int]] = []
    try:
        for expected_index, value in enumerate(frame_values, start=1):
            if type(value) is not dict or not _exact_keys(
                value,
                {
                    "frame_index",
                    "encoded_size",
                    "logical_width",
                    "logical_height",
                    "exif_orientation",
                },
            ):
                raise ProtocolError()
            frame_index = _strict_int(
                value["frame_index"], minimum=1, maximum=MAX_FRAMES
            )
            if frame_index != expected_index:
                raise ProtocolError()
            encoded_size = _strict_int(
                value["encoded_size"], minimum=1, maximum=MAX_JPEG_BYTES
            )
            logical_width = _strict_int(
                value["logical_width"], minimum=1, maximum=MAX_LONG_EDGE
            )
            logical_height = _strict_int(
                value["logical_height"], minimum=1, maximum=MAX_LONG_EDGE
            )
            if (
                max(logical_width, logical_height) > MAX_LONG_EDGE
                or min(logical_width, logical_height) > MAX_SHORT_EDGE
                or logical_width * logical_height > MAX_PIXELS
            ):
                raise ProtocolError()
            metadata.append(
                {
                    "frame_index": frame_index,
                    "encoded_size": encoded_size,
                    "logical_width": logical_width,
                    "logical_height": logical_height,
                    "exif_orientation": _strict_int(
                        value["exif_orientation"], minimum=1, maximum=8
                    ),
                }
            )
    except Exception:
        metadata.clear()
        raise
    return tuple(metadata)


async def read_request(reader: asyncio.StreamReader) -> Request:
    try:
        async with asyncio.timeout(REQUEST_READ_TIMEOUT_SECONDS):
            prefix = await reader.readexactly(MESSAGE_PREFIX.size)
            magic, version, header_length = MESSAGE_PREFIX.unpack(prefix)
            if (
                magic != REQUEST_MAGIC
                or version != SCHEMA_VERSION
                or not 1 <= header_length <= MAX_HEADER_BYTES
            ):
                raise ProtocolError()
            header = _decode_header(await reader.readexactly(header_length))
            if (
                header.get("schema_version") != SCHEMA_VERSION
                or type(header.get("schema_version")) is not int
            ):
                raise ProtocolError()

            operation = header.get("operation")
            if operation == "ping":
                if not _exact_keys(header, {"schema_version", "operation"}):
                    raise ProtocolError()
                if await reader.read(1):
                    raise ProtocolError()
                return Request(operation="ping")
            if operation != "ocr":
                raise ProtocolError()

            metadata = _parse_ocr_metadata(header)
            total_bytes = header_length
            frames: list[FrameRequest] = []
            try:
                for item in metadata:
                    encoded_size = FRAME_PREFIX.unpack(
                        await reader.readexactly(FRAME_PREFIX.size)
                    )[0]
                    if encoded_size != item["encoded_size"]:
                        raise ProtocolError()
                    total_bytes += FRAME_PREFIX.size + encoded_size
                    if total_bytes > MAX_TOTAL_REQUEST_BYTES:
                        raise ProtocolError()
                    jpeg_bytes = await reader.readexactly(encoded_size)
                    frames.append(FrameRequest(jpeg_bytes=jpeg_bytes, **item))
                if await reader.read(1):
                    raise ProtocolError()
                return Request(operation="ocr", frames=tuple(frames))
            except Exception:
                frames.clear()
                raise
    except ProtocolError:
        raise
    except (asyncio.IncompleteReadError, TimeoutError):
        raise ProtocolError() from None


def _encode_response(value: dict[str, Any]) -> bytes:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ProtocolError(ErrorCode.OCR_RESULT_INVALID) from None
    if not 1 <= len(payload) <= MAX_RESPONSE_BYTES:
        raise ProtocolError(ErrorCode.OCR_RESULT_INVALID)
    return MESSAGE_PREFIX.pack(RESPONSE_MAGIC, SCHEMA_VERSION, len(payload)) + payload


def encode_error(code: ErrorCode) -> bytes:
    return _encode_response(
        {
            "error_code": code.value,
            "schema_version": SCHEMA_VERSION,
            "status": "error",
        }
    )


def encode_ping(runtime_identity: dict[str, Any]) -> bytes:
    return _encode_response(
        {
            "runtime_identity": runtime_identity,
            "schema_version": SCHEMA_VERSION,
            "status": "ok",
        }
    )


def encode_ocr(frames: list[dict[str, Any]]) -> bytes:
    try:
        return _encode_response(
            {
                "frames": frames,
                "schema_version": SCHEMA_VERSION,
                "status": "ok",
            }
        )
    except ProtocolError as error:
        if error.code is ErrorCode.OCR_RESULT_INVALID:
            return encode_error(ErrorCode.OCR_RESULT_INVALID)
        raise

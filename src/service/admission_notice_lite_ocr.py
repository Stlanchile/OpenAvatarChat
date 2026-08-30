from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from loguru import logger

from service.admission_notice_lite_contracts import (
    OcrBatchLiteV1,
    OcrFrameLiteV1,
    OcrRuntimeIdentityLiteV1,
    OcrSpanLiteV1,
    RecognitionJobContextLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.admission_notice_lite_ocr_qualification import (
    QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1,
)
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1 = 1
MAX_OCR_REQUEST_METADATA_BYTES_LITE_V1 = 8 * 1024
MAX_OCR_RESPONSE_BYTES_LITE_V1 = 64 * 1024
MAX_OCR_REQUEST_JPEG_BYTES_LITE_V1 = 2 * 1024 * 1024
MAX_OCR_REQUEST_TOTAL_BYTES_LITE_V1 = MAX_OCR_REQUEST_METADATA_BYTES_LITE_V1 + 3 * (
    4 + MAX_OCR_REQUEST_JPEG_BYTES_LITE_V1
)

OCR_REQUEST_MAGIC_LITE_V1 = b"ANLQ"
OCR_RESPONSE_MAGIC_LITE_V1 = b"ANLR"
_FRAME_PREFIX = struct.Struct(">I")
_MESSAGE_PREFIX = struct.Struct(">4sBI")

QUALIFIED_OCR_BACKEND_LITE_V1 = "paddle_static"
QUALIFIED_OCR_DEVICE_LITE_V1 = "cpu"
QUALIFIED_OCR_THREAD_COUNT_LITE_V1 = 2
QUALIFIED_PADDLE_VERSION_LITE_V1 = "3.3.0"
QUALIFIED_PADDLEOCR_VERSION_LITE_V1 = "3.7.0"
QUALIFIED_PADDLEX_VERSION_LITE_V1 = "3.7.2"


class OcrFailureCodeLiteV1(str, Enum):
    OCR_SERVICE_UNAVAILABLE = "OCR_SERVICE_UNAVAILABLE"
    OCR_PROTOCOL_ERROR = "OCR_PROTOCOL_ERROR"
    OCR_TIMEOUT = "OCR_TIMEOUT"
    OCR_RUNTIME_ERROR = "OCR_RUNTIME_ERROR"
    OCR_RESULT_INVALID = "OCR_RESULT_INVALID"


class AdmissionNoticeOcrErrorLiteV1(Exception):
    def __init__(self, code: OcrFailureCodeLiteV1):
        super().__init__(code.value)
        self.code = code


def _error(code: OcrFailureCodeLiteV1) -> AdmissionNoticeOcrErrorLiteV1:
    return AdmissionNoticeOcrErrorLiteV1(code)


def _reject_json_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def _decode_json_object(payload: bytes) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR) from None
    if type(value) is not dict:
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    return value


def _has_exact_keys(value: dict[str, Any], keys: set[str]) -> bool:
    return set(value) == keys and all(type(key) is str for key in value)


def _encode_header(header: dict[str, Any]) -> bytes:
    encoded = json.dumps(
        header,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if not 1 <= len(encoded) <= MAX_OCR_REQUEST_METADATA_BYTES_LITE_V1:
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    return encoded


def _validate_request_frames(
    frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
) -> None:
    if (
        type(frames) is not tuple
        or not 1 <= len(frames) <= 3
        or any(not isinstance(frame, ValidatedAdmissionFrameLiteV1) for frame in frames)
        or tuple(frame.frame_index for frame in frames)
        != tuple(range(1, len(frames) + 1))
        or any(
            frame.encoded_size > MAX_OCR_REQUEST_JPEG_BYTES_LITE_V1 for frame in frames
        )
    ):
        raise ValueError("OCR client requires a contiguous validated frame tuple")


def _encode_ping_request() -> bytes:
    header = _encode_header(
        {
            "operation": "ping",
            "schema_version": OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1,
        }
    )
    return (
        _MESSAGE_PREFIX.pack(
            OCR_REQUEST_MAGIC_LITE_V1,
            OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1,
            len(header),
        )
        + header
    )


def _encode_ocr_request(
    frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
) -> bytes:
    _validate_request_frames(frames)
    header = _encode_header(
        {
            "frame_count": len(frames),
            "frames": [
                {
                    "encoded_size": frame.encoded_size,
                    "exif_orientation": frame.exif_orientation,
                    "frame_index": frame.frame_index,
                    "logical_height": frame.height,
                    "logical_width": frame.width,
                }
                for frame in frames
            ],
            "operation": "ocr",
            "schema_version": OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1,
        }
    )
    request = bytearray(
        _MESSAGE_PREFIX.pack(
            OCR_REQUEST_MAGIC_LITE_V1,
            OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1,
            len(header),
        )
    )
    request.extend(header)
    for frame in frames:
        request.extend(_FRAME_PREFIX.pack(frame.encoded_size))
        request.extend(frame.jpeg_bytes)
    if len(request) > _MESSAGE_PREFIX.size + MAX_OCR_REQUEST_TOTAL_BYTES_LITE_V1:
        request.clear()
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    encoded_request = bytes(request)
    request.clear()
    return encoded_request


def _parse_runtime_identity(value: Any) -> OcrRuntimeIdentityLiteV1:
    keys = {
        "backend",
        "device",
        "model_manifest_sha256",
        "paddle_version",
        "paddleocr_version",
        "paddlex_version",
        "thread_count",
    }
    if type(value) is not dict or not _has_exact_keys(value, keys):
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)
    try:
        return OcrRuntimeIdentityLiteV1(
            backend=value["backend"],
            device=value["device"],
            thread_count=value["thread_count"],
            paddle_version=value["paddle_version"],
            paddleocr_version=value["paddleocr_version"],
            paddlex_version=value["paddlex_version"],
            model_manifest_sha256=value["model_manifest_sha256"],
        )
    except (TypeError, ValueError):
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID) from None


def _parse_error_response(value: dict[str, Any]) -> None:
    if not _has_exact_keys(value, {"schema_version", "status", "error_code"}):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    try:
        code = OcrFailureCodeLiteV1(value["error_code"])
    except (TypeError, ValueError):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR) from None
    raise _error(code)


def _parse_ping_response(payload: bytes) -> OcrRuntimeIdentityLiteV1:
    value = _decode_json_object(payload)
    if (
        value.get("schema_version") != OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1
        or type(value.get("schema_version")) is not int
    ):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    if value.get("status") == "error":
        _parse_error_response(value)
    if (
        not _has_exact_keys(value, {"schema_version", "status", "runtime_identity"})
        or value["status"] != "ok"
    ):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    return _parse_runtime_identity(value["runtime_identity"])


def _parse_span(value: Any) -> OcrSpanLiteV1:
    if type(value) is not dict or not _has_exact_keys(
        value, {"text", "polygon", "score"}
    ):
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)
    polygon_value = value["polygon"]
    if type(polygon_value) is not list or len(polygon_value) != 4:
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)
    polygon_points: list[tuple[float, float]] = []
    try:
        for point in polygon_value:
            if type(point) is not list or len(point) != 2:
                raise ValueError
            if any(
                isinstance(coordinate, bool) or not isinstance(coordinate, (int, float))
                for coordinate in point
            ):
                raise ValueError
            polygon_points.append((float(point[0]), float(point[1])))
        if isinstance(value["score"], bool) or not isinstance(
            value["score"], (int, float)
        ):
            raise ValueError
        polygon = tuple(polygon_points)
        span = OcrSpanLiteV1(
            text=value["text"],
            polygon=polygon,
            score=float(value["score"]),
        )
    except (TypeError, ValueError, OverflowError):
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID) from None
    finally:
        polygon_points.clear()
    return span


def _parse_ocr_response(payload: bytes, expected_frame_count: int) -> OcrBatchLiteV1:
    value = _decode_json_object(payload)
    if (
        value.get("schema_version") != OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1
        or type(value.get("schema_version")) is not int
    ):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    if value.get("status") == "error":
        _parse_error_response(value)
    if (
        not _has_exact_keys(value, {"schema_version", "status", "frames"})
        or value["status"] != "ok"
        or type(value["frames"]) is not list
        or len(value["frames"]) != expected_frame_count
    ):
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)

    parsed_frames: list[OcrFrameLiteV1] = []
    try:
        for frame_value in value["frames"]:
            if type(frame_value) is not dict or not _has_exact_keys(
                frame_value, {"frame_index", "spans"}
            ):
                raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)
            spans_value = frame_value["spans"]
            if type(spans_value) is not list:
                raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)
            spans = tuple(_parse_span(span_value) for span_value in spans_value)
            parsed_frames.append(
                OcrFrameLiteV1(
                    frame_index=frame_value["frame_index"],
                    spans=spans,
                )
            )
        batch = OcrBatchLiteV1(frames=tuple(parsed_frames))
    except AdmissionNoticeOcrErrorLiteV1:
        raise
    except (TypeError, ValueError):
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID) from None
    finally:
        parsed_frames.clear()
    if len(batch.frames) != expected_frame_count:
        raise _error(OcrFailureCodeLiteV1.OCR_RESULT_INVALID)
    return batch


def _parse_response_prefix(prefix: bytes) -> int:
    if len(prefix) != _MESSAGE_PREFIX.size:
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    magic, version, response_length = _MESSAGE_PREFIX.unpack(prefix)
    if (
        magic != OCR_RESPONSE_MAGIC_LITE_V1
        or version != OCR_PROTOCOL_SCHEMA_VERSION_LITE_V1
        or not 1 <= response_length <= MAX_OCR_RESPONSE_BYTES_LITE_V1
    ):
        raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
    return response_length


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


@dataclass(frozen=True, slots=True)
class AdmissionNoticeOcrClientLiteV1:
    socket_path: str
    connect_timeout_seconds: float
    timeout_seconds: float

    async def ping(self) -> OcrRuntimeIdentityLiteV1:
        payload = await self._exchange(
            _encode_ping_request(),
            timeout_seconds=min(self.timeout_seconds, 2.0),
        )
        return _parse_ping_response(payload)

    def ping_sync(self) -> OcrRuntimeIdentityLiteV1:
        request = _encode_ping_request()
        timeout = min(self.timeout_seconds, 2.0)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.connect_timeout_seconds)
                connection.connect(self.socket_path)
                connection.settimeout(timeout)
                connection.sendall(request)
                connection.shutdown(socket.SHUT_WR)
                prefix = self._recv_exact(connection, _MESSAGE_PREFIX.size)
                response_length = _parse_response_prefix(prefix)
                payload = self._recv_exact(connection, response_length)
                if connection.recv(1):
                    raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
        except AdmissionNoticeOcrErrorLiteV1:
            raise
        except TimeoutError:
            raise _error(OcrFailureCodeLiteV1.OCR_TIMEOUT) from None
        except OSError:
            raise _error(OcrFailureCodeLiteV1.OCR_SERVICE_UNAVAILABLE) from None
        return _parse_ping_response(payload)

    async def recognize(
        self,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
        *,
        timeout_seconds: float | None = None,
    ) -> OcrBatchLiteV1:
        request = _encode_ocr_request(frames)
        payload = await self._exchange(
            request,
            timeout_seconds=(
                self.timeout_seconds if timeout_seconds is None else timeout_seconds
            ),
        )
        return _parse_ocr_response(payload, len(frames))

    async def _exchange(self, request: bytes, *, timeout_seconds: float) -> bytes:
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(timeout_seconds):
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_unix_connection(self.socket_path),
                        timeout=self.connect_timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    raise _error(OcrFailureCodeLiteV1.OCR_TIMEOUT) from None
                except OSError:
                    raise _error(OcrFailureCodeLiteV1.OCR_SERVICE_UNAVAILABLE) from None

                writer.write(request)
                await writer.drain()
                if not writer.can_write_eof():
                    raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
                writer.write_eof()

                prefix = await reader.readexactly(_MESSAGE_PREFIX.size)
                response_length = _parse_response_prefix(prefix)
                payload = await reader.readexactly(response_length)
                if await reader.read(1):
                    raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
                return payload
        except asyncio.CancelledError:
            raise
        except AdmissionNoticeOcrErrorLiteV1:
            raise
        except asyncio.TimeoutError:
            raise _error(OcrFailureCodeLiteV1.OCR_TIMEOUT) from None
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR) from None
        finally:
            await _close_writer(writer)

    @staticmethod
    def _recv_exact(connection: socket.socket, length: int) -> bytes:
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = connection.recv(remaining)
            if not chunk:
                raise _error(OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


@dataclass(slots=True)
class AdmissionNoticeOcrProcessorLiteV1:
    client: AdmissionNoticeOcrClientLiteV1
    _available: bool = field(default=True, init=False, repr=False)
    _readiness_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock,
        init=False,
        repr=False,
    )

    async def prepare_for_ingestion(self) -> bool:
        """Re-ping only after a transport failure marked the sidecar unavailable."""

        if self._available:
            return True
        async with self._readiness_lock:
            if self._available:
                return True
            try:
                identity = await self.client.ping()
            except AdmissionNoticeOcrErrorLiteV1 as error:
                logger.warning(
                    "Admission Notice Lite OCR readiness failed reason={}",
                    error.code.value,
                )
                return False
            self._available = _identity_is_qualified(identity)
            if not self._available:
                logger.warning(
                    "Admission Notice Lite OCR readiness failed "
                    "reason=OCR_RUNTIME_IDENTITY_MISMATCH"
                )
            return self._available

    async def process(
        self,
        context: RecognitionJobContextLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> None:
        if context.cancel_event.is_set():
            raise asyncio.CancelledError
        remaining = context.expires_at_monotonic - time.monotonic()
        if remaining <= 0:
            raise asyncio.CancelledError

        started_at = time.monotonic()
        try:
            batch = await self.client.recognize(
                frames,
                timeout_seconds=min(self.client.timeout_seconds, remaining),
            )
        except AdmissionNoticeOcrErrorLiteV1 as error:
            if error.code in {
                OcrFailureCodeLiteV1.OCR_SERVICE_UNAVAILABLE,
                OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR,
                OcrFailureCodeLiteV1.OCR_TIMEOUT,
            }:
                self._available = False
            logger.warning(
                "Admission Notice Lite OCR failed recognition_id={} reason={}",
                context.recognition_id,
                error.code.value,
            )
            raise

        if context.cancel_event.is_set() or time.monotonic() >= (
            context.expires_at_monotonic
        ):
            del batch
            raise asyncio.CancelledError
        del batch
        logger.info(
            "Admission Notice Lite OCR completed recognition_id={} "
            "frame_count={} duration_ms={:.1f}",
            context.recognition_id,
            len(frames),
            (time.monotonic() - started_at) * 1000.0,
        )


def _identity_is_qualified(identity: OcrRuntimeIdentityLiteV1) -> bool:
    expected_manifest = QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1
    return expected_manifest is not None and identity == OcrRuntimeIdentityLiteV1(
        backend=QUALIFIED_OCR_BACKEND_LITE_V1,
        device=QUALIFIED_OCR_DEVICE_LITE_V1,
        thread_count=QUALIFIED_OCR_THREAD_COUNT_LITE_V1,
        paddle_version=QUALIFIED_PADDLE_VERSION_LITE_V1,
        paddleocr_version=QUALIFIED_PADDLEOCR_VERSION_LITE_V1,
        paddlex_version=QUALIFIED_PADDLEX_VERSION_LITE_V1,
        model_manifest_sha256=expected_manifest,
    )


def build_qualified_admission_notice_ocr_processor_lite_v1(
    config: AdmissionNoticeLiteFeatureConfigV1,
) -> AdmissionNoticeOcrProcessorLiteV1 | None:
    if not config.enabled:
        return None
    if QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 is None:
        logger.error(
            "Admission Notice Lite OCR unavailable reason=OCR_RUNTIME_NOT_QUALIFIED"
        )
        return None

    client = AdmissionNoticeOcrClientLiteV1(
        socket_path=config.ocr_socket_path,
        connect_timeout_seconds=config.ocr_connect_timeout_seconds,
        timeout_seconds=config.ocr_timeout_seconds,
    )
    try:
        identity = client.ping_sync()
    except AdmissionNoticeOcrErrorLiteV1 as error:
        logger.error(
            "Admission Notice Lite OCR unavailable reason={}",
            error.code.value,
        )
        return None
    if not _identity_is_qualified(identity):
        logger.error(
            "Admission Notice Lite OCR unavailable reason=OCR_RUNTIME_IDENTITY_MISMATCH"
        )
        return None
    return AdmissionNoticeOcrProcessorLiteV1(client=client)

from __future__ import annotations

import io
import re
import warnings
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Request
from PIL import Image
from python_multipart.exceptions import FormParserError, MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import ClientDisconnect

from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    RecognitionErrorReasonLiteV1,
    ValidatedAdmissionFrameLiteV1,
)

MAX_ENCODED_FRAME_BYTES_LITE_V1 = 2 * 1024 * 1024
MAX_ADMISSION_FRAMES_LITE_V1 = 3
MAX_MULTIPART_OVERHEAD_BYTES_LITE_V1 = 64 * 1024
MAX_MULTIPART_BODY_BYTES_LITE_V1 = (
    MAX_ADMISSION_FRAMES_LITE_V1 * MAX_ENCODED_FRAME_BYTES_LITE_V1
    + MAX_MULTIPART_OVERHEAD_BYTES_LITE_V1
)
MAX_MULTIPART_PART_HEADER_BYTES_LITE_V1 = 16 * 1024

_CONTENT_TYPE_HEADER_LIMIT = 512
_CONTENT_LENGTH_HEADER_DIGIT_LIMIT = 16
_PARSER_FEED_CHUNK_BYTES = 64 * 1024
_JPEG_MEDIA_TYPE = b"image/jpeg"
_EXIF_ORIENTATION_TAG = 274
_ORIENTATIONS_THAT_SWAP_AXES = frozenset((5, 6, 7, 8))
_BOUNDARY_PATTERN = re.compile(rb"[0-9A-Za-z'()+_,./:=? -]{1,70}")
_CONTENT_LENGTH_PATTERN = re.compile(r"[0-9]+")
_FRAME_FIELD_PATTERN = re.compile(rb"frame_([0-9]+)")
_FRAME_INDEX_BY_FIELD = {
    b"frame_1": 1,
    b"frame_2": 2,
    b"frame_3": 3,
}


def _mime_parameters_are_unique(value: str | bytes) -> bool:
    if isinstance(value, str):
        try:
            raw_value = value.encode("latin-1")
        except UnicodeEncodeError:
            return False
    else:
        raw_value = value

    segments: list[bytes] = []
    segment_start = 0
    in_quote = False
    escaped = False
    for index, byte in enumerate(raw_value):
        if in_quote and escaped:
            escaped = False
        elif in_quote and byte == ord("\\"):
            escaped = True
        elif byte == ord('"'):
            in_quote = not in_quote
        elif byte == ord(";") and not in_quote:
            segments.append(raw_value[segment_start:index])
            segment_start = index + 1
    if in_quote or escaped:
        return False
    segments.append(raw_value[segment_start:])

    parameter_names: set[bytes] = set()
    for segment in segments[1:]:
        name, separator, _ = segment.strip().partition(b"=")
        normalized_name = name.strip().lower()
        if not separator or not normalized_name or normalized_name in parameter_names:
            return False
        parameter_names.add(normalized_name)
    return True


@dataclass(frozen=True, slots=True)
class AdmissionMultipartRequestSpecLiteV1:
    boundary: bytes
    declared_content_length: int | None


def _error(reason: RecognitionErrorReasonLiteV1) -> AdmissionNoticeLiteError:
    return AdmissionNoticeLiteError(reason)


def parse_admission_multipart_request_spec(
    request: Request,
) -> AdmissionMultipartRequestSpecLiteV1:
    if request.headers.getlist("transfer-encoding"):
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)

    content_length_values = request.headers.getlist("content-length")
    if len(content_length_values) > 1:
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)

    declared_content_length: int | None = None
    if content_length_values:
        raw_content_length = content_length_values[0]
        if (
            len(raw_content_length) > _CONTENT_LENGTH_HEADER_DIGIT_LIMIT
            or _CONTENT_LENGTH_PATTERN.fullmatch(raw_content_length) is None
        ):
            raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)
        significant_length = raw_content_length.lstrip("0") or "0"
        if len(significant_length) > len(str(MAX_MULTIPART_BODY_BYTES_LITE_V1)):
            raise _error(RecognitionErrorReasonLiteV1.IMAGE_TOO_LARGE)
        declared_content_length = int(significant_length)
        if declared_content_length > MAX_MULTIPART_BODY_BYTES_LITE_V1:
            raise _error(RecognitionErrorReasonLiteV1.IMAGE_TOO_LARGE)

    content_type_values = request.headers.getlist("content-type")
    if len(content_type_values) != 1:
        raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE)
    raw_content_type = content_type_values[0]
    if len(raw_content_type.encode("latin-1")) > _CONTENT_TYPE_HEADER_LIMIT:
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)
    if not _mime_parameters_are_unique(raw_content_type):
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)

    try:
        media_type, options = parse_options_header(raw_content_type)
    except (UnicodeError, ValueError):
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST) from None
    if media_type != b"multipart/form-data":
        raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE)
    if set(options) != {b"boundary"}:
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)

    boundary = options[b"boundary"]
    if _BOUNDARY_PATTERN.fullmatch(boundary) is None or boundary.endswith(b" "):
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)

    return AdmissionMultipartRequestSpecLiteV1(
        boundary=boundary,
        declared_content_length=declared_content_length,
    )


def _logical_dimensions(
    width: int, height: int, exif_orientation: int
) -> tuple[int, int]:
    if exif_orientation in _ORIENTATIONS_THAT_SWAP_AXES:
        return height, width
    return width, height


def _jpeg_stream_ends_at_buffer_end(jpeg_bytes: bytes) -> bool:
    if len(jpeg_bytes) < 4 or not jpeg_bytes.startswith(b"\xff\xd8"):
        return False

    position = 2
    in_entropy_scan = False
    while position < len(jpeg_bytes):
        if in_entropy_scan:
            marker_start = jpeg_bytes.find(b"\xff", position)
            if marker_start < 0:
                return False
            position = marker_start
        elif jpeg_bytes[position] != 0xFF:
            return False

        while position < len(jpeg_bytes) and jpeg_bytes[position] == 0xFF:
            position += 1
        if position >= len(jpeg_bytes):
            return False

        marker = jpeg_bytes[position]
        if in_entropy_scan:
            if marker == 0x00:
                position += 1
                continue
            if 0xD0 <= marker <= 0xD7:
                position += 1
                continue
            in_entropy_scan = False

        if marker == 0xD9:
            return position == len(jpeg_bytes) - 1
        if marker in (0x00, 0xD8) or 0xD0 <= marker <= 0xD7:
            return False
        if marker == 0x01:
            position += 1
            continue
        if position + 2 >= len(jpeg_bytes):
            return False

        segment_length = int.from_bytes(
            jpeg_bytes[position + 1 : position + 3],
            "big",
        )
        if segment_length < 2:
            return False
        position = position + 1 + segment_length
        if position > len(jpeg_bytes):
            return False
        if marker == 0xDA:
            in_entropy_scan = True

    return False


def _validate_admission_jpeg(
    *,
    frame_index: int,
    jpeg_bytes: bytes,
) -> ValidatedAdmissionFrameLiteV1:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with (
                io.BytesIO(jpeg_bytes) as source,
                Image.open(source) as image,
            ):
                if image.format != "JPEG":
                    raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE)
                if not _jpeg_stream_ends_at_buffer_end(jpeg_bytes):
                    raise _error(RecognitionErrorReasonLiteV1.INVALID_IMAGE)
                image.verify()

            with (
                io.BytesIO(jpeg_bytes) as source,
                Image.open(source) as image,
            ):
                if image.format != "JPEG":
                    raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE)

                raw_width, raw_height = image.size
                exif = image.getexif()
                exif_orientation = exif.get(_EXIF_ORIENTATION_TAG, 1)
                del exif
                if type(exif_orientation) is not int or exif_orientation not in range(
                    1, 9
                ):
                    raise _error(RecognitionErrorReasonLiteV1.INVALID_IMAGE)

                width, height = _logical_dimensions(
                    raw_width,
                    raw_height,
                    exif_orientation,
                )
                long_edge = max(width, height)
                short_edge = min(width, height)
                if (
                    width < 1
                    or height < 1
                    or long_edge > 1920
                    or short_edge > 1080
                    or width * height > 2_073_600
                ):
                    raise _error(
                        RecognitionErrorReasonLiteV1.IMAGE_DIMENSIONS_UNSUPPORTED
                    )

                image.load()
                if image.size != (raw_width, raw_height):
                    raise _error(RecognitionErrorReasonLiteV1.INVALID_IMAGE)
    except AdmissionNoticeLiteError:
        raise
    except Exception:  # noqa: BLE001 - sanitize the Pillow decoder boundary
        raise _error(RecognitionErrorReasonLiteV1.INVALID_IMAGE) from None

    return ValidatedAdmissionFrameLiteV1(
        frame_index=frame_index,
        jpeg_bytes=jpeg_bytes,
        encoded_size=len(jpeg_bytes),
        width=width,
        height=height,
        exif_orientation=exif_orientation,
    )


class _AdmissionMultipartAccumulator:
    def __init__(self) -> None:
        self._part_count = 0
        self._part_open = False
        self._header_open = False
        self._headers_finished = False
        self._header_bytes = 0
        self._header_name = bytearray()
        self._header_value = bytearray()
        self._headers: dict[bytes, bytes] = {}
        self._current_frame_index: int | None = None
        self._current_payload: bytearray | None = None
        self._payloads: dict[int, bytes] = {}
        self._ended = False

    @property
    def callbacks(self) -> dict[str, Callable[..., None]]:
        return {
            "on_part_begin": self.on_part_begin,
            "on_part_data": self.on_part_data,
            "on_part_end": self.on_part_end,
            "on_header_begin": self.on_header_begin,
            "on_header_field": self.on_header_field,
            "on_header_value": self.on_header_value,
            "on_header_end": self.on_header_end,
            "on_headers_finished": self.on_headers_finished,
            "on_end": self.on_end,
        }

    def _invalid_request(self) -> None:
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)

    def _add_header_bytes(self, count: int) -> None:
        self._header_bytes += count
        if self._header_bytes > MAX_MULTIPART_PART_HEADER_BYTES_LITE_V1:
            self._invalid_request()

    def on_part_begin(self) -> None:
        if self._part_open or self._ended:
            self._invalid_request()
        self._part_count += 1
        if self._part_count > MAX_ADMISSION_FRAMES_LITE_V1:
            raise _error(RecognitionErrorReasonLiteV1.TOO_MANY_FRAMES)
        self._part_open = True
        self._headers_finished = False
        self._header_bytes = 0
        self._headers.clear()
        self._current_frame_index = None
        self._current_payload = None

    def on_header_begin(self) -> None:
        if not self._part_open or self._header_open or self._headers_finished:
            self._invalid_request()
        self._header_open = True
        self._header_name.clear()
        self._header_value.clear()

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        if not self._header_open:
            self._invalid_request()
        fragment = data[start:end]
        self._add_header_bytes(len(fragment))
        self._header_name.extend(fragment)

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        if not self._header_open:
            self._invalid_request()
        fragment = data[start:end]
        self._add_header_bytes(len(fragment))
        self._header_value.extend(fragment)

    def on_header_end(self) -> None:
        if not self._header_open:
            self._invalid_request()
        self._header_open = False
        self._add_header_bytes(3)
        header_name = bytes(self._header_name).lower()
        header_value = bytes(self._header_value).strip(b" \t")
        self._header_name.clear()
        self._header_value.clear()
        if header_name not in (b"content-disposition", b"content-type"):
            self._invalid_request()
        if header_name in self._headers:
            self._invalid_request()
        self._headers[header_name] = header_value

    def on_headers_finished(self) -> None:
        if (
            not self._part_open
            or self._header_open
            or self._headers_finished
            or set(self._headers) != {b"content-disposition", b"content-type"}
        ):
            self._invalid_request()
        self._add_header_bytes(2)

        try:
            raw_content_disposition = self._headers[b"content-disposition"]
            if not _mime_parameters_are_unique(raw_content_disposition):
                self._invalid_request()
            disposition, disposition_options = parse_options_header(
                raw_content_disposition
            )
        except (UnicodeError, ValueError):
            self._invalid_request()
            return
        if (
            disposition != b"form-data"
            or b"name" not in disposition_options
            or not set(disposition_options).issubset({b"name", b"filename"})
        ):
            self._invalid_request()

        field_name = disposition_options[b"name"]
        frame_index = _FRAME_INDEX_BY_FIELD.get(field_name)
        if frame_index is None:
            field_match = _FRAME_FIELD_PATTERN.fullmatch(field_name)
            if field_match is not None and int(field_match.group(1)) > 3:
                raise _error(RecognitionErrorReasonLiteV1.TOO_MANY_FRAMES)
            self._invalid_request()
        if frame_index in self._payloads:
            self._invalid_request()

        try:
            raw_content_type = self._headers[b"content-type"]
            if not _mime_parameters_are_unique(raw_content_type):
                raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE)
            media_type, media_options = parse_options_header(raw_content_type)
        except (UnicodeError, ValueError):
            raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE) from None
        if media_type != _JPEG_MEDIA_TYPE or media_options:
            raise _error(RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE)

        self._headers_finished = True
        self._current_frame_index = frame_index
        self._current_payload = bytearray()

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        payload = self._current_payload
        if not self._part_open or not self._headers_finished or payload is None:
            self._invalid_request()
        fragment_length = end - start
        if len(payload) + fragment_length > MAX_ENCODED_FRAME_BYTES_LITE_V1:
            raise _error(RecognitionErrorReasonLiteV1.IMAGE_TOO_LARGE)
        payload.extend(data[start:end])

    def on_part_end(self) -> None:
        frame_index = self._current_frame_index
        payload = self._current_payload
        if (
            not self._part_open
            or not self._headers_finished
            or frame_index is None
            or payload is None
        ):
            self._invalid_request()

        self._current_payload = None
        try:
            if not payload:
                raise _error(RecognitionErrorReasonLiteV1.INVALID_IMAGE)
            jpeg_bytes = bytes(payload)
        finally:
            payload.clear()

        self._payloads[frame_index] = jpeg_bytes
        self._part_open = False
        self._headers_finished = False
        self._current_frame_index = None
        self._headers.clear()

    def on_end(self) -> None:
        if self._part_open or self._ended:
            self._invalid_request()
        self._ended = True

    def take_frames(self) -> tuple[ValidatedAdmissionFrameLiteV1, ...]:
        indices = tuple(sorted(self._payloads))
        if (
            not self._ended
            or not 1 <= len(indices) <= MAX_ADMISSION_FRAMES_LITE_V1
            or indices != tuple(range(1, len(indices) + 1))
        ):
            self._invalid_request()
        frames: list[ValidatedAdmissionFrameLiteV1] = []
        try:
            for index in indices:
                frames.append(
                    _validate_admission_jpeg(
                        frame_index=index,
                        jpeg_bytes=self._payloads[index],
                    )
                )
        except Exception:
            frames.clear()
            raise
        finally:
            self._payloads.clear()
        result = tuple(frames)
        frames.clear()
        return result

    def clear(self) -> None:
        if self._current_payload is not None:
            self._current_payload.clear()
            self._current_payload = None
        self._header_name.clear()
        self._header_value.clear()
        self._headers.clear()
        self._payloads.clear()
        self._current_frame_index = None


async def ingest_admission_frames(
    request: Request,
    spec: AdmissionMultipartRequestSpecLiteV1,
) -> tuple[ValidatedAdmissionFrameLiteV1, ...]:
    accumulator = _AdmissionMultipartAccumulator()
    parser = MultipartParser(
        spec.boundary,
        accumulator.callbacks,
        max_size=MAX_MULTIPART_BODY_BYTES_LITE_V1,
        max_header_count=2,
        max_header_size=MAX_MULTIPART_PART_HEADER_BYTES_LITE_V1,
    )
    actual_bytes = 0
    try:
        async for request_chunk in request.stream():
            if not request_chunk:
                continue
            next_actual_bytes = actual_bytes + len(request_chunk)
            if next_actual_bytes > MAX_MULTIPART_BODY_BYTES_LITE_V1:
                raise _error(RecognitionErrorReasonLiteV1.IMAGE_TOO_LARGE)
            if (
                spec.declared_content_length is not None
                and next_actual_bytes > spec.declared_content_length
            ):
                raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)
            actual_bytes = next_actual_bytes

            for offset in range(0, len(request_chunk), _PARSER_FEED_CHUNK_BYTES):
                parser_chunk = request_chunk[offset : offset + _PARSER_FEED_CHUNK_BYTES]
                if parser.write(parser_chunk) != len(parser_chunk):
                    raise _error(RecognitionErrorReasonLiteV1.IMAGE_TOO_LARGE)

        if (
            spec.declared_content_length is not None
            and actual_bytes != spec.declared_content_length
        ):
            raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST)
        parser.finalize()
        return accumulator.take_frames()
    except AdmissionNoticeLiteError:
        raise
    except (ClientDisconnect, MultipartParseError, FormParserError):
        raise _error(RecognitionErrorReasonLiteV1.INVALID_REQUEST) from None
    finally:
        parser.close()
        accumulator.clear()

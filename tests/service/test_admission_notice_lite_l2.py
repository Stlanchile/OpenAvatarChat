import asyncio
import builtins
import io
import json
import tempfile
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from loguru import logger
from PIL import Image

import service.admission_notice_lite_ingestion as ingestion_module
from chat_engine.core.chat_session import ChatSession
from service.admission_notice_lite_chat_context import AdmissionContextV1
from service.admission_notice_lite_contracts import (
    RecognitionJobContextLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.admission_notice_lite_ingestion import (
    MAX_ADMISSION_FRAMES_LITE_V1,
    MAX_ENCODED_FRAME_BYTES_LITE_V1,
    MAX_MULTIPART_BODY_BYTES_LITE_V1,
)
from service.admission_notice_lite_routes import (
    register_admission_notice_lite_routes,
)
from service.admission_notice_lite_service import AdmissionNoticeLiteService
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROUTE = "/api/v1/sessions/owner/admission-notice/recognitions"
BOUNDARY = b"admission-lite-v1-test-boundary"
_TEST_ADMISSION_CONTEXT = AdmissionContextV1(
    schema_version="admission_context_v1",
    institution_name="湖北交通职业技术学院",
    college="交通信息学院",
    name=None,
    source_province=None,
    major="智能交通技术",
)


class SessionStub(ChatSession):
    def __init__(self) -> None:
        self.stopped = False
        self._initialize_admission_context_state()

    def stop(self) -> None:
        self.stopped = True


class EngineStub:
    def __init__(self, sessions: dict[str, SessionStub] | None = None) -> None:
        self.sessions = sessions or {}
        self.observers: list[Callable[[str, SessionStub], None]] = []

    def add_session_stop_observer(
        self, observer: Callable[[str, SessionStub], None]
    ) -> AdmissionContextV1:
        self.observers.append(observer)

    def stop_session(self, session_id: str) -> None:
        session = self.sessions.pop(session_id, None)
        if session is None:
            return
        for observer in tuple(self.observers):
            observer(session_id, session)
        session.stop()


class ManualClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class BlockedBodyReceive:
    def __init__(self, body: bytes) -> None:
        split = max(1, len(body) // 2)
        self.first = body[:split]
        self.remaining = body[split:]
        self.delivered_chunks = 0
        self.waiting_for_more = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self) -> dict:
        if self.delivered_chunks == 0:
            self.delivered_chunks = 1
            return {
                "type": "http.request",
                "body": self.first,
                "more_body": True,
            }
        self.waiting_for_more.set()
        await self.release.wait()
        self.delivered_chunks += 1
        return {
            "type": "http.request",
            "body": self.remaining,
            "more_body": False,
        }


class ImageProcessorFake:
    def __init__(
        self,
        *,
        wait_for_release: bool = False,
        ignore_cancellation: bool = False,
        failure: Exception | None = None,
    ) -> None:
        self.wait_for_release = wait_for_release
        self.ignore_cancellation = ignore_cancellation
        self.failure = failure
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancellation_observed = asyncio.Event()
        self.calls = 0
        self.live_frames: tuple[ValidatedAdmissionFrameLiteV1, ...] = ()
        self.received: tuple[tuple[int, int, int, int, int, type], ...] = ()

    async def process(
        self,
        context: RecognitionJobContextLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> AdmissionContextV1:
        del context
        self.calls += 1
        self.live_frames = frames
        self.received = tuple(
            (
                frame.frame_index,
                frame.encoded_size,
                frame.width,
                frame.height,
                frame.exif_orientation,
                type(frame.jpeg_bytes),
            )
            for frame in frames
        )
        self.started.set()
        try:
            if self.wait_for_release:
                while not self.release.is_set():
                    try:
                        await self.release.wait()
                    except asyncio.CancelledError:
                        self.cancellation_observed.set()
                        if not self.ignore_cancellation:
                            raise
            if self.failure is not None:
                raise self.failure
        finally:
            self.live_frames = ()
        return _TEST_ADMISSION_CONTEXT


def _config(
    *,
    ttl: int = 120,
    max_global_jobs: int = 1,
) -> AdmissionNoticeLiteFeatureConfigV1:
    return AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        recognition_ttl_seconds=ttl,
        max_global_recognition_jobs=max_global_jobs,
    )


def _app(
    *,
    processor: ImageProcessorFake | None,
    sessions: dict[str, SessionStub] | None = None,
    ttl: int = 120,
    max_global_jobs: int = 1,
) -> tuple[FastAPI, EngineStub, AdmissionNoticeLiteService]:
    app = FastAPI()
    engine = EngineStub(sessions or {"owner": SessionStub()})
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(ttl=ttl, max_global_jobs=max_global_jobs),
        processor=processor,
    )
    assert service is not None
    return app, engine, service


def _jpeg_bytes(
    width: int = 16,
    height: int = 12,
    *,
    orientation: int = 1,
    description: str | None = None,
) -> bytes:
    output = io.BytesIO()
    exif = Image.Exif()
    exif[274] = orientation
    if description is not None:
        exif[270] = description
    Image.new("RGB", (width, height), "white").save(
        output,
        format="JPEG",
        quality=85,
        exif=exif,
    )
    return output.getvalue()


def _png_bytes() -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (16, 12), "white").save(output, format="PNG")
    return output.getvalue()


def _jpeg_with_exact_size(target_size: int) -> bytes:
    base = _jpeg_bytes()
    if target_size < len(base):
        raise ValueError("target size is smaller than the base JPEG")
    remaining = target_size - len(base)
    segments: list[bytes] = []
    while remaining:
        segment_size = min(65_537, remaining)
        leftover = remaining - segment_size
        if 0 < leftover < 4:
            segment_size -= 4 - leftover
        if segment_size < 4:
            raise ValueError("target size cannot be represented by JPEG comments")
        payload_size = segment_size - 4
        segments.append(
            b"\xff\xfe" + (payload_size + 2).to_bytes(2, "big") + b"x" * payload_size
        )
        remaining -= segment_size
    return base[:2] + b"".join(segments) + base[2:]


def _multipart_body(
    parts: list[tuple[str, bytes, str | None, str]],
    *,
    boundary: bytes = BOUNDARY,
    close: bool = True,
    epilogue: bytes = b"",
) -> bytes:
    body = bytearray()
    for field_name, payload, media_type, filename in parts:
        body.extend(b"--" + boundary + b"\r\n")
        body.extend(
            b'Content-Disposition: form-data; name="'
            + field_name.encode("ascii")
            + b'"; filename="'
            + filename.encode("ascii")
            + b'"\r\n'
        )
        if media_type is not None:
            body.extend(b"Content-Type: " + media_type.encode("ascii") + b"\r\n")
        body.extend(b"\r\n")
        body.extend(payload)
        body.extend(b"\r\n")
    if close:
        body.extend(b"--" + boundary + b"--\r\n")
    body.extend(epilogue)
    result = bytes(body)
    body.clear()
    return result


def _headers_for(
    body: bytes,
    *,
    boundary: bytes = BOUNDARY,
    include_content_length: bool = True,
) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"host", b"test"),
        (b"content-type", b"multipart/form-data; boundary=" + boundary),
    ]
    if include_content_length:
        headers.append((b"content-length", str(len(body)).encode("ascii")))
    return headers


def _asgi_scope(
    *,
    path: str,
    headers: list[tuple[bytes, bytes]],
) -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "2",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "root_path": "",
    }


async def _call_asgi(
    app: FastAPI,
    *,
    body: bytes,
    headers: list[tuple[bytes, bytes]],
    path: str = ROUTE,
    chunks: int = 1,
) -> tuple[int, dict[str, str], int]:
    scope = _asgi_scope(path=path, headers=headers)
    chunk_size = max(1, (len(body) + chunks - 1) // chunks)
    body_chunks = [
        body[offset : offset + chunk_size] for offset in range(0, len(body), chunk_size)
    ] or [b""]
    received = 0
    messages: list[dict] = []

    async def receive() -> dict:
        nonlocal received
        if received >= len(body_chunks):
            return {"type": "http.disconnect"}
        chunk = body_chunks[received]
        received += 1
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": received < len(body_chunks),
        }

    async def send(message: dict) -> None:
        messages.append(message)

    await app(scope, receive, send)
    status = next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return status, json.loads(response_body), received


async def _post_parts(
    app: FastAPI,
    parts: list[tuple[str, bytes, str | None, str]],
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            ROUTE,
            files=[
                (
                    name,
                    (filename, payload, media_type),
                )
                for name, payload, media_type, filename in parts
            ],
        )


async def _wait_for_terminal(
    app: FastAPI,
    recognition_id: str,
) -> dict[str, str]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(300):
            response = await client.get(f"{ROUTE}/{recognition_id}")
            content = response.json()
            if content["status"] not in {"created", "processing"}:
                return content
            await asyncio.sleep(0)
    pytest.fail("recognition did not reach a terminal state")


async def _wait_for_resources_released(
    service: AdmissionNoticeLiteService,
) -> None:
    for _ in range(300):
        if (
            service.owned_task_count == 0
            and service.resource_slot_count == 0
            and service.retained_frame_count == 0
        ):
            return
        await asyncio.sleep(0)
    pytest.fail("Admission Notice Lite resources were not released")


def _assert_error(
    response: httpx.Response,
    *,
    status: int,
    reason: str,
) -> None:
    assert response.status_code == status
    assert response.json() == {"reason": reason}


@pytest.mark.asyncio
@pytest.mark.parametrize("frame_count", (1, 2, 3))
async def test_accepts_one_to_three_jpegs_in_canonical_order(
    frame_count: int,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    parts = [
        (
            f"frame_{index}",
            _jpeg_bytes(20 + index, 10 + index),
            "image/jpeg",
            f"ignored-{index}.jpg",
        )
        for index in range(1, frame_count + 1)
    ]

    response = await _post_parts(app, parts)
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])

    assert tuple(item[0] for item in processor.received) == tuple(
        range(1, frame_count + 1)
    )
    assert all(item[-1] is bytes for item in processor.received)
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_physical_part_order_does_not_change_semantic_order() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    first = _jpeg_bytes(31, 21)
    second = _jpeg_bytes(32, 22)

    response = await _post_parts(
        app,
        [
            ("frame_2", second, "image/jpeg", "second.jpg"),
            ("frame_1", first, "image/jpeg", "first.jpg"),
        ],
    )
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])
    assert tuple(item[0] for item in processor.received) == (1, 2)
    assert tuple(item[2:4] for item in processor.received) == (
        (31, 21),
        (32, 22),
    )
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("parts", "reason"),
    (
        ([], "INVALID_REQUEST"),
        (
            [("frame_2", b"jpeg", "image/jpeg", "ignored.jpg")],
            "INVALID_REQUEST",
        ),
        (
            [
                ("frame_1", b"jpeg", "image/jpeg", "ignored.jpg"),
                ("frame_3", b"jpeg", "image/jpeg", "ignored.jpg"),
            ],
            "INVALID_REQUEST",
        ),
        (
            [("unknown", b"text", None, "ignored.txt")],
            "INVALID_REQUEST",
        ),
        (
            [("metadata", b"{}", "application/json", "ignored.json")],
            "INVALID_REQUEST",
        ),
    ),
)
async def test_rejects_missing_gapped_unknown_and_text_fields(
    parts: list[tuple[str, bytes, str | None, str]],
    reason: str,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body(parts)
    status, content, _ = await _call_asgi(
        app,
        body=body,
        headers=_headers_for(body),
    )

    assert status == 400
    assert content == {"reason": reason}
    assert processor.calls == 0
    assert service.retained_job_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_rejects_duplicate_frame_field() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_bytes()
    response = await _post_parts(
        app,
        [
            ("frame_1", jpeg, "image/jpeg", "one.jpg"),
            ("frame_1", jpeg, "image/jpeg", "duplicate.jpg"),
        ],
    )

    _assert_error(response, status=400, reason="INVALID_REQUEST")
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_rejects_frame_four_and_more_than_three_parts() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_bytes()

    frame_four = await _post_parts(
        app,
        [("frame_4", jpeg, "image/jpeg", "four.jpg")],
    )
    four_parts = await _post_parts(
        app,
        [
            (f"frame_{index}", jpeg, "image/jpeg", f"{index}.jpg")
            for index in range(1, 5)
        ],
    )

    _assert_error(frame_four, status=400, reason="TOO_MANY_FRAMES")
    _assert_error(four_parts, status=400, reason="TOO_MANY_FRAMES")
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_query_parameter_is_rejected_before_body_ingestion() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"{ROUTE}?profile_id=forbidden",
            files={
                "frame_1": (
                    "ignored.jpg",
                    _jpeg_bytes(),
                    "image/jpeg",
                )
            },
        )

    _assert_error(response, status=400, reason="INVALID_REQUEST")
    assert processor.calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "media_type", "status", "reason"),
    (
        (_jpeg_bytes(), "image/png", 415, "UNSUPPORTED_MEDIA_TYPE"),
        (_jpeg_bytes(), "image/jpg", 415, "UNSUPPORTED_MEDIA_TYPE"),
        (_png_bytes(), "image/jpeg", 415, "UNSUPPORTED_MEDIA_TYPE"),
        (b"arbitrary bytes", "image/jpeg", 422, "INVALID_IMAGE"),
        (b"", "image/jpeg", 422, "INVALID_IMAGE"),
    ),
)
async def test_requires_exact_jpeg_mime_and_decoded_format(
    payload: bytes,
    media_type: str,
    status: int,
    reason: str,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)

    response = await _post_parts(
        app,
        [("frame_1", payload, media_type, "ignored.bin")],
    )

    _assert_error(response, status=status, reason=reason)
    assert processor.calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "encoded_size",
    (
        MAX_ENCODED_FRAME_BYTES_LITE_V1 - 1,
        MAX_ENCODED_FRAME_BYTES_LITE_V1,
    ),
)
async def test_accepts_encoded_frame_limit_boundaries(
    encoded_size: int,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_with_exact_size(encoded_size)

    response = await _post_parts(
        app,
        [("frame_1", jpeg, "image/jpeg", "ignored.jpg")],
    )
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])
    assert processor.received[0][1] == encoded_size
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_rejects_encoded_frame_over_two_mib_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    decode_calls = 0
    real_validator = ingestion_module._validate_admission_jpeg

    def counted_validator(**kwargs):
        nonlocal decode_calls
        decode_calls += 1
        return real_validator(**kwargs)

    monkeypatch.setattr(
        ingestion_module,
        "_validate_admission_jpeg",
        counted_validator,
    )
    oversized = _jpeg_with_exact_size(MAX_ENCODED_FRAME_BYTES_LITE_V1 + 1)

    response = await _post_parts(
        app,
        [("frame_1", oversized, "image/jpeg", "ignored.jpg")],
    )

    _assert_error(response, status=413, reason="IMAGE_TOO_LARGE")
    assert decode_calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_declared_request_over_limit_is_rejected_without_body_read() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    headers = _headers_for(body, include_content_length=False)
    headers.append(
        (
            b"content-length",
            str(MAX_MULTIPART_BODY_BYTES_LITE_V1 + 1).encode("ascii"),
        )
    )

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=headers,
    )

    assert status == 413
    assert content == {"reason": "IMAGE_TOO_LARGE"}
    assert receive_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_actual_request_over_limit_is_rejected_without_content_length() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    ordinary = _multipart_body(
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")]
    )
    oversized_body = ordinary + b"x" * (
        MAX_MULTIPART_BODY_BYTES_LITE_V1 - len(ordinary) + 1
    )

    status, content, receive_count = await _call_asgi(
        app,
        body=oversized_body,
        headers=_headers_for(
            oversized_body,
            include_content_length=False,
        ),
        chunks=4,
    )

    assert status == 413
    assert content == {"reason": "IMAGE_TOO_LARGE"}
    assert receive_count == 4
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_actual_bytes_exceeding_declared_length_are_rejected() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    headers = _headers_for(body, include_content_length=False)
    headers.append((b"content-length", str(len(body) - 1).encode("ascii")))

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=headers,
    )

    assert status == 400
    assert content == {"reason": "INVALID_REQUEST"}
    assert receive_count == 1
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_request_without_content_length_is_streamed_and_accepted() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=_headers_for(body, include_content_length=False),
        chunks=3,
    )

    assert status == 202
    assert content["status"] == "created"
    assert receive_count == 3
    await _wait_for_terminal(app, content["recognition_id"])
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra_headers",
    (
        [(b"transfer-encoding", b"chunked")],
        [(b"content-length", b"10"), (b"content-length", b"10")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"1.5")],
    ),
)
async def test_rejects_unbounded_or_invalid_framing_before_body(
    extra_headers: list[tuple[bytes, bytes]],
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    headers = _headers_for(body, include_content_length=False) + extra_headers

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=headers,
    )

    assert status == 400
    assert content == {"reason": "INVALID_REQUEST"}
    assert receive_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("digit", (b"9", b"0"))
async def test_overlong_decimal_content_length_is_bounded_without_conversion(
    digit: bytes,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    headers = _headers_for(body, include_content_length=False)
    headers.append((b"content-length", digit * 4_301))

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=headers,
    )

    assert status == 400
    assert content == {"reason": "INVALID_REQUEST"}
    assert receive_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "disposition_replacement",
    (
        b'name="frame_2"; name="frame_1"',
        b'filename="one.jpg"; filename="two.jpg"',
    ),
    ids=("duplicate-name", "duplicate-filename"),
)
async def test_rejects_duplicate_content_disposition_parameters(
    disposition_replacement: bytes,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "one.jpg")])
    if disposition_replacement.startswith(b"name"):
        body = body.replace(b'name="frame_1"', disposition_replacement, 1)
    else:
        body = body.replace(b'filename="one.jpg"', disposition_replacement, 1)

    status, content, _ = await _call_asgi(
        app,
        body=body,
        headers=_headers_for(body),
    )

    assert status == 400
    assert content == {"reason": "INVALID_REQUEST"}
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_rejects_duplicate_multipart_boundary_parameters_before_body() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    headers = [
        (b"host", b"test"),
        (
            b"content-type",
            b"multipart/form-data; boundary=wrong; boundary=" + BOUNDARY,
        ),
        (b"content-length", str(len(body)).encode("ascii")),
    ]

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=headers,
    )

    assert status == 400
    assert content == {"reason": "INVALID_REQUEST"}
    assert receive_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("width", "height"),
    (
        (1920, 1080),
        (1080, 1920),
        (1600, 900),
        (900, 1600),
    ),
)
async def test_accepts_supported_logical_dimensions(
    width: int,
    height: int,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_bytes(width, height)

    response = await _post_parts(
        app,
        [("frame_1", jpeg, "image/jpeg", "ignored.jpg")],
    )
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])
    assert processor.received[0][2:4] == (width, height)
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("width", "height"),
    (
        (1921, 1080),
        (1080, 1921),
        (1920, 1081),
        (1441, 1440),
    ),
)
async def test_rejects_edge_or_pixel_limit_overflow(
    width: int,
    height: int,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_bytes(width, height)

    response = await _post_parts(
        app,
        [("frame_1", jpeg, "image/jpeg", "ignored.jpg")],
    )

    _assert_error(
        response,
        status=422,
        reason="IMAGE_DIMENSIONS_UNSUPPORTED",
    )
    assert processor.calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("orientation", "expected_dimensions"),
    (
        (1, (1920, 1080)),
        (6, (1080, 1920)),
        (8, (1080, 1920)),
    ),
)
async def test_exif_orientation_defines_logical_dimensions_without_transcoding(
    orientation: int,
    expected_dimensions: tuple[int, int],
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_bytes(1920, 1080, orientation=orientation)

    response = await _post_parts(
        app,
        [("frame_1", jpeg, "image/jpeg", "ignored.jpg")],
    )
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])

    received = processor.received[0]
    assert received[2:4] == expected_dimensions
    assert received[4] == orientation
    assert received[1] == len(jpeg)
    await _wait_for_resources_released(service)
    await service.shutdown()


def _corrupted_entropy_jpeg() -> bytes:
    jpeg = _jpeg_bytes(64, 64)
    start_of_scan = jpeg.index(b"\xff\xda")
    scan_header_length = int.from_bytes(
        jpeg[start_of_scan + 2 : start_of_scan + 4],
        "big",
    )
    entropy_start = start_of_scan + 2 + scan_header_length
    return jpeg[:entropy_start] + b"\xff\xc0\x00\x11" + b"\x00" * 20 + jpeg[-2:]


def _malformed_exif_jpeg() -> bytes:
    jpeg = _jpeg_bytes()
    malformed_exif = b"Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00"
    segment = (
        b"\xff\xe1" + (len(malformed_exif) + 2).to_bytes(2, "big") + malformed_exif
    )
    return jpeg[:2] + segment + jpeg[2:]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    (
        _jpeg_bytes()[:-2],
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
        _corrupted_entropy_jpeg(),
        _jpeg_bytes() + b"trailing-data",
        _jpeg_bytes() + b"trailing-data\xff\xd9",
        _jpeg_bytes() + _jpeg_bytes(),
        _malformed_exif_jpeg(),
    ),
    ids=(
        "missing-eoi",
        "header-only",
        "corrupted-entropy",
        "trailing-data",
        "trailing-data-final-eoi",
        "concatenated-jpegs",
        "malformed-exif",
    ),
)
async def test_strict_decode_rejects_truncation_corruption_and_bad_metadata(
    payload: bytes,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)

    response = await _post_parts(
        app,
        [("frame_1", payload, "image/jpeg", "ignored.jpg")],
    )

    _assert_error(response, status=422, reason="INVALID_IMAGE")
    assert processor.calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_decoder_exception_is_sanitized_as_invalid_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)

    def fail_open(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("decoder-private-exception")

    monkeypatch.setattr(ingestion_module.Image, "open", fail_open)
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )

    _assert_error(response, status=422, reason="INVALID_IMAGE")
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_decompression_bomb_warning_or_error_is_rejected_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    monkeypatch.setattr(ingestion_module.Image, "MAX_IMAGE_PIXELS", 1)

    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(16, 12), "image/jpeg", "ignored.jpg")],
    )

    _assert_error(response, status=422, reason="INVALID_IMAGE")
    assert processor.calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_malformed_unclosed_multipart_is_rejected() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body(
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
        close=False,
    )

    status, content, _ = await _call_asgi(
        app,
        body=body,
        headers=_headers_for(body),
    )

    assert status == 400
    assert content == {"reason": "INVALID_REQUEST"}
    assert processor.calls == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_processor_receives_only_small_immutable_validated_contract() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    first = _jpeg_bytes(40, 30)
    second = _jpeg_bytes(30, 40, orientation=6)

    response = await _post_parts(
        app,
        [
            ("frame_1", first, "image/jpeg", "private-name-one.jpg"),
            ("frame_2", second, "image/jpeg", "private-name-two.jpg"),
        ],
    )
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])

    assert processor.received == (
        (1, len(first), 40, 30, 1, bytes),
        (2, len(second), 40, 30, 6, bytes),
    )
    assert not hasattr(
        ValidatedAdmissionFrameLiteV1,
        "filename",
    )
    assert set(ValidatedAdmissionFrameLiteV1.__dataclass_fields__) == {
        "frame_index",
        "jpeg_bytes",
        "encoded_size",
        "width",
        "height",
        "exif_orientation",
    }
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_success_and_processor_failure_clear_frame_references() -> None:
    success_processor = ImageProcessorFake()
    success_app, _, success_service = _app(processor=success_processor)
    success = await _post_parts(
        success_app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )
    await _wait_for_terminal(success_app, success.json()["recognition_id"])
    await _wait_for_resources_released(success_service)
    assert success_processor.live_frames == ()
    await success_service.shutdown()

    failure_processor = ImageProcessorFake(
        failure=RuntimeError("processor-private-exception")
    )
    failure_app, _, failure_service = _app(processor=failure_processor)
    failure = await _post_parts(
        failure_app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )
    status = await _wait_for_terminal(
        failure_app,
        failure.json()["recognition_id"],
    )
    assert status["status"] == "failed"
    assert status["reason"] == "INTERNAL_ERROR"
    await _wait_for_resources_released(failure_service)
    assert failure_processor.live_frames == ()
    await failure_service.shutdown()


@pytest.mark.asyncio
async def test_cancel_clears_job_frames_and_waits_for_processor_unwind() -> None:
    processor = ImageProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    app, _, service = _app(processor=processor)
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )
    recognition_id = response.json()["recognition_id"]
    await processor.started.wait()
    assert service.retained_frame_count == 1
    assert service.resource_slot_count == 1

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        cancelled = await client.delete(f"{ROUTE}/{recognition_id}")
        status = await client.get(f"{ROUTE}/{recognition_id}")

    assert cancelled.status_code == 204
    assert status.json()["status"] == "cancelled"
    assert service.retained_frame_count == 0
    assert service.resource_slot_count == 1
    await processor.cancellation_observed.wait()
    assert processor.live_frames

    processor.release.set()
    await _wait_for_resources_released(service)
    assert processor.live_frames == ()
    await service.shutdown()


@pytest.mark.asyncio
async def test_expiry_clears_job_frames_and_discards_late_completion() -> None:
    clock = ManualClock()
    processor = ImageProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    app, _, service = _app(processor=processor, ttl=1)
    service._clock = clock
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )
    recognition_id = response.json()["recognition_id"]
    await processor.started.wait()

    clock.advance(1.1)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        expired = await client.get(f"{ROUTE}/{recognition_id}")

    assert expired.json()["status"] == "expired"
    assert service.retained_frame_count == 0
    assert service.resource_slot_count == 1
    processor.release.set()
    await _wait_for_resources_released(service)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        still_expired = await client.get(f"{ROUTE}/{recognition_id}")
    assert still_expired.json()["status"] == "expired"
    await service.shutdown()


@pytest.mark.asyncio
async def test_session_teardown_cancels_processing_and_releases_frames() -> None:
    processor = ImageProcessorFake(wait_for_release=True)
    old_session = SessionStub()
    app, engine, service = _app(
        processor=processor,
        sessions={"owner": old_session},
    )
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )
    await processor.started.wait()

    engine.stop_session("owner")
    await _wait_for_resources_released(service)

    assert old_session.stopped is True
    assert service.retained_frame_count == 0
    engine.sessions["owner"] = SessionStub()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        replacement_status = await client.get(
            f"{ROUTE}/{response.json()['recognition_id']}"
        )
    assert replacement_status.status_code == 404
    await service.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_processing_and_clears_registry_frames() -> None:
    processor = ImageProcessorFake(wait_for_release=True)
    app, _, service = _app(processor=processor)
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )
    assert response.status_code == 202
    await processor.started.wait()

    await service.shutdown()

    assert service.accepting is False
    assert service.retained_job_count == 0
    assert service.retained_frame_count == 0
    assert service.resource_slot_count == 0
    assert processor.live_frames == ()


@pytest.mark.asyncio
async def test_validation_failure_creates_no_job_and_retains_no_frames() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    response = await _post_parts(
        app,
        [
            ("frame_1", _jpeg_bytes(), "image/jpeg", "valid.jpg"),
            ("frame_2", b"invalid", "image/jpeg", "invalid.jpg"),
        ],
    )

    _assert_error(response, status=422, reason="INVALID_IMAGE")
    assert processor.calls == 0
    assert service.active_job_count == 0
    assert service.retained_job_count == 0
    assert service.retained_frame_count == 0
    assert service.active_ingestion_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_session_replacement_during_validation_cannot_receive_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processor = ImageProcessorFake()
    old_session = SessionStub()
    app, engine, service = _app(
        processor=processor,
        sessions={"owner": old_session},
    )
    real_validator = ingestion_module._validate_admission_jpeg

    def replace_then_validate(**kwargs):
        engine.sessions["owner"] = SessionStub()
        return real_validator(**kwargs)

    monkeypatch.setattr(
        ingestion_module,
        "_validate_admission_jpeg",
        replace_then_validate,
    )
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )

    _assert_error(response, status=404, reason="RECOGNITION_NOT_FOUND")
    assert processor.calls == 0
    assert service.retained_job_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_session_teardown_during_validation_creates_no_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processor = ImageProcessorFake()
    app, engine, service = _app(processor=processor)
    real_validator = ingestion_module._validate_admission_jpeg

    def stop_then_validate(**kwargs):
        engine.stop_session("owner")
        return real_validator(**kwargs)

    monkeypatch.setattr(
        ingestion_module,
        "_validate_admission_jpeg",
        stop_then_validate,
    )
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")],
    )

    _assert_error(response, status=404, reason="RECOGNITION_NOT_FOUND")
    assert processor.calls == 0
    assert service.retained_job_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_session_stop_cancels_a_stalled_upload_and_releases_capacity() -> None:
    processor = ImageProcessorFake()
    app, engine, service = _app(
        processor=processor,
        sessions={"owner": SessionStub(), "other": SessionStub()},
    )
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    receiver = BlockedBodyReceive(body)
    messages: list[dict] = []

    async def send(message: dict) -> None:
        messages.append(message)

    request_task = asyncio.create_task(
        app(
            _asgi_scope(path=ROUTE, headers=_headers_for(body)),
            receiver,
            send,
        )
    )
    await receiver.waiting_for_more.wait()
    assert receiver.delivered_chunks == 1
    assert service.resource_slot_count == 1

    engine.stop_session("owner")
    await asyncio.wait_for(request_task, timeout=1)

    response_status = next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    assert response_status == 404
    assert json.loads(response_body) == {"reason": "RECOGNITION_NOT_FOUND"}
    assert receiver.delivered_chunks == 1
    assert service.resource_slot_count == 0
    assert service.retained_job_count == 0

    other_body = _multipart_body(
        [("frame_1", _jpeg_bytes(), "image/jpeg", "other.jpg")]
    )
    other_status, _, receive_count = await _call_asgi(
        app,
        path="/api/v1/sessions/other/admission-notice/recognitions",
        body=other_body,
        headers=_headers_for(other_body),
    )
    assert other_status == 202
    assert receive_count == 1
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_request_cancellation_clears_partial_multipart_ownership() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    receiver = BlockedBodyReceive(body)

    async def send(message: dict) -> None:
        del message

    request_task = asyncio.create_task(
        app(
            _asgi_scope(path=ROUTE, headers=_headers_for(body)),
            receiver,
            send,
        )
    )
    await receiver.waiting_for_more.wait()
    request_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request_task

    assert service.active_ingestion_count == 0
    assert service.resource_slot_count == 0
    assert service.retained_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_a_partial_upload_and_releases_its_permit() -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "ignored.jpg")])
    receiver = BlockedBodyReceive(body)

    async def send(message: dict) -> None:
        del message

    request_task = asyncio.create_task(
        app(
            _asgi_scope(path=ROUTE, headers=_headers_for(body)),
            receiver,
            send,
        )
    )
    await receiver.waiting_for_more.wait()

    await service.shutdown()

    assert request_task.cancelled()
    assert service.active_ingestion_count == 0
    assert service.resource_slot_count == 0
    assert service.retained_job_count == 0


@pytest.mark.asyncio
async def test_two_simultaneous_posts_same_session_have_one_winner() -> None:
    processor = ImageProcessorFake(wait_for_release=True)
    app, _, service = _app(processor=processor)
    jpeg = _jpeg_bytes()

    first, second = await asyncio.gather(
        _post_parts(
            app,
            [("frame_1", jpeg, "image/jpeg", "one.jpg")],
        ),
        _post_parts(
            app,
            [("frame_1", jpeg, "image/jpeg", "two.jpg")],
        ),
    )

    assert sorted((first.status_code, second.status_code)) == [202, 409]
    loser = first if first.status_code == 409 else second
    assert loser.json() == {"reason": "RECOGNITION_ALREADY_ACTIVE"}
    assert service.active_job_count == 1
    assert service.resource_slot_count == 1

    winner = first if first.status_code == 202 else second
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.delete(f"{ROUTE}/{winner.json()['recognition_id']}")
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_global_capacity_rejects_before_second_body_read() -> None:
    processor = ImageProcessorFake(wait_for_release=True)
    app, _, service = _app(
        processor=processor,
        sessions={"one": SessionStub(), "two": SessionStub()},
    )
    first_body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "one.jpg")])
    first_status, first_content, _ = await _call_asgi(
        app,
        path="/api/v1/sessions/one/admission-notice/recognitions",
        body=first_body,
        headers=_headers_for(first_body),
    )
    assert first_status == 202
    await processor.started.wait()

    second_body = _multipart_body([("frame_1", _jpeg_bytes(), "image/jpeg", "two.jpg")])
    second_status, second_content, receive_count = await _call_asgi(
        app,
        path="/api/v1/sessions/two/admission-notice/recognitions",
        body=second_body,
        headers=_headers_for(second_body),
    )

    assert second_status == 503
    assert second_content == {"reason": "SERVICE_BUSY"}
    assert receive_count == 0
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.delete(
            "/api/v1/sessions/one/admission-notice/recognitions/"
            + first_content["recognition_id"]
        )
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_production_unavailable_does_not_consume_personal_body() -> None:
    app, _, service = _app(processor=None)
    body = _multipart_body(
        [("frame_1", _jpeg_bytes(), "image/jpeg", "private-name.jpg")]
    )

    status, content, receive_count = await _call_asgi(
        app,
        body=body,
        headers=_headers_for(body),
    )

    assert status == 503
    assert content == {"reason": "SERVICE_UNAVAILABLE"}
    assert receive_count == 0
    assert service.retained_job_count == 0
    assert service.retained_frame_count == 0
    assert service.resource_slot_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_ingestion_path_does_not_use_tempfiles_or_write_payload_to_disk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processor = ImageProcessorFake()
    app, _, service = _app(processor=processor)
    tempfile_calls: list[str] = []
    write_opens: list[str] = []
    real_open = builtins.open

    def forbidden_tempfile(*args, **kwargs):
        del args, kwargs
        tempfile_calls.append("called")
        raise AssertionError("multipart ingestion attempted tempfile use")

    def observed_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            write_opens.append(str(file))
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(tempfile, "SpooledTemporaryFile", forbidden_tempfile)
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", forbidden_tempfile)
    monkeypatch.setattr(tempfile, "TemporaryFile", forbidden_tempfile)
    monkeypatch.setattr(builtins, "open", observed_open)

    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "private-name.jpg")],
    )
    assert response.status_code == 202
    await _wait_for_terminal(app, response.json()["recognition_id"])

    assert tempfile_calls == []
    assert write_opens == []
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_logs_and_errors_omit_filename_exif_bytes_and_exception_text() -> None:
    filename_canary = "private-filename-canary.jpg"
    exif_canary = "private-exif-canary"
    exception_canary = "private-processor-exception-canary"
    jpeg = _jpeg_bytes(description=exif_canary)
    byte_canary = jpeg[:24].hex()
    processor = ImageProcessorFake(failure=RuntimeError(exception_canary))
    app, _, service = _app(processor=processor)
    messages: list[str] = []
    sink_id = logger.add(messages.append, format="{message}")
    try:
        response = await _post_parts(
            app,
            [
                (
                    "frame_1",
                    jpeg,
                    "image/jpeg",
                    filename_canary,
                )
            ],
        )
        status = await _wait_for_terminal(
            app,
            response.json()["recognition_id"],
        )
    finally:
        logger.remove(sink_id)

    assert status["reason"] == "INTERNAL_ERROR"
    log_text = "\n".join(messages)
    for canary in (
        filename_canary,
        exif_canary,
        exception_canary,
        byte_canary,
    ):
        assert canary not in log_text
        assert canary not in json.dumps(status)
    await _wait_for_resources_released(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_status_contract_does_not_expose_frame_metadata() -> None:
    processor = ImageProcessorFake(wait_for_release=True)
    app, _, service = _app(processor=processor)
    response = await _post_parts(
        app,
        [("frame_1", _jpeg_bytes(), "image/jpeg", "private-name.jpg")],
    )
    recognition_id = response.json()["recognition_id"]
    await processor.started.wait()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        status = await client.get(f"{ROUTE}/{recognition_id}")
        await client.delete(f"{ROUTE}/{recognition_id}")

    assert set(status.json()) == {"recognition_id", "status"}
    serialized = json.dumps(status.json())
    for forbidden in (
        "frame",
        "size",
        "width",
        "height",
        "mime",
        "filename",
        "orientation",
    ):
        assert forbidden not in serialized.lower()
    await _wait_for_resources_released(service)
    await service.shutdown()


def test_l2_uses_streaming_parser_without_framework_upload_spooling() -> None:
    source = (
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_ingestion.py"
    ).read_text(encoding="utf-8")

    assert "request.stream()" in source
    for forbidden in (
        "UploadFile",
        "request.form(",
        "request.body(",
        "SpooledTemporaryFile",
        "NamedTemporaryFile",
        "TemporaryFile",
        "tempfile",
    ):
        assert forbidden not in source


def test_pillow_is_existing_explicit_dependency_without_new_image_stack() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"pillow>=11.1.0"' in pyproject
    assert (
        "opencv"
        not in (PROJECT_ROOT / "src" / "service" / "admission_notice_lite_ingestion.py")
        .read_text(encoding="utf-8")
        .lower()
    )


def test_l3_backend_source_has_no_l4_frontend_or_hardened_dependencies() -> None:
    paths = (
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_contracts.py",
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_ingestion.py",
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_ocr.py",
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_routes.py",
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_service.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths).lower()

    for forbidden in (
        "openvino",
        "onnxruntime",
        "template_match",
        "major_catalog",
        "chatagent",
        "chat_agent",
        "text_to_speech",
        "frontend_service",
        "securityenvelope",
        "workfence",
        "captureepoch",
        "capturecoordinator",
        "aesgcm",
        "private_store",
        "evidence",
        "declassification",
    ):
        assert forbidden not in source


def test_l2_documentation_states_current_ingestion_boundary() -> None:
    document = (
        PROJECT_ROOT / "docs" / "en" / "reference" / "admission-notice-lite-v1.md"
    ).read_text(encoding="utf-8")

    for required in (
        "frame_1",
        "frame_2",
        "frame_3",
        "image/jpeg",
        "2,097,152",
        "1,920",
        "1,080",
        "2,073,600",
        "memory-only",
        "EXIF",
    ):
        assert required in document


def test_exact_l2_constants_are_frozen() -> None:
    assert MAX_ADMISSION_FRAMES_LITE_V1 == 3
    assert MAX_ENCODED_FRAME_BYTES_LITE_V1 == 2 * 1024 * 1024
    assert MAX_MULTIPART_BODY_BYTES_LITE_V1 == 6_356_992

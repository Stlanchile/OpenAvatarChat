from __future__ import annotations

# ruff: noqa: E402

import asyncio
import copy
import hashlib
import io
import json
import math
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from loguru import logger
from service.admission_notice_lite_chat_context import AdmissionContextV1
from PIL import Image

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SIDECAR_SOURCE = PROJECT_ROOT / "services" / "admission_notice_ocr" / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SIDECAR_SOURCE) not in sys.path:
    sys.path.insert(0, str(SIDECAR_SOURCE))

from admission_notice_ocr import provision_models, sidecar_qualify
from admission_notice_ocr.app import (
    OcrSidecarServer,
    SidecarStartupError,
    _write_ready_file,
)
from admission_notice_ocr.manifest import (
    BACKEND,
    DEVICE,
    PACKAGE_VERSIONS,
    PADDLE_CPU_WHEEL_SHA256,
    PADDLE_CPU_WHEEL_URL,
    RUNTIME_FLAGS,
    ManifestError,
    load_and_verify_manifest,
)
from admission_notice_ocr.pipeline import PipelineError, _convert_result, decode_frame
from admission_notice_ocr.protocol import (
    FRAME_PREFIX,
    MAX_HEADER_BYTES,
    MAX_JPEG_BYTES,
    MESSAGE_PREFIX,
    REQUEST_MAGIC,
    RESPONSE_MAGIC,
    SCHEMA_VERSION,
    ErrorCode,
    FrameRequest,
    ProtocolError,
    _decode_header,
    encode_error,
    encode_ocr,
    encode_ping,
    read_request,
)
from chat_engine.core.chat_session import ChatSession
from scripts import admission_notice_lite_l3_qualify as integration_qualify
from scripts.admission_notice_lite_l3_source_projection import (
    HISTORICAL_L3_COMMIT,
    L3_MAIN_SOURCE_PATHS,
    L3_QUALIFICATION_SOURCE_PATHS,
    L3_SIDECAR_SOURCE_PATHS,
    historical_l3_qualification_source_sha256,
    reconstruct_historical_l3_qualified_sources,
)
from service.admission_notice_lite_contracts import (
    MAX_OCR_AGGREGATE_CHARACTERS_PER_FRAME_LITE_V1,
    MAX_OCR_CHARACTERS_PER_SPAN_LITE_V1,
    AdmissionNoticeLiteError,
    OcrBatchLiteV1,
    OcrFrameLiteV1,
    OcrRuntimeIdentityLiteV1,
    OcrSpanLiteV1,
    RecognitionErrorReasonLiteV1,
    RecognitionJobContextLiteV1,
    RecognitionStateLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.admission_notice_lite_ingestion import _validate_admission_jpeg
from service.admission_notice_lite_ocr import (
    MAX_OCR_RESPONSE_BYTES_LITE_V1,
    AdmissionNoticeOcrClientLiteV1,
    AdmissionNoticeOcrErrorLiteV1,
    AdmissionNoticeOcrProcessorLiteV1,
    OcrFailureCodeLiteV1,
    _decode_json_object,
    _encode_ocr_request,
    _encode_ping_request,
    _parse_runtime_identity,
    build_qualified_admission_notice_ocr_processor_lite_v1,
)
from service.admission_notice_lite_service import AdmissionNoticeLiteService
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

APPROVED_MODEL_MANIFEST_SHA256 = (
    "1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b"
)
def _af_unix_blocker(directory: Path) -> str | None:
    socket_path = directory / "capability.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        return None
    except PermissionError:
        return "AF_UNIX_BIND_PERMISSION_DENIED"
    except OSError:
        return "AF_UNIX_BIND_UNAVAILABLE"
    finally:
        listener.close()
        try:
            node = socket_path.lstat()
        except (FileNotFoundError, OSError):
            pass
        else:
            if stat.S_ISSOCK(node.st_mode) and node.st_uid == os.geteuid():
                socket_path.unlink(missing_ok=True)


def _skip_if_af_unix_unavailable(directory: Path) -> None:
    blocker = _af_unix_blocker(directory)
    if blocker is not None:
        pytest.skip(f"BLOCKED: {blocker}")


@pytest.fixture
def af_unix_capability(tmp_path: Path) -> None:
    _skip_if_af_unix_unavailable(tmp_path)


def requires_af_unix(function):
    marked = pytest.mark.usefixtures("af_unix_capability")(function)
    return pytest.mark.admission_notice_ocr_af_unix(marked)


def _jpeg(
    *,
    width: int = 32,
    height: int = 24,
    orientation: int = 1,
) -> bytes:
    output = io.BytesIO()
    image = Image.new("RGB", (width, height), "white")
    exif = Image.Exif()
    if orientation != 1:
        exif[274] = orientation
    image.save(output, format="JPEG", exif=exif)
    return output.getvalue()


def _validated_frame(
    frame_index: int = 1,
    *,
    width: int = 32,
    height: int = 24,
    orientation: int = 1,
) -> ValidatedAdmissionFrameLiteV1:
    return _validate_admission_jpeg(
        frame_index=frame_index,
        jpeg_bytes=_jpeg(
            width=width,
            height=height,
            orientation=orientation,
        ),
    )


def _span(
    text: str = "synthetic",
    *,
    score: float = 0.75,
) -> OcrSpanLiteV1:
    return OcrSpanLiteV1(
        text=text,
        polygon=((0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)),
        score=score,
    )


def _identity(
    manifest_sha256: str = "a" * 64,
    *,
    thread_count: int = 2,
    paddle_version: str = "3.3.0",
    paddleocr_version: str = "3.7.0",
    paddlex_version: str = "3.7.2",
) -> OcrRuntimeIdentityLiteV1:
    return OcrRuntimeIdentityLiteV1(
        backend="paddle_static",
        device="cpu",
        thread_count=thread_count,
        paddle_version=paddle_version,
        paddleocr_version=paddleocr_version,
        paddlex_version=paddlex_version,
        model_manifest_sha256=manifest_sha256,
    )


def _identity_json(manifest_sha256: str = "a" * 64) -> dict[str, str | int]:
    identity = _identity(manifest_sha256)
    return {
        "backend": identity.backend,
        "device": identity.device,
        "model_manifest_sha256": identity.model_manifest_sha256,
        "paddle_version": identity.paddle_version,
        "paddleocr_version": identity.paddleocr_version,
        "paddlex_version": identity.paddlex_version,
        "thread_count": identity.thread_count,
    }


def _response(
    value: dict[str, Any] | None = None,
    *,
    payload: bytes | None = None,
    magic: bytes = RESPONSE_MAGIC,
    version: int = SCHEMA_VERSION,
    declared_length: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    if payload is None:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    length = len(payload) if declared_length is None else declared_length
    return MESSAGE_PREFIX.pack(magic, version, length) + payload + trailing


def _valid_ocr_response(
    frame_count: int,
    *,
    text: str = "synthetic",
) -> bytes:
    return _response(
        {
            "frames": [
                {
                    "frame_index": index,
                    "spans": [
                        {
                            "polygon": [
                                [0.0, 0.0],
                                [1.0, 0.0],
                                [1.0, 1.0],
                                [0.0, 1.0],
                            ],
                            "score": 0.75,
                            "text": text,
                        }
                    ],
                }
                for index in range(1, frame_count + 1)
            ],
            "schema_version": 1,
            "status": "ok",
        }
    )


async def _start_raw_server(
    socket_path: Path,
    handler,
) -> asyncio.AbstractServer:
    return await asyncio.start_unix_server(handler, path=str(socket_path))


async def _raw_exchange(socket_path: Path, request: bytes) -> bytes:
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    writer.write(request)
    await writer.drain()
    writer.write_eof()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return response


class _FakePipeline:
    def __init__(self) -> None:
        self.calls: list[tuple[int, ...]] = []

    def recognize(self, frames: tuple[FrameRequest, ...]) -> list[dict[str, Any]]:
        self.calls.append(tuple(frame.frame_index for frame in frames))
        return [
            {
                "frame_index": frame.frame_index,
                "spans": [
                    {
                        "polygon": [
                            [0.0, 0.0],
                            [1.0, 0.0],
                            [1.0, 1.0],
                            [0.0, 1.0],
                        ],
                        "score": 0.75,
                        "text": "synthetic",
                    }
                ],
            }
            for frame in frames
        ]


@pytest.mark.parametrize(
    "text",
    ("", " leading", "trailing ", "x\x00y", "x" * 513),
)
def test_ocr_span_rejects_empty_unstripped_nul_and_oversized_text(text: str) -> None:
    with pytest.raises(ValueError):
        _span(text)


@pytest.mark.parametrize("score", (math.nan, math.inf, -0.01, 1.01, True))
def test_ocr_span_rejects_invalid_raw_recognition_scores(score: float) -> None:
    with pytest.raises(ValueError):
        _span(score=score)


@pytest.mark.parametrize(
    "polygon",
    (
        (),
        ((0.0, 0.0),) * 3,
        ((0.0, 0.0),) * 5,
        ((0.0, 0.0, 0.0),) * 4,
        ((math.nan, 0.0),) * 4,
        ((-0.01, 0.0),) * 4,
        ((1.01, 0.0),) * 4,
    ),
)
def test_ocr_span_requires_four_finite_normalized_points(polygon) -> None:
    with pytest.raises(ValueError):
        OcrSpanLiteV1(text="x", polygon=polygon, score=0.5)


def test_ocr_frame_and_batch_are_bounded_unique_and_contiguous() -> None:
    valid = OcrFrameLiteV1(frame_index=1, spans=(_span(),))
    assert OcrBatchLiteV1(frames=(valid,)).frames == (valid,)

    with pytest.raises(ValueError):
        OcrFrameLiteV1(
            frame_index=1,
            spans=tuple(_span(str(index)) for index in range(129)),
        )
    aggregate_span = _span("x" * MAX_OCR_CHARACTERS_PER_SPAN_LITE_V1)
    with pytest.raises(ValueError):
        OcrFrameLiteV1(
            frame_index=1,
            spans=(aggregate_span,)
            * (
                MAX_OCR_AGGREGATE_CHARACTERS_PER_FRAME_LITE_V1
                // MAX_OCR_CHARACTERS_PER_SPAN_LITE_V1
                + 1
            ),
        )
    with pytest.raises(ValueError):
        OcrBatchLiteV1(
            frames=(
                OcrFrameLiteV1(1, ()),
                OcrFrameLiteV1(1, ()),
            )
        )
    with pytest.raises(ValueError):
        OcrBatchLiteV1(frames=(OcrFrameLiteV1(2, ()),))


def test_runtime_identity_is_small_fixed_cpu_diagnostic_summary() -> None:
    identity = _identity()
    assert set(identity.__dataclass_fields__) == {
        "backend",
        "device",
        "thread_count",
        "paddle_version",
        "paddleocr_version",
        "paddlex_version",
        "model_manifest_sha256",
    }
    with pytest.raises(ValueError):
        OcrRuntimeIdentityLiteV1(
            backend="auto",
            device="gpu:0",
            thread_count=4,
            paddle_version="3.3.0",
            paddleocr_version="3.7.0",
            paddlex_version="3.7.2",
            model_manifest_sha256="a" * 64,
        )


def test_protocol_json_rejects_duplicate_object_members() -> None:
    with pytest.raises(ProtocolError):
        _decode_header(b'{"schema_version":1,"operation":"ocr","operation":"ping"}')

    with pytest.raises(AdmissionNoticeOcrErrorLiteV1) as backend_error:
        _decode_json_object(b'{"schema_version":1,"status":"error","status":"ok"}')
    assert backend_error.value.code is OcrFailureCodeLiteV1.OCR_PROTOCOL_ERROR


@requires_af_unix
@pytest.mark.asyncio
async def test_backend_client_ping_and_one_to_three_frame_round_trip(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "fake.sock"
    observed = []

    async def handler(reader, writer) -> None:
        request = await read_request(reader)
        observed.append(request)
        if request.operation == "ping":
            writer.write(encode_ping(_identity_json()))
        else:
            writer.write(
                encode_ocr(
                    _FakePipeline().recognize(request.frames),
                )
            )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.5, 2.0)
    try:
        assert await client.ping() == _identity()
        for frame_count in (1, 2, 3):
            frames = tuple(
                _validated_frame(index) for index in range(1, frame_count + 1)
            )
            batch = await client.recognize(frames)
            assert tuple(frame.frame_index for frame in batch.frames) == tuple(
                range(1, frame_count + 1)
            )
    finally:
        server.close()
        await server.wait_closed()

    assert observed[0].operation == "ping"
    for request in observed[1:]:
        assert request.operation == "ocr"
        assert not hasattr(request, "recognition_id")
        assert not hasattr(request, "session_id")


@requires_af_unix
@pytest.mark.asyncio
async def test_backend_client_connect_failure_and_timeout_are_stable(
    tmp_path: Path,
) -> None:
    missing = AdmissionNoticeOcrClientLiteV1(
        str(tmp_path / "missing.sock"),
        0.05,
        0.1,
    )
    with pytest.raises(AdmissionNoticeOcrErrorLiteV1) as unavailable:
        await missing.ping()
    assert unavailable.value.code is OcrFailureCodeLiteV1.OCR_SERVICE_UNAVAILABLE

    socket_path = tmp_path / "timeout.sock"

    async def handler(reader, writer) -> None:
        await reader.read()
        await asyncio.sleep(1)
        writer.close()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.1, 0.05)
    try:
        with pytest.raises(AdmissionNoticeOcrErrorLiteV1) as timeout:
            await client.ping()
    finally:
        server.close()
        await server.wait_closed()
    assert timeout.value.code is OcrFailureCodeLiteV1.OCR_TIMEOUT


@pytest.mark.parametrize(
    "response",
    (
        b"",
        b"short",
        _response(
            {"schema_version": 1, "status": "ok", "runtime_identity": {}},
            magic=b"BAD!",
        ),
        _response(
            {"schema_version": 1, "status": "ok", "runtime_identity": {}},
            version=2,
        ),
        MESSAGE_PREFIX.pack(
            RESPONSE_MAGIC,
            SCHEMA_VERSION,
            MAX_OCR_RESPONSE_BYTES_LITE_V1 + 1,
        ),
        _response(payload=b"{"),
        _response({"schema_version": 2, "status": "ok", "runtime_identity": {}}),
        _response(
            {
                "schema_version": 1,
                "status": "ok",
                "runtime_identity": _identity_json(),
            },
            trailing=b"x",
        ),
    ),
)
@requires_af_unix
@pytest.mark.asyncio
async def test_backend_client_rejects_short_oversized_malformed_and_trailing_response(
    tmp_path: Path,
    response: bytes,
) -> None:
    socket_path = tmp_path / "bad-response.sock"

    async def handler(reader, writer) -> None:
        await reader.read()
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 1.0)
    try:
        with pytest.raises(AdmissionNoticeOcrErrorLiteV1):
            await client.ping()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.update(schema_version=2),
        lambda value: value["frames"].append(value["frames"][0]),
        lambda value: value["frames"].clear(),
        lambda value: value["frames"][0].update(frame_index=2),
        lambda value: value["frames"][0]["spans"][0].update(score=True),
        lambda value: value["frames"][0]["spans"][0].update(score=float("nan")),
        lambda value: value["frames"][0]["spans"][0].update(polygon=[[0, 0]] * 3),
        lambda value: value["frames"][0]["spans"][0].update(polygon=[[1.01, 0.0]] * 4),
        lambda value: value["frames"][0]["spans"][0].update(text="x" * 513),
        lambda value: value["frames"][0].update(
            spans=value["frames"][0]["spans"] * 129
        ),
    ),
)
@requires_af_unix
@pytest.mark.asyncio
async def test_backend_rejects_every_malformed_ocr_batch_shape(
    tmp_path: Path,
    mutate,
) -> None:
    value = json.loads(_valid_ocr_response(1)[MESSAGE_PREFIX.size :])
    mutate(value)
    payload = json.dumps(
        value,
        allow_nan=True,
        separators=(",", ":"),
    ).encode()
    response = (
        MESSAGE_PREFIX.pack(RESPONSE_MAGIC, SCHEMA_VERSION, len(payload)) + payload
    )
    socket_path = tmp_path / "invalid-result.sock"

    async def handler(reader, writer) -> None:
        await reader.read()
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 1.0)
    try:
        with pytest.raises(AdmissionNoticeOcrErrorLiteV1):
            await client.recognize((_validated_frame(),))
    finally:
        server.close()
        await server.wait_closed()


@requires_af_unix
@pytest.mark.asyncio
async def test_backend_client_cancellation_closes_connection(tmp_path: Path) -> None:
    socket_path = tmp_path / "cancel.sock"
    request_seen = asyncio.Event()
    disconnected = asyncio.Event()

    async def handler(reader, writer) -> None:
        await reader.read()
        request_seen.set()
        try:
            assert await reader.read() == b""
            await asyncio.sleep(1)
        finally:
            disconnected.set()
            writer.close()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 5.0)
    task = asyncio.create_task(client.recognize((_validated_frame(),)))
    try:
        await request_seen.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(disconnected.wait(), timeout=2)
    finally:
        server.close()
        await server.wait_closed()


@requires_af_unix
@pytest.mark.asyncio
async def test_real_sidecar_server_uses_only_af_unix_mode_0660_and_one_pipeline(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "sidecar.sock"
    pipeline = _FakePipeline()
    sidecar = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=pipeline,
        runtime_identity=_identity_json(),
    )
    await sidecar.start()
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 2.0)
    try:
        assert await client.ping() == _identity()
        for count in (1, 2, 3):
            frames = tuple(_validated_frame(index) for index in range(1, count + 1))
            assert len((await client.recognize(frames)).frames) == count
        assert sidecar._server is not None
        assert {sock.family for sock in sidecar._server.sockets or ()} == {
            socket.AF_UNIX
        }
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o660
    finally:
        await sidecar.close()
    assert pipeline.calls == [(1,), (1, 2), (1, 2, 3)]
    assert not socket_path.exists()


@pytest.mark.asyncio
async def test_sidecar_rejects_group_or_other_writable_socket_parent(
    tmp_path: Path,
) -> None:
    writable_parent = tmp_path / "writable-parent"
    writable_parent.mkdir(mode=0o770)
    writable_parent.chmod(0o770)
    socket_path = writable_parent / "unsafe.sock"
    sidecar = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=_FakePipeline(),
        runtime_identity=_identity_json(),
    )
    try:
        with pytest.raises(SidecarStartupError):
            await sidecar.start()
    finally:
        await sidecar.close()
    assert not socket_path.exists()


@requires_af_unix
@pytest.mark.asyncio
async def test_sidecar_shutdown_remains_bounded_during_native_inference(
    tmp_path: Path,
) -> None:
    class BlockingPipeline:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()
            self.finished = threading.Event()

        def recognize(self, frames):
            self.started.set()
            try:
                self.release.wait(timeout=5)
                return _FakePipeline().recognize(frames)
            finally:
                self.finished.set()

    socket_path = tmp_path / "bounded-shutdown.sock"
    pipeline = BlockingPipeline()
    sidecar = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=pipeline,
        runtime_identity=_identity_json(),
        shutdown_wait_seconds=0.05,
    )
    await sidecar.start()
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 5.0)
    request = asyncio.create_task(client.recognize((_validated_frame(),)))
    for _ in range(1_000):
        if pipeline.started.is_set():
            break
        await asyncio.sleep(0.001)
    assert pipeline.started.is_set()
    with pytest.raises(AdmissionNoticeOcrErrorLiteV1) as busy:
        await client.ping()
    assert busy.value.code is OcrFailureCodeLiteV1.OCR_SERVICE_UNAVAILABLE

    started_at = time.monotonic()
    await sidecar.close()
    elapsed = time.monotonic() - started_at
    assert elapsed < 0.5
    assert not socket_path.exists()

    pipeline.release.set()
    for _ in range(1_000):
        if pipeline.finished.is_set():
            break
        await asyncio.sleep(0.001)
    assert pipeline.finished.is_set()
    await asyncio.gather(request, return_exceptions=True)


def _raw_request(
    header: dict[str, Any],
    *,
    magic: bytes = REQUEST_MAGIC,
    version: int = SCHEMA_VERSION,
    header_length: int | None = None,
    binary: bytes = b"",
    trailing: bytes = b"",
) -> bytes:
    payload = json.dumps(header, separators=(",", ":")).encode()
    return (
        MESSAGE_PREFIX.pack(
            magic,
            version,
            len(payload) if header_length is None else header_length,
        )
        + payload
        + binary
        + trailing
    )


def _request_header(frame: ValidatedAdmissionFrameLiteV1) -> dict[str, Any]:
    return {
        "frame_count": 1,
        "frames": [
            {
                "encoded_size": frame.encoded_size,
                "exif_orientation": frame.exif_orientation,
                "frame_index": 1,
                "logical_height": frame.height,
                "logical_width": frame.width,
            }
        ],
        "operation": "ocr",
        "schema_version": 1,
    }


@pytest.mark.parametrize(
    "request_factory",
    (
        lambda frame: _raw_request(
            {"operation": "ping", "schema_version": 1},
            magic=b"BAD!",
        ),
        lambda frame: _raw_request(
            {"operation": "ping", "schema_version": 1},
            version=2,
        ),
        lambda frame: MESSAGE_PREFIX.pack(
            REQUEST_MAGIC,
            SCHEMA_VERSION,
            MAX_HEADER_BYTES + 1,
        ),
        lambda frame: MESSAGE_PREFIX.pack(REQUEST_MAGIC, SCHEMA_VERSION, 1) + b"{",
        lambda frame: _raw_request(
            {
                "operation": "ocr",
                "schema_version": 1,
                "frame_count": 1,
                "frames": [],
            }
        ),
        lambda frame: _raw_request(
            {
                **_request_header(frame),
                "frames": [
                    {
                        **_request_header(frame)["frames"][0],
                        "exif_orientation": 9,
                    }
                ],
            }
        ),
        lambda frame: _raw_request(
            _request_header(frame),
            binary=FRAME_PREFIX.pack(frame.encoded_size) + frame.jpeg_bytes[:-1],
        ),
        lambda frame: _raw_request(
            _request_header(frame),
            binary=FRAME_PREFIX.pack(frame.encoded_size + 1) + frame.jpeg_bytes,
        ),
        lambda frame: _raw_request(
            _request_header(frame),
            binary=FRAME_PREFIX.pack(frame.encoded_size) + frame.jpeg_bytes,
            trailing=b"x",
        ),
    ),
)
@requires_af_unix
@pytest.mark.asyncio
async def test_sidecar_rejects_bad_magic_version_bounds_truncation_and_trailing(
    tmp_path: Path,
    request_factory,
) -> None:
    socket_path = tmp_path / "sidecar-malformed.sock"
    sidecar = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=_FakePipeline(),
        runtime_identity=_identity_json(),
    )
    await sidecar.start()
    try:
        response = await _raw_exchange(
            socket_path,
            request_factory(_validated_frame()),
        )
    finally:
        await sidecar.close()
    value = json.loads(response[MESSAGE_PREFIX.size :])
    assert value == {
        "error_code": "OCR_PROTOCOL_ERROR",
        "schema_version": 1,
        "status": "error",
    }


@requires_af_unix
@pytest.mark.asyncio
async def test_disconnected_client_does_not_break_later_sidecar_ping(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "disconnect.sock"
    sidecar = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=_FakePipeline(),
        runtime_identity=_identity_json(),
    )
    await sidecar.start()
    _, writer = await asyncio.open_unix_connection(str(socket_path))
    writer.write(MESSAGE_PREFIX.pack(REQUEST_MAGIC, SCHEMA_VERSION, 100))
    await writer.drain()
    writer.close()
    await writer.wait_closed()
    await asyncio.sleep(0)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 1.0)
    try:
        assert await client.ping() == _identity()
    finally:
        await sidecar.close()


@requires_af_unix
@pytest.mark.asyncio
async def test_sidecar_replaces_only_its_owned_stale_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "stale.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(socket_path))
    stale.close()

    sidecar = OcrSidecarServer(
        socket_path=socket_path,
        pipeline=_FakePipeline(),
        runtime_identity=_identity_json(),
    )
    await sidecar.start()
    await sidecar.close()

    regular_path = tmp_path / "regular"
    regular_path.write_text("do not unlink", encoding="utf-8")
    unsafe = OcrSidecarServer(
        socket_path=regular_path,
        pipeline=_FakePipeline(),
        runtime_identity=_identity_json(),
    )
    with pytest.raises(SidecarStartupError):
        await unsafe.start()
    assert regular_path.read_text(encoding="utf-8") == "do not unlink"


def test_ready_file_is_published_complete_exclusively_and_privately(
    tmp_path: Path,
) -> None:
    ready_file = tmp_path / "ready.json"
    runtime_cache = tmp_path / "runtime-cache"
    _write_ready_file(
        ready_file,
        model_init_ms=1.0,
        startup_ms=2.0,
        thread_count=2,
        runtime_cache=runtime_cache,
    )
    ready = json.loads(ready_file.read_text(encoding="utf-8"))
    assert ready["pid"] == os.getpid()
    assert ready["model_init_ms"] == 1.0
    assert ready["startup_ms"] == 2.0
    assert stat.S_IMODE(ready_file.stat().st_mode) == 0o600

    with pytest.raises(SidecarStartupError):
        _write_ready_file(
            ready_file,
            model_init_ms=1.0,
            startup_ms=2.0,
            thread_count=2,
            runtime_cache=runtime_cache,
        )

    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    symlink_ready = tmp_path / "symlink-ready.json"
    symlink_ready.symlink_to(target)
    with pytest.raises(SidecarStartupError):
        _write_ready_file(
            symlink_ready,
            model_init_ms=1.0,
            startup_ms=2.0,
            thread_count=2,
            runtime_cache=runtime_cache,
        )
    assert target.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.parametrize("orientation", range(1, 9))
def test_sidecar_applies_explicit_orientation_and_checks_logical_dimensions(
    orientation: int,
) -> None:
    frame = _validated_frame(
        width=32,
        height=24,
        orientation=orientation,
    )
    request = FrameRequest(
        frame_index=1,
        encoded_size=frame.encoded_size,
        logical_width=frame.width,
        logical_height=frame.height,
        exif_orientation=orientation,
        jpeg_bytes=frame.jpeg_bytes,
    )
    decoded = decode_frame(request)
    assert (decoded.width, decoded.height) == (frame.width, frame.height)

    wrong = FrameRequest(
        frame_index=1,
        encoded_size=frame.encoded_size,
        logical_width=frame.width + 1,
        logical_height=frame.height,
        exif_orientation=orientation,
        jpeg_bytes=frame.jpeg_bytes,
    )
    with pytest.raises(PipelineError):
        decode_frame(wrong)


@pytest.mark.parametrize("text", ("", "synthetic"))
def test_sidecar_rejects_oversized_raw_paddle_candidates_before_iteration(
    text: str,
) -> None:
    class NoIteration(list):
        def __iter__(self):
            raise AssertionError("oversized raw output must not be traversed")

    class Result:
        json = {
            "res": {
                "rec_texts": NoIteration([text] * 129),
                "rec_scores": NoIteration([0.5] * 129),
                "rec_polys": NoIteration([[[0, 0], [1, 0], [1, 1], [0, 1]]] * 129),
            }
        }

    with pytest.raises(PipelineError):
        _convert_result(Result(), frame_index=1, width=1, height=1)


def test_qualification_latin_signal_requires_an_ascii_letter() -> None:
    punctuation_only = [
        {
            "frame_index": 1,
            "spans": [
                {
                    "polygon": [[0.0, 0.0]] * 4,
                    "score": 0.5,
                    "text": "[\\]^_`",
                }
            ],
        }
    ]
    with_letter = copy.deepcopy(punctuation_only)
    with_letter[0]["spans"][0]["text"] += "A"

    assert sidecar_qualify._functional_observation(punctuation_only)["latin"] is False
    assert sidecar_qualify._functional_observation(with_letter)["latin"] is True


def test_sidecar_qualification_rejects_duplicate_candidate_members(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        '{"schema_version":1,"result":"PASS","result":"FAIL"}',
        encoding="utf-8",
    )
    with pytest.raises(
        sidecar_qualify.QualificationBlocked,
        match="CANDIDATE_REPORT_UNAVAILABLE",
    ):
        sidecar_qualify._read_candidate_report(candidate)


def test_qualification_validates_the_frozen_production_thread_not_noisy_rank() -> None:
    production_candidate = {
        "cache_environment_match": True,
        "determinism": {
            "polygon_max_abs_delta": 0.0,
            "polygon_shape_stable": True,
            "score_max_abs_delta": 0.0,
            "score_shape_stable": True,
            "span_count_stable": True,
            "span_text_stable": True,
        },
        "error_count": 0,
        "first_inference_ms": 2_800.0,
        "isolated_cache_model_file_count": 0,
        "one_frame": {"p50_ms": 2_700.0},
        "result": "PASS",
        "three_frame": {"p95_ms": 8_500.0},
        "thread_count": 2,
        "thread_environment_match": True,
    }
    faster_candidate = {
        "one_frame": {"p50_ms": 2_100.0},
        "thread_count": 4,
    }

    assert (
        sidecar_qualify._select_thread(
            [production_candidate, faster_candidate],
            production_thread_count=2,
        )
        == 2
    )

    production_candidate["three_frame"]["p95_ms"] = 30_000.0
    with pytest.raises(
        sidecar_qualify.QualificationFailed,
        match="NO_STABLE_THREAD_CANDIDATE",
    ):
        sidecar_qualify._select_thread(
            [production_candidate, faster_candidate],
            production_thread_count=2,
        )

    production_candidate["three_frame"]["p95_ms"] = 8_500.0
    production_candidate["determinism"]["score_max_abs_delta"] = 0.000_000_001
    with pytest.raises(
        sidecar_qualify.QualificationFailed,
        match="NO_STABLE_THREAD_CANDIDATE",
    ):
        sidecar_qualify._select_thread(
            [production_candidate, faster_candidate],
            production_thread_count=2,
        )


def _write_test_manifest(root: Path, *, mutation=None) -> tuple[Path, Path]:
    model_root = root / "models"
    models = []
    identities = (
        (
            "text_detection",
            "PP-OCRv6_medium_det",
            "PP-OCRv6_medium_det_infer",
        ),
        (
            "text_recognition",
            "PP-OCRv6_medium_rec",
            "PP-OCRv6_medium_rec_infer",
        ),
    )
    for role, name, relative_path in identities:
        directory = model_root / relative_path
        directory.mkdir(parents=True)
        artifact = directory / "inference.bin"
        artifact.write_bytes(role.encode())
        payload = artifact.read_bytes()
        models.append(
            {
                "files": [
                    {
                        "path": artifact.name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                ],
                "name": name,
                "relative_path": relative_path,
                "role": role,
            }
        )
    value = {
        "backend": BACKEND,
        "device": DEVICE,
        "models": models,
        "package_versions": dict(PACKAGE_VERSIONS),
        "runtime_flags": dict(RUNTIME_FLAGS),
        "schema_version": 1,
        "thread_count": 4,
    }
    if mutation is not None:
        mutation(value)
    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path, model_root


def test_manifest_verifies_schema_files_hashes_and_fixed_cpu_tuple(
    tmp_path: Path,
) -> None:
    manifest_path, model_root = _write_test_manifest(tmp_path)
    verified = load_and_verify_manifest(
        manifest_path,
        model_root,
        verify_package_versions=False,
    )
    assert verified.thread_count == 4
    assert (
        verified.manifest_sha256
        == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )

    (model_root / "PP-OCRv6_medium_det_infer" / "inference.bin").write_bytes(b"bad")
    with pytest.raises(ManifestError):
        load_and_verify_manifest(
            manifest_path,
            model_root,
            verify_package_versions=False,
        )


def test_manifest_rejects_duplicate_json_members(tmp_path: Path) -> None:
    manifest_path, model_root = _write_test_manifest(tmp_path)
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        manifest_text.replace(
            '"thread_count": 4',
            '"thread_count": 2,\n  "thread_count": 4',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ManifestError):
        load_and_verify_manifest(
            manifest_path,
            model_root,
            verify_package_versions=False,
        )


def test_model_provisioner_defaults_to_approved_thread_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["admission-notice-ocr-provision"])
    args = provision_models._parse_args()

    assert provision_models.PRODUCTION_THREAD_COUNT == 2
    assert args.thread_count == 2
    assert provision_models._manifest_value(args.thread_count)["thread_count"] == 2


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.update(schema_version=2),
        lambda value: value.update(backend="auto"),
        lambda value: value.update(device="gpu:0"),
        lambda value: value.update(thread_count=3),
        lambda value: value["package_versions"].update(paddleocr="0"),
        lambda value: value["runtime_flags"].update(enable_hpi=True),
        lambda value: value.update(unexpected=True),
        lambda value: value["models"].reverse(),
    ),
)
def test_manifest_rejects_wrong_schema_runtime_packages_and_model_roles(
    tmp_path: Path,
    mutation,
) -> None:
    manifest_path, model_root = _write_test_manifest(tmp_path, mutation=mutation)
    with pytest.raises(ManifestError):
        load_and_verify_manifest(
            manifest_path,
            model_root,
            verify_package_versions=False,
        )


class _ClientStub:
    def __init__(
        self,
        *,
        batch: OcrBatchLiteV1 | None = None,
        failure: AdmissionNoticeOcrErrorLiteV1 | None = None,
    ):
        self.timeout_seconds = 30.0
        self.batch = batch or OcrBatchLiteV1(frames=(OcrFrameLiteV1(1, ()),))
        self.failure = failure
        self.called = asyncio.Event()
        self.release = asyncio.Event()
        self.block = False

    async def recognize(self, frames, *, timeout_seconds):
        del frames, timeout_seconds
        self.called.set()
        if self.block:
            await self.release.wait()
        if self.failure is not None:
            raise self.failure
        return self.batch


@pytest.mark.asyncio
async def test_processor_success_failure_and_cancellation_are_transient() -> None:
    context = RecognitionJobContextLiteV1(
        recognition_id="arn1_test",
        expires_at_monotonic=asyncio.get_running_loop().time() + 10,
        cancel_event=asyncio.Event(),
    )
    success_client = _ClientStub()
    await AdmissionNoticeOcrProcessorLiteV1(success_client).process(
        context,
        (_validated_frame(),),
    )

    failure_client = _ClientStub(
        failure=AdmissionNoticeOcrErrorLiteV1(OcrFailureCodeLiteV1.OCR_RUNTIME_ERROR)
    )
    with pytest.raises(AdmissionNoticeOcrErrorLiteV1):
        await AdmissionNoticeOcrProcessorLiteV1(failure_client).process(
            context,
            (_validated_frame(),),
        )

    blocked_client = _ClientStub()
    blocked_client.block = True
    task = asyncio.create_task(
        AdmissionNoticeOcrProcessorLiteV1(blocked_client).process(
            context,
            (_validated_frame(),),
        )
    )
    await blocked_client.called.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_ocr_text_never_enters_backend_logs_or_context() -> None:
    canary = "synthetic-ocr-canary"
    batch = OcrBatchLiteV1(frames=(OcrFrameLiteV1(1, (_span(canary),)),))
    client = _ClientStub(batch=batch)
    context = RecognitionJobContextLiteV1(
        recognition_id="arn1_log_test",
        expires_at_monotonic=asyncio.get_running_loop().time() + 10,
        cancel_event=asyncio.Event(),
    )
    messages: list[str] = []
    sink = logger.add(messages.append, format="{message}")
    try:
        await AdmissionNoticeOcrProcessorLiteV1(client).process(
            context,
            (_validated_frame(),),
        )
    finally:
        logger.remove(sink)
    assert canary not in "\n".join(messages)
    assert not hasattr(context, "ocr")
    assert not hasattr(context, "frames")


async def _create_service_job(
    *,
    client: AdmissionNoticeOcrClientLiteV1,
    frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
):
    owner = object.__new__(ChatSession)
    owner._initialize_admission_context_state()
    ocr_processor = AdmissionNoticeOcrProcessorLiteV1(client)

    class _QualifiedOcrServiceProjection:
        async def prepare_for_ingestion(self) -> bool:
            return await ocr_processor.prepare_for_ingestion()

        async def process(self, context, service_frames) -> AdmissionContextV1:
            await ocr_processor.process(context, service_frames)
            return AdmissionContextV1(
                schema_version="admission_context_v1",
                institution_name="湖北交通职业技术学院",
                college="交通信息学院",
                name=None,
                source_province=None,
                major="智能交通技术",
            )

    processor = _QualifiedOcrServiceProjection()
    service = AdmissionNoticeLiteService(
        config=AdmissionNoticeLiteFeatureConfigV1(enabled=True),
        session_lookup=lambda session_id: owner if session_id == "owner" else None,
        processor=processor,
    )
    permit = await service.begin_ingestion("owner")
    try:
        job = await service.create_recognition(permit, frames)
    finally:
        service.release_ingestion(permit)
    return service, job


async def _wait_service_terminal(
    service: AdmissionNoticeLiteService,
    recognition_id: str,
):
    for _ in range(400):
        snapshot = await service.get_recognition("owner", recognition_id)
        if snapshot.state not in {
            RecognitionStateLiteV1.CREATED,
            RecognitionStateLiteV1.PROCESSING,
        }:
            return snapshot
        await asyncio.sleep(0.005)
    pytest.fail("L3 service job did not terminate")


@pytest.mark.parametrize("frame_count", (1, 3))
@requires_af_unix
@pytest.mark.asyncio
async def test_real_processor_fake_uds_success_discards_batch_and_releases_frames(
    tmp_path: Path,
    frame_count: int,
) -> None:
    socket_path = tmp_path / "processor-success.sock"

    async def handler(reader, writer) -> None:
        await reader.read()
        writer.write(_valid_ocr_response(frame_count, text="private-canary"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await _start_raw_server(socket_path, handler)
    frames = tuple(_validated_frame(index) for index in range(1, frame_count + 1))
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 1.0)
    service, job = await _create_service_job(client=client, frames=frames)
    try:
        snapshot = await _wait_service_terminal(service, job.recognition_id)
        for _ in range(100):
            if service.resource_slot_count == 0:
                break
            await asyncio.sleep(0)
        assert snapshot.state is RecognitionStateLiteV1.COMPLETED
        assert service.retained_frame_count == 0
        assert service.resource_slot_count == 0
        assert not hasattr(snapshot, "ocr")
    finally:
        await service.shutdown()
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("mode", ("unavailable", "malformed", "timeout"))
@pytest.mark.asyncio
async def test_real_processor_fake_uds_failure_is_coarse_and_releases_capacity(
    tmp_path: Path,
    mode: str,
) -> None:
    socket_path = tmp_path / f"processor-{mode}.sock"
    server = None
    if mode != "unavailable":
        _skip_if_af_unix_unavailable(tmp_path)

        async def handler(reader, writer) -> None:
            await reader.read()
            if mode == "timeout":
                await asyncio.sleep(1)
            else:
                writer.write(_response(payload=b"{"))
                await writer.drain()
            writer.close()

        server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(
        str(socket_path),
        0.05,
        0.05 if mode == "timeout" else 1.0,
    )
    service, job = await _create_service_job(
        client=client,
        frames=(_validated_frame(),),
    )
    try:
        snapshot = await _wait_service_terminal(service, job.recognition_id)
        for _ in range(100):
            if service.resource_slot_count == 0:
                break
            await asyncio.sleep(0)
        assert snapshot.state is RecognitionStateLiteV1.FAILED
        assert snapshot.reason is not None
        assert snapshot.reason.value == "INTERNAL_ERROR"
        assert service.retained_frame_count == 0
        assert service.resource_slot_count == 0
    finally:
        await service.shutdown()
        if server is not None:
            server.close()
            await server.wait_closed()


@requires_af_unix
@pytest.mark.asyncio
async def test_transport_failure_restores_pre_ingestion_unavailable_gate_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_ocr as ocr_module

    test_manifest_hash = "d" * 64
    monkeypatch.setattr(
        ocr_module,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        test_manifest_hash,
    )
    socket_path = tmp_path / "readiness-retry.sock"
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.05, 1.0)
    service, job = await _create_service_job(
        client=client,
        frames=(_validated_frame(),),
    )
    server = None
    try:
        snapshot = await _wait_service_terminal(service, job.recognition_id)
        assert snapshot.state is RecognitionStateLiteV1.FAILED
        for _ in range(100):
            if service.resource_slot_count == 0:
                break
            await asyncio.sleep(0)

        with pytest.raises(AdmissionNoticeLiteError) as unavailable:
            await service.begin_ingestion("owner")
        assert (
            unavailable.value.reason is RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE
        )

        async def handler(reader, writer) -> None:
            request = await read_request(reader)
            assert request.operation == "ping"
            writer.write(encode_ping(_identity_json(test_manifest_hash)))
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await _start_raw_server(socket_path, handler)
        permit = await service.begin_ingestion("owner")
        service.release_ingestion(permit)
    finally:
        await service.shutdown()
        if server is not None:
            server.close()
            await server.wait_closed()


@requires_af_unix
@pytest.mark.asyncio
async def test_ocr_timeout_requires_readiness_ping_before_another_ingestion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_ocr as ocr_module

    manifest_hash = "e" * 64
    monkeypatch.setattr(
        ocr_module,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        manifest_hash,
    )
    socket_path = tmp_path / "timeout-readiness.sock"
    inference_started = asyncio.Event()
    inference_finished = asyncio.Event()

    async def handler(reader, writer) -> None:
        request = await read_request(reader)
        if request.operation == "ocr":
            inference_started.set()
            await inference_finished.wait()
        elif inference_finished.is_set():
            writer.write(encode_ping(_identity_json(manifest_hash)))
        else:
            writer.write(encode_error(ErrorCode.OCR_SERVICE_UNAVAILABLE))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.05, 0.05)
    service, job = await _create_service_job(
        client=client,
        frames=(_validated_frame(),),
    )
    try:
        await inference_started.wait()
        snapshot = await _wait_service_terminal(service, job.recognition_id)
        assert snapshot.state is RecognitionStateLiteV1.FAILED
        for _ in range(100):
            if service.resource_slot_count == 0:
                break
            await asyncio.sleep(0)

        with pytest.raises(AdmissionNoticeLiteError) as unavailable:
            await service.begin_ingestion("owner")
        assert (
            unavailable.value.reason is RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE
        )

        inference_finished.set()
        permit = await service.begin_ingestion("owner")
        service.release_ingestion(permit)
    finally:
        inference_finished.set()
        await service.shutdown()
        server.close()
        await server.wait_closed()


@requires_af_unix
@pytest.mark.asyncio
async def test_real_processor_fake_uds_cancellation_closes_wait_and_keeps_cancelled(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "processor-cancel.sock"
    received = asyncio.Event()
    disconnected = asyncio.Event()
    server_release = asyncio.Event()

    async def handler(reader, writer) -> None:
        await reader.read()
        received.set()
        try:
            await server_release.wait()
        finally:
            disconnected.set()
            writer.close()

    server = await _start_raw_server(socket_path, handler)
    client = AdmissionNoticeOcrClientLiteV1(str(socket_path), 0.2, 10.0)
    service, job = await _create_service_job(
        client=client,
        frames=(_validated_frame(),),
    )
    try:
        await received.wait()
        await service.cancel_recognition("owner", job.recognition_id)
        snapshot = await _wait_service_terminal(service, job.recognition_id)
        assert snapshot.state is RecognitionStateLiteV1.CANCELLED
        for _ in range(200):
            if service.resource_slot_count == 0:
                break
            await asyncio.sleep(0)
        assert service.resource_slot_count == 0
        assert service.retained_frame_count == 0
    finally:
        await service.shutdown()
        server_release.set()
        server.close()
        await server.wait_closed()
    await asyncio.wait_for(disconnected.wait(), timeout=2)


def test_production_builder_constructs_real_processor_for_approved_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_ocr as module

    config = AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        ocr_socket_path="/tmp/qualified.sock",
    )
    assert (
        module.QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1 == APPROVED_MODEL_MANIFEST_SHA256
    )
    monkeypatch.setattr(
        module.AdmissionNoticeOcrClientLiteV1,
        "ping_sync",
        lambda self: _identity(APPROVED_MODEL_MANIFEST_SHA256),
    )
    assert isinstance(
        build_qualified_admission_notice_ocr_processor_lite_v1(config),
        AdmissionNoticeOcrProcessorLiteV1,
    )


def test_production_builder_gate_none_is_unavailable_without_ping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_ocr as module

    monkeypatch.setattr(module, "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1", None)

    def unexpected_ping(self):
        del self
        raise AssertionError("disabled production gate must not ping the sidecar")

    monkeypatch.setattr(
        module.AdmissionNoticeOcrClientLiteV1,
        "ping_sync",
        unexpected_ping,
    )
    config = AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        ocr_socket_path="/tmp/qualified.sock",
    )
    assert build_qualified_admission_notice_ocr_processor_lite_v1(config) is None


def test_production_builder_wrong_gate_rejects_approved_sidecar_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_ocr as module

    monkeypatch.setattr(
        module,
        "QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1",
        "0" * 64,
    )
    monkeypatch.setattr(
        module.AdmissionNoticeOcrClientLiteV1,
        "ping_sync",
        lambda self: _identity(APPROVED_MODEL_MANIFEST_SHA256),
    )
    config = AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        ocr_socket_path="/tmp/qualified.sock",
    )
    assert build_qualified_admission_notice_ocr_processor_lite_v1(config) is None


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.update(
            model_manifest_sha256="0" * 64,
        ),
        lambda value: value.update(thread_count=4),
        lambda value: value.update(paddle_version="3.3.1"),
        lambda value: value.update(paddleocr_version="3.7.1"),
        lambda value: value.update(paddlex_version="3.7.1"),
        lambda value: value.update(backend="other_static"),
        lambda value: value.update(device="gpu:0"),
    ),
)
def test_production_builder_rejects_every_runtime_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    mutate,
) -> None:
    import service.admission_notice_lite_ocr as module

    identity = _identity_json(APPROVED_MODEL_MANIFEST_SHA256)
    mutate(identity)

    def ping(self):
        del self
        return _parse_runtime_identity(identity)

    monkeypatch.setattr(
        module.AdmissionNoticeOcrClientLiteV1,
        "ping_sync",
        ping,
    )
    config = AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        ocr_socket_path="/tmp/qualified.sock",
    )
    assert build_qualified_admission_notice_ocr_processor_lite_v1(config) is None


def test_production_builder_missing_sidecar_remains_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import service.admission_notice_lite_ocr as module

    def unavailable(self):
        del self
        raise AdmissionNoticeOcrErrorLiteV1(
            OcrFailureCodeLiteV1.OCR_SERVICE_UNAVAILABLE
        )

    monkeypatch.setattr(
        module.AdmissionNoticeOcrClientLiteV1,
        "ping_sync",
        unavailable,
    )
    config = AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        ocr_socket_path="/tmp/missing-qualified.sock",
    )
    assert build_qualified_admission_notice_ocr_processor_lite_v1(config) is None


def test_backend_protocol_has_no_paddle_import_and_l3_has_no_l4_surface() -> None:
    backend_path = PROJECT_ROOT / "src" / "service" / "admission_notice_lite_ocr.py"
    backend_source = backend_path.read_text(encoding="utf-8").lower()
    assert "import paddle" not in backend_source
    assert "from paddle" not in backend_source

    production_paths = (
        backend_path,
        PROJECT_ROOT / "src" / "service" / "admission_notice_lite_contracts.py",
        PROJECT_ROOT / "services" / "admission_notice_ocr" / "src",
    )
    source_parts = []
    for path in production_paths:
        if path.is_dir():
            source_parts.extend(
                child.read_text(encoding="utf-8")
                for child in sorted(path.rglob("*.py"))
            )
        else:
            source_parts.append(path.read_text(encoding="utf-8"))
    source = "\n".join(source_parts).lower()
    for forbidden in (
        "hbtc_traffic_information",
        "major_catalog",
        "field_extractor",
        "chatagent",
        "chat_agent",
        "securityenvelope",
        "workfence",
        "capturecoordinator",
        "captureepoch",
        "aesgcm",
        "declassification",
    ):
        assert forbidden not in source


def test_protocol_request_is_bounded_and_contains_no_session_state() -> None:
    frames = tuple(_validated_frame(index) for index in (1, 2, 3))
    request = _encode_ocr_request(frames)
    assert len(request) < 3 * MAX_JPEG_BYTES + MAX_HEADER_BYTES + 64
    prefix = request[: MESSAGE_PREFIX.size]
    _, _, header_length = MESSAGE_PREFIX.unpack(prefix)
    header = json.loads(
        request[MESSAGE_PREFIX.size : MESSAGE_PREFIX.size + header_length]
    )
    assert set(header) == {
        "schema_version",
        "operation",
        "frame_count",
        "frames",
    }
    serialized = json.dumps(header).lower()
    for forbidden in (
        "session",
        "recognition",
        "student",
        "filename",
        "chat",
        "major",
        "college",
    ):
        assert forbidden not in serialized
    assert _encode_ping_request().startswith(REQUEST_MAGIC)


def test_locked_sidecar_is_cpu_only_and_root_environment_stays_paddle_free() -> None:
    root_pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    sidecar_pyproject = (
        PROJECT_ROOT / "services" / "admission_notice_ocr" / "pyproject.toml"
    ).read_text(encoding="utf-8")
    sidecar_lock = (
        PROJECT_ROOT / "services" / "admission_notice_ocr" / "uv.lock"
    ).read_text(encoding="utf-8")

    for package in ("paddlepaddle", "paddleocr", "paddlex"):
        assert f'"{package}' not in root_pyproject.lower()
    assert 'name = "paddlepaddle"' in sidecar_lock
    assert PADDLE_CPU_WHEEL_URL in sidecar_pyproject
    assert PADDLE_CPU_WHEEL_SHA256 in sidecar_pyproject
    assert PADDLE_CPU_WHEEL_URL in sidecar_lock
    assert f"sha256:{PADDLE_CPU_WHEEL_SHA256}" in sidecar_lock
    for forbidden in (
        'name = "paddlepaddle-gpu"',
        'name = "tensorrt"',
        'name = "openvino"',
        'name = "onnxruntime"',
        'name = "fastapi"',
        'name = "flask"',
        'name = "gradio"',
        'name = "uvicorn"',
    ):
        assert forbidden not in sidecar_lock.lower()


def _qualification_approval_matches(
    report: dict[str, Any],
    *,
    gate: str | None,
    source_sha256: str,
    manifest_sha256: str,
) -> bool:
    try:
        gpu_observation = report["gpu_observation"]
        return (
            gate == manifest_sha256 == APPROVED_MODEL_MANIFEST_SHA256
            and report["schema_version"] == 2
            and report["result"] == "PASS"
            and report["qualification_source_sha256"] == source_sha256
            and report["model_manifest_sha256"] == manifest_sha256
            and report["backend"] == "paddle_static"
            and report["device"] == "cpu"
            and report["selected_thread_count"] == 2
            and report["manifest_thread_count"] == 2
            and report["selected"]["thread_count"] == 2
            and report["selected"]["compiled_with_cuda"] is False
            and report["af_unix_integration"]["passed"] is True
            and report["af_unix_integration"]["socket_family"] == "AF_UNIX"
            and report["production_processor_path"]["passed"] is True
            and report["production_processor_path"]["typed_batch_valid"] is True
            and report["production_processor_path"]["terminal_state"] == "COMPLETED"
            and report["clean_start_offline"]["passed"] is True
            and report["clean_start_offline"]["developer_cache_used"] is False
            and report["clean_start_offline"]["runtime_model_download"] is False
            and report["package_audit"]["paddle_cpu_wheel_lock_enforced"] is True
            and report["package_audit"]["paddle_cpu_wheel_sha256"]
            == PADDLE_CPU_WHEEL_SHA256
            and report["package_audit"]["paddle_package"] == "paddlepaddle"
            and report["package_audit"]["forbidden_packages"] == []
            and gpu_observation["sidecar_allocations"] == []
            and (
                not gpu_observation["available"]
                or gpu_observation["live_inference_sample_count"] > 0
            )
        )
    except (KeyError, TypeError):
        return False


def _preapproval_qualification_source_sha256() -> str:
    assert L3_SIDECAR_SOURCE_PATHS == integration_qualify._SIDECAR_SOURCE_PATHS
    assert L3_MAIN_SOURCE_PATHS == integration_qualify._MAIN_SOURCE_PATHS
    current_sources = {
        relative_path: (PROJECT_ROOT / relative_path).read_bytes()
        for relative_path in L3_QUALIFICATION_SOURCE_PATHS
    }
    historical_sources = {
        relative_path: subprocess.check_output(
            (
                "git",
                "show",
                f"{HISTORICAL_L3_COMMIT}:{relative_path}",
            ),
            cwd=PROJECT_ROOT,
        )
        for relative_path in L3_QUALIFICATION_SOURCE_PATHS
    }
    reconstructed = reconstruct_historical_l3_qualified_sources(
        current_sources=current_sources,
        historical_sources=historical_sources,
    )
    return historical_l3_qualification_source_sha256(reconstructed)


def test_manifest_qualification_artifact_and_approval_gate_are_consistent() -> None:
    import service.admission_notice_lite_ocr as ocr_module

    service_root = PROJECT_ROOT / "services" / "admission_notice_ocr"
    manifest_path = service_root / "model_manifest.json"
    report_path = service_root / "qualification" / "qualification.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert hashlib.sha256(manifest_bytes).hexdigest() == (
        "1de89743e56affd2a220ae90fa2ce383bc8856714400737a5e4828beb0cd012b"
    )
    assert manifest["backend"] == "paddle_static"
    assert manifest["device"] == "cpu"
    assert manifest["thread_count"] == 2
    assert len(manifest["models"]) == 2
    assert all(
        len(model["files"]) == 3
        and all(len(artifact["sha256"]) == 64 for artifact in model["files"])
        for model in manifest["models"]
    )
    serialized_manifest = json.dumps(manifest).lower()
    for forbidden in ("todo", "unknown", "example_hash", "placeholder"):
        assert forbidden not in serialized_manifest

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    source_sha256 = _preapproval_qualification_source_sha256()
    assert report["qualification_source_sha256"] == source_sha256
    assert (
        report["qualification_source_sha256"]
        != integration_qualify._qualification_source_sha256()
    )
    assert _qualification_approval_matches(
        report,
        gate=ocr_module.QUALIFIED_MODEL_MANIFEST_SHA256_LITE_V1,
        source_sha256=source_sha256,
        manifest_sha256=manifest_sha256,
    )
    assert report["package_audit"]["paddle_installed_record_files_verified"] > 0
    assert report["production_processor_path"]["frame_count"] == 3
    assert type(report["production_processor_path"]["builder_gate_enabled"]) is bool
    assert set(report["selected"]["determinism"]) == {
        "polygon_max_abs_delta",
        "polygon_shape_stable",
        "score_max_abs_delta",
        "score_shape_stable",
        "span_count_stable",
        "span_text_stable",
    }
    assert len(report["thread_candidates"]) == 5
    report_text = report_path.read_text(encoding="utf-8")
    for forbidden in ("/home/", "/mnt/", "private-fixtures", "rec_texts"):
        assert forbidden not in report_text


@pytest.mark.parametrize(
    ("mutation", "gate"),
    (
        (lambda report: None, None),
        (lambda report: None, "0" * 64),
        (
            lambda report: report.update(qualification_source_sha256="0" * 64),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.update(result="BLOCKED"),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.update(result="FAIL"),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.update(model_manifest_sha256="0" * 64),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.update(selected_thread_count=4),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.update(backend="other_static"),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.update(device="gpu"),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report["af_unix_integration"].update(passed=False),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report["production_processor_path"].update(passed=False),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
        (
            lambda report: report.clear(),
            APPROVED_MODEL_MANIFEST_SHA256,
        ),
    ),
)
def test_invalid_qualification_artifact_or_gate_cannot_satisfy_approval(
    mutation,
    gate: str | None,
) -> None:
    service_root = PROJECT_ROOT / "services" / "admission_notice_ocr"
    report = copy.deepcopy(
        json.loads(
            (service_root / "qualification" / "qualification.json").read_text(
                encoding="utf-8"
            )
        )
    )
    mutation(report)
    assert not _qualification_approval_matches(
        report,
        gate=gate,
        source_sha256=_preapproval_qualification_source_sha256(),
        manifest_sha256=APPROVED_MODEL_MANIFEST_SHA256,
    )


def test_l3_documentation_freezes_only_ocr_meaning_and_operations() -> None:
    document = (
        PROJECT_ROOT / "docs" / "en" / "reference" / "admission-notice-lite-v1.md"
    ).read_text(encoding="utf-8")
    readme = (
        PROJECT_ROOT / "services" / "admission_notice_ocr" / "README.md"
    ).read_text(encoding="utf-8")
    for required in (
        "AdmissionNoticeOcrClientLiteV1",
        "OcrSpanLiteV1",
        "OcrFrameLiteV1",
        "OcrBatchLiteV1",
        "paddle_static",
        "PP-OCRv6_medium_det",
        "PP-OCRv6_medium_rec",
        "mode `0660`",
        "COMPLETED",
        "does not mean",
        "No template/college matcher or field recognition",
        "currently records `PASS`",
        APPROVED_MODEL_MANIFEST_SHA256,
    ):
        assert required in document
    for required in (
        "uv sync",
        "provision_models",
        "--thread-count 2",
        "--verify-only",
        "admission_notice_ocr_integration",
        "admission_notice_ocr.qualify",
        "no outbound network",
        "mode `0660`",
        "production-approved runtime tuple",
        APPROVED_MODEL_MANIFEST_SHA256,
    ):
        assert required in readme

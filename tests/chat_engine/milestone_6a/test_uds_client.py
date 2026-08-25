from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from certificate_capture.contracts.common import canonical_json_bytes_v1
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    OcrPointV1,
    OcrSpanV1,
    processing_identity_sha256_v1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.ocr.client import (
    OcrSocketPolicyV1,
    OcrTimeoutsV1,
    OcrUdsClientV1,
)
from certificate_capture.ocr.protocol import (
    MAX_OCR_RESPONSE_BYTES_V1,
    OCR_FRAME_PREFIX_BYTES_V1,
    OCR_FRAME_PREFIX_V1,
    OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1,
    OCR_REQUEST_MAGIC_V1,
    OCR_RESPONSE_MAGIC_V1,
    OCR_UDS_PROTOCOL_VERSION_V1,
    OcrFailureReasonV1,
    OcrRequestV1,
    OcrServiceErrorV1,
    encode_ocr_response_frame_v1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkCancellationSignalV1
from tests.chat_engine.milestone_5a.conftest import (
    SYNTHETIC_SHA256_C_V1,
    synthetic_inference_identity_v1,
)


async def _read_request_frame_v1(reader):
    prefix = await reader.readexactly(OCR_FRAME_PREFIX_BYTES_V1)
    magic, metadata_length, payload_length = OCR_FRAME_PREFIX_V1.unpack(prefix)
    assert magic == OCR_REQUEST_MAGIC_V1
    metadata = await reader.readexactly(metadata_length)
    payload = await reader.readexactly(payload_length)
    return metadata, payload


async def _start_server_v1(
    socket_path: Path,
    handler,
):
    try:
        server = await asyncio.start_unix_server(handler, path=socket_path)
    except PermissionError:
        pytest.skip("execution sandbox prohibits local AF_UNIX bind")
    os.chmod(socket_path, 0o660)
    return server


def _client_v1(socket_path: Path, *, timeouts=None):
    identity = synthetic_inference_identity_v1()
    return OcrUdsClientV1(
        socket_policy=OcrSocketPolicyV1(path=socket_path),
        expected_identity=identity,
        expected_qualification_record_sha256=SYNTHETIC_SHA256_C_V1,
        timeouts=timeouts,
    )


def _capture_epoch_v1(controller):
    return CaptureEpochV1(
        session_epoch=controller.current_epoch_v1(),
        capture_id=new_uuid7_v1(),
        capture_seq=1,
    )


def _request_v1(capture_epoch, identity, jpeg_length):
    return OcrRequestV1(
        request_id=new_uuid7_v1(),
        frame_id=new_uuid7_v1(),
        capture_epoch=capture_epoch,
        operation_id=new_uuid7_v1(),
        inference_identity_expected=identity.inference_identity_sha256,
        preprocessing_identity_sha256_expected=(
            processing_identity_sha256_v1(identity.preprocessing)
        ),
        canonical_width=96,
        canonical_height=64,
        jpeg_length=jpeg_length,
    )


def _page_v1(request, identity):
    return OcrPageResultV1(
        result_id=new_uuid7_v1(),
        capture_epoch=request.capture_epoch,
        frame_id=request.frame_id,
        inference_identity_sha256=identity.inference_identity_sha256,
        preprocessing_identity=identity.preprocessing,
        spans=(
            OcrSpanV1(
                span_id=new_uuid7_v1(),
                text="私有 OCR",
                polygon=(
                    OcrPointV1(0.1, 0.1),
                    OcrPointV1(0.9, 0.1),
                    OcrPointV1(0.9, 0.2),
                    OcrPointV1(0.1, 0.2),
                ),
                raw_engine_score=0.8,
            ),
        ),
    )


@pytest.mark.asyncio
async def test_health_requires_exact_reviewed_processing_timeout(monkeypatch, tmp_path):
    identity = synthetic_inference_identity_v1()
    client = _client_v1(tmp_path / "unbound.sock")
    request_id = new_uuid7_v1()

    class WriterV1:
        def write(self, payload):
            assert payload

        async def drain(self):
            return None

    async def connect_v1(self):
        del self
        return object(), WriterV1()

    async def read_v1(self, reader):
        del self, reader
        return canonical_json_bytes_v1(
            {
                "healthy": True,
                "inference_identity": identity.canonical_object_v1(),
                "processing_timeout_seconds": 29.0,
                "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
                "qualification_record_sha256": SYNTHETIC_SHA256_C_V1,
                "request_id": str(request_id),
                "schema_version": OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1,
            }
        )

    async def close_v1(self, writer):
        del self, writer

    monkeypatch.setattr(OcrUdsClientV1, "_connect_v1", connect_v1)
    monkeypatch.setattr(OcrUdsClientV1, "_read_response_payload_v1", read_v1)
    monkeypatch.setattr(OcrUdsClientV1, "_close_writer_v1", close_v1)
    monkeypatch.setattr(
        "certificate_capture.ocr.client.new_uuid7_v1",
        lambda: request_id,
    )

    with pytest.raises(OcrServiceErrorV1) as mismatch:
        await client.health_v1()
    assert mismatch.value.reason is OcrFailureReasonV1.IDENTITY_MISMATCH


@pytest.mark.asyncio
async def test_health_and_ocr_exchange_use_private_exact_uds(tmp_path):
    socket_path = tmp_path / "ocr.sock"
    identity = synthetic_inference_identity_v1()
    request_holder: dict[str, OcrRequestV1] = {}
    observed_metadata: list[bytes] = []
    observed_payload_lengths: list[int] = []

    async def handler(reader, writer):
        metadata, payload = await _read_request_frame_v1(reader)
        observed_metadata.append(metadata)
        observed_payload_lengths.append(len(payload))
        if b'"operation":"HEALTH"' in metadata:
            response_payload = canonical_json_bytes_v1(
                {
                    "healthy": True,
                    "inference_identity": identity.canonical_object_v1(),
                    "processing_timeout_seconds": 30.0,
                    "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
                    "qualification_record_sha256": (SYNTHETIC_SHA256_C_V1),
                    "request_id": json.loads(metadata)["request_id"],
                    "schema_version": (OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1),
                }
            )
            response = (
                OCR_FRAME_PREFIX_V1.pack(
                    OCR_RESPONSE_MAGIC_V1,
                    len(response_payload),
                    0,
                )
                + response_payload
            )
        else:
            request = request_holder["request"]
            response = encode_ocr_response_frame_v1(
                request=request,
                result=_page_v1(request, identity),
            )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await _start_server_v1(socket_path, handler)
    client = _client_v1(socket_path)
    controller = SessionWorkControllerV1._create_for_test_v1()
    try:
        health = await client.health_v1()
        assert health.identity == identity
        jpeg = bytearray(b"\xff\xd8" + b"x" * 124 + b"\xff\xd9")
        request = _request_v1(
            _capture_epoch_v1(controller),
            identity,
            len(jpeg),
        )
        request_holder["request"] = request
        response_payload = await client.exchange_v1(
            request,
            jpeg,
            WorkCancellationSignalV1(),
        )

        assert jpeg == bytearray()
        assert response_payload
        assert observed_payload_lengths == [0, request.jpeg_length]
        request_metadata = observed_metadata[1].decode()
        assert "capture_capability" not in request_metadata
        assert "session_capability" not in request_metadata
        assert "access_token" not in request_metadata
        assert "authenticator" not in request_metadata
        assert await client.active_request_count_v1() == 0
    finally:
        await client.close_v1()
        server.close()
        await server.wait_closed()
        assert controller.shutdown()


@pytest.mark.asyncio
async def test_socket_permissions_are_fail_closed(tmp_path):
    socket_path = tmp_path / "ocr.sock"

    async def handler(reader, writer):
        del reader
        writer.close()

    server = await _start_server_v1(socket_path, handler)
    os.chmod(socket_path, 0o666)
    client = _client_v1(socket_path)
    try:
        with pytest.raises(OcrServiceErrorV1) as rejected:
            await client.health_v1()
        assert rejected.value.reason is OcrFailureReasonV1.SOCKET_REJECTED
    finally:
        await client.close_v1()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_missing_socket_is_stable_unavailable(tmp_path):
    client = _client_v1(tmp_path / "missing.sock")

    with pytest.raises(OcrServiceErrorV1) as unavailable:
        await client.health_v1()

    assert unavailable.value.reason is OcrFailureReasonV1.OCR_UNAVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize("response_kind", ["truncated", "oversized", "json"])
async def test_malformed_or_oversized_response_is_rejected_before_parse(
    tmp_path,
    response_kind,
):
    socket_path = tmp_path / "ocr.sock"

    async def handler(reader, writer):
        await _read_request_frame_v1(reader)
        if response_kind == "truncated":
            response = (
                OCR_FRAME_PREFIX_V1.pack(
                    OCR_RESPONSE_MAGIC_V1,
                    100,
                    0,
                )
                + b"{}"
            )
        elif response_kind == "oversized":
            response = OCR_FRAME_PREFIX_V1.pack(
                OCR_RESPONSE_MAGIC_V1,
                MAX_OCR_RESPONSE_BYTES_V1 + 1,
                0,
            )
        else:
            response = (
                OCR_FRAME_PREFIX_V1.pack(
                    OCR_RESPONSE_MAGIC_V1,
                    5,
                    0,
                )
                + b"{bad}"
            )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await _start_server_v1(socket_path, handler)
    client = _client_v1(socket_path)
    try:
        with pytest.raises(OcrServiceErrorV1) as malformed:
            await client.health_v1()
        assert malformed.value.reason is OcrFailureReasonV1.MALFORMED_RESPONSE
    finally:
        await client.close_v1()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_processing_timeout_is_bounded_and_payload_free(tmp_path):
    socket_path = tmp_path / "ocr.sock"
    finished = asyncio.Event()

    async def handler(reader, writer):
        try:
            await _read_request_frame_v1(reader)
            await asyncio.sleep(0.2)
            writer.close()
        finally:
            finished.set()

    server = await _start_server_v1(socket_path, handler)
    client = _client_v1(
        socket_path,
        timeouts=OcrTimeoutsV1(
            connect_seconds=0.05,
            write_seconds=0.05,
            processing_seconds=0.05,
            response_read_seconds=0.05,
        ),
    )
    try:
        with pytest.raises(OcrServiceErrorV1) as timeout:
            await client.health_v1()
        assert timeout.value.reason is OcrFailureReasonV1.PROCESSING_TIMEOUT
        assert "私有" not in str(timeout.value)
    finally:
        await client.close_v1()
        await finished.wait()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_ocr_processing_timeout_sends_opaque_cancel_request(
    tmp_path,
):
    socket_path = tmp_path / "ocr.sock"
    cancellation_seen = asyncio.Event()

    async def handler(reader, writer):
        metadata, _ = await _read_request_frame_v1(reader)
        request = json.loads(metadata)
        if request["operation"] == "CANCEL":
            cancellation_seen.set()
            writer.close()
            return
        assert request["operation"] == "OCR"
        await cancellation_seen.wait()
        writer.close()

    server = await _start_server_v1(socket_path, handler)
    client = _client_v1(
        socket_path,
        timeouts=OcrTimeoutsV1(
            connect_seconds=0.05,
            write_seconds=0.05,
            processing_seconds=0.05,
            response_read_seconds=0.05,
        ),
    )
    controller = SessionWorkControllerV1._create_for_test_v1()
    identity = synthetic_inference_identity_v1()
    jpeg = bytearray(b"\xff\xd8" + b"x" * 124 + b"\xff\xd9")
    request = _request_v1(
        _capture_epoch_v1(controller),
        identity,
        len(jpeg),
    )
    try:
        with pytest.raises(OcrServiceErrorV1) as timeout:
            await client.exchange_v1(
                request,
                jpeg,
                WorkCancellationSignalV1(),
            )
        assert timeout.value.reason is OcrFailureReasonV1.PROCESSING_TIMEOUT
        await asyncio.wait_for(cancellation_seen.wait(), timeout=0.5)
    finally:
        await client.close_v1()
        server.close()
        await server.wait_closed()
        assert controller.shutdown()

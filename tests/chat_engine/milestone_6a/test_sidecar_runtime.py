from __future__ import annotations

import asyncio
import importlib
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from chat_engine.security.ids import new_uuid7_v1
from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1


def _sidecar_app_v1(monkeypatch):
    root = Path(__file__).resolve().parents[3] / "services" / "certificate_ocr"
    monkeypatch.syspath_prepend(str(root))
    return importlib.import_module("certificate_ocr.app")


def test_sidecar_decode_matches_m4b_canonical_exif_orientation(
    monkeypatch,
):
    app = _sidecar_app_v1(monkeypatch)
    cv2 = importlib.import_module("cv2")
    numpy = importlib.import_module("numpy")
    pipeline = object.__new__(app.PaddleCpuPipelineV1)
    pipeline._cv2 = cv2
    pipeline._numpy = numpy
    buffer = synthetic_jpeg_v1(
        width=320,
        height=240,
        orientation=6,
    )

    image = pipeline._decode_v1(
        buffer,
        expected_width=240,
        expected_height=320,
    )

    assert image.shape == (320, 240, 3)
    del image


@pytest.mark.asyncio
async def test_sidecar_rejects_wrong_peer_before_reading_request(
    monkeypatch,
):
    app = _sidecar_app_v1(monkeypatch)

    class DeniedReaderV1:
        read_attempted = False

        async def readexactly(self, length):
            del length
            self.read_attempted = True
            raise AssertionError("unauthorized peer reached request read")

    class DeniedPeerSocketV1:
        def getsockopt(self, level, option, size):
            del level, option, size
            return struct.Struct("3i").pack(123, 2000, 2000)

    class DeniedWriterV1:
        def __init__(self):
            self.responses = bytearray()
            self.closed = False

        def get_extra_info(self, name):
            assert name == "socket"
            return DeniedPeerSocketV1()

        def write(self, payload):
            self.responses.extend(payload)

        async def drain(self):
            return None

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    reader = DeniedReaderV1()
    writer = DeniedWriterV1()
    runtime = SimpleNamespace(
        _expected_client_uid=1000,
        _expected_client_gid=1000,
    )

    await app.handle_connection_v1(runtime, reader, writer)

    assert not reader.read_attempted
    assert b"PROTOCOL_REJECTED" in writer.responses
    assert writer.closed


class _SyntheticPipelineV1:
    def __init__(self) -> None:
        self.call_count = 0

    def infer_v1(
        self,
        jpeg_buffer,
        *,
        expected_width,
        expected_height,
    ):
        del expected_width, expected_height
        self.call_count += 1
        jpeg_buffer.clear()
        return ()


def _request_v1(operation_id: object) -> dict[str, object]:
    return {
        "canonical_height": 1,
        "canonical_width": 1,
        "capture_epoch": {
            "capture_id": str(new_uuid7_v1()),
            "capture_seq": 1,
            "session_epoch": {
                "generation": 1,
                "session_instance_id": str(new_uuid7_v1()),
            },
        },
        "frame_id": str(new_uuid7_v1()),
        "inference_identity_expected": "a" * 64,
        "jpeg_length": 3,
        "operation": "OCR",
        "operation_id": str(operation_id),
        "preprocessing_identity_sha256_expected": "b" * 64,
        "protocol_version": "oac.private-ocr-uds.v1",
        "request_id": str(new_uuid7_v1()),
        "schema_version": "oac.ocr-request.v1",
    }


@pytest.mark.asyncio
async def test_timed_out_kernel_holds_single_inference_slot_until_exit(
    monkeypatch,
):
    app = _sidecar_app_v1(monkeypatch)
    manifest = SimpleNamespace(
        identity_sha256="a" * 64,
        preprocessing_identity_sha256="b" * 64,
        processing_timeout_seconds=0.05,
        identity={
            "preprocessing": {
                "configuration_sha256": "c" * 64,
                "implementation_version": "synthetic",
                "source_sha256": "d" * 64,
            }
        },
    )
    pipeline = _SyntheticPipelineV1()
    runtime = app.SidecarRuntimeV1(
        manifest,
        pipeline,
        expected_client_uid=0,
        expected_client_gid=0,
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    scheduled_count = 0

    async def controlled_to_thread(function, /, *args, **kwargs):
        nonlocal scheduled_count
        scheduled_count += 1
        entered.set()
        await release.wait()
        return function(*args, **kwargs)

    monkeypatch.setattr(app.asyncio, "to_thread", controlled_to_thread)
    first_operation = new_uuid7_v1()
    first_buffer = bytearray(b"jpg")

    first_response = await app._handle_ocr_v1(
        runtime=runtime,
        request=_request_v1(first_operation),
        jpeg_buffer=first_buffer,
    )

    assert b"OCR_FAILED" in first_response
    assert entered.is_set()
    assert scheduled_count == 1
    assert pipeline.call_count == 0
    assert first_buffer == bytearray(b"jpg")
    assert runtime._inference_slot.locked()
    assert str(first_operation) in runtime._cancellations

    second_buffer = bytearray(b"jpg")
    second_response = await app._handle_ocr_v1(
        runtime=runtime,
        request=_request_v1(new_uuid7_v1()),
        jpeg_buffer=second_buffer,
    )
    assert b"OCR_FAILED" in second_response
    assert scheduled_count == 1
    assert pipeline.call_count == 0
    assert not second_buffer

    release.set()
    for _ in range(200):
        if not runtime._inference_slot.locked() and not runtime._cancellations:
            break
        await asyncio.sleep(0.005)

    assert not runtime._inference_slot.locked()
    assert not runtime._cancellations
    assert not first_buffer
    assert pipeline.call_count == 1

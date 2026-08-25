"""Private UDS-only CPU OCR sidecar entry point."""

from __future__ import annotations

import asyncio
import hmac
import os
import signal
import socket
import stat
import struct
import threading
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Any

from certificate_ocr.manifest import (
    ManifestUnavailableV1,
    VerifiedManifestV1,
    load_verified_manifest_v1,
)
from certificate_ocr.pipeline import EngineSpanV1, PaddleCpuPipelineV1
from certificate_ocr.protocol import (
    MAX_OCR_JPEG_BYTES_V1,
    MAX_OCR_REQUEST_METADATA_BYTES_V1,
    OCR_FRAME_PREFIX_BYTES_V1,
    OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1,
    OCR_RESPONSE_SCHEMA_VERSION_V1,
    OCR_UDS_PROTOCOL_VERSION_V1,
    SidecarProtocolErrorV1,
    error_response_v1,
    new_uuid7_v1,
    parse_cancel_request_v1,
    parse_health_request_v1,
    parse_ocr_request_v1,
    response_frame_v1,
    strict_json_object_v1,
    unpack_request_prefix_v1,
)

REQUEST_READ_TIMEOUT_SECONDS_V1 = 5.0
RESPONSE_WRITE_TIMEOUT_SECONDS_V1 = 5.0
MAX_ACTIVE_CONNECTIONS_V1 = 4
OCR_SPAN_SCHEMA_VERSION_V1 = "oac.ocr-span.v1"
OCR_PAGE_RESULT_SCHEMA_VERSION_V1 = "oac.ocr-page-result.v1"
_PEER_CREDENTIALS_V1 = struct.Struct("3i")


class SidecarRuntimeV1:
    __slots__ = (
        "_cancellation_lock",
        "_cancellations",
        "_connection_slots",
        "_expected_client_gid",
        "_expected_client_uid",
        "_inference_slot",
        "manifest",
        "pipeline",
    )

    def __init__(
        self,
        manifest: VerifiedManifestV1,
        pipeline: PaddleCpuPipelineV1,
        *,
        expected_client_uid: int,
        expected_client_gid: int,
    ) -> None:
        for name, value in (
            ("expected_client_uid", expected_client_uid),
            ("expected_client_gid", expected_client_gid),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ManifestUnavailableV1(f"OCR {name} unavailable")
        self.manifest = manifest
        self.pipeline = pipeline
        self._expected_client_uid = expected_client_uid
        self._expected_client_gid = expected_client_gid
        self._cancellation_lock = threading.Lock()
        self._cancellations: dict[str, threading.Event] = {}
        self._inference_slot = asyncio.Semaphore(1)
        self._connection_slots = asyncio.Semaphore(MAX_ACTIVE_CONNECTIONS_V1)

    def register_operation_v1(self, operation_id: str) -> threading.Event:
        with self._cancellation_lock:
            if operation_id in self._cancellations:
                raise SidecarProtocolErrorV1("operation rejected")
            cancellation = threading.Event()
            self._cancellations[operation_id] = cancellation
            return cancellation

    def cancel_operation_v1(self, operation_id: str) -> None:
        with self._cancellation_lock:
            cancellation = self._cancellations.get(operation_id)
        if cancellation is not None:
            cancellation.set()

    def release_operation_v1(
        self,
        operation_id: str,
        cancellation: threading.Event,
    ) -> None:
        with self._cancellation_lock:
            if self._cancellations.get(operation_id) is cancellation:
                self._cancellations.pop(operation_id, None)


def _span_object_v1(span: EngineSpanV1) -> dict[str, object]:
    return {
        "polygon": [[float(point[0]), float(point[1])] for point in span.polygon],
        "raw_engine_score": float(span.raw_engine_score),
        "schema_version": OCR_SPAN_SCHEMA_VERSION_V1,
        "span_id": new_uuid7_v1(),
        "text": span.text,
    }


def _result_response_v1(
    *,
    runtime: SidecarRuntimeV1,
    request: dict[str, Any],
    spans: tuple[EngineSpanV1, ...],
) -> bytes:
    span_objects = [_span_object_v1(span) for span in spans]
    return response_frame_v1(
        {
            "operation": "OCR",
            "operation_id": request["operation_id"],
            "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
            "request_id": request["request_id"],
            "result": {
                "capture_epoch": request["capture_epoch"],
                "frame_id": request["frame_id"],
                "inference_identity_sha256": (runtime.manifest.identity_sha256),
                "preprocessing_identity": (runtime.manifest.identity["preprocessing"]),
                "result_id": new_uuid7_v1(),
                "schema_version": OCR_PAGE_RESULT_SCHEMA_VERSION_V1,
                "spans": span_objects,
            },
            "schema_version": OCR_RESPONSE_SCHEMA_VERSION_V1,
        }
    )


def _finish_detached_inference_v1(
    runtime: SidecarRuntimeV1,
    operation_id: str,
    cancellation: threading.Event,
    jpeg_buffer: bytearray,
    task: asyncio.Task[object],
) -> None:
    """Release a timed-out non-cancellable kernel only after it really exits."""

    try:
        result = task.result()
    except BaseException:  # noqa: BLE001, S110 - discard terminal task state
        pass
    else:
        del result
    finally:
        jpeg_buffer.clear()
        runtime.release_operation_v1(operation_id, cancellation)
        runtime._inference_slot.release()


async def _write_response_v1(
    writer: asyncio.StreamWriter,
    response: bytes,
) -> None:
    writer.write(response)
    try:
        await asyncio.wait_for(
            writer.drain(),
            timeout=RESPONSE_WRITE_TIMEOUT_SECONDS_V1,
        )
    except (TimeoutError, ConnectionError, OSError):
        return


async def _handle_ocr_v1(
    *,
    runtime: SidecarRuntimeV1,
    request: dict[str, Any],
    jpeg_buffer: bytearray,
) -> bytes:
    request_id = request["request_id"]
    operation_id = request["operation_id"]
    if not hmac.compare_digest(
        request["inference_identity_expected"],
        runtime.manifest.identity_sha256,
    ) or not hmac.compare_digest(
        request["preprocessing_identity_sha256_expected"],
        runtime.manifest.preprocessing_identity_sha256,
    ):
        jpeg_buffer.clear()
        return error_response_v1(
            request_id=request_id,
            reason_code="IDENTITY_MISMATCH",
        )
    cancellation = runtime.register_operation_v1(operation_id)
    inference_task: asyncio.Task[tuple[EngineSpanV1, ...]] | None = None
    inference_slot_acquired = False
    release_operation_on_exit = True
    clear_buffer_on_exit = True
    deadline = (
        asyncio.get_running_loop().time() + runtime.manifest.processing_timeout_seconds
    )
    try:
        if cancellation.is_set():
            return error_response_v1(
                request_id=request_id,
                reason_code="CANCELLED",
            )
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError
        await asyncio.wait_for(
            runtime._inference_slot.acquire(),
            timeout=remaining,
        )
        inference_slot_acquired = True
        if cancellation.is_set():
            return error_response_v1(
                request_id=request_id,
                reason_code="CANCELLED",
            )
        inference_task = asyncio.create_task(
            asyncio.to_thread(
                runtime.pipeline.infer_v1,
                jpeg_buffer,
                expected_width=request["canonical_width"],
                expected_height=request["canonical_height"],
            )
        )
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError
        spans = await asyncio.wait_for(
            asyncio.shield(inference_task),
            timeout=remaining,
        )
        if cancellation.is_set():
            del spans
            return error_response_v1(
                request_id=request_id,
                reason_code="CANCELLED",
            )
        try:
            return _result_response_v1(
                runtime=runtime,
                request=request,
                spans=spans,
            )
        finally:
            del spans
    except TimeoutError:
        cancellation.set()
        if inference_task is not None:
            release_operation_on_exit = False
            clear_buffer_on_exit = False
            inference_slot_acquired = False
            inference_task.add_done_callback(
                partial(
                    _finish_detached_inference_v1,
                    runtime,
                    operation_id,
                    cancellation,
                    jpeg_buffer,
                )
            )
        return error_response_v1(
            request_id=request_id,
            reason_code="OCR_FAILED",
        )
    except asyncio.CancelledError:
        cancellation.set()
        if inference_task is not None and not inference_task.done():
            release_operation_on_exit = False
            clear_buffer_on_exit = False
            inference_slot_acquired = False
            inference_task.add_done_callback(
                partial(
                    _finish_detached_inference_v1,
                    runtime,
                    operation_id,
                    cancellation,
                    jpeg_buffer,
                )
            )
        elif inference_task is not None:
            with suppress(BaseException):
                result = inference_task.result()
                del result
        raise
    finally:
        if clear_buffer_on_exit:
            jpeg_buffer.clear()
        if release_operation_on_exit:
            runtime.release_operation_v1(operation_id, cancellation)
        if inference_slot_acquired:
            runtime._inference_slot.release()


async def handle_connection_v1(
    runtime: SidecarRuntimeV1,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    request_id: str | None = None
    jpeg_buffer: bytearray | None = None
    acquired = False
    reading_paused = False
    try:
        peer_socket = writer.get_extra_info("socket")
        if peer_socket is None or not hasattr(socket, "SO_PEERCRED"):
            raise SidecarProtocolErrorV1("peer rejected")
        try:
            credentials = peer_socket.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                _PEER_CREDENTIALS_V1.size,
            )
            _, peer_uid, peer_gid = _PEER_CREDENTIALS_V1.unpack(credentials)
        except (OSError, struct.error):
            raise SidecarProtocolErrorV1("peer rejected") from None
        if (
            peer_uid != runtime._expected_client_uid
            or peer_gid != runtime._expected_client_gid
        ):
            raise SidecarProtocolErrorV1("peer rejected")
        transport = writer.transport
        transport.pause_reading()
        reading_paused = True
        try:
            await asyncio.wait_for(
                runtime._connection_slots.acquire(),
                timeout=0.05,
            )
            acquired = True
        except TimeoutError:
            await _write_response_v1(
                writer,
                error_response_v1(
                    request_id=None,
                    reason_code="OCR_UNAVAILABLE",
                ),
            )
            return
        transport.resume_reading()
        reading_paused = False
        prefix = await asyncio.wait_for(
            reader.readexactly(OCR_FRAME_PREFIX_BYTES_V1),
            timeout=REQUEST_READ_TIMEOUT_SECONDS_V1,
        )
        metadata_length, payload_length = unpack_request_prefix_v1(prefix)
        metadata_payload = await asyncio.wait_for(
            reader.readexactly(metadata_length),
            timeout=REQUEST_READ_TIMEOUT_SECONDS_V1,
        )
        metadata = strict_json_object_v1(
            metadata_payload,
            maximum_bytes=MAX_OCR_REQUEST_METADATA_BYTES_V1,
        )
        del metadata_payload
        operation = metadata.get("operation")
        if operation == "HEALTH":
            request_id = parse_health_request_v1(
                metadata,
                payload_length,
            )
            response = response_frame_v1(
                {
                    "healthy": True,
                    "inference_identity": runtime.manifest.identity,
                    "processing_timeout_seconds": (
                        runtime.manifest.processing_timeout_seconds
                    ),
                    "protocol_version": OCR_UDS_PROTOCOL_VERSION_V1,
                    "qualification_record_sha256": (
                        runtime.manifest.qualification_record_sha256
                    ),
                    "request_id": request_id,
                    "schema_version": (OCR_HEALTH_RESPONSE_SCHEMA_VERSION_V1),
                }
            )
        elif operation == "CANCEL":
            request_id, operation_id = parse_cancel_request_v1(
                metadata,
                payload_length,
            )
            runtime.cancel_operation_v1(operation_id)
            response = error_response_v1(
                request_id=request_id,
                reason_code="CANCELLED",
            )
        elif operation == "OCR":
            request = parse_ocr_request_v1(
                metadata,
                declared_payload_length=payload_length,
            )
            request_id = request["request_id"]
            jpeg_bytes = await asyncio.wait_for(
                reader.readexactly(payload_length),
                timeout=REQUEST_READ_TIMEOUT_SECONDS_V1,
            )
            jpeg_buffer = bytearray(jpeg_bytes)
            del jpeg_bytes
            response = await _handle_ocr_v1(
                runtime=runtime,
                request=request,
                jpeg_buffer=jpeg_buffer,
            )
            jpeg_buffer = None
        else:
            raise SidecarProtocolErrorV1("operation rejected")
        await _write_response_v1(writer, response)
    except (
        SidecarProtocolErrorV1,
        asyncio.IncompleteReadError,
        ConnectionError,
        OSError,
        TimeoutError,
    ):
        with suppress(Exception):
            await _write_response_v1(
                writer,
                error_response_v1(
                    request_id=request_id,
                    reason_code="PROTOCOL_REJECTED",
                ),
            )
    except Exception:  # noqa: BLE001 - stable payload-free service boundary
        with suppress(Exception):
            await _write_response_v1(
                writer,
                error_response_v1(
                    request_id=request_id,
                    reason_code="OCR_FAILED",
                ),
            )
    finally:
        if jpeg_buffer is not None:
            jpeg_buffer.clear()
        if reading_paused:
            with suppress(Exception):
                writer.transport.resume_reading()
        if acquired:
            runtime._connection_slots.release()
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


def _prepare_socket_path_v1(path: Path) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        details = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(details.st_mode) or details.st_uid != os.getuid():
        raise ManifestUnavailableV1("OCR socket path unavailable")
    path.unlink()


async def serve_v1(runtime: SidecarRuntimeV1, socket_path: Path) -> None:
    _prepare_socket_path_v1(socket_path)
    server = await asyncio.start_unix_server(
        lambda reader, writer: handle_connection_v1(
            runtime,
            reader,
            writer,
        ),
        path=socket_path,
        backlog=MAX_ACTIVE_CONNECTIONS_V1,
        limit=MAX_OCR_JPEG_BYTES_V1 + MAX_OCR_REQUEST_METADATA_BYTES_V1,
    )
    os.chmod(socket_path, 0o660)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(signal_number, stop.set)
    try:
        await stop.wait()
    finally:
        server.close()
        await server.wait_closed()
        with suppress(FileNotFoundError):
            socket_path.unlink()


async def run_v1() -> None:
    manifest_path = Path(
        os.environ.get(
            "OCR_MANIFEST_PATH",
            "/opt/certificate-ocr/models/model_manifest.json",
        )
    )
    model_root = Path(
        os.environ.get(
            "OCR_MODEL_ROOT",
            "/opt/certificate-ocr/models",
        )
    )
    socket_path = Path(
        os.environ.get(
            "OCR_SOCKET_PATH",
            "/run/openavatarchat-ocr/ocr.sock",
        )
    )
    manifest = load_verified_manifest_v1(
        manifest_path=manifest_path,
        model_root=model_root,
    )
    pipeline = PaddleCpuPipelineV1(manifest)
    pipeline.warmup_v1()
    try:
        expected_client_uid = int(
            os.environ["OCR_EXPECTED_CLIENT_UID"],
            10,
        )
        expected_client_gid = int(
            os.environ["OCR_EXPECTED_CLIENT_GID"],
            10,
        )
    except (KeyError, TypeError, ValueError):
        raise ManifestUnavailableV1("OCR peer identity unavailable") from None
    runtime = SidecarRuntimeV1(
        manifest,
        pipeline,
        expected_client_uid=expected_client_uid,
        expected_client_gid=expected_client_gid,
    )
    await serve_v1(runtime, socket_path)


def main() -> None:
    try:
        asyncio.run(run_v1())
    except (ManifestUnavailableV1, SidecarProtocolErrorV1):
        print("certificate OCR unavailable (READINESS_REJECTED)")
        raise SystemExit(78) from None
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception:  # noqa: BLE001 - stable payload-free startup boundary
        print("certificate OCR unavailable (STARTUP_FAILED)")
        raise SystemExit(78) from None


if __name__ == "__main__":
    main()

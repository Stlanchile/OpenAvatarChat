"""Standard-library-only private UDS client for the CPU OCR sidecar."""

from __future__ import annotations

import asyncio
import hmac
import math
import os
import socket
import stat
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from certificate_capture.contracts.inference import InferenceIdentityV1
from certificate_capture.ocr.protocol import (
    MAX_OCR_RESPONSE_BYTES_V1,
    OCR_FRAME_PREFIX_BYTES_V1,
    OCR_RESPONSE_MAGIC_V1,
    OcrCancelRequestV1,
    OcrFailureReasonV1,
    OcrHealthRequestV1,
    OcrHealthStatusV1,
    OcrRequestV1,
    OcrServiceErrorV1,
    parse_health_response_payload_v1,
    unpack_frame_prefix_v1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.work_fence import WorkCancellationSignalV1

_PEER_CREDENTIALS_STRUCT_V1 = struct.Struct("3i")
OCR_OWNER_POST_TRANSPORT_BUDGET_SECONDS_V1 = 5.0
MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1 = 420.0


@dataclass(frozen=True, slots=True)
class OcrTimeoutsV1:
    """Explicit provisional limits; production values require qualification."""

    connect_seconds: float = 1.0
    write_seconds: float = 5.0
    processing_seconds: float = 30.0
    response_read_seconds: float = 5.0

    def __post_init__(self) -> None:
        for name, value in (
            ("connect_seconds", self.connect_seconds),
            ("write_seconds", self.write_seconds),
            ("processing_seconds", self.processing_seconds),
            ("response_read_seconds", self.response_read_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.05 <= float(value) <= 300.0
            ):
                raise ValueError(f"{name} must be a bounded finite timeout")
            object.__setattr__(self, name, float(value))
        if self.work_fence_timeout_seconds_v1 > MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1:
            raise ValueError("OCR transport timeout budget is too large")

    @property
    def work_fence_timeout_seconds_v1(self) -> float:
        """Conservative root-fence budget including best-effort cancellation."""

        cancel_budget = (
            self.connect_seconds
            + min(1.0, self.write_seconds)
            + self.response_read_seconds
        )
        return (
            self.connect_seconds
            + self.write_seconds
            + self.processing_seconds
            + self.response_read_seconds
            + cancel_budget
            + OCR_OWNER_POST_TRANSPORT_BUDGET_SECONDS_V1
        )


@dataclass(frozen=True, slots=True)
class OcrSocketPolicyV1:
    path: Path
    expected_uid: int = field(default_factory=os.getuid)
    expected_gid: int = field(default_factory=os.getgid)
    maximum_permissions: int = 0o660

    def __post_init__(self) -> None:
        normalized = Path(self.path)
        if not normalized.is_absolute():
            raise ValueError("OCR UDS path must be absolute")
        if len(os.fsencode(normalized)) >= 100:
            raise ValueError("OCR UDS path exceeds the portable bound")
        for name, value in (
            ("expected_uid", self.expected_uid),
            ("expected_gid", self.expected_gid),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if (
            isinstance(self.maximum_permissions, bool)
            or not isinstance(self.maximum_permissions, int)
            or self.maximum_permissions < 0
            or self.maximum_permissions > 0o770
            or self.maximum_permissions & 0o007
        ):
            raise ValueError("OCR UDS permissions must deny all world access")
        object.__setattr__(self, "path", normalized)


@dataclass(frozen=True, slots=True)
class OcrDeploymentConfigV1:
    """Reviewed immutable owner configuration for one qualified sidecar."""

    socket_policy: OcrSocketPolicyV1
    expected_identity: InferenceIdentityV1
    expected_qualification_record_sha256: str
    timeouts: OcrTimeoutsV1

    def __post_init__(self) -> None:
        if not isinstance(self.socket_policy, OcrSocketPolicyV1):
            raise TypeError("socket_policy must be OcrSocketPolicyV1")
        if not isinstance(self.expected_identity, InferenceIdentityV1):
            raise TypeError("expected_identity must be InferenceIdentityV1")
        if not isinstance(self.timeouts, OcrTimeoutsV1):
            raise TypeError("timeouts must be OcrTimeoutsV1")
        qualification = self.expected_qualification_record_sha256
        if (
            not isinstance(qualification, str)
            or len(qualification) != 64
            or any(character not in "0123456789abcdef" for character in qualification)
        ):
            raise ValueError("expected qualification record must be a SHA-256 value")

    def create_client_v1(self) -> OcrUdsClientV1:
        return OcrUdsClientV1(
            socket_policy=self.socket_policy,
            expected_identity=self.expected_identity,
            expected_qualification_record_sha256=(
                self.expected_qualification_record_sha256
            ),
            timeouts=self.timeouts,
        )


class OcrTransportClientV1(Protocol):
    @property
    def expected_identity_v1(self) -> InferenceIdentityV1: ...

    @property
    def expected_qualification_record_sha256_v1(self) -> str: ...

    @property
    def work_fence_timeout_seconds_v1(self) -> float: ...

    async def health_v1(self) -> OcrHealthStatusV1: ...

    async def exchange_v1(
        self,
        request: OcrRequestV1,
        jpeg_buffer: bytearray,
        cancellation: WorkCancellationSignalV1,
    ) -> bytes: ...

    async def cancel_operation_v1(self, operation_id: uuid.UUID) -> None: ...

    async def close_v1(self) -> None: ...


class OcrUdsClientV1:
    """One-request-per-connection UDS client with strict peer authorization."""

    __slots__ = (
        "_active_lock",
        "_active_writers",
        "_closed",
        "_expected_identity",
        "_expected_qualification_record_sha256",
        "_socket_policy",
        "_timeouts",
    )

    def __init__(
        self,
        *,
        socket_policy: OcrSocketPolicyV1,
        expected_identity: InferenceIdentityV1,
        expected_qualification_record_sha256: str,
        timeouts: OcrTimeoutsV1 | None = None,
    ) -> None:
        if not isinstance(socket_policy, OcrSocketPolicyV1):
            raise TypeError("socket_policy must be OcrSocketPolicyV1")
        if not isinstance(expected_identity, InferenceIdentityV1):
            raise TypeError("expected_identity must be InferenceIdentityV1")
        if (
            not isinstance(expected_qualification_record_sha256, str)
            or len(expected_qualification_record_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_qualification_record_sha256
            )
        ):
            raise ValueError("expected qualification record must be a SHA-256 value")
        self._socket_policy = socket_policy
        self._expected_identity = expected_identity
        self._expected_qualification_record_sha256 = (
            expected_qualification_record_sha256
        )
        self._timeouts = timeouts or OcrTimeoutsV1()
        self._active_lock = asyncio.Lock()
        self._active_writers: dict[uuid.UUID, asyncio.StreamWriter] = {}
        self._closed = False

    @property
    def expected_identity_v1(self) -> InferenceIdentityV1:
        return self._expected_identity

    @property
    def expected_qualification_record_sha256_v1(self) -> str:
        return self._expected_qualification_record_sha256

    @property
    def work_fence_timeout_seconds_v1(self) -> float:
        return self._timeouts.work_fence_timeout_seconds_v1

    def _validate_socket_path_v1(self) -> None:
        try:
            details = os.lstat(self._socket_policy.path)
        except OSError:
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE) from None
        permissions = stat.S_IMODE(details.st_mode)
        if (
            not stat.S_ISSOCK(details.st_mode)
            or details.st_uid != self._socket_policy.expected_uid
            or details.st_gid != self._socket_policy.expected_gid
            or permissions & ~self._socket_policy.maximum_permissions
            or permissions & 0o007
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.SOCKET_REJECTED)

    def _validate_peer_v1(self, writer: asyncio.StreamWriter) -> None:
        peer_socket = writer.get_extra_info("socket")
        if peer_socket is None or not hasattr(socket, "SO_PEERCRED"):
            raise OcrServiceErrorV1(OcrFailureReasonV1.SOCKET_REJECTED)
        try:
            credentials = peer_socket.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                _PEER_CREDENTIALS_STRUCT_V1.size,
            )
            _, uid, gid = _PEER_CREDENTIALS_STRUCT_V1.unpack(credentials)
        except (OSError, struct.error):
            raise OcrServiceErrorV1(OcrFailureReasonV1.SOCKET_REJECTED) from None
        if (
            uid != self._socket_policy.expected_uid
            or gid != self._socket_policy.expected_gid
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.SOCKET_REJECTED)

    async def _connect_v1(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._closed:
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
        self._validate_socket_path_v1()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self._socket_policy.path),
                timeout=self._timeouts.connect_seconds,
            )
        except TimeoutError:
            raise OcrServiceErrorV1(OcrFailureReasonV1.CONNECT_TIMEOUT) from None
        except OSError:
            raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE) from None
        try:
            self._validate_peer_v1(writer)
        except BaseException:
            try:
                writer.close()
            except Exception:  # noqa: BLE001, S110 - peer stays rejected
                pass
            raise
        return reader, writer

    async def _read_response_payload_v1(
        self,
        reader: asyncio.StreamReader,
    ) -> bytes:
        try:
            prefix = await asyncio.wait_for(
                reader.readexactly(OCR_FRAME_PREFIX_BYTES_V1),
                timeout=self._timeouts.processing_seconds,
            )
        except TimeoutError:
            raise OcrServiceErrorV1(OcrFailureReasonV1.PROCESSING_TIMEOUT) from None
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
        try:
            response_length, trailing_payload_length = unpack_frame_prefix_v1(
                prefix,
                expected_magic=OCR_RESPONSE_MAGIC_V1,
                maximum_metadata_bytes=MAX_OCR_RESPONSE_BYTES_V1,
                maximum_payload_bytes=0,
            )
        except OcrServiceErrorV1:
            raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
        if trailing_payload_length != 0:
            raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE)
        try:
            response = await asyncio.wait_for(
                reader.readexactly(response_length),
                timeout=self._timeouts.response_read_seconds,
            )
            trailing = await asyncio.wait_for(
                reader.read(1),
                timeout=self._timeouts.response_read_seconds,
            )
        except TimeoutError:
            raise OcrServiceErrorV1(OcrFailureReasonV1.RESPONSE_TIMEOUT) from None
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE) from None
        if trailing:
            raise OcrServiceErrorV1(OcrFailureReasonV1.MALFORMED_RESPONSE)
        return response

    async def _close_writer_v1(
        self,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            writer.close()
        except (ConnectionError, OSError):
            return
        try:
            await asyncio.wait_for(
                writer.wait_closed(),
                timeout=self._timeouts.response_read_seconds,
            )
        except (TimeoutError, ConnectionError, OSError):
            return

    async def _register_writer_v1(
        self,
        operation_id: uuid.UUID,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._active_lock:
            if self._closed or operation_id in self._active_writers:
                raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE)
            self._active_writers[operation_id] = writer

    async def _unregister_writer_v1(
        self,
        operation_id: uuid.UUID,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._active_lock:
            if self._active_writers.get(operation_id) is writer:
                self._active_writers.pop(operation_id, None)

    async def _cancel_operation_best_effort_v1(
        self,
        operation_id: uuid.UUID,
    ) -> None:
        try:
            await self.cancel_operation_v1(operation_id)
        except BaseException:  # noqa: BLE001, S110 - caller failure is primary
            pass

    async def health_v1(self) -> OcrHealthStatusV1:
        request = OcrHealthRequestV1(request_id=new_uuid7_v1())
        reader, writer = await self._connect_v1()
        try:
            try:
                writer.write(request.frame_v1())
                await asyncio.wait_for(
                    writer.drain(),
                    timeout=self._timeouts.write_seconds,
                )
            except TimeoutError:
                raise OcrServiceErrorV1(OcrFailureReasonV1.WRITE_TIMEOUT) from None
            except (ConnectionError, OSError):
                raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE) from None
            response = await self._read_response_payload_v1(reader)
        finally:
            await self._close_writer_v1(writer)
        status = parse_health_response_payload_v1(
            response,
            request_id=request.request_id,
        )
        expected_hash = self._expected_identity.inference_identity_sha256
        if (
            not hmac.compare_digest(
                status.identity.inference_identity_sha256,
                expected_hash,
            )
            or not hmac.compare_digest(
                status.qualification_record_sha256,
                self._expected_qualification_record_sha256,
            )
            or not hmac.compare_digest(
                status.processing_timeout_seconds.hex(),
                self._timeouts.processing_seconds.hex(),
            )
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.IDENTITY_MISMATCH)
        return status

    async def exchange_v1(
        self,
        request: OcrRequestV1,
        jpeg_buffer: bytearray,
        cancellation: WorkCancellationSignalV1,
    ) -> bytes:
        if not isinstance(request, OcrRequestV1):
            raise TypeError("request must be OcrRequestV1")
        if (
            not isinstance(jpeg_buffer, bytearray)
            or len(jpeg_buffer) != request.jpeg_length
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.REQUEST_REJECTED)
        if not isinstance(cancellation, WorkCancellationSignalV1):
            jpeg_buffer.clear()
            raise TypeError("cancellation must be WorkCancellationSignalV1")
        if (
            request.inference_identity_expected
            != self._expected_identity.inference_identity_sha256
        ):
            jpeg_buffer.clear()
            raise OcrServiceErrorV1(OcrFailureReasonV1.IDENTITY_MISMATCH)

        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        response_task: asyncio.Task[bytes] | None = None
        cancellation_task: asyncio.Task[bool] | None = None
        request_started = False
        cancellation_sent = False
        try:
            reader, writer = await self._connect_v1()
            await self._register_writer_v1(request.operation_id, writer)
            try:
                request_started = True
                writer.write(request.frame_prefix_and_metadata_v1())
                writer.write(jpeg_buffer)
                await asyncio.wait_for(
                    writer.drain(),
                    timeout=self._timeouts.write_seconds,
                )
            except TimeoutError:
                raise OcrServiceErrorV1(OcrFailureReasonV1.WRITE_TIMEOUT) from None
            except (ConnectionError, OSError):
                raise OcrServiceErrorV1(OcrFailureReasonV1.OCR_UNAVAILABLE) from None
            finally:
                jpeg_buffer.clear()

            response_task = asyncio.create_task(self._read_response_payload_v1(reader))
            cancellation_task = asyncio.create_task(cancellation.wait_async())
            done, _ = await asyncio.wait(
                {response_task, cancellation_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if (
                cancellation_task in done
                and cancellation_task.result()
                and response_task not in done
            ):
                response_task.cancel()
                await self._cancel_operation_best_effort_v1(request.operation_id)
                cancellation_sent = True
                raise OcrServiceErrorV1(OcrFailureReasonV1.CANCELLED)
            return await response_task
        except OcrServiceErrorV1:
            if request_started and not cancellation_sent:
                await self._cancel_operation_best_effort_v1(request.operation_id)
                cancellation_sent = True
            raise
        except asyncio.CancelledError:
            if response_task is not None:
                response_task.cancel()
            if request_started and not cancellation_sent:
                await self._cancel_operation_best_effort_v1(request.operation_id)
            raise
        finally:
            jpeg_buffer.clear()
            if cancellation_task is not None:
                cancellation_task.cancel()
            if response_task is not None and not response_task.done():
                response_task.cancel()
            if writer is not None:
                await self._unregister_writer_v1(
                    request.operation_id,
                    writer,
                )
                await self._close_writer_v1(writer)

    async def cancel_operation_v1(self, operation_id: uuid.UUID) -> None:
        if not isinstance(operation_id, uuid.UUID):
            return
        async with self._active_lock:
            active = self._active_writers.get(operation_id)
        if active is not None:
            active.close()
        try:
            _, writer = await self._connect_v1()
        except OcrServiceErrorV1:
            return
        try:
            request = OcrCancelRequestV1(
                request_id=new_uuid7_v1(),
                operation_id=operation_id,
            )
            try:
                writer.write(request.frame_v1())
                await asyncio.wait_for(
                    writer.drain(),
                    timeout=min(1.0, self._timeouts.write_seconds),
                )
            except (TimeoutError, ConnectionError, OSError):
                return
        finally:
            await self._close_writer_v1(writer)

    async def close_v1(self) -> None:
        async with self._active_lock:
            self._closed = True
            writers = tuple(self._active_writers.values())
            self._active_writers.clear()
        for writer in writers:
            await self._close_writer_v1(writer)

    async def active_request_count_v1(self) -> int:
        async with self._active_lock:
            return len(self._active_writers)

    def __repr__(self) -> str:
        return "OcrUdsClientV1(<private-uds>)"


__all__ = [
    "MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1",
    "OCR_OWNER_POST_TRANSPORT_BUDGET_SECONDS_V1",
    "OcrDeploymentConfigV1",
    "OcrSocketPolicyV1",
    "OcrTimeoutsV1",
    "OcrTransportClientV1",
    "OcrUdsClientV1",
]

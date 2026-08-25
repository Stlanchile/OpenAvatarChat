"""Enabled-only authenticated private Milestone 4B HTTP routes."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Protocol, TypeVar

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ValidationError

from certificate_capture.api_models import (
    BeginCaptureRequestV1,
    BeginCaptureResponseV1,
    CaptureStatusResponseV1,
    EndCaptureRequestV1,
    EndCaptureResponseV1,
    FrameUploadResponseV1,
    SealCaptureRequestV1,
    SealResponseV1,
)
from certificate_capture.capabilities import CAPTURE_CAPABILITY_HEADER_V1
from certificate_capture.frame_ingress import (
    read_bounded_private_jpeg_v1,
    validate_private_jpeg_headers_v1,
    validate_private_jpeg_v1,
)
from certificate_capture.protocol import (
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
    FrameUploadPermitV1,
)
from certificate_capture.state import CaptureStateV1
from service.service_security.certificate_session_authority import (
    SessionOwnershipV1,
)
from service.service_security.certificate_session_control import (
    CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
    CertificateSessionControlRuntimeV1,
    apply_certificate_no_store_headers_v1,
    certificate_control_http_error_v1,
    require_certificate_control_authorization_v1,
    require_certificate_session_ownership_v1,
)

_MAX_CONTROL_REQUEST_BYTES_V1 = 4096
_CONTROL_REQUEST_READ_TIMEOUT_SECONDS_V1 = 5.0
_CAPTURE_ROUTE_RUNTIME_ATTRIBUTE_V1 = "certificate_capture_routes_v1"


class _CaptureSessionResolverV1(Protocol):
    def _resolve_certificate_capture_session_v1(
        self,
        ownership: SessionOwnershipV1,
    ) -> object | None:
        """Return the exact live application session for trusted ownership."""


@dataclass(frozen=True, slots=True, repr=False)
class CertificateCaptureRoutesRuntimeV1:
    resolver: _CaptureSessionResolverV1

    def __repr__(self) -> str:
        return "CertificateCaptureRoutesRuntimeV1(<redacted>)"


RequestModelV1 = TypeVar("RequestModelV1", bound=BaseModel)


def install_certificate_capture_routes_v1(
    app: FastAPI,
    resolver: _CaptureSessionResolverV1,
) -> CertificateCaptureRoutesRuntimeV1 | None:
    """Mount exactly the five private routes in enabled mode."""

    if not getattr(
        app.state,
        CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
        False,
    ):
        return None
    control_runtime = getattr(
        app.state,
        "certificate_session_control_v1",
        None,
    )
    if not isinstance(control_runtime, CertificateSessionControlRuntimeV1):
        raise TypeError("certificate session control unavailable")
    if getattr(app.state, _CAPTURE_ROUTE_RUNTIME_ATTRIBUTE_V1, None) is not None:
        raise RuntimeError("certificate capture routes already installed")
    resolve = getattr(
        resolver,
        "_resolve_certificate_capture_session_v1",
        None,
    )
    if not callable(resolve):
        raise TypeError("certificate capture session resolver unavailable")

    runtime = CertificateCaptureRoutesRuntimeV1(resolver=resolver)
    setattr(app.state, _CAPTURE_ROUTE_RUNTIME_ATTRIBUTE_V1, runtime)

    async def authorized_session_v1(
        request: Request,
        session_id: str,
    ) -> tuple[object, SessionOwnershipV1]:
        principal = await require_certificate_control_authorization_v1(
            app,
            request,
        )
        if principal is None:
            raise certificate_control_http_error_v1(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "AUTHENTICATION_UNAVAILABLE",
            )
        ownership = require_certificate_session_ownership_v1(
            app,
            request,
            principal,
            session_id,
        )
        session = runtime.resolver._resolve_certificate_capture_session_v1(
            ownership
        )
        if session is None:
            raise _capture_http_error_v1(
                CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
            )
        return session, ownership

    @app.post(
        "/api/v1/sessions/{session_id}/certificate-captures",
        status_code=status.HTTP_201_CREATED,
        response_model=BeginCaptureResponseV1,
    )
    async def begin_capture_v1(
        session_id: str,
        request: Request,
        response: Response,
    ) -> BeginCaptureResponseV1:
        session, ownership = await authorized_session_v1(
            request,
            session_id,
        )
        control = await _read_control_request_v1(
            request,
            BeginCaptureRequestV1,
        )
        try:
            grant = await session._begin_certificate_capture_protocol_v1(
                request_id=control.request_id,
                control_seq=control.control_seq,
                profile_id=control.profile_id,
                ownership=ownership,
            )
        except CaptureProtocolErrorV1 as exception:
            raise _capture_http_error_v1(exception.reason) from None
        apply_certificate_no_store_headers_v1(response)
        return BeginCaptureResponseV1(
            capture_id=grant.capture_epoch.capture_id,
            capture_seq=grant.capture_epoch.capture_seq,
            session_generation=grant.capture_epoch.session_epoch.generation,
            state=CaptureStateV1.ARMED,
            capture_capability=grant.capture_capability,
            expires_at_epoch_seconds=grant.expires_at_epoch_seconds,
        )

    @app.put(
        (
            "/api/v1/sessions/{session_id}/certificate-captures/"
            "{capture_id}/frames/{frame_seq}"
        ),
        response_model=FrameUploadResponseV1,
    )
    async def upload_frame_v1(
        session_id: str,
        capture_id: str,
        frame_seq: str,
        request: Request,
        response: Response,
    ) -> FrameUploadResponseV1:
        session, ownership = await authorized_session_v1(
            request,
            session_id,
        )
        parsed_capture_id = _parse_capture_id_v1(capture_id)
        parsed_frame_seq = _parse_frame_seq_v1(frame_seq)
        capture_capability = _extract_capture_capability_v1(request)
        permit: FrameUploadPermitV1 | None = None
        body: bytearray | None = None
        try:
            permit = await session._admit_certificate_frame_upload_v1(
                capture_id=parsed_capture_id,
                frame_seq=parsed_frame_seq,
                capture_capability=capture_capability,
                ownership=ownership,
            )
            validate_private_jpeg_headers_v1(request)
            body = await read_bounded_private_jpeg_v1(
                request,
                cancelled_v1=lambda: permit.registered_work.cancellation.is_cancelled,
            )
            if permit.registered_work.cancellation.is_cancelled:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            # Pillow decode is synchronous but strictly bounded to 2 MiB and
            # 2,073,600 pixels. Keeping it in the request task avoids an
            # uncancellable worker retaining frame bytes after disconnect.
            validated = validate_private_jpeg_v1(body)
            if permit.registered_work.cancellation.is_cancelled:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
                )
            result = await session._commit_certificate_frame_upload_v1(
                permit,
                validated,
                body,
            )
        except CaptureProtocolErrorV1 as exception:
            raise _capture_http_error_v1(exception.reason) from None
        finally:
            if body is not None:
                body.clear()
            if permit is not None:
                session._release_certificate_frame_upload_v1(permit)
        apply_certificate_no_store_headers_v1(response)
        return FrameUploadResponseV1(
            capture_id=result.capture_id,
            capture_seq=result.capture_seq,
            frame_seq=result.frame_seq,
            state=result.state,
            encoded_size=result.encoded_size,
            decoded_width=result.decoded_width,
            decoded_height=result.decoded_height,
            accepted_frame_count=result.accepted_frame_count,
            remaining_frame_slots=result.remaining_frame_slots,
            total_accepted_bytes=result.total_accepted_bytes,
        )

    @app.post(
        (
            "/api/v1/sessions/{session_id}/certificate-captures/"
            "{capture_id}/seal"
        ),
        response_model=SealResponseV1,
    )
    async def seal_capture_v1(
        session_id: str,
        capture_id: str,
        request: Request,
        response: Response,
    ) -> SealResponseV1:
        session, ownership = await authorized_session_v1(
            request,
            session_id,
        )
        parsed_capture_id = _parse_capture_id_v1(capture_id)
        capture_capability = _extract_capture_capability_v1(request)
        control = await _read_control_request_v1(
            request,
            SealCaptureRequestV1,
        )
        try:
            result = await session._seal_certificate_capture_protocol_v1(
                request_id=control.request_id,
                control_seq=control.control_seq,
                capture_id=parsed_capture_id,
                capture_capability=capture_capability,
                ownership=ownership,
            )
        except CaptureProtocolErrorV1 as exception:
            raise _capture_http_error_v1(exception.reason) from None
        apply_certificate_no_store_headers_v1(response)
        return SealResponseV1(
            seal_attempt_seq=result.seal_attempt_seq,
            outcome=result.outcome,
            capture_state=result.capture_state,
            accepted_frame_count=result.accepted_frame_count,
            independent_correlation_groups=(
                result.independent_correlation_groups
            ),
            remaining_frame_slots=result.remaining_frame_slots,
            reason_codes=result.reason_codes,
            restart_required=result.restart_required,
        )

    @app.get(
        (
            "/api/v1/sessions/{session_id}/certificate-captures/"
            "{capture_id}"
        ),
        response_model=CaptureStatusResponseV1,
    )
    async def capture_status_v1(
        session_id: str,
        capture_id: str,
        request: Request,
        response: Response,
    ) -> CaptureStatusResponseV1:
        session, ownership = await authorized_session_v1(
            request,
            session_id,
        )
        parsed_capture_id = _parse_capture_id_v1(capture_id)
        capture_capability = _extract_capture_capability_v1(request)
        try:
            result = await session._certificate_capture_public_status_v1(
                capture_id=parsed_capture_id,
                capture_capability=capture_capability,
                ownership=ownership,
            )
        except CaptureProtocolErrorV1 as exception:
            raise _capture_http_error_v1(exception.reason) from None
        apply_certificate_no_store_headers_v1(response)
        return CaptureStatusResponseV1(
            capture_id=result.capture_id,
            capture_seq=result.capture_seq,
            state=result.state,
            accepted_frame_count=result.accepted_frame_count,
            remaining_frame_slots=result.remaining_frame_slots,
            total_accepted_bytes=result.total_accepted_bytes,
            independent_correlation_groups=(
                result.independent_correlation_groups
            ),
            inactivity_expires_at_epoch_seconds=(
                result.inactivity_expires_at_epoch_seconds
            ),
            last_seal_outcome=result.last_seal_outcome,
            reason_codes=result.reason_codes,
            restart_required=result.restart_required,
        )

    @app.post(
        (
            "/api/v1/sessions/{session_id}/certificate-captures/"
            "{capture_id}/end"
        ),
        response_model=EndCaptureResponseV1,
    )
    async def end_capture_v1(
        session_id: str,
        capture_id: str,
        request: Request,
        response: Response,
    ) -> EndCaptureResponseV1:
        session, ownership = await authorized_session_v1(
            request,
            session_id,
        )
        parsed_capture_id = _parse_capture_id_v1(capture_id)
        capture_capability = _extract_capture_capability_v1(request)
        control = await _read_control_request_v1(
            request,
            EndCaptureRequestV1,
        )
        try:
            result = await session._end_certificate_capture_protocol_v1(
                request_id=control.request_id,
                control_seq=control.control_seq,
                capture_id=parsed_capture_id,
                capture_capability=capture_capability,
                ownership=ownership,
            )
        except CaptureProtocolErrorV1 as exception:
            raise _capture_http_error_v1(exception.reason) from None
        apply_certificate_no_store_headers_v1(response)
        return EndCaptureResponseV1(
            capture_id=result.capture_id,
            capture_seq=result.capture_seq,
            session_generation=result.session_generation,
            state=result.state,
        )

    return runtime


async def _read_control_request_v1(
    request: Request,
    model: type[RequestModelV1],
) -> RequestModelV1:
    content_types = request.headers.getlist("Content-Type")
    if (
        len(content_types) != 1
        or content_types[0].partition(";")[0].strip().casefold()
        != "application/json"
    ):
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.INVALID_REQUEST
        )
    content_lengths = request.headers.getlist("Content-Length")
    if len(content_lengths) > 1:
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.INVALID_REQUEST
        )
    if content_lengths:
        raw_length = content_lengths[0]
        if (
            not raw_length
            or len(raw_length) > 10
            or not raw_length.isascii()
            or not raw_length.isdecimal()
            or int(raw_length, 10) > _MAX_CONTROL_REQUEST_BYTES_V1
        ):
            raise _capture_http_error_v1(
                CaptureProtocolReasonV1.INVALID_REQUEST
            )

    body = bytearray()
    try:
        async with asyncio.timeout(
            _CONTROL_REQUEST_READ_TIMEOUT_SECONDS_V1
        ):
            async for chunk in request.stream():
                if len(body) + len(chunk) > _MAX_CONTROL_REQUEST_BYTES_V1:
                    raise ValueError
                body.extend(chunk)
        decoded = json.loads(
            bytes(body),
            object_pairs_hook=_unique_json_object_v1,
        )
        return model.model_validate(decoded)
    except asyncio.CancelledError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
        TypeError,
        RecursionError,
        TimeoutError,
    ):
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.INVALID_REQUEST
        ) from None
    except Exception:  # noqa: BLE001 - body transport errors stay redacted
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.INVALID_REQUEST
        ) from None
    finally:
        body.clear()


def _unique_json_object_v1(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError
        output[key] = value
    return output


def _parse_capture_id_v1(value: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
        ) from None
    if (
        str(parsed) != value
        or parsed.variant != uuid.RFC_4122
        or parsed.version != 7
    ):
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
        )
    return parsed


def _parse_frame_seq_v1(value: str) -> int:
    if (
        not value
        or len(value) > 1
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.FRAME_SEQUENCE_INVALID
        )
    parsed = int(value, 10)
    if not 1 <= parsed <= 8:
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.FRAME_SEQUENCE_INVALID
        )
    return parsed


def _extract_capture_capability_v1(request: Request) -> str:
    values = request.headers.getlist(CAPTURE_CAPABILITY_HEADER_V1)
    if len(values) != 1:
        raise _capture_http_error_v1(
            CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED
        )
    return values[0]


def _capture_http_error_v1(
    reason: CaptureProtocolReasonV1,
):
    status_by_reason = {
        CaptureProtocolReasonV1.INVALID_REQUEST: status.HTTP_400_BAD_REQUEST,
        CaptureProtocolReasonV1.SESSION_LIFETIME_INSUFFICIENT: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.CAPTURE_ACCESS_DENIED: (
            status.HTTP_404_NOT_FOUND
        ),
        CaptureProtocolReasonV1.CAPTURE_BUSY: status.HTTP_409_CONFLICT,
        CaptureProtocolReasonV1.CAPTURE_STATE_INVALID: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.CAPTURE_EXPIRED: status.HTTP_404_NOT_FOUND,
        CaptureProtocolReasonV1.CONTROL_SEQUENCE_STALE: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.CONTROL_SEQUENCE_GAP: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.IDEMPOTENCY_CONFLICT: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.CONTROL_CAPACITY_EXCEEDED: (
            status.HTTP_429_TOO_MANY_REQUESTS
        ),
        CaptureProtocolReasonV1.CONTROL_BUSY: (
            status.HTTP_429_TOO_MANY_REQUESTS
        ),
        CaptureProtocolReasonV1.UPLOAD_BUSY: (
            status.HTTP_429_TOO_MANY_REQUESTS
        ),
        CaptureProtocolReasonV1.FRAME_SEQUENCE_INVALID: (
            status.HTTP_400_BAD_REQUEST
        ),
        CaptureProtocolReasonV1.FRAME_SEQUENCE_CONFLICT: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.FRAME_LIMIT_REACHED: (
            status.HTTP_409_CONFLICT
        ),
        CaptureProtocolReasonV1.CAPTURE_BYTE_LIMIT_REACHED: (
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        ),
        CaptureProtocolReasonV1.JPEG_REQUIRED: (
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        ),
        CaptureProtocolReasonV1.FRAME_TOO_LARGE: (
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        ),
        CaptureProtocolReasonV1.JPEG_INVALID: status.HTTP_400_BAD_REQUEST,
        CaptureProtocolReasonV1.JPEG_DIMENSIONS_EXCEEDED: (
            status.HTTP_400_BAD_REQUEST
        ),
        CaptureProtocolReasonV1.FRAME_BODY_UNAVAILABLE: (
            status.HTTP_400_BAD_REQUEST
        ),
        CaptureProtocolReasonV1.PROCESSOR_NOT_READY: (
            status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        CaptureProtocolReasonV1.CAPTURE_FAILED_CLOSED: (
            status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED: (
            status.HTTP_503_SERVICE_UNAVAILABLE
        ),
    }
    return certificate_control_http_error_v1(
        status_by_reason.get(
            reason,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        ),
        reason.value,
    )


__all__ = [
    "CertificateCaptureRoutesRuntimeV1",
    "install_certificate_capture_routes_v1",
]

"""Milestone 1D-B authenticated RTC signaling contract.

Initial ``POST /webrtc/offer`` requests carry an OIDC bearer token,
``X-OpenAvatar-RTC-Session-V1``, and ``X-OpenAvatar-RTC-Admission-V1``.
Only an SDP offer and transport-only ``webrtc_id`` are accepted in the JSON
body. Data-channel-only offers are rejected; at least one pinned FastRTC media
callback must be bound. The successful answer returns a one-peer
``rtc_transport_binding``.

Subsequent ICE requests use the same route with the OIDC bearer token and
``X-OpenAvatar-RTC-Transport-V1``. Session and admission-ticket headers are
forbidden on ICE requests. No credential is accepted from URLs, SDP, ICE,
data-channel messages, or application metadata.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import logging
import math
import re
import secrets
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Literal, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from service.service_security.certificate_session_authority import (
    ConsumedSessionAdmissionV1,
    SessionAdmissionChannelV1,
    SessionAuthorityErrorV1,
    SessionAuthorityReasonV1,
    session_admission_ownership_matches_v1,
)
from service.service_security.certificate_session_control import (
    CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
    CertificateSessionControlRuntimeV1,
)
from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
)
from service.service_utils.ssl_helpers import CertificateCaptureStartupError

if TYPE_CHECKING:
    from service.rtc_service.rtc_stream import RtcStream


RTC_SIGNALING_ROUTE_V1 = "/webrtc/offer"
RTC_SESSION_ID_HEADER_V1 = "X-OpenAvatar-RTC-Session-V1"
RTC_ADMISSION_TICKET_HEADER_V1 = "X-OpenAvatar-RTC-Admission-V1"
RTC_TRANSPORT_BINDING_HEADER_V1 = "X-OpenAvatar-RTC-Transport-V1"
RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1 = "rtc_transport_binding"
RTC_LEGACY_ALTERNATE_SIGNALING_ROUTES_V1 = frozenset(
    {
        "/telephone/handler",
        "/telephone/incoming",
        "/websocket/offer",
    }
)

RTC_SIGNALING_MAX_REQUEST_BYTES_V1 = 256 * 1024
RTC_SIGNALING_MAX_SDP_CHARACTERS_V1 = 192 * 1024
RTC_SIGNALING_MAX_CANDIDATE_CHARACTERS_V1 = 8 * 1024
RTC_SIGNALING_MAX_TRANSPORT_ID_CHARACTERS_V1 = 128
RTC_SIGNALING_READ_TIMEOUT_SECONDS_V1 = 5
RTC_OFFER_TIMEOUT_SECONDS_V1 = 30
RTC_CANDIDATE_TIMEOUT_SECONDS_V1 = 5
RTC_MAX_ACTIVE_TRANSPORT_BINDINGS_V1 = 1024

_AUTHORIZATION_HEADER_V1 = "Authorization"
_MAX_AUTHORIZATION_HEADER_CHARACTERS_V1 = 16 * 1024
_SESSION_ID_PATTERN_V1 = re.compile(r"^cs1_[A-Za-z0-9_-]{43}$")
_ADMISSION_TICKET_PATTERN_V1 = re.compile(r"^att1_[A-Za-z0-9_-]{43}$")
_TRANSPORT_BINDING_PREFIX_V1 = "rtb1_"
_TRANSPORT_BINDING_PATTERN_V1 = re.compile(r"^rtb1_[A-Za-z0-9_-]{43}$")
_INTERNAL_TRANSPORT_ID_PREFIX_V1 = "rti1_"
_TRANSPORT_ID_PATTERN_V1 = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_ACCESS_LOG_OPAQUE_VALUE_PATTERN_V1 = re.compile(
    r"(?:att1_|ati1_|csc1_|cs1_|rtb1_|rti1_)[A-Za-z0-9_-]{43}"
)
_NO_STORE_HEADERS_V1 = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class RtcAdmissionReasonV1(str, Enum):
    AUTHENTICATION_REQUIRED = "RTC_AUTHENTICATION_REQUIRED"
    AUTHENTICATION_FAILED = "RTC_AUTHENTICATION_FAILED"
    AUTHENTICATION_UNAVAILABLE = "RTC_AUTHENTICATION_UNAVAILABLE"
    SIGNALING_REQUEST_INVALID = "RTC_SIGNALING_REQUEST_INVALID"
    ADMISSION_CREDENTIAL_REQUIRED = "RTC_ADMISSION_CREDENTIAL_REQUIRED"
    ADMISSION_CREDENTIAL_INVALID = "RTC_ADMISSION_CREDENTIAL_INVALID"
    ADMISSION_DENIED = "RTC_ADMISSION_DENIED"
    TRANSPORT_BINDING_REQUIRED = "RTC_TRANSPORT_BINDING_REQUIRED"
    TRANSPORT_BINDING_INVALID = "RTC_TRANSPORT_BINDING_INVALID"
    TRANSPORT_BINDING_DENIED = "RTC_TRANSPORT_BINDING_DENIED"
    TRANSPORT_CONFLICT = "RTC_TRANSPORT_CONFLICT"
    AUTHORITY_UNAVAILABLE = "RTC_ADMISSION_AUTHORITY_UNAVAILABLE"
    PEER_CONSTRUCTION_FAILED = "RTC_PEER_CONSTRUCTION_FAILED"
    SIGNALING_FAILED = "RTC_SIGNALING_FAILED"


class RtcAdmissionErrorV1(RuntimeError):
    """Stable, credential-free failure returned by the RTC admission wrapper."""

    __slots__ = ("reason_code", "status_code")

    def __init__(
        self,
        reason: RtcAdmissionReasonV1,
        *,
        status_code: int,
    ):
        self.reason_code = reason.value
        self.status_code = status_code
        super().__init__(f"RTC admission failed ({self.reason_code}).")


class RtcIceCandidateV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    candidate: str = Field(
        min_length=1,
        max_length=RTC_SIGNALING_MAX_CANDIDATE_CHARACTERS_V1,
    )
    sdpMid: str | None = Field(default=None, max_length=256)
    sdpMLineIndex: int | None = Field(default=None, ge=0, le=65_535)
    usernameFragment: str | None = Field(default=None, max_length=256)


class RtcSignalingRequestV1(BaseModel):
    """Strict subset of the pinned FastRTC 0.0.34 HTTP signaling body."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    sdp: str | None = Field(
        default=None,
        max_length=RTC_SIGNALING_MAX_SDP_CHARACTERS_V1,
    )
    candidate: RtcIceCandidateV1 | None = None
    type: Literal["offer", "ice-candidate"]
    webrtc_id: str = Field(
        min_length=1,
        max_length=RTC_SIGNALING_MAX_TRANSPORT_ID_CHARACTERS_V1,
    )

    @model_validator(mode="after")
    def validate_signaling_shape(self) -> RtcSignalingRequestV1:
        if _TRANSPORT_ID_PATTERN_V1.fullmatch(self.webrtc_id) is None:
            raise ValueError("invalid transport identity")
        if self.type == "offer":
            if not self.sdp or self.candidate is not None:
                raise ValueError("invalid offer shape")
        elif self.sdp is not None or self.candidate is None:
            raise ValueError("invalid candidate shape")
        return self

    def as_fastrtc_body(self, internal_transport_id: str) -> dict[str, object]:
        body: dict[str, object] = {
            "type": self.type,
            "webrtc_id": internal_transport_id,
        }
        if self.type == "offer":
            body["sdp"] = self.sdp
        else:
            assert self.candidate is not None
            body["candidate"] = self.candidate.model_dump(exclude_none=True)
        return body


class _FastRtcStreamV1(Protocol):
    event_handler: object
    concurrency_limit: int
    time_limit: float | None
    pcs: dict[str, object]
    handlers: dict[str, object]

    def mount(self, app: FastAPI) -> None: ...

    def set_additional_outputs(self, webrtc_id: str): ...

    async def handle_offer(self, body: dict[str, object], set_outputs): ...

    def clean_up(self, webrtc_id: str): ...


class _BindingStateV1(str, Enum):
    RESERVED = "reserved"
    ACTIVE = "active"
    ATTACHED = "attached"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True, repr=False)
class TrustedRtcSessionAdmissionV1:
    """Server-owned consumed admission bound to one RTC transport identity."""

    transport_id: str
    webrtc_id: str
    session_admission: ConsumedSessionAdmissionV1
    _controller: AuthenticatedRtcAdmissionControllerV1 = field(
        repr=False,
        compare=False,
    )

    def __repr__(self) -> str:
        return "TrustedRtcSessionAdmissionV1(<redacted>)"

    def bind_stream(self, stream: RtcStream) -> None:
        self._controller.bind_stream(self, stream)

    async def attach_stream(self, stream: RtcStream) -> None:
        await self._controller.attach_stream(self, stream)

    async def abort_stream(self, stream: RtcStream) -> None:
        await self._controller.abort_stream(self, stream)

    def release_stream(self, stream: RtcStream) -> None:
        self._controller.release_stream(self, stream)


@dataclass(slots=True, repr=False)
class _RtcTransportBindingStateV1:
    trusted_admission: TrustedRtcSessionAdmissionV1
    transport_token_digest: bytes
    state: _BindingStateV1 = _BindingStateV1.RESERVED
    stream: RtcStream | None = None
    peer_connection: object | None = None
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    cleanup_complete: asyncio.Event = field(default_factory=asyncio.Event)
    expiry_task: asyncio.Task[None] | None = None
    connection_timeout_event: object | None = None


_CURRENT_TRUSTED_RTC_ADMISSION_V1: ContextVar[TrustedRtcSessionAdmissionV1 | None] = (
    ContextVar("current_trusted_rtc_admission_v1", default=None)
)


def get_current_trusted_rtc_admission_v1() -> TrustedRtcSessionAdmissionV1 | None:
    """Return only the server-installed per-offer trusted admission context."""

    return _CURRENT_TRUSTED_RTC_ADMISSION_V1.get()


class _SecureRtcSecretLogFilterV1(logging.Filter):
    _openavatar_secure_rtc_filter_v1 = True

    def filter(self, record: logging.LogRecord) -> bool:
        # Pinned FastRTC installs later peer/data-channel callbacks that may
        # execute outside the request task's context. Once secure RTC is
        # enabled, suppress these exact protocol loggers process-wide so SDP,
        # ICE, and data-channel material can never escape through them.
        return False


class _SecureRtcAccessLogFilterV1(logging.Filter):
    _openavatar_secure_rtc_access_filter_v1 = True

    def filter(self, record: logging.LogRecord) -> bool:
        arguments = record.args
        if (
            isinstance(arguments, tuple)
            and len(arguments) >= 3
            and isinstance(arguments[2], str)
        ):
            redacted_arguments = list(arguments)
            request_target = arguments[2].partition("?")[0]
            for signaling_root in (
                RTC_SIGNALING_ROUTE_V1,
                *RTC_LEGACY_ALTERNATE_SIGNALING_ROUTES_V1,
            ):
                if request_target.startswith(f"{signaling_root}/"):
                    request_target = f"{signaling_root}/<redacted>"
                    break
            redacted_arguments[2] = _ACCESS_LOG_OPAQUE_VALUE_PATTERN_V1.sub(
                "<redacted>",
                request_target,
            )
            record.args = tuple(redacted_arguments)
        return True


_SENSITIVE_RTC_LOGGERS_V1 = (
    "fastrtc.webrtc_connection_mixin",
    "fastrtc.tracks",
    "aiortc.rtcpeerconnection",
    "aiortc.rtcicetransport",
    "aioice.ice",
    "aioice.turn",
)


def _install_secure_rtc_log_filters_v1() -> None:
    for logger_name in _SENSITIVE_RTC_LOGGERS_V1:
        selected_logger = logging.getLogger(logger_name)
        if any(
            getattr(existing_filter, "_openavatar_secure_rtc_filter_v1", False)
            for existing_filter in selected_logger.filters
        ):
            continue
        selected_logger.addFilter(_SecureRtcSecretLogFilterV1())

    access_logger = logging.getLogger("uvicorn.access")
    if not any(
        getattr(
            existing_filter,
            "_openavatar_secure_rtc_access_filter_v1",
            False,
        )
        for existing_filter in access_logger.filters
    ):
        access_logger.addFilter(_SecureRtcAccessLogFilterV1())


class AuthenticatedRtcAdmissionControllerV1:
    """Authenticated HTTP signaling wrapper for pinned FastRTC 0.0.34."""

    __slots__ = (
        "_app",
        "_bindings",
        "_bindings_by_session",
        "_bindings_by_webrtc_id",
        "_close_completed",
        "_close_task",
        "_closed",
        "_factory",
        "_inflight_offers",
        "_lock",
        "_max_active_bindings",
        "_runtime",
        "_stream",
        "_transport_digest_key",
        "_transport_time_limit",
    )

    def __init__(
        self,
        *,
        app: FastAPI,
        stream: _FastRtcStreamV1,
        factory: RtcStream,
        runtime: CertificateSessionControlRuntimeV1,
    ):
        if stream.event_handler is not factory:
            raise CertificateCaptureStartupError("RTC_STREAM_FACTORY_BINDING_INVALID")
        handler_delegate = getattr(factory, "client_handler_delegate", None)
        if handler_delegate is None:
            raise CertificateCaptureStartupError(
                "RTC_CLIENT_HANDLER_DELEGATE_UNAVAILABLE"
            )
        try:
            configured_limit = int(stream.concurrency_limit)
        except (TypeError, ValueError, OverflowError):
            raise CertificateCaptureStartupError(
                "RTC_CONCURRENCY_LIMIT_INVALID"
            ) from None
        if configured_limit <= 0:
            raise CertificateCaptureStartupError("RTC_CONCURRENCY_LIMIT_INVALID")
        configured_time_limit = getattr(stream, "time_limit", None)
        if configured_time_limit is None:
            transport_time_limit = None
        else:
            try:
                transport_time_limit = float(configured_time_limit)
            except (TypeError, ValueError, OverflowError):
                raise CertificateCaptureStartupError("RTC_TIME_LIMIT_INVALID") from None
            if not math.isfinite(transport_time_limit) or transport_time_limit <= 0:
                raise CertificateCaptureStartupError("RTC_TIME_LIMIT_INVALID")

        self._app = app
        self._stream = stream
        self._factory = factory
        self._runtime = runtime
        self._closed = False
        self._close_completed = False
        self._close_task: asyncio.Task[None] | None = None
        self._lock = threading.RLock()
        self._bindings: dict[str, _RtcTransportBindingStateV1] = {}
        self._bindings_by_session: dict[str, _RtcTransportBindingStateV1] = {}
        self._bindings_by_webrtc_id: dict[str, _RtcTransportBindingStateV1] = {}
        self._inflight_offers: set[asyncio.Task[object]] = set()
        self._max_active_bindings = min(
            configured_limit,
            RTC_MAX_ACTIVE_TRANSPORT_BINDINGS_V1,
        )
        self._transport_time_limit = transport_time_limit
        # Pinned FastRTC creates an untracked sleep task for time_limit. The
        # controller owns the equivalent bounded lifecycle task in secure mode.
        stream.time_limit = None
        try:
            self._transport_digest_key = secrets.token_bytes(32)
        except Exception:  # noqa: BLE001
            raise CertificateCaptureStartupError(
                "RTC_TRANSPORT_BINDING_INITIALIZATION_FAILED"
            ) from None
        if len(self._transport_digest_key) != 32:
            raise CertificateCaptureStartupError(
                "RTC_TRANSPORT_BINDING_INITIALIZATION_FAILED"
            )
        _install_secure_rtc_log_filters_v1()

    def __repr__(self) -> str:
        return "AuthenticatedRtcAdmissionControllerV1(<redacted>)"

    def mount(self) -> None:
        @self._app.post(RTC_SIGNALING_ROUTE_V1)
        async def authenticated_rtc_signaling_v1(request: Request):
            return await self.handle_request(request)

    async def handle_request(self, request: Request) -> JSONResponse:
        try:
            query_was_present = bool(request.scope.get("query_string", b""))
            if query_was_present:
                # Uvicorn renders its access-log target from this same ASGI
                # scope after the response starts. Strip rejected query
                # material before that point so URL-borne credentials cannot
                # be reflected into the enabled-mode access log.
                request.scope["query_string"] = b""
            self._ensure_runtime_is_current()
            if query_was_present:
                raise _signaling_request_invalid_error_v1()
            principal = await self._authenticate_principal(request)
            signaling_request = await _parse_signaling_request_v1(request)
            if signaling_request.type == "offer":
                offer_task = self._begin_initial_offer()
                try:
                    return await self._handle_initial_offer(
                        request,
                        signaling_request,
                        principal,
                    )
                finally:
                    self._end_initial_offer(offer_task)
            return await self._handle_candidate(
                request,
                signaling_request,
                principal,
            )
        except RtcAdmissionErrorV1 as error:
            return _error_response_v1(error)
        except Exception:  # noqa: BLE001
            return _error_response_v1(_authority_unavailable_error_v1())

    def bind_stream(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        stream: RtcStream,
    ) -> None:
        with self._lock:
            self._ensure_runtime_is_current_locked()
            binding = self._bindings.get(trusted_admission.transport_id)
            if (
                binding is None
                or binding.trusted_admission is not trusted_admission
                or binding.state is _BindingStateV1.CLOSED
                or binding.stream is not None
            ):
                raise RuntimeError("RTC_SECURE_TRANSPORT_BINDING_UNAVAILABLE")
            binding.stream = stream

    async def attach_stream(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        stream: RtcStream,
    ) -> None:
        binding = self._binding_for_trusted_admission(trusted_admission)
        created_session = False
        session_id = trusted_admission.session_admission.session_id
        handler_delegate = getattr(self._factory, "client_handler_delegate", None)
        if handler_delegate is None:
            await self._abort_transport(trusted_admission)
            raise RuntimeError("RTC_SECURE_SESSION_ATTACHMENT_UNAVAILABLE")

        try:
            async with (
                binding.operation_lock,
                self._runtime.authority.serialized_transition(),
            ):
                self._runtime.authority.validate_consumed_session_admission(
                    trusted_admission.session_admission,
                    channel=SessionAdmissionChannelV1.RTC,
                )
                with self._lock:
                    self._ensure_runtime_is_current_locked()
                    current = self._bindings.get(trusted_admission.transport_id)
                    if (
                        current is not binding
                        or binding.trusted_admission is not trusted_admission
                        or binding.stream is not stream
                        or binding.state is _BindingStateV1.CLOSED
                    ):
                        raise RuntimeError("RTC_SECURE_TRANSPORT_BINDING_UNAVAILABLE")
                    if (
                        binding.state is _BindingStateV1.ATTACHED
                        and stream.client_session_delegate is not None
                    ):
                        return
                    established_binding = self._bindings_by_session.get(session_id)
                    if (
                        established_binding is not None
                        and established_binding is not binding
                    ):
                        raise RuntimeError("RTC_SECURE_SESSION_ALREADY_BOUND")

                session_delegate = handler_delegate.find_session_delegate(session_id)
                if session_delegate is None:
                    try:
                        session_delegate = handler_delegate.start_session(
                            session_id=session_id,
                            timestamp_base=stream.input_sample_rate,
                            session_admission=(trusted_admission.session_admission),
                        )
                        created_session = True
                    except Exception:  # noqa: BLE001
                        _stop_failed_session_v1(
                            handler_delegate,
                            session_id,
                        )
                        raise RuntimeError(
                            "RTC_SECURE_SESSION_ATTACHMENT_FAILED"
                        ) from None
                else:
                    established_admission = handler_delegate.find_session_admission(
                        session_id
                    )
                    if not session_admission_ownership_matches_v1(
                        established_admission,
                        trusted_admission.session_admission,
                    ):
                        raise RuntimeError("RTC_SECURE_SESSION_ATTACHMENT_DENIED")

                with self._lock:
                    self._ensure_runtime_is_current_locked()
                    current = self._bindings.get(trusted_admission.transport_id)
                    if (
                        current is not binding
                        or binding.stream is not stream
                        or binding.state is _BindingStateV1.CLOSED
                    ):
                        if created_session:
                            _stop_failed_session_v1(
                                handler_delegate,
                                session_id,
                            )
                            created_session = False
                        raise RuntimeError("RTC_SECURE_TRANSPORT_BINDING_UNAVAILABLE")
                    self._bindings_by_session[session_id] = binding
                    binding.state = _BindingStateV1.ATTACHED
                    stream.session_id = session_id
                    stream.transport_id = trusted_admission.transport_id
                    stream.session_admission = trusted_admission.session_admission
                    stream.client_session_delegate = session_delegate
                    stream.owns_session = created_session
                    self._factory.streams[session_id] = stream
        except BaseException:
            if created_session and not stream.owns_session:
                _stop_failed_session_v1(
                    handler_delegate,
                    session_id,
                )
            await self._abort_transport(trusted_admission)
            raise

    async def abort_stream(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        stream: RtcStream,
    ) -> None:
        with self._lock:
            binding = self._bindings.get(trusted_admission.transport_id)
            if (
                binding is None
                or binding.trusted_admission is not trusted_admission
                or (binding.stream is not None and binding.stream is not stream)
            ):
                return
        await self._abort_transport(trusted_admission)

    def release_stream(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        stream: RtcStream,
    ) -> None:
        with self._lock:
            binding = self._bindings.get(trusted_admission.transport_id)
            if (
                binding is None
                or binding.trusted_admission is not trusted_admission
                or (binding.stream is not None and binding.stream is not stream)
            ):
                return
            _release_fastrtc_connection_timeout_v1(
                self._stream,
                trusted_admission.transport_id,
                binding.connection_timeout_event,
            )
            self._retire_binding_locked(binding)

    def snapshot(self) -> dict[str, int]:
        """Return only non-secret transport counts for tests and diagnostics."""

        with self._lock:
            return {
                "active_bindings": len(self._bindings),
                "attached_sessions": len(self._bindings_by_session),
            }

    async def close(self) -> None:
        """Destroy transport bindings and controller secret material."""

        with self._lock:
            if self._close_completed:
                return
            self._closed = True
            if self._close_task is None or self._close_task.done():
                self._close_task = asyncio.create_task(
                    self._finish_close(asyncio.current_task())
                )
            close_task = self._close_task
        await asyncio.shield(close_task)

    async def _finish_close(
        self,
        excluded_offer_task: asyncio.Task[object] | None,
    ) -> None:
        with self._lock:
            inflight_offers = tuple(
                task
                for task in self._inflight_offers
                if task is not excluded_offer_task
            )
        if inflight_offers:
            await asyncio.gather(
                *inflight_offers,
                return_exceptions=True,
            )
        while True:
            with self._lock:
                trusted_admissions = tuple(
                    binding.trusted_admission for binding in self._bindings.values()
                )
            if not trusted_admissions:
                break
            for trusted_admission in trusted_admissions:
                await self._abort_transport(trusted_admission)
        with self._lock:
            self._transport_digest_key = bytes(len(self._transport_digest_key))
            self._close_completed = True

    async def _handle_initial_offer(
        self,
        request: Request,
        signaling_request: RtcSignalingRequestV1,
        principal: AuthenticatedPrincipalV1,
    ) -> JSONResponse:
        _forbid_header_v1(request, RTC_TRANSPORT_BINDING_HEADER_V1)
        session_id = _extract_offer_credential_v1(
            request,
            RTC_SESSION_ID_HEADER_V1,
            _SESSION_ID_PATTERN_V1,
        )
        admission_ticket = _extract_offer_credential_v1(
            request,
            RTC_ADMISSION_TICKET_HEADER_V1,
            _ADMISSION_TICKET_PATTERN_V1,
        )

        try:
            async with self._runtime.authority.serialized_transition():
                self._ensure_runtime_is_current()
                with self._lock:
                    if signaling_request.webrtc_id in self._bindings_by_webrtc_id:
                        raise RtcAdmissionErrorV1(
                            RtcAdmissionReasonV1.TRANSPORT_CONFLICT,
                            status_code=409,
                        )
                    if len(self._bindings) >= self._max_active_bindings:
                        raise RtcAdmissionErrorV1(
                            RtcAdmissionReasonV1.TRANSPORT_CONFLICT,
                            status_code=429,
                        )

                admission = self._runtime.authority.consume_admission_ticket(
                    principal,
                    session_id,
                    admission_ticket,
                    SessionAdmissionChannelV1.RTC,
                )
                if (
                    not isinstance(admission, ConsumedSessionAdmissionV1)
                    or admission.session_id != session_id
                    or admission.channel is not SessionAdmissionChannelV1.RTC
                ):
                    raise _authority_unavailable_error_v1()
                trusted_admission, raw_transport_token = self._reserve_binding(
                    signaling_request.webrtc_id,
                    admission,
                )
        except RtcAdmissionErrorV1:
            raise
        except SessionAuthorityErrorV1 as exception:
            if (
                exception.reason_code
                == SessionAuthorityReasonV1.TICKET_ACCESS_DENIED.value
            ):
                raise _admission_denied_error_v1() from None
            raise _authority_unavailable_error_v1() from None
        except Exception:  # noqa: BLE001
            raise _authority_unavailable_error_v1() from None

        admission_context_token = _CURRENT_TRUSTED_RTC_ADMISSION_V1.set(
            trusted_admission
        )
        try:
            self._ensure_runtime_is_current()
            try:
                async with asyncio.timeout(RTC_OFFER_TIMEOUT_SECONDS_V1):
                    answer = await self._stream.handle_offer(
                        signaling_request.as_fastrtc_body(
                            trusted_admission.transport_id
                        ),
                        set_outputs=self._stream.set_additional_outputs(
                            trusted_admission.transport_id
                        ),
                    )
            except asyncio.CancelledError:
                await self._abort_transport(trusted_admission)
                raise
            except Exception:  # noqa: BLE001
                await self._abort_transport(trusted_admission)
                raise _peer_construction_error_v1() from None

            if (
                not isinstance(answer, dict)
                or not isinstance(answer.get("sdp"), str)
                or not answer.get("sdp")
                or answer.get("type") != "answer"
            ):
                await self._abort_transport(trusted_admission)
                raise _peer_construction_error_v1()

            peer_connection = self._stream.pcs.get(trusted_admission.transport_id)
            if peer_connection is None:
                await self._abort_transport(trusted_admission)
                raise _peer_construction_error_v1()
            try:
                async with self._runtime.authority.serialized_transition():
                    self._ensure_runtime_is_current()
                    self._runtime.authority.validate_consumed_session_admission(
                        trusted_admission.session_admission,
                        channel=SessionAdmissionChannelV1.RTC,
                        principal=principal,
                    )
                    self._mark_offer_succeeded(
                        trusted_admission,
                        peer_connection,
                    )
                    self._install_peer_cleanup_callback(
                        trusted_admission,
                        peer_connection,
                    )
                    self._ensure_runtime_is_current()
            except asyncio.CancelledError:
                await self._abort_transport(trusted_admission)
                raise
            except RtcAdmissionErrorV1:
                await self._abort_transport(trusted_admission)
                raise
            except Exception:  # noqa: BLE001
                await self._abort_transport(trusted_admission)
                raise _peer_construction_error_v1() from None
            response_payload = {
                "sdp": answer["sdp"],
                "type": "answer",
                RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1: raw_transport_token,
            }
            return JSONResponse(
                status_code=200,
                content=response_payload,
                headers=_NO_STORE_HEADERS_V1,
            )
        finally:
            _CURRENT_TRUSTED_RTC_ADMISSION_V1.reset(admission_context_token)

    async def _handle_candidate(
        self,
        request: Request,
        signaling_request: RtcSignalingRequestV1,
        principal: AuthenticatedPrincipalV1,
    ) -> JSONResponse:
        _forbid_header_v1(request, RTC_SESSION_ID_HEADER_V1)
        _forbid_header_v1(request, RTC_ADMISSION_TICKET_HEADER_V1)
        raw_transport_token = _extract_transport_binding_v1(request)
        binding = self._authorize_transport_binding(
            signaling_request.webrtc_id,
            raw_transport_token,
            principal,
        )
        trusted_admission = binding.trusted_admission

        authority_denied = False
        signaling_failed = False
        async with binding.operation_lock:
            try:
                async with self._runtime.authority.serialized_transition():
                    self._ensure_runtime_is_current()
                    self._runtime.authority.validate_consumed_session_admission(
                        trusted_admission.session_admission,
                        channel=SessionAdmissionChannelV1.RTC,
                        principal=principal,
                    )
                    with self._lock:
                        self._ensure_runtime_is_current_locked()
                        current = self._bindings.get(trusted_admission.transport_id)
                        peer_connection = self._stream.pcs.get(
                            trusted_admission.transport_id
                        )
                        handler = self._stream.handlers.get(
                            trusted_admission.transport_id
                        )
                        if (
                            current is not binding
                            or binding.state
                            not in {
                                _BindingStateV1.ACTIVE,
                                _BindingStateV1.ATTACHED,
                            }
                            or binding.peer_connection is None
                            or peer_connection is not binding.peer_connection
                            or binding.stream is None
                            or handler is not binding.stream
                        ):
                            raise _transport_binding_denied_error_v1()

                    admission_context_token = _CURRENT_TRUSTED_RTC_ADMISSION_V1.set(
                        trusted_admission
                    )
                    try:
                        async with asyncio.timeout(RTC_CANDIDATE_TIMEOUT_SECONDS_V1):
                            result = await self._stream.handle_offer(
                                signaling_request.as_fastrtc_body(
                                    trusted_admission.transport_id
                                ),
                                set_outputs=self._stream.set_additional_outputs(
                                    trusted_admission.transport_id
                                ),
                            )
                    finally:
                        _CURRENT_TRUSTED_RTC_ADMISSION_V1.reset(admission_context_token)

                    if not _fastrtc_candidate_succeeded_v1(result):
                        signaling_failed = True
                    self._ensure_runtime_is_current()
            except RtcAdmissionErrorV1:
                await self._abort_transport(trusted_admission)
                raise
            except SessionAuthorityErrorV1:
                authority_denied = True
            except asyncio.CancelledError:
                await self._abort_transport(trusted_admission)
                raise
            except Exception:  # noqa: BLE001
                signaling_failed = True

        if authority_denied:
            await self._abort_transport(trusted_admission)
            raise _transport_binding_denied_error_v1()
        if signaling_failed:
            await self._abort_transport(trusted_admission)
            raise RtcAdmissionErrorV1(
                RtcAdmissionReasonV1.SIGNALING_FAILED,
                status_code=400,
            )
        return JSONResponse(
            status_code=200,
            content={"status": "success"},
            headers=_NO_STORE_HEADERS_V1,
        )

    async def _authenticate_principal(
        self,
        request: Request,
    ) -> AuthenticatedPrincipalV1:
        encoded_access_token = _extract_bearer_token_v1(request)
        try:
            principal = (
                await self._runtime.access_token_validator.validate_access_token(
                    encoded_access_token
                )
            )
        except OidcAuthenticationErrorV1:
            raise RtcAdmissionErrorV1(
                RtcAdmissionReasonV1.AUTHENTICATION_FAILED,
                status_code=401,
            ) from None
        except Exception:  # noqa: BLE001
            raise RtcAdmissionErrorV1(
                RtcAdmissionReasonV1.AUTHENTICATION_UNAVAILABLE,
                status_code=503,
            ) from None
        if not isinstance(principal, AuthenticatedPrincipalV1):
            raise RtcAdmissionErrorV1(
                RtcAdmissionReasonV1.AUTHENTICATION_UNAVAILABLE,
                status_code=503,
            )
        return principal

    def _ensure_runtime_is_current(self) -> None:
        with self._lock:
            self._ensure_runtime_is_current_locked()

    def _ensure_runtime_is_current_locked(self) -> None:
        if self._closed or (
            getattr(
                self._app.state,
                "certificate_session_control_v1",
                None,
            )
            is not self._runtime
        ):
            raise _authority_unavailable_error_v1()

    def _begin_initial_offer(self) -> asyncio.Task[object]:
        offer_task = asyncio.current_task()
        if offer_task is None:
            raise _authority_unavailable_error_v1()
        with self._lock:
            self._ensure_runtime_is_current_locked()
            self._inflight_offers.add(offer_task)
        return offer_task

    def _end_initial_offer(self, offer_task: asyncio.Task[object]) -> None:
        with self._lock:
            self._inflight_offers.discard(offer_task)

    def _reserve_binding(
        self,
        webrtc_id: str,
        admission: ConsumedSessionAdmissionV1,
    ) -> tuple[TrustedRtcSessionAdmissionV1, str]:
        try:
            binding_entropy = secrets.token_bytes(64)
        except Exception:  # noqa: BLE001
            raise _authority_unavailable_error_v1() from None
        if len(binding_entropy) != 64:
            raise _authority_unavailable_error_v1()
        internal_transport_id = (
            _INTERNAL_TRANSPORT_ID_PREFIX_V1
            + _urlsafe_no_padding_v1(binding_entropy[:32])
        )
        raw_transport_token = _TRANSPORT_BINDING_PREFIX_V1 + _urlsafe_no_padding_v1(
            binding_entropy[32:]
        )
        token_digest = self._transport_token_digest(raw_transport_token)
        trusted_admission = TrustedRtcSessionAdmissionV1(
            transport_id=internal_transport_id,
            webrtc_id=webrtc_id,
            session_admission=admission,
            _controller=self,
        )
        binding = _RtcTransportBindingStateV1(
            trusted_admission=trusted_admission,
            transport_token_digest=token_digest,
        )
        with self._lock:
            self._ensure_runtime_is_current_locked()
            if (
                webrtc_id in self._bindings_by_webrtc_id
                or internal_transport_id in self._bindings
                or _fastrtc_transport_id_in_use_v1(
                    self._stream,
                    internal_transport_id,
                )
                or any(
                    hmac.compare_digest(
                        existing.transport_token_digest,
                        token_digest,
                    )
                    for existing in self._bindings.values()
                )
            ):
                raise _authority_unavailable_error_v1()
            self._bindings[internal_transport_id] = binding
            self._bindings_by_webrtc_id[webrtc_id] = binding
        return trusted_admission, raw_transport_token

    def _mark_offer_succeeded(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        peer_connection: object,
    ) -> None:
        with self._lock:
            self._ensure_runtime_is_current_locked()
            binding = self._bindings.get(trusted_admission.transport_id)
            if (
                binding is None
                or binding.trusted_admission is not trusted_admission
                or binding.state is _BindingStateV1.CLOSED
                or binding.peer_connection is not None
                or binding.stream is None
                or self._stream.handlers.get(trusted_admission.transport_id)
                is not binding.stream
                or not _fastrtc_media_binding_is_present_v1(
                    self._stream,
                    trusted_admission.transport_id,
                    binding.stream,
                )
            ):
                raise _peer_construction_error_v1()
            binding.peer_connection = peer_connection
            connection_timeouts = getattr(
                self._stream,
                "connection_timeouts",
                None,
            )
            if connection_timeouts is not None:
                try:
                    binding.connection_timeout_event = connection_timeouts.get(
                        trusted_admission.transport_id
                    )
                except Exception:  # noqa: BLE001
                    binding.connection_timeout_event = None
            if binding.state is _BindingStateV1.RESERVED:
                binding.state = _BindingStateV1.ACTIVE

    def _start_transport_expiry(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
    ) -> None:
        if self._transport_time_limit is None:
            return
        with self._lock:
            binding = self._bindings.get(trusted_admission.transport_id)
            if (
                binding is None
                or binding.trusted_admission is not trusted_admission
                or binding.state
                not in {
                    _BindingStateV1.ACTIVE,
                    _BindingStateV1.ATTACHED,
                }
                or binding.expiry_task is not None
            ):
                return
            binding.expiry_task = asyncio.create_task(
                self._expire_transport(
                    trusted_admission,
                    self._transport_time_limit,
                )
            )

    async def _expire_transport(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        time_limit: float,
    ) -> None:
        await asyncio.sleep(time_limit)
        await self._abort_transport(trusted_admission)

    def _install_peer_cleanup_callback(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        peer_connection: object,
    ) -> None:
        register = getattr(peer_connection, "on", None)
        if not callable(register):
            raise _peer_construction_error_v1()

        @register("connectionstatechange")
        async def secure_rtc_connection_state_cleanup_v1():
            connection_state = getattr(
                peer_connection,
                "connectionState",
                None,
            )
            if connection_state == "connected":
                self._start_transport_expiry(trusted_admission)
            elif connection_state in {
                "failed",
                "closed",
            }:
                await self._abort_transport(
                    trusted_admission,
                    close_peer=False,
                )

        connection_state = getattr(peer_connection, "connectionState", None)
        if connection_state == "connected":
            self._start_transport_expiry(trusted_admission)
        elif connection_state in {
            "failed",
            "closed",
        }:
            raise _peer_construction_error_v1()

    def _authorize_transport_binding(
        self,
        webrtc_id: str,
        raw_transport_token: str,
        principal: AuthenticatedPrincipalV1,
    ) -> _RtcTransportBindingStateV1:
        presented_digest = self._transport_token_digest(raw_transport_token)
        with self._lock:
            self._ensure_runtime_is_current_locked()
            binding = self._bindings_by_webrtc_id.get(webrtc_id)
            expected_digest = (
                binding.transport_token_digest
                if binding is not None
                else bytes(hashlib.sha256().digest_size)
            )
            digest_matches = hmac.compare_digest(
                expected_digest,
                presented_digest,
            )
            owner_matches = (
                binding is not None
                and binding.trusted_admission.webrtc_id == webrtc_id
                and binding.trusted_admission.session_admission.owner_issuer
                == principal.issuer
                and binding.trusted_admission.session_admission.owner_subject
                == principal.subject
            )
            if (
                binding is None
                or not digest_matches
                or not owner_matches
                or binding.state
                not in {
                    _BindingStateV1.ACTIVE,
                    _BindingStateV1.ATTACHED,
                }
            ):
                raise _transport_binding_denied_error_v1()
            return binding

    def _binding_for_trusted_admission(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
    ) -> _RtcTransportBindingStateV1:
        with self._lock:
            binding = self._bindings.get(trusted_admission.transport_id)
            if (
                binding is None
                or binding.trusted_admission is not trusted_admission
                or binding.state is _BindingStateV1.CLOSED
            ):
                raise RuntimeError("RTC_SECURE_TRANSPORT_BINDING_UNAVAILABLE")
            return binding

    async def _abort_transport(
        self,
        trusted_admission: TrustedRtcSessionAdmissionV1,
        *,
        close_peer: bool = True,
    ) -> None:
        wait_for_cleanup: asyncio.Event | None = None
        with self._lock:
            binding = self._bindings.get(trusted_admission.transport_id)
            if binding is None or binding.trusted_admission is not trusted_admission:
                return
            if binding.state is _BindingStateV1.CLOSED:
                if not close_peer:
                    return
                wait_for_cleanup = binding.cleanup_complete
                peer_connection = None
                bound_stream = None
            else:
                binding.state = _BindingStateV1.CLOSED
                peer_connection = binding.peer_connection or self._stream.pcs.get(
                    trusted_admission.transport_id
                )
                bound_stream = binding.stream

        if wait_for_cleanup is not None:
            await wait_for_cleanup.wait()
            return

        _release_fastrtc_connection_timeout_v1(
            self._stream,
            trusted_admission.transport_id,
            binding.connection_timeout_event,
        )
        try:
            if close_peer and peer_connection is not None:
                close = getattr(peer_connection, "close", None)
                if callable(close):
                    try:
                        close_result = close()
                        if inspect.isawaitable(close_result):
                            async with asyncio.timeout(5):
                                await close_result
                    except Exception:  # noqa: BLE001
                        close_result = None
        finally:
            try:
                try:
                    connections = self._stream.clean_up(trusted_admission.transport_id)
                except Exception:  # noqa: BLE001
                    connections = []
                for connection in connections or []:
                    stop = getattr(connection, "stop", None)
                    if callable(stop):
                        try:
                            stop()
                        except Exception:  # noqa: BLE001
                            connection = None

                if bound_stream is not None:
                    try:
                        shutdown_result = bound_stream.shutdown()
                        if inspect.isawaitable(shutdown_result):
                            await shutdown_result
                    except Exception:  # noqa: BLE001
                        shutdown_result = None
            finally:
                with self._lock:
                    if self._bindings.get(trusted_admission.transport_id) is binding:
                        self._retire_binding_locked(binding)

    def _retire_binding_locked(
        self,
        binding: _RtcTransportBindingStateV1,
    ) -> None:
        binding.state = _BindingStateV1.CLOSED
        transport_id = binding.trusted_admission.transport_id
        if self._bindings.get(transport_id) is binding:
            del self._bindings[transport_id]
        webrtc_id = binding.trusted_admission.webrtc_id
        if self._bindings_by_webrtc_id.get(webrtc_id) is binding:
            del self._bindings_by_webrtc_id[webrtc_id]
        session_id = binding.trusted_admission.session_admission.session_id
        if self._bindings_by_session.get(session_id) is binding:
            del self._bindings_by_session[session_id]
        binding.transport_token_digest = bytes(len(binding.transport_token_digest))
        binding.connection_timeout_event = None
        expiry_task = binding.expiry_task
        binding.expiry_task = None
        if expiry_task is not None:
            try:
                current_task = asyncio.current_task()
            except RuntimeError:
                current_task = None
            if expiry_task is not current_task:
                expiry_task.cancel()
        binding.cleanup_complete.set()

    def _transport_token_digest(self, raw_transport_token: str) -> bytes:
        return hmac.new(
            self._transport_digest_key,
            b"openavatar-rtc-transport-binding-v1"
            + raw_transport_token.encode("ascii", errors="strict"),
            hashlib.sha256,
        ).digest()


def mount_rtc_signaling_routes_v1(
    app: FastAPI,
    stream: _FastRtcStreamV1,
    factory: RtcStream,
) -> AuthenticatedRtcAdmissionControllerV1 | None:
    """Mount legacy FastRTC routes or the enabled authenticated HTTP surface."""

    runtime = getattr(app.state, "certificate_session_control_v1", None)
    if runtime is None:
        if getattr(
            app.state,
            CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
            False,
        ):
            raise CertificateCaptureStartupError("RTC_SESSION_AUTHORITY_UNAVAILABLE")
        stream.mount(app)
        return None
    if not isinstance(runtime, CertificateSessionControlRuntimeV1):
        raise CertificateCaptureStartupError("RTC_SESSION_AUTHORITY_UNAVAILABLE")

    _ensure_enabled_route_isolation_v1(app)
    require_secure_admission = getattr(
        factory,
        "require_secure_rtc_admission_v1",
        None,
    )
    if not callable(require_secure_admission):
        raise CertificateCaptureStartupError("RTC_STREAM_FACTORY_BINDING_INVALID")
    require_secure_admission()
    controller = AuthenticatedRtcAdmissionControllerV1(
        app=app,
        stream=stream,
        factory=factory,
        runtime=runtime,
    )
    controller.mount()
    app.add_event_handler("shutdown", controller.close)
    app.state.authenticated_rtc_admission_v1 = controller
    return controller


def _ensure_enabled_route_isolation_v1(app: FastAPI) -> None:
    forbidden_paths = {
        RTC_SIGNALING_ROUTE_V1,
        *RTC_LEGACY_ALTERNATE_SIGNALING_ROUTES_V1,
    }
    if any(getattr(route, "path", None) in forbidden_paths for route in app.routes):
        raise CertificateCaptureStartupError("RTC_SIGNALING_ROUTE_CONFLICT")


async def _parse_signaling_request_v1(
    request: Request,
) -> RtcSignalingRequestV1:
    content_types = request.headers.getlist("Content-Type")
    if (
        len(content_types) != 1
        or content_types[0].partition(";")[0].strip().casefold() != "application/json"
    ):
        raise _signaling_request_invalid_error_v1()

    content_lengths = request.headers.getlist("Content-Length")
    if len(content_lengths) > 1:
        raise _signaling_request_invalid_error_v1()
    if content_lengths:
        try:
            content_length = int(content_lengths[0], 10)
        except (TypeError, ValueError):
            raise _signaling_request_invalid_error_v1() from None
        if content_length < 0 or content_length > RTC_SIGNALING_MAX_REQUEST_BYTES_V1:
            raise _signaling_request_invalid_error_v1()

    body = bytearray()
    try:
        async with asyncio.timeout(RTC_SIGNALING_READ_TIMEOUT_SECONDS_V1):
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > RTC_SIGNALING_MAX_REQUEST_BYTES_V1:
                    raise _RtcSignalingRequestInvalidV1
    except _RtcSignalingRequestInvalidV1:
        raise _signaling_request_invalid_error_v1() from None
    except Exception:  # noqa: BLE001
        raise _signaling_request_invalid_error_v1() from None

    try:
        decoded = json.loads(
            bytes(body),
            object_pairs_hook=_unique_json_object_v1,
        )
        return RtcSignalingRequestV1.model_validate(decoded)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        _RtcSignalingRequestInvalidV1,
        RecursionError,
    ):
        raise _signaling_request_invalid_error_v1() from None


class _RtcSignalingRequestInvalidV1(ValueError):
    pass


def _unique_json_object_v1(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise _RtcSignalingRequestInvalidV1
        output[key] = value
    return output


def _extract_bearer_token_v1(request: Request) -> str:
    values = request.headers.getlist(_AUTHORIZATION_HEADER_V1)
    if not values:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.AUTHENTICATION_REQUIRED,
            status_code=401,
        )
    if len(values) != 1:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.AUTHENTICATION_FAILED,
            status_code=401,
        )
    authorization = values[0]
    if (
        len(authorization) > _MAX_AUTHORIZATION_HEADER_CHARACTERS_V1
        or "\r" in authorization
        or "\n" in authorization
    ):
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.AUTHENTICATION_FAILED,
            status_code=401,
        )
    scheme, separator, encoded_access_token = authorization.partition(" ")
    if (
        separator != " "
        or scheme.casefold() != "bearer"
        or not encoded_access_token
        or encoded_access_token != encoded_access_token.strip()
        or any(character.isspace() for character in encoded_access_token)
    ):
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.AUTHENTICATION_FAILED,
            status_code=401,
        )
    return encoded_access_token


def _extract_offer_credential_v1(
    request: Request,
    header_name: str,
    pattern: re.Pattern[str],
) -> str:
    values = request.headers.getlist(header_name)
    if not values:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.ADMISSION_CREDENTIAL_REQUIRED,
            status_code=400,
        )
    if len(values) != 1:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.ADMISSION_CREDENTIAL_INVALID,
            status_code=400,
        )
    value = values[0]
    if pattern.fullmatch(value) is None:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.ADMISSION_CREDENTIAL_INVALID,
            status_code=400,
        )
    return value


def _extract_transport_binding_v1(request: Request) -> str:
    values = request.headers.getlist(RTC_TRANSPORT_BINDING_HEADER_V1)
    if not values:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.TRANSPORT_BINDING_REQUIRED,
            status_code=400,
        )
    if len(values) != 1:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.TRANSPORT_BINDING_INVALID,
            status_code=400,
        )
    value = values[0]
    if _TRANSPORT_BINDING_PATTERN_V1.fullmatch(value) is None:
        raise RtcAdmissionErrorV1(
            RtcAdmissionReasonV1.TRANSPORT_BINDING_INVALID,
            status_code=400,
        )
    return value


def _forbid_header_v1(request: Request, header_name: str) -> None:
    if request.headers.getlist(header_name):
        raise _signaling_request_invalid_error_v1()


def _fastrtc_candidate_succeeded_v1(result: object) -> bool:
    if isinstance(result, JSONResponse):
        try:
            decoded = json.loads(result.body)
        except (TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        return (
            result.status_code == 200
            and isinstance(decoded, dict)
            and decoded.get("status") == "success"
        )
    return isinstance(result, dict) and result.get("status") == "success"


def _stop_failed_session_v1(handler_delegate: object, session_id: str) -> None:
    try:
        handler_delegate.stop_session(session_id)
    except Exception:  # noqa: BLE001
        return


def _fastrtc_transport_id_in_use_v1(
    stream: object,
    internal_transport_id: str,
) -> bool:
    for attribute_name in (
        "pcs",
        "handlers",
        "connections",
        "data_channels",
        "additional_outputs",
        "connection_timeouts",
    ):
        state = getattr(stream, attribute_name, None)
        if state is None:
            continue
        try:
            if internal_transport_id in state:
                return True
        except Exception:  # noqa: BLE001
            return True
    return False


def _fastrtc_media_binding_is_present_v1(
    stream: object,
    internal_transport_id: str,
    bound_stream: object,
) -> bool:
    connections_by_transport = getattr(stream, "connections", None)
    if connections_by_transport is None:
        return False
    try:
        connections = connections_by_transport.get(internal_transport_id)
    except Exception:  # noqa: BLE001
        return False
    return isinstance(connections, list) and any(
        getattr(connection, "event_handler", None) is bound_stream
        for connection in connections
    )


def _release_fastrtc_connection_timeout_v1(
    stream: object,
    internal_transport_id: str,
    retained_event: object | None,
) -> None:
    events = [retained_event] if retained_event is not None else []
    connection_timeouts = getattr(stream, "connection_timeouts", None)
    if connection_timeouts is not None:
        try:
            current_event = connection_timeouts.get(internal_transport_id)
            if current_event is not None and all(
                current_event is not event for event in events
            ):
                events.append(current_event)
        except Exception:  # noqa: BLE001
            connection_timeouts = None
    for event in events:
        try:
            event.set()
        except Exception:  # noqa: BLE001, S112
            continue


def _urlsafe_no_padding_v1(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _error_response_v1(error: RtcAdmissionErrorV1) -> JSONResponse:
    headers = dict(_NO_STORE_HEADERS_V1)
    if error.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=error.status_code,
        content={"reason_code": error.reason_code},
        headers=headers,
    )


def _signaling_request_invalid_error_v1() -> RtcAdmissionErrorV1:
    return RtcAdmissionErrorV1(
        RtcAdmissionReasonV1.SIGNALING_REQUEST_INVALID,
        status_code=400,
    )


def _admission_denied_error_v1() -> RtcAdmissionErrorV1:
    return RtcAdmissionErrorV1(
        RtcAdmissionReasonV1.ADMISSION_DENIED,
        status_code=403,
    )


def _transport_binding_denied_error_v1() -> RtcAdmissionErrorV1:
    return RtcAdmissionErrorV1(
        RtcAdmissionReasonV1.TRANSPORT_BINDING_DENIED,
        status_code=403,
    )


def _authority_unavailable_error_v1() -> RtcAdmissionErrorV1:
    return RtcAdmissionErrorV1(
        RtcAdmissionReasonV1.AUTHORITY_UNAVAILABLE,
        status_code=503,
    )


def _peer_construction_error_v1() -> RtcAdmissionErrorV1:
    return RtcAdmissionErrorV1(
        RtcAdmissionReasonV1.PEER_CONSTRUCTION_FAILED,
        status_code=503,
    )

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocket

from service.service_security.certificate_session_authority import (
    ConsumedSessionAdmissionV1,
    SessionAdmissionChannelV1,
    SessionAuthorityErrorV1,
    SessionAuthorityReasonV1,
    session_admission_ownership_matches_v1,
)
from service.service_security.certificate_session_control import (
    CertificateSessionControlRuntimeV1,
)

WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1 = "oac.cert-admission.v1."
WEBSOCKET_ADMISSION_PROTOCOL_MAX_HEADER_CHARACTERS_V1 = 256
WEBSOCKET_ADMISSION_PROTOCOL_MAX_TOKEN_COUNT_V1 = 8

_SEC_WEBSOCKET_PROTOCOL_HEADER_V1 = "Sec-WebSocket-Protocol"
_ADMISSION_TICKET_PATTERN_V1 = r"att1_[A-Za-z0-9_-]{43}"
_ADMISSION_PROTOCOL_PATTERN_V1 = re.compile(
    rf"^{re.escape(WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1)}"
    rf"(?P<ticket>{_ADMISSION_TICKET_PATTERN_V1})$"
)
_NO_STORE_HEADERS_V1 = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class WebSocketAdmissionReasonV1(str, Enum):
    PROTOCOL_REQUIRED = "WEBSOCKET_ADMISSION_PROTOCOL_REQUIRED"
    PROTOCOL_INVALID = "WEBSOCKET_ADMISSION_PROTOCOL_INVALID"
    ADMISSION_DENIED = "WEBSOCKET_ADMISSION_DENIED"
    AUTHORITY_UNAVAILABLE = "WEBSOCKET_ADMISSION_AUTHORITY_UNAVAILABLE"


class WebSocketAdmissionErrorV1(RuntimeError):
    """A stable, secret-free WebSocket admission failure."""

    __slots__ = ("reason_code", "status_code")

    def __init__(
        self,
        reason: WebSocketAdmissionReasonV1,
        *,
        status_code: int,
    ):
        self.reason_code = reason.value
        self.status_code = status_code
        super().__init__(f"WebSocket admission failed ({self.reason_code}).")


@dataclass(frozen=True, slots=True, repr=False)
class ParsedWebSocketAdmissionProtocolV1:
    admission_ticket: str

    def __repr__(self) -> str:
        return "ParsedWebSocketAdmissionProtocolV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class WebSocketSessionAdmissionGuardV1:
    """Enabled-mode adapter around the single Milestone 1C authority."""

    runtime: CertificateSessionControlRuntimeV1

    def __repr__(self) -> str:
        return "WebSocketSessionAdmissionGuardV1(<redacted>)"

    def serialized_transition(self):
        return self.runtime.authority.serialized_transition()

    def consume(
        self,
        websocket: WebSocket,
        session_id: str,
    ) -> ConsumedSessionAdmissionV1:
        parsed_protocol = parse_websocket_admission_protocol_v1(websocket)
        try:
            admission = self.runtime.authority.consume_websocket_admission_ticket(
                session_id,
                parsed_protocol.admission_ticket,
            )
        except SessionAuthorityErrorV1 as exception:
            if (
                exception.reason_code
                == SessionAuthorityReasonV1.TICKET_ACCESS_DENIED.value
            ):
                raise _admission_denied_error() from None
            raise _authority_unavailable_error() from None
        except Exception:  # noqa: BLE001
            raise _authority_unavailable_error() from None

        if (
            not isinstance(admission, ConsumedSessionAdmissionV1)
            or admission.session_id != session_id
            or admission.channel is not SessionAdmissionChannelV1.WEBSOCKET
        ):
            raise _authority_unavailable_error()
        return admission


def websocket_session_admission_guard_v1(
    app: FastAPI,
) -> WebSocketSessionAdmissionGuardV1 | None:
    """Capture enabled-only runtime wiring when the route is registered."""

    runtime = getattr(app.state, "certificate_session_control_v1", None)
    if runtime is None:
        return None
    if not isinstance(runtime, CertificateSessionControlRuntimeV1):
        raise TypeError("INVALID_CERTIFICATE_SESSION_CONTROL_RUNTIME")
    return WebSocketSessionAdmissionGuardV1(runtime=runtime)


def parse_websocket_admission_protocol_v1(
    websocket: WebSocket,
) -> ParsedWebSocketAdmissionProtocolV1:
    """Parse exactly one bounded, canonical admission subprotocol token."""

    try:
        header_values = websocket.headers.getlist(
            _SEC_WEBSOCKET_PROTOCOL_HEADER_V1
        )
    except Exception:  # noqa: BLE001
        raise _protocol_invalid_error() from None

    if not header_values:
        raise WebSocketAdmissionErrorV1(
            WebSocketAdmissionReasonV1.PROTOCOL_REQUIRED,
            status_code=400,
        )
    try:
        total_header_characters = sum(len(value) for value in header_values)
    except TypeError:
        raise _protocol_invalid_error() from None
    if (
        total_header_characters
        > WEBSOCKET_ADMISSION_PROTOCOL_MAX_HEADER_CHARACTERS_V1
    ):
        raise _protocol_invalid_error()
    if len(header_values) != 1:
        raise _protocol_invalid_error()

    header_value = header_values[0]
    if (
        not isinstance(header_value, str)
        or not header_value
        or header_value != header_value.strip(" \t")
    ):
        raise _protocol_invalid_error()
    try:
        header_value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise _protocol_invalid_error() from None

    protocol_tokens = header_value.split(",")
    if (
        len(protocol_tokens) > WEBSOCKET_ADMISSION_PROTOCOL_MAX_TOKEN_COUNT_V1
        or len(protocol_tokens) != 1
        or any(
            not token or token != token.strip(" \t")
            for token in protocol_tokens
        )
    ):
        raise _protocol_invalid_error()

    match = _ADMISSION_PROTOCOL_PATTERN_V1.fullmatch(protocol_tokens[0])
    if match is None:
        raise _protocol_invalid_error()
    return ParsedWebSocketAdmissionProtocolV1(
        admission_ticket=match.group("ticket")
    )


def session_admissions_match_v1(
    established: object,
    candidate: ConsumedSessionAdmissionV1,
) -> bool:
    """Compare only immutable server-owned session-authority identity."""

    return (
        session_admission_ownership_matches_v1(established, candidate)
        and isinstance(established, ConsumedSessionAdmissionV1)
        and established.channel is candidate.channel
    )


async def reject_websocket_admission_v1(
    websocket: WebSocket,
    error: WebSocketAdmissionErrorV1,
) -> None:
    """Reject the HTTP handshake without accepting or reflecting credentials."""

    response = JSONResponse(
        status_code=error.status_code,
        content={"reason_code": error.reason_code},
        headers=_NO_STORE_HEADERS_V1,
    )
    try:
        await websocket.send_denial_response(response)
    except RuntimeError:
        close_code = 1013 if error.status_code == 503 else 1008
        await websocket.close(code=close_code, reason=error.reason_code)


def _protocol_invalid_error() -> WebSocketAdmissionErrorV1:
    return WebSocketAdmissionErrorV1(
        WebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        status_code=400,
    )


def _admission_denied_error() -> WebSocketAdmissionErrorV1:
    return WebSocketAdmissionErrorV1(
        WebSocketAdmissionReasonV1.ADMISSION_DENIED,
        status_code=403,
    )


def _authority_unavailable_error() -> WebSocketAdmissionErrorV1:
    return WebSocketAdmissionErrorV1(
        WebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE,
        status_code=503,
    )

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocket

from service.service_security.manager_authorization import (
    MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1,
    ManagerAuthorizationRuntimeV1,
)
from service.service_security.manager_websocket_authority import (
    MANAGER_WEBSOCKET_TICKET_PREFIX_V1,
    ConsumedManagerWebSocketAdmissionV1,
    ManagerWebSocketAuthorityErrorV1,
    ManagerWebSocketAuthorityReasonV1,
    ManagerWebSocketPurposeV1,
)

MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1 = (
    "oac.manager-admission.v1."
)
MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_MAX_HEADER_CHARACTERS_V1 = 256
MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_MAX_TOKEN_COUNT_V1 = 8

_CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1 = (
    "certificate_capture_enabled_v1"
)
_SEC_WEBSOCKET_PROTOCOL_HEADER_V1 = "Sec-WebSocket-Protocol"
_MANAGER_TICKET_PATTERN_V1 = (
    rf"{re.escape(MANAGER_WEBSOCKET_TICKET_PREFIX_V1)}"
    r"[A-Za-z0-9_-]{43}"
)
_MANAGER_PROTOCOL_PATTERN_V1 = re.compile(
    rf"^{re.escape(MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1)}"
    rf"(?P<ticket>{_MANAGER_TICKET_PATTERN_V1})$"
)
_NO_STORE_HEADERS_V1 = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class ManagerWebSocketAdmissionReasonV1(str, Enum):
    PROTOCOL_REQUIRED = "MANAGER_ADMISSION_PROTOCOL_REQUIRED"
    PROTOCOL_INVALID = "MANAGER_ADMISSION_PROTOCOL_INVALID"
    ADMISSION_DENIED = "MANAGER_ADMISSION_DENIED"
    AUTHORITY_UNAVAILABLE = "MANAGER_ADMISSION_AUTHORITY_UNAVAILABLE"


class ManagerWebSocketAdmissionErrorV1(RuntimeError):
    """A stable, secret-free manager WebSocket admission failure."""

    __slots__ = ("reason_code", "status_code")

    def __init__(
        self,
        reason: ManagerWebSocketAdmissionReasonV1,
        *,
        status_code: int,
    ):
        self.reason_code = reason.value
        self.status_code = status_code
        super().__init__(
            f"Manager WebSocket admission failed ({self.reason_code})."
        )


@dataclass(frozen=True, slots=True, repr=False)
class ParsedManagerWebSocketAdmissionProtocolV1:
    admission_ticket: str

    def __repr__(self) -> str:
        return "ParsedManagerWebSocketAdmissionProtocolV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManagerWebSocketAdmissionGuardV1:
    app: FastAPI
    runtime: ManagerAuthorizationRuntimeV1

    def __repr__(self) -> str:
        return "ManagerWebSocketAdmissionGuardV1(<redacted>)"

    def consume(
        self,
        websocket: WebSocket,
    ) -> ConsumedManagerWebSocketAdmissionV1:
        if (
            getattr(
                self.app.state,
                MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1,
                None,
            )
            is not self.runtime
        ):
            raise _authority_unavailable_error()
        parsed_protocol = parse_manager_websocket_admission_protocol_v1(
            websocket
        )
        try:
            admission = self.runtime.ticket_authority.consume(
                parsed_protocol.admission_ticket
            )
        except ManagerWebSocketAuthorityErrorV1 as exception:
            if (
                exception.reason_code
                == ManagerWebSocketAuthorityReasonV1.TICKET_ACCESS_DENIED.value
            ):
                raise _admission_denied_error() from None
            raise _authority_unavailable_error() from None
        except Exception:  # noqa: BLE001
            raise _authority_unavailable_error() from None

        if (
            not isinstance(admission, ConsumedManagerWebSocketAdmissionV1)
            or admission.purpose
            is not ManagerWebSocketPurposeV1.MANAGER_WEBSOCKET
        ):
            raise _authority_unavailable_error()
        return admission


def manager_websocket_admission_guard_v1(
    app: FastAPI,
) -> ManagerWebSocketAdmissionGuardV1 | None:
    """Resolve legacy or enabled manager admission at handshake time."""

    if not _certificate_mode_is_enabled_v1(app):
        return None
    runtime = getattr(
        app.state,
        MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1,
        None,
    )
    if not isinstance(runtime, ManagerAuthorizationRuntimeV1):
        raise _authority_unavailable_error()
    return ManagerWebSocketAdmissionGuardV1(app=app, runtime=runtime)


def _certificate_mode_is_enabled_v1(app: FastAPI) -> bool:
    return bool(
        getattr(
            app.state,
            _CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
            False,
        )
        or getattr(app.state, "certificate_session_control_v1", None)
        is not None
    )


def parse_manager_websocket_admission_protocol_v1(
    websocket: WebSocket,
) -> ParsedManagerWebSocketAdmissionProtocolV1:
    """Parse exactly one bounded, canonical manager-admission protocol."""

    try:
        header_values = websocket.headers.getlist(
            _SEC_WEBSOCKET_PROTOCOL_HEADER_V1
        )
    except Exception:  # noqa: BLE001
        raise _protocol_invalid_error() from None

    if not header_values:
        raise ManagerWebSocketAdmissionErrorV1(
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_REQUIRED,
            status_code=400,
        )
    try:
        total_header_characters = sum(len(value) for value in header_values)
    except TypeError:
        raise _protocol_invalid_error() from None
    if (
        total_header_characters
        > MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_MAX_HEADER_CHARACTERS_V1
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
        len(protocol_tokens)
        > MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_MAX_TOKEN_COUNT_V1
        or len(protocol_tokens) != 1
        or any(
            not token or token != token.strip(" \t")
            for token in protocol_tokens
        )
    ):
        raise _protocol_invalid_error()

    match = _MANAGER_PROTOCOL_PATTERN_V1.fullmatch(protocol_tokens[0])
    if match is None:
        raise _protocol_invalid_error()
    return ParsedManagerWebSocketAdmissionProtocolV1(
        admission_ticket=match.group("ticket")
    )


async def reject_manager_websocket_admission_v1(
    websocket: WebSocket,
    error: ManagerWebSocketAdmissionErrorV1,
) -> None:
    """Reject the handshake without accepting or reflecting credentials."""

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


def _protocol_invalid_error() -> ManagerWebSocketAdmissionErrorV1:
    return ManagerWebSocketAdmissionErrorV1(
        ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        status_code=400,
    )


def _admission_denied_error() -> ManagerWebSocketAdmissionErrorV1:
    return ManagerWebSocketAdmissionErrorV1(
        ManagerWebSocketAdmissionReasonV1.ADMISSION_DENIED,
        status_code=403,
    )


def _authority_unavailable_error() -> ManagerWebSocketAdmissionErrorV1:
    return ManagerWebSocketAdmissionErrorV1(
        ManagerWebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE,
        status_code=503,
    )

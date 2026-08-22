from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from service.service_security.manager_websocket_authority import (
    ManagerWebSocketAuthorityErrorV1,
    ManagerWebSocketAuthorityReasonV1,
    ManagerWebSocketPurposeV1,
    ManagerWebSocketTicketAuthorityV1,
    ManagerWebSocketTicketGrantV1,
)
from service.service_security.oidc_resource_server import (
    OIDC_MANAGER_SCOPE_V1,
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
    OidcAuthenticationReasonV1,
    OidcRequiredScopeV1,
)
from service.service_utils.ssl_helpers import CertificateCaptureStartupError

MANAGER_WEBSOCKET_TICKET_ROUTE_V1 = (
    "/api/v1/manager/websocket-admission-tickets"
)
MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1 = "manager_authorization_v1"

_CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1 = (
    "certificate_capture_enabled_v1"
)
_AUTHORIZATION_HEADER_V1 = "Authorization"
_MAX_AUTHORIZATION_HEADER_CHARACTERS_V1 = 16 * 1024
_NO_STORE_HEADERS_V1 = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}
_MANAGER_ACCESS_LOG_ROUTE_ROOTS_V1 = (
    MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
    "/ws/manager/data_tool",
    "/download/manager/data_tool/file",
    "/version",
    "/liveness",
    "/readiness",
    "/openavatarchat/initconfig",
    "/api/v1/session-capabilities",
    "/api/v1/sessions",
    "/ws/session",
)


class _ManagerAccessTokenValidatorV1(Protocol):
    async def validate_access_token_for_scope(
        self,
        encoded_access_token: str,
        required_scope: OidcRequiredScopeV1,
    ) -> AuthenticatedPrincipalV1:
        """Validate a bearer token for one explicit resource scope."""


class ManagerWebSocketTicketResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    admission_ticket: str = Field(repr=False)
    purpose: ManagerWebSocketPurposeV1
    expires_at_epoch_seconds: float


@dataclass(frozen=True, slots=True, repr=False)
class ManagerAuthorizationRuntimeV1:
    """Enabled-only manager authorization state, separate from sessions."""

    ticket_authority: ManagerWebSocketTicketAuthorityV1
    access_token_validator: _ManagerAccessTokenValidatorV1

    def __repr__(self) -> str:
        return "ManagerAuthorizationRuntimeV1(<redacted>)"


class _SecureManagerAccessLogFilterV1(logging.Filter):
    _openavatar_secure_manager_access_filter_v1 = True

    def filter(self, record: logging.LogRecord) -> bool:
        arguments = record.args
        if (
            isinstance(arguments, tuple)
            and len(arguments) >= 3
            and isinstance(arguments[2], str)
        ):
            request_target = arguments[2]
            path = request_target.partition("?")[0]
            for route_root in _MANAGER_ACCESS_LOG_ROUTE_ROOTS_V1:
                if path == route_root:
                    redacted_arguments = list(arguments)
                    redacted_arguments[2] = path
                    record.args = tuple(redacted_arguments)
                    break
                if path.startswith(f"{route_root}/"):
                    redacted_arguments = list(arguments)
                    redacted_arguments[2] = f"{route_root}/<redacted>"
                    record.args = tuple(redacted_arguments)
                    break
        return True


def install_manager_authorization_v1(
    app: FastAPI,
    access_token_validator: _ManagerAccessTokenValidatorV1,
    *,
    ticket_authority: ManagerWebSocketTicketAuthorityV1 | None = None,
) -> ManagerAuthorizationRuntimeV1 | None:
    """Install the independent manager control plane only in enabled mode."""

    if not getattr(
        app.state,
        _CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
        False,
    ):
        return None
    if hasattr(app.state, MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1):
        raise CertificateCaptureStartupError(
            "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
        )
    if not callable(
        getattr(
            access_token_validator,
            "validate_access_token_for_scope",
            None,
        )
    ):
        raise CertificateCaptureStartupError(
            "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
        )

    if ticket_authority is None:
        try:
            authority = ManagerWebSocketTicketAuthorityV1()
        except Exception:  # noqa: BLE001
            raise CertificateCaptureStartupError(
                "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
            ) from None
    elif isinstance(ticket_authority, ManagerWebSocketTicketAuthorityV1):
        authority = ticket_authority
    else:
        raise CertificateCaptureStartupError(
            "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
        )

    try:
        authority_snapshot = authority.snapshot()
    except Exception:  # noqa: BLE001
        authority_snapshot = None
    if authority_snapshot is None or authority_snapshot.closed:
        raise CertificateCaptureStartupError(
            "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
        )

    runtime = ManagerAuthorizationRuntimeV1(
        ticket_authority=authority,
        access_token_validator=access_token_validator,
    )
    setattr(app.state, MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1, runtime)
    _install_secure_manager_access_log_filter_v1()

    @app.post(
        MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
        status_code=status.HTTP_201_CREATED,
        response_model=ManagerWebSocketTicketResponseV1,
    )
    async def issue_manager_websocket_ticket(
        request: Request,
        response: Response,
    ) -> ManagerWebSocketTicketResponseV1:
        principal = await require_manager_http_authorization_v1(app, request)
        if principal is None:
            raise _manager_http_error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "MANAGER_AUTHORIZATION_UNAVAILABLE",
            )
        try:
            grant = runtime.ticket_authority.issue(principal)
        except ManagerWebSocketAuthorityErrorV1 as exception:
            raise _manager_authority_http_error(exception) from None
        except Exception:  # noqa: BLE001
            raise _manager_http_error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "MANAGER_ADMISSION_AUTHORITY_UNAVAILABLE",
            ) from None
        _apply_no_store(response)
        return _manager_websocket_ticket_response(grant)

    async def close_manager_authority() -> None:
        runtime.ticket_authority.close()

    app.add_event_handler("shutdown", close_manager_authority)
    return runtime


def _install_secure_manager_access_log_filter_v1() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    if any(
        getattr(
            existing_filter,
            "_openavatar_secure_manager_access_filter_v1",
            False,
        )
        for existing_filter in access_logger.filters
    ):
        return
    access_logger.addFilter(_SecureManagerAccessLogFilterV1())


async def require_manager_http_authorization_v1(
    app: FastAPI,
    request: Request,
) -> AuthenticatedPrincipalV1 | None:
    """Require `oac:manager` before an enabled-mode manager side effect."""

    runtime = manager_authorization_runtime_v1(app)
    if runtime is None:
        return None
    encoded_access_token = _extract_bearer_token_v1(request)
    validate_for_scope = getattr(
        runtime.access_token_validator,
        "validate_access_token_for_scope",
        None,
    )
    if not callable(validate_for_scope):
        raise _manager_http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "MANAGER_AUTHORIZATION_UNAVAILABLE",
        )
    try:
        principal = await validate_for_scope(
            encoded_access_token,
            OIDC_MANAGER_SCOPE_V1,
        )
    except OidcAuthenticationErrorV1 as exception:
        if (
            exception.reason_code
            == OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING.value
        ):
            raise _manager_http_error(
                status.HTTP_403_FORBIDDEN,
                "MANAGER_AUTHORIZATION_DENIED",
            ) from None
        raise _manager_http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        ) from None
    except Exception:  # noqa: BLE001
        raise _manager_http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "MANAGER_AUTHORIZATION_UNAVAILABLE",
        ) from None

    if not isinstance(principal, AuthenticatedPrincipalV1):
        raise _manager_http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "MANAGER_AUTHORIZATION_UNAVAILABLE",
        )
    if OIDC_MANAGER_SCOPE_V1 not in principal.scopes:
        raise _manager_http_error(
            status.HTTP_403_FORBIDDEN,
            "MANAGER_AUTHORIZATION_DENIED",
        )
    return principal


def manager_authorization_runtime_v1(
    app: FastAPI,
) -> ManagerAuthorizationRuntimeV1 | None:
    if not _certificate_mode_is_enabled_v1(app):
        return None
    runtime = getattr(
        app.state,
        MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1,
        None,
    )
    if not isinstance(runtime, ManagerAuthorizationRuntimeV1):
        raise _manager_http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "MANAGER_AUTHORIZATION_UNAVAILABLE",
        )
    return runtime


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


def _extract_bearer_token_v1(request: Request) -> str:
    values = request.headers.getlist(_AUTHORIZATION_HEADER_V1)
    if len(values) != 1:
        raise _manager_http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            authenticate=True,
        )
    authorization = values[0]
    if (
        len(authorization) > _MAX_AUTHORIZATION_HEADER_CHARACTERS_V1
        or "\r" in authorization
        or "\n" in authorization
    ):
        raise _manager_http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        )
    scheme, separator, encoded_access_token = authorization.partition(" ")
    if (
        separator != " "
        or scheme.casefold() != "bearer"
        or not encoded_access_token
        or encoded_access_token != encoded_access_token.strip()
        or any(character.isspace() for character in encoded_access_token)
    ):
        raise _manager_http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        )
    return encoded_access_token


def _manager_authority_http_error(
    exception: ManagerWebSocketAuthorityErrorV1,
) -> HTTPException:
    if exception.reason_code in {
        ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID.value,
        ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED.value,
    }:
        return _manager_http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        )
    return _manager_http_error(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "MANAGER_ADMISSION_AUTHORITY_UNAVAILABLE",
    )


def _manager_http_error(
    status_code: int,
    reason_code: str,
    *,
    authenticate: bool = False,
) -> HTTPException:
    headers = dict(_NO_STORE_HEADERS_V1)
    if authenticate:
        headers["WWW-Authenticate"] = "Bearer"
    return HTTPException(
        status_code=status_code,
        detail={"reason_code": reason_code},
        headers=headers,
    )


def _manager_websocket_ticket_response(
    grant: ManagerWebSocketTicketGrantV1,
) -> ManagerWebSocketTicketResponseV1:
    return ManagerWebSocketTicketResponseV1(
        admission_ticket=grant.admission_ticket,
        purpose=grant.purpose,
        expires_at_epoch_seconds=grant.expires_at_epoch_seconds,
    )


def _apply_no_store(response: Response) -> None:
    for header_name, header_value in _NO_STORE_HEADERS_V1.items():
        response.headers[header_name] = header_value

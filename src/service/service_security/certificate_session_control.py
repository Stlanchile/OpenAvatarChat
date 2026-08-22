from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
)
from service.service_security.certificate_session_authority import (
    AdmissionTicketGrantV1,
    CertificateSessionAuthorityV1,
    SessionAdmissionChannelV1,
    SessionAuthorityErrorV1,
    SessionAuthorityReasonV1,
    SessionCapabilityGrantV1,
)
from service.service_security.oidc_resource_server import (
    OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
    create_oidc_access_token_validator_v1,
)
from service.service_utils.ssl_helpers import CertificateCaptureStartupError

SESSION_CAPABILITY_HEADER_V1 = "X-Certificate-Session-Capability"
CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1 = (
    "certificate_capture_enabled_v1"
)
_LEGACY_RTC_ROUTE_PATHS_V1 = {
    "/webrtc/offer",
    "/telephone/handler",
    "/telephone/incoming",
    "/websocket/offer",
}

_AUTHORIZATION_HEADER_V1 = "Authorization"
_MAX_AUTHORIZATION_HEADER_CHARACTERS_V1 = 16 * 1024
_MAX_ADMISSION_REQUEST_BYTES_V1 = 1024
_NO_STORE_HEADERS_V1 = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class _AccessTokenValidatorV1(Protocol):
    async def validate_access_token(
        self,
        encoded_access_token: str,
    ) -> AuthenticatedPrincipalV1:
        """Validate a bearer token without retaining or logging it."""


class AdmissionTicketRequestV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    channel: SessionAdmissionChannelV1


class SessionCapabilityResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str = Field(repr=False)
    session_capability: str = Field(repr=False)
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float


class AdmissionTicketResponseV1(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str = Field(repr=False)
    ticket_id: str = Field(repr=False)
    admission_ticket: str = Field(repr=False)
    channel: SessionAdmissionChannelV1
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float


@dataclass(frozen=True, slots=True, repr=False)
class CertificateSessionControlRuntimeV1:
    """Enabled-only references shared by control and transport admission."""

    authority: CertificateSessionAuthorityV1
    access_token_validator: _AccessTokenValidatorV1

    def __repr__(self) -> str:
        return "CertificateSessionControlRuntimeV1(<redacted>)"


def install_certificate_session_control_v1(
    app: FastAPI,
    feature_config: CertificateCaptureFeatureConfigV1,
    *,
    access_token_validator: _AccessTokenValidatorV1 | None = None,
    authority: CertificateSessionAuthorityV1 | None = None,
) -> CertificateSessionControlRuntimeV1 | None:
    """Install the 1C control plane only when certificate capture is enabled."""

    if not feature_config.enabled:
        return None

    if any(getattr(route, "path", None) == "/gradio" for route in app.routes):
        raise CertificateCaptureStartupError("LEGACY_GRADIO_ROUTE_CONFLICT")
    if any(
        getattr(route, "path", None) in _LEGACY_RTC_ROUTE_PATHS_V1
        for route in app.routes
    ):
        raise CertificateCaptureStartupError("RTC_SIGNALING_ROUTE_CONFLICT")

    setattr(
        app.state,
        CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
        True,
    )
    validator = access_token_validator
    if validator is None:
        try:
            validator = create_oidc_access_token_validator_v1(feature_config)
        except Exception:  # noqa: BLE001
            raise CertificateCaptureStartupError(
                "OIDC_VALIDATOR_INITIALIZATION_FAILED"
            ) from None
    if validator is None:
        raise CertificateCaptureStartupError("OIDC_VALIDATOR_INITIALIZATION_FAILED")
    if authority is None:
        try:
            session_authority = CertificateSessionAuthorityV1()
        except SessionAuthorityErrorV1:
            raise CertificateCaptureStartupError(
                "SESSION_AUTHORITY_INITIALIZATION_FAILED"
            ) from None
    else:
        session_authority = authority
    runtime = CertificateSessionControlRuntimeV1(
        authority=session_authority,
        access_token_validator=validator,
    )
    app.state.certificate_session_control_v1 = runtime
    try:
        from service.service_security.manager_authorization import (
            install_manager_authorization_v1,
        )

        manager_runtime = install_manager_authorization_v1(
            app,
            validator,
        )
    except CertificateCaptureStartupError:
        session_authority.close()
        delattr(app.state, "certificate_session_control_v1")
        raise
    except Exception:  # noqa: BLE001
        session_authority.close()
        delattr(app.state, "certificate_session_control_v1")
        raise CertificateCaptureStartupError(
            "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
        ) from None
    if manager_runtime is None:
        session_authority.close()
        delattr(app.state, "certificate_session_control_v1")
        raise CertificateCaptureStartupError(
            "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
        )

    async def authenticated_principal(
        request: Request,
    ) -> AuthenticatedPrincipalV1:
        principal = await require_certificate_control_authorization_v1(
            app,
            request,
        )
        if principal is None:
            raise _http_error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "AUTHENTICATION_UNAVAILABLE",
            )
        return principal

    @app.post(
        "/api/v1/session-capabilities",
        status_code=status.HTTP_201_CREATED,
        response_model=SessionCapabilityResponseV1,
    )
    async def create_session_capability(
        request: Request,
        response: Response,
    ) -> SessionCapabilityResponseV1:
        principal = await authenticated_principal(request)
        try:
            async with session_authority.serialized_transition():
                grant = session_authority.create_session(principal)
        except SessionAuthorityErrorV1 as exception:
            raise _authority_http_error(exception) from None
        _apply_no_store(response)
        return _session_capability_response(grant)

    @app.post(
        "/api/v1/sessions/{session_id}/admission-tickets",
        status_code=status.HTTP_201_CREATED,
        response_model=AdmissionTicketResponseV1,
    )
    async def issue_admission_ticket(
        session_id: str,
        request: Request,
        response: Response,
    ) -> AdmissionTicketResponseV1:
        principal = await authenticated_principal(request)
        session_capability = _extract_session_capability(request)
        admission_channel = await _extract_admission_channel(request)
        try:
            async with session_authority.serialized_transition():
                grant = session_authority.issue_admission_ticket(
                    principal,
                    session_id,
                    session_capability,
                    admission_channel,
                )
        except SessionAuthorityErrorV1 as exception:
            raise _authority_http_error(exception) from None
        _apply_no_store(response)
        return _admission_ticket_response(grant)

    @app.delete(
        "/api/v1/sessions/{session_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    async def revoke_session(
        session_id: str,
        request: Request,
    ) -> Response:
        principal = await authenticated_principal(request)
        session_capability = _extract_session_capability(request)
        try:
            async with session_authority.serialized_transition():
                session_authority.revoke_session(
                    principal,
                    session_id,
                    session_capability,
                )
        except SessionAuthorityErrorV1 as exception:
            raise _authority_http_error(exception) from None
        return Response(
            status_code=status.HTTP_204_NO_CONTENT,
            headers=_NO_STORE_HEADERS_V1,
        )

    async def close_session_authority() -> None:
        async with session_authority.serialized_transition():
            session_authority.close()

    app.add_event_handler("shutdown", close_session_authority)
    return runtime


async def require_certificate_control_authorization_v1(
    app: FastAPI,
    request: Request,
) -> AuthenticatedPrincipalV1 | None:
    """Require certificate scope for an enabled-mode control-plane surface."""

    if not (
        getattr(
            app.state,
            CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
            False,
        )
        or getattr(app.state, "certificate_session_control_v1", None)
        is not None
    ):
        return None
    runtime = getattr(app.state, "certificate_session_control_v1", None)
    if not isinstance(runtime, CertificateSessionControlRuntimeV1):
        raise _http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "AUTHENTICATION_UNAVAILABLE",
        )

    encoded_access_token = _extract_bearer_token(request)
    try:
        principal = await runtime.access_token_validator.validate_access_token(
            encoded_access_token
        )
    except OidcAuthenticationErrorV1:
        raise _http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        ) from None
    except Exception:  # noqa: BLE001
        raise _http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "AUTHENTICATION_UNAVAILABLE",
        ) from None

    if (
        not isinstance(principal, AuthenticatedPrincipalV1)
        or OIDC_CERTIFICATE_CAPTURE_SCOPE_V1 not in principal.scopes
    ):
        raise _http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        )
    return principal


def _extract_bearer_token(request: Request) -> str:
    values = request.headers.getlist(_AUTHORIZATION_HEADER_V1)
    if len(values) != 1:
        raise _http_error(
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
        raise _http_error(
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
        raise _http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        )
    return encoded_access_token


def _extract_session_capability(request: Request) -> str:
    values = request.headers.getlist(SESSION_CAPABILITY_HEADER_V1)
    if len(values) != 1:
        raise _http_error(
            status.HTTP_404_NOT_FOUND,
            SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value,
        )
    return values[0]


async def _extract_admission_channel(
    request: Request,
) -> SessionAdmissionChannelV1:
    content_types = request.headers.getlist("Content-Type")
    if (
        len(content_types) != 1
        or content_types[0].partition(";")[0].strip().casefold() != "application/json"
    ):
        raise _admission_request_http_error()

    body = bytearray()
    try:
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > _MAX_ADMISSION_REQUEST_BYTES_V1:
                raise _AdmissionRequestInvalidV1
    except _AdmissionRequestInvalidV1:
        raise _admission_request_http_error() from None
    # Transport/body-stream failures remain value-free and fail closed.
    except Exception:  # noqa: BLE001
        raise _admission_request_http_error() from None

    try:
        decoded = json.loads(
            bytes(body),
            object_pairs_hook=_unique_json_object,
        )
        admission_request = AdmissionTicketRequestV1.model_validate(decoded)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        _AdmissionRequestInvalidV1,
        RecursionError,
    ):
        raise _admission_request_http_error() from None
    return admission_request.channel


class _AdmissionRequestInvalidV1(ValueError):
    pass


def _unique_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise _AdmissionRequestInvalidV1
        output[key] = value
    return output


def _admission_request_http_error() -> HTTPException:
    return _http_error(
        status.HTTP_400_BAD_REQUEST,
        SessionAuthorityReasonV1.ADMISSION_CHANNEL_INVALID.value,
    )


def _authority_http_error(
    exception: SessionAuthorityErrorV1,
) -> HTTPException:
    reason_code = exception.reason_code
    if reason_code == SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value:
        return _http_error(
            status.HTTP_404_NOT_FOUND,
            SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value,
        )
    if reason_code in {
        SessionAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID.value,
        SessionAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED.value,
    }:
        return _http_error(
            status.HTTP_401_UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            authenticate=True,
        )
    if reason_code == SessionAuthorityReasonV1.ADMISSION_CHANNEL_INVALID.value:
        return _http_error(
            status.HTTP_400_BAD_REQUEST,
            SessionAuthorityReasonV1.ADMISSION_CHANNEL_INVALID.value,
        )
    return _http_error(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "SESSION_AUTHORITY_UNAVAILABLE",
    )


def _http_error(
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


def _session_capability_response(
    grant: SessionCapabilityGrantV1,
) -> SessionCapabilityResponseV1:
    return SessionCapabilityResponseV1(
        session_id=grant.session_id,
        session_capability=grant.session_capability,
        issued_at_epoch_seconds=grant.issued_at_epoch_seconds,
        expires_at_epoch_seconds=grant.expires_at_epoch_seconds,
    )


def _admission_ticket_response(
    grant: AdmissionTicketGrantV1,
) -> AdmissionTicketResponseV1:
    return AdmissionTicketResponseV1(
        session_id=grant.session_id,
        ticket_id=grant.ticket_id,
        admission_ticket=grant.admission_ticket,
        channel=grant.channel,
        issued_at_epoch_seconds=grant.issued_at_epoch_seconds,
        expires_at_epoch_seconds=grant.expires_at_epoch_seconds,
    )


def _apply_no_store(response: Response) -> None:
    for header_name, header_value in _NO_STORE_HEADERS_V1.items():
        response.headers[header_name] = header_value

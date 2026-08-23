from __future__ import annotations

import base64
import sys
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from loguru import logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
)
from service.service_security import certificate_session_control
from service.service_security.certificate_session_authority import (
    CertificateSessionAuthorityV1,
    SessionAdmissionChannelV1,
    SessionAuthorityErrorV1,
    SessionAuthorityReasonV1,
)
from service.service_security.certificate_session_control import (
    CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
    SESSION_CAPABILITY_HEADER_V1,
    install_certificate_session_control_v1,
)
from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
    OidcAuthenticationReasonV1,
    OidcRequiredScopeV1,
)
from service.service_utils.ssl_helpers import CertificateCaptureStartupError

NOW = 2_000_000_000
ISSUER = "https://issuer.example.test"


def _feature_config(
    *,
    enabled: bool = True,
) -> CertificateCaptureFeatureConfigV1:
    if not enabled:
        return CertificateCaptureFeatureConfigV1()
    return CertificateCaptureFeatureConfigV1.model_validate(
        {
            "enabled": True,
            "oidc": {
                "issuer": ISSUER,
                "jwks_url": f"{ISSUER}/.well-known/jwks.json",
                "audience": "open-avatar-chat",
                "allowed_algorithms": ["RS256"],
                "required_scope": "certificate:capture",
            },
        }
    )


def _principal(
    *,
    issuer: str = ISSUER,
    subject: str = "owner",
) -> AuthenticatedPrincipalV1:
    return AuthenticatedPrincipalV1(
        issuer=issuer,
        subject=subject,
        scopes=frozenset({"certificate:capture"}),
        token_expiry_epoch_seconds=NOW + 3600,
    )


class FakeAccessTokenValidator:
    def __init__(self, principals_by_token: dict[str, AuthenticatedPrincipalV1]):
        self._principals_by_token = principals_by_token
        self.calls: list[str] = []

    async def validate_access_token(
        self,
        encoded_access_token: str,
    ) -> AuthenticatedPrincipalV1:
        self.calls.append(encoded_access_token)
        principal = self._principals_by_token.get(encoded_access_token)
        if principal is None:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNATURE_INVALID
            )
        return principal

    async def validate_access_token_for_scope(
        self,
        encoded_access_token: str,
        required_scope: OidcRequiredScopeV1,
    ) -> AuthenticatedPrincipalV1:
        principal = await self.validate_access_token(encoded_access_token)
        if required_scope not in principal.scopes:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING
            )
        return principal


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _asgi_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://service.example.test",
    )


def _install(
    *,
    principals_by_token: dict[str, AuthenticatedPrincipalV1] | None = None,
) -> tuple[FastAPI, FakeAccessTokenValidator, CertificateSessionAuthorityV1]:
    app = FastAPI(docs_url=None, redoc_url=None)
    validator = FakeAccessTokenValidator(
        principals_by_token
        if principals_by_token is not None
        else {"owner-token": _principal()}
    )
    authority = CertificateSessionAuthorityV1(
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 10_000,
    )
    runtime = install_certificate_session_control_v1(
        app,
        _feature_config(),
        access_token_validator=validator,
        authority=authority,
    )
    assert runtime is not None
    assert runtime.authority is authority
    return app, validator, authority


def test_disabled_mode_installs_no_store_service_routes_or_shutdown_work(
    monkeypatch,
):
    app = FastAPI(docs_url=None, redoc_url=None)
    original_paths = [route.path for route in app.routes]
    validator_factory = Mock(
        side_effect=AssertionError("validator must not be created")
    )
    authority_factory = Mock(
        side_effect=AssertionError("authority must not be created")
    )
    monkeypatch.setattr(
        certificate_session_control,
        "create_oidc_access_token_validator_v1",
        validator_factory,
    )
    monkeypatch.setattr(
        certificate_session_control,
        "CertificateSessionAuthorityV1",
        authority_factory,
    )

    runtime = install_certificate_session_control_v1(
        app,
        _feature_config(enabled=False),
    )

    assert runtime is None
    assert [route.path for route in app.routes] == original_paths
    assert not hasattr(app.state, "certificate_session_control_v1")
    assert app.router.on_shutdown == []
    validator_factory.assert_not_called()
    authority_factory.assert_not_called()


def test_enabled_mode_authority_initialization_failure_is_stable_and_fail_closed(
    monkeypatch,
):
    app = FastAPI(docs_url=None, redoc_url=None)
    validator = FakeAccessTokenValidator({"owner-token": _principal()})
    monkeypatch.setattr(
        certificate_session_control,
        "CertificateSessionAuthorityV1",
        Mock(
            side_effect=SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            )
        ),
    )

    with pytest.raises(CertificateCaptureStartupError) as exception:
        install_certificate_session_control_v1(
            app,
            _feature_config(),
            access_token_validator=validator,
        )

    assert exception.value.reason_code == "SESSION_AUTHORITY_INITIALIZATION_FAILED"
    assert not hasattr(app.state, "certificate_session_control_v1")
    assert not any(route.path.startswith("/api/v1/session") for route in app.routes)


@pytest.mark.asyncio
async def test_https_session_control_uses_only_validated_principal_and_server_identity():
    principal = _principal(
        issuer="https://validated-issuer.example.test",
        subject="validated-subject",
    )
    app, validator, authority = _install(
        principals_by_token={"opaque-access-token": principal}
    )

    async with _asgi_client(app) as client:
        response = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("opaque-access-token"),
            json={
                "session_id": "caller-selected-session",
                "webrtc_id": "caller-selected-webrtc",
                "issuer": "caller-issuer",
                "subject": "caller-subject",
            },
        )
        assert response.status_code == 201
        payload = response.json()
        assert payload["session_id"] != "caller-selected-session"
        assert payload["session_id"] != "caller-selected-webrtc"
        assert payload["session_id"].startswith("cs1_")
        assert (
            len(
                base64.urlsafe_b64decode(
                    payload["session_id"].removeprefix("cs1_") + "="
                )
            )
            == 32
        )
        assert payload["session_capability"].startswith("csc1_")
        assert response.headers["cache-control"] == "no-store"
        ownership = authority.get_session_ownership(
            principal,
            payload["session_id"],
            payload["session_capability"],
        )
        assert ownership.owner_issuer == principal.issuer
        assert ownership.owner_subject == principal.subject
    assert validator.calls == ["opaque-access-token"]


@pytest.mark.asyncio
async def test_ticket_issue_route_and_internal_consume_seam_are_channel_bound():
    principal = _principal()
    app, _, authority = _install()

    async with _asgi_client(app) as client:
        session_response = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("owner-token"),
        )
        session = session_response.json()
        ticket_response = await client.post(
            f"/api/v1/sessions/{session['session_id']}/admission-tickets",
            headers={
                **_authorization("owner-token"),
                SESSION_CAPABILITY_HEADER_V1: session["session_capability"],
            },
            json={"channel": "websocket"},
        )

        assert ticket_response.status_code == 201
        assert ticket_response.headers["cache-control"] == "no-store"
        ticket = ticket_response.json()
        assert ticket["channel"] == "websocket"
        assert ticket["admission_ticket"].startswith("att1_")
        assert ticket["ticket_id"].startswith("ati1_")

        admission = authority.consume_admission_ticket(
            principal,
            session["session_id"],
            ticket["admission_ticket"],
            SessionAdmissionChannelV1.WEBSOCKET,
        )
        assert admission.ticket_id == ticket["ticket_id"]

        route_paths = {route.path for route in app.routes}
        assert not any("consume" in path for path in route_paths)
        assert not any(path.startswith("/ws") for path in route_paths)


@pytest.mark.asyncio
async def test_unknown_session_and_wrong_owner_are_http_indistinguishable():
    owner = _principal()
    other = _principal(
        issuer="https://other-issuer.example.test",
        subject=owner.subject,
    )
    app, _, _ = _install(
        principals_by_token={
            "owner-token": owner,
            "other-token": other,
        }
    )

    async with _asgi_client(app) as client:
        created = (
            await client.post(
                "/api/v1/session-capabilities",
                headers=_authorization("owner-token"),
            )
        ).json()
        wrong_owner = await client.post(
            f"/api/v1/sessions/{created['session_id']}/admission-tickets",
            headers={
                **_authorization("other-token"),
                SESSION_CAPABILITY_HEADER_V1: created["session_capability"],
            },
            json={"channel": "rtc"},
        )
        guessed = await client.post(
            f"/api/v1/sessions/{'cs1_' + 'A' * 43}/admission-tickets",
            headers={
                **_authorization("owner-token"),
                SESSION_CAPABILITY_HEADER_V1: created["session_capability"],
            },
            json={"channel": "rtc"},
        )

    assert wrong_owner.status_code == guessed.status_code == 404
    assert (
        wrong_owner.json()
        == guessed.json()
        == {
            "detail": {
                "reason_code": SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value
            }
        }
    )


@pytest.mark.asyncio
async def test_invalid_admission_requests_use_stable_non_echoing_error_code():
    app, _, authority = _install()

    async with _asgi_client(app) as client:
        created = (
            await client.post(
                "/api/v1/session-capabilities",
                headers=_authorization("owner-token"),
            )
        ).json()
        common_headers = {
            **_authorization("owner-token"),
            SESSION_CAPABILITY_HEADER_V1: created["session_capability"],
        }
        invalid_channel = await client.post(
            f"/api/v1/sessions/{created['session_id']}/admission-tickets",
            headers=common_headers,
            json={"channel": "invalid-channel-canary"},
        )
        untrusted_principal_field = await client.post(
            f"/api/v1/sessions/{created['session_id']}/admission-tickets",
            headers=common_headers,
            json={
                "channel": "websocket",
                "subject": "body-subject-canary",
            },
        )
        duplicate_channel = await client.post(
            f"/api/v1/sessions/{created['session_id']}/admission-tickets",
            headers={
                **common_headers,
                "Content-Type": "application/json",
            },
            content='{"channel":"websocket","channel":"rtc"}',
        )

    expected = {
        "detail": {
            "reason_code": (SessionAuthorityReasonV1.ADMISSION_CHANNEL_INVALID.value)
        }
    }
    assert invalid_channel.status_code == 400
    assert untrusted_principal_field.status_code == 400
    assert duplicate_channel.status_code == 400
    assert invalid_channel.json() == expected
    assert untrusted_principal_field.json() == expected
    assert duplicate_channel.json() == expected
    visible_errors = (
        invalid_channel.text + untrusted_principal_field.text + duplicate_channel.text
    )
    assert "invalid-channel-canary" not in visible_errors
    assert "body-subject-canary" not in visible_errors
    assert authority.snapshot().active_tickets == 0


@pytest.mark.asyncio
async def test_revoke_route_invalidates_session_and_returns_no_secret_body():
    app, _, authority = _install()
    principal = _principal()
    retired_sessions: list[str] = []

    class _Lifecycle:
        @staticmethod
        async def retire_secure_session_v1(session_id: str) -> None:
            retired_sessions.append(session_id)

    setattr(
        app.state,
        CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
        _Lifecycle(),
    )

    async with _asgi_client(app) as client:
        created = (
            await client.post(
                "/api/v1/session-capabilities",
                headers=_authorization("owner-token"),
            )
        ).json()
        response = await client.delete(
            f"/api/v1/sessions/{created['session_id']}",
            headers={
                **_authorization("owner-token"),
                SESSION_CAPABILITY_HEADER_V1: created["session_capability"],
            },
        )
        assert response.status_code == 204
        assert response.content == b""
        assert response.headers["cache-control"] == "no-store"
        assert retired_sessions == [created["session_id"]]
        with pytest.raises(SessionAuthorityErrorV1) as exception:
            authority.get_session_ownership(
                principal,
                created["session_id"],
                created["session_capability"],
            )
        assert (
            exception.value.reason_code
            == SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value
        )


@pytest.mark.asyncio
async def test_revoke_route_fails_closed_without_application_lifecycle():
    app, _, authority = _install()
    principal = _principal()

    async with _asgi_client(app) as client:
        created = (
            await client.post(
                "/api/v1/session-capabilities",
                headers=_authorization("owner-token"),
            )
        ).json()
        response = await client.delete(
            f"/api/v1/sessions/{created['session_id']}",
            headers={
                **_authorization("owner-token"),
                SESSION_CAPABILITY_HEADER_V1: created[
                    "session_capability"
                ],
            },
        )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "reason_code": "SESSION_LIFECYCLE_UNAVAILABLE"
        }
    }
    with pytest.raises(SessionAuthorityErrorV1):
        authority.get_session_ownership(
            principal,
            created["session_id"],
            created["session_capability"],
        )


@pytest.mark.asyncio
async def test_replacement_fails_closed_without_application_lifecycle():
    app, _, _ = _install()

    async with _asgi_client(app) as client:
        first = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("owner-token"),
        )
        replacement = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("owner-token"),
        )

    assert first.status_code == 201
    assert replacement.status_code == 503
    assert replacement.json() == {
        "detail": {
            "reason_code": "SESSION_LIFECYCLE_UNAVAILABLE"
        }
    }


@pytest.mark.asyncio
async def test_authentication_errors_are_stable_and_do_not_echo_access_token():
    access_token_canary = "raw-access-token-canary"
    app, validator, _ = _install()

    async with _asgi_client(app) as client:
        missing = await client.post("/api/v1/session-capabilities")
        invalid = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization(access_token_canary),
        )

    assert missing.status_code == invalid.status_code == 401
    assert missing.json()["detail"]["reason_code"] == "AUTHENTICATION_REQUIRED"
    assert invalid.json()["detail"]["reason_code"] == "AUTHENTICATION_FAILED"
    assert access_token_canary not in invalid.text
    assert validator.calls == [access_token_canary]


@pytest.mark.asyncio
async def test_route_failures_and_logs_do_not_leak_principal_or_session_secrets():
    issuer_canary = "https://issuer-route-canary.example.test"
    subject_canary = "subject-route-canary"
    token_canary = "token-route-canary"
    principal = _principal(
        issuer=issuer_canary,
        subject=subject_canary,
    )
    app, _, _ = _install(principals_by_token={token_canary: principal})
    log_messages: list[str] = []
    sink_id = logger.add(log_messages.append, format="{message}")
    try:
        async with _asgi_client(app) as client:
            created = (
                await client.post(
                    "/api/v1/session-capabilities",
                    headers=_authorization(token_canary),
                )
            ).json()
            ticket = (
                await client.post(
                    (f"/api/v1/sessions/{created['session_id']}/admission-tickets"),
                    headers={
                        **_authorization(token_canary),
                        SESSION_CAPABILITY_HEADER_V1: created["session_capability"],
                    },
                    json={"channel": "websocket"},
                )
            ).json()
            failure = await client.post(
                (f"/api/v1/sessions/{created['session_id']}/admission-tickets"),
                headers={
                    **_authorization(token_canary),
                    SESSION_CAPABILITY_HEADER_V1: "wrong-capability-canary",
                },
                json={"channel": "websocket"},
            )
    finally:
        logger.remove(sink_id)

    visible_logs = "".join(log_messages)
    assert failure.status_code == 404
    canaries = [
        issuer_canary,
        subject_canary,
        token_canary,
        created["session_capability"],
        ticket["admission_ticket"],
        "wrong-capability-canary",
    ]
    assert all(canary not in visible_logs for canary in canaries)
    assert all(canary not in failure.text for canary in canaries)


@pytest.mark.asyncio
async def test_app_shutdown_destroys_process_local_authority():
    app, _, authority = _install()

    async with app.router.lifespan_context(app), _asgi_client(app) as client:
        response = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("owner-token"),
        )
        assert response.status_code == 201
        assert authority.snapshot().active_sessions == 1

    assert authority.snapshot().active_sessions == 0
    assert authority.snapshot().active_tickets == 0
    assert authority.snapshot().closed is True

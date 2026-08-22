from __future__ import annotations

import concurrent.futures
import logging
import sys
import threading
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Response
from loguru import logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from service.manager_service import manager_service_register
from service.manager_service.manager_service_register import (
    register_manager_apis,
)
from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
)
from service.service_security import manager_authorization
from service.service_security.certificate_session_authority import (
    CertificateSessionAuthorityV1,
)
from service.service_security.certificate_session_control import (
    SESSION_CAPABILITY_HEADER_V1,
    install_certificate_session_control_v1,
)
from service.service_security.manager_authorization import (
    MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
    ManagerAuthorizationRuntimeV1,
    install_manager_authorization_v1,
)
from service.service_security.manager_websocket_authority import (
    MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1,
    MANAGER_WEBSOCKET_TICKET_PREFIX_V1,
    ConsumedManagerWebSocketAdmissionV1,
    ManagerWebSocketAuthorityErrorV1,
    ManagerWebSocketAuthorityReasonV1,
    ManagerWebSocketTicketAuthorityV1,
)
from service.service_security.oidc_resource_server import (
    OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
    OIDC_MANAGER_SCOPE_V1,
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
    OidcAuthenticationReasonV1,
    OidcRequiredScopeV1,
)
from service.service_utils.ssl_helpers import CertificateCaptureStartupError

NOW = 2_000_000_000.0
ISSUER = "https://issuer.example.test"


class FakeClock:
    def __init__(self):
        self.epoch = NOW
        self.monotonic = 10_000.0

    def wall_time(self) -> float:
        return self.epoch

    def monotonic_time(self) -> float:
        return self.monotonic

    def advance(self, seconds: float) -> None:
        self.epoch += seconds
        self.monotonic += seconds


class ScopedAccessTokenValidator:
    def __init__(
        self,
        principals_by_token: dict[str, AuthenticatedPrincipalV1],
    ):
        self.principals_by_token = principals_by_token
        self.calls: list[tuple[str, str]] = []

    async def validate_access_token(
        self,
        encoded_access_token: str,
    ) -> AuthenticatedPrincipalV1:
        return await self._validate(
            encoded_access_token,
            OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
        )

    async def validate_access_token_for_scope(
        self,
        encoded_access_token: str,
        required_scope: OidcRequiredScopeV1,
    ) -> AuthenticatedPrincipalV1:
        return await self._validate(encoded_access_token, required_scope)

    async def _validate(
        self,
        encoded_access_token: str,
        required_scope: str,
    ) -> AuthenticatedPrincipalV1:
        self.calls.append((encoded_access_token, required_scope))
        principal = self.principals_by_token.get(encoded_access_token)
        if principal is None:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNATURE_INVALID
            )
        if principal.token_expiry_epoch_seconds <= NOW:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.TOKEN_EXPIRED
            )
        if required_scope not in principal.scopes:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING
            )
        return principal


def _principal(
    *scopes: str,
    subject: str = "manager",
    token_expiry: float = NOW + 3600,
) -> AuthenticatedPrincipalV1:
    return AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject=subject,
        scopes=frozenset(scopes),
        token_expiry_epoch_seconds=token_expiry,
    )


def _feature_config() -> CertificateCaptureFeatureConfigV1:
    return CertificateCaptureFeatureConfigV1.model_validate(
        {
            "enabled": True,
            "oidc": {
                "issuer": ISSUER,
                "jwks_url": f"{ISSUER}/.well-known/jwks.json",
                "audience": "open-avatar-chat",
                "allowed_algorithms": ["RS256"],
                "required_scope": OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
            },
        }
    )


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _asgi_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://service.example.test",
    )


def _install_manager_app(
    principals_by_token: dict[str, AuthenticatedPrincipalV1],
    *,
    clock: FakeClock | None = None,
) -> tuple[
    FastAPI,
    ScopedAccessTokenValidator,
    ManagerWebSocketTicketAuthorityV1,
]:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.certificate_capture_enabled_v1 = True
    validator = ScopedAccessTokenValidator(principals_by_token)
    active_clock = clock or FakeClock()
    authority = ManagerWebSocketTicketAuthorityV1(
        wall_clock=active_clock.wall_time,
        monotonic_clock=active_clock.monotonic_time,
    )
    runtime = install_manager_authorization_v1(
        app,
        validator,
        ticket_authority=authority,
    )
    assert isinstance(runtime, ManagerAuthorizationRuntimeV1)
    return app, validator, authority


def test_missing_scoped_validator_fails_closed_at_manager_startup():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.certificate_capture_enabled_v1 = True

    with pytest.raises(CertificateCaptureStartupError) as exception:
        install_manager_authorization_v1(app, object())

    assert exception.value.reason_code == (
        "MANAGER_AUTHORIZATION_INITIALIZATION_FAILED"
    )
    assert not hasattr(app.state, "manager_authorization_v1")
    assert not any(
        route.path == MANAGER_WEBSOCKET_TICKET_ROUTE_V1
        for route in app.routes
    )
    assert app.router.on_shutdown == []


def test_manager_ticket_has_256_bits_server_side_digest_and_sixty_second_life():
    clock = FakeClock()
    authority = ManagerWebSocketTicketAuthorityV1(
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )

    grant = authority.issue(_principal(OIDC_MANAGER_SCOPE_V1))

    assert grant.admission_ticket.startswith(MANAGER_WEBSOCKET_TICKET_PREFIX_V1)
    assert len(grant.admission_ticket.removeprefix("mat1_")) == 43
    assert (
        grant.expires_at_epoch_seconds - grant.issued_at_epoch_seconds
        == MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1
    )
    stored_ticket_digests = tuple(authority._tickets)
    assert len(stored_ticket_digests) == 1
    assert isinstance(stored_ticket_digests[0], bytes)
    assert grant.admission_ticket.encode() not in stored_ticket_digests[0]
    assert grant.admission_ticket not in repr(authority._tickets)
    assert repr(grant) == "ManagerWebSocketTicketGrantV1(<redacted>)"


def test_manager_authority_rejects_certificate_scope_and_caps_at_token_expiry():
    clock = FakeClock()
    authority = ManagerWebSocketTicketAuthorityV1(
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )

    with pytest.raises(ManagerWebSocketAuthorityErrorV1) as exception:
        authority.issue(_principal(OIDC_CERTIFICATE_CAPTURE_SCOPE_V1))
    assert (
        exception.value.reason_code
        == ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID.value
    )

    grant = authority.issue(
        _principal(
            OIDC_MANAGER_SCOPE_V1,
            token_expiry=NOW + 12,
        )
    )
    assert grant.expires_at_epoch_seconds == NOW + 12


def test_manager_ticket_is_one_use_under_concurrent_double_consumption():
    authority = ManagerWebSocketTicketAuthorityV1()
    grant = authority.issue(_principal(OIDC_MANAGER_SCOPE_V1))
    start = threading.Barrier(2)

    def consume():
        start.wait()
        try:
            return authority.consume(grant.admission_ticket)
        except ManagerWebSocketAuthorityErrorV1 as exception:
            return exception

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = [
            future.result(timeout=5)
            for future in (executor.submit(consume), executor.submit(consume))
        ]

    admissions = [
        result
        for result in results
        if isinstance(result, ConsumedManagerWebSocketAdmissionV1)
    ]
    failures = [
        result
        for result in results
        if isinstance(result, ManagerWebSocketAuthorityErrorV1)
    ]
    assert len(admissions) == 1
    assert len(failures) == 1
    assert (
        failures[0].reason_code
        == ManagerWebSocketAuthorityReasonV1.TICKET_ACCESS_DENIED.value
    )
    assert authority.snapshot().active_tickets == 0


def test_expired_manager_ticket_is_denied_and_removed():
    clock = FakeClock()
    authority = ManagerWebSocketTicketAuthorityV1(
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    grant = authority.issue(_principal(OIDC_MANAGER_SCOPE_V1))
    clock.advance(MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1)

    with pytest.raises(ManagerWebSocketAuthorityErrorV1) as exception:
        authority.consume(grant.admission_ticket)

    assert (
        exception.value.reason_code
        == ManagerWebSocketAuthorityReasonV1.TICKET_ACCESS_DENIED.value
    )
    assert authority.snapshot().active_tickets == 0


@pytest.mark.asyncio
async def test_manager_and_certificate_scopes_remain_independent():
    certificate_only = _principal(
        OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
        subject="certificate-only",
    )
    manager_only = _principal(
        OIDC_MANAGER_SCOPE_V1,
        subject="manager-only",
    )
    both = _principal(
        OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
        OIDC_MANAGER_SCOPE_V1,
        subject="both",
    )
    validator = ScopedAccessTokenValidator(
        {
            "certificate-token": certificate_only,
            "manager-token": manager_only,
            "both-token": both,
        }
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    session_authority = CertificateSessionAuthorityV1(
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 10_000,
    )
    install_certificate_session_control_v1(
        app,
        _feature_config(),
        access_token_validator=validator,
        authority=session_authority,
    )

    async with _asgi_client(app) as client:
        manager_success = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("manager-token"),
        )
        manager_both = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("both-token"),
        )
        manager_certificate_only = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("certificate-token"),
        )
        assert session_authority.snapshot().active_sessions == 0

        certificate_success = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("certificate-token"),
        )
        certificate_both = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("both-token"),
        )
        certificate_manager_only = await client.post(
            "/api/v1/session-capabilities",
            headers=_authorization("manager-token"),
        )

    assert manager_success.status_code == manager_both.status_code == 201
    assert set(manager_success.json()) == {
        "admission_ticket",
        "purpose",
        "expires_at_epoch_seconds",
    }
    assert manager_success.json()["purpose"] == "manager_websocket"
    assert manager_certificate_only.status_code == 403
    assert certificate_success.status_code == certificate_both.status_code == 201
    assert certificate_manager_only.status_code == 401
    assert (
        manager_success.json()["admission_ticket"]
        != manager_both.json()["admission_ticket"]
    )


@pytest.mark.asyncio
async def test_manager_ticket_endpoint_has_stable_authentication_errors():
    app, _, authority = _install_manager_app(
        {
            "manager-token": _principal(OIDC_MANAGER_SCOPE_V1),
            "certificate-token": _principal(
                OIDC_CERTIFICATE_CAPTURE_SCOPE_V1
            ),
            "expired-token": _principal(
                OIDC_MANAGER_SCOPE_V1,
                token_expiry=NOW,
            ),
        }
    )

    async with _asgi_client(app) as client:
        missing = await client.post(MANAGER_WEBSOCKET_TICKET_ROUTE_V1)
        invalid = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("invalid-token-canary"),
        )
        expired = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("expired-token"),
        )
        wrong_scope = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("certificate-token"),
        )
        query_only = await client.post(
            f"{MANAGER_WEBSOCKET_TICKET_ROUTE_V1}?access_token=manager-token"
        )

    assert missing.status_code == invalid.status_code == expired.status_code == 401
    assert query_only.status_code == 401
    assert wrong_scope.status_code == 403
    assert missing.json()["detail"]["reason_code"] == "AUTHENTICATION_REQUIRED"
    assert invalid.json()["detail"]["reason_code"] == "AUTHENTICATION_FAILED"
    assert wrong_scope.json()["detail"]["reason_code"] == (
        "MANAGER_AUTHORIZATION_DENIED"
    )
    assert "invalid-token-canary" not in invalid.text
    assert authority.snapshot().active_tickets == 0


def test_enabled_manager_access_log_filter_redacts_query_and_path_canaries():
    app, _, _ = _install_manager_app(
        {"manager-token": _principal(OIDC_MANAGER_SCOPE_V1)}
    )
    del app
    access_filter = next(
        selected_filter
        for selected_filter in logging.getLogger("uvicorn.access").filters
        if getattr(
            selected_filter,
            "_openavatar_secure_manager_access_filter_v1",
            False,
        )
    )
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "client",
            "GET",
            (
                "/download/manager/data_tool/file"
                "?file_path=protected-path-canary.wav"
                "&access_token=manager-token-canary"
            ),
            "1.1",
            401,
        ),
        None,
    )
    assert access_filter.filter(record) is True
    assert record.args[2] == "/download/manager/data_tool/file"

    malformed_path = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "client",
            "GET",
            "/ws/manager/data_tool/mat1_" + "A" * 43,
            "1.1",
            404,
        ),
        None,
    )
    assert access_filter.filter(malformed_path) is True
    assert malformed_path.args[2] == "/ws/manager/data_tool/<redacted>"

    unrelated = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("client", "GET", "/public?value=legacy", "1.1", 200),
        None,
    )
    assert access_filter.filter(unrelated) is True
    assert unrelated.args[2] == "/public?value=legacy"
    assert isinstance(
        access_filter,
        manager_authorization._SecureManagerAccessLogFilterV1,
    )


@pytest.mark.asyncio
async def test_manager_authority_shutdown_invalidates_unused_tickets():
    app, _, authority = _install_manager_app(
        {"manager-token": _principal(OIDC_MANAGER_SCOPE_V1)}
    )

    async with app.router.lifespan_context(app), _asgi_client(app) as client:
        response = await client.post(
            MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
            headers=_authorization("manager-token"),
        )
        assert response.status_code == 201
        ticket = response.json()["admission_ticket"]
        assert authority.snapshot().active_tickets == 1

    assert authority.snapshot().active_tickets == 0
    assert authority.snapshot().closed is True
    with pytest.raises(ManagerWebSocketAuthorityErrorV1):
        authority.consume(ticket)


@pytest.mark.asyncio
async def test_download_authorizes_before_any_filesystem_lookup(
    tmp_path,
    monkeypatch,
):
    app, _, _ = _install_manager_app(
        {
            "manager-token": _principal(OIDC_MANAGER_SCOPE_V1),
            "certificate-token": _principal(
                OIDC_CERTIFICATE_CAPTURE_SCOPE_V1
            ),
        }
    )
    base_dir_calls: list[str] = []

    def get_base_dir() -> Path:
        base_dir_calls.append("base_dir")
        return tmp_path

    monkeypatch.setattr(manager_service_register, "_data_tool_service", None)
    monkeypatch.setattr(
        manager_service_register,
        "get_data_tool_base_dir",
        get_base_dir,
    )
    protected_dir = tmp_path / "session"
    protected_dir.mkdir()
    protected_file = protected_dir / "protected-file-canary.wav"
    protected_file.write_bytes(b"manager-file")
    file_response_calls: list[Path] = []

    def file_response(path: Path) -> Response:
        file_response_calls.append(path)
        return Response(content=path.read_bytes())

    monkeypatch.setattr(manager_service_register, "FileResponse", file_response)
    register_manager_apis(app)

    async with _asgi_client(app) as client:
        missing_existing = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "session/protected-file-canary.wav"},
        )
        missing_absent = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "session/absent-file-canary.wav"},
        )
        wrong_scope = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "session/protected-file-canary.wav"},
            headers=_authorization("certificate-token"),
        )
        query_credential = await client.get(
            "/download/manager/data_tool/file",
            params={
                "file_path": "session/protected-file-canary.wav",
                "access_token": "manager-token",
            },
        )
        session_capability = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "session/protected-file-canary.wav"},
            headers={SESSION_CAPABILITY_HEADER_V1: "csc1_" + "A" * 43},
        )
        assert base_dir_calls == []

        valid = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "session/protected-file-canary.wav"},
            headers=_authorization("manager-token"),
        )
        traversal = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "../outside-file-canary.wav"},
            headers=_authorization("manager-token"),
        )
        absent = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "session/absent-file-canary.wav"},
            headers=_authorization("manager-token"),
        )

    assert missing_existing.status_code == missing_absent.status_code == 401
    assert missing_existing.json() == missing_absent.json()
    assert wrong_scope.status_code == 403
    assert query_credential.status_code == 401
    assert session_capability.status_code == 401
    assert valid.status_code == 200
    assert valid.content == b"manager-file"
    assert file_response_calls == [protected_file]
    assert traversal.status_code == 400
    assert absent.status_code == 404
    assert base_dir_calls == ["base_dir", "base_dir", "base_dir"]
    unauthorized_output = (
        missing_existing.text
        + missing_absent.text
        + wrong_scope.text
        + query_credential.text
        + session_capability.text
    )
    assert "protected-file-canary" not in unauthorized_output
    assert "absent-file-canary" not in unauthorized_output


@pytest.mark.asyncio
async def test_download_rejects_other_ticket_domains_and_redacts_logs(
    tmp_path,
    monkeypatch,
):
    issuer_canary = "https://manager-issuer-canary.example.test"
    subject_canary = "manager-subject-canary"
    principal = AuthenticatedPrincipalV1(
        issuer=issuer_canary,
        subject=subject_canary,
        scopes=frozenset({OIDC_MANAGER_SCOPE_V1}),
        token_expiry_epoch_seconds=NOW + 3600,
    )
    app, _, _ = _install_manager_app({"manager-token-canary": principal})
    monkeypatch.setattr(manager_service_register, "_data_tool_service", None)
    monkeypatch.setattr(manager_service_register, "_data_tool_base_dir", tmp_path)
    register_manager_apis(app)
    log_messages: list[str] = []
    sink_id = logger.add(log_messages.append, format="{message}")
    try:
        async with _asgi_client(app) as client:
            manager_ticket = (
                await client.post(
                    MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
                    headers=_authorization("manager-token-canary"),
                )
            ).json()["admission_ticket"]
            rejected = []
            for credential in (
                manager_ticket,
                "att1_" + "A" * 43,
                "rtb1_" + "B" * 43,
                "csc1_" + "C" * 43,
            ):
                rejected.append(
                    await client.get(
                        "/download/manager/data_tool/file",
                        params={"file_path": "protected-path-canary.wav"},
                        headers=_authorization(credential),
                    )
                )
    finally:
        logger.remove(sink_id)

    assert all(response.status_code == 401 for response in rejected)
    visible = "".join(log_messages) + "".join(
        response.text for response in rejected
    )
    for canary in (
        issuer_canary,
        subject_canary,
        "manager-token-canary",
        manager_ticket,
        "att1_" + "A" * 43,
        "rtb1_" + "B" * 43,
        "csc1_" + "C" * 43,
        "protected-path-canary.wav",
    ):
        assert canary not in visible


@pytest.mark.asyncio
async def test_disabled_download_preserves_legacy_behavior(tmp_path, monkeypatch):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    monkeypatch.setattr(manager_service_register, "_data_tool_service", None)
    monkeypatch.setattr(manager_service_register, "_data_tool_base_dir", tmp_path)
    protected = tmp_path / "legacy.wav"
    protected.write_bytes(b"legacy-manager-file")
    monkeypatch.setattr(
        manager_service_register,
        "FileResponse",
        lambda path: Response(content=path.read_bytes()),
    )
    register_manager_apis(app)

    async with _asgi_client(app) as client:
        response = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "legacy.wav"},
        )

    assert response.status_code == 200
    assert response.content == b"legacy-manager-file"
    assert not hasattr(app.state, "manager_authorization_v1")


@pytest.mark.asyncio
async def test_certificate_runtime_marker_without_manager_runtime_fails_closed(
    tmp_path,
    monkeypatch,
):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.certificate_session_control_v1 = object()
    base_dir_calls: list[str] = []
    monkeypatch.setattr(manager_service_register, "_data_tool_service", None)
    monkeypatch.setattr(
        manager_service_register,
        "get_data_tool_base_dir",
        lambda: base_dir_calls.append("lookup") or tmp_path,
    )
    register_manager_apis(app)

    async with _asgi_client(app) as client:
        response = await client.get(
            "/download/manager/data_tool/file",
            params={"file_path": "protected.wav"},
        )

    assert response.status_code == 503
    assert response.json()["detail"]["reason_code"] == (
        "MANAGER_AUTHORIZATION_UNAVAILABLE"
    )
    assert base_dir_calls == []

from __future__ import annotations

import io
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from PIL import Image
from starlette.requests import Request

from certificate_capture.capabilities import CAPTURE_CAPABILITY_HEADER_V1
from certificate_capture.coordinator import CaptureCoordinatorV1
from certificate_capture.frame_ingress import read_bounded_private_jpeg_v1
from certificate_capture.protocol import (
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)
from certificate_capture.routes import install_certificate_capture_routes_v1
from chat_engine.chat_engine import ChatEngine
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from chat_engine.data_models.session_info_data import SessionInfoData
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
)
from service.service_security.certificate_session_authority import (
    CertificateSessionAuthorityV1,
    ConsumedSessionAdmissionV1,
    SessionAdmissionChannelV1,
    SessionOwnershipV1,
)
from service.service_security.certificate_session_control import (
    SESSION_CAPABILITY_HEADER_V1,
    install_certificate_session_control_v1,
)
from service.service_security.oidc_resource_server import (
    OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
    OidcAuthenticationReasonV1,
)
from tests.chat_engine.milestone_4b.conftest import synthetic_jpeg_v1

ISSUER = "https://issuer.example.test"


class RouteAccessTokenValidatorV1:
    def __init__(self, principals: dict[str, AuthenticatedPrincipalV1]) -> None:
        self.principals = principals

    async def validate_access_token(self, token: str) -> AuthenticatedPrincipalV1:
        principal = self.principals.get(token)
        if principal is None:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNATURE_INVALID
            )
        return principal

    async def validate_access_token_for_scope(self, token, required_scope):
        principal = await self.validate_access_token(token)
        if required_scope not in principal.scopes:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING
            )
        return principal


class RouteCaptureSessionV1:
    def __init__(
        self,
        coordinator: CaptureCoordinatorV1,
        ownership: SessionOwnershipV1,
    ) -> None:
        self.coordinator = coordinator
        self.ownership = ownership

    def _require(self, ownership: SessionOwnershipV1) -> None:
        assert ownership == self.ownership

    async def _begin_certificate_capture_protocol_v1(
        self,
        *,
        request_id,
        control_seq,
        profile_id,
        ownership,
    ):
        self._require(ownership)
        return await self.coordinator.begin_capture_protocol_v1(
            request_id=request_id,
            control_seq=control_seq,
            profile_id=profile_id,
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
            session_expires_at_epoch_seconds=(
                ownership.expires_at_epoch_seconds
            ),
        )

    async def _admit_certificate_frame_upload_v1(self, *, ownership, **kwargs):
        self._require(ownership)
        return await self.coordinator.admit_frame_upload_v1(
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
            **kwargs,
        )

    async def _commit_certificate_frame_upload_v1(self, permit, validated):
        return await self.coordinator.commit_frame_upload_v1(
            permit,
            validated,
        )

    def _release_certificate_frame_upload_v1(self, permit) -> None:
        self.coordinator.release_frame_upload_permit_v1(permit)

    async def _seal_certificate_capture_protocol_v1(
        self,
        *,
        ownership,
        **kwargs,
    ):
        self._require(ownership)
        return await self.coordinator.seal_capture_protocol_v1(
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
            **kwargs,
        )

    async def _certificate_capture_public_status_v1(
        self,
        *,
        ownership,
        **kwargs,
    ):
        self._require(ownership)
        return await self.coordinator.capture_public_status_v1(
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
            **kwargs,
        )

    async def _end_certificate_capture_protocol_v1(
        self,
        *,
        ownership,
        **kwargs,
    ):
        self._require(ownership)
        return await self.coordinator.end_capture_protocol_v1(
            session_id=ownership.session_id,
            owner_issuer=ownership.owner_issuer,
            owner_subject=ownership.owner_subject,
            **kwargs,
        )


@dataclass
class RouteResolverV1:
    sessions: dict[str, RouteCaptureSessionV1]

    def _resolve_certificate_capture_session_v1(self, ownership):
        candidate = self.sessions.get(ownership.session_id)
        if candidate is None or candidate.ownership != ownership:
            return None
        return candidate


@dataclass
class RouteHarnessV1:
    app: FastAPI
    authority: CertificateSessionAuthorityV1
    controller: SessionWorkControllerV1
    coordinator: CaptureCoordinatorV1
    ownership: SessionOwnershipV1
    session_capability: str
    token: str = "owner-token"

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            SESSION_CAPABILITY_HEADER_V1: self.session_capability,
        }

    async def close(self) -> None:
        await self.coordinator.shutdown_async_v1()
        await self.controller.shutdown_async()
        async with self.authority.serialized_transition():
            self.authority.close()


def _feature_config(enabled: bool = True) -> CertificateCaptureFeatureConfigV1:
    if not enabled:
        return CertificateCaptureFeatureConfigV1()
    return CertificateCaptureFeatureConfigV1.model_validate(
        {
            "enabled": True,
            "oidc": {
                "issuer": ISSUER,
                "jwks_url": f"{ISSUER}/jwks.json",
                "audience": "open-avatar-chat",
                "allowed_algorithms": ["RS256"],
                "required_scope": OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
            },
        }
    )


@pytest_asyncio.fixture
async def route_harness():
    now = time.time()
    owner = AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject="owner",
        scopes=frozenset({OIDC_CERTIFICATE_CAPTURE_SCOPE_V1}),
        token_expiry_epoch_seconds=now + 900,
    )
    wrong_owner = AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject="wrong-owner",
        scopes=frozenset({OIDC_CERTIFICATE_CAPTURE_SCOPE_V1}),
        token_expiry_epoch_seconds=now + 900,
    )
    wrong_scope = AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject="owner",
        scopes=frozenset({"oac:manager"}),
        token_expiry_epoch_seconds=now + 900,
    )
    validator = RouteAccessTokenValidatorV1(
        {
            "owner-token": owner,
            "wrong-owner-token": wrong_owner,
            "wrong-scope-token": wrong_scope,
        }
    )
    authority = CertificateSessionAuthorityV1()
    app = FastAPI(docs_url=None, redoc_url=None)
    install_certificate_session_control_v1(
        app,
        _feature_config(),
        access_token_validator=validator,
        authority=authority,
    )
    grant = authority.create_session(owner)
    ownership = authority.get_session_ownership(
        owner,
        grant.session_id,
        grant.session_capability,
    )
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.5
    )
    coordinator, _ = CaptureCoordinatorV1._create_for_session_v1(
        work_controller=controller,
        feature_enabled_v1=lambda: True,
        security_authority_usable_v1=lambda: True,
        session_live_action_v1=lambda action: (action() or True),
        quiescence_drain_v1=lambda epoch: None,
        semantic_cleanup_v1=lambda epoch: None,
    )
    session = RouteCaptureSessionV1(coordinator, ownership)
    install_certificate_capture_routes_v1(
        app,
        RouteResolverV1({ownership.session_id: session}),
    )
    harness = RouteHarnessV1(
        app=app,
        authority=authority,
        controller=controller,
        coordinator=coordinator,
        ownership=ownership,
        session_capability=grant.session_capability,
    )
    yield harness
    await harness.close()


async def _begin_v1(
    client: httpx.AsyncClient,
    harness: RouteHarnessV1,
    *,
    request_id: str | None = None,
    control_seq: int = 1,
    profile_id: str = "mock-no-profile-v1",
):
    return await client.post(
        (
            f"/api/v1/sessions/{harness.ownership.session_id}/"
            "certificate-captures"
        ),
        headers=harness.session_headers,
        json={
            "request_id": request_id or str(uuid.uuid4()),
            "control_seq": control_seq,
            "profile_id": profile_id,
        },
    )


def _capture_headers_v1(
    harness: RouteHarnessV1,
    capture_capability: str,
) -> dict[str, str]:
    return {
        **harness.session_headers,
        CAPTURE_CAPABILITY_HEADER_V1: capture_capability,
    }


@pytest.mark.asyncio
async def test_begin_retains_profile_identifier_as_uninterpreted_opaque_text(
    route_harness,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        begin = await _begin_v1(
            client,
            route_harness,
            profile_id="opaque profile / 模拟-v1",
        )
        assert begin.status_code == 201
        body = begin.json()
        assert "profile_id" not in body
        end = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{body['capture_id']}/end"
            ),
            headers=_capture_headers_v1(
                route_harness,
                body["capture_capability"],
            ),
            json={
                "request_id": str(uuid.uuid4()),
                "control_seq": 2,
            },
        )
        assert end.status_code == 200


@pytest.mark.asyncio
async def test_changed_capture_path_conflicts_with_seal_and_end_replay(
    route_harness,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        begin = await _begin_v1(client, route_harness)
        body = begin.json()
        capture_id = body["capture_id"]
        headers = _capture_headers_v1(
            route_harness,
            body["capture_capability"],
        )
        upload = await client.put(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/frames/1"
            ),
            headers={**headers, "Content-Type": "image/jpeg"},
            content=bytes(synthetic_jpeg_v1()),
        )
        assert upload.status_code == 200

        seal_request_id = str(uuid.uuid4())
        seal_payload = {
            "request_id": seal_request_id,
            "control_seq": 2,
        }
        seal = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/seal"
            ),
            headers=headers,
            json=seal_payload,
        )
        assert seal.status_code == 200
        changed_seal = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{new_uuid7_v1()}/seal"
            ),
            headers=headers,
            json=seal_payload,
        )
        assert changed_seal.status_code == 409
        assert changed_seal.json()["detail"]["reason_code"] == (
            "IDEMPOTENCY_CONFLICT"
        )

        end_request_id = str(uuid.uuid4())
        end_payload = {
            "request_id": end_request_id,
            "control_seq": 3,
        }
        end = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/end"
            ),
            headers=headers,
            json=end_payload,
        )
        assert end.status_code == 200
        changed_end = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{new_uuid7_v1()}/end"
            ),
            headers=headers,
            json=end_payload,
        )
        assert changed_end.status_code == 409
        assert changed_end.json()["detail"]["reason_code"] == (
            "IDEMPOTENCY_CONFLICT"
        )


@pytest.mark.asyncio
async def test_exact_enabled_route_flow_and_production_processor_boundary(
    route_harness,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        begin = await _begin_v1(client, route_harness)
        assert begin.status_code == 201
        begin_body = begin.json()
        assert set(begin_body) == {
            "capture_id",
            "capture_seq",
            "session_generation",
            "state",
            "capture_capability",
            "expires_at_epoch_seconds",
        }
        assert begin_body["state"] == "ARMED"
        capture_id = begin_body["capture_id"]
        capture_capability = begin_body["capture_capability"]
        headers = _capture_headers_v1(
            route_harness,
            capture_capability,
        )

        for frame_seq, color in enumerate(
            ((1, 2, 3), (4, 5, 6), (7, 8, 9)),
            start=1,
        ):
            encoded = synthetic_jpeg_v1(
                width=1080 if frame_seq == 2 else 320,
                height=1920 if frame_seq == 2 else 240,
                color=color,
            )
            upload = await client.put(
                (
                    f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                    f"certificate-captures/{capture_id}/frames/{frame_seq}"
                ),
                headers={**headers, "Content-Type": "image/jpeg"},
                content=bytes(encoded),
            )
            assert upload.status_code == 200
            assert upload.json()["accepted_frame_count"] == frame_seq
            assert upload.json()["state"] == "CAPTURING"

        status_response = await client.get(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}"
            ),
            headers=headers,
        )
        assert status_response.status_code == 200
        status_body = status_response.json()
        assert status_body["accepted_frame_count"] == 3
        assert status_body["independent_correlation_groups"] == 3
        assert "sha256" not in status_response.text
        assert "principal" not in status_response.text
        assert "capability" not in status_response.text

        seal_request = {
            "request_id": str(uuid.uuid4()),
            "control_seq": 2,
        }
        seal = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/seal"
            ),
            headers=headers,
            json=seal_request,
        )
        assert seal.status_code == 503
        assert seal.json()["detail"]["reason_code"] == "PROCESSOR_NOT_READY"
        seal_replay = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/seal"
            ),
            headers=headers,
            json=seal_request,
        )
        assert seal_replay.status_code == 503
        assert seal_replay.json() == seal.json()

        end_request = {
            "request_id": str(uuid.uuid4()),
            "control_seq": 3,
        }
        end = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/end"
            ),
            headers=headers,
            json=end_request,
        )
        assert end.status_code == 200
        assert end.json()["state"] == "IDLE"
        end_replay = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}/end"
            ),
            headers=headers,
            json=end_request,
        )
        assert end_replay.status_code == 200
        assert end_replay.json() == end.json()

        gone = await client.get(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{capture_id}"
            ),
            headers=headers,
        )
        assert gone.status_code == 404
        assert gone.json()["detail"]["reason_code"] == "CAPTURE_ACCESS_DENIED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "expected_status", "reason_code"),
    (
        ({}, 401, "AUTHENTICATION_REQUIRED"),
        (
            {"Authorization": "Bearer invalid-token"},
            401,
            "AUTHENTICATION_FAILED",
        ),
        (
            {"Authorization": "Bearer wrong-scope-token"},
            401,
            "AUTHENTICATION_FAILED",
        ),
        (
            {"Authorization": "Bearer wrong-owner-token"},
            404,
            "SESSION_ACCESS_DENIED",
        ),
    ),
)
async def test_begin_authentication_owner_and_scope_fail_without_oracles(
    route_harness,
    headers,
    expected_status,
    reason_code,
):
    supplied = {
        **headers,
        SESSION_CAPABILITY_HEADER_V1: route_harness.session_capability,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        response = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                "certificate-captures"
            ),
            headers=supplied,
            json={
                "request_id": str(uuid.uuid4()),
                "control_seq": 1,
                "profile_id": "mock-no-profile-v1",
            },
        )

    assert response.status_code == expected_status
    assert response.json()["detail"]["reason_code"] == reason_code


@pytest.mark.asyncio
async def test_guessed_session_and_wrong_session_capability_are_indistinguishable(
    route_harness,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        guessed = await client.post(
            "/api/v1/sessions/cs1_guessed/certificate-captures",
            headers=route_harness.session_headers,
            json={
                "request_id": str(uuid.uuid4()),
                "control_seq": 1,
                "profile_id": "mock-no-profile-v1",
            },
        )
        wrong_capability = await client.post(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                "certificate-captures"
            ),
            headers={
                "Authorization": "Bearer owner-token",
                SESSION_CAPABILITY_HEADER_V1: "csc1_" + "A" * 43,
            },
            json={
                "request_id": str(uuid.uuid4()),
                "control_seq": 1,
                "profile_id": "mock-no-profile-v1",
            },
        )

    assert guessed.status_code == wrong_capability.status_code == 404
    assert guessed.json() == wrong_capability.json()


@pytest.mark.asyncio
async def test_frame_capability_content_type_size_and_content_are_enforced(
    route_harness,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        begin = await _begin_v1(client, route_harness)
        body = begin.json()
        base_path = (
            f"/api/v1/sessions/{route_harness.ownership.session_id}/"
            f"certificate-captures/{body['capture_id']}/frames/1"
        )
        valid_headers = _capture_headers_v1(
            route_harness,
            body["capture_capability"],
        )
        jpeg = synthetic_jpeg_v1()

        wrong_capture_capability = await client.put(
            base_path,
            headers={
                **route_harness.session_headers,
                CAPTURE_CAPABILITY_HEADER_V1: "ccp1_" + "A" * 43,
                "Content-Type": "image/jpeg",
            },
            content=bytes(jpeg),
        )
        missing_capture_capability = await client.put(
            base_path,
            headers={
                **route_harness.session_headers,
                "Content-Type": "image/jpeg",
            },
            content=bytes(jpeg),
        )
        wrong_mime = await client.put(
            base_path,
            headers={**valid_headers, "Content-Type": "application/octet-stream"},
            content=bytes(jpeg),
        )
        non_jpeg = await client.put(
            base_path,
            headers={**valid_headers, "Content-Type": "image/jpeg"},
            content=b"not-a-jpeg",
        )
        truncated = await client.put(
            base_path,
            headers={**valid_headers, "Content-Type": "image/jpeg"},
            content=bytes(jpeg[:-2]),
        )
        declared_too_large = await client.put(
            base_path,
            headers={
                **valid_headers,
                "Content-Type": "image/jpeg",
                "Content-Length": str(2 * 1024 * 1024 + 1),
            },
            content=bytes(jpeg),
        )

    assert wrong_capture_capability.status_code == 404
    assert missing_capture_capability.status_code == 404
    assert wrong_capture_capability.json() == missing_capture_capability.json()
    assert wrong_mime.status_code == 415
    assert non_jpeg.status_code == 400
    assert truncated.status_code == 400
    assert declared_too_large.status_code == 413
    assert route_harness.coordinator._frame_records_v1 == {}


@pytest.mark.asyncio
async def test_frame_sequence_retry_conflict_and_bounds_over_http(route_harness):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        begin = await _begin_v1(client, route_harness)
        body = begin.json()
        prefix = (
            f"/api/v1/sessions/{route_harness.ownership.session_id}/"
            f"certificate-captures/{body['capture_id']}/frames"
        )
        headers = {
            **_capture_headers_v1(
                route_harness,
                body["capture_capability"],
            ),
            "Content-Type": "image/jpeg",
        }
        first_jpeg = synthetic_jpeg_v1(color=(1, 2, 3))
        first = await client.put(
            f"{prefix}/1",
            headers=headers,
            content=bytes(first_jpeg),
        )
        retry = await client.put(
            f"{prefix}/1",
            headers=headers,
            content=bytes(first_jpeg),
        )
        conflict = await client.put(
            f"{prefix}/1",
            headers=headers,
            content=bytes(synthetic_jpeg_v1(color=(9, 8, 7))),
        )
        below = await client.put(
            f"{prefix}/0",
            headers=headers,
            content=bytes(first_jpeg),
        )
        above = await client.put(
            f"{prefix}/9",
            headers=headers,
            content=bytes(first_jpeg),
        )

    assert first.status_code == retry.status_code == 200
    assert first.json() == retry.json()
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["reason_code"] == (
        "FRAME_SEQUENCE_CONFLICT"
    )
    assert below.status_code == above.status_code == 400
    assert route_harness.coordinator._accepted_frame_bytes_v1 == len(
        first_jpeg
    )


@pytest.mark.asyncio
async def test_actual_streamed_size_is_enforced_despite_small_content_length(
    route_harness,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=route_harness.app),
        base_url="https://service.example.test",
    ) as client:
        begin = await _begin_v1(client, route_harness)
        body = begin.json()
        response = await client.put(
            (
                f"/api/v1/sessions/{route_harness.ownership.session_id}/"
                f"certificate-captures/{body['capture_id']}/frames/1"
            ),
            headers={
                **_capture_headers_v1(
                    route_harness,
                    body["capture_capability"],
                ),
                "Content-Type": "image/jpeg",
                "Content-Length": "1",
            },
            content=b"\xff\xd8" + b"A" * (2 * 1024 * 1024) + b"\xff\xd9",
        )

    assert response.status_code == 413
    assert response.json()["detail"]["reason_code"] == "FRAME_TOO_LARGE"
    assert route_harness.coordinator._frame_records_v1 == {}
    assert route_harness.coordinator._active_frame_upload_permits_v1 == set()


@pytest.mark.asyncio
async def test_client_disconnect_mid_body_releases_partial_bytes_and_rejects():
    messages = iter(
        (
            {
                "type": "http.request",
                "body": b"\xff\xd8partial",
                "more_body": True,
            },
            {"type": "http.disconnect"},
        )
    )

    async def receive():
        return next(messages)

    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "PUT",
            "scheme": "https",
            "path": "/private-frame",
            "raw_path": b"/private-frame",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("service.example.test", 443),
        },
        receive,
    )

    with pytest.raises(CaptureProtocolErrorV1) as disconnected:
        await read_bounded_private_jpeg_v1(request)

    assert (
        disconnected.value.reason
        is CaptureProtocolReasonV1.FRAME_BODY_UNAVAILABLE
    )


def test_disabled_installer_mounts_no_routes_or_runtime():
    app = FastAPI(docs_url=None, redoc_url=None)
    original = tuple(app.routes)

    assert install_certificate_capture_routes_v1(
        app,
        RouteResolverV1({}),
    ) is None
    assert tuple(app.routes) == original
    assert not hasattr(app.state, "certificate_capture_routes_v1")


def test_production_route_installer_has_no_mock_processor_parameter():
    assert "processor" not in (
        install_certificate_capture_routes_v1.__annotations__
    )


def test_disabled_chat_engine_does_not_import_private_jpeg_or_route_modules(
    tmp_path,
):
    script = """
import sys
from fastapi import FastAPI
from chat_engine.chat_engine import ChatEngine
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel

app = FastAPI()
engine = ChatEngine()
engine.initialize(
    ChatEngineConfigModel(
        model_root=sys.argv[1],
        handler_configs={},
        logic_configs={},
    ),
    app=app,
)
assert "certificate_capture.frame_ingress" not in sys.modules
assert "certificate_capture.routes" not in sys.modules
assert not hasattr(app.state, "certificate_capture_routes_v1")
"""
    environment = dict(os.environ)
    project_root = Path(__file__).resolve().parents[2]
    environment["PYTHONPATH"] = (
        f"{project_root}:{project_root / 'src'}"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=str(project_root),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr


def test_synthetic_fixtures_are_local_non_sensitive_jpegs():
    encoded = synthetic_jpeg_v1()
    with Image.open(io.BytesIO(encoded)) as image:
        assert image.format == "JPEG"
        assert image.size == (96, 64)


@pytest.mark.asyncio
async def test_production_chat_engine_resolver_uses_exact_session_coordinator(
    tmp_path,
    monkeypatch,
):
    now = time.time()
    principal = AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject="integrated-owner",
        scopes=frozenset({OIDC_CERTIFICATE_CAPTURE_SCOPE_V1}),
        token_expiry_epoch_seconds=now + 900,
    )
    validator = RouteAccessTokenValidatorV1({"integrated-token": principal})
    authority = CertificateSessionAuthorityV1()
    app = FastAPI(docs_url=None, redoc_url=None)
    install_certificate_session_control_v1(
        app,
        _feature_config(),
        access_token_validator=validator,
        authority=authority,
    )
    engine = ChatEngine()
    engine.initialize(
        ChatEngineConfigModel(
            model_root=str(tmp_path),
            handler_configs={},
            logic_configs={},
        ),
        app=app,
    )
    grant = authority.create_session(principal)
    admission = ConsumedSessionAdmissionV1(
        session_id=grant.session_id,
        ticket_id="ati1_integrated",
        owner_issuer=principal.issuer,
        owner_subject=principal.subject,
        channel=SessionAdmissionChannelV1.WEBSOCKET,
        admitted_at_epoch_seconds=now,
    )
    session = engine._create_session(
        SessionInfoData(session_id=grant.session_id),
        session_admission=admission,
    )
    session.start()

    generic_calls: list[str] = []

    def generic_denied(name):
        def denied(*args, **kwargs):
            generic_calls.append(name)
            raise AssertionError(name)

        return denied

    monkeypatch.setattr(
        session.stream_manager,
        "create_streamer",
        generic_denied("stream"),
    )
    monkeypatch.setattr(
        session.signal_manager,
        "enqueue_signal_v1",
        generic_denied("signal"),
    )
    monkeypatch.setattr(
        session.session_context.session_history,
        "add_event",
        generic_denied("history"),
    )

    session_headers = {
        "Authorization": "Bearer integrated-token",
        SESSION_CAPABILITY_HEADER_V1: grant.session_capability,
    }
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://service.example.test",
        ) as client:
            begin = await client.post(
                (
                    f"/api/v1/sessions/{grant.session_id}/"
                    "certificate-captures"
                ),
                headers=session_headers,
                json={
                    "request_id": str(uuid.uuid4()),
                    "control_seq": 1,
                    "profile_id": "mock-no-profile-v1",
                },
            )
            assert begin.status_code == 201
            begin_body = begin.json()
            upload = await client.put(
                (
                    f"/api/v1/sessions/{grant.session_id}/"
                    f"certificate-captures/{begin_body['capture_id']}/"
                    "frames/1"
                ),
                headers={
                    **session_headers,
                    CAPTURE_CAPABILITY_HEADER_V1: (
                        begin_body["capture_capability"]
                    ),
                    "Content-Type": "image/jpeg",
                },
                content=bytes(synthetic_jpeg_v1()),
            )
            assert upload.status_code == 200
            end = await client.post(
                (
                    f"/api/v1/sessions/{grant.session_id}/"
                    f"certificate-captures/{begin_body['capture_id']}/end"
                ),
                headers={
                    **session_headers,
                    CAPTURE_CAPABILITY_HEADER_V1: (
                        begin_body["capture_capability"]
                    ),
                },
                json={
                    "request_id": str(uuid.uuid4()),
                    "control_seq": 2,
                },
            )
            assert end.status_code == 200
    finally:
        await engine.retire_secure_session_v1(grant.session_id)
        async with authority.serialized_transition():
            authority.close()

    assert generic_calls == []


@pytest.mark.asyncio
async def test_session_replacement_destroys_active_capture_before_returning(
    tmp_path,
):
    now = time.time()
    principal = AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject="replacement-owner",
        scopes=frozenset({OIDC_CERTIFICATE_CAPTURE_SCOPE_V1}),
        token_expiry_epoch_seconds=now + 900,
    )
    validator = RouteAccessTokenValidatorV1({"replace-token": principal})
    authority = CertificateSessionAuthorityV1()
    app = FastAPI(docs_url=None, redoc_url=None)
    install_certificate_session_control_v1(
        app,
        _feature_config(),
        access_token_validator=validator,
        authority=authority,
    )
    engine = ChatEngine()
    engine.initialize(
        ChatEngineConfigModel(
            model_root=str(tmp_path),
            handler_configs={},
            logic_configs={},
        ),
        app=app,
    )
    old_grant = authority.create_session(principal)
    admission = ConsumedSessionAdmissionV1(
        session_id=old_grant.session_id,
        ticket_id="ati1_replacement",
        owner_issuer=principal.issuer,
        owner_subject=principal.subject,
        channel=SessionAdmissionChannelV1.WEBSOCKET,
        admitted_at_epoch_seconds=now,
    )
    old_session = engine._create_session(
        SessionInfoData(session_id=old_grant.session_id),
        session_admission=admission,
    )
    old_session.start()
    old_coordinator = old_session._capture_coordinator_v1
    assert old_coordinator is not None
    old_headers = {
        "Authorization": "Bearer replace-token",
        SESSION_CAPABILITY_HEADER_V1: old_grant.session_capability,
    }

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://service.example.test",
        ) as client:
            begin = await client.post(
                (
                    f"/api/v1/sessions/{old_grant.session_id}/"
                    "certificate-captures"
                ),
                headers=old_headers,
                json={
                    "request_id": str(uuid.uuid4()),
                    "control_seq": 1,
                    "profile_id": "mock-no-profile-v1",
                },
            )
            assert begin.status_code == 201
            begin_body = begin.json()
            upload = await client.put(
                (
                    f"/api/v1/sessions/{old_grant.session_id}/"
                    f"certificate-captures/{begin_body['capture_id']}/"
                    "frames/1"
                ),
                headers={
                    **old_headers,
                    CAPTURE_CAPABILITY_HEADER_V1: (
                        begin_body["capture_capability"]
                    ),
                    "Content-Type": "image/jpeg",
                },
                content=bytes(synthetic_jpeg_v1()),
            )
            assert upload.status_code == 200

            replacement = await client.post(
                "/api/v1/session-capabilities",
                headers={"Authorization": "Bearer replace-token"},
            )
            assert replacement.status_code == 201
            assert replacement.json()["session_id"] != old_grant.session_id
            assert old_coordinator.snapshot_v1().destroyed is True
            assert old_coordinator._private_capture_is_clear_locked_v1()
            assert old_session._stop_complete_event_v1.is_set()

            old_status = await client.get(
                (
                    f"/api/v1/sessions/{old_grant.session_id}/"
                    f"certificate-captures/{begin_body['capture_id']}"
                ),
                headers={
                    **old_headers,
                    CAPTURE_CAPABILITY_HEADER_V1: (
                        begin_body["capture_capability"]
                    ),
                },
            )
            assert old_status.status_code == 404
    finally:
        if old_grant.session_id in engine.sessions:
            await engine.retire_secure_session_v1(old_grant.session_id)
        async with authority.serialized_transition():
            authority.close()

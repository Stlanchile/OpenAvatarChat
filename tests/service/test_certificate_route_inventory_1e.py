from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastrtc import Stream
from starlette.routing import Mount, WebSocketRoute

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import demo
from chat_engine.chat_engine import ChatEngine
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from handlers.client.rtc_client.client_handler_rtc import RtcStream
from handlers.client.ws_client.ws_session_endpoint import (
    register_ws_session_endpoint,
)
from handlers.client.ws_lam_client import ws_lam_client_handler
from handlers.client.ws_lam_client.ws_lam_client_handler import (
    WsLamClientHandler,
)
from service.frontend_service.frontend_service import register_frontend
from service.manager_service.data_tool_service import ManagerDataToolService
from service.manager_service.manager_service_register import (
    register_data_tool_service,
    register_manager_apis,
)
from service.rtc_service.rtc_session_admission import (
    mount_rtc_signaling_routes_v1,
)
from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
)
from service.service_security.certificate_session_control import (
    install_certificate_session_control_v1,
)
from service.service_security.manager_authorization import (
    MANAGER_WEBSOCKET_TICKET_ROUTE_V1,
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


class DummySessionDelegate:
    pass


class DummyHandlerDelegate:
    pass


class InventoryAccessTokenValidator:
    def __init__(self):
        expiry = int(time.time()) + 3600
        self.principals = {
            "certificate-token": AuthenticatedPrincipalV1(
                issuer="https://issuer.example.test",
                subject="certificate",
                scopes=frozenset({OIDC_CERTIFICATE_CAPTURE_SCOPE_V1}),
                token_expiry_epoch_seconds=expiry,
            ),
            "manager-token": AuthenticatedPrincipalV1(
                issuer="https://issuer.example.test",
                subject="manager",
                scopes=frozenset({OIDC_MANAGER_SCOPE_V1}),
                token_expiry_epoch_seconds=expiry,
            ),
        }

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
        principal = self.principals.get(encoded_access_token)
        if principal is None:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNATURE_INVALID
            )
        if required_scope not in principal.scopes:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING
            )
        return principal


def _feature_config() -> CertificateCaptureFeatureConfigV1:
    return CertificateCaptureFeatureConfigV1.model_validate(
        {
            "enabled": True,
            "oidc": {
                "issuer": "https://issuer.example.test",
                "jwks_url": "https://issuer.example.test/jwks.json",
                "audience": "open-avatar-chat",
                "allowed_algorithms": ["RS256"],
                "required_scope": OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
            },
        }
    )


def _route_inventory(app: FastAPI) -> set[tuple[str, str]]:
    inventory: set[tuple[str, str]] = set()
    for route in app.routes:
        methods = getattr(route, "methods", None)
        if methods:
            inventory.update((method, route.path) for method in methods)
        elif isinstance(route, WebSocketRoute):
            inventory.add(("WEBSOCKET", route.path))
        elif isinstance(route, Mount):
            inventory.add(("MOUNT", route.path))
        elif getattr(route, "path", None) is not None:
            inventory.add(("ASGI", route.path))
    return inventory


def _mounted_route_paths(app: FastAPI, mount_path: str) -> set[str]:
    mount = next(
        route
        for route in app.routes
        if isinstance(route, Mount) and route.path == mount_path
    )
    return {route.path for route in mount.app.routes}


def _assemble_security_test_app(
    *,
    certificate_enabled: bool,
) -> FastAPI:
    app, ui, parent = demo.setup_demo(
        mount_legacy_gradio=not certificate_enabled
    )
    if certificate_enabled:
        install_certificate_session_control_v1(
            app,
            _feature_config(),
            access_token_validator=InventoryAccessTokenValidator(),
        )

    chat_engine = ChatEngine()
    chat_engine.initialize(
        ChatEngineConfigModel(
            model_root=str(PROJECT_ROOT / "models"),
            handler_configs={},
            logic_configs={},
        ),
        app=app,
        ui=ui,
        parent_block=parent,
    )
    app.state.route_inventory_chat_engine = chat_engine

    data_tool_service = ManagerDataToolService()
    register_data_tool_service(data_tool_service)
    register_manager_apis(app)
    register_ws_session_endpoint(
        app,
        DummyHandlerDelegate(),
        DummySessionDelegate,
    )

    rtc_factory = RtcStream(session_id=None)
    rtc_factory.client_handler_delegate = DummyHandlerDelegate()
    rtc_stream = Stream(
        handler=rtc_factory,
        modality="audio-video",
        mode="send-receive",
        concurrency_limit=2,
        verbose=False,
    )
    mount_rtc_signaling_routes_v1(app, rtc_stream, rtc_factory)
    register_frontend(
        app,
        ui,
        parent,
        init_config={"rtc_configuration": {"iceServers": []}},
    )
    return app


def test_complete_security_route_inventory_in_both_feature_modes():
    disabled_app = _assemble_security_test_app(certificate_enabled=False)
    enabled_app = _assemble_security_test_app(certificate_enabled=True)
    disabled = _route_inventory(disabled_app)
    enabled = _route_inventory(enabled_app)

    assert disabled == {
        ("GET", "/openapi.json"),
        ("HEAD", "/openapi.json"),
        ("POST", "/webrtc/offer"),
        ("WEBSOCKET", "/telephone/handler"),
        ("POST", "/telephone/incoming"),
        ("WEBSOCKET", "/websocket/offer"),
        ("WEBSOCKET", "/ws/session/{session_id}"),
        ("WEBSOCKET", "/ws/manager/data_tool"),
        ("GET", "/download/manager/data_tool/file"),
        ("GET", "/openavatarchat/initconfig"),
        ("GET", "/version"),
        ("GET", "/liveness"),
        ("GET", "/readiness"),
        ("MOUNT", "/gradio"),
        ("MOUNT", "/ui"),
        ("ASGI", "/"),
    }

    assert enabled == {
        ("GET", "/openapi.json"),
        ("HEAD", "/openapi.json"),
        ("POST", "/webrtc/offer"),
        ("WEBSOCKET", "/ws/session/{session_id}"),
        ("WEBSOCKET", "/ws/manager/data_tool"),
        ("GET", "/download/manager/data_tool/file"),
        ("POST", MANAGER_WEBSOCKET_TICKET_ROUTE_V1),
        ("POST", "/api/v1/session-capabilities"),
        ("POST", "/api/v1/sessions/{session_id}/admission-tickets"),
        ("DELETE", "/api/v1/sessions/{session_id}"),
        ("GET", "/openavatarchat/initconfig"),
        ("GET", "/version"),
        ("GET", "/liveness"),
        ("GET", "/readiness"),
        ("MOUNT", "/ui"),
        ("ASGI", "/"),
    }
    assert ("WEBSOCKET", "/telephone/handler") not in enabled
    assert ("POST", "/telephone/incoming") not in enabled
    assert ("WEBSOCKET", "/websocket/offer") not in enabled
    assert ("MOUNT", "/gradio") not in enabled
    assert {
        (method, path)
        for method, path in enabled
        if "offer" in path or "telephone" in path
    } == {("POST", "/webrtc/offer")}


@pytest.mark.asyncio
async def test_lam_route_is_only_the_configured_public_asset_in_enabled_mode(
    tmp_path,
    monkeypatch,
):
    configured_asset = tmp_path / "public-avatar.zip"
    sibling_media = tmp_path / "unrelated-session-media.wav"
    configured_asset.write_bytes(b"public-avatar")
    sibling_media.write_bytes(b"unrelated-media")

    class StubFileResponse:
        def __new__(cls, path):
            from fastapi.responses import JSONResponse

            return JSONResponse(
                {"served": Path(path).name},
                status_code=200,
            )

    monkeypatch.setattr(
        ws_lam_client_handler,
        "FileResponse",
        StubFileResponse,
    )

    disabled_app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    disabled_handler = WsLamClientHandler()
    disabled_handler.asset_dir = str(tmp_path)
    disabled_handler.asset_name = configured_asset.name
    disabled_handler._register_asset_route(disabled_app)

    enabled_app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    enabled_handler = WsLamClientHandler()
    enabled_handler.asset_dir = str(tmp_path)
    enabled_handler.asset_name = configured_asset.name
    enabled_handler._register_asset_route(enabled_app)
    # Resolve the gate at request time: certificate mode can be installed
    # after a handler registered its routes.
    enabled_app.state.certificate_capture_enabled_v1 = True

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=disabled_app),
        base_url="https://service.example.test",
    ) as disabled_client:
        legacy_sibling = await disabled_client.get(
            f"/download/lam_asset/{sibling_media.name}"
        )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=enabled_app),
        base_url="https://service.example.test",
    ) as enabled_client:
        public_asset = await enabled_client.get(
            f"/download/lam_asset/{configured_asset.name}"
        )
        protected_sibling = await enabled_client.get(
            f"/download/lam_asset/{sibling_media.name}"
        )

    assert legacy_sibling.status_code == 200
    assert public_asset.status_code == 200
    assert public_asset.json() == {"served": configured_asset.name}
    assert protected_sibling.status_code == 404
    assert sibling_media.name not in protected_sibling.text


@pytest.mark.asyncio
async def test_production_diagnostics_are_manager_scoped_only_when_enabled():
    disabled_app = _assemble_security_test_app(certificate_enabled=False)
    enabled_app = _assemble_security_test_app(certificate_enabled=True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=disabled_app),
        base_url="https://service.example.test",
    ) as disabled_client:
        disabled_responses = [
            await disabled_client.get(path)
            for path in ("/version", "/liveness", "/readiness")
        ]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=enabled_app),
        base_url="https://service.example.test",
    ) as enabled_client:
        for path in ("/version", "/liveness", "/readiness"):
            missing = await enabled_client.get(path)
            certificate_only = await enabled_client.get(
                path,
                headers={"Authorization": "Bearer certificate-token"},
            )
            manager = await enabled_client.get(
                path,
                headers={"Authorization": "Bearer manager-token"},
            )

            assert missing.status_code == 401
            assert certificate_only.status_code == 403
            assert manager.status_code == 200

    assert [response.status_code for response in disabled_responses] == [
        200,
        200,
        200,
    ]


@pytest.mark.asyncio
async def test_readiness_authorizes_before_diagnostic_state_disclosure():
    app = _assemble_security_test_app(certificate_enabled=True)
    app.state.route_inventory_chat_engine.states.inited = False

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://service.example.test",
    ) as client:
        missing = await client.get("/readiness")
        certificate_only = await client.get(
            "/readiness",
            headers={"Authorization": "Bearer certificate-token"},
        )
        manager = await client.get(
            "/readiness",
            headers={"Authorization": "Bearer manager-token"},
        )

    assert missing.status_code == 401
    assert certificate_only.status_code == 403
    assert manager.status_code == 500
    assert "not ready" not in missing.text.casefold()
    assert "not ready" not in certificate_only.text.casefold()


def test_enabled_mode_removes_all_mounted_gradio_alternate_service_routes():
    disabled_app, _, _ = demo.setup_demo()
    enabled_app, _, _ = demo.setup_demo(mount_legacy_gradio=False)
    disabled_gradio = _mounted_route_paths(disabled_app, "/gradio")

    assert {
        "/gradio_api/proxy={url_path:path}",
        "/gradio_api/file={path_or_url:path}",
        "/gradio_api/file/{path:path}",
        "/gradio_api/upload",
        "/gradio_api/monitoring",
        "/gradio_api/stream/{event_id}",
    }.issubset(disabled_gradio)
    assert ("MOUNT", "/gradio") not in _route_inventory(enabled_app)


def test_enabled_installer_rejects_preexisting_legacy_gradio_mount():
    app, _, _ = demo.setup_demo()

    with pytest.raises(CertificateCaptureStartupError) as exception:
        install_certificate_session_control_v1(
            app,
            _feature_config(),
            access_token_validator=InventoryAccessTokenValidator(),
        )

    assert exception.value.reason_code == "LEGACY_GRADIO_ROUTE_CONFLICT"
    assert not hasattr(app.state, "certificate_session_control_v1")
    assert not hasattr(app.state, "manager_authorization_v1")


@pytest.mark.parametrize(
    "legacy_path",
    [
        "/webrtc/offer",
        "/telephone/handler",
        "/telephone/incoming",
        "/websocket/offer",
    ],
)
def test_enabled_installer_rejects_preexisting_rtc_service_routes(
    legacy_path,
):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_api_route(legacy_path, lambda: None, methods=["POST"])

    with pytest.raises(CertificateCaptureStartupError) as exception:
        install_certificate_session_control_v1(
            app,
            _feature_config(),
            access_token_validator=InventoryAccessTokenValidator(),
        )

    assert exception.value.reason_code == "RTC_SIGNALING_ROUTE_CONFLICT"
    assert not hasattr(app.state, "certificate_session_control_v1")
    assert not hasattr(app.state, "manager_authorization_v1")


@pytest.mark.asyncio
async def test_client_bootstrap_config_is_certificate_scoped_only_when_enabled():
    calls: list[str] = []

    def init_config():
        calls.append("materialize")
        return {
            "rtc_configuration": {
                "iceServers": [
                    {
                        "urls": ["turn:turn.example.test"],
                        "username": "turn-user",
                        "credential": "turn-credential-canary",
                    }
                ]
            }
        }

    disabled_app, disabled_ui, disabled_parent = demo.setup_demo()
    register_frontend(
        disabled_app,
        disabled_ui,
        disabled_parent,
        init_config=init_config,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=disabled_app),
        base_url="https://service.example.test",
    ) as client:
        legacy = await client.get("/openavatarchat/initconfig")
    assert legacy.status_code == 200
    assert calls == ["materialize"]

    calls.clear()
    enabled_app, enabled_ui, enabled_parent = demo.setup_demo(
        mount_legacy_gradio=False
    )
    install_certificate_session_control_v1(
        enabled_app,
        _feature_config(),
        access_token_validator=InventoryAccessTokenValidator(),
    )
    register_frontend(
        enabled_app,
        enabled_ui,
        enabled_parent,
        init_config=init_config,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=enabled_app),
        base_url="https://service.example.test",
    ) as client:
        missing = await client.get("/openavatarchat/initconfig")
        manager_only = await client.get(
            "/openavatarchat/initconfig",
            headers={"Authorization": "Bearer manager-token"},
        )
        certificate = await client.get(
            "/openavatarchat/initconfig",
            headers={"Authorization": "Bearer certificate-token"},
        )

    assert missing.status_code == manager_only.status_code == 401
    assert calls == ["materialize"]
    assert certificate.status_code == 200
    assert certificate.json()["rtc_configuration"]["iceServers"][0][
        "credential"
    ] == "turn-credential-canary"
    assert "turn-credential-canary" not in missing.text
    assert "turn-credential-canary" not in manager_only.text


def test_manager_webui_uses_https_ticket_and_never_query_string_bearer():
    api_source = (
        PROJECT_ROOT
        / "src/service/frontend_service/frontend/src/renderer/src/apis/index.ts"
    ).read_text(encoding="utf-8")
    manager_function = api_source.split(
        "export async function createDataToolWS"
    )[1].split("\n}\n", 1)[0]
    websocket_helper = (
        PROJECT_ROOT
        / "src/service/frontend_service/frontend/src/renderer/src/helpers/ws.ts"
    ).read_text(encoding="utf-8")
    inline_audio_player = (
        PROJECT_ROOT
        / (
            "src/service/frontend_service/frontend/src/renderer/src/"
            "components/InlineAudioPlayer.vue"
        )
    ).read_text(encoding="utf-8")
    message_list = (
        PROJECT_ROOT
        / (
            "src/service/frontend_service/frontend/src/renderer/src/"
            "views/Manager/components/MessageList.vue"
        )
    ).read_text(encoding="utf-8")

    assert MANAGER_WEBSOCKET_TICKET_ROUTE_V1 in manager_function
    assert "oac.manager-admission.v1." in manager_function
    assert "?token=" not in manager_function
    assert "new WebSocket(url, protocols)" in websocket_helper
    for manager_download_source in (inline_audio_player, message_list):
        assert "window.fetch(" in manager_download_source
        assert "headers['Authorization'] = `Bearer ${token}`" in (
            manager_download_source
        )

    manager_html = (
        PROJECT_ROOT
        / "src/service/frontend_service/frontend/dist/manager.html"
    ).read_text(encoding="utf-8")
    manager_asset = re.search(
        r'src="\./assets/(?P<asset>manager\.[^"]+\.js)"',
        manager_html,
    )
    shared_asset = re.search(
        r'href="\./assets/(?P<asset>index\.[^"]+\.js)"',
        manager_html,
    )
    assert manager_asset is not None
    assert shared_asset is not None
    dist_assets = (
        PROJECT_ROOT / "src/service/frontend_service/frontend/dist/assets"
    )
    manager_bundle = (
        dist_assets / manager_asset.group("asset")
    ).read_text(encoding="utf-8")
    shared_bundle = (
        dist_assets / shared_asset.group("asset")
    ).read_text(encoding="utf-8")
    assert MANAGER_WEBSOCKET_TICKET_ROUTE_V1 in shared_bundle
    assert "oac.manager-admission.v1." in shared_bundle
    assert "Manager authorization failed" in manager_bundle

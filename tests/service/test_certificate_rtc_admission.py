from __future__ import annotations

import asyncio
import inspect
import logging
import sys
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import numpy as np
import pytest
from aiortc import RTCPeerConnection
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastrtc import Stream
from loguru import logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from handlers.client.rtc_client.client_handler_rtc import ClientRtcConfigModel
from handlers.client.ws_client.ws_session_endpoint import (
    register_ws_session_endpoint,
)
from service.manager_service.data_tool_service import ManagerDataToolService
from service.rtc_service.rtc_provider import RTCProvider
from service.rtc_service.rtc_session_admission import (
    RTC_ADMISSION_TICKET_HEADER_V1,
    RTC_SESSION_ID_HEADER_V1,
    RTC_SIGNALING_ROUTE_V1,
    RTC_TRANSPORT_BINDING_HEADER_V1,
    RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1,
    AuthenticatedRtcAdmissionControllerV1,
    RtcAdmissionReasonV1,
    mount_rtc_signaling_routes_v1,
)
from service.rtc_service.rtc_stream import RtcStream
from service.service_security.certificate_session_authority import (
    CertificateSessionAuthorityV1,
    ConsumedSessionAdmissionV1,
    SessionAdmissionChannelV1,
)
from service.service_security.certificate_session_control import (
    CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
    CertificateSessionControlRuntimeV1,
)
from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
    OidcAuthenticationErrorV1,
    OidcAuthenticationReasonV1,
)
from service.service_security.websocket_session_admission import (
    WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1,
)
from service.service_utils.ssl_helpers import CertificateCaptureStartupError

NOW = 2_000_000_000.0
ISSUER = "https://issuer.example.test"
OWNER_SUBJECT = "certificate-owner"
OWNER_ACCESS_TOKEN = "owner-access-token-canary"
ATTACKER_ACCESS_TOKEN = "attacker-access-token-canary"


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


def _principal(
    *,
    issuer: str = ISSUER,
    subject: str = OWNER_SUBJECT,
    token_expiry: float = NOW + 3600,
) -> AuthenticatedPrincipalV1:
    return AuthenticatedPrincipalV1(
        issuer=issuer,
        subject=subject,
        scopes=frozenset({"certificate:capture"}),
        token_expiry_epoch_seconds=token_expiry,
    )


class RecordingAuthority(CertificateSessionAuthorityV1):
    def __init__(self, clock: FakeClock, events: list[str]):
        super().__init__(
            wall_clock=clock.wall_time,
            monotonic_clock=clock.monotonic_time,
        )
        self.events = events

    def consume_admission_ticket(self, *args, **kwargs):
        self.events.append("ticket_consume")
        return super().consume_admission_ticket(*args, **kwargs)

    def validate_consumed_session_admission(self, *args, **kwargs):
        self.events.append("admission_validate")
        return super().validate_consumed_session_admission(*args, **kwargs)


class FakeAccessTokenValidator:
    def __init__(
        self,
        principals_by_token: dict[str, AuthenticatedPrincipalV1],
        events: list[str],
    ):
        self.principals_by_token = principals_by_token
        self.events = events
        self.calls: list[str] = []
        self.gate_entered: asyncio.Event | None = None
        self.gate_release: asyncio.Event | None = None

    async def validate_access_token(
        self,
        encoded_access_token: str,
    ) -> AuthenticatedPrincipalV1:
        self.events.append("oidc_validate")
        self.calls.append(encoded_access_token)
        if self.gate_entered is not None and self.gate_release is not None:
            self.gate_entered.set()
            await self.gate_release.wait()
        principal = self.principals_by_token.get(encoded_access_token)
        if principal is None:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNATURE_INVALID
            )
        return principal


@dataclass
class ApplicationSideEffects:
    delegate_lookups: int = 0
    delegate_starts: int = 0
    chat_session_creations: int = 0
    handler_initializations: int = 0
    media_deliveries: int = 0
    data_channel_deliveries: int = 0


class RecordingSessionDelegate:
    def __init__(
        self,
        effects: ApplicationSideEffects,
        events: list[str],
    ):
        self.effects = effects
        self.events = events
        self.received: list[tuple[object, object]] = []
        self.signals: list[object] = []
        self.output_queues: dict[object, asyncio.Queue] = {}

    async def get_data(self, modality, timeout=0.1):
        queue = self.output_queues.get(modality)
        if queue is None or queue.empty():
            return None
        return queue.get_nowait()

    def put_data(
        self,
        modality,
        data,
        timestamp=None,
        samplerate=None,
        loopback=False,
    ):
        self.effects.media_deliveries += 1
        if isinstance(data, str):
            self.effects.data_channel_deliveries += 1
        self.received.append((modality, data))

    def get_timestamp(self):
        return (10, 1)

    def emit_signal(self, signal):
        self.signals.append(signal)

    def clear_data(self):
        return None

    async def serve_websocket(self, websocket):
        self.events.append("application_websocket_serve")
        return False


class RecordingHandlerDelegate:
    def __init__(
        self,
        events: list[str],
        *,
        fail_start: bool = False,
        fail_stop: bool = False,
    ):
        self.events = events
        self.effects = ApplicationSideEffects()
        self.fail_start = fail_start
        self.fail_stop = fail_stop
        self.session_delegates: dict[str, RecordingSessionDelegate] = {}
        self.session_admissions: dict[str, ConsumedSessionAdmissionV1] = {}
        self.stop_calls: list[str] = []
        self.after_start = None

    def find_session_delegate(self, session_id: str):
        self.events.append("delegate_lookup")
        self.effects.delegate_lookups += 1
        return self.session_delegates.get(session_id)

    def find_session_admission(self, session_id: str):
        self.events.append("session_admission_lookup")
        return self.session_admissions.get(session_id)

    def start_session(
        self,
        session_id: str,
        *,
        session_admission: ConsumedSessionAdmissionV1 | None = None,
        **kwargs,
    ):
        self.events.append("delegate_start")
        self.effects.delegate_starts += 1
        self.effects.chat_session_creations += 1
        if self.fail_start:
            # Model a partially inserted ChatSession that the caller must remove.
            self.session_admissions[session_id] = session_admission
            raise RuntimeError("application-attachment-failure-canary")
        delegate = RecordingSessionDelegate(self.effects, self.events)
        self.effects.handler_initializations += 1
        self.session_delegates[session_id] = delegate
        if session_admission is not None:
            self.session_admissions[session_id] = session_admission
        if self.after_start is not None:
            self.after_start()
        return delegate

    def stop_session(self, session_id: str):
        self.events.append("delegate_stop")
        self.stop_calls.append(session_id)
        self.session_delegates.pop(session_id, None)
        self.session_admissions.pop(session_id, None)
        if self.fail_stop:
            raise RuntimeError("application-stop-failure-canary")


class FakePeerConnection:
    def __init__(
        self,
        close_waiting: asyncio.Event | None = None,
        close_release: asyncio.Event | None = None,
    ):
        self.connectionState = "new"
        self.closed = False
        self.callbacks: dict[str, list[Any]] = {}
        self.close_waiting = close_waiting
        self.close_release = close_release

    def on(self, event_name: str):
        def register(callback):
            self.callbacks.setdefault(event_name, []).append(callback)
            return callback

        return register

    async def close(self):
        if self.closed:
            return
        if self.close_waiting is not None and self.close_release is not None:
            self.close_waiting.set()
            await self.close_release.wait()
        self.closed = True
        self.connectionState = "closed"
        for callback in tuple(self.callbacks.get("connectionstatechange", [])):
            result = callback()
            if inspect.isawaitable(result):
                await result


class FakeMediaConnection:
    def __init__(self, event_handler: RtcStream):
        self.event_handler = event_handler
        self.stopped = False

    def stop(self):
        self.stopped = True


class FakeFastRtcStream:
    def __init__(
        self,
        factory: RtcStream,
        events: list[str],
        *,
        auto_start: bool = True,
        offer_has_media: bool = True,
        time_limit: float | None = None,
        fail_offer_at: str | None = None,
        log_signaling: bool = False,
    ):
        self.event_handler = factory
        self.events = events
        self.concurrency_limit = 8
        self.time_limit = time_limit
        self.pcs: dict[str, FakePeerConnection] = {}
        self.handlers: dict[str, RtcStream] = {}
        self.connections: dict[str, list[object]] = {}
        self.connection_timeouts: dict[str, asyncio.Event] = {}
        self.auto_start = auto_start
        self.offer_has_media = offer_has_media
        self.fail_offer_at = fail_offer_at
        self.log_signaling = log_signaling
        self.offer_start_waiting = asyncio.Event()
        self.offer_start_release = asyncio.Event()
        self.pause_before_start = False
        self.offer_return_waiting = asyncio.Event()
        self.offer_return_release = asyncio.Event()
        self.pause_before_return = False
        self.candidate_waiting = asyncio.Event()
        self.candidate_release = asyncio.Event()
        self.pause_candidate = False
        self.peer_close_waiting = asyncio.Event()
        self.peer_close_release = asyncio.Event()
        self.pause_peer_close = False
        self.received_bodies: list[dict[str, object]] = []
        self.last_peer: FakePeerConnection | None = None
        self.last_handler: RtcStream | None = None
        self.mount_called = False

    def set_additional_outputs(self, webrtc_id: str):
        return lambda output: None

    async def handle_offer(self, body, set_outputs):
        self.received_bodies.append(body)
        self.events.append(f"fastrtc_{body['type']}")
        if self.log_signaling:
            logging.getLogger("fastrtc.webrtc_connection_mixin").debug(
                "Offer body %s",
                body,
            )
            logging.getLogger("aiortc.rtcpeerconnection").debug(
                "setRemoteDescription\n%s",
                body.get("sdp") or body.get("candidate"),
            )

        webrtc_id = body["webrtc_id"]
        if body["type"] == "ice-candidate":
            if self.pause_candidate:
                self.candidate_waiting.set()
                await self.candidate_release.wait()
            if self.fail_offer_at == "candidate":
                raise RuntimeError("candidate-failure-canary")
            if webrtc_id not in self.pcs:
                return JSONResponse(
                    status_code=200,
                    content={"status": "failed"},
                )
            return JSONResponse(
                status_code=200,
                content={"status": "success"},
            )

        if self.fail_offer_at == "before_peer":
            raise RuntimeError("peer-construction-failure-canary")
        peer = FakePeerConnection(
            self.peer_close_waiting if self.pause_peer_close else None,
            self.peer_close_release if self.pause_peer_close else None,
        )
        self.pcs[webrtc_id] = peer
        self.last_peer = peer
        if self.fail_offer_at == "after_peer":
            raise RuntimeError("peer-construction-failure-canary")

        self.events.append("handler_copy")
        handler = self.event_handler.copy()
        self.handlers[webrtc_id] = handler
        self.last_handler = handler
        if self.fail_offer_at == "after_copy":
            raise RuntimeError("peer-construction-failure-canary")

        if self.offer_has_media:
            self.connections[webrtc_id] = [FakeMediaConnection(handler)]
        self.connection_timeouts[webrtc_id] = asyncio.Event()

        if self.auto_start and self.offer_has_media:
            if self.pause_before_start:
                self.offer_start_waiting.set()
                await self.offer_start_release.wait()
            self.events.append("handler_start")
            await handler.start_up()
        if self.fail_offer_at == "after_start":
            raise RuntimeError("peer-construction-failure-canary")
        if self.pause_before_return:
            self.offer_return_waiting.set()
            await self.offer_return_release.wait()
        return {"sdp": "server-answer-sdp", "type": "answer"}

    def clean_up(self, webrtc_id: str):
        self.events.append("fastrtc_cleanup")
        self.pcs.pop(webrtc_id, None)
        self.handlers.pop(webrtc_id, None)
        self.connection_timeouts.pop(webrtc_id, None)
        return self.connections.pop(webrtc_id, [])

    def mount(self, app: FastAPI):
        self.mount_called = True


@dataclass
class RtcTestEnvironment:
    app: FastAPI
    clock: FakeClock
    events: list[str]
    authority: RecordingAuthority
    validator: FakeAccessTokenValidator
    principal: AuthenticatedPrincipalV1
    handler_delegate: RecordingHandlerDelegate
    factory: RtcStream
    fastrtc: FakeFastRtcStream
    controller: AuthenticatedRtcAdmissionControllerV1

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="https://service.example.test",
        )


def _environment(
    *,
    auto_start: bool = True,
    offer_has_media: bool = True,
    time_limit: float | None = None,
    fail_offer_at: str | None = None,
    fail_session_start: bool = False,
    fail_session_stop: bool = False,
    log_signaling: bool = False,
    principals_by_token: dict[str, AuthenticatedPrincipalV1] | None = None,
) -> RtcTestEnvironment:
    events: list[str] = []
    clock = FakeClock()
    principal = _principal()
    authority = RecordingAuthority(clock, events)
    selected_principals = (
        principals_by_token
        if principals_by_token is not None
        else {
            OWNER_ACCESS_TOKEN: principal,
            ATTACKER_ACCESS_TOKEN: _principal(subject="attacker"),
        }
    )
    validator = FakeAccessTokenValidator(selected_principals, events)
    runtime = CertificateSessionControlRuntimeV1(
        authority=authority,
        access_token_validator=validator,
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.certificate_session_control_v1 = runtime
    handler_delegate = RecordingHandlerDelegate(
        events,
        fail_start=fail_session_start,
        fail_stop=fail_session_stop,
    )
    factory = RtcStream(
        session_id=None,
        stream_start_delay=0,
    )
    factory.client_handler_delegate = handler_delegate
    fastrtc = FakeFastRtcStream(
        factory,
        events,
        auto_start=auto_start,
        offer_has_media=offer_has_media,
        time_limit=time_limit,
        fail_offer_at=fail_offer_at,
        log_signaling=log_signaling,
    )
    controller = mount_rtc_signaling_routes_v1(app, fastrtc, factory)
    assert isinstance(controller, AuthenticatedRtcAdmissionControllerV1)
    return RtcTestEnvironment(
        app=app,
        clock=clock,
        events=events,
        authority=authority,
        validator=validator,
        principal=principal,
        handler_delegate=handler_delegate,
        factory=factory,
        fastrtc=fastrtc,
        controller=controller,
    )


def _issue(
    environment: RtcTestEnvironment,
    *,
    principal: AuthenticatedPrincipalV1 | None = None,
    channel: SessionAdmissionChannelV1 = SessionAdmissionChannelV1.RTC,
):
    owner = principal if principal is not None else environment.principal
    session = environment.authority.create_session(owner)
    ticket = environment.authority.issue_admission_ticket(
        owner,
        session.session_id,
        session.session_capability,
        channel,
    )
    return owner, session, ticket


def _offer_headers(
    session_id: str,
    admission_ticket: str,
    *,
    access_token: str = OWNER_ACCESS_TOKEN,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        RTC_SESSION_ID_HEADER_V1: session_id,
        RTC_ADMISSION_TICKET_HEADER_V1: admission_ticket,
    }


def _candidate_headers(
    transport_binding: str,
    *,
    access_token: str = OWNER_ACCESS_TOKEN,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        RTC_TRANSPORT_BINDING_HEADER_V1: transport_binding,
    }


def _offer_body(
    webrtc_id: str,
    *,
    sdp: str = "client-offer-sdp",
) -> dict[str, object]:
    return {
        "sdp": sdp,
        "type": "offer",
        "webrtc_id": webrtc_id,
    }


def _candidate_body(
    webrtc_id: str,
    *,
    candidate: str = (
        "candidate:1 1 udp 2122260223 127.0.0.1 5000 "
        "typ host generation 0 ufrag ice-user-canary"
    ),
) -> dict[str, object]:
    return {
        "candidate": {
            "candidate": candidate,
            "sdpMid": "0",
            "sdpMLineIndex": 0,
            "usernameFragment": "ice-user-canary",
        },
        "type": "ice-candidate",
        "webrtc_id": webrtc_id,
    }


def _route_inventory(app: FastAPI) -> set[tuple[str, str]]:
    inventory: set[tuple[str, str]] = set()
    for route in app.routes:
        methods = getattr(route, "methods", None)
        if methods:
            for method in methods:
                inventory.add((method, route.path))
        else:
            inventory.add(("WEBSOCKET", route.path))
    return inventory


def _assert_zero_application_side_effects(
    environment: RtcTestEnvironment,
) -> None:
    assert environment.handler_delegate.effects == ApplicationSideEffects()
    assert environment.handler_delegate.session_delegates == {}


async def _run_asgi_websocket(
    app: FastAPI,
    session_id: str,
    admission_ticket: str,
) -> list[dict[str, object]]:
    protocol = WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1 + admission_ticket
    path = f"/ws/session/{session_id}"
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "scheme": "wss",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"service.example.test"),
            (b"sec-websocket-protocol", protocol.encode("ascii")),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("service.example.test", 443),
        "subprotocols": [protocol],
        "extensions": {"websocket.http.response": {}},
    }
    incoming = [
        {"type": "websocket.connect"},
        {"type": "websocket.disconnect", "code": 1000},
    ]
    sent: list[dict[str, object]] = []

    async def receive():
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def test_installed_fastrtc_is_exactly_pinned_0_0_34():
    assert version("fastrtc") == "0.0.34"


@pytest.mark.asyncio
async def test_audio_video_offer_exposes_media_tracks_during_remote_setup():
    client_peer = RTCPeerConnection()
    server_peer = RTCPeerConnection()
    observed_tracks: list[str] = []
    server_peer.on("track")(lambda track: observed_tracks.append(track.kind))
    client_peer.addTransceiver("audio", direction="sendrecv")
    client_peer.addTransceiver("video", direction="sendrecv")
    try:
        offer = await client_peer.createOffer()
        await server_peer.setRemoteDescription(offer)
    finally:
        await server_peer.close()
        await client_peer.close()

    assert observed_tracks == ["audio", "video"]


def test_actual_fastrtc_route_inventory_is_legacy_when_feature_disabled():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    factory = RtcStream(session_id=None)
    factory.client_handler_delegate = RecordingHandlerDelegate([])
    stream = Stream(
        handler=factory,
        modality="audio-video",
        mode="send-receive",
        concurrency_limit=2,
        verbose=False,
    )

    controller = mount_rtc_signaling_routes_v1(app, stream, factory)

    assert controller is None
    assert _route_inventory(app) == {
        ("POST", "/webrtc/offer"),
        ("WEBSOCKET", "/telephone/handler"),
        ("POST", "/telephone/incoming"),
        ("WEBSOCKET", "/websocket/offer"),
    }
    assert factory._secure_admission_required_v1 is False
    assert not hasattr(app.state, "authenticated_rtc_admission_v1")


def test_actual_fastrtc_route_inventory_is_isolated_when_feature_enabled():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    clock = FakeClock()
    events: list[str] = []
    authority = RecordingAuthority(clock, events)
    runtime = CertificateSessionControlRuntimeV1(
        authority=authority,
        access_token_validator=FakeAccessTokenValidator(
            {OWNER_ACCESS_TOKEN: _principal()},
            events,
        ),
    )
    app.state.certificate_session_control_v1 = runtime
    factory = RtcStream(session_id=None)
    factory.client_handler_delegate = RecordingHandlerDelegate(events)
    stream = Stream(
        handler=factory,
        modality="audio-video",
        mode="send-receive",
        concurrency_limit=2,
        verbose=False,
    )

    controller = mount_rtc_signaling_routes_v1(app, stream, factory)

    assert isinstance(controller, AuthenticatedRtcAdmissionControllerV1)
    assert _route_inventory(app) == {("POST", "/webrtc/offer")}
    assert factory._secure_admission_required_v1 is True
    assert ("WEBSOCKET", "/telephone/handler") not in _route_inventory(app)
    assert ("POST", "/telephone/incoming") not in _route_inventory(app)
    assert ("WEBSOCKET", "/websocket/offer") not in _route_inventory(app)


def test_enabled_mode_fails_closed_if_legacy_fastrtc_was_already_mounted():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    clock = FakeClock()
    events: list[str] = []
    app.state.certificate_session_control_v1 = CertificateSessionControlRuntimeV1(
        authority=RecordingAuthority(clock, events),
        access_token_validator=FakeAccessTokenValidator(
            {OWNER_ACCESS_TOKEN: _principal()},
            events,
        ),
    )
    factory = RtcStream(session_id=None)
    factory.client_handler_delegate = RecordingHandlerDelegate(events)
    stream = Stream(
        handler=factory,
        modality="audio-video",
        mode="send-receive",
        concurrency_limit=2,
        verbose=False,
    )
    stream.mount(app)

    with pytest.raises(CertificateCaptureStartupError) as exception:
        mount_rtc_signaling_routes_v1(app, stream, factory)

    assert exception.value.reason_code == "RTC_SIGNALING_ROUTE_CONFLICT"
    assert factory._secure_admission_required_v1 is False


def test_enabled_marker_without_authority_fails_closed_before_legacy_mount():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    setattr(
        app.state,
        CERTIFICATE_CAPTURE_ENABLED_STATE_ATTRIBUTE_V1,
        True,
    )
    events: list[str] = []
    factory = RtcStream(session_id=None)
    factory.client_handler_delegate = RecordingHandlerDelegate(events)
    stream = FakeFastRtcStream(factory, events)

    with pytest.raises(CertificateCaptureStartupError) as exception:
        mount_rtc_signaling_routes_v1(app, stream, factory)

    assert exception.value.reason_code == "RTC_SESSION_AUTHORITY_UNAVAILABLE"
    assert stream.mount_called is False
    assert _route_inventory(app) == set()


@pytest.mark.asyncio
async def test_pinned_fastrtc_peer_failure_consumes_ticket_and_cleans_state():
    clock = FakeClock()
    events: list[str] = []
    authority = RecordingAuthority(clock, events)
    principal = _principal()
    runtime = CertificateSessionControlRuntimeV1(
        authority=authority,
        access_token_validator=FakeAccessTokenValidator(
            {OWNER_ACCESS_TOKEN: principal},
            events,
        ),
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.certificate_session_control_v1 = runtime
    handler_delegate = RecordingHandlerDelegate(events)
    factory = RtcStream(session_id=None)
    factory.client_handler_delegate = handler_delegate
    stream = Stream(
        handler=factory,
        modality="audio-video",
        mode="send-receive",
        concurrency_limit=2,
        verbose=False,
    )
    controller = mount_rtc_signaling_routes_v1(app, stream, factory)
    session = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.RTC,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://service.example.test",
    ) as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body(
                "pinned-fastrtc-invalid-sdp",
                sdp="v=x\r\n",
            ),
        )

    assert response.status_code == 503
    assert authority.snapshot().active_tickets == 0
    assert controller.snapshot()["active_bindings"] == 0
    assert stream.pcs == {}
    assert stream.handlers == {}
    assert factory.streams == {}
    assert handler_delegate.effects.delegate_starts == 0


@pytest.mark.asyncio
async def test_data_channel_only_offer_is_rejected_and_cleaned():
    environment = _environment(offer_has_media=False)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("data-only-offer"),
        )

    assert response.status_code == 503
    assert (
        response.json()["reason_code"]
        == RtcAdmissionReasonV1.PEER_CONSTRUCTION_FAILED.value
    )
    assert environment.authority.snapshot().active_tickets == 0
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert environment.fastrtc.connections == {}
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
async def test_valid_rtc_admission_precedes_copy_and_attaches_exact_session():
    environment = _environment()
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("attacker-selected-transport"),
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "answer"
    assert payload[RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1].startswith("rtb1_")
    stream = environment.fastrtc.last_handler
    assert stream is not None
    assert stream.session_id == session.session_id
    assert stream.session_id != "attacker-selected-transport"
    assert stream.webrtc_id == "attacker-selected-transport"
    assert stream.transport_id.startswith("rti1_")
    assert stream.transport_id != stream.webrtc_id
    assert stream.session_admission is stream.trusted_rtc_admission.session_admission
    assert stream.session_admission.ticket_id == ticket.ticket_id
    assert stream.session_admission.channel is SessionAdmissionChannelV1.RTC
    assert (
        environment.handler_delegate.session_delegates[session.session_id]
        is stream.client_session_delegate
    )
    assert environment.events.index("ticket_consume") < environment.events.index(
        "fastrtc_offer"
    )
    assert environment.events.index("fastrtc_offer") < environment.events.index(
        "admission_validate"
    )
    assert environment.events.index("admission_validate") < environment.events.index(
        "delegate_lookup"
    )
    assert environment.authority.snapshot().active_tickets == 0
    assert all(
        set(body) <= {"sdp", "candidate", "type", "webrtc_id"}
        for body in environment.fastrtc.received_bodies
    )
    assert all(
        body["webrtc_id"] == stream.transport_id
        for body in environment.fastrtc.received_bodies
    )


@pytest.mark.asyncio
async def test_media_and_data_are_dropped_before_secure_session_attachment():
    environment = _environment(auto_start=False)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("transport-before-attachment"),
        )

    assert response.status_code == 200
    stream = environment.fastrtc.last_handler
    assert stream is not None
    assert stream.client_session_delegate is None
    await stream.receive((16_000, np.ones((1, 160), dtype=np.int16)))
    await stream.video_receive(np.ones((2, 2, 3), dtype=np.uint8))

    class FakeDataChannel:
        def __init__(self):
            self.callbacks = {}
            self.sent: list[str] = []

        def on(self, event_name):
            def register(callback):
                self.callbacks[event_name] = callback
                return callback

            return register

        def send(self, message):
            self.sent.append(message)

    channel = FakeDataChannel()
    stream.set_channel(channel)
    channel.callbacks["message"](
        '{"header":{"name":"SendHumanText"},"payload":{"text":"blocked"}}'
    )
    assert environment.handler_delegate.effects.media_deliveries == 0
    assert environment.handler_delegate.effects.data_channel_deliveries == 0
    assert environment.handler_delegate.effects.delegate_starts == 0


@pytest.mark.asyncio
async def test_duplicate_startup_on_one_peer_is_idempotent():
    environment = _environment(auto_start=False)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("duplicate-startup"),
        )

    assert response.status_code == 200
    stream = environment.fastrtc.last_handler
    await asyncio.gather(stream.start_up(), stream.start_up())
    assert environment.handler_delegate.effects.delegate_starts == 1
    assert environment.handler_delegate.effects.chat_session_creations == 1
    assert stream.owns_session is True
    assert (
        stream.client_session_delegate
        is (environment.handler_delegate.session_delegates[session.session_id])
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("session_id", "ticket_value", "expected_status"),
    [
        ("cs1_" + "A" * 43, "att1_" + "B" * 43, 403),
        ("cs1_" + "A" * 43, "not-a-ticket", 400),
        ("not-a-session", "att1_" + "B" * 43, 400),
    ],
)
async def test_random_malformed_and_guessed_admission_are_side_effect_free(
    session_id: str,
    ticket_value: str,
    expected_status: int,
):
    environment = _environment()

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(session_id, ticket_value),
            json=_offer_body("guessed-transport"),
        )

    assert response.status_code == expected_status
    _assert_zero_application_side_effects(environment)
    assert environment.fastrtc.received_bodies == []
    assert environment.controller.snapshot()["active_bindings"] == 0


@pytest.mark.asyncio
async def test_ticket_session_mismatch_and_attacker_principal_are_denied():
    owner = _principal()
    other_issuer_same_subject = _principal(
        issuer="https://other-issuer.example.test",
        subject=OWNER_SUBJECT,
    )
    environment = _environment(
        principals_by_token={
            OWNER_ACCESS_TOKEN: owner,
            ATTACKER_ACCESS_TOKEN: other_issuer_same_subject,
        }
    )
    _, owner_session, ticket = _issue(environment, principal=owner)
    other_session = environment.authority.create_session(
        _principal(subject="other-owner")
    )

    async with environment.client() as client:
        wrong_session = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                other_session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("wrong-session-transport"),
        )
        wrong_principal = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                owner_session.session_id,
                ticket.admission_ticket,
                access_token=ATTACKER_ACCESS_TOKEN,
            ),
            json=_offer_body("wrong-principal-transport"),
        )

    assert wrong_session.status_code == 403
    assert wrong_principal.status_code == 403
    _assert_zero_application_side_effects(environment)
    # Failed mismatches do not consume the still-valid owner-bound ticket.
    admission = environment.authority.consume_admission_ticket(
        owner,
        owner_session.session_id,
        ticket.admission_ticket,
        SessionAdmissionChannelV1.RTC,
    )
    assert admission.ticket_id == ticket.ticket_id


@pytest.mark.asyncio
@pytest.mark.parametrize("lifecycle", ["revoked", "replaced", "expired"])
async def test_non_live_session_is_denied_before_fastrtc(
    lifecycle: str,
):
    environment = _environment()
    principal = (
        _principal(token_expiry=NOW + 30)
        if lifecycle == "expired"
        else environment.principal
    )
    _, session, ticket = _issue(environment, principal=principal)
    if lifecycle == "revoked":
        environment.authority.revoke_session(
            principal,
            session.session_id,
            session.session_capability,
        )
    elif lifecycle == "replaced":
        environment.authority.create_session(principal)
    else:
        environment.clock.advance(30)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body(f"{lifecycle}-transport"),
        )

    assert response.status_code == 403
    _assert_zero_application_side_effects(environment)
    assert environment.fastrtc.received_bodies == []


@pytest.mark.asyncio
async def test_expired_ticket_is_denied_while_owned_session_remains_live():
    environment = _environment()
    _, session, ticket = _issue(environment)
    environment.clock.advance(60)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("expired-ticket-transport"),
        )

    assert response.status_code == 403
    assert environment.authority.snapshot().active_sessions == 1
    _assert_zero_application_side_effects(environment)
    assert environment.fastrtc.received_bodies == []


@pytest.mark.asyncio
async def test_wrong_channel_ticket_is_denied_and_remains_ws_bound():
    environment = _environment()
    principal, session, ticket = _issue(
        environment,
        channel=SessionAdmissionChannelV1.WEBSOCKET,
    )

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("wrong-channel-transport"),
        )

    assert response.status_code == 403
    _assert_zero_application_side_effects(environment)
    consumed = environment.authority.consume_websocket_admission_ticket(
        session.session_id,
        ticket.admission_ticket,
    )
    assert consumed.channel is SessionAdmissionChannelV1.WEBSOCKET
    assert consumed.owner_subject == principal.subject


@pytest.mark.asyncio
async def test_concurrent_double_consume_authorizes_at_most_one_transport():
    environment = _environment()
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        first, second = await asyncio.gather(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body("concurrent-transport-a"),
            ),
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body("concurrent-transport-b"),
            ),
        )

    assert sorted([first.status_code, second.status_code]) == [200, 403]
    assert environment.handler_delegate.effects.delegate_starts == 1
    assert environment.handler_delegate.effects.chat_session_creations == 1
    assert environment.controller.snapshot()["active_bindings"] == 1
    assert len(environment.fastrtc.pcs) == 1
    assert environment.authority.snapshot().active_tickets == 0


@pytest.mark.asyncio
async def test_two_valid_rtc_tickets_cannot_bind_two_peers_to_one_session():
    environment = _environment()
    principal, session, first_ticket = _issue(environment)
    second_ticket = environment.authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.RTC,
    )

    async with environment.client() as client:
        first, second = await asyncio.gather(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    first_ticket.admission_ticket,
                ),
                json=_offer_body("same-session-peer-a"),
            ),
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    second_ticket.admission_ticket,
                ),
                json=_offer_body("same-session-peer-b"),
            ),
        )

    assert sorted([first.status_code, second.status_code]) == [200, 503]
    assert environment.handler_delegate.effects.delegate_starts == 1
    assert environment.handler_delegate.effects.chat_session_creations == 1
    assert environment.controller.snapshot() == {
        "active_bindings": 1,
        "attached_sessions": 1,
    }
    assert len(environment.fastrtc.pcs) == 1
    assert environment.authority.snapshot().active_tickets == 0


@pytest.mark.asyncio
async def test_session_remains_reserved_until_old_transport_cleanup_finishes():
    environment = _environment()
    principal, session, first_ticket = _issue(environment)
    environment.fastrtc.pause_peer_close = True

    async with environment.client() as client:
        first = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                first_ticket.admission_ticket,
            ),
            json=_offer_body("cleanup-in-progress-old-peer"),
        )
        assert first.status_code == 200

        old_stream = environment.fastrtc.last_handler
        assert old_stream is not None
        old_admission = old_stream.trusted_rtc_admission
        assert old_admission is not None
        cleanup_task = asyncio.create_task(old_admission.abort_stream(old_stream))
        await asyncio.wait_for(
            environment.fastrtc.peer_close_waiting.wait(),
            timeout=1,
        )

        second_ticket = environment.authority.issue_admission_ticket(
            principal,
            session.session_id,
            session.session_capability,
            SessionAdmissionChannelV1.RTC,
        )
        environment.fastrtc.pause_peer_close = False
        second = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                second_ticket.admission_ticket,
            ),
            json=_offer_body("cleanup-in-progress-new-peer"),
        )

        assert second.status_code == 503
        assert environment.handler_delegate.effects.delegate_starts == 1
        assert environment.controller.snapshot()["attached_sessions"] == 1
        environment.fastrtc.peer_close_release.set()
        await asyncio.wait_for(cleanup_task, timeout=1)

    assert environment.controller.snapshot() == {
        "active_bindings": 0,
        "attached_sessions": 0,
    }
    assert environment.handler_delegate.session_delegates == {}
    assert environment.fastrtc.pcs == {}


@pytest.mark.asyncio
async def test_cancelled_peer_close_still_retires_application_and_binding_state():
    environment = _environment()
    _, session, ticket = _issue(environment)
    environment.fastrtc.pause_peer_close = True

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("cancelled-cleanup-peer"),
        )
    assert response.status_code == 200
    stream = environment.fastrtc.last_handler
    assert stream is not None
    admission = stream.trusted_rtc_admission
    assert admission is not None

    cleanup_task = asyncio.create_task(admission.abort_stream(stream))
    await asyncio.wait_for(
        environment.fastrtc.peer_close_waiting.wait(),
        timeout=1,
    )
    cleanup_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cleanup_task

    assert environment.controller.snapshot() == {
        "active_bindings": 0,
        "attached_sessions": 0,
    }
    assert environment.handler_delegate.session_delegates == {}
    assert session.session_id in environment.handler_delegate.stop_calls
    assert environment.fastrtc.pcs == {}


@pytest.mark.asyncio
async def test_stop_session_exception_is_contained_after_state_cleanup():
    environment = _environment(fail_session_stop=True)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("stop-exception-peer"),
        )
    assert response.status_code == 200

    await environment.controller.close()

    assert environment.controller.snapshot() == {
        "active_bindings": 0,
        "attached_sessions": 0,
    }
    assert environment.handler_delegate.session_delegates == {}
    assert environment.handler_delegate.session_admissions == {}
    assert session.session_id in environment.handler_delegate.stop_calls
    assert environment.fastrtc.pcs == {}


@pytest.mark.asyncio
async def test_reused_caller_webrtc_id_gets_fresh_internal_fastrtc_generation():
    environment = _environment()
    principal, session, first_ticket = _issue(environment)
    caller_webrtc_id = "reused-caller-transport"

    async with environment.client() as client:
        first = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                first_ticket.admission_ticket,
            ),
            json=_offer_body(caller_webrtc_id),
        )
        assert first.status_code == 200
        first_stream = environment.fastrtc.last_handler
        assert first_stream is not None
        first_internal_id = first_stream.transport_id
        first_admission = first_stream.trusted_rtc_admission
        assert first_admission is not None
        await first_admission.abort_stream(first_stream)

        second_ticket = environment.authority.issue_admission_ticket(
            principal,
            session.session_id,
            session.session_capability,
            SessionAdmissionChannelV1.RTC,
        )
        second = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                second_ticket.admission_ticket,
            ),
            json=_offer_body(caller_webrtc_id),
        )
        assert second.status_code == 200
        second_stream = environment.fastrtc.last_handler
        assert second_stream is not None
        second_internal_id = second_stream.transport_id
        assert second_internal_id != first_internal_id

        # A delayed ID-keyed FastRTC 0.0.34 timeout from the retired peer can
        # clean only its never-reused internal generation.
        environment.fastrtc.clean_up(first_internal_id)
        candidate = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers(
                second.json()[RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1]
            ),
            json=_candidate_body(caller_webrtc_id),
        )

    assert candidate.status_code == 200
    assert second_internal_id in environment.fastrtc.pcs
    assert environment.fastrtc.handlers[second_internal_id] is second_stream
    assert environment.controller.snapshot() == {
        "active_bindings": 1,
        "attached_sessions": 1,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_point",
    ["before_peer", "after_peer", "after_copy"],
)
async def test_consumed_ticket_is_not_restored_when_peer_creation_fails(
    failure_point: str,
):
    environment = _environment(fail_offer_at=failure_point)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body(f"failed-peer-{failure_point}"),
        )
        replay = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body(f"replay-{failure_point}"),
        )

    assert response.status_code == 503
    assert (
        response.json()["reason_code"]
        == RtcAdmissionReasonV1.PEER_CONSTRUCTION_FAILED.value
    )
    assert replay.status_code == 403
    assert environment.authority.snapshot().active_tickets == 0
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert environment.handler_delegate.effects.delegate_starts == 0
    if environment.fastrtc.last_peer is not None:
        assert environment.fastrtc.last_peer.closed is True


@pytest.mark.asyncio
async def test_attachment_failure_cleans_peer_and_partial_application_state():
    environment = _environment(fail_session_start=True)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("attachment-failure-transport"),
        )

    assert response.status_code == 503
    assert environment.authority.snapshot().active_tickets == 0
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.handler_delegate.session_delegates == {}
    assert environment.handler_delegate.session_admissions == {}
    assert session.session_id in environment.handler_delegate.stop_calls
    assert environment.fastrtc.pcs == {}
    assert environment.fastrtc.last_peer.closed is True


@pytest.mark.asyncio
async def test_duplicate_offer_cannot_duplicate_authority_or_consume_new_ticket():
    environment = _environment()
    principal, session, first_ticket = _issue(environment)

    async with environment.client() as client:
        first = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                first_ticket.admission_ticket,
            ),
            json=_offer_body("duplicate-offer-transport"),
        )
        second_ticket = environment.authority.issue_admission_ticket(
            principal,
            session.session_id,
            session.session_capability,
            SessionAdmissionChannelV1.RTC,
        )
        duplicate = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                second_ticket.admission_ticket,
            ),
            json=_offer_body("duplicate-offer-transport"),
        )

    assert first.status_code == 200
    assert duplicate.status_code == 409
    assert environment.handler_delegate.effects.delegate_starts == 1
    assert len(environment.fastrtc.pcs) == 1
    remaining = environment.authority.consume_admission_ticket(
        principal,
        session.session_id,
        second_ticket.admission_ticket,
        SessionAdmissionChannelV1.RTC,
    )
    assert remaining.ticket_id == second_ticket.ticket_id


@pytest.mark.asyncio
async def test_ticket_replay_with_new_transport_is_denied():
    environment = _environment()
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        first = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("replay-original"),
        )
        replay = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("replay-attacker"),
        )

    assert first.status_code == 200
    assert replay.status_code == 403
    assert environment.controller.snapshot()["active_bindings"] == 1
    assert len(environment.fastrtc.pcs) == 1


@pytest.mark.asyncio
async def test_candidate_requires_owner_and_server_binding_proof():
    environment = _environment()
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        offer = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("candidate-proof-transport"),
        )
        binding = offer.json()[RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1]
        no_binding = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers={"Authorization": f"Bearer {OWNER_ACCESS_TOKEN}"},
            json=_candidate_body("candidate-proof-transport"),
        )
        wrong_binding = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers("rtb1_" + "A" * 43),
            json=_candidate_body("candidate-proof-transport"),
        )
        wrong_owner = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers(
                binding,
                access_token=ATTACKER_ACCESS_TOKEN,
            ),
            json=_candidate_body("candidate-proof-transport"),
        )
        wrong_peer = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers(binding),
            json=_candidate_body("another-peer"),
        )
        valid = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers(binding),
            json=_candidate_body("candidate-proof-transport"),
        )

    assert no_binding.status_code == 400
    assert wrong_binding.status_code == 403
    assert wrong_owner.status_code == 403
    assert wrong_peer.status_code == 403
    assert valid.status_code == 200
    assert valid.json() == {"status": "success"}
    assert environment.controller.snapshot()["active_bindings"] == 1


@pytest.mark.asyncio
async def test_candidate_before_authorized_peer_exists_is_denied():
    environment = _environment()

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers("rtb1_" + "A" * 43),
            json=_candidate_body("missing-peer"),
        )

    assert response.status_code == 403
    assert environment.fastrtc.received_bodies == []
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
async def test_candidate_cannot_supply_session_or_ticket_authority():
    environment = _environment()
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        offer = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("candidate-no-authority"),
        )
        binding = offer.json()[RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1]
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers={
                **_candidate_headers(binding),
                RTC_SESSION_ID_HEADER_V1: session.session_id,
                RTC_ADMISSION_TICKET_HEADER_V1: ticket.admission_ticket,
            },
            json=_candidate_body("candidate-no-authority"),
        )

    assert response.status_code == 400
    assert (
        response.json()["reason_code"]
        == RtcAdmissionReasonV1.SIGNALING_REQUEST_INVALID.value
    )
    assert environment.controller.snapshot()["active_bindings"] == 1


@pytest.mark.asyncio
async def test_sdp_candidate_and_metadata_cannot_reconstruct_admission():
    environment = _environment()
    _, session, ticket = _issue(environment)
    embedded = (
        f"v=0\\r\\na=x-session:{session.session_id}\\r\\n"
        f"a=x-ticket:{ticket.admission_ticket}\\r\\n"
    )

    async with environment.client() as client:
        sdp_only = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers={"Authorization": f"Bearer {OWNER_ACCESS_TOKEN}"},
            json=_offer_body("sdp-only-authority", sdp=embedded),
        )
        metadata = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers={"Authorization": f"Bearer {OWNER_ACCESS_TOKEN}"},
            json={
                **_offer_body("metadata-authority", sdp=embedded),
                "metadata": {
                    "session_id": session.session_id,
                    "admission_ticket": ticket.admission_ticket,
                },
            },
        )
        candidate_only = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers={"Authorization": f"Bearer {OWNER_ACCESS_TOKEN}"},
            json=_candidate_body(
                "candidate-only-authority",
                candidate=f"candidate:{ticket.admission_ticket}",
            ),
        )

    assert sdp_only.status_code == 400
    assert metadata.status_code == 400
    assert candidate_only.status_code == 400
    _assert_zero_application_side_effects(environment)
    assert environment.fastrtc.received_bodies == []


@pytest.mark.asyncio
async def test_admission_ticket_in_query_string_is_never_accepted():
    environment = _environment()
    principal, session, ticket = _issue(environment)
    observed_query_strings: list[bytes] = []

    class ObserveAccessLogScope:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)
            observed_query_strings.append(scope["query_string"])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ObserveAccessLogScope(environment.app)),
        base_url="https://service.example.test",
    ) as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            params={
                "session_id": session.session_id,
                "admission_ticket": ticket.admission_ticket,
            },
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("query-credential"),
        )

    assert response.status_code == 400
    assert observed_query_strings == [b""]
    assert environment.fastrtc.received_bodies == []
    _assert_zero_application_side_effects(environment)
    consumed = environment.authority.consume_admission_ticket(
        principal,
        session.session_id,
        ticket.admission_ticket,
        SessionAdmissionChannelV1.RTC,
    )
    assert consumed.ticket_id == ticket.ticket_id


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["revoke", "replace"])
async def test_control_transition_winning_before_ticket_consume_denies_offer(
    transition: str,
):
    environment = _environment()
    principal, session, ticket = _issue(environment)
    environment.validator.gate_entered = asyncio.Event()
    environment.validator.gate_release = asyncio.Event()

    async with environment.client() as client:
        request_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body(f"consume-race-{transition}"),
            )
        )
        await asyncio.wait_for(environment.validator.gate_entered.wait(), timeout=1)
        async with environment.authority.serialized_transition():
            if transition == "revoke":
                environment.authority.revoke_session(
                    principal,
                    session.session_id,
                    session.session_capability,
                )
            else:
                environment.authority.create_session(principal)
        environment.validator.gate_release.set()
        response = await asyncio.wait_for(request_task, timeout=1)

    assert response.status_code == 403
    assert environment.fastrtc.received_bodies == []
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["revoke", "replace"])
async def test_revocation_or_replacement_before_attachment_aborts_peer(
    transition: str,
):
    environment = _environment()
    principal, session, ticket = _issue(environment)
    environment.fastrtc.pause_before_start = True

    async with environment.client() as client:
        request_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body(f"transition-{transition}"),
            )
        )
        await asyncio.wait_for(
            environment.fastrtc.offer_start_waiting.wait(),
            timeout=1,
        )
        assert environment.authority.snapshot().active_tickets == 0
        if transition == "revoke":
            async with environment.authority.serialized_transition():
                environment.authority.revoke_session(
                    principal,
                    session.session_id,
                    session.session_capability,
                )
        else:
            async with environment.authority.serialized_transition():
                environment.authority.create_session(principal)
        environment.fastrtc.offer_start_release.set()
        response = await asyncio.wait_for(request_task, timeout=1)

    assert response.status_code == 503
    assert environment.handler_delegate.session_delegates == {}
    assert environment.handler_delegate.effects.delegate_starts == 0
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert environment.fastrtc.last_peer.closed is True


@pytest.mark.asyncio
async def test_candidate_and_revocation_are_linearized_then_stale_binding_dies():
    environment = _environment()
    principal, session, ticket = _issue(environment)
    environment.fastrtc.pause_candidate = True

    async with environment.client() as client:
        offer = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("candidate-revoke-race"),
        )
        binding = offer.json()[RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1]
        candidate_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_candidate_headers(binding),
                json=_candidate_body("candidate-revoke-race"),
            )
        )
        await asyncio.wait_for(
            environment.fastrtc.candidate_waiting.wait(),
            timeout=1,
        )

        async def revoke():
            async with environment.authority.serialized_transition():
                environment.authority.revoke_session(
                    principal,
                    session.session_id,
                    session.session_capability,
                )

        revoke_task = asyncio.create_task(revoke())
        await asyncio.sleep(0)
        assert not revoke_task.done()
        environment.fastrtc.candidate_release.set()
        candidate_response = await asyncio.wait_for(
            candidate_task,
            timeout=1,
        )
        await asyncio.wait_for(revoke_task, timeout=1)
        stale_candidate = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_candidate_headers(binding),
            json=_candidate_body("candidate-revoke-race"),
        )

    assert candidate_response.status_code == 200
    assert stale_candidate.status_code == 403
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert session.session_id in environment.handler_delegate.stop_calls


@pytest.mark.asyncio
async def test_ws_and_rtc_race_create_only_one_secure_chat_session():
    environment = _environment()
    principal, session, rtc_ticket = _issue(environment)
    websocket_ticket = environment.authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    register_ws_session_endpoint(
        environment.app,
        environment.handler_delegate,
        RecordingSessionDelegate,
    )

    async with environment.client() as client:
        rtc_response, websocket_messages = await asyncio.gather(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    rtc_ticket.admission_ticket,
                ),
                json=_offer_body("ws-rtc-race"),
            ),
            _run_asgi_websocket(
                environment.app,
                session.session_id,
                websocket_ticket.admission_ticket,
            ),
        )

    assert rtc_response.status_code == 200
    assert websocket_messages[0]["type"] == "websocket.accept"
    assert environment.handler_delegate.effects.delegate_starts == 1
    assert environment.handler_delegate.effects.chat_session_creations == 1
    assert len(environment.handler_delegate.session_delegates) == 1
    assert environment.authority.snapshot().active_tickets == 0
    stream = environment.fastrtc.last_handler
    assert (
        stream.client_session_delegate
        is (environment.handler_delegate.session_delegates[session.session_id])
    )


@pytest.mark.asyncio
async def test_rtc_attaches_to_existing_ws_owned_session_with_its_own_ticket():
    environment = _environment()
    principal, session, websocket_ticket = _issue(
        environment,
        channel=SessionAdmissionChannelV1.WEBSOCKET,
    )
    websocket_admission = environment.authority.consume_websocket_admission_ticket(
        session.session_id,
        websocket_ticket.admission_ticket,
    )
    existing_delegate = environment.handler_delegate.start_session(
        session.session_id,
        session_admission=websocket_admission,
    )
    starts_before = environment.handler_delegate.effects.delegate_starts
    rtc_ticket = environment.authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.RTC,
    )

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                rtc_ticket.admission_ticket,
            ),
            json=_offer_body("rtc-after-websocket"),
        )

    assert response.status_code == 200
    assert environment.handler_delegate.effects.delegate_starts == starts_before
    assert environment.fastrtc.last_handler.client_session_delegate is (
        existing_delegate
    )
    assert (
        environment.fastrtc.last_handler.session_admission.channel
        is SessionAdmissionChannelV1.RTC
    )
    assert (
        environment.handler_delegate.session_admissions[session.session_id].channel
        is SessionAdmissionChannelV1.WEBSOCKET
    )


@pytest.mark.asyncio
async def test_authority_runtime_removal_fails_closed_without_fastrtc():
    environment = _environment()
    _, session, ticket = _issue(environment)
    del environment.app.state.certificate_session_control_v1

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("missing-authority"),
        )

    assert response.status_code == 503
    _assert_zero_application_side_effects(environment)
    assert environment.fastrtc.received_bodies == []


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["close", "replace_runtime"])
async def test_inflight_offer_fails_if_controller_closes_or_runtime_changes(
    transition: str,
):
    environment = _environment()
    _, session, ticket = _issue(environment)
    environment.validator.gate_entered = asyncio.Event()
    environment.validator.gate_release = asyncio.Event()

    async with environment.client() as client:
        request_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body(f"inflight-{transition}"),
            )
        )
        await asyncio.wait_for(environment.validator.gate_entered.wait(), timeout=1)
        if transition == "close":
            await environment.controller.close()
        else:
            environment.app.state.certificate_session_control_v1 = (
                CertificateSessionControlRuntimeV1(
                    authority=environment.authority,
                    access_token_validator=environment.validator,
                )
            )
        environment.validator.gate_release.set()
        response = await asyncio.wait_for(request_task, timeout=1)

    assert response.status_code == 503
    assert environment.fastrtc.received_bodies == []
    assert environment.controller.snapshot()["active_bindings"] == 0
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["close", "replace_runtime"])
async def test_consumed_offer_is_aborted_if_controller_or_runtime_changes(
    transition: str,
):
    environment = _environment()
    _, session, ticket = _issue(environment)
    environment.fastrtc.pause_before_start = True

    async with environment.client() as client:
        request_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body(f"consumed-{transition}"),
            )
        )
        await asyncio.wait_for(
            environment.fastrtc.offer_start_waiting.wait(),
            timeout=1,
        )
        assert environment.authority.snapshot().active_tickets == 0
        if transition == "close":
            transition_task = asyncio.create_task(environment.controller.close())
            await asyncio.sleep(0)
            assert not transition_task.done()
        else:
            environment.app.state.certificate_session_control_v1 = (
                CertificateSessionControlRuntimeV1(
                    authority=environment.authority,
                    access_token_validator=environment.validator,
                )
            )
            transition_task = None
        environment.fastrtc.offer_start_release.set()
        response = await asyncio.wait_for(request_task, timeout=1)
        if transition_task is not None:
            await asyncio.wait_for(transition_task, timeout=1)

    assert response.status_code == 503
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert environment.fastrtc.last_peer.closed is True
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["revoke", "replace", "expire"])
async def test_peer_construction_is_revalidated_before_offer_success(
    transition: str,
):
    environment = _environment(auto_start=False)
    principal, session, ticket = _issue(environment)
    environment.fastrtc.pause_before_return = True

    async with environment.client() as client:
        request_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body(f"post-construction-{transition}"),
            )
        )
        await asyncio.wait_for(
            environment.fastrtc.offer_return_waiting.wait(),
            timeout=1,
        )
        assert environment.authority.snapshot().active_tickets == 0
        async with environment.authority.serialized_transition():
            if transition == "revoke":
                environment.authority.revoke_session(
                    principal,
                    session.session_id,
                    session.session_capability,
                )
            elif transition == "replace":
                environment.authority.create_session(principal)
            else:
                environment.clock.advance(3600)
        environment.fastrtc.offer_return_release.set()
        response = await asyncio.wait_for(request_task, timeout=1)

    assert response.status_code == 503
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert environment.fastrtc.last_peer.closed is True
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
async def test_cancel_while_waiting_for_post_offer_revalidation_cleans_peer():
    environment = _environment(auto_start=False)
    _, session, ticket = _issue(environment)
    environment.fastrtc.pause_before_return = True

    async with environment.client() as client:
        request_task = asyncio.create_task(
            client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body("cancel-post-offer-revalidation"),
            )
        )
        await asyncio.wait_for(
            environment.fastrtc.offer_return_waiting.wait(),
            timeout=1,
        )
        transition_lock = environment.authority._transition_lock
        await transition_lock.acquire()
        try:
            environment.fastrtc.offer_return_release.set()
            for _ in range(100):
                if getattr(transition_lock, "_waiters", None):
                    break
                await asyncio.sleep(0)
            assert getattr(transition_lock, "_waiters", None)
            request_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request_task
        finally:
            transition_lock.release()

    assert environment.authority.snapshot().active_tickets == 0
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}
    assert environment.fastrtc.last_peer.closed is True
    _assert_zero_application_side_effects(environment)


@pytest.mark.asyncio
async def test_runtime_change_after_session_creation_cleans_partial_session():
    environment = _environment()
    _, session, ticket = _issue(environment)

    def replace_runtime():
        environment.app.state.certificate_session_control_v1 = (
            CertificateSessionControlRuntimeV1(
                authority=environment.authority,
                access_token_validator=environment.validator,
            )
        )

    environment.handler_delegate.after_start = replace_runtime

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("runtime-change-after-session"),
        )

    assert response.status_code == 503
    assert environment.handler_delegate.session_delegates == {}
    assert environment.handler_delegate.session_admissions == {}
    assert session.session_id in environment.handler_delegate.stop_calls
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}


@pytest.mark.asyncio
async def test_controller_shutdown_closes_peer_session_and_secret_binding():
    environment = _environment()
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("shutdown-cleanup"),
        )
        assert response.status_code == 200
        await environment.controller.close()
        after_close = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers={"Authorization": f"Bearer {OWNER_ACCESS_TOKEN}"},
            json=_candidate_body("shutdown-cleanup"),
        )

    assert after_close.status_code == 503
    assert environment.controller.snapshot() == {
        "active_bindings": 0,
        "attached_sessions": 0,
    }
    assert environment.fastrtc.last_peer.closed is True
    assert environment.fastrtc.pcs == {}
    assert session.session_id in environment.handler_delegate.stop_calls


@pytest.mark.asyncio
async def test_secure_controller_owns_and_cancels_transport_timeout_tasks():
    environment = _environment(time_limit=3600)
    _, session, ticket = _issue(environment)

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("controller-owned-timeout"),
        )
    assert response.status_code == 200
    stream = environment.fastrtc.last_handler
    assert stream is not None
    internal_transport_id = stream.transport_id
    timeout_event = environment.fastrtc.connection_timeouts[internal_transport_id]
    binding = next(iter(environment.controller._bindings.values()))
    assert binding.expiry_task is None
    peer = environment.fastrtc.last_peer
    assert peer is not None
    peer.connectionState = "connected"
    for callback in peer.callbacks["connectionstatechange"]:
        callback_result = callback()
        if inspect.isawaitable(callback_result):
            await callback_result
    expiry_task = binding.expiry_task
    assert expiry_task is not None
    assert environment.fastrtc.time_limit is None

    await environment.controller.close()
    await asyncio.sleep(0)

    assert timeout_event.is_set()
    assert expiry_task.cancelled()
    assert environment.controller.snapshot()["active_bindings"] == 0
    assert environment.fastrtc.pcs == {}


@pytest.mark.asyncio
async def test_cancelled_close_caller_does_not_cancel_controller_cleanup():
    environment = _environment()
    _, session, ticket = _issue(environment)
    environment.fastrtc.pause_peer_close = True

    async with environment.client() as client:
        response = await client.post(
            RTC_SIGNALING_ROUTE_V1,
            headers=_offer_headers(
                session.session_id,
                ticket.admission_ticket,
            ),
            json=_offer_body("cancelled-controller-close"),
        )
    assert response.status_code == 200

    close_caller = asyncio.create_task(environment.controller.close())
    await asyncio.wait_for(
        environment.fastrtc.peer_close_waiting.wait(),
        timeout=1,
    )
    close_caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await close_caller

    environment.fastrtc.peer_close_release.set()
    await asyncio.wait_for(environment.controller.close(), timeout=1)

    assert environment.controller.snapshot() == {
        "active_bindings": 0,
        "attached_sessions": 0,
    }
    assert environment.handler_delegate.session_delegates == {}
    assert session.session_id in environment.handler_delegate.stop_calls
    assert environment.fastrtc.pcs == {}


@pytest.mark.asyncio
async def test_signaling_credentials_and_ice_secrets_are_not_logged(caplog):
    full_sdp = (
        "v=0\\r\\na=ice-ufrag:ice-user-canary\\r\\na=ice-pwd:ice-password-canary\\r\\n"
    )
    environment = _environment(log_signaling=True)
    _, session, ticket = _issue(environment)
    loguru_messages: list[str] = []
    sink_id = logger.add(lambda message: loguru_messages.append(str(message)))
    caplog.set_level(logging.DEBUG)

    try:
        async with environment.client() as client:
            response = await client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_offer_headers(
                    session.session_id,
                    ticket.admission_ticket,
                ),
                json=_offer_body("secret-log-transport", sdp=full_sdp),
            )
            binding = response.json()[RTC_TRANSPORT_BINDING_RESPONSE_FIELD_V1]
            candidate = await client.post(
                RTC_SIGNALING_ROUTE_V1,
                headers=_candidate_headers(binding),
                json=_candidate_body("secret-log-transport"),
            )
            logging.getLogger("fastrtc.webrtc_connection_mixin").debug(
                "Delayed peer callback %s %s",
                full_sdp,
                ticket.admission_ticket,
            )
            logging.getLogger("uvicorn.access").info(
                '%s - "%s %s HTTP/%s" %d',
                "127.0.0.1:1",
                "POST",
                (
                    f"/webrtc/offer/{OWNER_ACCESS_TOKEN}"
                    f"/{session.session_capability}"
                    f"?access_token={OWNER_ACCESS_TOKEN}"
                    f"&issuer={ISSUER}&subject={OWNER_SUBJECT}"
                    f"&ticket={ticket.admission_ticket}&sdp={full_sdp}"
                ),
                "1.1",
                400,
            )
    finally:
        logger.remove(sink_id)

    assert response.status_code == 200
    assert candidate.status_code == 200
    combined_logs = caplog.text + "\n".join(loguru_messages)
    canaries = [
        OWNER_ACCESS_TOKEN,
        session.session_capability,
        session.session_id,
        ticket.admission_ticket,
        binding,
        ISSUER,
        OWNER_SUBJECT,
        full_sdp,
        "ice-user-canary",
        "ice-password-canary",
    ]
    for canary in canaries:
        assert canary not in combined_logs


def test_turn_credentials_are_not_logged():
    messages: list[str] = []
    sink_id = logger.add(lambda message: messages.append(str(message)))
    try:
        RTCProvider().prepare_rtc_configuration(
            {
                "turn_provider": "turn_server",
                "urls": ["turn:turn.example.test"],
                "username": "turn-user-canary",
                "credential": "turn-password-canary",
            }
        )
    finally:
        logger.remove(sink_id)

    combined = "\n".join(messages)
    assert "turn-user-canary" not in combined
    assert "turn-password-canary" not in combined


def test_rtc_handler_config_repr_hides_turn_credentials():
    config = ClientRtcConfigModel(
        turn_config={
            "turn_provider": "turn_server",
            "username": "handler-turn-user-canary",
            "credential": "handler-turn-password-canary",
        }
    )

    rendered = f"{config}\n{config!r}"

    assert "handler-turn-user-canary" not in rendered
    assert "handler-turn-password-canary" not in rendered
    assert config.turn_config["username"] == "handler-turn-user-canary"
    assert config.turn_config["credential"] == "handler-turn-password-canary"


@pytest.mark.asyncio
async def test_disabled_legacy_stream_still_uses_webrtc_id_without_authority(
    monkeypatch,
):
    events: list[str] = []
    handler_delegate = RecordingHandlerDelegate(events)
    factory = RtcStream(session_id=None, stream_start_delay=0)
    factory.client_handler_delegate = handler_delegate
    stream = factory.copy()
    monkeypatch.setattr(
        "service.rtc_service.rtc_stream.get_current_context",
        lambda: SimpleNamespace(webrtc_id="legacy-webrtc-session"),
    )

    await stream.start_up()

    assert stream.session_id == "legacy-webrtc-session"
    assert stream.transport_id is None
    assert stream.session_admission is None
    assert handler_delegate.effects.delegate_starts == 1
    assert handler_delegate.session_admissions.get("legacy-webrtc-session") is None


def test_manager_data_tool_route_is_not_an_rtc_session_creation_bypass():
    source = inspect.getsource(ManagerDataToolService.register_routes)
    assert '"/ws/manager/data_tool"' in source
    assert "ClientHandlerDelegate" not in source
    assert "start_session" not in source
    assert "find_session_delegate" not in source
    assert "RtcStream" not in source

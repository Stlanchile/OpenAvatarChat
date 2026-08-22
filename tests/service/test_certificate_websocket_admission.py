from __future__ import annotations

import asyncio
import base64
import io
import json
import sys
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from loguru import logger
from starlette.datastructures import Headers
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocketState

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from chat_engine.common.client_handler_base import ClientHandlerDelegate
from chat_engine.contexts.session_context import SessionContext
from chat_engine.data_models.session_info_data import SessionInfoData
from handlers.client.ws_client.ws_session_endpoint import (
    register_ws_session_endpoint,
)
from service.service_security.certificate_session_authority import (
    CertificateSessionAuthorityV1,
    ConsumedSessionAdmissionV1,
    SessionAdmissionChannelV1,
    SessionAuthorityErrorV1,
    SessionAuthorityReasonV1,
)
from service.service_security.certificate_session_control import (
    CertificateSessionControlRuntimeV1,
)
from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
)
from service.service_security.websocket_session_admission import (
    WEBSOCKET_ADMISSION_PROTOCOL_MAX_HEADER_CHARACTERS_V1,
    WEBSOCKET_ADMISSION_PROTOCOL_MAX_TOKEN_COUNT_V1,
    WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1,
    WebSocketAdmissionErrorV1,
    WebSocketAdmissionReasonV1,
    parse_websocket_admission_protocol_v1,
)

NOW = 2_000_000_000
ISSUER = "https://issuer.example.test"
SESSION_ROUTE = "/ws/session/{session_id}"


@dataclass
class FakeClock:
    wall: float = float(NOW)
    monotonic: float = 50_000.0

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.monotonic += seconds


@dataclass
class SideEffectCounts:
    delegate_creation: int = 0
    chat_session_creation: int = 0
    session_context_creation: int = 0
    handler_initialization: int = 0
    history_initialization: int = 0
    application_messages: int = 0


class RecordingSessionDelegate:
    def __init__(self, events: list[str], side_effects: SideEffectCounts):
        self._events = events
        self._side_effects = side_effects

    async def serve_websocket(self, _websocket) -> bool:
        self._events.append("application_serve")
        self._side_effects.application_messages += 1
        return False


class RecordingHandlerDelegate:
    def __init__(
        self,
        *,
        events: list[str] | None = None,
        fail_start: bool = False,
    ):
        self.events = events if events is not None else []
        self.fail_start = fail_start
        self.side_effects = SideEffectCounts()
        self.session_delegates: dict[str, RecordingSessionDelegate] = {}
        self.session_admissions: dict[str, ConsumedSessionAdmissionV1] = {}
        self.stop_calls: list[str] = []

    def find_session_delegate(self, session_id: str):
        self.events.append("delegate_lookup")
        return self.session_delegates.get(session_id)

    def start_session(
        self,
        session_id: str,
        *,
        session_admission: ConsumedSessionAdmissionV1 | None = None,
    ):
        self.events.append("delegate_start")
        self.side_effects.delegate_creation += 1
        self.side_effects.chat_session_creation += 1
        self.side_effects.session_context_creation += 1
        self.side_effects.handler_initialization += 1
        self.side_effects.history_initialization += 1
        if self.fail_start:
            raise RuntimeError("start failure canary")
        delegate = RecordingSessionDelegate(self.events, self.side_effects)
        self.session_delegates[session_id] = delegate
        if session_admission is not None:
            self.session_admissions[session_id] = session_admission
        return delegate

    def find_session_admission(self, session_id: str):
        self.events.append("session_admission_lookup")
        return self.session_admissions.get(session_id)

    def stop_session(self, session_id: str) -> None:
        self.events.append("delegate_stop")
        self.stop_calls.append(session_id)
        self.session_delegates.pop(session_id, None)
        self.session_admissions.pop(session_id, None)


class FakeWebSocket:
    def __init__(
        self,
        *,
        protocol_values: list[str] | None = None,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
        query_string: bytes = b"",
        events: list[str] | None = None,
        accept_error: Exception | None = None,
        denial_supported: bool = True,
        accept_entered: asyncio.Event | None = None,
        accept_release: asyncio.Event | None = None,
    ):
        raw_headers = list(extra_headers or [])
        for value in protocol_values or []:
            raw_headers.append(
                (b"sec-websocket-protocol", value.encode("latin-1"))
            )
        self.headers = Headers(raw=raw_headers)
        self.scope = {
            "type": "websocket",
            "headers": raw_headers,
            "query_string": query_string,
            "extensions": {"websocket.http.response": {}},
        }
        self.events = events if events is not None else []
        self.accept_error = accept_error
        self.denial_supported = denial_supported
        self.accept_entered = accept_entered
        self.accept_release = accept_release
        self.client_state = WebSocketState.CONNECTING
        self.accepted_subprotocol: str | None = None
        self.denial_status: int | None = None
        self.denial_body: dict[str, str] | None = None
        self.denial_headers: dict[str, str] = {}
        self.close_code: int | None = None
        self.close_reason: str | None = None

    async def accept(self, subprotocol=None, headers=None) -> None:
        del headers
        self.events.append("websocket_accept")
        self.accepted_subprotocol = subprotocol
        if self.accept_entered is not None:
            self.accept_entered.set()
        if self.accept_release is not None:
            await self.accept_release.wait()
        if self.accept_error is not None:
            raise self.accept_error
        self.client_state = WebSocketState.CONNECTED

    async def send_denial_response(self, response) -> None:
        if not self.denial_supported:
            raise RuntimeError("denial extension unavailable")
        self.events.append("handshake_denied")
        self.denial_status = response.status_code
        self.denial_body = json.loads(response.body)
        self.denial_headers = dict(response.headers)
        self.client_state = WebSocketState.DISCONNECTED

    async def close(self, code=1000, reason=None) -> None:
        self.events.append("websocket_close")
        self.close_code = code
        self.close_reason = reason
        self.client_state = WebSocketState.DISCONNECTED


class RecordingAuthority:
    def __init__(
        self,
        authority: CertificateSessionAuthorityV1,
        events: list[str],
    ):
        self._authority = authority
        self._events = events

    def serialized_transition(self):
        return self._authority.serialized_transition()

    def consume_websocket_admission_ticket(
        self,
        session_id: str,
        admission_ticket: str,
    ) -> ConsumedSessionAdmissionV1:
        self._events.append("ticket_consume")
        return self._authority.consume_websocket_admission_ticket(
            session_id,
            admission_ticket,
        )


class FailingAuthority:
    def __init__(self, error: Exception):
        self._error = error
        self._transition_authority = _authority()

    def serialized_transition(self):
        return self._transition_authority.serialized_transition()

    def consume_websocket_admission_ticket(
        self,
        _session_id: str,
        _admission_ticket: str,
    ) -> ConsumedSessionAdmissionV1:
        raise self._error


def _principal(
    *,
    issuer: str = ISSUER,
    subject: str = "owner",
    token_expiry: int = NOW + 3600,
) -> AuthenticatedPrincipalV1:
    return AuthenticatedPrincipalV1(
        issuer=issuer,
        subject=subject,
        scopes=frozenset({"certificate:capture"}),
        token_expiry_epoch_seconds=token_expiry,
    )


def _authority(
    clock: FakeClock | None = None,
) -> CertificateSessionAuthorityV1:
    effective_clock = clock or FakeClock()
    return CertificateSessionAuthorityV1(
        wall_clock=lambda: effective_clock.wall,
        monotonic_clock=lambda: effective_clock.monotonic,
    )


def _issue_ticket(
    authority: CertificateSessionAuthorityV1,
    *,
    principal: AuthenticatedPrincipalV1 | None = None,
    channel: SessionAdmissionChannelV1 = SessionAdmissionChannelV1.WEBSOCKET,
):
    owner = principal or _principal()
    session = authority.create_session(owner)
    ticket = authority.issue_admission_ticket(
        owner,
        session.session_id,
        session.session_capability,
        channel,
    )
    return owner, session, ticket


def _protocol(admission_ticket: str) -> str:
    return WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1 + admission_ticket


def _canonical_random_ticket(seed: int = 73) -> str:
    entropy = bytes([seed]) * 32
    encoded = base64.urlsafe_b64encode(entropy).rstrip(b"=").decode("ascii")
    return "att1_" + encoded


def _register_endpoint(
    handler_delegate: RecordingHandlerDelegate,
    *,
    authority: object | None,
) -> tuple[FastAPI, object]:
    app = FastAPI(docs_url=None, redoc_url=None)
    if authority is not None:
        app.state.certificate_session_control_v1 = (
            CertificateSessionControlRuntimeV1(
                authority=authority,
                access_token_validator=object(),
            )
        )
    register_ws_session_endpoint(
        app,
        handler_delegate,
        RecordingSessionDelegate,
    )
    route = next(
        route
        for route in app.routes
        if isinstance(route, WebSocketRoute) and route.path == SESSION_ROUTE
    )
    return app, route.endpoint


def _assert_denial(
    websocket: FakeWebSocket,
    *,
    status_code: int,
    reason: WebSocketAdmissionReasonV1,
) -> None:
    assert websocket.denial_status == status_code
    assert websocket.denial_body == {"reason_code": reason.value}
    assert websocket.denial_headers["cache-control"] == "no-store"
    assert "websocket_accept" not in websocket.events


def _assert_zero_application_side_effects(
    handler_delegate: RecordingHandlerDelegate,
) -> None:
    assert handler_delegate.side_effects == SideEffectCounts()
    assert "delegate_lookup" not in handler_delegate.events
    assert "delegate_start" not in handler_delegate.events
    assert "application_serve" not in handler_delegate.events


async def _run_asgi_websocket(
    app: FastAPI,
    session_id: str,
    *,
    protocol: str | None,
) -> list[dict[str, object]]:
    path = f"/ws/session/{session_id}"
    headers = [(b"host", b"service.example.test")]
    if protocol is not None:
        headers.append(
            (b"sec-websocket-protocol", protocol.encode("latin-1"))
        )
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "scheme": "wss",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("service.example.test", 443),
        "subprotocols": [protocol] if protocol is not None else [],
        "extensions": {"websocket.http.response": {}},
    }
    incoming = [{"type": "websocket.connect"}]
    sent: list[dict[str, object]] = []

    async def receive():
        if incoming:
            return incoming.pop(0)
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


@pytest.mark.asyncio
async def test_valid_admission_is_consumed_and_attached_before_accept():
    events: list[str] = []
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    recording_authority = RecordingAuthority(authority, events)
    handler_delegate = RecordingHandlerDelegate(events=events)
    _, endpoint = _register_endpoint(
        handler_delegate,
        authority=recording_authority,
    )
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)],
        events=events,
    )

    await endpoint(websocket, session.session_id)

    assert events[:5] == [
        "ticket_consume",
        "delegate_lookup",
        "delegate_start",
        "websocket_accept",
        "application_serve",
    ]
    assert websocket.accepted_subprotocol is None
    assert authority.snapshot().active_tickets == 0
    admission = handler_delegate.session_admissions[session.session_id]
    assert admission.session_id == session.session_id
    assert admission.ticket_id == ticket.ticket_id
    assert admission.channel is SessionAdmissionChannelV1.WEBSOCKET
    assert handler_delegate.side_effects == SideEffectCounts(
        delegate_creation=1,
        chat_session_creation=1,
        session_context_creation=1,
        handler_initialization=1,
        history_initialization=1,
        application_messages=1,
    )


@pytest.mark.asyncio
async def test_real_asgi_handshake_denial_does_not_emit_websocket_accept():
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    app, _ = _register_endpoint(handler_delegate, authority=authority)

    sent = await _run_asgi_websocket(
        app,
        "cs1_" + "A" * 43,
        protocol=None,
    )

    assert [message["type"] for message in sent] == [
        "websocket.http.response.start",
        "websocket.http.response.body",
    ]
    assert sent[0]["status"] == 400
    assert b"WEBSOCKET_ADMISSION_PROTOCOL_REQUIRED" in sent[1]["body"]
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_real_asgi_valid_handshake_accepts_without_echoing_ticket():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    app, _ = _register_endpoint(handler_delegate, authority=authority)

    sent = await _run_asgi_websocket(
        app,
        session.session_id,
        protocol=_protocol(ticket.admission_ticket),
    )

    assert sent[0]["type"] == "websocket.accept"
    assert sent[0].get("subprotocol") is None
    assert ticket.admission_ticket not in repr(sent)
    assert sent[-1]["type"] == "websocket.close"
    assert authority.snapshot().active_tickets == 0


@pytest.mark.asyncio
async def test_runtime_installed_after_route_registration_enables_admission():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    app, endpoint = _register_endpoint(handler_delegate, authority=None)
    app.state.certificate_session_control_v1 = (
        CertificateSessionControlRuntimeV1(
            authority=authority,
            access_token_validator=object(),
        )
    )
    missing_protocol = FakeWebSocket()

    await endpoint(missing_protocol, session.session_id)

    _assert_denial(
        missing_protocol,
        status_code=400,
        reason=WebSocketAdmissionReasonV1.PROTOCOL_REQUIRED,
    )
    _assert_zero_application_side_effects(handler_delegate)

    await endpoint(
        FakeWebSocket(
            protocol_values=[_protocol(ticket.admission_ticket)]
        ),
        session.session_id,
    )
    assert session.session_id in handler_delegate.session_delegates


@pytest.mark.asyncio
@pytest.mark.parametrize("control_operation", ["revoke", "replace"])
async def test_accept_transition_linearizes_revoke_and_replacement_races(
    control_operation: str,
):
    authority = _authority()
    principal, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    accept_entered = asyncio.Event()
    accept_release = asyncio.Event()
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)],
        accept_entered=accept_entered,
        accept_release=accept_release,
    )
    connection_task = asyncio.create_task(
        endpoint(websocket, session.session_id)
    )
    await asyncio.wait_for(accept_entered.wait(), timeout=1)

    with pytest.raises(SessionAuthorityErrorV1) as direct_attempt:
        if control_operation == "revoke":
            authority.revoke_session(
                principal,
                session.session_id,
                session.session_capability,
            )
        else:
            authority.create_session(principal)
    assert direct_attempt.value.reason_code == (
        SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE.value
    )

    async def serialized_control_operation():
        async with authority.serialized_transition():
            if control_operation == "revoke":
                authority.revoke_session(
                    principal,
                    session.session_id,
                    session.session_capability,
                )
                return None
            return authority.create_session(principal)

    control_task = asyncio.create_task(serialized_control_operation())
    await asyncio.sleep(0)
    assert not control_task.done()

    accept_release.set()
    await asyncio.wait_for(connection_task, timeout=1)
    control_result = await asyncio.wait_for(control_task, timeout=1)

    assert "websocket_accept" in websocket.events
    if control_operation == "replace":
        assert control_result.session_id != session.session_id


@pytest.mark.asyncio
async def test_reconnection_requires_new_ticket_and_attaches_same_secure_session():
    authority = _authority()
    principal, session, first_ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)

    await endpoint(
        FakeWebSocket(
            protocol_values=[_protocol(first_ticket.admission_ticket)]
        ),
        session.session_id,
    )
    second_ticket = authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    starts_before = handler_delegate.side_effects.delegate_creation

    await endpoint(
        FakeWebSocket(
            protocol_values=[_protocol(second_ticket.admission_ticket)]
        ),
        session.session_id,
    )

    assert handler_delegate.side_effects.delegate_creation == starts_before
    assert "session_admission_lookup" in handler_delegate.events
    assert authority.snapshot().active_tickets == 0


def test_trusted_admission_reaches_session_context_as_server_owned_state():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    admission = authority.consume_websocket_admission_ticket(
        session.session_id,
        ticket.admission_ticket,
    )

    context = SessionContext(
        SessionInfoData(session_id=session.session_id),
        session_admission=admission,
    )

    assert context.session_admission is admission
    assert context.session_info.session_id == admission.session_id


def test_client_handler_delegate_forwards_trusted_admission_to_engine_creation():
    authority = _authority()
    _, session_grant, ticket = _issue_ticket(authority)
    admission = authority.consume_websocket_admission_ticket(
        session_grant.session_id,
        ticket.admission_ticket,
    )
    events: list[object] = []

    class Delegate:
        pass

    class Handler:
        def on_setup_session_delegate(
            self,
            session_context,
            handler_context,
            session_delegate,
        ):
            events.append(
                (
                    "delegate_setup",
                    session_context,
                    handler_context,
                    session_delegate,
                )
            )

    class Session:
        session_context = object()

        def start(self):
            events.append("session_start")

    handler = Handler()
    handler_env = SimpleNamespace(
        handler_info=SimpleNamespace(
            client_session_delegate_class=Delegate,
            handler_name="test-client",
        ),
        handler=handler,
        context=object(),
    )

    class Engine:
        def __init__(self):
            self.sessions = {}

        def create_client_session(
            self,
            session_info,
            client_handler,
            *,
            session_admission=None,
        ):
            events.append(
                (
                    "engine_create",
                    session_info.session_id,
                    client_handler,
                    session_admission,
                )
            )
            return Session(), handler_env

    engine = Engine()
    delegate = ClientHandlerDelegate(weakref.ref(engine), handler)

    created = delegate.start_session(
        session_grant.session_id,
        session_admission=admission,
    )

    assert isinstance(created, Delegate)
    assert events[0] == (
        "engine_create",
        session_grant.session_id,
        handler,
        admission,
    )
    assert events[1] == "session_start"
    assert events[2][0] == "delegate_setup"


@pytest.mark.asyncio
async def test_guessed_session_id_and_random_ticket_are_denied_without_side_effects():
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(_canonical_random_ticket())]
    )

    await endpoint(websocket, "cs1_" + "A" * 43)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_valid_ticket_with_wrong_session_path_is_denied_and_not_consumed():
    authority = _authority()
    owner, owner_session, ticket = _issue_ticket(authority)
    other_session = authority.create_session(_principal(subject="other"))
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, other_session.session_id)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    _assert_zero_application_side_effects(handler_delegate)
    assert (
        authority.consume_admission_ticket(
            owner,
            owner_session.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        ).ticket_id
        == ticket.ticket_id
    )


@pytest.mark.asyncio
async def test_valid_ticket_cannot_attach_to_legacy_unadmitted_session_delegate():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    handler_delegate.session_delegates[session.session_id] = (
        RecordingSessionDelegate(
            handler_delegate.events,
            handler_delegate.side_effects,
        )
    )
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, session.session_id)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    assert handler_delegate.side_effects.application_messages == 0
    assert "websocket_accept" not in websocket.events
    assert authority.snapshot().active_tickets == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("lifecycle_case", ["revoked", "replaced", "expired"])
async def test_non_live_owned_session_is_denied_before_application_state(
    lifecycle_case: str,
):
    clock = FakeClock()
    authority = _authority(clock)
    principal = _principal(
        token_expiry=NOW + 30 if lifecycle_case == "expired" else NOW + 3600
    )
    principal, session, ticket = _issue_ticket(
        authority,
        principal=principal,
    )
    if lifecycle_case == "revoked":
        authority.revoke_session(
            principal,
            session.session_id,
            session.session_capability,
        )
    elif lifecycle_case == "replaced":
        authority.create_session(principal)
    else:
        clock.advance(30)

    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, session.session_id)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_session_revoked_between_ticket_issue_and_connection_is_denied():
    authority = _authority()
    principal, session, ticket = _issue_ticket(authority)
    authority.revoke_session(
        principal,
        session.session_id,
        session.session_capability,
    )
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, session.session_id)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_malformed_ticket_encoding_is_a_protocol_error():
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[
            WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1 + "att1_not-canonical"
        ]
    )

    await endpoint(websocket, "cs1_" + "A" * 43)

    _assert_denial(
        websocket,
        status_code=400,
        reason=WebSocketAdmissionReasonV1.PROTOCOL_INVALID,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_expired_ticket_is_denied_before_delegate_lookup():
    clock = FakeClock()
    authority = _authority(clock)
    _, session, ticket = _issue_ticket(authority)
    clock.advance(60)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, session.session_id)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_replayed_ticket_and_second_handshake_are_denied():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)

    await endpoint(
        FakeWebSocket(
            protocol_values=[_protocol(ticket.admission_ticket)]
        ),
        session.session_id,
    )
    side_effects_after_first = SideEffectCounts(
        **vars(handler_delegate.side_effects)
    )
    replay = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(replay, session.session_id)

    _assert_denial(
        replay,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    assert handler_delegate.side_effects == side_effects_after_first


@pytest.mark.asyncio
async def test_wrong_channel_ticket_is_denied_and_remains_channel_bound():
    authority = _authority()
    principal, session, ticket = _issue_ticket(
        authority,
        channel=SessionAdmissionChannelV1.RTC,
    )
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, session.session_id)

    _assert_denial(
        websocket,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )
    _assert_zero_application_side_effects(handler_delegate)
    assert (
        authority.consume_admission_ticket(
            principal,
            session.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.RTC,
        ).ticket_id
        == ticket.ticket_id
    )


def test_concurrent_websocket_ticket_consumption_allows_one_winner():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)

    def consume() -> str:
        try:
            authority.consume_websocket_admission_ticket(
                session.session_id,
                ticket.admission_ticket,
            )
        except SessionAuthorityErrorV1 as exception:
            return exception.reason_code
        return "SUCCESS"

    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(lambda _: consume(), range(64)))

    assert outcomes.count("SUCCESS") == 1
    assert (
        outcomes.count(SessionAuthorityReasonV1.TICKET_ACCESS_DENIED.value)
        == 63
    )


@pytest.mark.asyncio
async def test_aborted_accept_does_not_restore_ticket_or_leave_new_session():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    aborted = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)],
        accept_error=RuntimeError("transport-aborted-canary"),
    )

    await endpoint(aborted, session.session_id)

    assert authority.snapshot().active_tickets == 0
    assert handler_delegate.stop_calls == [session.session_id]
    assert session.session_id not in handler_delegate.session_delegates
    replay = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )
    await endpoint(replay, session.session_id)
    _assert_denial(
        replay,
        status_code=403,
        reason=WebSocketAdmissionReasonV1.ADMISSION_DENIED,
    )


@pytest.mark.asyncio
async def test_cancelled_accept_releases_transition_and_keeps_ticket_consumed():
    authority = _authority()
    principal, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    accept_entered = asyncio.Event()
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)],
        accept_entered=accept_entered,
        accept_release=asyncio.Event(),
    )
    connection_task = asyncio.create_task(
        endpoint(websocket, session.session_id)
    )
    await asyncio.wait_for(accept_entered.wait(), timeout=1)

    connection_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await connection_task

    assert authority.snapshot().active_tickets == 0
    assert handler_delegate.stop_calls == [session.session_id]
    replacement_ticket = authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    await endpoint(
        FakeWebSocket(
            protocol_values=[_protocol(replacement_ticket.admission_ticket)]
        ),
        session.session_id,
    )
    assert session.session_id in handler_delegate.session_delegates


@pytest.mark.asyncio
async def test_post_consume_session_creation_failure_fails_closed_pre_accept():
    authority = _authority()
    _, session, ticket = _issue_ticket(authority)
    handler_delegate = RecordingHandlerDelegate(fail_start=True)
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(ticket.admission_ticket)]
    )

    await endpoint(websocket, session.session_id)

    _assert_denial(
        websocket,
        status_code=503,
        reason=WebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE,
    )
    assert authority.snapshot().active_tickets == 0
    assert handler_delegate.stop_calls == [session.session_id]
    assert handler_delegate.side_effects.application_messages == 0


@pytest.mark.asyncio
async def test_missing_admission_protocol_is_rejected():
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket()

    await endpoint(websocket, "cs1_" + "A" * 43)

    _assert_denial(
        websocket,
        status_code=400,
        reason=WebSocketAdmissionReasonV1.PROTOCOL_REQUIRED,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "protocol_values",
    [
        [""],
        ["not-the-admission-protocol"],
        [" oac.cert-admission.v1.att1_" + "A" * 43],
        ["oac.cert-admission.v1.att1_" + "A" * 43 + " "],
        ["oac.cert-admission.v1.att1_" + "A" * 42 + "="],
        ["oac.cert-admission.v1.att1_" + "é" * 43],
        ["x" * (WEBSOCKET_ADMISSION_PROTOCOL_MAX_HEADER_CHARACTERS_V1 + 1)],
        [
            ",".join(
                ["token"]
                * (WEBSOCKET_ADMISSION_PROTOCOL_MAX_TOKEN_COUNT_V1 + 1)
            )
        ],
    ],
)
async def test_malformed_oversized_excessive_or_unexpected_protocol_is_rejected(
    protocol_values: list[str],
):
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(protocol_values=protocol_values)

    await endpoint(websocket, "cs1_" + "A" * 43)

    _assert_denial(
        websocket,
        status_code=400,
        reason=WebSocketAdmissionReasonV1.PROTOCOL_INVALID,
    )
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_duplicate_and_conflicting_admission_protocols_are_rejected():
    authority = _authority()
    _, session, first = _issue_ticket(authority)
    principal = _principal()
    second = authority.issue_admission_ticket(
        principal,
        session.session_id,
        session.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    cases = [
        [_protocol(first.admission_ticket), _protocol(first.admission_ticket)],
        [_protocol(first.admission_ticket), _protocol(second.admission_ticket)],
        [
            _protocol(first.admission_ticket)
            + ","
            + _protocol(first.admission_ticket)
        ],
        [
            _protocol(first.admission_ticket)
            + ","
            + _protocol(second.admission_ticket)
        ],
    ]

    for protocol_values in cases:
        handler_delegate = RecordingHandlerDelegate()
        _, endpoint = _register_endpoint(
            handler_delegate,
            authority=authority,
        )
        websocket = FakeWebSocket(protocol_values=protocol_values)
        await endpoint(websocket, session.session_id)
        _assert_denial(
            websocket,
            status_code=400,
            reason=WebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        )
        _assert_zero_application_side_effects(handler_delegate)

    assert authority.snapshot().active_tickets == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("extra_headers", "query_string"),
    [
        ([], b"admission_ticket=att1_query-canary"),
        ([], b"access_token=bearer-url-canary"),
        (
            [(b"authorization", b"Bearer att1_authorization-canary")],
            b"",
        ),
        (
            [(b"x-certificate-admission-ticket", b"att1_header-canary")],
            b"",
        ),
        (
            [(b"cookie", b"admission_ticket=att1_cookie-canary")],
            b"",
        ),
    ],
)
async def test_non_protocol_credential_transports_are_not_fallbacks(
    extra_headers: list[tuple[bytes, bytes]],
    query_string: bytes,
):
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        extra_headers=extra_headers,
        query_string=query_string,
    )

    await endpoint(websocket, "cs1_" + "A" * 43)

    _assert_denial(
        websocket,
        status_code=400,
        reason=WebSocketAdmissionReasonV1.PROTOCOL_REQUIRED,
    )
    _assert_zero_application_side_effects(handler_delegate)


def test_parser_objects_and_errors_have_secret_free_representations():
    ticket = _canonical_random_ticket()
    parsed = parse_websocket_admission_protocol_v1(
        FakeWebSocket(protocol_values=[_protocol(ticket)])
    )

    assert ticket not in repr(parsed)
    with pytest.raises(WebSocketAdmissionErrorV1) as raised:
        parse_websocket_admission_protocol_v1(
            FakeWebSocket(protocol_values=["malformed-header-canary"])
        )
    assert "malformed-header-canary" not in repr(raised.value)
    assert raised.value.reason_code == (
        WebSocketAdmissionReasonV1.PROTOCOL_INVALID.value
    )


@pytest.mark.asyncio
async def test_secret_canaries_never_reach_logs_errors_or_denial_bodies():
    issuer_canary = "https://issuer.secret-canary.test"
    subject_canary = "subject-secret-canary"
    access_token_canary = "access-token-secret-canary"
    authority = _authority()
    principal, session, ticket = _issue_ticket(
        authority,
        principal=_principal(
            issuer=issuer_canary,
            subject=subject_canary,
        ),
    )
    capability_canary = session.session_capability
    raw_admission_header = _protocol(ticket.admission_ticket)
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    log_output = io.StringIO()
    sink_id = logger.add(log_output, format="{message}")
    try:
        await endpoint(
            FakeWebSocket(
                protocol_values=[raw_admission_header],
                extra_headers=[
                    (
                        b"authorization",
                        f"Bearer {access_token_canary}".encode("ascii"),
                    ),
                    (
                        b"x-certificate-session-capability",
                        capability_canary.encode("ascii"),
                    ),
                ],
                query_string=(
                    f"access_token={access_token_canary}".encode("ascii")
                ),
            ),
            session.session_id,
        )
        replay = FakeWebSocket(
            protocol_values=[raw_admission_header],
            extra_headers=[
                (b"x-access-token", access_token_canary.encode("ascii"))
            ],
        )
        await endpoint(replay, session.session_id)
    finally:
        logger.remove(sink_id)

    assert principal.issuer == issuer_canary
    visible = log_output.getvalue() + json.dumps(replay.denial_body)
    for canary in (
        ticket.admission_ticket,
        capability_canary,
        access_token_canary,
        issuer_canary,
        subject_canary,
        raw_admission_header,
    ):
        assert canary not in visible


@pytest.mark.asyncio
async def test_authority_failure_is_secret_free_and_fails_closed():
    failure_canary = "authority-internal-secret-canary"
    authority = FailingAuthority(RuntimeError(failure_canary))
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(
        protocol_values=[_protocol(_canonical_random_ticket())]
    )
    log_output = io.StringIO()
    sink_id = logger.add(log_output, format="{message}")
    try:
        await endpoint(websocket, "cs1_" + "A" * 43)
    finally:
        logger.remove(sink_id)

    _assert_denial(
        websocket,
        status_code=503,
        reason=WebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE,
    )
    _assert_zero_application_side_effects(handler_delegate)
    assert failure_canary not in log_output.getvalue()
    assert failure_canary not in json.dumps(websocket.denial_body)


@pytest.mark.asyncio
async def test_denial_falls_back_to_pre_accept_close_without_upgrade():
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)
    websocket = FakeWebSocket(denial_supported=False)

    await endpoint(websocket, "cs1_" + "A" * 43)

    assert websocket.close_code == 1008
    assert websocket.close_reason == (
        WebSocketAdmissionReasonV1.PROTOCOL_REQUIRED.value
    )
    assert "websocket_accept" not in websocket.events
    _assert_zero_application_side_effects(handler_delegate)


@pytest.mark.asyncio
async def test_disabled_mode_preserves_accept_first_legacy_contract(
    monkeypatch,
):
    events: list[str] = []
    consume_ticket = Mock(
        side_effect=AssertionError(
            "disabled mode must not invoke certificate session authority"
        )
    )
    monkeypatch.setattr(
        CertificateSessionAuthorityV1,
        "consume_websocket_admission_ticket",
        consume_ticket,
    )
    handler_delegate = RecordingHandlerDelegate(events=events)
    _, endpoint = _register_endpoint(handler_delegate, authority=None)
    legacy_session_id = "legacy-client-selected-session"
    websocket = FakeWebSocket(
        events=events,
        query_string=b"admission_ticket=ignored-in-disabled-mode",
        extra_headers=[
            (b"x-certificate-admission-ticket", b"ignored-legacy-header")
        ],
    )

    await endpoint(websocket, legacy_session_id)

    assert events[:4] == [
        "websocket_accept",
        "delegate_lookup",
        "delegate_start",
        "application_serve",
    ]
    assert websocket.accepted_subprotocol is None
    assert legacy_session_id in handler_delegate.session_delegates
    consume_ticket.assert_not_called()


@pytest.mark.asyncio
async def test_failed_enabled_admission_has_zero_all_named_side_effect_seams():
    authority = _authority()
    handler_delegate = RecordingHandlerDelegate()
    _, endpoint = _register_endpoint(handler_delegate, authority=authority)

    await endpoint(FakeWebSocket(), "client-controlled-session")

    _assert_zero_application_side_effects(handler_delegate)
    assert handler_delegate.side_effects.delegate_creation == 0
    assert handler_delegate.side_effects.chat_session_creation == 0
    assert handler_delegate.side_effects.session_context_creation == 0
    assert handler_delegate.side_effects.handler_initialization == 0
    assert handler_delegate.side_effects.history_initialization == 0
    assert handler_delegate.side_effects.application_messages == 0


def test_both_websocket_handler_variants_mount_the_same_gated_route(
    monkeypatch,
):
    from handlers.client.ws_client import ws_client_handler
    from handlers.client.ws_lam_client.ws_lam_client_handler import (
        WsLamClientHandler,
    )

    authority = _authority()

    standard_app = FastAPI(docs_url=None, redoc_url=None)
    standard_app.state.certificate_session_control_v1 = (
        CertificateSessionControlRuntimeV1(
            authority=authority,
            access_token_validator=object(),
        )
    )
    monkeypatch.setattr(
        ws_client_handler,
        "register_frontend",
        lambda **_kwargs: None,
    )
    standard_handler = ws_client_handler.WsClientHandler()
    standard_handler.on_setup_app(standard_app, None)

    lam_app = FastAPI(docs_url=None, redoc_url=None)
    lam_app.state.certificate_session_control_v1 = (
        CertificateSessionControlRuntimeV1(
            authority=authority,
            access_token_validator=object(),
        )
    )
    lam_handler = WsLamClientHandler()
    lam_handler._register_ws_session_endpoint(lam_app)

    for app in (standard_app, lam_app):
        websocket_routes = [
            route.path
            for route in app.routes
            if isinstance(route, WebSocketRoute)
        ]
        assert websocket_routes == [SESSION_ROUTE]


def test_repository_direct_websocket_routes_are_explicitly_enumerated():
    direct_decorators: dict[str, list[str]] = {}
    excluded_root = SRC_ROOT / "service" / "frontend_service" / "frontend"
    for path in SRC_ROOT.rglob("*.py"):
        if excluded_root in path.parents:
            continue
        decorator_lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("@app.websocket(")
        ]
        if decorator_lines:
            direct_decorators[str(path.relative_to(PROJECT_ROOT))] = (
                decorator_lines
            )

    assert direct_decorators == {
        "src/handlers/client/ws_client/ws_session_endpoint.py": [
            "@app.websocket(_SESSION_WEBSOCKET_ROUTE_V1)"
        ],
        "src/service/manager_service/data_tool_service.py": [
            '@app.websocket("/ws/manager/data_tool")'
        ],
    }

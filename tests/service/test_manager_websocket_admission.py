from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocketState

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from service.manager_service.data_tool_service import ManagerDataToolService
from service.service_security.manager_authorization import (
    MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1,
    ManagerAuthorizationRuntimeV1,
)
from service.service_security.manager_websocket_admission import (
    MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1,
    ManagerWebSocketAdmissionReasonV1,
)
from service.service_security.manager_websocket_authority import (
    MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1,
    ManagerWebSocketTicketAuthorityV1,
)
from service.service_security.oidc_resource_server import (
    OIDC_MANAGER_SCOPE_V1,
    AuthenticatedPrincipalV1,
)

NOW = 2_000_000_000.0
MANAGER_ROUTE = "/ws/manager/data_tool"


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


class RecordingManagerDataToolService(ManagerDataToolService):
    def __init__(self, events: list[str]):
        super().__init__()
        self.events = events
        self.sender_starts = 0
        self.receiver_starts = 0
        self.queue_counts_at_task_start: list[int] = []
        self.tasks_started = asyncio.Event()

    async def _wait_for_peer_task(self) -> None:
        if self.sender_starts + self.receiver_starts == 2:
            self.tasks_started.set()
        await self.tasks_started.wait()

    async def _sender_loop(self, websocket, queue):
        del websocket, queue
        self.sender_starts += 1
        self.queue_counts_at_task_start.append(len(self._queues))
        self.events.append("sender_started")
        await self._wait_for_peer_task()

    async def _receiver_loop(self, websocket):
        del websocket
        self.receiver_starts += 1
        self.queue_counts_at_task_start.append(len(self._queues))
        self.events.append("receiver_started")
        await self._wait_for_peer_task()


class RecordingManagerAuthority(ManagerWebSocketTicketAuthorityV1):
    def __init__(
        self,
        service: RecordingManagerDataToolService,
        events: list[str],
        clock: FakeClock,
    ):
        super().__init__(
            wall_clock=clock.wall_time,
            monotonic_clock=clock.monotonic_time,
        )
        self.service = service
        self.events = events

    def consume(self, admission_ticket):
        self.events.append("ticket_consume")
        assert self.service._queues == set()
        return super().consume(admission_ticket)


def _principal() -> AuthenticatedPrincipalV1:
    return AuthenticatedPrincipalV1(
        issuer="https://issuer.example.test",
        subject="manager",
        scopes=frozenset({OIDC_MANAGER_SCOPE_V1}),
        token_expiry_epoch_seconds=NOW + 3600,
    )


def _manager_protocol(ticket: str) -> str:
    return MANAGER_WEBSOCKET_ADMISSION_PROTOCOL_PREFIX_V1 + ticket


def _endpoint(app: FastAPI):
    return next(
        route.endpoint
        for route in app.routes
        if isinstance(route, WebSocketRoute) and route.path == MANAGER_ROUTE
    )


def _install_enabled_route(
    *,
    clock: FakeClock | None = None,
) -> tuple[
    FastAPI,
    RecordingManagerDataToolService,
    RecordingManagerAuthority,
    object,
]:
    events: list[str] = []
    service = RecordingManagerDataToolService(events)
    active_clock = clock or FakeClock()
    authority = RecordingManagerAuthority(service, events, active_clock)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.certificate_capture_enabled_v1 = True
    app.state.manager_authorization_v1 = ManagerAuthorizationRuntimeV1(
        ticket_authority=authority,
        access_token_validator=object(),
    )
    service.register_routes(app)
    return app, service, authority, _endpoint(app)


@pytest.mark.asyncio
async def test_valid_manager_ticket_is_consumed_before_accept_queue_and_tasks():
    app, service, authority, endpoint = _install_enabled_route()
    del app
    grant = authority.issue(_principal())
    websocket = FakeWebSocket(
        protocol_values=[_manager_protocol(grant.admission_ticket)],
        events=service.events,
    )

    await endpoint(websocket)

    assert service.events[0:2] == ["ticket_consume", "websocket_accept"]
    assert service.events.index("websocket_accept") < service.events.index(
        "sender_started"
    )
    assert service.events.index("websocket_accept") < service.events.index(
        "receiver_started"
    )
    assert service.queue_counts_at_task_start == [1, 1]
    assert service._queues == set()
    assert service.sender_starts == service.receiver_starts == 1
    assert websocket.accepted_subprotocol is None
    assert grant.admission_ticket not in json.dumps(websocket.events)


@pytest.mark.asyncio
async def test_manager_ticket_replay_is_denied_before_accept_or_task_creation():
    _, service, authority, endpoint = _install_enabled_route()
    grant = authority.issue(_principal())
    protocol = _manager_protocol(grant.admission_ticket)
    first = FakeWebSocket(protocol_values=[protocol], events=service.events)
    await endpoint(first)
    sender_starts = service.sender_starts
    receiver_starts = service.receiver_starts
    replay = FakeWebSocket(protocol_values=[protocol])

    await endpoint(replay)

    assert replay.denial_status == 403
    assert replay.denial_body == {
        "reason_code": ManagerWebSocketAdmissionReasonV1.ADMISSION_DENIED.value
    }
    assert "websocket_accept" not in replay.events
    assert service.sender_starts == sender_starts
    assert service.receiver_starts == receiver_starts
    assert service._queues == set()
    assert grant.admission_ticket not in json.dumps(replay.denial_body)


@pytest.mark.asyncio
async def test_expired_manager_ticket_is_denied_before_side_effects():
    clock = FakeClock()
    _, service, authority, endpoint = _install_enabled_route(clock=clock)
    grant = authority.issue(_principal())
    clock.advance(MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1)
    websocket = FakeWebSocket(
        protocol_values=[_manager_protocol(grant.admission_ticket)]
    )

    await endpoint(websocket)

    assert websocket.denial_status == 403
    assert "websocket_accept" not in websocket.events
    assert service.sender_starts == service.receiver_starts == 0
    assert service._queues == set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("protocol_values", "expected_reason"),
    [
        (None, ManagerWebSocketAdmissionReasonV1.PROTOCOL_REQUIRED),
        ([""], ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID),
        (["x" * 257], ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID),
        (
            ["oac.manager-admission.v1.att1_" + "A" * 43],
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        ),
        (
            ["oac.manager-admission.v1.rtb1_" + "B" * 43],
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        ),
        (
            ["oac.cert-admission.v1.mat1_" + "C" * 43],
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        ),
        (
            [
                "oac.manager-admission.v1.mat1_"
                + "D" * 43
                + ",unrelated"
            ],
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        ),
        (
            [
                "oac.manager-admission.v1.mat1_" + "E" * 43,
                "oac.manager-admission.v1.mat1_" + "F" * 43,
            ],
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        ),
        (
            ["oac.manager-admission.v1.mat1_" + "é" * 43],
            ManagerWebSocketAdmissionReasonV1.PROTOCOL_INVALID,
        ),
    ],
)
async def test_missing_malformed_and_cross_domain_protocols_create_no_side_effects(
    protocol_values,
    expected_reason,
):
    _, service, _, endpoint = _install_enabled_route()
    websocket = FakeWebSocket(protocol_values=protocol_values)

    await endpoint(websocket)

    assert websocket.denial_status == 400
    assert websocket.denial_body == {"reason_code": expected_reason.value}
    assert websocket.denial_headers["cache-control"] == "no-store"
    assert "websocket_accept" not in websocket.events
    assert service._queues == set()
    assert service.sender_starts == service.receiver_starts == 0


@pytest.mark.asyncio
async def test_unknown_well_formed_manager_ticket_is_denied_not_reflected():
    _, service, _, endpoint = _install_enabled_route()
    ticket_canary = "mat1_" + "A" * 43
    websocket = FakeWebSocket(
        protocol_values=[_manager_protocol(ticket_canary)]
    )

    await endpoint(websocket)

    assert websocket.denial_status == 403
    assert ticket_canary not in json.dumps(websocket.denial_body)
    assert ticket_canary not in (websocket.close_reason or "")
    assert service.sender_starts == service.receiver_starts == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("extra_headers", "query_string"),
    [
        ([], b"token=mat1_" + b"A" * 43),
        ([(b"authorization", b"Bearer mat1_" + b"B" * 43)], b""),
        ([(b"cookie", b"manager_ticket=mat1_" + b"C" * 43)], b""),
    ],
)
async def test_manager_admission_never_uses_query_bearer_or_cookie_credentials(
    extra_headers,
    query_string,
):
    _, service, _, endpoint = _install_enabled_route()
    websocket = FakeWebSocket(
        extra_headers=extra_headers,
        query_string=query_string,
    )

    await endpoint(websocket)

    assert websocket.denial_status == 400
    assert websocket.denial_body == {
        "reason_code": ManagerWebSocketAdmissionReasonV1.PROTOCOL_REQUIRED.value
    }
    assert "websocket_accept" not in websocket.events
    assert service.sender_starts == service.receiver_starts == 0


@pytest.mark.asyncio
async def test_failed_accept_leaves_ticket_consumed_and_creates_zero_tasks(
    monkeypatch,
):
    _, service, authority, endpoint = _install_enabled_route()
    grant = authority.issue(_principal())
    create_task_calls = 0
    original_create_task = asyncio.create_task

    def recording_create_task(*args, **kwargs):
        nonlocal create_task_calls
        create_task_calls += 1
        return original_create_task(*args, **kwargs)

    monkeypatch.setattr(asyncio, "create_task", recording_create_task)
    websocket = FakeWebSocket(
        protocol_values=[_manager_protocol(grant.admission_ticket)],
        accept_error=RuntimeError("handshake failure canary"),
    )

    await endpoint(websocket)

    replay = FakeWebSocket(
        protocol_values=[_manager_protocol(grant.admission_ticket)]
    )
    await endpoint(replay)
    assert websocket.events == ["websocket_accept"]
    assert replay.denial_status == 403
    assert create_task_calls == 0
    assert service._queues == set()
    assert service.sender_starts == service.receiver_starts == 0


@pytest.mark.asyncio
async def test_missing_or_closed_manager_authority_fails_closed():
    service = RecordingManagerDataToolService([])
    missing_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    missing_app.state.certificate_capture_enabled_v1 = True
    service.register_routes(missing_app)
    missing = FakeWebSocket()

    await _endpoint(missing_app)(missing)

    assert missing.denial_status == 503
    assert missing.denial_body == {
        "reason_code": (
            ManagerWebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE.value
        )
    }
    assert "websocket_accept" not in missing.events

    malformed_runtime_app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    malformed_runtime_app.state.certificate_session_control_v1 = object()
    malformed_service = RecordingManagerDataToolService([])
    malformed_service.register_routes(malformed_runtime_app)
    malformed = FakeWebSocket()
    await _endpoint(malformed_runtime_app)(malformed)
    assert malformed.denial_status == 503
    assert "websocket_accept" not in malformed.events
    assert malformed_service.sender_starts == 0
    assert malformed_service.receiver_starts == 0

    _, closed_service, authority, endpoint = _install_enabled_route()
    grant = authority.issue(_principal())
    authority.close()
    closed = FakeWebSocket(
        protocol_values=[_manager_protocol(grant.admission_ticket)]
    )
    await endpoint(closed)
    assert closed.denial_status == 503
    assert "websocket_accept" not in closed.events
    assert closed_service._queues == set()
    assert closed_service.sender_starts == closed_service.receiver_starts == 0


@pytest.mark.asyncio
async def test_denial_fallback_closes_without_echoing_secret():
    _, service, _, endpoint = _install_enabled_route()
    ticket_canary = "mat1_" + "Z" * 43
    websocket = FakeWebSocket(
        protocol_values=[_manager_protocol(ticket_canary)],
        denial_supported=False,
    )

    await endpoint(websocket)

    assert websocket.close_code == 1008
    assert (
        websocket.close_reason
        == ManagerWebSocketAdmissionReasonV1.ADMISSION_DENIED.value
    )
    assert ticket_canary not in websocket.close_reason
    assert "websocket_accept" not in websocket.events
    assert service.sender_starts == service.receiver_starts == 0


@pytest.mark.asyncio
async def test_disabled_mode_preserves_legacy_manager_websocket_behavior():
    events: list[str] = []
    service = RecordingManagerDataToolService(events)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    service.register_routes(app)
    websocket = FakeWebSocket(
        query_string=b"token=legacy-token",
        events=events,
    )

    await _endpoint(app)(websocket)

    assert events[0] == "websocket_accept"
    assert "sender_started" in events
    assert "receiver_started" in events
    assert service.sender_starts == service.receiver_starts == 1
    assert service._queues == set()
    assert not hasattr(app.state, MANAGER_AUTHORIZATION_STATE_ATTRIBUTE_V1)

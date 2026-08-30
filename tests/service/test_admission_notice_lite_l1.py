import asyncio
import json
import re
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from loguru import logger

import service.admission_notice_lite_service as lite_service_module
from chat_engine.chat_engine import ChatEngine
from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    RecognitionErrorReasonLiteV1,
    RecognitionJobContextLiteV1,
    RecognitionStateLiteV1,
)
from service.admission_notice_lite_routes import (
    register_admission_notice_lite_routes,
)
from service.admission_notice_lite_service import AdmissionNoticeLiteService
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
L1_SOURCE_PATHS = (
    PROJECT_ROOT / "src" / "service" / "admission_notice_lite_contracts.py",
    PROJECT_ROOT / "src" / "service" / "admission_notice_lite_routes.py",
    PROJECT_ROOT / "src" / "service" / "admission_notice_lite_service.py",
    PROJECT_ROOT
    / "src"
    / "service"
    / "service_data_models"
    / "admission_notice_lite_config.py",
)
ROUTE_BASE = "/api/v1/sessions/{session_id}/admission-notice/recognitions"


class SessionStub:
    def __init__(self) -> None:
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


class ManualClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class ControlPlaneProcessorFake:
    def __init__(
        self,
        *,
        wait_for_release: bool = False,
        failure: Exception | None = None,
        ignore_cancellation: bool = False,
    ) -> None:
        self.wait_for_release = wait_for_release
        self.failure = failure
        self.ignore_cancellation = ignore_cancellation
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancellation_observed = asyncio.Event()
        self.calls = 0

    async def process(self, context: RecognitionJobContextLiteV1) -> None:
        del context
        self.calls += 1
        self.started.set()
        if self.wait_for_release:
            while not self.release.is_set():
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    self.cancellation_observed.set()
                    if not self.ignore_cancellation:
                        raise
        if self.failure is not None:
            raise self.failure


def _config(
    *,
    ttl: int = 120,
    max_global_jobs: int = 1,
) -> AdmissionNoticeLiteFeatureConfigV1:
    return AdmissionNoticeLiteFeatureConfigV1(
        enabled=True,
        recognition_ttl_seconds=ttl,
        max_global_recognition_jobs=max_global_jobs,
    )


def _service(
    sessions: dict[str, SessionStub],
    processor: ControlPlaneProcessorFake | None,
    *,
    ttl: int = 120,
    max_global_jobs: int = 1,
    clock: ManualClock | None = None,
) -> AdmissionNoticeLiteService:
    return AdmissionNoticeLiteService(
        config=_config(ttl=ttl, max_global_jobs=max_global_jobs),
        session_lookup=sessions.get,
        processor=processor,
        clock=clock or ManualClock(),
    )


async def _wait_for_state(
    service: AdmissionNoticeLiteService,
    session_id: str,
    recognition_id: str,
    expected: RecognitionStateLiteV1,
) -> None:
    for _ in range(200):
        snapshot = await service.get_recognition(session_id, recognition_id)
        if snapshot.state is expected:
            return
        await asyncio.sleep(0)
    pytest.fail(f"recognition did not reach {expected.value}")


async def _wait_for_no_tasks(service: AdmissionNoticeLiteService) -> None:
    for _ in range(200):
        if service.owned_task_count == 0:
            return
        await asyncio.sleep(0)
    pytest.fail("owned Admission Notice Lite tasks did not finish")


async def _post_asgi_body_without_length(
    app: FastAPI, path: str, body: bytes
) -> tuple[int, dict[str, str]]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "2",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [(b"host", b"test")],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "root_path": "",
    }
    received = False
    messages: list[dict] = []

    async def receive() -> dict:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app(scope, receive, send)
    status = next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return status, json.loads(response_body)


def _assert_reason(
    error: pytest.ExceptionInfo[AdmissionNoticeLiteError],
    reason: RecognitionErrorReasonLiteV1,
) -> None:
    assert error.value.reason is reason


def test_disabled_registration_adds_no_routes_runtime_or_observer() -> None:
    app = FastAPI()
    engine = ChatEngine()

    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=AdmissionNoticeLiteFeatureConfigV1(),
    )

    assert service is None
    assert engine._session_stop_observers == []
    assert not any("admission-notice" in route.path for route in app.routes)


@pytest.mark.asyncio
async def test_enabled_default_processor_fails_closed_without_job() -> None:
    app = FastAPI()
    engine = ChatEngine()
    engine.sessions["owner"] = SessionStub()
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
    )
    assert service is not None

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/sessions/owner/admission-notice/recognitions"
        )

    assert response.status_code == 503
    assert response.json() == {"reason": "SERVICE_UNAVAILABLE"}
    assert service.active_job_count == 0
    assert service.retained_job_count == 0
    assert service.owned_task_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_create_uses_server_id_and_exact_session_owner() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = _service(sessions, processor)

    job = await service.create_recognition("owner")
    await processor.started.wait()

    assert re.fullmatch(r"arn1_[A-Za-z0-9_-]{24}", job.recognition_id)
    assert job.owning_session_id == "owner"
    assert job.state is RecognitionStateLiteV1.CREATED
    current = await service.get_recognition("owner", job.recognition_id)
    assert current.state is RecognitionStateLiteV1.PROCESSING
    assert service.active_job_count == 1

    processor.release.set()
    await _wait_for_state(
        service, "owner", job.recognition_id, RecognitionStateLiteV1.COMPLETED
    )
    await _wait_for_no_tasks(service)
    assert service.active_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_simultaneous_create_claims_one_session_slot_atomically() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = _service(sessions, processor)

    results = await asyncio.gather(
        service.create_recognition("owner"),
        service.create_recognition("owner"),
        return_exceptions=True,
    )

    jobs = [result for result in results if not isinstance(result, Exception)]
    errors = [result for result in results if isinstance(result, Exception)]
    assert len(jobs) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], AdmissionNoticeLiteError)
    assert errors[0].reason is RecognitionErrorReasonLiteV1.RECOGNITION_ALREADY_ACTIVE
    assert service.active_job_count == 1

    await service.cancel_recognition("owner", jobs[0].recognition_id)
    await _wait_for_no_tasks(service)
    assert service.active_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_global_limit_rejects_without_allocating_or_queueing() -> None:
    sessions = {"one": SessionStub(), "two": SessionStub()}
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = _service(sessions, processor, max_global_jobs=1)

    first = await service.create_recognition("one")
    with pytest.raises(AdmissionNoticeLiteError) as error:
        await service.create_recognition("two")

    _assert_reason(error, RecognitionErrorReasonLiteV1.SERVICE_BUSY)
    assert service.active_job_count == 1
    assert service.retained_job_count == 1

    await service.cancel_recognition("one", first.recognition_id)
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_configured_global_limit_is_used() -> None:
    sessions = {"one": SessionStub(), "two": SessionStub()}
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = _service(sessions, processor, max_global_jobs=2)

    first, second = await asyncio.gather(
        service.create_recognition("one"),
        service.create_recognition("two"),
    )

    assert first.recognition_id != second.recognition_id
    assert service.active_job_count == 2
    await service.cancel_recognition("one", first.recognition_id)
    await service.cancel_recognition("two", second.recognition_id)
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_owner_status_is_coarse_and_cross_session_is_not_found() -> None:
    app = FastAPI()
    engine = ChatEngine()
    engine.sessions.update(owner=SessionStub(), other=SessionStub())
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
        processor=processor,
    )
    assert service is not None

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/sessions/owner/admission-notice/recognitions"
        )
        recognition_id = created.json()["recognition_id"]
        owner_status = await client.get(
            f"/api/v1/sessions/owner/admission-notice/recognitions/{recognition_id}"
        )
        other_status = await client.get(
            f"/api/v1/sessions/other/admission-notice/recognitions/{recognition_id}"
        )
        unknown_status = await client.get(
            "/api/v1/sessions/owner/admission-notice/recognitions/arn1_unknown"
        )
        other_cancel = await client.delete(
            f"/api/v1/sessions/other/admission-notice/recognitions/{recognition_id}"
        )
        owner_cancel = await client.delete(
            f"/api/v1/sessions/owner/admission-notice/recognitions/{recognition_id}"
        )
        duplicate_owner_cancel = await client.delete(
            f"/api/v1/sessions/owner/admission-notice/recognitions/{recognition_id}"
        )
        cancelled_status = await client.get(
            f"/api/v1/sessions/owner/admission-notice/recognitions/{recognition_id}"
        )

    assert created.status_code == 202
    assert created.json()["status"] == "created"
    assert set(owner_status.json()) == {"recognition_id", "status"}
    assert owner_status.json()["status"] in {"created", "processing"}
    for response in (other_status, unknown_status, other_cancel):
        assert response.status_code == 404
        assert response.json() == {"reason": "RECOGNITION_NOT_FOUND"}
    assert owner_cancel.status_code == 204
    assert duplicate_owner_cancel.status_code == 204
    assert cancelled_status.json() == {
        "recognition_id": recognition_id,
        "status": "cancelled",
        "reason": "RECOGNITION_CANCELLED",
    }

    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_control_route_rejects_body_query_and_client_owner_fields() -> None:
    app = FastAPI()
    engine = ChatEngine()
    engine.sessions.update(owner=SessionStub(), other=SessionStub())
    processor = ControlPlaneProcessorFake()
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
        processor=processor,
    )
    assert service is not None

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        body_response = await client.post(
            "/api/v1/sessions/owner/admission-notice/recognitions",
            json={"owner_session_id": "other"},
        )
        query_response = await client.post(
            "/api/v1/sessions/owner/admission-notice/recognitions?mock=true"
        )

    assert body_response.status_code == 400
    assert body_response.json() == {"reason": "INVALID_REQUEST"}
    assert query_response.status_code == 400
    assert query_response.json() == {"reason": "INVALID_REQUEST"}
    assert processor.calls == 0
    assert service.retained_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_post_rejects_headerless_asgi_body_without_consuming_it() -> None:
    app = FastAPI()
    engine = ChatEngine()
    engine.sessions["owner"] = SessionStub()
    processor = ControlPlaneProcessorFake()
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
        processor=processor,
    )
    assert service is not None

    status, response = await _post_asgi_body_without_length(
        app,
        "/api/v1/sessions/owner/admission-notice/recognitions",
        b'{"owner_session_id":"other"}',
    )

    assert status == 400
    assert response == {"reason": "INVALID_REQUEST"}
    assert processor.calls == 0
    assert service.retained_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_completion_releases_capacity_and_never_resurrects() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake()
    service = _service(sessions, processor)

    first = await service.create_recognition("owner")
    await _wait_for_state(
        service, "owner", first.recognition_id, RecognitionStateLiteV1.COMPLETED
    )
    assert service.active_job_count == 0

    second = await service.create_recognition("owner")
    await _wait_for_state(
        service, "owner", second.recognition_id, RecognitionStateLiteV1.COMPLETED
    )
    first_after = await service.get_recognition("owner", first.recognition_id)
    assert first_after.state is RecognitionStateLiteV1.COMPLETED
    assert service.active_job_count == 0
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_processor_exception_is_safe_failed_status_and_releases_slot() -> None:
    sessions = {"owner": SessionStub()}
    secret_marker = "future-private-payload-marker"
    processor = ControlPlaneProcessorFake(failure=RuntimeError(secret_marker))
    service = _service(sessions, processor)
    messages: list[str] = []
    sink_id = logger.add(messages.append, format="{message}")
    try:
        job = await service.create_recognition("owner")
        await _wait_for_state(
            service, "owner", job.recognition_id, RecognitionStateLiteV1.FAILED
        )
    finally:
        logger.remove(sink_id)

    status = await service.get_recognition("owner", job.recognition_id)
    assert status.reason is RecognitionErrorReasonLiteV1.INTERNAL_ERROR
    assert secret_marker not in status.reason.value
    assert all(secret_marker not in message for message in messages)
    assert service.active_job_count == 0
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_owner_cancel_is_idempotent_and_releases_slot_once() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = _service(sessions, processor)
    job = await service.create_recognition("owner")
    await processor.started.wait()

    await service.cancel_recognition("owner", job.recognition_id)
    await service.cancel_recognition("owner", job.recognition_id)
    status = await service.get_recognition("owner", job.recognition_id)

    assert status.state is RecognitionStateLiteV1.CANCELLED
    assert status.reason is RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED
    assert service.active_job_count == 0
    await _wait_for_no_tasks(service)

    replacement = await service.create_recognition("owner")
    await service.cancel_recognition("owner", replacement.recognition_id)
    assert service.active_job_count == 0
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_delayed_completion_after_cancel_is_discarded() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    service = _service(sessions, processor)
    job = await service.create_recognition("owner")
    await processor.started.wait()

    await service.cancel_recognition("owner", job.recognition_id)
    await processor.cancellation_observed.wait()
    processor.release.set()
    await _wait_for_no_tasks(service)
    status = await service.get_recognition("owner", job.recognition_id)

    assert status.state is RecognitionStateLiteV1.CANCELLED
    assert service.active_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_ttl_expires_active_job_and_polling_does_not_slide() -> None:
    clock = ManualClock()
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    service = _service(sessions, processor, ttl=2, clock=clock)
    job = await service.create_recognition("owner")
    await processor.started.wait()

    clock.advance(1)
    first_poll = await service.get_recognition("owner", job.recognition_id)
    assert first_poll.expires_at_monotonic == job.expires_at_monotonic

    clock.advance(1.1)
    expired = await service.get_recognition("owner", job.recognition_id)
    assert expired.state is RecognitionStateLiteV1.EXPIRED
    assert expired.reason is RecognitionErrorReasonLiteV1.RECOGNITION_EXPIRED
    assert expired.expires_at_monotonic == job.expires_at_monotonic
    assert service.active_job_count == 0

    processor.release.set()
    await _wait_for_no_tasks(service)
    still_expired = await service.get_recognition("owner", job.recognition_id)
    assert still_expired.state is RecognitionStateLiteV1.EXPIRED
    await service.shutdown()


@pytest.mark.asyncio
async def test_completion_observed_after_deadline_cannot_win_expiry_race() -> None:
    clock = ManualClock()
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = _service(sessions, processor, ttl=1, clock=clock)
    job = await service.create_recognition("owner")
    await processor.started.wait()

    clock.advance(1.1)
    processor.release.set()
    await _wait_for_state(
        service, "owner", job.recognition_id, RecognitionStateLiteV1.EXPIRED
    )
    assert service.active_job_count == 0
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_supervisor_timeout_cancels_when_exact_owner_is_no_longer_live() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    service = AdmissionNoticeLiteService(
        config=_config(ttl=1),
        session_lookup=sessions.get,
        processor=processor,
    )
    job = await service.create_recognition("owner")
    await processor.started.wait()

    sessions["owner"] = SessionStub()
    for _ in range(150):
        runtime = service._jobs[job.recognition_id]
        if runtime.state is RecognitionStateLiteV1.CANCELLED:
            break
        await asyncio.sleep(0.01)

    assert runtime.state is RecognitionStateLiteV1.CANCELLED
    assert service.active_job_count == 0
    processor.release.set()
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_session_stop_cancels_exact_instance_and_id_reuse_cannot_claim_job() -> (
    None
):
    app = FastAPI()
    engine = ChatEngine()
    old_session = SessionStub()
    engine.sessions["reused"] = old_session
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
        processor=processor,
    )
    assert service is not None
    job = await service.create_recognition("reused")
    await processor.started.wait()

    engine.stop_session("reused")
    for _ in range(200):
        if service.active_job_count == 0:
            break
        await asyncio.sleep(0)
    assert old_session.stopped is True
    assert service.active_job_count == 0

    engine.sessions["reused"] = SessionStub()
    with pytest.raises(AdmissionNoticeLiteError) as error:
        await service.get_recognition("reused", job.recognition_id)
    _assert_reason(error, RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND)

    processor.release.set()
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_session_stop_marker_beats_already_queued_processor_completion() -> None:
    app = FastAPI()
    engine = ChatEngine()
    old_session = SessionStub()
    engine.sessions["owner"] = old_session
    processor = ControlPlaneProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
        processor=processor,
    )
    assert service is not None
    job = await service.create_recognition("owner")
    await processor.started.wait()

    processor.release.set()
    engine.stop_session("owner")
    await _wait_for_no_tasks(service)

    runtime = service._jobs[job.recognition_id]
    assert runtime.state is RecognitionStateLiteV1.CANCELLED
    assert service.active_job_count == 0
    await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ("get", "cancel"))
async def test_status_and_cancel_revalidate_session_after_waiting_for_lock(
    operation: str,
) -> None:
    app = FastAPI()
    engine = ChatEngine()
    old_session = SessionStub()
    engine.sessions["reused"] = old_session
    processor = ControlPlaneProcessorFake(wait_for_release=True)
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
        processor=processor,
    )
    assert service is not None
    job = await service.create_recognition("reused")
    await processor.started.wait()

    await service._lock.acquire()
    if operation == "get":
        operation_task = asyncio.create_task(
            service.get_recognition("reused", job.recognition_id)
        )
    else:
        operation_task = asyncio.create_task(
            service.cancel_recognition("reused", job.recognition_id)
        )
    await asyncio.sleep(0)

    engine.stop_session("reused")
    engine.sessions["reused"] = SessionStub()
    service._lock.release()

    with pytest.raises(AdmissionNoticeLiteError) as error:
        await operation_task
    _assert_reason(error, RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND)

    for _ in range(200):
        if service.active_job_count == 0:
            break
        await asyncio.sleep(0)
    assert service.active_job_count == 0
    processor.release.set()
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_shutdown_closes_admission_cancels_and_clears_registry_boundedly() -> (
    None
):
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake(
        wait_for_release=True,
        ignore_cancellation=True,
    )
    service = _service(sessions, processor)
    await service.create_recognition("owner")
    await processor.started.wait()

    loop = asyncio.get_running_loop()
    started_at = loop.time()
    await service.shutdown(wait_seconds=0.001)
    elapsed = loop.time() - started_at

    assert elapsed < 0.1
    assert service.accepting is False
    assert service.active_job_count == 0
    assert service.retained_job_count == 0
    with pytest.raises(AdmissionNoticeLiteError) as error:
        await service.create_recognition("owner")
    _assert_reason(error, RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE)

    processor.release.set()
    await _wait_for_no_tasks(service)
    assert service.retained_job_count == 0


@pytest.mark.asyncio
async def test_terminal_retention_has_a_hard_count_bound() -> None:
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake()
    service = _service(sessions, processor)

    for _ in range(70):
        job = await service.create_recognition("owner")
        await _wait_for_state(
            service,
            "owner",
            job.recognition_id,
            RecognitionStateLiteV1.COMPLETED,
        )

    assert service.active_job_count == 0
    assert service.retained_job_count == 64
    await _wait_for_no_tasks(service)
    await service.shutdown()


@pytest.mark.asyncio
async def test_terminal_retention_expires_while_service_is_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lite_service_module, "_TERMINAL_RETENTION_SECONDS", 0.02)
    sessions = {"owner": SessionStub()}
    processor = ControlPlaneProcessorFake()
    service = AdmissionNoticeLiteService(
        config=_config(ttl=1),
        session_lookup=sessions.get,
        processor=processor,
    )
    job = await service.create_recognition("owner")
    await _wait_for_state(
        service, "owner", job.recognition_id, RecognitionStateLiteV1.COMPLETED
    )
    assert service.retained_job_count == 1

    for _ in range(200):
        if service.retained_job_count == 0:
            break
        await asyncio.sleep(0.001)

    assert service.retained_job_count == 0
    await _wait_for_no_tasks(service)
    await service.shutdown()


def test_exact_l1_route_inventory_has_no_extra_or_debug_endpoint() -> None:
    app = FastAPI()
    engine = ChatEngine()
    service = register_admission_notice_lite_routes(
        app=app,
        chat_engine=engine,
        config=_config(),
    )
    assert service is not None

    paths_and_methods = {
        (route.path, frozenset(route.methods or ()))
        for route in app.routes
        if "admission-notice" in route.path
    }
    assert paths_and_methods == {
        (ROUTE_BASE, frozenset({"POST"})),
        (f"{ROUTE_BASE}/{{recognition_id}}", frozenset({"GET"})),
        (f"{ROUTE_BASE}/{{recognition_id}}", frozenset({"DELETE"})),
    }


def test_production_config_and_routes_cannot_select_test_processor() -> None:
    config_fields = set(AdmissionNoticeLiteFeatureConfigV1.model_fields)
    assert config_fields == {
        "enabled",
        "recognition_ttl_seconds",
        "max_global_recognition_jobs",
    }

    production_text = "\n".join(
        path.read_text(encoding="utf-8") for path in L1_SOURCE_PATHS
    ).lower()
    for forbidden in (
        "?mock",
        "force_ready",
        "x-debug-processor",
        "fake_processor",
        "test_processor",
    ):
        assert forbidden not in production_text


def test_l1_source_has_no_l2_or_hardened_dependencies() -> None:
    source_text = "\n".join(
        path.read_text(encoding="utf-8") for path in L1_SOURCE_PATHS
    ).lower()
    for forbidden in (
        "from pil",
        "import pil",
        "pillow",
        "paddle",
        "paddleocr",
        "ocrpage",
        "certificate_capture",
        "securityenvelope",
        "workfence",
        "aesgcm",
        "chatagent",
        "chat_agent",
        "text_to_speech",
        "frontend_service",
    ):
        assert forbidden not in source_text

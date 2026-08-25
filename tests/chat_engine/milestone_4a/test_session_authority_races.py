from __future__ import annotations

import asyncio
import threading
import time

import pytest

from certificate_capture.coordinator import (
    CaptureCoordinatorV1,
    CaptureFailedClosedV1,
    CaptureTransitionRejectedV1,
)
from certificate_capture.private_authority import (
    PrivateEvidenceAuthorityV1,
)
from certificate_capture.state import (
    CaptureStateV1,
    CaptureTransitionPointV1,
)
from chat_engine.chat_engine import ChatEngine
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.chat_session import ChatSession
from chat_engine.data_models.chat_engine_config_data import (
    ChatEngineConfigModel,
)
from chat_engine.data_models.session_info_data import SessionInfoData
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import WorkOperationKindV1
from service.service_security.certificate_session_authority import (
    CertificateSessionAuthorityV1,
    SessionAdmissionChannelV1,
)
from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
)


def _authority_binding():
    authority = CertificateSessionAuthorityV1()
    principal = AuthenticatedPrincipalV1(
        issuer="https://issuer.example.test",
        subject="capture-owner",
        scopes=frozenset({"certificate:capture"}),
        token_expiry_epoch_seconds=time.time() + 3600,
    )
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    admission = authority.consume_admission_ticket(
        principal,
        grant.session_id,
        ticket.admission_ticket,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    return authority, principal, grant, admission


def _authority_bound_coordinator():
    authority, principal, grant, admission = _authority_binding()
    controller = SessionWorkControllerV1._create_for_test_v1(
        cleanup_timeout_seconds=0.2
    )
    security_authority, security_registrar = SecurityAuthorityV1.create_v1()
    private_evidence_authority = (
        PrivateEvidenceAuthorityV1._create_for_session_v1(
            security_authority=security_authority,
            registrar=security_registrar,
        )
    )
    terminations: list[bool] = []
    coordinator, gate = CaptureCoordinatorV1._create_for_session_v1(
        work_controller=controller,
        private_evidence_authority_v1=private_evidence_authority,
        feature_enabled_v1=lambda: True,
        security_authority_usable_v1=lambda: True,
        session_live_action_v1=(
            lambda action: authority.perform_if_consumed_session_live_v1(
                admission,
                action,
            )
        ),
        quiescence_drain_v1=lambda epoch: None,
        semantic_cleanup_v1=lambda epoch: None,
        failure_terminator_v1=lambda: terminations.append(True),
    )
    return (
        authority,
        principal,
        grant,
        admission,
        controller,
        coordinator,
        gate,
        terminations,
    )


def _engine_bound_secure_session():
    authority, principal, grant, admission = _authority_binding()
    engine = ChatEngine()
    context = SessionContext(
        SessionInfoData(
            session_id=grant.session_id,
            timestamp_base=0,
        ),
        session_admission=admission,
        certificate_capture_enabled_v1=True,
    )
    session = ChatSession(
        context,
        ChatEngineConfigModel(),
        _capture_session_live_action_v1=(
            lambda action: authority.perform_if_consumed_session_live_v1(
                admission,
                action,
            )
        ),
        _capture_feature_enabled_v1=lambda: True,
    )
    session.start()
    engine.sessions[grant.session_id] = session
    return authority, principal, grant, admission, engine, session


async def _wait_for_destroyed(coordinator) -> None:
    for _ in range(200):
        if coordinator.snapshot_v1().destroyed:
            return
        await asyncio.sleep(0.005)
    raise AssertionError("capture coordinator was not destroyed")


def test_session_live_action_linearizes_against_revoke():
    authority, principal, grant, admission = _authority_binding()
    action_started = threading.Event()
    action_release = threading.Event()
    action_finished = threading.Event()
    revoke_finished = threading.Event()

    def action() -> None:
        action_started.set()
        action_release.wait(timeout=1)
        action_finished.set()

    def run_action() -> None:
        assert authority.perform_if_consumed_session_live_v1(
            admission,
            action,
        )

    def revoke() -> None:
        authority.revoke_session(
            principal,
            grant.session_id,
            grant.session_capability,
        )
        revoke_finished.set()

    action_thread = threading.Thread(target=run_action)
    revoke_thread = threading.Thread(target=revoke)
    action_thread.start()
    assert action_started.wait(timeout=1)
    revoke_thread.start()
    assert not revoke_finished.wait(timeout=0.02)
    action_release.set()
    action_thread.join(timeout=1)
    revoke_thread.join(timeout=1)

    assert action_finished.is_set()
    assert revoke_finished.is_set()
    assert not authority.perform_if_consumed_session_live_v1(
        admission,
        lambda: None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "point",
    [
        CaptureTransitionPointV1.AFTER_ENTERING,
        CaptureTransitionPointV1.AFTER_QUIESCING,
        CaptureTransitionPointV1.BEFORE_ARMED,
    ],
)
async def test_revoke_during_begin_prevents_armed(point):
    (
        authority,
        principal,
        grant,
        _admission,
        _controller,
        coordinator,
        gate,
        terminations,
    ) = _authority_bound_coordinator()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(observed: CaptureTransitionPointV1) -> None:
        if observed is point:
            reached.set()
            await release.wait()

    coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(coordinator.begin_capture_v1())
    await reached.wait()
    authority.revoke_session(
        principal,
        grant.session_id,
        grant.session_capability,
    )
    release.set()

    with pytest.raises(CaptureFailedClosedV1):
        await begin
    status = coordinator.snapshot_v1()
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert not gate.is_open_v1()
    assert not status.quiescence_complete
    assert terminations == [True]


@pytest.mark.asyncio
async def test_replacement_during_begin_prevents_old_capture_authority():
    (
        authority,
        principal,
        _grant,
        _admission,
        _controller,
        coordinator,
        gate,
        _terminations,
    ) = _authority_bound_coordinator()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_ARMED:
            reached.set()
            await release.wait()

    coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(coordinator.begin_capture_v1())
    await reached.wait()
    replacement = authority.create_session(principal)
    release.set()

    with pytest.raises(CaptureFailedClosedV1):
        await begin
    assert replacement.session_id
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not gate.is_open_v1()


@pytest.mark.asyncio
async def test_authority_shutdown_during_begin_prevents_armed():
    (
        authority,
        _principal,
        _grant,
        _admission,
        _controller,
        coordinator,
        gate,
        _terminations,
    ) = _authority_bound_coordinator()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_ARMED:
            reached.set()
            await release.wait()

    coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(coordinator.begin_capture_v1())
    await reached.wait()
    authority.close()
    release.set()

    with pytest.raises(CaptureFailedClosedV1):
        await begin
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not gate.is_open_v1()


@pytest.mark.asyncio
async def test_revoke_while_armed_then_shutdown_destroys_capture_authority():
    (
        authority,
        principal,
        grant,
        _admission,
        _controller,
        coordinator,
        gate,
        _terminations,
    ) = _authority_bound_coordinator()
    await coordinator.begin_capture_v1()
    authority.revoke_session(
        principal,
        grant.session_id,
        grant.session_capability,
    )

    assert await coordinator.shutdown_async_v1()
    status = coordinator.snapshot_v1()
    assert status.destroyed
    assert status.shutdown_started
    assert status.state is CaptureStateV1.FAILED_CLOSED
    assert status.capture_id is None
    assert gate.snapshot_v1().destroyed


@pytest.mark.asyncio
async def test_revoke_immediately_before_end_resume_never_reopens():
    (
        authority,
        principal,
        grant,
        _admission,
        _controller,
        coordinator,
        gate,
        terminations,
    ) = _authority_bound_coordinator()
    capture_epoch = await coordinator.begin_capture_v1()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_RESUME:
            reached.set()
            await release.wait()

    coordinator._set_transition_hook_for_test_v1(hook)
    ending = asyncio.create_task(coordinator.end_capture_v1(capture_epoch))
    await reached.wait()
    authority.revoke_session(
        principal,
        grant.session_id,
        grant.session_capability,
    )
    release.set()

    with pytest.raises(CaptureFailedClosedV1) as failure:
        await ending
    assert failure.value.reason_code == "RESUME_BARRIER_FAILED"
    assert coordinator.snapshot_v1().state is CaptureStateV1.FAILED_CLOSED
    assert not gate.is_open_v1()
    assert terminations == [True]


@pytest.mark.asyncio
async def test_shutdown_during_entering_fences_delayed_begin_callback(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENTERING:
            reached.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await reached.wait()
    shutdown = asyncio.create_task(harness.coordinator.shutdown_async_v1())
    await asyncio.sleep(0.02)
    assert shutdown.done()
    release.set()

    outcomes = await asyncio.gather(
        begin,
        shutdown,
        return_exceptions=True,
    )
    assert isinstance(outcomes[0], CaptureTransitionRejectedV1)
    assert outcomes[0].reason_code == "STALE_TRANSITION"
    assert outcomes[1] is True
    status = harness.coordinator.snapshot_v1()
    assert status.destroyed
    assert not status.normal_application_admission_open


@pytest.mark.asyncio
async def test_shutdown_during_ending_never_reopens_normal_admission(
    capture_harness_factory,
):
    harness = capture_harness_factory()
    capture_epoch = await harness.coordinator.begin_capture_v1()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_ENDING:
            reached.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    ending = asyncio.create_task(harness.coordinator.end_capture_v1(capture_epoch))
    await reached.wait()
    shutdown = asyncio.create_task(harness.coordinator.shutdown_async_v1())
    release.set()
    results = await asyncio.gather(
        ending,
        shutdown,
        return_exceptions=True,
    )

    assert isinstance(results[0], CaptureTransitionRejectedV1)
    assert results[1] is True
    assert harness.coordinator.snapshot_v1().destroyed
    assert not harness.gate.is_open_v1()


@pytest.mark.asyncio
async def test_failure_termination_is_requested_exactly_once(
    capture_harness_factory,
):
    harness = capture_harness_factory(semantic_error=True)
    with pytest.raises(CaptureFailedClosedV1):
        await harness.coordinator.begin_capture_v1()
    harness.coordinator._fail_closed_for_test_v1()
    harness.coordinator._fail_closed_for_test_v1()
    assert harness.termination_requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_transition", ["revoke", "replacement"])
async def test_control_transition_and_engine_retirement_dominate_paused_begin(
    authority_transition,
):
    (
        authority,
        principal,
        grant,
        _admission,
        engine,
        session,
    ) = _engine_bound_secure_session()
    coordinator = session._capture_coordinator_v1
    gate = session._normal_application_admission_v1
    assert coordinator is not None
    assert gate is not None
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_ARMED:
            reached.set()
            await release.wait()

    coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(coordinator.begin_capture_v1())
    await reached.wait()

    async def perform_control_transition() -> None:
        async with authority.serialized_transition():
            if authority_transition == "revoke":
                authority.revoke_session(
                    principal,
                    grant.session_id,
                    grant.session_capability,
                )
            else:
                authority.create_session(principal)
            await engine.retire_secure_session_v1(grant.session_id)

    retirement = asyncio.create_task(perform_control_transition())
    await _wait_for_destroyed(coordinator)
    assert not gate.is_open_v1()
    release.set()
    results = await asyncio.gather(
        begin,
        retirement,
        return_exceptions=True,
    )

    assert isinstance(results[0], CaptureTransitionRejectedV1)
    assert results[1] is None
    assert session.is_fully_quiesced_v1()
    assert grant.session_id not in engine.sessions
    assert gate.snapshot_v1().destroyed


@pytest.mark.asyncio
async def test_engine_retirement_during_end_cannot_reopen_normal_admission():
    (
        _authority,
        _principal,
        grant,
        _admission,
        engine,
        session,
    ) = _engine_bound_secure_session()
    coordinator = session._capture_coordinator_v1
    gate = session._normal_application_admission_v1
    assert coordinator is not None
    assert gate is not None
    capture_epoch = await coordinator.begin_capture_v1()
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.BEFORE_RESUME:
            reached.set()
            await release.wait()

    coordinator._set_transition_hook_for_test_v1(hook)
    ending = asyncio.create_task(coordinator.end_capture_v1(capture_epoch))
    await reached.wait()
    retirement = asyncio.create_task(engine.retire_secure_session_v1(grant.session_id))
    await _wait_for_destroyed(coordinator)
    assert not gate.is_open_v1()
    release.set()
    results = await asyncio.gather(
        ending,
        retirement,
        return_exceptions=True,
    )

    assert isinstance(results[0], CaptureTransitionRejectedV1)
    assert results[1] is None
    assert session.is_fully_quiesced_v1()
    assert grant.session_id not in engine.sessions
    assert gate.snapshot_v1().destroyed


@pytest.mark.asyncio
async def test_replacement_while_armed_destroys_old_coordinator():
    (
        authority,
        principal,
        grant,
        _admission,
        engine,
        session,
    ) = _engine_bound_secure_session()
    coordinator = session._capture_coordinator_v1
    gate = session._normal_application_admission_v1
    assert coordinator is not None
    assert gate is not None
    await coordinator.begin_capture_v1()

    async with authority.serialized_transition():
        replacement = authority.create_session(principal)
        await engine.retire_secure_session_v1(grant.session_id)

    assert replacement.session_id != grant.session_id
    assert coordinator.snapshot_v1().destroyed
    assert gate.snapshot_v1().destroyed
    assert not gate.is_open_v1()
    assert session.is_fully_quiesced_v1()
    assert grant.session_id not in engine.sessions


@pytest.mark.asyncio
async def test_engine_shutdown_while_armed_destroys_capture_authority():
    (
        _authority,
        _principal,
        grant,
        _admission,
        engine,
        session,
    ) = _engine_bound_secure_session()
    coordinator = session._capture_coordinator_v1
    gate = session._normal_application_admission_v1
    assert coordinator is not None
    assert gate is not None
    await coordinator.begin_capture_v1()

    await engine.retire_secure_session_v1(grant.session_id)

    assert coordinator.snapshot_v1().destroyed
    assert gate.snapshot_v1().destroyed
    assert not gate.is_open_v1()
    assert session.is_fully_quiesced_v1()
    assert grant.session_id not in engine.sessions


@pytest.mark.asyncio
async def test_cleanup_timeout_during_shutdown_never_reopens_admission(
    capture_harness_factory,
):
    harness = capture_harness_factory(cleanup_timeout_seconds=0.05)
    work = harness.runtime.register_root_work_v1(WorkOperationKindV1.TOOL_EXECUTION)
    reached = asyncio.Event()
    release = asyncio.Event()

    async def hook(point: CaptureTransitionPointV1) -> None:
        if point is CaptureTransitionPointV1.AFTER_QUIESCING:
            reached.set()
            await release.wait()

    harness.coordinator._set_transition_hook_for_test_v1(hook)
    begin = asyncio.create_task(harness.coordinator.begin_capture_v1())
    await reached.wait()
    shutdown_result = await harness.coordinator.shutdown_async_v1()
    release.set()
    results = await asyncio.gather(begin, return_exceptions=True)

    assert not shutdown_result
    assert isinstance(results[0], CaptureTransitionRejectedV1)
    assert harness.coordinator.snapshot_v1().destroyed
    assert not harness.gate.is_open_v1()
    assert harness.runtime.release_work_v1(work)

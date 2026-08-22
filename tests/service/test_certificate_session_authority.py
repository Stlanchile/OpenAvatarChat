from __future__ import annotations

import base64
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Lock

import pytest
from loguru import logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from service.service_security import certificate_session_authority
from service.service_security.certificate_session_authority import (
    ADMISSION_TICKET_DEFAULT_LIFETIME_SECONDS_V1,
    SESSION_CAPABILITY_RANDOM_BYTES_V1,
    SESSION_ID_RANDOM_BYTES_V1,
    SESSION_MAX_LIFETIME_SECONDS_V1,
    CertificateSessionAuthorityV1,
    SessionAdmissionChannelV1,
    SessionAuthorityErrorV1,
    SessionAuthorityReasonV1,
)
from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
)

NOW = 2_000_000_000.0
ISSUER = "https://issuer.example.test"


class FakeClock:
    def __init__(self, epoch: float = NOW, monotonic: float = 10_000.0):
        self.epoch = epoch
        self.monotonic = monotonic

    def wall_time(self) -> float:
        return self.epoch

    def monotonic_time(self) -> float:
        return self.monotonic

    def advance(self, seconds: float) -> None:
        self.epoch += seconds
        self.monotonic += seconds


class ScriptedRandom:
    def __init__(self, values: list[bytes]):
        self._values = list(values)
        self._lock = Lock()

    def __call__(self, requested_bytes: int) -> bytes:
        assert requested_bytes == 32
        with self._lock:
            if not self._values:
                raise AssertionError("unexpected random-material request")
            return self._values.pop(0)


def _principal(
    *,
    issuer: str = ISSUER,
    subject: str = "owner",
    token_expiry: float = NOW + 3600,
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
    selected_clock = clock if clock is not None else FakeClock()
    return CertificateSessionAuthorityV1(
        wall_clock=selected_clock.wall_time,
        monotonic_clock=selected_clock.monotonic_time,
    )


def _opaque_entropy(value: str, expected_prefix: str) -> bytes:
    assert value.startswith(expected_prefix)
    encoded = value[len(expected_prefix) :]
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def _assert_reason(
    exception: pytest.ExceptionInfo[SessionAuthorityErrorV1],
    reason: SessionAuthorityReasonV1,
) -> None:
    assert exception.value.reason_code == reason.value


def test_session_ids_are_server_random_unique_and_capabilities_are_independent():
    authority = _authority()
    grants = [
        authority.create_session(_principal(subject=f"owner-{index}"))
        for index in range(128)
    ]

    assert len({grant.session_id for grant in grants}) == len(grants)
    assert len({grant.session_capability for grant in grants}) == len(grants)
    for grant in grants:
        session_entropy = _opaque_entropy(grant.session_id, "cs1_")
        capability_entropy = _opaque_entropy(
            grant.session_capability,
            "csc1_",
        )
        assert len(session_entropy) == SESSION_ID_RANDOM_BYTES_V1 == 32
        assert len(capability_entropy) == SESSION_CAPABILITY_RANDOM_BYTES_V1 == 32
        assert session_entropy != capability_entropy


def test_session_id_collision_fails_closed_without_replacing_existing_session():
    random_bytes = ScriptedRandom(
        [
            b"\x01" * 32,
            b"\x02" * 32,
            b"\x03" * 32,
            b"\x04" * 32,
            b"\x03" * 32,
            b"\x05" * 32,
        ]
    )
    clock = FakeClock()
    authority = CertificateSessionAuthorityV1(
        random_bytes=random_bytes,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    first_owner = _principal(subject="first")
    first = authority.create_session(first_owner)

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.create_session(_principal(subject="second"))

    _assert_reason(exception, SessionAuthorityReasonV1.SESSION_ID_COLLISION)
    ownership = authority.get_session_ownership(
        first_owner,
        first.session_id,
        first.session_capability,
    )
    assert ownership.session_id == first.session_id


def test_ownership_contract_is_immutable_and_correct_owner_can_access():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)

    ownership = authority.get_session_ownership(
        principal,
        grant.session_id,
        grant.session_capability,
    )

    assert ownership.owner_issuer == principal.issuer
    assert ownership.owner_subject == principal.subject
    assert repr(ownership) == "SessionOwnershipV1(<redacted>)"
    with pytest.raises(FrozenInstanceError):
        ownership.owner_subject = "replacement"


@pytest.mark.parametrize(
    "other_principal",
    [
        _principal(
            issuer="https://other-issuer.example.test",
            subject="owner",
        ),
        _principal(subject="different-subject"),
    ],
)
def test_cross_principal_session_access_is_denied(other_principal):
    authority = _authority()
    grant = authority.create_session(_principal())

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.get_session_ownership(
            other_principal,
            grant.session_id,
            grant.session_capability,
        )

    _assert_reason(
        exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )


def test_guessed_session_id_and_guessed_capability_fail_identically():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    guessed_session = "cs1_" + base64.urlsafe_b64encode(b"\x71" * 32).rstrip(
        b"="
    ).decode("ascii")
    guessed_capability = "csc1_" + base64.urlsafe_b64encode(b"\x72" * 32).rstrip(
        b"="
    ).decode("ascii")

    failures = []
    for session_id, capability in (
        (guessed_session, grant.session_capability),
        (grant.session_id, guessed_capability),
        (grant.session_id, "not-a-capability"),
    ):
        with pytest.raises(SessionAuthorityErrorV1) as exception:
            authority.get_session_ownership(
                principal,
                session_id,
                capability,
            )
        failures.append(exception.value.reason_code)

    assert failures == [SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value] * 3


def test_capability_from_replaced_session_cannot_authorize_new_session():
    authority = _authority()
    principal = _principal()
    replaced = authority.create_session(principal)
    current = authority.create_session(principal)

    with pytest.raises(SessionAuthorityErrorV1) as old_session_exception:
        authority.get_session_ownership(
            principal,
            replaced.session_id,
            replaced.session_capability,
        )
    with pytest.raises(SessionAuthorityErrorV1) as mismatch_exception:
        authority.get_session_ownership(
            principal,
            current.session_id,
            replaced.session_capability,
        )

    _assert_reason(
        old_session_exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )
    _assert_reason(
        mismatch_exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )
    assert authority.snapshot().active_sessions == 1


def test_session_replacement_atomically_invalidates_outstanding_ticket():
    authority = _authority()
    principal = _principal()
    replaced = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        replaced.session_id,
        replaced.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )

    current = authority.create_session(principal)

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            principal,
            replaced.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )
    assert authority.snapshot().active_sessions == 1
    assert authority.snapshot().active_tickets == 0
    assert (
        authority.get_session_ownership(
            principal,
            current.session_id,
            current.session_capability,
        ).session_id
        == current.session_id
    )


def test_concurrent_session_replacements_leave_exactly_one_live_authority():
    authority = _authority()
    principal = _principal()

    with ThreadPoolExecutor(max_workers=16) as executor:
        grants = list(
            executor.map(
                lambda _: authority.create_session(principal),
                range(64),
            )
        )

    live_session_ids = []
    for grant in grants:
        try:
            authority.get_session_ownership(
                principal,
                grant.session_id,
                grant.session_capability,
            )
        except SessionAuthorityErrorV1 as exception:
            assert (
                exception.reason_code
                == SessionAuthorityReasonV1.SESSION_ACCESS_DENIED.value
            )
        else:
            live_session_ids.append(grant.session_id)

    assert len(live_session_ids) == 1
    assert authority.snapshot().active_sessions == 1


def test_authority_capacity_limits_fail_closed_and_release_on_cleanup(
    monkeypatch,
):
    monkeypatch.setattr(
        certificate_session_authority,
        "SESSION_AUTHORITY_MAX_ACTIVE_SESSIONS_V1",
        1,
    )
    monkeypatch.setattr(
        certificate_session_authority,
        "SESSION_AUTHORITY_MAX_ACTIVE_TICKETS_V1",
        1,
    )
    monkeypatch.setattr(
        certificate_session_authority,
        "SESSION_MAX_ACTIVE_TICKETS_V1",
        1,
    )
    authority = _authority()
    principal = _principal()
    first = authority.create_session(principal)

    with pytest.raises(SessionAuthorityErrorV1) as session_exception:
        authority.create_session(_principal(subject="other"))
    _assert_reason(
        session_exception,
        SessionAuthorityReasonV1.AUTHORITY_CAPACITY_EXCEEDED,
    )

    ticket = authority.issue_admission_ticket(
        principal,
        first.session_id,
        first.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    with pytest.raises(SessionAuthorityErrorV1) as ticket_exception:
        authority.issue_admission_ticket(
            principal,
            first.session_id,
            first.session_capability,
            SessionAdmissionChannelV1.RTC,
        )
    _assert_reason(
        ticket_exception,
        SessionAuthorityReasonV1.AUTHORITY_CAPACITY_EXCEEDED,
    )

    authority.consume_admission_ticket(
        principal,
        first.session_id,
        ticket.admission_ticket,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    replacement_ticket = authority.issue_admission_ticket(
        principal,
        first.session_id,
        first.session_capability,
        SessionAdmissionChannelV1.RTC,
    )
    assert replacement_ticket.channel is SessionAdmissionChannelV1.RTC


def test_session_lifetime_is_capped_and_truncated_by_token_expiry():
    clock = FakeClock()
    authority = _authority(clock)

    long_token = authority.create_session(
        _principal(subject="long", token_expiry=NOW + 10_000)
    )
    short_token = authority.create_session(
        _principal(subject="short", token_expiry=NOW + 47)
    )

    assert long_token.expires_at_epoch_seconds == NOW + SESSION_MAX_LIFETIME_SECONDS_V1
    assert short_token.expires_at_epoch_seconds == NOW + 47


def test_session_expiry_boundary_is_fail_closed():
    clock = FakeClock()
    authority = _authority(clock)
    principal = _principal(token_expiry=NOW + 30)
    grant = authority.create_session(principal)
    clock.advance(30)

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.get_session_ownership(
            principal,
            grant.session_id,
            grant.session_capability,
        )

    _assert_reason(
        exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )
    assert authority.snapshot().active_sessions == 0


def test_monotonic_clock_rollback_invalidates_session_authority():
    clock = FakeClock()
    authority = _authority(clock)
    principal = _principal()
    grant = authority.create_session(principal)
    clock.monotonic -= 1

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.get_session_ownership(
            principal,
            grant.session_id,
            grant.session_capability,
        )

    _assert_reason(
        exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )
    assert authority.snapshot().active_sessions == 0


def test_session_access_does_not_slide_or_renew_expiry():
    clock = FakeClock()
    authority = _authority(clock)
    principal = _principal(token_expiry=NOW + 10_000)
    grant = authority.create_session(principal)
    original_expiry = grant.expires_at_epoch_seconds

    for seconds in (100, 200, 300):
        clock.advance(seconds)
        ownership = authority.get_session_ownership(
            principal,
            grant.session_id,
            grant.session_capability,
        )
        assert ownership.expires_at_epoch_seconds == original_expiry

    clock.advance(original_expiry - clock.epoch)
    with pytest.raises(SessionAuthorityErrorV1):
        authority.get_session_ownership(
            principal,
            grant.session_id,
            grant.session_capability,
        )


def test_expired_parent_principal_cannot_create_or_extend_authority():
    clock = FakeClock()
    authority = _authority(clock)

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.create_session(
            _principal(token_expiry=NOW),
        )

    _assert_reason(
        exception,
        SessionAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED,
    )
    assert authority.snapshot().active_sessions == 0


def test_session_revocation_invalidates_capability_and_outstanding_ticket():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )

    authority.revoke_session(
        principal,
        grant.session_id,
        grant.session_capability,
    )

    with pytest.raises(SessionAuthorityErrorV1) as session_exception:
        authority.get_session_ownership(
            principal,
            grant.session_id,
            grant.session_capability,
        )
    with pytest.raises(SessionAuthorityErrorV1) as ticket_exception:
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        )
    _assert_reason(
        session_exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )
    _assert_reason(
        ticket_exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )
    assert authority.snapshot().active_tickets == 0


def test_ticket_is_one_use_and_replay_always_fails():
    authority = _authority()
    principal = _principal()
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
    assert admission.session_id == grant.session_id
    assert admission.ticket_id == ticket.ticket_id
    assert admission.owner_issuer == principal.issuer
    assert admission.owner_subject == principal.subject
    with pytest.raises(FrozenInstanceError):
        ticket.channel = SessionAdmissionChannelV1.RTC
    with pytest.raises(FrozenInstanceError):
        admission.owner_subject = "replacement"

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )


def test_ticket_ids_and_opaque_tokens_are_unique_256_bit_values():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)

    tickets = [
        authority.issue_admission_ticket(
            principal,
            grant.session_id,
            grant.session_capability,
            SessionAdmissionChannelV1.WEBSOCKET,
        )
        for _ in range(32)
    ]

    assert len({ticket.ticket_id for ticket in tickets}) == len(tickets)
    assert len({ticket.admission_ticket for ticket in tickets}) == len(tickets)
    for ticket in tickets:
        assert len(_opaque_entropy(ticket.ticket_id, "ati1_")) == 32
        assert len(_opaque_entropy(ticket.admission_ticket, "att1_")) == 32


def test_ticket_session_mismatch_does_not_consume_correct_session_ticket():
    authority = _authority()
    owner = _principal()
    owner_session = authority.create_session(owner)
    other_session = authority.create_session(_principal(subject="other"))
    ticket = authority.issue_admission_ticket(
        owner,
        owner_session.session_id,
        owner_session.session_capability,
        SessionAdmissionChannelV1.RTC,
    )

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            owner,
            other_session.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.RTC,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )

    admission = authority.consume_admission_ticket(
        owner,
        owner_session.session_id,
        ticket.admission_ticket,
        SessionAdmissionChannelV1.RTC,
    )
    assert admission.ticket_id == ticket.ticket_id


def test_concurrent_ticket_double_consume_allows_exactly_one_success():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.RTC,
    )

    def consume() -> str:
        try:
            authority.consume_admission_ticket(
                principal,
                grant.session_id,
                ticket.admission_ticket,
                SessionAdmissionChannelV1.RTC,
            )
        except SessionAuthorityErrorV1 as exception:
            return exception.reason_code
        return "SUCCESS"

    with ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(lambda _: consume(), range(64)))

    assert outcomes.count("SUCCESS") == 1
    assert outcomes.count(SessionAuthorityReasonV1.TICKET_ACCESS_DENIED.value) == 63


def test_wrong_channel_does_not_consume_ticket_for_correct_channel():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.RTC,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )

    assert (
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        ).channel
        is SessionAdmissionChannelV1.WEBSOCKET
    )


def test_ticket_expiry_boundary_is_sixty_seconds_and_fail_closed():
    clock = FakeClock()
    authority = _authority(clock)
    principal = _principal()
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.RTC,
    )
    assert (
        ticket.expires_at_epoch_seconds
        == NOW + ADMISSION_TICKET_DEFAULT_LIFETIME_SECONDS_V1
    )
    clock.advance(ADMISSION_TICKET_DEFAULT_LIFETIME_SECONDS_V1)

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.RTC,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )
    assert authority.snapshot().active_tickets == 0


def test_ticket_lifetime_is_truncated_by_session_and_current_token_expiry():
    clock = FakeClock()
    authority = _authority(clock)
    principal = _principal(token_expiry=NOW + 25)
    grant = authority.create_session(principal)

    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )

    assert ticket.expires_at_epoch_seconds == NOW + 25
    assert ticket.expires_at_epoch_seconds <= grant.expires_at_epoch_seconds


def test_wrong_principal_ticket_attempt_does_not_consume_owner_ticket():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            _principal(subject="other"),
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )
    assert (
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.WEBSOCKET,
        ).ticket_id
        == ticket.ticket_id
    )


def test_session_revoked_between_ticket_issue_and_consume_fails():
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.RTC,
    )
    authority.revoke_session(
        principal,
        grant.session_id,
        grant.session_capability,
    )

    with pytest.raises(SessionAuthorityErrorV1) as exception:
        authority.consume_admission_ticket(
            principal,
            grant.session_id,
            ticket.admission_ticket,
            SessionAdmissionChannelV1.RTC,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.TICKET_ACCESS_DENIED,
    )


def test_explicit_cleanup_and_process_restart_remove_all_authority():
    clock = FakeClock()
    authority = _authority(clock)
    grants = []
    for subject in ("one", "two"):
        principal = _principal(subject=subject)
        grant = authority.create_session(principal)
        authority.issue_admission_ticket(
            principal,
            grant.session_id,
            grant.session_capability,
            SessionAdmissionChannelV1.WEBSOCKET,
        )
        grants.append((principal, grant))

    clock.advance(SESSION_MAX_LIFETIME_SECONDS_V1)
    cleanup = authority.cleanup_expired()
    assert cleanup.removed_sessions == 2
    assert cleanup.removed_tickets == 2
    assert authority.snapshot().active_sessions == 0
    assert authority.snapshot().active_tickets == 0

    old_principal, old_grant = grants[0]
    restarted = _authority(clock)
    with pytest.raises(SessionAuthorityErrorV1) as exception:
        restarted.get_session_ownership(
            old_principal,
            old_grant.session_id,
            old_grant.session_capability,
        )
    _assert_reason(
        exception,
        SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
    )

    authority.close()
    assert authority.snapshot().closed is True
    with pytest.raises(SessionAuthorityErrorV1) as closed_exception:
        authority.create_session(_principal())
    _assert_reason(
        closed_exception,
        SessionAuthorityReasonV1.AUTHORITY_CLOSED,
    )


def test_capability_validation_uses_constant_time_digest_comparison(monkeypatch):
    authority = _authority()
    principal = _principal()
    grant = authority.create_session(principal)
    compare_calls: list[tuple[int, int]] = []
    real_compare_digest = certificate_session_authority.hmac.compare_digest

    def recording_compare_digest(left, right):
        compare_calls.append((len(left), len(right)))
        return real_compare_digest(left, right)

    monkeypatch.setattr(
        certificate_session_authority.hmac,
        "compare_digest",
        recording_compare_digest,
    )

    with pytest.raises(SessionAuthorityErrorV1):
        authority.get_session_ownership(
            principal,
            grant.session_id,
            "csc1_" + "A" * 43,
        )

    assert compare_calls
    assert all(
        left_length == right_length for left_length, right_length in compare_calls
    )
    assert any(left_length == 32 for left_length, _ in compare_calls)


def test_authority_reprs_errors_and_logs_redact_principal_and_secret_canaries():
    issuer_canary = "https://issuer-canary.example.test"
    subject_canary = "subject-canary-value"
    principal = _principal(
        issuer=issuer_canary,
        subject=subject_canary,
    )
    authority = _authority()
    grant = authority.create_session(principal)
    ownership = authority.get_session_ownership(
        principal,
        grant.session_id,
        grant.session_capability,
    )
    ticket = authority.issue_admission_ticket(
        principal,
        grant.session_id,
        grant.session_capability,
        SessionAdmissionChannelV1.WEBSOCKET,
    )
    with pytest.raises(SessionAuthorityErrorV1) as failure:
        authority.get_session_ownership(
            principal,
            grant.session_id,
            "wrong-capability-canary",
        )

    log_messages: list[str] = []
    sink_id = logger.add(log_messages.append, format="{message}")
    try:
        logger.error("{}", ownership)
        logger.error("{}", grant)
        logger.error("{}", ticket)
        logger.error("{}", failure.value)
    finally:
        logger.remove(sink_id)

    visible_output = "".join(
        [
            repr(ownership),
            repr(grant),
            repr(ticket),
            str(failure.value),
            repr(failure.value),
            *log_messages,
        ]
    )
    canaries = [
        issuer_canary,
        subject_canary,
        grant.session_id,
        grant.session_capability,
        ticket.ticket_id,
        ticket.admission_ticket,
        "wrong-capability-canary",
    ]
    assert all(canary not in visible_output for canary in canaries)

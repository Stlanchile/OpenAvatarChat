from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum

from service.service_security.oidc_resource_server import (
    AuthenticatedPrincipalV1,
)

SESSION_ID_RANDOM_BYTES_V1 = 32
SESSION_CAPABILITY_RANDOM_BYTES_V1 = 32
ADMISSION_TICKET_RANDOM_BYTES_V1 = 32
SESSION_MAX_LIFETIME_SECONDS_V1 = 15 * 60
ADMISSION_TICKET_DEFAULT_LIFETIME_SECONDS_V1 = 60
SESSION_AUTHORITY_MAX_ACTIVE_SESSIONS_V1 = 4096
SESSION_AUTHORITY_MAX_ACTIVE_TICKETS_V1 = 16_384
SESSION_MAX_ACTIVE_TICKETS_V1 = 64

_SESSION_ID_PREFIX_V1 = "cs1_"
_SESSION_CAPABILITY_PREFIX_V1 = "csc1_"
_ADMISSION_TICKET_ID_PREFIX_V1 = "ati1_"
_ADMISSION_TICKET_PREFIX_V1 = "att1_"
_OPAQUE_VALUE_ENCODED_CHARACTERS_V1 = 43
_OPAQUE_VALUE_PATTERN_V1 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_ISSUER_UTF8_BYTES_V1 = 4096
_MAX_SUBJECT_UTF8_BYTES_V1 = 4096
_MAX_TICKET_SEQUENCE_V1 = (1 << 128) - 1


class SessionAdmissionChannelV1(str, Enum):
    """Transport purposes reserved for a later admission integration."""

    WEBSOCKET = "websocket"
    RTC = "rtc"


class SessionAuthorityReasonV1(str, Enum):
    PARENT_AUTHORIZATION_INVALID = "PARENT_AUTHORIZATION_INVALID"
    PARENT_AUTHORIZATION_EXPIRED = "PARENT_AUTHORIZATION_EXPIRED"
    SESSION_ACCESS_DENIED = "SESSION_ACCESS_DENIED"
    TICKET_ACCESS_DENIED = "TICKET_ACCESS_DENIED"
    ADMISSION_CHANNEL_INVALID = "ADMISSION_CHANNEL_INVALID"
    SESSION_ID_COLLISION = "SESSION_ID_COLLISION"
    TICKET_ID_COLLISION = "TICKET_ID_COLLISION"
    SECRET_MATERIAL_COLLISION = "SECRET_MATERIAL_COLLISION"
    AUTHORITY_CAPACITY_EXCEEDED = "AUTHORITY_CAPACITY_EXCEEDED"
    AUTHORITY_UNAVAILABLE = "AUTHORITY_UNAVAILABLE"
    AUTHORITY_CLOSED = "AUTHORITY_CLOSED"


class SessionAuthorityErrorV1(RuntimeError):
    """A stable, value-free certificate-session authority failure."""

    __slots__ = ("reason_code",)

    def __init__(self, reason: SessionAuthorityReasonV1):
        self.reason_code = reason.value
        super().__init__(
            f"Certificate session authority rejected the operation "
            f"({self.reason_code})."
        )


@dataclass(frozen=True, slots=True, repr=False)
class SessionOwnershipV1:
    """Immutable server-issued session identity and validated owner binding."""

    session_id: str
    owner_issuer: str
    owner_subject: str
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "SessionOwnershipV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SessionCapabilityGrantV1:
    """The one-time response containing a new session capability."""

    session_id: str
    session_capability: str
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "SessionCapabilityGrantV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AdmissionTicketGrantV1:
    """The one-time response containing a channel-bound admission ticket."""

    session_id: str
    ticket_id: str
    admission_ticket: str
    channel: SessionAdmissionChannelV1
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "AdmissionTicketGrantV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ConsumedSessionAdmissionV1:
    """Principal/session binding returned only by the internal consume seam."""

    session_id: str
    ticket_id: str
    owner_issuer: str
    owner_subject: str
    channel: SessionAdmissionChannelV1
    admitted_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "ConsumedSessionAdmissionV1(<redacted>)"


def session_admission_ownership_matches_v1(
    established: object,
    candidate: ConsumedSessionAdmissionV1,
) -> bool:
    """Compare immutable authority-owned session and principal identity."""

    return (
        isinstance(established, ConsumedSessionAdmissionV1)
        and established.session_id == candidate.session_id
        and established.owner_issuer == candidate.owner_issuer
        and established.owner_subject == candidate.owner_subject
    )


@dataclass(frozen=True, slots=True)
class SessionAuthorityCleanupV1:
    removed_sessions: int
    removed_tickets: int


@dataclass(frozen=True, slots=True)
class SessionAuthoritySnapshotV1:
    active_sessions: int
    active_tickets: int
    closed: bool


@dataclass(slots=True, repr=False)
class _SessionAuthorityStateV1:
    ownership: SessionOwnershipV1
    owner_digest: bytes
    capability_digest: bytes
    issued_at_monotonic: float
    expires_at_monotonic: float
    ticket_digests: set[bytes] = field(default_factory=set)


@dataclass(frozen=True, slots=True, repr=False)
class _AdmissionTicketStateV1:
    ticket_id: str
    ticket_digest: bytes
    session_id: str
    owner_digest: bytes
    channel: SessionAdmissionChannelV1
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float
    issued_at_monotonic: float
    expires_at_monotonic: float


class CertificateSessionAuthorityV1:
    """Process-local authority for certificate sessions and admissions."""

    __slots__ = (
        "_closed",
        "_digest_key",
        "_dummy_capability_digest",
        "_dummy_owner_digest",
        "_issued_session_ids",
        "_issued_ticket_ids",
        "_lock",
        "_monotonic_clock",
        "_random_bytes",
        "_session_ids_by_owner",
        "_sessions",
        "_ticket_key",
        "_ticket_sequence",
        "_tickets",
        "_transition_active",
        "_transition_lock",
        "_transition_owner_task",
        "_wall_clock",
    )

    def __init__(
        self,
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ):
        self._random_bytes = random_bytes
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._lock = threading.RLock()
        self._transition_lock = asyncio.Lock()
        self._transition_active = False
        self._transition_owner_task: asyncio.Task[object] | None = None
        self._closed = False
        self._sessions: dict[str, _SessionAuthorityStateV1] = {}
        self._session_ids_by_owner: dict[bytes, str] = {}
        self._tickets: dict[bytes, _AdmissionTicketStateV1] = {}
        self._issued_session_ids: set[str] = set()
        self._issued_ticket_ids: set[str] = set()
        self._ticket_sequence = 0

        self._digest_key = self._generate_random_material()
        self._ticket_key = self._generate_random_material()
        if hmac.compare_digest(self._digest_key, self._ticket_key):
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.SECRET_MATERIAL_COLLISION
            )
        self._dummy_capability_digest = self._secret_digest(
            b"certificate-session-capability-v1",
            bytes(SESSION_CAPABILITY_RANDOM_BYTES_V1),
        )
        self._dummy_owner_digest = self._secret_digest(
            b"certificate-session-owner-v1",
            b"",
        )

    @asynccontextmanager
    async def serialized_transition(self) -> AsyncIterator[None]:
        """Serialize admission commit with create/revoke control transitions."""

        async with self._transition_lock:
            owner_task = asyncio.current_task()
            if owner_task is None:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
                )
            with self._lock:
                self._ensure_open_locked()
                if self._transition_active:
                    raise SessionAuthorityErrorV1(
                        SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
                    )
                self._transition_active = True
                self._transition_owner_task = owner_task
            try:
                yield
            finally:
                with self._lock:
                    if self._transition_owner_task is owner_task:
                        self._transition_owner_task = None
                        self._transition_active = False

    def create_session(
        self,
        principal: AuthenticatedPrincipalV1,
    ) -> SessionCapabilityGrantV1:
        """Create a new session and atomically replace this owner's old session."""

        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)
            owner_material = self._validated_owner_material(
                principal,
                SessionAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID,
            )
            token_expiry = self._validated_token_expiry(
                principal,
                SessionAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID,
            )
            if token_expiry <= now_epoch:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED
                )

            session_entropy = self._generate_random_material()
            capability_entropy = self._generate_random_material()
            if hmac.compare_digest(session_entropy, capability_entropy):
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.SECRET_MATERIAL_COLLISION
                )

            session_id = _encode_opaque_value(
                _SESSION_ID_PREFIX_V1,
                session_entropy,
            )
            if session_id in self._sessions:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.SESSION_ID_COLLISION
                )

            session_capability = _encode_opaque_value(
                _SESSION_CAPABILITY_PREFIX_V1,
                capability_entropy,
            )
            owner_digest = self._owner_digest(owner_material)
            expires_at_epoch = min(
                token_expiry,
                now_epoch + SESSION_MAX_LIFETIME_SECONDS_V1,
            )
            lifetime = expires_at_epoch - now_epoch
            if lifetime <= 0:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED
                )

            ownership = SessionOwnershipV1(
                session_id=session_id,
                owner_issuer=principal.issuer,
                owner_subject=principal.subject,
                issued_at_epoch_seconds=now_epoch,
                expires_at_epoch_seconds=expires_at_epoch,
            )
            new_state = _SessionAuthorityStateV1(
                ownership=ownership,
                owner_digest=owner_digest,
                capability_digest=self._secret_digest(
                    b"certificate-session-capability-v1",
                    capability_entropy,
                ),
                issued_at_monotonic=now_monotonic,
                expires_at_monotonic=now_monotonic + lifetime,
            )

            previous_session_id = self._session_ids_by_owner.get(owner_digest)
            if (
                previous_session_id is None
                and len(self._sessions) >= SESSION_AUTHORITY_MAX_ACTIVE_SESSIONS_V1
            ):
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.AUTHORITY_CAPACITY_EXCEEDED
                )
            if previous_session_id is not None:
                previous_state = self._sessions.get(previous_session_id)
                if (
                    previous_state is None
                    or previous_state.ownership.owner_issuer != principal.issuer
                    or previous_state.ownership.owner_subject != principal.subject
                ):
                    raise SessionAuthorityErrorV1(
                        SessionAuthorityReasonV1.SECRET_MATERIAL_COLLISION
                    )
                self._remove_session_locked(previous_session_id)

            self._sessions[session_id] = new_state
            self._session_ids_by_owner[owner_digest] = session_id
            self._issued_session_ids.add(session_id)
            return SessionCapabilityGrantV1(
                session_id=session_id,
                session_capability=session_capability,
                issued_at_epoch_seconds=now_epoch,
                expires_at_epoch_seconds=expires_at_epoch,
            )

    def get_session_ownership(
        self,
        principal: AuthenticatedPrincipalV1,
        session_id: str,
        session_capability: str,
    ) -> SessionOwnershipV1:
        """Authorize an owner/capability pair without extending its lifetime."""

        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)
            state = self._authorize_session_locked(
                principal,
                session_id,
                session_capability,
                now_epoch,
            )
            return state.ownership

    def issue_admission_ticket(
        self,
        principal: AuthenticatedPrincipalV1,
        session_id: str,
        session_capability: str,
        channel: SessionAdmissionChannelV1 | str,
    ) -> AdmissionTicketGrantV1:
        """Issue one opaque, one-use admission ticket for a fixed channel."""

        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)
            state = self._authorize_session_locked(
                principal,
                session_id,
                session_capability,
                now_epoch,
            )
            validated_channel = _validated_channel(channel)
            token_expiry = self._validated_token_expiry(
                principal,
                SessionAuthorityReasonV1.SESSION_ACCESS_DENIED,
            )
            expires_at_epoch = min(
                state.ownership.expires_at_epoch_seconds,
                token_expiry,
                now_epoch + ADMISSION_TICKET_DEFAULT_LIFETIME_SECONDS_V1,
            )
            lifetime = expires_at_epoch - now_epoch
            if lifetime <= 0:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.SESSION_ACCESS_DENIED
                )
            if (
                len(state.ticket_digests) >= SESSION_MAX_ACTIVE_TICKETS_V1
                or len(self._tickets) >= SESSION_AUTHORITY_MAX_ACTIVE_TICKETS_V1
            ):
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.AUTHORITY_CAPACITY_EXCEEDED
                )

            ticket_id_entropy = self._generate_random_material()
            ticket_id = _encode_opaque_value(
                _ADMISSION_TICKET_ID_PREFIX_V1,
                ticket_id_entropy,
            )
            if ticket_id in self._issued_ticket_ids:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.TICKET_ID_COLLISION
                )
            if self._ticket_sequence >= _MAX_TICKET_SEQUENCE_V1:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.AUTHORITY_CAPACITY_EXCEEDED
                )
            ticket_nonce = self._generate_random_material()
            next_sequence = self._ticket_sequence + 1
            ticket_entropy = hmac.new(
                self._ticket_key,
                (
                    b"certificate-session-admission-ticket-v1"
                    + next_sequence.to_bytes(16, "big")
                    + ticket_id_entropy
                    + ticket_nonce
                ),
                hashlib.sha256,
            ).digest()
            admission_ticket = _encode_opaque_value(
                _ADMISSION_TICKET_PREFIX_V1,
                ticket_entropy,
            )
            ticket_digest = self._secret_digest(
                b"certificate-session-admission-ticket-digest-v1",
                ticket_entropy,
            )
            if ticket_digest in self._tickets:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.SECRET_MATERIAL_COLLISION
                )

            ticket_state = _AdmissionTicketStateV1(
                ticket_id=ticket_id,
                ticket_digest=ticket_digest,
                session_id=session_id,
                owner_digest=state.owner_digest,
                channel=validated_channel,
                issued_at_epoch_seconds=now_epoch,
                expires_at_epoch_seconds=expires_at_epoch,
                issued_at_monotonic=now_monotonic,
                expires_at_monotonic=min(
                    state.expires_at_monotonic,
                    now_monotonic + lifetime,
                ),
            )
            self._ticket_sequence = next_sequence
            self._tickets[ticket_digest] = ticket_state
            state.ticket_digests.add(ticket_digest)
            self._issued_ticket_ids.add(ticket_id)
            return AdmissionTicketGrantV1(
                session_id=session_id,
                ticket_id=ticket_id,
                admission_ticket=admission_ticket,
                channel=validated_channel,
                issued_at_epoch_seconds=now_epoch,
                expires_at_epoch_seconds=expires_at_epoch,
            )

    def consume_admission_ticket(
        self,
        principal: AuthenticatedPrincipalV1,
        session_id: str,
        admission_ticket: str,
        channel: SessionAdmissionChannelV1 | str,
    ) -> ConsumedSessionAdmissionV1:
        """Atomically consume a ticket; this is intentionally not an HTTP API."""

        return self._consume_admission_ticket(
            principal=principal,
            session_id=session_id,
            admission_ticket=admission_ticket,
            channel=channel,
        )

    def consume_websocket_admission_ticket(
        self,
        session_id: str,
        admission_ticket: str,
    ) -> ConsumedSessionAdmissionV1:
        """Consume a WebSocket ticket using only server-owned authority state.

        The ticket is a short-lived bearer capability issued only after OIDC,
        capability, owner, and session validation. WebSocket admission therefore
        does not require a second access-token credential in the handshake.
        """

        return self._consume_admission_ticket(
            principal=None,
            session_id=session_id,
            admission_ticket=admission_ticket,
            channel=SessionAdmissionChannelV1.WEBSOCKET,
        )

    def validate_consumed_session_admission(
        self,
        admission: ConsumedSessionAdmissionV1,
        *,
        channel: SessionAdmissionChannelV1 | str,
        principal: AuthenticatedPrincipalV1 | None = None,
    ) -> SessionOwnershipV1:
        """Validate that a trusted consumed admission still names live authority.

        Consumed tickets are intentionally not restored or retained. This seam
        checks the immutable admission against the current Milestone 1C session
        lifecycle so a later transport-to-application transition cannot attach
        after revocation, replacement, or expiry.
        """

        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)

            try:
                validated_channel = SessionAdmissionChannelV1(channel)
            except (TypeError, ValueError):
                validated_channel = None

            state = (
                self._sessions.get(admission.session_id)
                if isinstance(admission, ConsumedSessionAdmissionV1)
                else None
            )
            admission_matches = (
                state is not None
                and validated_channel is not None
                and admission.channel is validated_channel
                and state.ownership.owner_issuer == admission.owner_issuer
                and state.ownership.owner_subject == admission.owner_subject
            )

            principal_matches = True
            if principal is not None:
                owner_material = self._owner_material_or_none(principal)
                principal_expiry = self._token_expiry_or_none(principal)
                principal_matches = (
                    state is not None
                    and owner_material is not None
                    and principal_expiry is not None
                    and principal_expiry > now_epoch
                    and state.ownership.owner_issuer
                    == getattr(principal, "issuer", None)
                    and state.ownership.owner_subject
                    == getattr(principal, "subject", None)
                    and hmac.compare_digest(
                        state.owner_digest,
                        self._owner_digest(owner_material),
                    )
                )

            if not admission_matches or not principal_matches:
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.TICKET_ACCESS_DENIED
                )
            return state.ownership

    def _consume_admission_ticket(
        self,
        *,
        principal: AuthenticatedPrincipalV1 | None,
        session_id: str,
        admission_ticket: str,
        channel: SessionAdmissionChannelV1 | str,
    ) -> ConsumedSessionAdmissionV1:
        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)

            owner_material = (
                self._owner_material_or_none(principal)
                if principal is not None
                else None
            )
            owner_digest = (
                self._owner_digest(owner_material)
                if owner_material is not None
                else self._dummy_owner_digest
            )
            principal_expiry = (
                self._token_expiry_or_none(principal)
                if principal is not None
                else None
            )
            ticket_entropy = _decode_opaque_value(
                _ADMISSION_TICKET_PREFIX_V1,
                admission_ticket,
            )
            ticket_digest = (
                self._secret_digest(
                    b"certificate-session-admission-ticket-digest-v1",
                    ticket_entropy,
                )
                if ticket_entropy is not None
                else self._dummy_capability_digest
            )
            ticket_state = self._tickets.get(ticket_digest)
            session_state = self._sessions.get(session_id)
            candidate_owner_digest = (
                ticket_state.owner_digest
                if ticket_state is not None
                else self._dummy_owner_digest
            )
            owner_matches = hmac.compare_digest(
                candidate_owner_digest,
                owner_digest,
            )
            exact_owner_matches = (
                principal is not None
                and session_state is not None
                and session_state.ownership.owner_issuer
                == getattr(principal, "issuer", None)
                and session_state.ownership.owner_subject
                == getattr(principal, "subject", None)
            )
            session_matches = (
                ticket_state is not None
                and ticket_state.session_id == session_id
                and session_state is not None
                and hmac.compare_digest(
                    ticket_state.owner_digest,
                    session_state.owner_digest,
                )
            )
            try:
                validated_channel = SessionAdmissionChannelV1(channel)
            except (TypeError, ValueError):
                validated_channel = None
            channel_matches = (
                ticket_state is not None
                and validated_channel is not None
                and ticket_state.channel is validated_channel
            )
            principal_is_current = (
                principal is None
                or (
                    principal_expiry is not None
                    and principal_expiry > now_epoch
                )
            )
            owner_authorized = (
                session_matches
                if principal is None
                else (
                    owner_material is not None
                    and owner_matches
                    and exact_owner_matches
                )
            )

            if not (
                ticket_entropy is not None
                and ticket_state is not None
                and session_matches
                and owner_authorized
                and channel_matches
                and principal_is_current
            ):
                raise SessionAuthorityErrorV1(
                    SessionAuthorityReasonV1.TICKET_ACCESS_DENIED
                )

            self._remove_ticket_locked(ticket_digest)
            ownership = session_state.ownership
            return ConsumedSessionAdmissionV1(
                session_id=session_id,
                ticket_id=ticket_state.ticket_id,
                owner_issuer=ownership.owner_issuer,
                owner_subject=ownership.owner_subject,
                channel=ticket_state.channel,
                admitted_at_epoch_seconds=now_epoch,
            )

    def revoke_session(
        self,
        principal: AuthenticatedPrincipalV1,
        session_id: str,
        session_capability: str,
    ) -> None:
        """Explicitly revoke a session and every outstanding ticket."""

        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)
            self._authorize_session_locked(
                principal,
                session_id,
                session_capability,
                now_epoch,
            )
            self._remove_session_locked(session_id)

    def cleanup_expired(self) -> SessionAuthorityCleanupV1:
        """Opportunistically remove expired authority without background work."""

        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            return self._cleanup_expired_locked(now_epoch, now_monotonic)

    def snapshot(self) -> SessionAuthoritySnapshotV1:
        """Return only non-sensitive counts for tests and operational wiring."""

        with self._lock:
            return SessionAuthoritySnapshotV1(
                active_sessions=len(self._sessions),
                active_tickets=len(self._tickets),
                closed=self._closed,
            )

    def close(self) -> None:
        """Destroy all process-local authorization state and close the service."""

        with self._lock:
            self._ensure_transition_access_locked()
            for session_id in tuple(self._sessions):
                self._remove_session_locked(session_id)
            self._sessions.clear()
            self._session_ids_by_owner.clear()
            self._tickets.clear()
            self._issued_session_ids.clear()
            self._issued_ticket_ids.clear()
            self._digest_key = bytes(len(self._digest_key))
            self._ticket_key = bytes(len(self._ticket_key))
            self._dummy_capability_digest = bytes(len(self._dummy_capability_digest))
            self._dummy_owner_digest = bytes(len(self._dummy_owner_digest))
            self._closed = True

    def _authorize_session_locked(
        self,
        principal: AuthenticatedPrincipalV1,
        session_id: str,
        session_capability: str,
        now_epoch: float,
    ) -> _SessionAuthorityStateV1:
        owner_material = self._owner_material_or_none(principal)
        owner_digest = (
            self._owner_digest(owner_material)
            if owner_material is not None
            else self._dummy_owner_digest
        )
        capability_entropy = _decode_opaque_value(
            _SESSION_CAPABILITY_PREFIX_V1,
            session_capability,
        )
        presented_capability_digest = (
            self._secret_digest(
                b"certificate-session-capability-v1",
                capability_entropy,
            )
            if capability_entropy is not None
            else self._dummy_capability_digest
        )
        state = self._sessions.get(session_id)
        expected_capability_digest = (
            state.capability_digest
            if state is not None
            else self._dummy_capability_digest
        )
        expected_owner_digest = (
            state.owner_digest if state is not None else self._dummy_owner_digest
        )
        capability_matches = hmac.compare_digest(
            expected_capability_digest,
            presented_capability_digest,
        )
        owner_matches = hmac.compare_digest(
            expected_owner_digest,
            owner_digest,
        )
        exact_owner_matches = (
            state is not None
            and state.ownership.owner_issuer == getattr(principal, "issuer", None)
            and state.ownership.owner_subject == getattr(principal, "subject", None)
        )
        principal_expiry = self._token_expiry_or_none(principal)
        principal_is_current = (
            principal_expiry is not None and principal_expiry > now_epoch
        )

        if not (
            state is not None
            and owner_material is not None
            and capability_entropy is not None
            and capability_matches
            and owner_matches
            and exact_owner_matches
            and principal_is_current
        ):
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.SESSION_ACCESS_DENIED
            )
        return state

    def _cleanup_expired_locked(
        self,
        now_epoch: float,
        now_monotonic: float,
    ) -> SessionAuthorityCleanupV1:
        removed_sessions = 0
        removed_tickets = 0
        for session_id, state in tuple(self._sessions.items()):
            if _deadline_reached(
                now_epoch,
                now_monotonic,
                state.ownership.expires_at_epoch_seconds,
                state.issued_at_monotonic,
                state.expires_at_monotonic,
            ):
                removed_tickets += len(state.ticket_digests)
                self._remove_session_locked(session_id)
                removed_sessions += 1

        for ticket_digest, ticket_state in tuple(self._tickets.items()):
            if ticket_state.session_id not in self._sessions or _deadline_reached(
                now_epoch,
                now_monotonic,
                ticket_state.expires_at_epoch_seconds,
                ticket_state.issued_at_monotonic,
                ticket_state.expires_at_monotonic,
            ):
                self._remove_ticket_locked(ticket_digest)
                removed_tickets += 1
        return SessionAuthorityCleanupV1(
            removed_sessions=removed_sessions,
            removed_tickets=removed_tickets,
        )

    def _remove_session_locked(self, session_id: str) -> None:
        state = self._sessions.pop(session_id, None)
        if state is None:
            return
        self._issued_session_ids.discard(session_id)
        if self._session_ids_by_owner.get(state.owner_digest) == session_id:
            del self._session_ids_by_owner[state.owner_digest]
        for ticket_digest in tuple(state.ticket_digests):
            self._remove_ticket_locked(ticket_digest)
        state.ticket_digests.clear()

    def _remove_ticket_locked(self, ticket_digest: bytes) -> None:
        ticket_state = self._tickets.pop(ticket_digest, None)
        if ticket_state is None:
            return
        self._issued_ticket_ids.discard(ticket_state.ticket_id)
        session_state = self._sessions.get(ticket_state.session_id)
        if session_state is not None:
            session_state.ticket_digests.discard(ticket_digest)

    def _validated_owner_material(
        self,
        principal: AuthenticatedPrincipalV1,
        reason: SessionAuthorityReasonV1,
    ) -> bytes:
        owner_material = self._owner_material_or_none(principal)
        if owner_material is None:
            raise SessionAuthorityErrorV1(reason)
        return owner_material

    @staticmethod
    def _owner_material_or_none(
        principal: AuthenticatedPrincipalV1,
    ) -> bytes | None:
        issuer = getattr(principal, "issuer", None)
        subject = getattr(principal, "subject", None)
        if not isinstance(issuer, str) or not isinstance(subject, str):
            return None
        try:
            issuer_bytes = issuer.encode("utf-8", errors="strict")
            subject_bytes = subject.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return None
        if (
            not issuer_bytes
            or not subject_bytes
            or len(issuer_bytes) > _MAX_ISSUER_UTF8_BYTES_V1
            or len(subject_bytes) > _MAX_SUBJECT_UTF8_BYTES_V1
        ):
            return None
        return (
            len(issuer_bytes).to_bytes(4, "big")
            + issuer_bytes
            + len(subject_bytes).to_bytes(4, "big")
            + subject_bytes
        )

    def _owner_digest(self, owner_material: bytes) -> bytes:
        return self._secret_digest(
            b"certificate-session-owner-v1",
            owner_material,
        )

    def _validated_token_expiry(
        self,
        principal: AuthenticatedPrincipalV1,
        reason: SessionAuthorityReasonV1,
    ) -> float:
        token_expiry = self._token_expiry_or_none(principal)
        if token_expiry is None:
            raise SessionAuthorityErrorV1(reason)
        return token_expiry

    @staticmethod
    def _token_expiry_or_none(
        principal: AuthenticatedPrincipalV1,
    ) -> float | None:
        token_expiry = getattr(
            principal,
            "token_expiry_epoch_seconds",
            None,
        )
        if (
            isinstance(token_expiry, bool)
            or not isinstance(token_expiry, (int, float))
            or not math.isfinite(token_expiry)
        ):
            return None
        return float(token_expiry)

    def _read_clocks_locked(self) -> tuple[float, float]:
        try:
            now_epoch = self._wall_clock()
            now_monotonic = self._monotonic_clock()
        # Injected/system clocks must not let implementation failures bypass
        # authority checks or expose their exception values.
        except Exception:  # noqa: BLE001
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            ) from None
        if (
            isinstance(now_epoch, bool)
            or not isinstance(now_epoch, (int, float))
            or not math.isfinite(now_epoch)
            or isinstance(now_monotonic, bool)
            or not isinstance(now_monotonic, (int, float))
            or not math.isfinite(now_monotonic)
        ):
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            )
        return float(now_epoch), float(now_monotonic)

    def _generate_random_material(self) -> bytes:
        try:
            material = self._random_bytes(SESSION_ID_RANDOM_BYTES_V1)
        # Random-source failures are availability failures at this boundary.
        except Exception:  # noqa: BLE001
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            ) from None
        if (
            not isinstance(material, bytes)
            or len(material) != SESSION_ID_RANDOM_BYTES_V1
        ):
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            )
        return material

    def _secret_digest(self, context: bytes, secret: bytes) -> bytes:
        return hmac.new(
            self._digest_key,
            context + secret,
            hashlib.sha256,
        ).digest()

    def _ensure_open_locked(self) -> None:
        if self._closed:
            raise SessionAuthorityErrorV1(SessionAuthorityReasonV1.AUTHORITY_CLOSED)
        self._ensure_transition_access_locked()

    def _ensure_transition_access_locked(self) -> None:
        if not self._transition_active:
            return
        try:
            current_task = asyncio.current_task()
        except RuntimeError:
            current_task = None
        if current_task is not self._transition_owner_task:
            raise SessionAuthorityErrorV1(
                SessionAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            )


def _validated_channel(
    channel: SessionAdmissionChannelV1 | str,
) -> SessionAdmissionChannelV1:
    try:
        return SessionAdmissionChannelV1(channel)
    except (TypeError, ValueError):
        raise SessionAuthorityErrorV1(
            SessionAuthorityReasonV1.ADMISSION_CHANNEL_INVALID
        ) from None


def _encode_opaque_value(prefix: str, entropy: bytes) -> str:
    encoded = base64.urlsafe_b64encode(entropy).rstrip(b"=").decode("ascii")
    return prefix + encoded


def _decode_opaque_value(prefix: str, value: object) -> bytes | None:
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    encoded = value[len(prefix) :]
    if (
        len(encoded) != _OPAQUE_VALUE_ENCODED_CHARACTERS_V1
        or _OPAQUE_VALUE_PATTERN_V1.fullmatch(encoded) is None
    ):
        return None
    try:
        decoded = base64.b64decode(
            (encoded + "=").encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return None
    if len(decoded) != SESSION_ID_RANDOM_BYTES_V1:
        return None
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != encoded:
        return None
    return decoded


def _deadline_reached(
    now_epoch: float,
    now_monotonic: float,
    expires_at_epoch: float,
    issued_at_monotonic: float,
    expires_at_monotonic: float,
) -> bool:
    return (
        now_epoch >= expires_at_epoch
        or now_monotonic < issued_at_monotonic
        or now_monotonic >= expires_at_monotonic
    )

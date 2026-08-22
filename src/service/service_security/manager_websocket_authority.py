from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from service.service_security.oidc_resource_server import (
    OIDC_MANAGER_SCOPE_V1,
    AuthenticatedPrincipalV1,
)

MANAGER_WEBSOCKET_TICKET_RANDOM_BYTES_V1 = 32
MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1 = 60
MANAGER_WEBSOCKET_AUTHORITY_MAX_ACTIVE_TICKETS_V1 = 4096
MANAGER_WEBSOCKET_TICKET_PREFIX_V1 = "mat1_"

_OPAQUE_TICKET_ENCODED_CHARACTERS_V1 = 43
_OPAQUE_TICKET_PATTERN_V1 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_TICKET_DIGEST_CONTEXT_V1 = b"openavatar-manager-websocket-ticket-v1"


class ManagerWebSocketPurposeV1(str, Enum):
    MANAGER_WEBSOCKET = "manager_websocket"


class ManagerWebSocketAuthorityReasonV1(str, Enum):
    PARENT_AUTHORIZATION_INVALID = "PARENT_AUTHORIZATION_INVALID"
    PARENT_AUTHORIZATION_EXPIRED = "PARENT_AUTHORIZATION_EXPIRED"
    TICKET_ACCESS_DENIED = "MANAGER_TICKET_ACCESS_DENIED"
    TICKET_COLLISION = "MANAGER_TICKET_COLLISION"
    AUTHORITY_CAPACITY_EXCEEDED = "MANAGER_AUTHORITY_CAPACITY_EXCEEDED"
    AUTHORITY_UNAVAILABLE = "MANAGER_AUTHORITY_UNAVAILABLE"
    AUTHORITY_CLOSED = "MANAGER_AUTHORITY_CLOSED"


class ManagerWebSocketAuthorityErrorV1(RuntimeError):
    """A stable, value-free manager-ticket authority failure."""

    __slots__ = ("reason_code",)

    def __init__(self, reason: ManagerWebSocketAuthorityReasonV1):
        self.reason_code = reason.value
        super().__init__(
            f"Manager WebSocket authority rejected the operation "
            f"({self.reason_code})."
        )


@dataclass(frozen=True, slots=True, repr=False)
class ManagerWebSocketTicketGrantV1:
    admission_ticket: str
    purpose: ManagerWebSocketPurposeV1
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "ManagerWebSocketTicketGrantV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ConsumedManagerWebSocketAdmissionV1:
    purpose: ManagerWebSocketPurposeV1
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float

    def __repr__(self) -> str:
        return "ConsumedManagerWebSocketAdmissionV1(<redacted>)"


@dataclass(frozen=True, slots=True)
class ManagerWebSocketAuthoritySnapshotV1:
    active_tickets: int
    closed: bool


@dataclass(frozen=True, slots=True, repr=False)
class _ManagerWebSocketTicketStateV1:
    ticket_digest: bytes
    purpose: ManagerWebSocketPurposeV1
    issued_at_epoch_seconds: float
    expires_at_epoch_seconds: float
    issued_at_monotonic: float
    expires_at_monotonic: float


class ManagerWebSocketTicketAuthorityV1:
    """Independent process-local authority for one-use manager WS tickets."""

    __slots__ = (
        "_closed",
        "_digest_key",
        "_dummy_ticket_digest",
        "_lock",
        "_monotonic_clock",
        "_random_bytes",
        "_tickets",
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
        self._closed = False
        self._tickets: dict[bytes, _ManagerWebSocketTicketStateV1] = {}
        self._digest_key = self._generate_random_material()
        self._dummy_ticket_digest = self._ticket_digest(
            bytes(MANAGER_WEBSOCKET_TICKET_RANDOM_BYTES_V1)
        )

    def issue(
        self,
        principal: AuthenticatedPrincipalV1,
    ) -> ManagerWebSocketTicketGrantV1:
        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)
            token_expiry = self._validated_manager_authorization(
                principal,
                now_epoch,
            )
            if (
                len(self._tickets)
                >= MANAGER_WEBSOCKET_AUTHORITY_MAX_ACTIVE_TICKETS_V1
            ):
                raise ManagerWebSocketAuthorityErrorV1(
                    ManagerWebSocketAuthorityReasonV1.AUTHORITY_CAPACITY_EXCEEDED
                )

            ticket_entropy = self._generate_random_material()
            ticket_digest = self._ticket_digest(ticket_entropy)
            if ticket_digest in self._tickets:
                raise ManagerWebSocketAuthorityErrorV1(
                    ManagerWebSocketAuthorityReasonV1.TICKET_COLLISION
                )

            expires_at_epoch = min(
                token_expiry,
                now_epoch + MANAGER_WEBSOCKET_TICKET_LIFETIME_SECONDS_V1,
            )
            lifetime = expires_at_epoch - now_epoch
            if lifetime <= 0:
                raise ManagerWebSocketAuthorityErrorV1(
                    ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED
                )
            state = _ManagerWebSocketTicketStateV1(
                ticket_digest=ticket_digest,
                purpose=ManagerWebSocketPurposeV1.MANAGER_WEBSOCKET,
                issued_at_epoch_seconds=now_epoch,
                expires_at_epoch_seconds=expires_at_epoch,
                issued_at_monotonic=now_monotonic,
                expires_at_monotonic=now_monotonic + lifetime,
            )
            self._tickets[ticket_digest] = state
            return ManagerWebSocketTicketGrantV1(
                admission_ticket=_encode_ticket(ticket_entropy),
                purpose=state.purpose,
                issued_at_epoch_seconds=state.issued_at_epoch_seconds,
                expires_at_epoch_seconds=state.expires_at_epoch_seconds,
            )

    def consume(
        self,
        admission_ticket: object,
    ) -> ConsumedManagerWebSocketAdmissionV1:
        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            self._cleanup_expired_locked(now_epoch, now_monotonic)

            ticket_entropy = _decode_ticket(admission_ticket)
            ticket_digest = (
                self._ticket_digest(ticket_entropy)
                if ticket_entropy is not None
                else self._dummy_ticket_digest
            )
            state = self._tickets.get(ticket_digest)
            if (
                ticket_entropy is None
                or state is None
                or state.purpose
                is not ManagerWebSocketPurposeV1.MANAGER_WEBSOCKET
                or _deadline_reached(
                    now_epoch,
                    now_monotonic,
                    state.expires_at_epoch_seconds,
                    state.issued_at_monotonic,
                    state.expires_at_monotonic,
                )
            ):
                if state is not None:
                    self._tickets.pop(ticket_digest, None)
                raise ManagerWebSocketAuthorityErrorV1(
                    ManagerWebSocketAuthorityReasonV1.TICKET_ACCESS_DENIED
                )

            self._tickets.pop(ticket_digest, None)
            return ConsumedManagerWebSocketAdmissionV1(
                purpose=state.purpose,
                issued_at_epoch_seconds=state.issued_at_epoch_seconds,
                expires_at_epoch_seconds=state.expires_at_epoch_seconds,
            )

    def cleanup_expired(self) -> int:
        with self._lock:
            self._ensure_open_locked()
            now_epoch, now_monotonic = self._read_clocks_locked()
            return self._cleanup_expired_locked(now_epoch, now_monotonic)

    def snapshot(self) -> ManagerWebSocketAuthoritySnapshotV1:
        with self._lock:
            return ManagerWebSocketAuthoritySnapshotV1(
                active_tickets=len(self._tickets),
                closed=self._closed,
            )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._tickets.clear()
            self._digest_key = bytes(len(self._digest_key))
            self._dummy_ticket_digest = bytes(len(self._dummy_ticket_digest))
            self._closed = True

    def _validated_manager_authorization(
        self,
        principal: object,
        now_epoch: float,
    ) -> float:
        if (
            not isinstance(principal, AuthenticatedPrincipalV1)
            or OIDC_MANAGER_SCOPE_V1 not in principal.scopes
        ):
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID
            )
        token_expiry = principal.token_expiry_epoch_seconds
        if (
            isinstance(token_expiry, bool)
            or not isinstance(token_expiry, (int, float))
            or not math.isfinite(token_expiry)
        ):
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_INVALID
            )
        if token_expiry <= now_epoch:
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.PARENT_AUTHORIZATION_EXPIRED
            )
        return float(token_expiry)

    def _cleanup_expired_locked(
        self,
        now_epoch: float,
        now_monotonic: float,
    ) -> int:
        removed = 0
        for ticket_digest, state in tuple(self._tickets.items()):
            if _deadline_reached(
                now_epoch,
                now_monotonic,
                state.expires_at_epoch_seconds,
                state.issued_at_monotonic,
                state.expires_at_monotonic,
            ):
                self._tickets.pop(ticket_digest, None)
                removed += 1
        return removed

    def _read_clocks_locked(self) -> tuple[float, float]:
        try:
            now_epoch = self._wall_clock()
            now_monotonic = self._monotonic_clock()
        except Exception:  # noqa: BLE001
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            ) from None
        if (
            isinstance(now_epoch, bool)
            or not isinstance(now_epoch, (int, float))
            or not math.isfinite(now_epoch)
            or isinstance(now_monotonic, bool)
            or not isinstance(now_monotonic, (int, float))
            or not math.isfinite(now_monotonic)
        ):
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            )
        return float(now_epoch), float(now_monotonic)

    def _generate_random_material(self) -> bytes:
        try:
            material = self._random_bytes(
                MANAGER_WEBSOCKET_TICKET_RANDOM_BYTES_V1
            )
        except Exception:  # noqa: BLE001
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            ) from None
        if (
            not isinstance(material, bytes)
            or len(material) != MANAGER_WEBSOCKET_TICKET_RANDOM_BYTES_V1
        ):
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.AUTHORITY_UNAVAILABLE
            )
        return material

    def _ticket_digest(self, ticket_entropy: bytes) -> bytes:
        return hmac.new(
            self._digest_key,
            _TICKET_DIGEST_CONTEXT_V1 + ticket_entropy,
            hashlib.sha256,
        ).digest()

    def _ensure_open_locked(self) -> None:
        if self._closed:
            raise ManagerWebSocketAuthorityErrorV1(
                ManagerWebSocketAuthorityReasonV1.AUTHORITY_CLOSED
            )


def _encode_ticket(ticket_entropy: bytes) -> str:
    encoded = base64.urlsafe_b64encode(ticket_entropy).rstrip(b"=").decode("ascii")
    return MANAGER_WEBSOCKET_TICKET_PREFIX_V1 + encoded


def _decode_ticket(value: object) -> bytes | None:
    if not isinstance(value, str) or not value.startswith(
        MANAGER_WEBSOCKET_TICKET_PREFIX_V1
    ):
        return None
    encoded = value[len(MANAGER_WEBSOCKET_TICKET_PREFIX_V1) :]
    if (
        len(encoded) != _OPAQUE_TICKET_ENCODED_CHARACTERS_V1
        or _OPAQUE_TICKET_PATTERN_V1.fullmatch(encoded) is None
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
    if len(decoded) != MANAGER_WEBSOCKET_TICKET_RANDOM_BYTES_V1:
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

"""Thread-safe temporal-validity authority for one secure runtime session."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import secrets
import threading
import time
import uuid
import weakref
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from chat_engine.security.audit_events import (
    CoreSecurityAuditV1,
    SecurityAuditEventCodeV1,
    SecurityAuditEventV1,
)
from chat_engine.security.cleanup_fence import (
    CleanupActionV1,
    CleanupTokenV1,
    GenerationRetirementV1,
    RetiredGenerationCleanupFenceV1,
    RetiredGenerationCleanupStateV1,
    RetiredGenerationCleanupStatusV1,
)
from chat_engine.security.epochs import SessionEpochV1
from chat_engine.security.ids import UINT64_MAX_V1, new_uuid7_v1
from chat_engine.security.work_fence import (
    RegisteredWorkV1,
    WorkCancellationSignalV1,
    WorkFenceV1,
    WorkLeaseV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

RETIRED_GENERATION_CLEANUP_TIMEOUT_SECONDS_V1 = 10.0
COMPLETED_CLEANUP_TOMBSTONES_V1 = 128


class WorkAdmissionDeniedV1(RuntimeError):
    """Stable, payload-free admission failure."""


class SessionGenerationOverflowV1(RuntimeError):
    """Raised after fail-closing a controller whose uint64 generation is full."""


class GenerationRetirementReasonV1(str, Enum):
    GENERIC = "GENERIC"
    SESSION_SHUTDOWN = "SESSION_SHUTDOWN"


class WorkControllerFailureReasonV1(str, Enum):
    CLEANUP_TIMEOUT = "CLEANUP_TIMEOUT"
    GENERATION_OVERFLOW = "GENERATION_OVERFLOW"
    INTERNAL_AUTHORITY_FAILURE = "INTERNAL_AUTHORITY_FAILURE"


class ControllerTransitionPointV1(str, Enum):
    """Deterministic test-only transition observation points."""

    BEFORE_REGISTRATION_LOCK = "BEFORE_REGISTRATION_LOCK"
    REGISTRATION_LOCKED = "REGISTRATION_LOCKED"
    AFTER_REGISTRATION = "AFTER_REGISTRATION"
    RETIREMENT_BEFORE_PUBLICATION = "RETIREMENT_BEFORE_PUBLICATION"
    AFTER_RETIREMENT_PUBLICATION = "AFTER_RETIREMENT_PUBLICATION"


class _WorkStateV1(str, Enum):
    LIVE = "LIVE"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    RELEASED = "RELEASED"


@dataclass(slots=True)
class _RegisteredWorkStateV1:
    registered_work: RegisteredWorkV1
    state: _WorkStateV1


@dataclass(slots=True)
class _CleanupTokenStateV1:
    token: CleanupTokenV1
    released: bool = False


@dataclass(slots=True)
class _RetiredGenerationRecordV1:
    retired_epoch: SessionEpochV1
    cleanup_fence: RetiredGenerationCleanupFenceV1
    reason: GenerationRetirementReasonV1
    state: RetiredGenerationCleanupStateV1
    outstanding_work_token_ids: set[uuid.UUID]
    outstanding_cleanup_token_ids: set[uuid.UUID]


@dataclass(frozen=True, slots=True)
class SessionWorkControllerSnapshotV1:
    current_epoch: SessionEpochV1
    active: bool
    admission_open: bool
    failed: bool
    failure_reason: WorkControllerFailureReasonV1 | None
    shutdown_started: bool
    shutdown_complete: bool
    destroyed: bool
    unreleased_work_by_generation: tuple[tuple[int, int], ...]
    retired_cleanup_states: tuple[
        tuple[int, RetiredGenerationCleanupStateV1, int, int], ...
    ]


def _controller_mac_key_accessors_v1():
    keys: weakref.WeakKeyDictionary[SessionWorkControllerV1, bytes] = (
        weakref.WeakKeyDictionary()
    )
    keys_lock = threading.Lock()

    def initialize(controller: SessionWorkControllerV1) -> None:
        with keys_lock:
            keys.setdefault(controller, secrets.token_bytes(32))

    def sign(controller: SessionWorkControllerV1, message: bytes) -> bytes:
        with keys_lock:
            key = keys.get(controller)
        if key is None:
            raise RuntimeError("work controller authority unavailable")
        return hmac.new(key, message, hashlib.sha256).digest()

    def rotate(controller: SessionWorkControllerV1) -> None:
        with keys_lock:
            if controller in keys:
                keys[controller] = secrets.token_bytes(32)

    return initialize, sign, rotate


(
    _initialize_controller_mac_key_v1,
    _sign_controller_message_v1,
    _rotate_controller_mac_key_v1,
) = _controller_mac_key_accessors_v1()


def _opaque_id_v1(prefix: str) -> str:
    return f"{prefix}{secrets.token_urlsafe(18)}"


def _authority_part_v1(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, uuid.UUID):
        return value.bytes
    if isinstance(value, Enum):
        return str(value.value).encode("ascii")
    if isinstance(value, float):
        return value.hex().encode("ascii")
    return str(value).encode("utf-8")


class SessionWorkControllerV1:
    """Owns temporal work validity for one secure runtime session instance.

    All state transitions and authoritative validation use one session-local
    re-entrant lock. Async cancellation uses loop-native futures, and async
    cleanup waits poll only after releasing the blocking lock.
    """

    def __init__(self) -> None:
        self._authority_id = _opaque_id_v1("swc1_")
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._clock_v1: Callable[[], float] = time.monotonic
        self._cleanup_timeout_seconds_v1 = RETIRED_GENERATION_CLEANUP_TIMEOUT_SECONDS_V1
        self._current_epoch = SessionEpochV1(new_uuid7_v1(), 1)
        self._active = True
        self._admission_open = True
        self._failed = False
        self._failure_reason: WorkControllerFailureReasonV1 | None = None
        self._shutdown_started = False
        self._shutdown_complete = False
        self._shutdown_result: bool | None = None
        self._destroyed = False
        self._session_owner_claimed = False
        self._protected_action_thread_id: int | None = None
        self._registered_work: dict[uuid.UUID, _RegisteredWorkStateV1] = {}
        self._cleanup_tokens: dict[uuid.UUID, _CleanupTokenStateV1] = {}
        self._retired_generations: dict[int, _RetiredGenerationRecordV1] = {}
        self._cleanup_generation_by_id: dict[uuid.UUID, int] = {}
        self._completed_cleanup_records: OrderedDict[
            uuid.UUID, _RetiredGenerationRecordV1
        ] = OrderedDict()
        self._audit = CoreSecurityAuditV1()
        self._transition_hook_for_test_v1: (
            Callable[[ControllerTransitionPointV1], None] | None
        ) = None
        _initialize_controller_mac_key_v1(self)

    @classmethod
    def _create_for_test_v1(
        cls,
        *,
        monotonic_clock: Callable[[], float] | None = None,
        cleanup_timeout_seconds: float | None = None,
    ) -> SessionWorkControllerV1:
        """Private deterministic-test constructor; never sourced from config."""

        controller = cls()
        with controller._lock:
            if monotonic_clock is not None:
                controller._clock_v1 = monotonic_clock
            if cleanup_timeout_seconds is not None:
                if (
                    not math.isfinite(cleanup_timeout_seconds)
                    or cleanup_timeout_seconds <= 0
                ):
                    raise ValueError(
                        "cleanup_timeout_seconds must be finite and positive"
                    )
                controller._cleanup_timeout_seconds_v1 = cleanup_timeout_seconds
        return controller

    def _set_transition_hook_for_test_v1(
        self,
        hook: Callable[[ControllerTransitionPointV1], None] | None,
    ) -> None:
        with self._lock:
            self._transition_hook_for_test_v1 = hook

    def _claim_session_owner_v1(self) -> bool:
        """Bind this pristine controller to exactly one secure ChatSession."""

        with self._lock:
            self._expire_due_cleanups_locked_v1(self._now_v1())
            if (
                self._session_owner_claimed
                or not self._active
                or not self._admission_open
                or self._failed
                or self._shutdown_started
                or self._destroyed
                or self._registered_work
                or self._cleanup_tokens
                or self._retired_generations
                or self._completed_cleanup_records
            ):
                return False
            self._session_owner_claimed = True
            return True

    def _set_generation_for_test_v1(self, generation: int) -> None:
        """Private overflow seam, permitted only on a pristine controller."""

        with self._lock:
            if (
                self._registered_work
                or self._cleanup_tokens
                or self._retired_generations
                or self._completed_cleanup_records
                or self._shutdown_started
                or self._session_owner_claimed
            ):
                raise RuntimeError("test generation requires a pristine controller")
            self._current_epoch = SessionEpochV1(
                self._current_epoch.session_instance_id,
                generation,
            )

    def _call_transition_hook_v1(
        self,
        point: ControllerTransitionPointV1,
    ) -> None:
        hook = self._transition_hook_for_test_v1
        if hook is not None:
            hook(point)

    def _mac_v1(self, label: bytes, *parts: object) -> bytes:
        message = bytearray(label)
        for part in parts:
            encoded = _authority_part_v1(part)
            message.extend(len(encoded).to_bytes(8, "big"))
            message.extend(encoded)
        try:
            return _sign_controller_message_v1(self, bytes(message))
        except RuntimeError:
            if not self._destroyed:
                self._fail_internal_authority_locked_v1()
            raise

    def _record_v1(self, code: SecurityAuditEventCodeV1) -> None:
        self._audit.record(code)

    def audit_events_v1(self) -> tuple[SecurityAuditEventV1, ...]:
        return self._audit.snapshot()

    def _now_v1(self) -> float:
        now = self._clock_v1()
        if not math.isfinite(now):
            self._fail_internal_authority_locked_v1()
            raise RuntimeError("monotonic clock unavailable")
        return now

    def _fail_internal_authority_locked_v1(self) -> None:
        self._failed = True
        self._active = False
        self._admission_open = False
        if self._failure_reason is None:
            self._failure_reason = (
                WorkControllerFailureReasonV1.INTERNAL_AUTHORITY_FAILURE
            )
        self._cancel_all_unreleased_work_locked_v1()
        self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
        self._condition.notify_all()

    def _cancel_all_unreleased_work_locked_v1(self) -> None:
        for registered in self._registered_work.values():
            if registered.state is _WorkStateV1.RELEASED:
                continue
            if registered.state is _WorkStateV1.LIVE:
                registered.state = _WorkStateV1.CANCELLED
            registered.registered_work.cancellation._cancel_v1()

    def current_epoch_v1(self) -> SessionEpochV1:
        with self._lock:
            self._expire_due_cleanups_locked_v1(self._now_v1())
            return self._current_epoch

    def failure_reason_v1(self) -> WorkControllerFailureReasonV1 | None:
        with self._lock:
            self._expire_due_cleanups_locked_v1(self._now_v1())
            return self._failure_reason

    def is_usable_v1(self) -> bool:
        with self._lock:
            self._expire_due_cleanups_locked_v1(self._now_v1())
            return (
                self._active
                and self._admission_open
                and not self._failed
                and not self._shutdown_started
                and not self._destroyed
            )

    def snapshot_v1(self) -> SessionWorkControllerSnapshotV1:
        with self._lock:
            self._expire_due_cleanups_locked_v1(self._now_v1())
            work_counts: dict[int, int] = {}
            for registered in self._registered_work.values():
                if registered.state is _WorkStateV1.RELEASED:
                    continue
                generation = registered.registered_work.fence.session_epoch.generation
                work_counts[generation] = work_counts.get(generation, 0) + 1
            cleanup_states = tuple(
                (
                    generation,
                    record.state,
                    len(record.outstanding_work_token_ids),
                    len(record.outstanding_cleanup_token_ids),
                )
                for generation, record in sorted(self._retired_generations.items())
            ) + tuple(
                (
                    record.retired_epoch.generation,
                    record.state,
                    0,
                    0,
                )
                for record in self._completed_cleanup_records.values()
            )
            return SessionWorkControllerSnapshotV1(
                current_epoch=self._current_epoch,
                active=self._active,
                admission_open=self._admission_open,
                failed=self._failed,
                failure_reason=self._failure_reason,
                shutdown_started=self._shutdown_started,
                shutdown_complete=self._shutdown_complete,
                destroyed=self._destroyed,
                unreleased_work_by_generation=tuple(sorted(work_counts.items())),
                retired_cleanup_states=cleanup_states,
            )

    def _ensure_normal_admission_locked_v1(self) -> None:
        if (
            not self._active
            or not self._admission_open
            or self._failed
            or self._shutdown_started
            or self._destroyed
        ):
            self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
            raise WorkAdmissionDeniedV1("secure work admission is unavailable")

    def _ensure_no_protected_action_reentry_locked_v1(self) -> None:
        if self._protected_action_thread_id == threading.get_ident():
            self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
            raise WorkAdmissionDeniedV1(
                "controller mutation denied during protected action"
            )

    def register_work_v1(
        self,
        operation_kind: WorkOperationKindV1,
        deadline_monotonic: float,
    ) -> RegisteredWorkV1:
        """Atomically bind a new operation and cleanup-owning lease."""

        self._call_transition_hook_v1(
            ControllerTransitionPointV1.BEFORE_REGISTRATION_LOCK
        )
        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            try:
                self._call_transition_hook_v1(
                    ControllerTransitionPointV1.REGISTRATION_LOCKED
                )
                now = self._now_v1()
                self._expire_due_cleanups_locked_v1(now)
                self._ensure_normal_admission_locked_v1()
                if not isinstance(operation_kind, WorkOperationKindV1):
                    self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
                    raise WorkAdmissionDeniedV1("invalid work operation kind")
                if (
                    isinstance(deadline_monotonic, bool)
                    or not isinstance(deadline_monotonic, (int, float))
                    or not math.isfinite(deadline_monotonic)
                    or deadline_monotonic <= now
                ):
                    self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
                    raise WorkAdmissionDeniedV1("invalid monotonic work deadline")

                deadline = float(deadline_monotonic)
                epoch = self._current_epoch
                operation_id = new_uuid7_v1()
                token_id = new_uuid7_v1()
                fence = WorkFenceV1(
                    authority_id=self._authority_id,
                    session_epoch=epoch,
                    operation_id=operation_id,
                    operation_kind=operation_kind,
                    deadline_monotonic=deadline,
                    authenticator=self._mac_v1(
                        b"work-fence-v1",
                        self._authority_id,
                        epoch.session_instance_id,
                        epoch.generation,
                        operation_id,
                        operation_kind,
                        deadline,
                    ),
                )
                lease = WorkLeaseV1(
                    authority_id=self._authority_id,
                    session_epoch=epoch,
                    operation_id=operation_id,
                    token_id=token_id,
                    authenticator=self._mac_v1(
                        b"work-lease-v1",
                        self._authority_id,
                        epoch.session_instance_id,
                        epoch.generation,
                        operation_id,
                        token_id,
                    ),
                )
                registered_work = RegisteredWorkV1(
                    fence=fence,
                    cancellation=WorkCancellationSignalV1(),
                    lease=lease,
                )
                self._registered_work[operation_id] = _RegisteredWorkStateV1(
                    registered_work=registered_work,
                    state=_WorkStateV1.LIVE,
                )
            except WorkAdmissionDeniedV1:
                raise
            except Exception:  # noqa: BLE001 - stable fail-closed API
                self._fail_internal_authority_locked_v1()
                raise WorkAdmissionDeniedV1("secure work registration failed") from None
        self._call_transition_hook_v1(ControllerTransitionPointV1.AFTER_REGISTRATION)
        return registered_work

    def _registered_state_for_fence_locked_v1(
        self,
        fence: object,
    ) -> _RegisteredWorkStateV1 | None:
        if not isinstance(fence, WorkFenceV1):
            return None
        registered = self._registered_work.get(fence.operation_id)
        if registered is None or registered.registered_work.fence is not fence:
            return None
        canonical = registered.registered_work.fence
        if (
            canonical.authority_id != self._authority_id
            or canonical.session_epoch != registered.registered_work.lease.session_epoch
            or canonical.operation_id != registered.registered_work.lease.operation_id
        ):
            return None
        expected = self._mac_v1(
            b"work-fence-v1",
            canonical.authority_id,
            canonical.session_epoch.session_instance_id,
            canonical.session_epoch.generation,
            canonical.operation_id,
            canonical.operation_kind,
            canonical.deadline_monotonic,
        )
        if not hmac.compare_digest(expected, canonical.authenticator):
            return None
        return registered

    def _work_fence_is_live_locked_v1(
        self,
        fence: object,
        now: float,
        *,
        audit_denial: bool,
    ) -> bool:
        if (
            not self._active
            or self._failed
            or self._shutdown_started
            or self._destroyed
        ):
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
            return False
        registered = self._registered_state_for_fence_locked_v1(fence)
        if registered is None:
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
            return False
        canonical = registered.registered_work.fence
        if (
            canonical.session_epoch.session_instance_id
            != self._current_epoch.session_instance_id
            or canonical.session_epoch.generation != self._current_epoch.generation
            or canonical.session_epoch.generation in self._retired_generations
        ):
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
            return False
        if registered.state is _WorkStateV1.RELEASED:
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
            return False
        if (
            registered.state is _WorkStateV1.CANCELLED
            or registered.registered_work.cancellation.is_cancelled
        ):
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.WORK_CANCELLED)
            return False
        if (
            registered.state is _WorkStateV1.EXPIRED
            or now >= canonical.deadline_monotonic
        ):
            if registered.state is _WorkStateV1.LIVE:
                registered.state = _WorkStateV1.EXPIRED
                registered.registered_work.cancellation._cancel_v1()
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.WORK_DEADLINE_EXPIRED)
            return False
        return registered.state is _WorkStateV1.LIVE

    def validate_work_v1(
        self,
        fence: object,
        boundary: WorkValidationBoundaryV1,
    ) -> bool:
        """Central authoritative temporal-liveness predicate."""

        if not isinstance(boundary, WorkValidationBoundaryV1):
            self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
            return False
        try:
            with self._lock:
                now = self._now_v1()
                self._expire_due_cleanups_locked_v1(now)
                return self._work_fence_is_live_locked_v1(
                    fence,
                    now,
                    audit_denial=True,
                )
        except RuntimeError:
            return False

    def validate_at_admission_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.ADMISSION,
        )

    def validate_at_dequeue_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.QUEUE_DEQUEUE,
        )

    def validate_before_external_call_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
        )

    def validate_after_callback_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
        )

    def validate_before_state_mutation_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
        )

    def validate_before_private_store_write_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
        )

    def validate_before_egress_v1(self, fence: object) -> bool:
        return self.validate_work_v1(
            fence,
            WorkValidationBoundaryV1.BEFORE_EGRESS,
        )

    def perform_if_live_v1(
        self,
        fence: object,
        boundary: WorkValidationBoundaryV1,
        action: Callable[[], Any],
    ) -> bool:
        """Serialize a short protected side effect against retirement.

        ``action`` must be core-owned, non-blocking, and must not perform an
        external request. Long-running work validates before initiation and
        again after return; protected mutation/publication uses this method.
        """

        if not isinstance(boundary, WorkValidationBoundaryV1) or not callable(action):
            self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
            return False
        with self._lock:
            if self._protected_action_thread_id == threading.get_ident():
                self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
                return False
            now = self._now_v1()
            self._expire_due_cleanups_locked_v1(now)
            if not self._work_fence_is_live_locked_v1(
                fence,
                now,
                audit_denial=True,
            ):
                return False
            self._protected_action_thread_id = threading.get_ident()
            try:
                action()
                return True
            finally:
                self._protected_action_thread_id = None

    def cancel_work_v1(self, fence: object) -> bool:
        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            self._expire_due_cleanups_locked_v1(self._now_v1())
            registered = self._registered_state_for_fence_locked_v1(fence)
            if registered is None:
                self._record_v1(SecurityAuditEventCodeV1.STALE_WORK_FENCE)
                return False
            if registered.state is _WorkStateV1.RELEASED:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            if registered.state is _WorkStateV1.LIVE:
                registered.state = _WorkStateV1.CANCELLED
                registered.registered_work.cancellation._cancel_v1()
                self._record_v1(SecurityAuditEventCodeV1.WORK_CANCELLED)
            return True

    def _registered_state_for_lease_locked_v1(
        self,
        lease: object,
    ) -> _RegisteredWorkStateV1 | None:
        if not isinstance(lease, WorkLeaseV1):
            return None
        registered = self._registered_work.get(lease.operation_id)
        if registered is None or registered.registered_work.lease is not lease:
            return None
        canonical = registered.registered_work.lease
        expected = self._mac_v1(
            b"work-lease-v1",
            canonical.authority_id,
            canonical.session_epoch.session_instance_id,
            canonical.session_epoch.generation,
            canonical.operation_id,
            canonical.token_id,
        )
        if canonical.authority_id != self._authority_id or not hmac.compare_digest(
            expected, canonical.authenticator
        ):
            return None
        return registered

    def release_work_v1(self, lease: object) -> bool:
        """Release one work-owned cleanup token exactly once."""

        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            if self._destroyed:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            self._expire_due_cleanups_locked_v1(self._now_v1())
            registered = self._registered_state_for_lease_locked_v1(lease)
            if registered is None:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            if registered.state is _WorkStateV1.RELEASED:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False

            canonical = registered.registered_work.lease
            retired = self._retired_generations.get(canonical.session_epoch.generation)
            if (
                retired is not None
                and canonical.token_id not in retired.outstanding_work_token_ids
            ):
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            registered.state = _WorkStateV1.RELEASED
            if retired is not None:
                retired.outstanding_work_token_ids.remove(canonical.token_id)
                self._maybe_complete_cleanup_locked_v1(retired)
            self._registered_work.pop(canonical.operation_id, None)
            self._condition.notify_all()
            return True

    def register_cleanup_participant_v1(self) -> CleanupTokenV1:
        """Register a destructor/cleanup participant in the current generation."""

        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            try:
                now = self._now_v1()
                self._expire_due_cleanups_locked_v1(now)
                self._ensure_normal_admission_locked_v1()
                epoch = self._current_epoch
                token_id = new_uuid7_v1()
                token = CleanupTokenV1(
                    authority_id=self._authority_id,
                    session_epoch=epoch,
                    token_id=token_id,
                    authenticator=self._mac_v1(
                        b"cleanup-token-v1",
                        self._authority_id,
                        epoch.session_instance_id,
                        epoch.generation,
                        token_id,
                    ),
                )
                self._cleanup_tokens[token_id] = _CleanupTokenStateV1(token=token)
                return token
            except WorkAdmissionDeniedV1:
                raise
            except Exception:  # noqa: BLE001 - stable fail-closed API
                self._fail_internal_authority_locked_v1()
                raise WorkAdmissionDeniedV1(
                    "cleanup participant registration failed"
                ) from None

    def _cleanup_token_state_locked_v1(
        self,
        token: object,
    ) -> _CleanupTokenStateV1 | None:
        if not isinstance(token, CleanupTokenV1):
            return None
        state = self._cleanup_tokens.get(token.token_id)
        if state is None or state.token is not token:
            return None
        canonical = state.token
        expected = self._mac_v1(
            b"cleanup-token-v1",
            canonical.authority_id,
            canonical.session_epoch.session_instance_id,
            canonical.session_epoch.generation,
            canonical.token_id,
        )
        if canonical.authority_id != self._authority_id or not hmac.compare_digest(
            expected, canonical.authenticator
        ):
            return None
        return state

    def withdraw_cleanup_participant_v1(self, token: object) -> bool:
        """Release a participant before its generation retires."""

        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            if self._destroyed:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            state = self._cleanup_token_state_locked_v1(token)
            if state is None or state.released:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            generation = state.token.session_epoch.generation
            if generation in self._retired_generations:
                self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
                return False
            state.released = True
            self._cleanup_tokens.pop(state.token.token_id, None)
            return True

    def _fail_generation_overflow_locked_v1(self) -> None:
        self._failed = True
        self._active = False
        self._admission_open = False
        if self._failure_reason is None:
            self._failure_reason = WorkControllerFailureReasonV1.GENERATION_OVERFLOW
        self._cancel_all_unreleased_work_locked_v1()
        self._record_v1(SecurityAuditEventCodeV1.GENERATION_OVERFLOW)
        self._condition.notify_all()

    def _retire_current_generation_locked_v1(
        self,
        reason: GenerationRetirementReasonV1,
        *,
        reopen_admission: bool,
        allow_failed: bool,
    ) -> GenerationRetirementV1:
        now = self._now_v1()
        self._expire_due_cleanups_locked_v1(now)
        if self._destroyed or (self._failed and not allow_failed):
            self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
            raise WorkAdmissionDeniedV1("generation retirement unavailable")
        if self._current_epoch.generation == UINT64_MAX_V1:
            self._fail_generation_overflow_locked_v1()
            raise SessionGenerationOverflowV1("session generation exhausted")

        self._admission_open = False
        self._call_transition_hook_v1(
            ControllerTransitionPointV1.RETIREMENT_BEFORE_PUBLICATION
        )
        retired_epoch = self._current_epoch
        new_epoch = SessionEpochV1(
            retired_epoch.session_instance_id,
            retired_epoch.generation + 1,
        )
        cleanup_id = new_uuid7_v1()
        cleanup_deadline = now + self._cleanup_timeout_seconds_v1
        cleanup_fence = RetiredGenerationCleanupFenceV1(
            authority_id=self._authority_id,
            session_instance_id=retired_epoch.session_instance_id,
            retired_generation=retired_epoch.generation,
            cleanup_id=cleanup_id,
            deadline_monotonic=cleanup_deadline,
            authenticator=self._mac_v1(
                b"retired-cleanup-fence-v1",
                self._authority_id,
                retired_epoch.session_instance_id,
                retired_epoch.generation,
                cleanup_id,
                cleanup_deadline,
            ),
        )

        work_token_ids: set[uuid.UUID] = set()
        for registered in self._registered_work.values():
            work = registered.registered_work
            if (
                work.fence.session_epoch.generation != retired_epoch.generation
                or registered.state is _WorkStateV1.RELEASED
            ):
                continue
            work_token_ids.add(work.lease.token_id)
            if registered.state is _WorkStateV1.LIVE:
                registered.state = _WorkStateV1.CANCELLED
            work.cancellation._cancel_v1()

        cleanup_token_ids = {
            token_id
            for token_id, state in self._cleanup_tokens.items()
            if (
                not state.released
                and state.token.session_epoch.generation == retired_epoch.generation
            )
        }
        record = _RetiredGenerationRecordV1(
            retired_epoch=retired_epoch,
            cleanup_fence=cleanup_fence,
            reason=reason,
            state=RetiredGenerationCleanupStateV1.PENDING,
            outstanding_work_token_ids=work_token_ids,
            outstanding_cleanup_token_ids=cleanup_token_ids,
        )
        self._retired_generations[retired_epoch.generation] = record
        self._cleanup_generation_by_id[cleanup_id] = retired_epoch.generation
        self._current_epoch = new_epoch
        if reopen_admission and self._active and not self._failed:
            self._admission_open = True
        self._maybe_complete_cleanup_locked_v1(record)
        self._record_v1(SecurityAuditEventCodeV1.GENERATION_RETIRED)
        self._condition.notify_all()
        return GenerationRetirementV1(
            new_epoch=new_epoch,
            cleanup_fence=cleanup_fence,
        )

    def retire_generation_v1(
        self,
        reason: GenerationRetirementReasonV1 = (GenerationRetirementReasonV1.GENERIC),
    ) -> GenerationRetirementV1:
        if not isinstance(reason, GenerationRetirementReasonV1):
            self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
            raise WorkAdmissionDeniedV1("invalid generation retirement reason")
        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            if self._shutdown_started:
                self._record_v1(SecurityAuditEventCodeV1.WORK_ADMISSION_DENIED)
                raise WorkAdmissionDeniedV1("generation retirement unavailable")
            try:
                retirement = self._retire_current_generation_locked_v1(
                    reason,
                    reopen_admission=True,
                    allow_failed=False,
                )
            except (SessionGenerationOverflowV1, WorkAdmissionDeniedV1):
                raise
            except Exception:  # noqa: BLE001 - stable fail-closed API
                self._fail_internal_authority_locked_v1()
                raise WorkAdmissionDeniedV1("generation retirement failed") from None
        self._call_transition_hook_v1(
            ControllerTransitionPointV1.AFTER_RETIREMENT_PUBLICATION
        )
        return retirement

    def _canonical_cleanup_record_locked_v1(
        self,
        cleanup_fence: object,
    ) -> _RetiredGenerationRecordV1 | None:
        if not isinstance(
            cleanup_fence,
            RetiredGenerationCleanupFenceV1,
        ):
            return None
        generation = self._cleanup_generation_by_id.get(cleanup_fence.cleanup_id)
        record = (
            self._retired_generations.get(generation)
            if generation is not None
            else self._completed_cleanup_records.get(cleanup_fence.cleanup_id)
        )
        if (
            record is None
            or record.cleanup_fence is not cleanup_fence
            or cleanup_fence.authority_id != self._authority_id
            or cleanup_fence.session_instance_id
            != record.retired_epoch.session_instance_id
            or cleanup_fence.retired_generation != record.retired_epoch.generation
        ):
            return None
        expected = self._mac_v1(
            b"retired-cleanup-fence-v1",
            cleanup_fence.authority_id,
            cleanup_fence.session_instance_id,
            cleanup_fence.retired_generation,
            cleanup_fence.cleanup_id,
            cleanup_fence.deadline_monotonic,
        )
        if not hmac.compare_digest(expected, cleanup_fence.authenticator):
            return None
        return record

    def _cleanup_action_is_authorized_locked_v1(
        self,
        cleanup_fence: object,
        action: object,
        *,
        audit_denial: bool,
    ) -> bool:
        if not isinstance(action, CleanupActionV1):
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
            return False
        record = self._canonical_cleanup_record_locked_v1(cleanup_fence)
        if record is None:
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
            return False
        if record.state is RetiredGenerationCleanupStateV1.COMPLETE:
            if audit_denial:
                self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
            return False
        if record.state is RetiredGenerationCleanupStateV1.TIMED_OUT:
            return action in {
                CleanupActionV1.CANCEL,
                CleanupActionV1.PURGE,
                CleanupActionV1.DELETE,
                CleanupActionV1.RELEASE,
                CleanupActionV1.CLOSE,
            }
        return record.state is RetiredGenerationCleanupStateV1.PENDING

    def authorize_cleanup_v1(
        self,
        cleanup_fence: object,
        action: CleanupActionV1,
    ) -> bool:
        """Authorize cleanup-only semantics, never ordinary work."""

        try:
            with self._lock:
                self._expire_due_cleanups_locked_v1(self._now_v1())
                return self._cleanup_action_is_authorized_locked_v1(
                    cleanup_fence,
                    action,
                    audit_denial=True,
                )
        except RuntimeError:
            return False

    def release_cleanup_v1(
        self,
        cleanup_fence: object,
        token: object,
        *,
        action: CleanupActionV1 = CleanupActionV1.ACK_CLEANUP,
    ) -> bool:
        """Acknowledge one retired-generation cleanup participant once."""

        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            if self._destroyed:
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            self._expire_due_cleanups_locked_v1(self._now_v1())
            if action not in {
                CleanupActionV1.ACK_CLEANUP,
                CleanupActionV1.RELEASE,
                CleanupActionV1.CLOSE,
            } or not self._cleanup_action_is_authorized_locked_v1(
                cleanup_fence,
                action,
                audit_denial=True,
            ):
                return False
            record = self._canonical_cleanup_record_locked_v1(cleanup_fence)
            token_state = self._cleanup_token_state_locked_v1(token)
            if (
                record is None
                or token_state is None
                or token_state.released
                or token_state.token.session_epoch.generation
                != record.retired_epoch.generation
                or token_state.token.token_id
                not in record.outstanding_cleanup_token_ids
            ):
                self._record_v1(SecurityAuditEventCodeV1.WORK_TOKEN_INVARIANT_VIOLATION)
                return False
            token_state.released = True
            record.outstanding_cleanup_token_ids.remove(token_state.token.token_id)
            self._cleanup_tokens.pop(token_state.token.token_id, None)
            self._maybe_complete_cleanup_locked_v1(record)
            self._condition.notify_all()
            return True

    def _maybe_complete_cleanup_locked_v1(
        self,
        record: _RetiredGenerationRecordV1,
    ) -> None:
        if (
            record.state is RetiredGenerationCleanupStateV1.PENDING
            and not record.outstanding_work_token_ids
            and not record.outstanding_cleanup_token_ids
        ):
            record.state = RetiredGenerationCleanupStateV1.COMPLETE
            generation = record.retired_epoch.generation
            cleanup_id = record.cleanup_fence.cleanup_id
            self._retired_generations.pop(generation, None)
            self._cleanup_generation_by_id.pop(cleanup_id, None)
            self._completed_cleanup_records[cleanup_id] = record
            self._completed_cleanup_records.move_to_end(cleanup_id)
            while (
                len(self._completed_cleanup_records) > COMPLETED_CLEANUP_TOMBSTONES_V1
            ):
                self._completed_cleanup_records.popitem(last=False)
            self._condition.notify_all()

    def _mark_cleanup_timeout_locked_v1(
        self,
        record: _RetiredGenerationRecordV1,
    ) -> None:
        if record.state is not RetiredGenerationCleanupStateV1.PENDING:
            return
        record.state = RetiredGenerationCleanupStateV1.TIMED_OUT
        self._failed = True
        self._active = False
        self._admission_open = False
        if self._failure_reason is None:
            self._failure_reason = WorkControllerFailureReasonV1.CLEANUP_TIMEOUT
        self._cancel_all_unreleased_work_locked_v1()
        self._record_v1(SecurityAuditEventCodeV1.CLEANUP_TIMEOUT)
        self._condition.notify_all()

    def _expire_due_cleanups_locked_v1(self, now: float) -> None:
        for record in self._retired_generations.values():
            if (
                record.state is RetiredGenerationCleanupStateV1.PENDING
                and now >= record.cleanup_fence.deadline_monotonic
            ):
                self._mark_cleanup_timeout_locked_v1(record)

    def cleanup_status_v1(
        self,
        cleanup_fence: object,
    ) -> RetiredGenerationCleanupStatusV1 | None:
        try:
            with self._lock:
                self._expire_due_cleanups_locked_v1(self._now_v1())
                record = self._canonical_cleanup_record_locked_v1(cleanup_fence)
                if record is None:
                    self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
                    return None
                return RetiredGenerationCleanupStatusV1(
                    retired_generation=record.retired_epoch.generation,
                    cleanup_id=record.cleanup_fence.cleanup_id,
                    state=record.state,
                    outstanding_work_tokens=len(record.outstanding_work_token_ids),
                    outstanding_cleanup_tokens=len(
                        record.outstanding_cleanup_token_ids
                    ),
                    deadline_monotonic=(record.cleanup_fence.deadline_monotonic),
                )
        except RuntimeError:
            return None

    def wait_for_cleanup_v1(self, cleanup_fence: object) -> bool:
        """Wait until one barrier completes or its fixed deadline expires."""

        with self._condition:
            self._ensure_no_protected_action_reentry_locked_v1()
            record = self._canonical_cleanup_record_locked_v1(cleanup_fence)
            if record is None:
                self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
                return False
            while record.state is RetiredGenerationCleanupStateV1.PENDING:
                now = self._now_v1()
                remaining = record.cleanup_fence.deadline_monotonic - now
                if remaining <= 0:
                    self._mark_cleanup_timeout_locked_v1(record)
                    break
                self._condition.wait(timeout=remaining)
            return record.state is RetiredGenerationCleanupStateV1.COMPLETE

    async def wait_for_cleanup_async_v1(
        self,
        cleanup_fence: object,
    ) -> bool:
        """Async cleanup wait that never retains the blocking lock at await."""

        with self._lock:
            self._ensure_no_protected_action_reentry_locked_v1()
            record = self._canonical_cleanup_record_locked_v1(cleanup_fence)
            if record is None:
                self._record_v1(SecurityAuditEventCodeV1.INVALID_CLEANUP_FENCE)
                return False
        while True:
            with self._lock:
                self._ensure_no_protected_action_reentry_locked_v1()
                if record.state is RetiredGenerationCleanupStateV1.COMPLETE:
                    return True
                if record.state is RetiredGenerationCleanupStateV1.TIMED_OUT:
                    return False
                now = self._now_v1()
                remaining = record.cleanup_fence.deadline_monotonic - now
                if remaining <= 0:
                    self._mark_cleanup_timeout_locked_v1(record)
                    return False
            await asyncio.sleep(min(remaining, 0.01))

    def _finish_shutdown_locked_v1(self, result: bool) -> bool:
        self._active = False
        self._admission_open = False
        self._cancel_all_unreleased_work_locked_v1()
        self._destroyed = True
        self._shutdown_result = bool(result and not self._failed)
        self._shutdown_complete = True
        _rotate_controller_mac_key_v1(self)
        self._condition.notify_all()
        return self._shutdown_result

    def shutdown(self) -> bool:
        """Retire, cancel, await all barriers, and destroy this authority."""

        with self._condition:
            self._ensure_no_protected_action_reentry_locked_v1()
            if self._shutdown_complete:
                return bool(self._shutdown_result)
            if self._shutdown_started:
                while not self._shutdown_complete:
                    self._condition.wait()
                return bool(self._shutdown_result)
            self._shutdown_started = True
            self._admission_open = False
            try:
                self._retire_current_generation_locked_v1(
                    GenerationRetirementReasonV1.SESSION_SHUTDOWN,
                    reopen_admission=False,
                    allow_failed=True,
                )
            except SessionGenerationOverflowV1:
                return self._finish_shutdown_locked_v1(False)
            except Exception:  # noqa: BLE001 - fail closed without exception data
                self._fail_internal_authority_locked_v1()
                return self._finish_shutdown_locked_v1(False)
            cleanup_fences = tuple(
                record.cleanup_fence
                for record in self._retired_generations.values()
                if record.state is RetiredGenerationCleanupStateV1.PENDING
            )

        cleanup_succeeded = True
        try:
            for cleanup_fence in cleanup_fences:
                if not self.wait_for_cleanup_v1(cleanup_fence):
                    cleanup_succeeded = False
        except Exception:  # noqa: BLE001 - stable fail-closed result
            with self._condition:
                self._fail_internal_authority_locked_v1()
                return self._finish_shutdown_locked_v1(False)
        except BaseException:
            with self._condition:
                self._fail_internal_authority_locked_v1()
                self._finish_shutdown_locked_v1(False)
            raise

        with self._condition:
            if any(
                record.state is not RetiredGenerationCleanupStateV1.COMPLETE
                for record in self._retired_generations.values()
            ):
                cleanup_succeeded = False
            return self._finish_shutdown_locked_v1(cleanup_succeeded)

    async def shutdown_async(self) -> bool:
        """Native async counterpart to shutdown without blocking the loop."""

        with self._condition:
            self._ensure_no_protected_action_reentry_locked_v1()
            if self._shutdown_complete:
                return bool(self._shutdown_result)
            if self._shutdown_started:
                owns_shutdown = False
                cleanup_fences: tuple[RetiredGenerationCleanupFenceV1, ...] = ()
            else:
                owns_shutdown = True
                self._shutdown_started = True
                self._admission_open = False
                try:
                    self._retire_current_generation_locked_v1(
                        GenerationRetirementReasonV1.SESSION_SHUTDOWN,
                        reopen_admission=False,
                        allow_failed=True,
                    )
                except SessionGenerationOverflowV1:
                    return self._finish_shutdown_locked_v1(False)
                except Exception:  # noqa: BLE001 - stable fail-closed result
                    self._fail_internal_authority_locked_v1()
                    return self._finish_shutdown_locked_v1(False)
                cleanup_fences = tuple(
                    record.cleanup_fence
                    for record in self._retired_generations.values()
                    if (record.state is RetiredGenerationCleanupStateV1.PENDING)
                )

        if not owns_shutdown:
            while True:
                with self._lock:
                    if self._shutdown_complete:
                        return bool(self._shutdown_result)
                await asyncio.sleep(0.01)

        cleanup_succeeded = True
        try:
            for cleanup_fence in cleanup_fences:
                if not await self.wait_for_cleanup_async_v1(cleanup_fence):
                    cleanup_succeeded = False
        except Exception:  # noqa: BLE001 - stable fail-closed result
            with self._condition:
                self._fail_internal_authority_locked_v1()
                return self._finish_shutdown_locked_v1(False)
        except BaseException:
            with self._condition:
                self._fail_internal_authority_locked_v1()
                self._finish_shutdown_locked_v1(False)
            raise

        with self._condition:
            if any(
                record.state is not RetiredGenerationCleanupStateV1.COMPLETE
                for record in self._retired_generations.values()
            ):
                cleanup_succeeded = False
            return self._finish_shutdown_locked_v1(cleanup_succeeded)

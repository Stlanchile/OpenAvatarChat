"""Bounded canonical idempotency and control-sequence enforcement."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from enum import Enum

from certificate_capture.protocol import (
    MAX_CONTROL_MUTATIONS_PER_SESSION_V1,
    CaptureProtocolErrorV1,
    CaptureProtocolReasonV1,
)


class ControlOperationV1(str, Enum):
    BEGIN = "BEGIN"
    SEAL = "SEAL"
    END = "END"


@dataclass(slots=True, repr=False)
class ControlReplayRecordV1:
    operation: ControlOperationV1
    request_id: uuid.UUID
    control_seq: int
    request_digest: bytes
    completed: bool = False
    result: object | None = None
    error_reason: CaptureProtocolReasonV1 | None = None
    authorization_binding: object | None = None

    def __repr__(self) -> str:
        return "ControlReplayRecordV1(<redacted>)"


class ControlReplayLedgerV1:
    """A session-scoped monotonic ledger with a bounded replay window.

    Completed records may age out, but the sequence high-water never moves
    backward. A successful End replaces capture-scoped records with one
    authenticated End tombstone.
    """

    __slots__ = (
        "_capacity",
        "_last_control_seq",
        "_records_by_request_id",
        "_request_id_by_control_seq",
    )

    def __init__(
        self,
        *,
        capacity: int = MAX_CONTROL_MUTATIONS_PER_SESSION_V1,
    ) -> None:
        if capacity <= 0:
            raise ValueError("replay capacity must be positive")
        self._capacity = capacity
        self._last_control_seq = 0
        self._records_by_request_id: dict[
            uuid.UUID, ControlReplayRecordV1
        ] = {}
        self._request_id_by_control_seq: dict[int, uuid.UUID] = {}

    def lookup_or_claim_v1(
        self,
        *,
        operation: ControlOperationV1,
        request_id: uuid.UUID,
        control_seq: int,
        request_digest: bytes,
    ) -> tuple[ControlReplayRecordV1, bool]:
        existing = self._records_by_request_id.get(request_id)
        if existing is not None:
            self._require_exact_v1(
                existing,
                operation=operation,
                control_seq=control_seq,
                request_digest=request_digest,
            )
            if not existing.completed:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CONTROL_BUSY
                )
            return existing, True

        existing_request_id = self._request_id_by_control_seq.get(control_seq)
        if existing_request_id is not None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CONTROL_SEQUENCE_STALE
            )
        if control_seq <= self._last_control_seq:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CONTROL_SEQUENCE_STALE
            )
        if control_seq != self._last_control_seq + 1:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CONTROL_SEQUENCE_GAP
            )
        self._make_room_v1()

        record = ControlReplayRecordV1(
            operation=operation,
            request_id=request_id,
            control_seq=control_seq,
            request_digest=bytes(request_digest),
        )
        self._records_by_request_id[request_id] = record
        self._request_id_by_control_seq[control_seq] = request_id
        self._last_control_seq = control_seq
        return record, False

    def _make_room_v1(self) -> None:
        """Keep a sliding bounded replay window without blocking future End."""

        while len(self._records_by_request_id) >= self._capacity:
            evicted_request_id: uuid.UUID | None = None
            for request_id, record in self._records_by_request_id.items():
                if record.completed:
                    evicted_request_id = request_id
                    break
            if evicted_request_id is None:
                raise CaptureProtocolErrorV1(
                    CaptureProtocolReasonV1.CONTROL_CAPACITY_EXCEEDED
                )
            evicted = self._records_by_request_id.pop(evicted_request_id)
            self._request_id_by_control_seq.pop(evicted.control_seq, None)

    def existing_record_v1(
        self,
        *,
        operation: ControlOperationV1,
        request_id: uuid.UUID,
        control_seq: int,
        request_digest: bytes,
    ) -> ControlReplayRecordV1 | None:
        existing = self._records_by_request_id.get(request_id)
        if existing is None:
            return None
        self._require_exact_v1(
            existing,
            operation=operation,
            control_seq=control_seq,
            request_digest=request_digest,
        )
        if not existing.completed:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CONTROL_BUSY
            )
        return existing

    def candidate_record_v1(
        self,
        request_id: uuid.UUID,
    ) -> ControlReplayRecordV1 | None:
        """Return only a private candidate for capability-first replay checks."""

        return self._records_by_request_id.get(request_id)

    @staticmethod
    def _require_exact_v1(
        existing: ControlReplayRecordV1,
        *,
        operation: ControlOperationV1,
        control_seq: int,
        request_digest: bytes,
    ) -> None:
        exact = (
            existing.operation is operation
            and existing.control_seq == control_seq
            and hmac.compare_digest(
                existing.request_digest,
                request_digest,
            )
        )
        if not exact:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.IDEMPOTENCY_CONFLICT
            )

    @staticmethod
    def complete_result_v1(
        record: ControlReplayRecordV1,
        result: object,
    ) -> None:
        record.result = result
        record.error_reason = None
        record.completed = True

    @staticmethod
    def complete_error_v1(
        record: ControlReplayRecordV1,
        reason: CaptureProtocolReasonV1,
    ) -> None:
        record.result = None
        record.error_reason = reason
        record.completed = True

    @staticmethod
    def replay_result_v1(record: ControlReplayRecordV1) -> object:
        if not record.completed:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CONTROL_BUSY
            )
        if record.error_reason is not None:
            raise CaptureProtocolErrorV1(record.error_reason)
        if record.result is None:
            raise CaptureProtocolErrorV1(
                CaptureProtocolReasonV1.CAPTURE_OPERATION_FAILED
            )
        return record.result

    def clear_v1(self) -> None:
        self._records_by_request_id.clear()
        self._request_id_by_control_seq.clear()
        self._last_control_seq = 0

    def discard_replay_records_v1(self) -> None:
        """Delete retained results while preserving the sequence high-water."""

        self._records_by_request_id.clear()
        self._request_id_by_control_seq.clear()

    def retain_only_v1(self, record: ControlReplayRecordV1) -> None:
        """Retain one authenticated End tombstone and delete capture records."""

        if self._records_by_request_id.get(record.request_id) is not record:
            raise RuntimeError("replay tombstone is not ledger-owned")
        self._records_by_request_id.clear()
        self._request_id_by_control_seq.clear()
        self._records_by_request_id[record.request_id] = record
        self._request_id_by_control_seq[record.control_seq] = record.request_id

    def snapshot_v1(self) -> tuple[int, int]:
        return self._last_control_seq, len(self._records_by_request_id)


def canonical_control_request_digest_v1(
    *,
    operation: ControlOperationV1,
    request_id: uuid.UUID,
    control_seq: int,
    profile_id: str | None = None,
    capture_id: uuid.UUID | None = None,
) -> bytes:
    """Digest an immutable explicit schema, never a caller-owned mapping."""

    canonical = {
        "capture_id": str(capture_id) if capture_id is not None else None,
        "control_seq": control_seq,
        "operation": operation.value,
        "profile_id": profile_id,
        "request_id": str(request_id),
        "schema_version": 1,
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    return hashlib.sha256(
        b"oac-certificate-capture-control-request-v1\x00" + encoded
    ).digest()


__all__ = [
    "ControlOperationV1",
    "ControlReplayLedgerV1",
    "ControlReplayRecordV1",
    "canonical_control_request_digest_v1",
]

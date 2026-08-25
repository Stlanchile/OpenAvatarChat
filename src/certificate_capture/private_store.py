"""Bounded process-local AES-256-GCM certificate-private evidence store."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from certificate_capture.contracts.common import (
    canonical_json_bytes_v1,
    require_epoch_seconds_v1,
    require_uuid7_v1,
)
from certificate_capture.contracts.evidence import (
    CaptureSetV1,
    CaptureWindowV1,
    EvidenceFrameV1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.private_authority import (
    PrivateEvidenceAccessKindV1,
    PrivateEvidenceAccessV1,
    PrivateEvidenceAuthorityV1,
)
from certificate_capture.private_codec import (
    MAX_AUXILIARY_CANONICAL_JSON_BYTES_V1,
    PRIVATE_CODEC_OVERHEAD_BYTES_V1,
    PRIVATE_CODEC_SCHEMA_VERSION_V1,
    PrivateCodecErrorV1,
    PrivateEvidenceRecordTypeV1,
    decode_private_record_v1,
    encode_private_record_v1,
)
from certificate_capture.protocol import (
    MAX_CAPTURE_ENCODED_BYTES_V1,
    MAX_CAPTURE_FRAMES_V1,
)
from chat_engine.security.cleanup_fence import (
    CleanupActionV1,
    RetiredGenerationCleanupFenceV1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
)
from chat_engine.security.work_fence import (
    WorkFenceV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

ENCRYPTED_RECORD_SCHEMA_VERSION_V1 = "oac.encrypted-record.v1"
PRIVATE_EVIDENCE_AAD_SCHEMA_VERSION_V1 = (
    "oac.private-evidence-aad.v1"
)
AES_256_KEY_BYTES_V1 = 32
AES_GCM_NONCE_BYTES_V1 = 12
AES_GCM_TAG_BYTES_V1 = 16

MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1 = 16
MAX_AUXILIARY_CAPTURE_PLAINTEXT_BYTES_V1 = 1024 * 1024
MAX_PRIVATE_RECORDS_PER_CAPTURE_V1 = (
    MAX_CAPTURE_FRAMES_V1 + MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1
)
MAX_CONCURRENT_PRIVATE_STORE_OPERATIONS_V1 = 4
ENCRYPTED_RECORD_METADATA_ACCOUNTING_BYTES_V1 = 256
MAX_PRIVATE_INDEX_ACCOUNTING_BYTES_V1 = (
    MAX_PRIVATE_RECORDS_PER_CAPTURE_V1
    * ENCRYPTED_RECORD_METADATA_ACCOUNTING_BYTES_V1
)
MAX_FRAME_STORED_CIPHERTEXT_BYTES_V1 = (
    MAX_CAPTURE_ENCODED_BYTES_V1
    + MAX_CAPTURE_FRAMES_V1
    * (PRIVATE_CODEC_OVERHEAD_BYTES_V1 + AES_GCM_TAG_BYTES_V1)
)
MAX_AUXILIARY_STORED_CIPHERTEXT_BYTES_V1 = (
    MAX_AUXILIARY_CAPTURE_PLAINTEXT_BYTES_V1
    + MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1
    * (PRIVATE_CODEC_OVERHEAD_BYTES_V1 + AES_GCM_TAG_BYTES_V1)
)

_STORE_CONSTRUCTION_AUTHORITY_V1 = object()
_KEY_AUTHORITY_CONSTRUCTION_V1 = object()
_MAX_NONCE_COUNTER_V1 = (1 << (8 * AES_GCM_NONCE_BYTES_V1)) - 1


class PrivateEvidenceStoreReasonV1(str, Enum):
    ACCESS_DENIED = "ACCESS_DENIED"
    CAPTURE_CLOSED = "CAPTURE_CLOSED"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    RECORD_TYPE_MISMATCH = "RECORD_TYPE_MISMATCH"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    INVARIANT_FAILURE = "INVARIANT_FAILURE"
    OPERATION_BUSY = "OPERATION_BUSY"
    OPERATION_FAILED = "OPERATION_FAILED"


class PrivateEvidenceStoreErrorV1(RuntimeError):
    """Stable non-sensitive store failure."""

    __slots__ = ("reason", "reason_code")

    def __init__(self, reason: PrivateEvidenceStoreReasonV1) -> None:
        self.reason = reason
        self.reason_code = reason.value
        super().__init__(
            f"private evidence store operation failed ({reason.value})"
        )


class PrivateEvidenceStoreFaultPointV1(str, Enum):
    BEFORE_KEY_LOOKUP = "BEFORE_KEY_LOOKUP"
    BEFORE_ENCRYPTION = "BEFORE_ENCRYPTION"
    AFTER_ENCRYPTION_BEFORE_INSERTION = (
        "AFTER_ENCRYPTION_BEFORE_INSERTION"
    )
    AFTER_INSERTION_BEFORE_METADATA_COMMIT = (
        "AFTER_INSERTION_BEFORE_METADATA_COMMIT"
    )


class PrivateEvidenceCleanupStepV1(str, Enum):
    ADMISSION_CLOSED = "ADMISSION_CLOSED"
    KEY_DESTROYED = "KEY_DESTROYED"
    CIPHERTEXT_CLEARED = "CIPHERTEXT_CLEARED"
    INDICES_CLEARED = "INDICES_CLEARED"
    METADATA_CLEARED = "METADATA_CLEARED"


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class EncryptedRecordV1:
    record_id: uuid.UUID
    record_type: PrivateEvidenceRecordTypeV1
    nonce: bytes
    ciphertext: bytes
    created_at_epoch_seconds: float
    plaintext_length: int
    codec_schema_version: str = PRIVATE_CODEC_SCHEMA_VERSION_V1
    schema_version: str = ENCRYPTED_RECORD_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != ENCRYPTED_RECORD_SCHEMA_VERSION_V1:
            raise ValueError("unsupported encrypted-record schema")
        if self.codec_schema_version != PRIVATE_CODEC_SCHEMA_VERSION_V1:
            raise ValueError("unsupported private codec schema")
        require_uuid7_v1("record_id", self.record_id)
        if not isinstance(
            self.record_type,
            PrivateEvidenceRecordTypeV1,
        ):
            raise TypeError("record_type must be PrivateEvidenceRecordTypeV1")
        if (
            not isinstance(self.nonce, bytes)
            or len(self.nonce) != AES_GCM_NONCE_BYTES_V1
        ):
            raise ValueError("AES-GCM nonce must be exactly 96 bits")
        if (
            not isinstance(self.ciphertext, bytes)
            or len(self.ciphertext) <= AES_GCM_TAG_BYTES_V1
        ):
            raise ValueError("AES-GCM ciphertext is invalid")
        created_at = require_epoch_seconds_v1(
            "created_at_epoch_seconds",
            self.created_at_epoch_seconds,
        )
        if (
            isinstance(self.plaintext_length, bool)
            or not isinstance(self.plaintext_length, int)
            or self.plaintext_length <= PRIVATE_CODEC_OVERHEAD_BYTES_V1
            or len(self.ciphertext)
            != self.plaintext_length + AES_GCM_TAG_BYTES_V1
        ):
            raise ValueError("encrypted-record length accounting is invalid")
        object.__setattr__(
            self,
            "created_at_epoch_seconds",
            created_at,
        )

    def __repr__(self) -> str:
        return (
            "EncryptedRecordV1("
            f"record_type={self.record_type.value!r}, "
            "record_id=<opaque>, nonce=<internal>, ciphertext=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class StoredFrameV1:
    evidence_frame: EvidenceFrameV1
    stored_ciphertext_bytes: int

    def __repr__(self) -> str:
        return "StoredFrameV1(<private-metadata>)"


@dataclass(frozen=True, slots=True)
class PrivateEvidenceStoreSnapshotV1:
    partition_open: bool
    key_present: bool
    frame_record_count: int
    auxiliary_record_count: int
    accepted_plaintext_encoded_bytes: int
    stored_frame_ciphertext_bytes: int
    stored_auxiliary_ciphertext_bytes: int
    bounded_index_accounting_bytes: int
    last_destroyed_capture_seq: int


@dataclass(slots=True)
class _CapturePartitionV1:
    capture_epoch: CaptureEpochV1
    capture_set: CaptureSetV1
    open: bool
    committed: bool
    nonce_counter: int
    records: dict[uuid.UUID, EncryptedRecordV1]
    evidence_by_frame_id: dict[uuid.UUID, EvidenceFrameV1]
    frame_id_by_seq: dict[int, uuid.UUID]
    auxiliary_record_ids: set[uuid.UUID]
    accepted_plaintext_encoded_bytes: int
    auxiliary_plaintext_bytes: int
    stored_frame_ciphertext_bytes: int
    stored_auxiliary_ciphertext_bytes: int


class _CaptureKeyUnavailableV1(RuntimeError):
    pass


class _CaptureKeyAuthorityV1:
    """The only long-lived owner of one capture DEK."""

    __slots__ = (
        "_capture_epoch",
        "_key",
        "_last_destroyed_capture_seq",
    )

    def __init__(self, *, _construction_authority_v1: object) -> None:
        if _construction_authority_v1 is not _KEY_AUTHORITY_CONSTRUCTION_V1:
            raise RuntimeError("capture key authority construction denied")
        self._capture_epoch: CaptureEpochV1 | None = None
        self._key: bytes | None = None
        self._last_destroyed_capture_seq = 0

    def create_v1(self, capture_epoch: CaptureEpochV1) -> bool:
        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or capture_epoch.capture_seq <= self._last_destroyed_capture_seq
            or self._capture_epoch is not None
            or self._key is not None
        ):
            return False
        key = secrets.token_bytes(AES_256_KEY_BYTES_V1)
        if len(key) != AES_256_KEY_BYTES_V1:
            return False
        self._capture_epoch = capture_epoch
        self._key = key
        return True

    def encrypt_v1(
        self,
        capture_epoch: CaptureEpochV1,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes,
    ) -> bytes:
        key = self._key
        if self._capture_epoch is not capture_epoch or key is None:
            raise _CaptureKeyUnavailableV1
        cipher = AESGCM(key)
        try:
            return cipher.encrypt(nonce, plaintext, aad)
        finally:
            del cipher
            del key

    def decrypt_v1(
        self,
        capture_epoch: CaptureEpochV1,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
    ) -> bytes:
        key = self._key
        if self._capture_epoch is not capture_epoch or key is None:
            raise _CaptureKeyUnavailableV1
        cipher = AESGCM(key)
        try:
            return cipher.decrypt(nonce, ciphertext, aad)
        finally:
            del cipher
            del key

    def destroy_v1(self, capture_epoch: CaptureEpochV1) -> bool:
        if self._capture_epoch is None and self._key is None:
            return capture_epoch.capture_seq <= self._last_destroyed_capture_seq
        if self._capture_epoch is not capture_epoch or self._key is None:
            return False
        key = self._key
        self._key = None
        self._capture_epoch = None
        self._last_destroyed_capture_seq = max(
            self._last_destroyed_capture_seq,
            capture_epoch.capture_seq,
        )
        del key
        return True

    def has_key_v1(self, capture_epoch: CaptureEpochV1) -> bool:
        return self._capture_epoch is capture_epoch and self._key is not None

    def is_clear_v1(self) -> bool:
        return self._capture_epoch is None and self._key is None


CaptureLivePredicateV1 = Callable[[CaptureEpochV1], bool]
FrameMetadataCommitV1 = Callable[[EvidenceFrameV1], None]
StoreFaultHookV1 = Callable[[PrivateEvidenceStoreFaultPointV1], None]


class PrivateEvidenceStoreV1:
    """One session-owned, capture-scoped encrypted evidence partition.

    This is a trusted-core boundary against ordinary handler access.  It does
    not claim isolation from arbitrary code already executing in this Python
    interpreter.
    """

    __slots__ = (
        "_capture_is_live_v1",
        "_cleanup_trace_v1",
        "_destroyed",
        "_fault_hook_for_test_v1",
        "_key_authority",
        "_last_destroyed_capture_seq",
        "_last_destroyed_cleanup_fence",
        "_lock",
        "_operation_slots",
        "_partition",
        "_private_authority",
        "_work_controller",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        private_authority: PrivateEvidenceAuthorityV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: CaptureLivePredicateV1,
    ) -> None:
        if _construction_authority_v1 is not _STORE_CONSTRUCTION_AUTHORITY_V1:
            raise RuntimeError("private evidence store construction denied")
        if not isinstance(private_authority, PrivateEvidenceAuthorityV1):
            raise TypeError(
                "private_authority must be PrivateEvidenceAuthorityV1"
            )
        if not isinstance(work_controller, SessionWorkControllerV1):
            raise TypeError("work_controller must be SessionWorkControllerV1")
        if not callable(capture_is_live_v1):
            raise TypeError("capture_is_live_v1 must be callable")
        self._private_authority = private_authority
        self._work_controller = work_controller
        self._capture_is_live_v1 = capture_is_live_v1
        self._key_authority = _CaptureKeyAuthorityV1(
            _construction_authority_v1=_KEY_AUTHORITY_CONSTRUCTION_V1
        )
        self._lock = threading.RLock()
        self._operation_slots = threading.BoundedSemaphore(
            MAX_CONCURRENT_PRIVATE_STORE_OPERATIONS_V1
        )
        self._partition: _CapturePartitionV1 | None = None
        self._last_destroyed_capture_seq = 0
        self._last_destroyed_cleanup_fence: (
            RetiredGenerationCleanupFenceV1 | None
        ) = None
        self._destroyed = False
        self._cleanup_trace_v1: tuple[
            PrivateEvidenceCleanupStepV1,
            ...,
        ] = ()
        self._fault_hook_for_test_v1: StoreFaultHookV1 | None = None

    @classmethod
    def _create_for_session_v1(
        cls,
        *,
        private_authority: PrivateEvidenceAuthorityV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: CaptureLivePredicateV1,
    ) -> PrivateEvidenceStoreV1:
        return cls(
            _construction_authority_v1=_STORE_CONSTRUCTION_AUTHORITY_V1,
            private_authority=private_authority,
            work_controller=work_controller,
            capture_is_live_v1=capture_is_live_v1,
        )

    def _set_fault_hook_for_test_v1(
        self,
        hook: StoreFaultHookV1 | None,
    ) -> None:
        with self._lock:
            self._fault_hook_for_test_v1 = hook

    def _call_fault_hook_v1(
        self,
        point: PrivateEvidenceStoreFaultPointV1,
    ) -> None:
        hook = self._fault_hook_for_test_v1
        if hook is not None:
            hook(point)

    @contextmanager
    def _operation_slot_v1(self) -> Iterator[None]:
        if not self._operation_slots.acquire(blocking=False):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.OPERATION_BUSY
            )
        try:
            yield
        finally:
            self._operation_slots.release()

    def _require_access_v1(
        self,
        access: object,
        kind: PrivateEvidenceAccessKindV1,
    ) -> None:
        if not self._private_authority.authorizes_v1(access, kind):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )

    def _require_temporal_binding_locked_v1(
        self,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        operation_kind: WorkOperationKindV1,
        *,
        require_open: bool,
    ) -> _CapturePartitionV1:
        partition = self._partition
        if (
            self._destroyed
            or partition is None
            or partition.capture_epoch is not capture_epoch
            or fence.session_epoch != capture_epoch.session_epoch
            or fence.operation_kind is not operation_kind
            or (require_open and not partition.open)
        ):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.CAPTURE_CLOSED
            )
        return partition

    def create_capture_partition_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        profile_id: str,
        capture_created_at_epoch_seconds: float,
        maximum_expires_at_epoch_seconds: float,
    ) -> CaptureSetV1:
        """Create one key and empty partition under exact live M2/M3 authority."""

        result: list[CaptureSetV1] = []

        def create() -> None:
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.WRITE,
                )
                if (
                    self._destroyed
                    or fence.session_epoch != capture_epoch.session_epoch
                    or fence.operation_kind
                    is not WorkOperationKindV1.CAPTURE_EVIDENCE_PARTITION_OPEN
                    or capture_epoch.capture_seq
                    <= self._last_destroyed_capture_seq
                ):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.CAPTURE_CLOSED
                    )
                existing = self._partition
                if existing is not None:
                    if (
                        existing.capture_epoch is capture_epoch
                        and existing.open
                        and self._key_authority.has_key_v1(capture_epoch)
                    ):
                        result.append(existing.capture_set)
                        return
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                    )
                capture_window = CaptureWindowV1(
                    opened_at_epoch_seconds=(
                        capture_created_at_epoch_seconds
                    ),
                    maximum_expires_at_epoch_seconds=(
                        maximum_expires_at_epoch_seconds
                    ),
                )
                capture_set = CaptureSetV1(
                    capture_epoch=capture_epoch,
                    profile_id=profile_id,
                    capture_created_at_epoch_seconds=(
                        capture_created_at_epoch_seconds
                    ),
                    capture_window=capture_window,
                )
                if not self._key_authority.create_v1(capture_epoch):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                    )
                try:
                    partition = _CapturePartitionV1(
                        capture_epoch=capture_epoch,
                        capture_set=capture_set,
                        open=True,
                        committed=False,
                        nonce_counter=0,
                        records={},
                        evidence_by_frame_id={},
                        frame_id_by_seq={},
                        auxiliary_record_ids=set(),
                        accepted_plaintext_encoded_bytes=0,
                        auxiliary_plaintext_bytes=0,
                        stored_frame_ciphertext_bytes=0,
                        stored_auxiliary_ciphertext_bytes=0,
                    )
                    result.append(capture_set)
                    self._partition = partition
                except Exception:
                    result.clear()
                    self._key_authority.destroy_v1(capture_epoch)
                    raise
                self._cleanup_trace_v1 = ()

        with self._operation_slot_v1():
            try:
                performed = self._work_controller.perform_if_live_v1(
                    fence,
                    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
                    create,
                    _admission_guard_v1=(
                        lambda: self._capture_is_live_v1(capture_epoch)
                    ),
                )
            except PrivateEvidenceStoreErrorV1:
                raise
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - stable store boundary
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
        if not performed or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    def _commit_capture_partition_for_owner_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        """Publish a fully activated, still-empty bootstrap partition."""

        with self._lock:
            partition = self._partition
            if (
                partition is None
                or partition.capture_epoch is not capture_epoch
                or not partition.open
                or partition.committed
                or partition.records
                or partition.evidence_by_frame_id
                or partition.frame_id_by_seq
                or not self._key_authority.has_key_v1(capture_epoch)
                or not self._private_authority._is_canonical_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.WRITE,
                )
            ):
                return False
            partition.committed = True
            return True

    def _rollback_uncommitted_capture_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        """Erase only a never-published empty bootstrap partition.

        A committed capture can be destroyed only with an authenticated M3
        retired-generation cleanup fence.
        """

        with self._lock:
            partition = self._partition
            if partition is None:
                return (
                    capture_epoch.capture_seq
                    <= self._last_destroyed_capture_seq
                )
            if (
                partition.capture_epoch is not capture_epoch
                or partition.committed
                or partition.records
                or partition.evidence_by_frame_id
                or partition.frame_id_by_seq
                or not self._private_authority._is_canonical_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.CLEANUP,
                )
            ):
                return False
            return self._destroy_partition_locked_v1(capture_epoch)

    @staticmethod
    def _aad_v1(
        capture_epoch: CaptureEpochV1,
        record_id: uuid.UUID,
        record_type: PrivateEvidenceRecordTypeV1,
    ) -> bytes:
        return canonical_json_bytes_v1(
            {
                "aad_schema_version": (
                    PRIVATE_EVIDENCE_AAD_SCHEMA_VERSION_V1
                ),
                "capture_id": str(capture_epoch.capture_id),
                "capture_seq": capture_epoch.capture_seq,
                "codec_schema_version": PRIVATE_CODEC_SCHEMA_VERSION_V1,
                "record_id": str(record_id),
                "record_type": record_type.value,
                "schema_version": ENCRYPTED_RECORD_SCHEMA_VERSION_V1,
                "session_generation": (
                    capture_epoch.session_epoch.generation
                ),
                "session_instance_id": str(
                    capture_epoch.session_epoch.session_instance_id
                ),
            }
        )

    @staticmethod
    def _next_nonce_locked_v1(partition: _CapturePartitionV1) -> bytes:
        if partition.nonce_counter >= _MAX_NONCE_COUNTER_V1:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
            )
        partition.nonce_counter += 1
        return partition.nonce_counter.to_bytes(
            AES_GCM_NONCE_BYTES_V1,
            "big",
        )

    def put_frame_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        frame_seq: int,
        received_at_epoch_seconds: float,
        encoded_frame: bytearray,
        encoded_size: int,
        canonical_width: int,
        canonical_height: int,
        sha256_digest: bytes,
        metadata_commit_v1: FrameMetadataCommitV1,
    ) -> StoredFrameV1:
        """Encrypt, insert, and metadata-commit one frame with rollback."""

        if (
            not isinstance(encoded_frame, bytearray)
            or len(encoded_frame) != encoded_size
            or not isinstance(sha256_digest, bytes)
            or len(sha256_digest) != 32
            or not hmac.compare_digest(
                hashlib.sha256(encoded_frame).digest(),
                sha256_digest,
            )
            or not callable(metadata_commit_v1)
        ):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.OPERATION_FAILED
            )
        result: list[StoredFrameV1] = []

        def put() -> None:
            encoded_plaintext: bytes | None = None
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.WRITE,
                )
                partition = self._require_temporal_binding_locked_v1(
                    capture_epoch,
                    fence,
                    WorkOperationKindV1.CAPTURE_FRAME_UPLOAD,
                    require_open=True,
                )
                if (
                    frame_seq in partition.frame_id_by_seq
                    or len(partition.frame_id_by_seq)
                    >= MAX_CAPTURE_FRAMES_V1
                    or len(partition.records)
                    >= MAX_PRIVATE_RECORDS_PER_CAPTURE_V1
                    or partition.accepted_plaintext_encoded_bytes
                    + encoded_size
                    > MAX_CAPTURE_ENCODED_BYTES_V1
                ):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.CAPACITY_EXCEEDED
                    )
                self._call_fault_hook_v1(
                    PrivateEvidenceStoreFaultPointV1.BEFORE_KEY_LOOKUP
                )
                if not self._key_authority.has_key_v1(capture_epoch):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                    )
                frame_id = new_uuid7_v1()
                record_id = new_uuid7_v1()
                nonce = self._next_nonce_locked_v1(partition)
                aad = self._aad_v1(
                    capture_epoch,
                    record_id,
                    PrivateEvidenceRecordTypeV1.FRAME_JPEG,
                )
                previous_capture_set = partition.capture_set
                previous_records = dict(partition.records)
                previous_evidence = dict(partition.evidence_by_frame_id)
                previous_frame_ids = dict(partition.frame_id_by_seq)
                previous_accepted_bytes = (
                    partition.accepted_plaintext_encoded_bytes
                )
                previous_ciphertext_bytes = (
                    partition.stored_frame_ciphertext_bytes
                )
                try:
                    encoded_plaintext = encode_private_record_v1(
                        PrivateEvidenceRecordTypeV1.FRAME_JPEG,
                        encoded_frame,
                    )
                    self._call_fault_hook_v1(
                        PrivateEvidenceStoreFaultPointV1.BEFORE_ENCRYPTION
                    )
                    ciphertext = self._key_authority.encrypt_v1(
                        capture_epoch,
                        nonce,
                        encoded_plaintext,
                        aad,
                    )
                    self._call_fault_hook_v1(
                        PrivateEvidenceStoreFaultPointV1
                        .AFTER_ENCRYPTION_BEFORE_INSERTION
                    )
                    next_ciphertext_bytes = (
                        partition.stored_frame_ciphertext_bytes
                        + len(ciphertext)
                    )
                    if (
                        next_ciphertext_bytes
                        > MAX_FRAME_STORED_CIPHERTEXT_BYTES_V1
                    ):
                        raise PrivateEvidenceStoreErrorV1(
                            PrivateEvidenceStoreReasonV1.CAPACITY_EXCEEDED
                        )
                    record = EncryptedRecordV1(
                        record_id=record_id,
                        record_type=(
                            PrivateEvidenceRecordTypeV1.FRAME_JPEG
                        ),
                        nonce=nonce,
                        ciphertext=ciphertext,
                        created_at_epoch_seconds=(
                            received_at_epoch_seconds
                        ),
                        plaintext_length=len(encoded_plaintext),
                    )
                    evidence = EvidenceFrameV1(
                        frame_id=frame_id,
                        frame_seq=frame_seq,
                        received_at_epoch_seconds=(
                            received_at_epoch_seconds
                        ),
                        encoded_size=encoded_size,
                        canonical_width=canonical_width,
                        canonical_height=canonical_height,
                        sha256=bytes(sha256_digest),
                        capture_epoch=capture_epoch,
                        encrypted_record_ref=record_id,
                    )
                    next_evidence = dict(partition.evidence_by_frame_id)
                    next_evidence[frame_id] = evidence
                    ordered_record_ids = tuple(
                        item.frame_id
                        for item in sorted(
                            next_evidence.values(),
                            key=lambda item: item.frame_seq,
                        )
                    )
                    next_capture_set = replace(
                        partition.capture_set,
                        frame_record_ids=ordered_record_ids,
                    )
                    partition.records[record_id] = record
                    partition.evidence_by_frame_id[frame_id] = evidence
                    partition.frame_id_by_seq[frame_seq] = frame_id
                    partition.accepted_plaintext_encoded_bytes += (
                        encoded_size
                    )
                    partition.stored_frame_ciphertext_bytes = (
                        next_ciphertext_bytes
                    )
                    partition.capture_set = next_capture_set
                    self._call_fault_hook_v1(
                        PrivateEvidenceStoreFaultPointV1
                        .AFTER_INSERTION_BEFORE_METADATA_COMMIT
                    )
                    stored_frame = StoredFrameV1(
                        evidence_frame=evidence,
                        stored_ciphertext_bytes=len(ciphertext),
                    )
                    result.append(stored_frame)
                    metadata_commit_v1(evidence)
                except BaseException:
                    result.clear()
                    partition.capture_set = previous_capture_set
                    partition.records = previous_records
                    partition.evidence_by_frame_id = previous_evidence
                    partition.frame_id_by_seq = previous_frame_ids
                    partition.accepted_plaintext_encoded_bytes = (
                        previous_accepted_bytes
                    )
                    partition.stored_frame_ciphertext_bytes = (
                        previous_ciphertext_bytes
                    )
                    raise
                finally:
                    if encoded_plaintext is not None:
                        del encoded_plaintext

        with self._operation_slot_v1():
            try:
                performed = self._work_controller.perform_if_live_v1(
                    fence,
                    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
                    put,
                    _admission_guard_v1=(
                        lambda: self._capture_is_live_v1(capture_epoch)
                    ),
                )
            except PrivateEvidenceStoreErrorV1:
                raise
            except asyncio.CancelledError:
                raise
            except (PrivateCodecErrorV1, _CaptureKeyUnavailableV1):
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                ) from None
            except Exception:  # noqa: BLE001 - stable store boundary
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
        if not performed or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    def put_record_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        canonical_json_payload: bytes,
        created_at_epoch_seconds: float,
    ) -> uuid.UUID:
        """Store one bounded synthetic/future canonical auxiliary record."""

        if (
            not isinstance(canonical_json_payload, bytes)
            or not 0 < len(canonical_json_payload)
            <= MAX_AUXILIARY_CANONICAL_JSON_BYTES_V1
        ):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.OPERATION_FAILED
            )
        result: list[uuid.UUID] = []

        def put() -> None:
            encoded_plaintext: bytes | None = None
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.WRITE,
                )
                partition = self._require_temporal_binding_locked_v1(
                    capture_epoch,
                    fence,
                    WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY,
                    require_open=True,
                )
                if (
                    len(partition.auxiliary_record_ids)
                    >= MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1
                    or len(partition.records)
                    >= MAX_PRIVATE_RECORDS_PER_CAPTURE_V1
                    or partition.auxiliary_plaintext_bytes
                    + len(canonical_json_payload)
                    > MAX_AUXILIARY_CAPTURE_PLAINTEXT_BYTES_V1
                ):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.CAPACITY_EXCEEDED
                    )
                if not self._key_authority.has_key_v1(capture_epoch):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                    )
                record_id = new_uuid7_v1()
                nonce = self._next_nonce_locked_v1(partition)
                aad = self._aad_v1(
                    capture_epoch,
                    record_id,
                    PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON,
                )
                previous_records = dict(partition.records)
                previous_auxiliary_ids = set(
                    partition.auxiliary_record_ids
                )
                previous_plaintext_bytes = (
                    partition.auxiliary_plaintext_bytes
                )
                previous_ciphertext_bytes = (
                    partition.stored_auxiliary_ciphertext_bytes
                )
                try:
                    encoded_plaintext = encode_private_record_v1(
                        PrivateEvidenceRecordTypeV1
                        .AUXILIARY_CANONICAL_JSON,
                        canonical_json_payload,
                    )
                    ciphertext = self._key_authority.encrypt_v1(
                        capture_epoch,
                        nonce,
                        encoded_plaintext,
                        aad,
                    )
                    next_ciphertext_bytes = (
                        partition.stored_auxiliary_ciphertext_bytes
                        + len(ciphertext)
                    )
                    if (
                        next_ciphertext_bytes
                        > MAX_AUXILIARY_STORED_CIPHERTEXT_BYTES_V1
                    ):
                        raise PrivateEvidenceStoreErrorV1(
                            PrivateEvidenceStoreReasonV1.CAPACITY_EXCEEDED
                        )
                    record = EncryptedRecordV1(
                        record_id=record_id,
                        record_type=(
                            PrivateEvidenceRecordTypeV1
                            .AUXILIARY_CANONICAL_JSON
                        ),
                        nonce=nonce,
                        ciphertext=ciphertext,
                        created_at_epoch_seconds=(
                            created_at_epoch_seconds
                        ),
                        plaintext_length=len(encoded_plaintext),
                    )
                    partition.records[record_id] = record
                    partition.auxiliary_record_ids.add(record_id)
                    partition.auxiliary_plaintext_bytes += len(
                        canonical_json_payload
                    )
                    partition.stored_auxiliary_ciphertext_bytes = (
                        next_ciphertext_bytes
                    )
                    result.append(record_id)
                except BaseException:
                    result.clear()
                    partition.records = previous_records
                    partition.auxiliary_record_ids = (
                        previous_auxiliary_ids
                    )
                    partition.auxiliary_plaintext_bytes = (
                        previous_plaintext_bytes
                    )
                    partition.stored_auxiliary_ciphertext_bytes = (
                        previous_ciphertext_bytes
                    )
                    raise
                finally:
                    if encoded_plaintext is not None:
                        del encoded_plaintext

        with self._operation_slot_v1():
            try:
                performed = self._work_controller.perform_if_live_v1(
                    fence,
                    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
                    put,
                    _admission_guard_v1=(
                        lambda: self._capture_is_live_v1(capture_epoch)
                    ),
                )
            except PrivateEvidenceStoreErrorV1:
                raise
            except asyncio.CancelledError:
                raise
            except (PrivateCodecErrorV1, _CaptureKeyUnavailableV1):
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
            except Exception:  # noqa: BLE001 - stable store boundary
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
        if not performed or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    def _decrypt_record_locked_v1(
        self,
        partition: _CapturePartitionV1,
        record: EncryptedRecordV1,
        expected_record_id: uuid.UUID,
        expected_record_type: PrivateEvidenceRecordTypeV1,
    ) -> bytes:
        if record.record_id != expected_record_id:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
            )
        if record.record_type is not expected_record_type:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.RECORD_TYPE_MISMATCH
            )
        aad = self._aad_v1(
            partition.capture_epoch,
            expected_record_id,
            expected_record_type,
        )
        encoded_plaintext: bytes | None = None
        try:
            encoded_plaintext = self._key_authority.decrypt_v1(
                partition.capture_epoch,
                record.nonce,
                record.ciphertext,
                aad,
            )
            if len(encoded_plaintext) != record.plaintext_length:
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
                )
            return decode_private_record_v1(
                expected_record_type,
                encoded_plaintext,
            )
        except PrivateEvidenceStoreErrorV1:
            raise
        except (InvalidTag, PrivateCodecErrorV1):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
            ) from None
        except _CaptureKeyUnavailableV1:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
            ) from None
        except Exception:  # noqa: BLE001 - no crypto exception escapes
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
            ) from None
        finally:
            if encoded_plaintext is not None:
                del encoded_plaintext

    def get_frame_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        frame_id: uuid.UUID,
    ) -> bytes:
        """Return exact JPEG bytes only to a live authorized internal caller."""

        result: list[bytes] = []

        def read() -> None:
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.READ,
                )
                partition = self._require_temporal_binding_locked_v1(
                    capture_epoch,
                    fence,
                    WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
                    require_open=True,
                )
                evidence = partition.evidence_by_frame_id.get(frame_id)
                if (
                    evidence is None
                    or evidence.capture_epoch is not capture_epoch
                    or partition.frame_id_by_seq.get(evidence.frame_seq)
                    != frame_id
                ):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.RECORD_NOT_FOUND
                    )
                record = partition.records.get(
                    evidence.encrypted_record_ref
                )
                if record is None:
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
                    )
                result.append(
                    self._decrypt_record_locked_v1(
                        partition,
                        record,
                        evidence.encrypted_record_ref,
                        PrivateEvidenceRecordTypeV1.FRAME_JPEG,
                    )
                )

        with self._operation_slot_v1():
            try:
                performed = self._work_controller.perform_if_live_v1(
                    fence,
                    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
                    read,
                    _admission_guard_v1=(
                        lambda: self._capture_is_live_v1(capture_epoch)
                    ),
                )
            except PrivateEvidenceStoreErrorV1:
                raise
            except Exception:  # noqa: BLE001 - stable store boundary
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
        if not performed or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    def get_record_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        record_id: uuid.UUID,
        expected_record_type: PrivateEvidenceRecordTypeV1,
    ) -> bytes:
        """Read one exact auxiliary record; frame reads use get_frame_v1."""

        if (
            expected_record_type
            is not PrivateEvidenceRecordTypeV1.AUXILIARY_CANONICAL_JSON
        ):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.RECORD_TYPE_MISMATCH
            )
        result: list[bytes] = []

        def read() -> None:
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.READ,
                )
                partition = self._require_temporal_binding_locked_v1(
                    capture_epoch,
                    fence,
                    WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
                    require_open=True,
                )
                if record_id not in partition.auxiliary_record_ids:
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.RECORD_NOT_FOUND
                    )
                record = partition.records.get(record_id)
                if record is None:
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE
                    )
                result.append(
                    self._decrypt_record_locked_v1(
                        partition,
                        record,
                        record_id,
                        expected_record_type,
                    )
                )

        with self._operation_slot_v1():
            try:
                performed = self._work_controller.perform_if_live_v1(
                    fence,
                    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
                    read,
                    _admission_guard_v1=(
                        lambda: self._capture_is_live_v1(capture_epoch)
                    ),
                )
            except PrivateEvidenceStoreErrorV1:
                raise
            except Exception:  # noqa: BLE001 - stable store boundary
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
        if not performed or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    def delete_record_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
        record_id: uuid.UUID,
    ) -> bool:
        """Delete one bounded auxiliary record under live ordinary authority."""

        deleted: list[bool] = []

        def delete() -> None:
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.DELETE,
                )
                partition = self._require_temporal_binding_locked_v1(
                    capture_epoch,
                    fence,
                    WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY,
                    require_open=True,
                )
                if record_id not in partition.auxiliary_record_ids:
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.RECORD_NOT_FOUND
                    )
                record = partition.records.get(record_id)
                if (
                    record is None
                    or record.record_type
                    is not PrivateEvidenceRecordTypeV1
                    .AUXILIARY_CANONICAL_JSON
                ):
                    raise PrivateEvidenceStoreErrorV1(
                        PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                    )
                previous_records = dict(partition.records)
                previous_auxiliary_ids = set(
                    partition.auxiliary_record_ids
                )
                previous_plaintext_bytes = (
                    partition.auxiliary_plaintext_bytes
                )
                previous_ciphertext_bytes = (
                    partition.stored_auxiliary_ciphertext_bytes
                )
                try:
                    partition.records.pop(record_id)
                    partition.auxiliary_record_ids.remove(record_id)
                    partition.auxiliary_plaintext_bytes -= (
                        record.plaintext_length
                        - PRIVATE_CODEC_OVERHEAD_BYTES_V1
                    )
                    partition.stored_auxiliary_ciphertext_bytes -= len(
                        record.ciphertext
                    )
                    deleted.append(True)
                except BaseException:
                    deleted.clear()
                    partition.records = previous_records
                    partition.auxiliary_record_ids = (
                        previous_auxiliary_ids
                    )
                    partition.auxiliary_plaintext_bytes = (
                        previous_plaintext_bytes
                    )
                    partition.stored_auxiliary_ciphertext_bytes = (
                        previous_ciphertext_bytes
                    )
                    raise

        with self._operation_slot_v1():
            try:
                performed = self._work_controller.perform_if_live_v1(
                    fence,
                    WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
                    delete,
                    _admission_guard_v1=(
                        lambda: self._capture_is_live_v1(capture_epoch)
                    ),
                )
            except PrivateEvidenceStoreErrorV1:
                raise
            except Exception:  # noqa: BLE001 - stable store boundary
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.OPERATION_FAILED
                ) from None
        return bool(performed and deleted)

    def capture_set_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        fence: WorkFenceV1,
    ) -> CaptureSetV1:
        result: list[CaptureSetV1] = []

        def read() -> None:
            with self._lock:
                self._require_access_v1(
                    access,
                    PrivateEvidenceAccessKindV1.READ,
                )
                partition = self._require_temporal_binding_locked_v1(
                    capture_epoch,
                    fence,
                    WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
                    require_open=True,
                )
                result.append(partition.capture_set)

        with self._operation_slot_v1():
            performed = self._work_controller.perform_if_live_v1(
                fence,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
                read,
                _admission_guard_v1=(
                    lambda: self._capture_is_live_v1(capture_epoch)
                ),
            )
        if not performed or not result:
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        return result[0]

    def close_capture_admission_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        """Close new store operations before retirement/key destruction."""

        with self._lock:
            self._require_access_v1(
                access,
                PrivateEvidenceAccessKindV1.CLEANUP,
            )
            partition = self._partition
            if partition is None:
                return self._key_authority.is_clear_v1()
            if partition.capture_epoch is not capture_epoch:
                return False
            partition.open = False
            if (
                not self._cleanup_trace_v1
                or self._cleanup_trace_v1[-1]
                is not PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED
            ):
                self._cleanup_trace_v1 = (
                    PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED,
                )
            return True

    def _close_capture_admission_for_owner_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        """Core-owned admission close that remains usable after M2 revocation."""

        with self._lock:
            if not self._private_authority._is_canonical_access_v1(
                access,
                PrivateEvidenceAccessKindV1.CLEANUP,
            ):
                return False
            partition = self._partition
            if partition is None:
                return self._key_authority.is_clear_v1()
            if partition.capture_epoch is not capture_epoch:
                return False
            partition.open = False
            if (
                not self._cleanup_trace_v1
                or self._cleanup_trace_v1[-1]
                is not PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED
            ):
                self._cleanup_trace_v1 = (
                    PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED,
                )
            return True

    def _destroy_partition_locked_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> bool:
        partition = self._partition
        if partition is None:
            return capture_epoch.capture_seq <= self._last_destroyed_capture_seq
        if partition.capture_epoch is not capture_epoch:
            return False
        partition.open = False
        trace = list(self._cleanup_trace_v1)
        if not trace:
            trace.append(PrivateEvidenceCleanupStepV1.ADMISSION_CLOSED)
        if not self._key_authority.destroy_v1(capture_epoch):
            return False
        trace.append(PrivateEvidenceCleanupStepV1.KEY_DESTROYED)
        partition.records.clear()
        trace.append(PrivateEvidenceCleanupStepV1.CIPHERTEXT_CLEARED)
        partition.evidence_by_frame_id.clear()
        partition.frame_id_by_seq.clear()
        partition.auxiliary_record_ids.clear()
        trace.append(PrivateEvidenceCleanupStepV1.INDICES_CLEARED)
        partition.capture_set = replace(
            partition.capture_set,
            frame_record_ids=(),
            inference_identity_ref=None,
            calibration_dependency_ref=None,
        )
        partition.accepted_plaintext_encoded_bytes = 0
        partition.auxiliary_plaintext_bytes = 0
        partition.stored_frame_ciphertext_bytes = 0
        partition.stored_auxiliary_ciphertext_bytes = 0
        trace.append(PrivateEvidenceCleanupStepV1.METADATA_CLEARED)
        self._last_destroyed_capture_seq = max(
            self._last_destroyed_capture_seq,
            capture_epoch.capture_seq,
        )
        self._partition = None
        self._cleanup_trace_v1 = tuple(trace)
        return True

    def destroy_capture_v1(
        self,
        *,
        access: PrivateEvidenceAccessV1,
        capture_epoch: CaptureEpochV1,
        cleanup_fence: RetiredGenerationCleanupFenceV1,
    ) -> bool:
        """Cryptographically erase one retired capture before record cleanup."""

        with self._lock:
            if not self._private_authority._is_canonical_access_v1(
                access,
                PrivateEvidenceAccessKindV1.CLEANUP,
            ):
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.ACCESS_DENIED
                )
            if (
                self._partition is None
                and capture_epoch.capture_seq
                <= self._last_destroyed_capture_seq
            ):
                return cleanup_fence is self._last_destroyed_cleanup_fence
        if any(
            not self._work_controller.authorize_cleanup_v1(
                cleanup_fence,
                action,
            )
            for action in (
                CleanupActionV1.CLOSE,
                CleanupActionV1.DELETE,
                CleanupActionV1.PURGE,
            )
        ):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        if (
            cleanup_fence.session_instance_id
            != capture_epoch.session_epoch.session_instance_id
            or cleanup_fence.retired_generation
            != capture_epoch.session_epoch.generation
        ):
            raise PrivateEvidenceStoreErrorV1(
                PrivateEvidenceStoreReasonV1.ACCESS_DENIED
            )
        with self._lock:
            if not self._destroy_partition_locked_v1(capture_epoch):
                raise PrivateEvidenceStoreErrorV1(
                    PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE
                )
            self._last_destroyed_cleanup_fence = cleanup_fence
            return True

    def shutdown_v1(
        self,
        *,
        cleanup_access: PrivateEvidenceAccessV1,
    ) -> bool:
        with self._lock:
            if not self._private_authority._is_canonical_access_v1(
                cleanup_access,
                PrivateEvidenceAccessKindV1.CLEANUP,
            ):
                return False
            if self._partition is not None or not self._key_authority.is_clear_v1():
                return False
            self._destroyed = True
            self._private_authority.close_v1()
            return self._partition is None

    def is_capture_clear_v1(self) -> bool:
        with self._lock:
            return bool(
                self._partition is None
                and self._key_authority.is_clear_v1()
            )

    def snapshot_v1(self) -> PrivateEvidenceStoreSnapshotV1:
        with self._lock:
            partition = self._partition
            if partition is None:
                return PrivateEvidenceStoreSnapshotV1(
                    partition_open=False,
                    key_present=False,
                    frame_record_count=0,
                    auxiliary_record_count=0,
                    accepted_plaintext_encoded_bytes=0,
                    stored_frame_ciphertext_bytes=0,
                    stored_auxiliary_ciphertext_bytes=0,
                    bounded_index_accounting_bytes=0,
                    last_destroyed_capture_seq=(
                        self._last_destroyed_capture_seq
                    ),
                )
            return PrivateEvidenceStoreSnapshotV1(
                partition_open=partition.open,
                key_present=self._key_authority.has_key_v1(
                    partition.capture_epoch
                ),
                frame_record_count=len(partition.frame_id_by_seq),
                auxiliary_record_count=len(
                    partition.auxiliary_record_ids
                ),
                accepted_plaintext_encoded_bytes=(
                    partition.accepted_plaintext_encoded_bytes
                ),
                stored_frame_ciphertext_bytes=(
                    partition.stored_frame_ciphertext_bytes
                ),
                stored_auxiliary_ciphertext_bytes=(
                    partition.stored_auxiliary_ciphertext_bytes
                ),
                bounded_index_accounting_bytes=(
                    len(partition.records)
                    * ENCRYPTED_RECORD_METADATA_ACCOUNTING_BYTES_V1
                ),
                last_destroyed_capture_seq=(
                    self._last_destroyed_capture_seq
                ),
            )

    def cleanup_trace_v1(self) -> tuple[PrivateEvidenceCleanupStepV1, ...]:
        with self._lock:
            return self._cleanup_trace_v1

    def __repr__(self) -> str:
        return "PrivateEvidenceStoreV1(<encrypted-private-state>)"
__all__ = [
    "AES_256_KEY_BYTES_V1",
    "AES_GCM_NONCE_BYTES_V1",
    "AES_GCM_TAG_BYTES_V1",
    "ENCRYPTED_RECORD_SCHEMA_VERSION_V1",
    "MAX_AUXILIARY_CAPTURE_PLAINTEXT_BYTES_V1",
    "MAX_AUXILIARY_RECORDS_PER_CAPTURE_V1",
    "MAX_CONCURRENT_PRIVATE_STORE_OPERATIONS_V1",
    "MAX_FRAME_STORED_CIPHERTEXT_BYTES_V1",
    "MAX_PRIVATE_INDEX_ACCOUNTING_BYTES_V1",
    "MAX_PRIVATE_RECORDS_PER_CAPTURE_V1",
    "PRIVATE_EVIDENCE_AAD_SCHEMA_VERSION_V1",
    "EncryptedRecordV1",
    "PrivateEvidenceCleanupStepV1",
    "PrivateEvidenceStoreErrorV1",
    "PrivateEvidenceStoreFaultPointV1",
    "PrivateEvidenceStoreReasonV1",
    "PrivateEvidenceStoreSnapshotV1",
    "PrivateEvidenceStoreV1",
    "StoredFrameV1",
]

"""Owning-process M2/M3/M5A composition for private CPU OCR."""

from __future__ import annotations

import asyncio
import hmac
import math
import threading
import time
import uuid
from collections.abc import Callable

from certificate_capture.contracts.evidence import EvidenceFrameV1
from certificate_capture.contracts.inference import InferenceIdentityV1
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    OcrResultStorageKeyV1,
    StoredOcrResultV1,
    processing_identity_sha256_v1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.ocr.client import (
    MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1,
    OcrTransportClientV1,
)
from certificate_capture.ocr.protocol import (
    MAX_OCR_FRAMES_PER_OPERATION_V1,
    OcrFailureReasonV1,
    OcrRequestV1,
    OcrServiceErrorV1,
    parse_ocr_response_payload_v1,
)
from certificate_capture.private_authority import (
    PrivateEvidenceAccessV1,
    PrivateEvidenceAuthorityV1,
)
from certificate_capture.private_store import (
    PrivateEvidenceStoreErrorV1,
    PrivateEvidenceStoreReasonV1,
    PrivateEvidenceStoreV1,
)
from chat_engine.security.ids import new_uuid7_v1
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    RegisteredWorkV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

CaptureOcrLivePredicateV1 = Callable[[CaptureEpochV1], bool]
FatalStoreFailureV1 = Callable[[], None]

_OCR_SERVICE_CONSTRUCTION_AUTHORITY_V1 = object()


class PrivateOcrServiceV1:
    """Core-owned private OCR runner; it returns only encrypted-store receipts."""

    __slots__ = (
        "_active_lock",
        "_active_work",
        "_capture_is_live_v1",
        "_client",
        "_closed",
        "_expected_identity",
        "_expected_qualification_record_sha256",
        "_fatal_store_failure_v1",
        "_monotonic_clock_v1",
        "_private_authority",
        "_read_access",
        "_store",
        "_wall_clock_v1",
        "_work_controller",
        "_work_fence_timeout_seconds",
        "_write_access",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        client: OcrTransportClientV1,
        expected_identity: InferenceIdentityV1,
        expected_qualification_record_sha256: str,
        private_authority: PrivateEvidenceAuthorityV1,
        store: PrivateEvidenceStoreV1,
        read_access: PrivateEvidenceAccessV1,
        write_access: PrivateEvidenceAccessV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: CaptureOcrLivePredicateV1,
        fatal_store_failure_v1: FatalStoreFailureV1,
        wall_clock_v1: Callable[[], float],
        monotonic_clock_v1: Callable[[], float],
    ) -> None:
        if _construction_authority_v1 is not _OCR_SERVICE_CONSTRUCTION_AUTHORITY_V1:
            raise RuntimeError("private OCR service construction denied")
        if not isinstance(private_authority, PrivateEvidenceAuthorityV1):
            raise TypeError("private_authority must be PrivateEvidenceAuthorityV1")
        if not isinstance(store, PrivateEvidenceStoreV1):
            raise TypeError("store must be PrivateEvidenceStoreV1")
        if not isinstance(work_controller, SessionWorkControllerV1):
            raise TypeError("work_controller must be SessionWorkControllerV1")
        if not isinstance(expected_identity, InferenceIdentityV1):
            raise TypeError("expected_identity must be InferenceIdentityV1")
        if (
            not isinstance(expected_qualification_record_sha256, str)
            or len(expected_qualification_record_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_qualification_record_sha256
            )
        ):
            raise ValueError("expected qualification identity is invalid")
        client_identity = getattr(client, "expected_identity_v1", None)
        client_qualification = getattr(
            client,
            "expected_qualification_record_sha256_v1",
            None,
        )
        work_fence_timeout = getattr(
            client,
            "work_fence_timeout_seconds_v1",
            None,
        )
        if (
            not isinstance(client_identity, InferenceIdentityV1)
            or not hmac.compare_digest(
                client_identity.inference_identity_sha256,
                expected_identity.inference_identity_sha256,
            )
            or not isinstance(client_qualification, str)
            or not hmac.compare_digest(
                client_qualification,
                expected_qualification_record_sha256,
            )
            or isinstance(work_fence_timeout, bool)
            or not isinstance(work_fence_timeout, (int, float))
            or not math.isfinite(work_fence_timeout)
            or not 1.0
            <= float(work_fence_timeout)
            <= MAX_OCR_WORK_FENCE_TIMEOUT_SECONDS_V1
        ):
            raise ValueError("OCR client identity does not match readiness")
        if not callable(capture_is_live_v1):
            raise TypeError("capture_is_live_v1 must be callable")
        if not callable(fatal_store_failure_v1):
            raise TypeError("fatal_store_failure_v1 must be callable")
        self._client = client
        self._expected_identity = expected_identity
        self._expected_qualification_record_sha256 = (
            expected_qualification_record_sha256
        )
        self._work_fence_timeout_seconds = float(work_fence_timeout)
        self._private_authority = private_authority
        self._store = store
        self._read_access = read_access
        self._write_access = write_access
        self._work_controller = work_controller
        self._capture_is_live_v1 = capture_is_live_v1
        self._fatal_store_failure_v1 = fatal_store_failure_v1
        self._wall_clock_v1 = wall_clock_v1
        self._monotonic_clock_v1 = monotonic_clock_v1
        self._active_lock = threading.RLock()
        self._active_work: dict[
            uuid.UUID,
            tuple[CaptureEpochV1, RegisteredWorkV1],
        ] = {}
        self._closed = False

    @classmethod
    def _create_for_coordinator_v1(
        cls,
        *,
        client: OcrTransportClientV1,
        expected_identity: InferenceIdentityV1,
        expected_qualification_record_sha256: str,
        private_authority: PrivateEvidenceAuthorityV1,
        store: PrivateEvidenceStoreV1,
        read_access: PrivateEvidenceAccessV1,
        write_access: PrivateEvidenceAccessV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: CaptureOcrLivePredicateV1,
        fatal_store_failure_v1: FatalStoreFailureV1,
        wall_clock_v1: Callable[[], float] = time.time,
        monotonic_clock_v1: Callable[[], float] = time.monotonic,
    ) -> PrivateOcrServiceV1:
        return cls(
            _construction_authority_v1=(_OCR_SERVICE_CONSTRUCTION_AUTHORITY_V1),
            client=client,
            expected_identity=expected_identity,
            expected_qualification_record_sha256=(expected_qualification_record_sha256),
            private_authority=private_authority,
            store=store,
            read_access=read_access,
            write_access=write_access,
            work_controller=work_controller,
            capture_is_live_v1=capture_is_live_v1,
            fatal_store_failure_v1=fatal_store_failure_v1,
            wall_clock_v1=wall_clock_v1,
            monotonic_clock_v1=monotonic_clock_v1,
        )

    @property
    def expected_identity_v1(self) -> InferenceIdentityV1:
        return self._expected_identity

    def _require_fixed_client_identity_v1(self) -> None:
        current_identity = getattr(
            self._client,
            "expected_identity_v1",
            None,
        )
        current_qualification = getattr(
            self._client,
            "expected_qualification_record_sha256_v1",
            None,
        )
        if (
            not isinstance(current_identity, InferenceIdentityV1)
            or not hmac.compare_digest(
                current_identity.inference_identity_sha256,
                self._expected_identity.inference_identity_sha256,
            )
            or not isinstance(current_qualification, str)
            or not hmac.compare_digest(
                current_qualification,
                self._expected_qualification_record_sha256,
            )
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.IDENTITY_MISMATCH)

    def _capture_live_v1(self, capture_epoch: CaptureEpochV1) -> bool:
        try:
            return bool(
                not self._closed
                and self._private_authority.is_usable_v1()
                and self._capture_is_live_v1(capture_epoch)
            )
        except Exception:  # noqa: BLE001 - authority callbacks fail closed
            return False

    def _require_live_v1(
        self,
        capture_epoch: CaptureEpochV1,
        registered_work: RegisteredWorkV1,
        boundary: WorkValidationBoundaryV1,
    ) -> None:
        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or not isinstance(registered_work, RegisteredWorkV1)
            or registered_work.fence.session_epoch != capture_epoch.session_epoch
            or registered_work.fence.operation_kind
            is not WorkOperationKindV1.OCR_INFERENCE
            or not self._capture_live_v1(capture_epoch)
            or not self._work_controller.validate_work_v1(
                registered_work.fence,
                boundary,
            )
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED)

    def _register_child_v1(
        self,
        *,
        parent: RegisteredWorkV1,
        operation_kind: WorkOperationKindV1,
    ) -> RegisteredWorkV1:
        try:
            return self._work_controller.register_child_work_v1(
                parent.fence,
                operation_kind,
                parent.fence.deadline_monotonic,
            )
        except WorkAdmissionDeniedV1:
            raise OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED) from None

    def _register_root_v1(
        self,
        capture_epoch: CaptureEpochV1,
    ) -> RegisteredWorkV1:
        deadline = float(self._monotonic_clock_v1()) + self._work_fence_timeout_seconds
        try:
            registered = self._work_controller.register_work_v1(
                WorkOperationKindV1.OCR_INFERENCE,
                deadline,
            )
        except Exception:  # noqa: BLE001 - stable OCR admission boundary
            raise OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED) from None
        if registered.fence.session_epoch != capture_epoch.session_epoch:
            self._work_controller.release_work_v1(registered.lease)
            raise OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED)
        if not self._capture_live_v1(capture_epoch):
            self._work_controller.release_work_v1(registered.lease)
            raise OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED)
        with self._active_lock:
            if self._closed:
                self._work_controller.release_work_v1(registered.lease)
                raise OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED)
            self._active_work[registered.fence.operation_id] = (
                capture_epoch,
                registered,
            )
        return registered

    def _release_root_v1(
        self,
        registered: RegisteredWorkV1,
    ) -> None:
        with self._active_lock:
            self._active_work.pop(
                registered.fence.operation_id,
                None,
            )
        self._work_controller.release_work_v1(registered.lease)

    def _map_store_error_v1(
        self,
        exception: PrivateEvidenceStoreErrorV1,
    ) -> OcrServiceErrorV1:
        if exception.reason in {
            PrivateEvidenceStoreReasonV1.ACCESS_DENIED,
            PrivateEvidenceStoreReasonV1.CAPTURE_CLOSED,
            PrivateEvidenceStoreReasonV1.RECORD_NOT_FOUND,
        }:
            return OcrServiceErrorV1(OcrFailureReasonV1.WORK_RETIRED)
        if exception.reason is PrivateEvidenceStoreReasonV1.IDENTITY_MISMATCH:
            return OcrServiceErrorV1(OcrFailureReasonV1.IDENTITY_MISMATCH)
        if exception.reason in {
            PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE,
            PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE,
            PrivateEvidenceStoreReasonV1.RECORD_TYPE_MISMATCH,
        }:
            try:
                self._fatal_store_failure_v1()
            except Exception:  # noqa: BLE001, S110 - failure remains closed
                pass
        return OcrServiceErrorV1(OcrFailureReasonV1.STORE_REJECTED)

    async def _process_one_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        evidence_frame: EvidenceFrameV1,
    ) -> StoredOcrResultV1:
        registered = self._register_root_v1(capture_epoch)
        read_work: RegisteredWorkV1 | None = None
        write_work: RegisteredWorkV1 | None = None
        jpeg_buffer: bytearray | None = None
        response_payload: bytes | None = None
        page_result: OcrPageResultV1 | None = None
        try:
            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
            )
            self._require_fixed_client_identity_v1()
            expected_identity = self._expected_identity
            preprocessing_sha256 = processing_identity_sha256_v1(
                expected_identity.preprocessing
            )
            key = OcrResultStorageKeyV1(
                frame_id=evidence_frame.frame_id,
                inference_identity_sha256=(expected_identity.inference_identity_sha256),
                preprocessing_identity_sha256=preprocessing_sha256,
            )

            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
            )
            read_work = self._register_child_v1(
                parent=registered,
                operation_kind=WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
            )
            try:
                existing = self._store.find_ocr_result_v1(
                    access=self._read_access,
                    capture_epoch=capture_epoch,
                    fence=read_work.fence,
                    key=key,
                )
                if existing is not None:
                    self._require_live_v1(
                        capture_epoch,
                        registered,
                        WorkValidationBoundaryV1.BEFORE_COMPLETION,
                    )
                    return existing
                frame_plaintext = self._store.get_frame_for_ocr_v1(
                    access=self._read_access,
                    capture_epoch=capture_epoch,
                    fence=read_work.fence,
                    frame_id=evidence_frame.frame_id,
                )
            except PrivateEvidenceStoreErrorV1 as exception:
                raise self._map_store_error_v1(exception) from None
            finally:
                self._work_controller.release_work_v1(read_work.lease)
                read_work = None

            try:
                jpeg_buffer = bytearray(frame_plaintext)
            finally:
                del frame_plaintext

            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.BEFORE_EXTERNAL_CALL,
            )
            request = OcrRequestV1(
                request_id=new_uuid7_v1(),
                frame_id=evidence_frame.frame_id,
                capture_epoch=capture_epoch,
                operation_id=registered.fence.operation_id,
                inference_identity_expected=(
                    expected_identity.inference_identity_sha256
                ),
                preprocessing_identity_sha256_expected=(preprocessing_sha256),
                canonical_width=evidence_frame.canonical_width,
                canonical_height=evidence_frame.canonical_height,
                jpeg_length=len(jpeg_buffer),
            )
            response_payload = await self._client.exchange_v1(
                request,
                jpeg_buffer,
                registered.cancellation,
            )
            jpeg_buffer.clear()
            jpeg_buffer = None

            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
            )
            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
            )
            page_result = parse_ocr_response_payload_v1(
                response_payload,
                request=request,
            )
            del response_payload
            response_payload = None

            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
            )
            write_work = self._register_child_v1(
                parent=registered,
                operation_kind=(WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY),
            )
            try:
                stored = self._store.put_ocr_result_v1(
                    access=self._write_access,
                    capture_epoch=capture_epoch,
                    fence=write_work.fence,
                    page_result=page_result,
                    calibration_dependency_ref=(
                        expected_identity.calibration_dependency_v1().calibration_dependency_sha256
                    ),
                    created_at_epoch_seconds=float(self._wall_clock_v1()),
                )
            except PrivateEvidenceStoreErrorV1 as exception:
                raise self._map_store_error_v1(exception) from None
            finally:
                self._work_controller.release_work_v1(write_work.lease)
                write_work = None
            self._require_live_v1(
                capture_epoch,
                registered,
                WorkValidationBoundaryV1.BEFORE_COMPLETION,
            )
            return stored
        except asyncio.CancelledError:
            try:
                await self._client.cancel_operation_v1(registered.fence.operation_id)
            except BaseException:  # noqa: BLE001, S110 - payload-free cancel
                pass
            raise
        finally:
            if jpeg_buffer is not None:
                jpeg_buffer.clear()
            if response_payload is not None:
                del response_payload
            if page_result is not None:
                del page_result
            if read_work is not None:
                self._work_controller.release_work_v1(read_work.lease)
            if write_work is not None:
                self._work_controller.release_work_v1(write_work.lease)
            self._release_root_v1(registered)

    async def process_frames_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        evidence_frames: tuple[EvidenceFrameV1, ...],
    ) -> tuple[StoredOcrResultV1, ...]:
        """Process an explicit bounded frame list sequentially."""

        if not isinstance(capture_epoch, CaptureEpochV1):
            raise OcrServiceErrorV1(OcrFailureReasonV1.REQUEST_REJECTED)
        if (
            not isinstance(evidence_frames, tuple)
            or not 1 <= len(evidence_frames) <= MAX_OCR_FRAMES_PER_OPERATION_V1
            or not all(
                isinstance(frame, EvidenceFrameV1)
                and frame.capture_epoch is capture_epoch
                for frame in evidence_frames
            )
            or len({frame.frame_id for frame in evidence_frames})
            != len(evidence_frames)
        ):
            raise OcrServiceErrorV1(OcrFailureReasonV1.REQUEST_REJECTED)
        results: list[StoredOcrResultV1] = []
        for evidence_frame in evidence_frames:
            results.append(
                await self._process_one_v1(
                    capture_epoch=capture_epoch,
                    evidence_frame=evidence_frame,
                )
            )
        return tuple(results)

    def retire_capture_v1(self, capture_epoch: CaptureEpochV1) -> None:
        """Cancel exact-generation OCR work without awaiting under owner locks."""

        with self._active_lock:
            work_items = tuple(
                registered
                for active_epoch, registered in self._active_work.values()
                if active_epoch is capture_epoch
            )
        for registered in work_items:
            try:
                self._work_controller.cancel_work_v1(registered.fence)
            except Exception:  # noqa: BLE001, S112 - retirement fails closed
                continue

    def active_request_count_v1(self) -> int:
        with self._active_lock:
            return len(self._active_work)

    def close_admission_v1(self) -> None:
        with self._active_lock:
            self._closed = True
            work_items = tuple(
                registered for _, registered in self._active_work.values()
            )
        for registered in work_items:
            try:
                self._work_controller.cancel_work_v1(registered.fence)
            except Exception:  # noqa: BLE001, S112 - close remains fail closed
                continue

    async def close_v1(self) -> None:
        self.close_admission_v1()
        await self._client.close_v1()

    def __repr__(self) -> str:
        return "PrivateOcrServiceV1(<certificate-private>)"


__all__ = [
    "PrivateOcrServiceV1",
]

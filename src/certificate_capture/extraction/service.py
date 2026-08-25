"""M2/M3/M5A composition for private deterministic extraction."""

from __future__ import annotations

import inspect
import threading
import time
import uuid
from collections.abc import Callable
from enum import Enum

from certificate_capture.contracts.admission_notice import (
    MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1,
    AdmissionNoticeExtractionStorageKeyV1,
    AdmissionNoticeExtractionV1,
    StoredAdmissionNoticeExtractionV1,
)
from certificate_capture.contracts.ocr import (
    OcrPageResultV1,
    StoredOcrResultV1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
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
from chat_engine.security.session_work_controller import (
    SessionWorkControllerV1,
    WorkAdmissionDeniedV1,
)
from chat_engine.security.work_fence import (
    RegisteredWorkV1,
    WorkOperationKindV1,
    WorkValidationBoundaryV1,
)

CaptureExtractionLivePredicateV1 = Callable[[CaptureEpochV1], bool]
FatalExtractionStoreFailureV1 = Callable[[], None]
ExtractionStageHookV1 = Callable[[str], object]

_EXTRACTION_SERVICE_CONSTRUCTION_AUTHORITY_V1 = object()


class AdmissionNoticeExtractionFailureReasonV1(str, Enum):
    EXTRACTION_INPUT_INVALID = "EXTRACTION_INPUT_INVALID"
    EXTRACTION_RESULT_TOO_LARGE = "EXTRACTION_RESULT_TOO_LARGE"
    EXTRACTION_AUTHORITY_INVALID = "EXTRACTION_AUTHORITY_INVALID"
    EXTRACTION_STALE = "EXTRACTION_STALE"
    EXTRACTION_INTERNAL_ERROR = "EXTRACTION_INTERNAL_ERROR"


class AdmissionNoticeExtractionServiceErrorV1(RuntimeError):
    """Stable payload-free extraction processing failure."""

    __slots__ = ("reason", "reason_code")

    def __init__(
        self,
        reason: AdmissionNoticeExtractionFailureReasonV1,
    ) -> None:
        self.reason = reason
        self.reason_code = reason.value
        super().__init__(f"admission notice extraction failed ({reason.value})")


class PrivateAdmissionNoticeExtractionServiceV1:
    """Core-only runner returning only an encrypted-store receipt."""

    __slots__ = (
        "_active_lock",
        "_active_work",
        "_capture_is_live_v1",
        "_closed",
        "_extractor",
        "_fatal_store_failure_v1",
        "_private_authority",
        "_read_access",
        "_stage_hook_for_test_v1",
        "_store",
        "_wall_clock_v1",
        "_work_controller",
        "_write_access",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        extractor: AdmissionNoticeExtractorV1,
        private_authority: PrivateEvidenceAuthorityV1,
        store: PrivateEvidenceStoreV1,
        read_access: PrivateEvidenceAccessV1,
        write_access: PrivateEvidenceAccessV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: CaptureExtractionLivePredicateV1,
        fatal_store_failure_v1: FatalExtractionStoreFailureV1,
        wall_clock_v1: Callable[[], float],
    ) -> None:
        if (
            _construction_authority_v1
            is not _EXTRACTION_SERVICE_CONSTRUCTION_AUTHORITY_V1
        ):
            raise RuntimeError("private extraction service construction denied")
        if not isinstance(extractor, AdmissionNoticeExtractorV1):
            raise TypeError("extractor must be AdmissionNoticeExtractorV1")
        if not isinstance(private_authority, PrivateEvidenceAuthorityV1):
            raise TypeError("private_authority must be PrivateEvidenceAuthorityV1")
        if not isinstance(store, PrivateEvidenceStoreV1):
            raise TypeError("store must be PrivateEvidenceStoreV1")
        if not isinstance(work_controller, SessionWorkControllerV1):
            raise TypeError("work_controller must be SessionWorkControllerV1")
        if not callable(capture_is_live_v1):
            raise TypeError("capture_is_live_v1 must be callable")
        if not callable(fatal_store_failure_v1):
            raise TypeError("fatal_store_failure_v1 must be callable")
        if not callable(wall_clock_v1):
            raise TypeError("wall_clock_v1 must be callable")
        self._extractor = extractor
        self._private_authority = private_authority
        self._store = store
        self._read_access = read_access
        self._write_access = write_access
        self._work_controller = work_controller
        self._capture_is_live_v1 = capture_is_live_v1
        self._fatal_store_failure_v1 = fatal_store_failure_v1
        self._wall_clock_v1 = wall_clock_v1
        self._active_lock = threading.RLock()
        self._active_work: dict[
            uuid.UUID,
            tuple[CaptureEpochV1, RegisteredWorkV1],
        ] = {}
        self._closed = False
        self._stage_hook_for_test_v1: ExtractionStageHookV1 | None = None

    @classmethod
    def _create_for_coordinator_v1(
        cls,
        *,
        private_authority: PrivateEvidenceAuthorityV1,
        store: PrivateEvidenceStoreV1,
        read_access: PrivateEvidenceAccessV1,
        write_access: PrivateEvidenceAccessV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: CaptureExtractionLivePredicateV1,
        fatal_store_failure_v1: FatalExtractionStoreFailureV1,
        wall_clock_v1: Callable[[], float] = time.time,
        _extractor_for_test_v1: AdmissionNoticeExtractorV1 | None = None,
    ) -> PrivateAdmissionNoticeExtractionServiceV1:
        return cls(
            _construction_authority_v1=(_EXTRACTION_SERVICE_CONSTRUCTION_AUTHORITY_V1),
            extractor=(
                _extractor_for_test_v1
                if _extractor_for_test_v1 is not None
                else AdmissionNoticeExtractorV1()
            ),
            private_authority=private_authority,
            store=store,
            read_access=read_access,
            write_access=write_access,
            work_controller=work_controller,
            capture_is_live_v1=capture_is_live_v1,
            fatal_store_failure_v1=fatal_store_failure_v1,
            wall_clock_v1=wall_clock_v1,
        )

    @property
    def extraction_identity_v1(self):
        return self._extractor.identity_v1

    def _set_stage_hook_for_test_v1(
        self,
        hook: ExtractionStageHookV1 | None,
    ) -> None:
        with self._active_lock:
            self._stage_hook_for_test_v1 = hook

    async def _call_stage_hook_v1(self, stage: str) -> None:
        with self._active_lock:
            hook = self._stage_hook_for_test_v1
        if hook is None:
            return
        result = hook(stage)
        if inspect.isawaitable(result):
            await result

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
        if not self._private_authority.is_usable_v1():
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_AUTHORITY_INVALID
            )
        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or not isinstance(registered_work, RegisteredWorkV1)
            or registered_work.fence.session_epoch != capture_epoch.session_epoch
            or registered_work.fence.operation_kind
            is not WorkOperationKindV1.ADMISSION_NOTICE_EXTRACTION
            or not self._capture_live_v1(capture_epoch)
            or not self._work_controller.validate_work_v1(
                registered_work.fence,
                boundary,
            )
        ):
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
            )

    def _register_extraction_child_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        parent: RegisteredWorkV1,
    ) -> RegisteredWorkV1:
        if not self._private_authority.is_usable_v1():
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_AUTHORITY_INVALID
            )
        if (
            not isinstance(parent, RegisteredWorkV1)
            or parent.fence.operation_kind is not WorkOperationKindV1.OCR_INFERENCE
            or parent.fence.session_epoch != capture_epoch.session_epoch
            or not self._capture_live_v1(capture_epoch)
            or not self._work_controller.validate_work_v1(
                parent.fence,
                WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
            )
        ):
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
            )
        try:
            registered = self._work_controller.register_child_work_v1(
                parent.fence,
                WorkOperationKindV1.ADMISSION_NOTICE_EXTRACTION,
                parent.fence.deadline_monotonic,
            )
        except WorkAdmissionDeniedV1:
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
            ) from None
        with self._active_lock:
            if self._closed:
                self._work_controller.release_work_v1(registered.lease)
                raise AdmissionNoticeExtractionServiceErrorV1(
                    AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
                )
            self._active_work[registered.fence.operation_id] = (
                capture_epoch,
                registered,
            )
        return registered

    def _register_store_child_v1(
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
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
            ) from None

    def _release_extraction_v1(
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
    ) -> AdmissionNoticeExtractionServiceErrorV1:
        if exception.reason in {
            PrivateEvidenceStoreReasonV1.ACCESS_DENIED,
            PrivateEvidenceStoreReasonV1.CAPTURE_CLOSED,
        }:
            return AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_STALE
            )
        if exception.reason is PrivateEvidenceStoreReasonV1.RECORD_NOT_FOUND:
            return AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_INPUT_INVALID
            )
        if exception.reason is PrivateEvidenceStoreReasonV1.CAPACITY_EXCEEDED:
            return AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_RESULT_TOO_LARGE
            )
        if exception.reason in {
            PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE,
            PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE,
            PrivateEvidenceStoreReasonV1.RECORD_TYPE_MISMATCH,
        }:
            try:
                self._fatal_store_failure_v1()
            except Exception:  # noqa: BLE001, S110 - remains failed closed
                pass
        return AdmissionNoticeExtractionServiceErrorV1(
            AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_INTERNAL_ERROR
        )

    async def extract_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        ocr_receipts: tuple[StoredOcrResultV1, ...],
        parent_work: RegisteredWorkV1,
    ) -> StoredAdmissionNoticeExtractionV1:
        """Decrypt, deterministically extract, and re-encrypt under one parent."""

        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or not isinstance(ocr_receipts, tuple)
            or not 1 <= len(ocr_receipts) <= MAX_ADMISSION_NOTICE_SOURCE_RESULTS_V1
            or not all(
                isinstance(receipt, StoredOcrResultV1) for receipt in ocr_receipts
            )
            or len({receipt.result_id for receipt in ocr_receipts}) != len(ocr_receipts)
            or len({receipt.key.frame_id for receipt in ocr_receipts})
            != len(ocr_receipts)
        ):
            raise AdmissionNoticeExtractionServiceErrorV1(
                AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_INPUT_INVALID
            )
        extraction_work = self._register_extraction_child_v1(
            capture_epoch=capture_epoch,
            parent=parent_work,
        )
        read_work: RegisteredWorkV1 | None = None
        write_work: RegisteredWorkV1 | None = None
        page_results: list[OcrPageResultV1] = []
        extraction: AdmissionNoticeExtractionV1 | None = None
        try:
            ordered_receipts = tuple(
                sorted(
                    ocr_receipts,
                    key=lambda receipt: receipt.result_id.int,
                )
            )
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
            )
            for receipt in ordered_receipts:
                read_work = self._register_store_child_v1(
                    parent=extraction_work,
                    operation_kind=(WorkOperationKindV1.CAPTURE_EVIDENCE_READ),
                )
                try:
                    page_result = self._store.get_ocr_result_v1(
                        access=self._read_access,
                        capture_epoch=capture_epoch,
                        fence=read_work.fence,
                        receipt=receipt,
                    )
                except PrivateEvidenceStoreErrorV1 as exception:
                    raise self._map_store_error_v1(exception) from None
                finally:
                    self._work_controller.release_work_v1(read_work.lease)
                    read_work = None
                self._require_live_v1(
                    capture_epoch,
                    extraction_work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                )
                await self._call_stage_hook_v1("AFTER_OCR_DECRYPT")
                self._require_live_v1(
                    capture_epoch,
                    extraction_work,
                    WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
                )
                page_results.append(page_result)

            pages = tuple(page_results)
            key = AdmissionNoticeExtractionStorageKeyV1(
                source_ocr_result_ids=tuple(page.result_id for page in pages),
                extraction_identity_sha256=(
                    self._extractor.identity_v1.extraction_identity_sha256
                ),
            )
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
            )
            await self._call_stage_hook_v1("BEFORE_EXTRACTION")
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_FOLLOW_ON_WORK,
            )

            read_work = self._register_store_child_v1(
                parent=extraction_work,
                operation_kind=WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
            )
            try:
                existing = self._store.find_admission_notice_extraction_v1(
                    access=self._read_access,
                    capture_epoch=capture_epoch,
                    fence=read_work.fence,
                    key=key,
                    _admission_guard_v1=(lambda: self._capture_live_v1(capture_epoch)),
                )
            except PrivateEvidenceStoreErrorV1 as exception:
                raise self._map_store_error_v1(exception) from None
            finally:
                self._work_controller.release_work_v1(read_work.lease)
                read_work = None
            if existing is not None:
                self._require_live_v1(
                    capture_epoch,
                    extraction_work,
                    WorkValidationBoundaryV1.BEFORE_COMPLETION,
                )
                return existing

            try:
                extraction = self._extractor.extract_pages_v1(pages)
            except (TypeError, ValueError):
                raise AdmissionNoticeExtractionServiceErrorV1(
                    AdmissionNoticeExtractionFailureReasonV1.EXTRACTION_INPUT_INVALID
                ) from None
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.AFTER_RETURN_OR_CALLBACK,
            )
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_MEMORY_WRITE,
            )
            await self._call_stage_hook_v1("AFTER_EXTRACTION")

            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
            )
            await self._call_stage_hook_v1("BEFORE_RESULT_WRITE")
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_WRITE,
            )
            write_work = self._register_store_child_v1(
                parent=extraction_work,
                operation_kind=(WorkOperationKindV1.CAPTURE_EVIDENCE_AUXILIARY),
            )
            try:
                stored = self._store.put_admission_notice_extraction_v1(
                    access=self._write_access,
                    source_read_access=self._read_access,
                    capture_epoch=capture_epoch,
                    fence=write_work.fence,
                    page_results=pages,
                    extraction=extraction,
                    created_at_epoch_seconds=float(self._wall_clock_v1()),
                    _admission_guard_v1=(lambda: self._capture_live_v1(capture_epoch)),
                )
            except PrivateEvidenceStoreErrorV1 as exception:
                raise self._map_store_error_v1(exception) from None
            finally:
                self._work_controller.release_work_v1(write_work.lease)
                write_work = None
            await self._call_stage_hook_v1("BEFORE_COMPLETION")
            self._require_live_v1(
                capture_epoch,
                extraction_work,
                WorkValidationBoundaryV1.BEFORE_COMPLETION,
            )
            return stored
        finally:
            page_results.clear()
            if extraction is not None:
                del extraction
            if read_work is not None:
                self._work_controller.release_work_v1(read_work.lease)
            if write_work is not None:
                self._work_controller.release_work_v1(write_work.lease)
            self._release_extraction_v1(extraction_work)

    def retire_capture_v1(self, capture_epoch: CaptureEpochV1) -> None:
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
            except Exception:  # noqa: BLE001, S112 - close fails closed
                continue

    def __repr__(self) -> str:
        return "PrivateAdmissionNoticeExtractionServiceV1(certificate-private)"


__all__ = [
    "AdmissionNoticeExtractionFailureReasonV1",
    "AdmissionNoticeExtractionServiceErrorV1",
    "PrivateAdmissionNoticeExtractionServiceV1",
]

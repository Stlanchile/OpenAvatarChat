"""M2/M3/M5-bound release of one safe HBTC admission context."""

from __future__ import annotations

import hmac
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from loguru import logger

from certificate_capture.contracts.admission_notice import (
    ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1,
    EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1,
    MAX_ADMISSION_COLLEGE_CODEPOINTS_V1,
    MAX_ADMISSION_MAJOR_CODEPOINTS_V1,
    MAX_ADMISSION_NAME_CODEPOINTS_V1,
    MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1,
    AdmissionFieldStatusV1,
    AdmissionNoticeExtractionV1,
    ExtractedAdmissionFieldV1,
    StoredAdmissionNoticeExtractionV1,
    admission_notice_extraction_from_canonical_json_v1,
)
from certificate_capture.contracts.admission_notice_release import (
    ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
    SanitizedAdmissionContextV1,
    _require_released_text_v1,
)
from certificate_capture.contracts.admission_notice_template import (
    HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1,
    HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.extraction.identity import (
    DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1,
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
from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import (
    AdmissionNoticeReleaseAuthorityV1,
    SecurityEnvelopeReferenceV1,
)
from chat_engine.security.epochs import SessionEpochV1
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

AdmissionReleaseCaptureLiveV1 = Callable[[CaptureEpochV1], bool]
AdmissionReleaseFatalFailureV1 = Callable[[], None]

_RELEASE_SERVICE_CONSTRUCTION_AUTHORITY_V1 = object()
_CONTINUATION_CONSTRUCTION_AUTHORITY_V1 = object()


class AdmissionNoticeReleaseReasonV1(str, Enum):
    ADMISSION_RELEASE_PREPARED = "ADMISSION_RELEASE_PREPARED"
    ADMISSION_RELEASE_COMMITTED = "ADMISSION_RELEASE_COMMITTED"
    ADMISSION_RELEASE_NO_FIELDS = "ADMISSION_RELEASE_NO_FIELDS"
    ADMISSION_RELEASE_AUTHORITY_INVALID = "ADMISSION_RELEASE_AUTHORITY_INVALID"
    ADMISSION_RELEASE_STALE = "ADMISSION_RELEASE_STALE"
    ADMISSION_RELEASE_CLEANUP_FAILED = "ADMISSION_RELEASE_CLEANUP_FAILED"
    ADMISSION_RELEASE_POLICY_REJECTED = "ADMISSION_RELEASE_POLICY_REJECTED"
    ADMISSION_RELEASE_ALREADY_CONSUMED = "ADMISSION_RELEASE_ALREADY_CONSUMED"
    ADMISSION_RELEASE_INTERNAL_ERROR = "ADMISSION_RELEASE_INTERNAL_ERROR"


class AdmissionNoticeReleaseServiceErrorV1(RuntimeError):
    """Stable payload-free failure at the single-purpose release boundary."""

    __slots__ = ("reason", "reason_code")

    def __init__(self, reason: AdmissionNoticeReleaseReasonV1) -> None:
        self.reason = reason
        self.reason_code = reason.value
        super().__init__(f"admission notice release failed ({reason.value})")


@dataclass(frozen=True, slots=True, repr=False)
class _PrivateAdmissionNoticeReleaseCandidateV1:
    """Bounded values remain certificate-private until commit succeeds."""

    release_id: uuid.UUID
    capture_epoch: CaptureEpochV1
    values: tuple[tuple[str, str], ...]
    policy_version: str

    def __repr__(self) -> str:
        return (
            "_PrivateAdmissionNoticeReleaseCandidateV1("
            f"release_id={self.release_id}, "
            f"field_count={len(self.values)}, values=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _PendingAdmissionNoticeReleasePreparationV1:
    """Opaque encrypted receipt plus exact capture-generation parent."""

    capture_epoch: CaptureEpochV1
    receipt: StoredAdmissionNoticeExtractionV1
    registered_work: RegisteredWorkV1

    def __repr__(self) -> str:
        return "_PendingAdmissionNoticeReleasePreparationV1(<opaque>)"


class AdmissionNoticePersonalizationContinuationV1:
    """One-use core continuation carrying no private-store provenance."""

    __slots__ = (
        "_consumed",
        "_context",
        "_envelope_ref",
        "_lock",
        "_revocation_ref",
        "_successor_epoch",
        "policy_version",
        "release_id",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object = None,
        release_id: uuid.UUID,
        policy_version: str,
        successor_epoch: SessionEpochV1,
        context: SanitizedAdmissionContextV1,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> None:
        if (
            _construction_authority_v1 is not _CONTINUATION_CONSTRUCTION_AUTHORITY_V1
            or not isinstance(release_id, uuid.UUID)
            or release_id.version != 7
            or release_id.variant != uuid.RFC_4122
            or policy_version != ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1
            or not isinstance(successor_epoch, SessionEpochV1)
            or type(context) is not SanitizedAdmissionContextV1
            or not isinstance(
                envelope_ref,
                SecurityEnvelopeReferenceV1,
            )
        ):
            raise ValueError("invalid admission personalization continuation")
        self.release_id = release_id
        self.policy_version = policy_version
        self._successor_epoch = successor_epoch
        self._context: SanitizedAdmissionContextV1 | None = context
        self._envelope_ref: SecurityEnvelopeReferenceV1 | None = envelope_ref
        self._revocation_ref: SecurityEnvelopeReferenceV1 | None = envelope_ref
        self._consumed = False
        self._lock = threading.Lock()

    def _consume_for_core_v1(
        self,
        *,
        expected_successor_epoch: SessionEpochV1,
    ) -> (
        tuple[
            SanitizedAdmissionContextV1,
            SecurityEnvelopeReferenceV1,
        ]
        | None
    ):
        with self._lock:
            if (
                self._consumed
                or expected_successor_epoch is not self._successor_epoch
                or self.policy_version
                != ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1
                or self._context is None
                or self._envelope_ref is None
            ):
                return None
            context = self._context
            envelope_ref = self._envelope_ref
            self._context = None
            self._envelope_ref = None
            self._consumed = True
            return context, envelope_ref

    def _discard_for_core_v1(
        self,
    ) -> SecurityEnvelopeReferenceV1 | None:
        with self._lock:
            revocation_ref = self._revocation_ref
            self._context = None
            self._envelope_ref = None
            self._revocation_ref = None
            self._consumed = True
            return revocation_ref

    def __repr__(self) -> str:
        return (
            "AdmissionNoticePersonalizationContinuationV1("
            f"release_id={self.release_id}, context=<ephemeral>)"
        )


class AdmissionNoticeSafeReleaseServiceV1:
    """The only policy allowed to release certificate-private M6B data."""

    __slots__ = (
        "_bound_transition_id",
        "_candidate",
        "_capture_is_live_v1",
        "_closed",
        "_fatal_failure_v1",
        "_last_reason",
        "_lock",
        "_monotonic_clock_v1",
        "_pending_preparation",
        "_private_authority",
        "_processed_capture_policy",
        "_read_access",
        "_release_authority",
        "_security_authority",
        "_store",
        "_work_controller",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        security_authority: SecurityAuthorityV1,
        release_authority: AdmissionNoticeReleaseAuthorityV1,
        private_authority: PrivateEvidenceAuthorityV1,
        store: PrivateEvidenceStoreV1,
        read_access: PrivateEvidenceAccessV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: AdmissionReleaseCaptureLiveV1,
        fatal_failure_v1: AdmissionReleaseFatalFailureV1,
        monotonic_clock_v1: Callable[[], float],
    ) -> None:
        if _construction_authority_v1 is not _RELEASE_SERVICE_CONSTRUCTION_AUTHORITY_V1:
            raise RuntimeError("admission release service construction denied")
        if (
            not isinstance(security_authority, SecurityAuthorityV1)
            or not isinstance(
                release_authority,
                AdmissionNoticeReleaseAuthorityV1,
            )
            or not isinstance(
                private_authority,
                PrivateEvidenceAuthorityV1,
            )
            or not isinstance(store, PrivateEvidenceStoreV1)
            or not isinstance(work_controller, SessionWorkControllerV1)
            or not callable(capture_is_live_v1)
            or not callable(fatal_failure_v1)
            or not callable(monotonic_clock_v1)
        ):
            raise TypeError("invalid admission release service dependency")
        self._security_authority = security_authority
        self._release_authority = release_authority
        self._private_authority = private_authority
        self._store = store
        self._read_access = read_access
        self._work_controller = work_controller
        self._capture_is_live_v1 = capture_is_live_v1
        self._fatal_failure_v1 = fatal_failure_v1
        self._monotonic_clock_v1 = monotonic_clock_v1
        self._lock = threading.RLock()
        self._closed = False
        self._candidate: _PrivateAdmissionNoticeReleaseCandidateV1 | None = None
        self._pending_preparation: (
            _PendingAdmissionNoticeReleasePreparationV1 | None
        ) = None
        self._bound_transition_id: uuid.UUID | None = None
        self._processed_capture_policy: (
            tuple[
                CaptureEpochV1,
                str,
            ]
            | None
        ) = None
        self._last_reason: AdmissionNoticeReleaseReasonV1 | None = None

    @classmethod
    def _create_for_coordinator_v1(
        cls,
        *,
        security_authority: SecurityAuthorityV1,
        release_authority: AdmissionNoticeReleaseAuthorityV1,
        private_authority: PrivateEvidenceAuthorityV1,
        store: PrivateEvidenceStoreV1,
        read_access: PrivateEvidenceAccessV1,
        work_controller: SessionWorkControllerV1,
        capture_is_live_v1: AdmissionReleaseCaptureLiveV1,
        fatal_failure_v1: AdmissionReleaseFatalFailureV1,
        monotonic_clock_v1: Callable[[], float] = time.monotonic,
    ) -> AdmissionNoticeSafeReleaseServiceV1:
        return cls(
            _construction_authority_v1=(_RELEASE_SERVICE_CONSTRUCTION_AUTHORITY_V1),
            security_authority=security_authority,
            release_authority=release_authority,
            private_authority=private_authority,
            store=store,
            read_access=read_access,
            work_controller=work_controller,
            capture_is_live_v1=capture_is_live_v1,
            fatal_failure_v1=fatal_failure_v1,
            monotonic_clock_v1=monotonic_clock_v1,
        )

    @staticmethod
    def _sanitize_candidate_values_v1(
        extraction: object,
        *,
        expected_capture_epoch: CaptureEpochV1,
    ) -> tuple[tuple[str, str], ...]:
        if type(extraction) is not AdmissionNoticeExtractionV1:
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
            )
        if (
            extraction.schema_version != ADMISSION_NOTICE_EXTRACTION_SCHEMA_VERSION_V1
            or extraction.capture_epoch is not expected_capture_epoch
            or extraction.extraction_identity
            != DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1
            or extraction.extraction_identity.template_id
            != HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
        ):
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
            )
        values: list[tuple[str, str]] = []
        for field_name, field, maximum in (
            ("name", extraction.name, MAX_ADMISSION_NAME_CODEPOINTS_V1),
            (
                "source_province",
                extraction.source_province,
                MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1,
            ),
            ("college", extraction.college, MAX_ADMISSION_COLLEGE_CODEPOINTS_V1),
            ("major", extraction.major, MAX_ADMISSION_MAJOR_CODEPOINTS_V1),
        ):
            if (
                type(field) is not ExtractedAdmissionFieldV1
                or field.schema_version != EXTRACTED_ADMISSION_FIELD_SCHEMA_VERSION_V1
                or type(field.status) is not AdmissionFieldStatusV1
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
                )
            if field.status is AdmissionFieldStatusV1.FOUND:
                try:
                    value = _require_released_text_v1(
                        field_name,
                        field.value,
                        maximum,
                    )
                except ValueError:
                    raise AdmissionNoticeReleaseServiceErrorV1(
                        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
                    ) from None
                values.append((field_name, value))
            elif (
                field.status
                in {
                    AdmissionFieldStatusV1.AMBIGUOUS,
                    AdmissionFieldStatusV1.NOT_FOUND,
                }
                and field.value is None
                and field.source_span_ids == ()
                and field.source_polygon is None
            ):
                continue
            else:
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
                )
        return tuple(values)

    def _set_last_reason_v1(
        self,
        reason: AdmissionNoticeReleaseReasonV1,
    ) -> None:
        self._last_reason = reason

    def stage_extraction_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1,
        receipt: StoredAdmissionNoticeExtractionV1,
        parent_work: RegisteredWorkV1,
    ) -> None:
        """Retain only an opaque receipt and exact capture-generation work."""

        if (
            not isinstance(capture_epoch, CaptureEpochV1)
            or not isinstance(
                receipt,
                StoredAdmissionNoticeExtractionV1,
            )
            or not isinstance(parent_work, RegisteredWorkV1)
        ):
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
            )
        with self._lock:
            if self._closed:
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID
                )
            pending = self._pending_preparation
            if (
                pending is not None
                and pending.capture_epoch is capture_epoch
                and pending.receipt.record_id == receipt.record_id
                and hmac.compare_digest(
                    pending.receipt.extraction_sha256,
                    receipt.extraction_sha256,
                )
            ):
                return
            if (
                pending is not None
                or self._candidate is not None
                or (
                    self._processed_capture_policy is not None
                    and self._processed_capture_policy[0] is capture_epoch
                )
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_ALREADY_CONSUMED
                )

        if (
            parent_work.fence.session_epoch is not capture_epoch.session_epoch
            or not self._private_authority.is_usable_v1()
            or not self._security_authority.is_usable_v1()
            or not self._capture_is_live_v1(capture_epoch)
        ):
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID
            )

        try:
            staged_work = self._work_controller.register_child_work_v1(
                parent_work.fence,
                WorkOperationKindV1.ADMISSION_NOTICE_RELEASE_PREPARE,
                self._monotonic_clock_v1() + (15.0 * 60.0),
                _admission_guard_v1=(lambda: self._capture_is_live_v1(capture_epoch)),
            )
        except WorkAdmissionDeniedV1:
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
            ) from None

        installed = False
        try:
            with self._lock:
                if (
                    self._closed
                    or self._pending_preparation is not None
                    or self._candidate is not None
                    or not self._capture_is_live_v1(capture_epoch)
                ):
                    raise AdmissionNoticeReleaseServiceErrorV1(
                        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                    )
                self._pending_preparation = _PendingAdmissionNoticeReleasePreparationV1(
                    capture_epoch=capture_epoch,
                    receipt=receipt,
                    registered_work=staged_work,
                )
                installed = True
        finally:
            if not installed:
                self._work_controller.release_work_v1(staged_work.lease)

    def prepare_for_end_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1 | None,
    ) -> AdmissionNoticeReleaseReasonV1 | None:
        """Build the private four-field candidate inside End processing."""

        with self._lock:
            pending = self._pending_preparation
            if pending is None:
                return self._last_reason
        receipt = pending.receipt
        prepare_work = pending.registered_work
        extraction: AdmissionNoticeExtractionV1 | None = None
        read_work: RegisteredWorkV1 | None = None
        try:
            if capture_epoch is None or pending.capture_epoch is not capture_epoch:
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                )
            if (
                not self._private_authority.is_usable_v1()
                or not self._security_authority.is_usable_v1()
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID
                )
            if not self._capture_is_live_v1(
                capture_epoch
            ) or not self._work_controller.validate_work_v1(
                prepare_work.fence,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                )
            read_work = self._work_controller.register_child_work_v1(
                prepare_work.fence,
                WorkOperationKindV1.CAPTURE_EVIDENCE_READ,
                self._monotonic_clock_v1() + 30.0,
                _admission_guard_v1=(lambda: self._capture_is_live_v1(capture_epoch)),
            )
            if not self._work_controller.validate_work_v1(
                prepare_work.fence,
                WorkValidationBoundaryV1.BEFORE_PRIVATE_STORE_READ,
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                )
            extraction = self._store.get_admission_notice_extraction_v1(
                access=self._read_access,
                capture_epoch=capture_epoch,
                fence=read_work.fence,
                receipt=receipt,
            )
            try:
                reparsed = admission_notice_extraction_from_canonical_json_v1(
                    extraction.canonical_json_v1(),
                    expected_capture_epoch=capture_epoch,
                )
            except (TypeError, ValueError):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
                ) from None
            if reparsed != extraction or not hmac.compare_digest(
                reparsed.extraction_sha256,
                receipt.extraction_sha256,
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_POLICY_REJECTED
                )
            values = self._sanitize_candidate_values_v1(
                reparsed,
                expected_capture_epoch=capture_epoch,
            )
            if not self._work_controller.validate_work_v1(
                prepare_work.fence,
                WorkValidationBoundaryV1.BEFORE_STATE_MUTATION,
            ):
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                )
            with self._lock:
                if (
                    self._closed
                    or not self._capture_is_live_v1(capture_epoch)
                    or self._candidate is not None
                    or self._pending_preparation is not pending
                ):
                    raise AdmissionNoticeReleaseServiceErrorV1(
                        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                    )
                self._pending_preparation = None
                self._processed_capture_policy = (
                    capture_epoch,
                    ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
                )
                if not values:
                    self._set_last_reason_v1(
                        AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_NO_FIELDS
                    )
                    return self._last_reason
                candidate = _PrivateAdmissionNoticeReleaseCandidateV1(
                    release_id=new_uuid7_v1(),
                    capture_epoch=capture_epoch,
                    values=values,
                    policy_version=(ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1),
                )
                self._candidate = candidate
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_PREPARED
                )
                logger.bind(
                    release_policy_version=candidate.policy_version,
                    opaque_release_id=str(candidate.release_id),
                    released_field_count=len(values),
                    lifecycle="PREPARED_PRIVATE",
                ).info("ADMISSION_NOTICE_RELEASE_PREPARED")
                return self._last_reason
        except WorkAdmissionDeniedV1:
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
            ) from None
        except PrivateEvidenceStoreErrorV1 as exception:
            if exception.reason in {
                PrivateEvidenceStoreReasonV1.INTEGRITY_FAILURE,
                PrivateEvidenceStoreReasonV1.INVARIANT_FAILURE,
            }:
                self._fatal_failure_v1()
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID
            ) from None
        except AdmissionNoticeReleaseServiceErrorV1:
            raise
        except Exception:  # noqa: BLE001 - stable fail-closed reason mapping
            raise AdmissionNoticeReleaseServiceErrorV1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_INTERNAL_ERROR
            ) from None
        finally:
            if extraction is not None:
                del extraction
            if read_work is not None:
                self._work_controller.release_work_v1(read_work.lease)
            with self._lock:
                if self._pending_preparation is pending:
                    self._pending_preparation = None
            self._work_controller.release_work_v1(prepare_work.lease)

    def bind_end_v1(
        self,
        *,
        capture_epoch: CaptureEpochV1 | None,
        transition_id: uuid.UUID,
    ) -> None:
        with self._lock:
            candidate = self._candidate
            if candidate is None:
                return
            if (
                capture_epoch is None
                or candidate.capture_epoch is not capture_epoch
                or self._bound_transition_id is not None
            ):
                self._candidate = None
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                )
                raise AdmissionNoticeReleaseServiceErrorV1(self._last_reason)
            self._bound_transition_id = transition_id

    def commit_after_cleanup_v1(
        self,
        *,
        transition_id: uuid.UUID,
        successor_epoch: SessionEpochV1,
        cleanup_proven: bool,
        private_capture_clear: bool,
    ) -> AdmissionNoticePersonalizationContinuationV1 | None:
        """Commit declassification only after exact cleanup/successor proof."""

        with self._lock:
            candidate = self._candidate
            if candidate is None:
                return None
            if (
                self._closed
                or self._bound_transition_id != transition_id
                or successor_epoch.session_instance_id
                != candidate.capture_epoch.session_epoch.session_instance_id
                or successor_epoch.generation
                != candidate.capture_epoch.session_epoch.generation + 1
            ):
                self._candidate = None
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_STALE
                )
                raise AdmissionNoticeReleaseServiceErrorV1(self._last_reason)
            if not cleanup_proven or not private_capture_clear:
                self._candidate = None
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_CLEANUP_FAILED
                )
                raise AdmissionNoticeReleaseServiceErrorV1(self._last_reason)
            if not self._security_authority.is_usable_v1():
                self._candidate = None
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID
                )
                raise AdmissionNoticeReleaseServiceErrorV1(self._last_reason)

            values = dict(candidate.values)
            envelope_ref = (
                self._security_authority._issue_admission_notice_safe_public_root_v1(
                    self._release_authority
                )
            )
            if envelope_ref is None:
                self._candidate = None
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_AUTHORITY_INVALID
                )
                raise AdmissionNoticeReleaseServiceErrorV1(self._last_reason)
            try:
                context = SanitizedAdmissionContextV1(
                    institution_name=(HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1),
                    name=values.get("name"),
                    source_province=values.get("source_province"),
                    college=values.get("college"),
                    major=values.get("major"),
                )
                continuation = AdmissionNoticePersonalizationContinuationV1(
                    _construction_authority_v1=(
                        _CONTINUATION_CONSTRUCTION_AUTHORITY_V1
                    ),
                    release_id=candidate.release_id,
                    policy_version=candidate.policy_version,
                    successor_epoch=successor_epoch,
                    context=context,
                    envelope_ref=envelope_ref,
                )
            except Exception:  # noqa: BLE001 - revoke minted root fail closed
                (
                    self._security_authority._revoke_admission_notice_safe_public_root_v1(
                        self._release_authority,
                        envelope_ref,
                    )
                )
                self._candidate = None
                self._bound_transition_id = None
                self._set_last_reason_v1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_INTERNAL_ERROR
                )
                raise AdmissionNoticeReleaseServiceErrorV1(self._last_reason) from None
            self._candidate = None
            self._bound_transition_id = None
            self._set_last_reason_v1(
                AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_COMMITTED
            )
            logger.bind(
                release_policy_version=candidate.policy_version,
                opaque_release_id=str(candidate.release_id),
                released_field_count=(context.released_field_count_v1),
                lifecycle="COMMITTED_PUBLIC_SAFE",
            ).info("ADMISSION_NOTICE_RELEASE_COMMITTED")
            return continuation

    def discard_v1(
        self,
        reason: AdmissionNoticeReleaseReasonV1,
    ) -> None:
        pending = None
        with self._lock:
            if (
                self._pending_preparation is None
                and self._candidate is None
                and self._bound_transition_id is None
            ):
                return
            pending = self._pending_preparation
            self._pending_preparation = None
            self._candidate = None
            self._bound_transition_id = None
            self._set_last_reason_v1(reason)
        if pending is not None:
            self._work_controller.release_work_v1(pending.registered_work.lease)

    def discard_continuation_v1(
        self,
        continuation: AdmissionNoticePersonalizationContinuationV1,
    ) -> None:
        """Destroy one ephemeral attachment and retire its M2 release root."""

        if type(continuation) is not AdmissionNoticePersonalizationContinuationV1:
            return
        envelope_ref = continuation._discard_for_core_v1()
        if envelope_ref is not None:
            (
                self._security_authority._revoke_admission_notice_safe_public_root_v1(
                    self._release_authority,
                    envelope_ref,
                )
            )

    def record_failure_v1(
        self,
        reason: AdmissionNoticeReleaseReasonV1,
    ) -> None:
        pending = None
        with self._lock:
            pending = self._pending_preparation
            self._pending_preparation = None
            self._candidate = None
            self._bound_transition_id = None
            self._set_last_reason_v1(reason)
        if pending is not None:
            self._work_controller.release_work_v1(pending.registered_work.lease)

    def reset_for_capture_v1(self) -> None:
        with self._lock:
            if self._pending_preparation is not None or self._candidate is not None:
                raise AdmissionNoticeReleaseServiceErrorV1(
                    AdmissionNoticeReleaseReasonV1.ADMISSION_RELEASE_ALREADY_CONSUMED
                )
            self._bound_transition_id = None
            self._processed_capture_policy = None
            self._last_reason = None

    def last_reason_v1(
        self,
    ) -> AdmissionNoticeReleaseReasonV1 | None:
        with self._lock:
            return self._last_reason

    def close_v1(self) -> None:
        pending = None
        with self._lock:
            self._closed = True
            pending = self._pending_preparation
            self._pending_preparation = None
            self._candidate = None
            self._bound_transition_id = None
            self._processed_capture_policy = None
        if pending is not None:
            self._work_controller.release_work_v1(pending.registered_work.lease)

    def __repr__(self) -> str:
        return (
            "AdmissionNoticeSafeReleaseServiceV1("
            f"policy={ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1!r}, "
            "values=<never-logged>)"
        )


__all__ = [
    "AdmissionNoticePersonalizationContinuationV1",
    "AdmissionNoticeReleaseReasonV1",
    "AdmissionNoticeReleaseServiceErrorV1",
    "AdmissionNoticeSafeReleaseServiceV1",
]

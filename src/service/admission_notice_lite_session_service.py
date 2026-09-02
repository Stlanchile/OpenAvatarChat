"""L6V exact-ChatSession activation layered above the qualified L1-L4 service."""

from __future__ import annotations

from chat_engine.core.chat_session import ChatSession
from service.admission_notice_lite_chat_context import AdmissionContextV1
from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    RecognitionErrorReasonLiteV1,
    RecognitionStateLiteV1,
)
from service.admission_notice_lite_service import (
    AdmissionNoticeLiteService,
    _RecognitionIngestionPermitLiteV1,
    _RecognitionJobRuntimeLiteV1,
)


class AdmissionNoticeSessionServiceLiteV1(AdmissionNoticeLiteService):
    """Bind sanitized recognition results to one exact live ChatSession."""

    async def begin_ingestion(
        self,
        owning_session_id: str,
    ) -> _RecognitionIngestionPermitLiteV1:
        owning_session = self._session_lookup(owning_session_id)
        if not isinstance(owning_session, ChatSession):
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            )
        if owning_session.active_admission_context is not None:
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_ALREADY_ACTIVE
            )

        permit = await super().begin_ingestion(owning_session_id)
        if owning_session.try_reserve_admission_context_activation(permit):
            return permit

        super().release_ingestion(permit)
        reason = (
            RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            if self._session_lookup(owning_session_id) is not owning_session
            else RecognitionErrorReasonLiteV1.RECOGNITION_ALREADY_ACTIVE
        )
        raise AdmissionNoticeLiteError(reason)

    def _release_resource_permit(
        self,
        permit: _RecognitionIngestionPermitLiteV1,
    ) -> None:
        owning_session = permit.owning_session
        if isinstance(owning_session, ChatSession):
            owning_session.cancel_admission_context_activation(permit)
        super()._release_resource_permit(permit)

    async def _finish_completed(
        self,
        job: _RecognitionJobRuntimeLiteV1,
        admission_context: AdmissionContextV1,
    ) -> None:
        if type(admission_context) is not AdmissionContextV1:
            raise TypeError("expected exact AdmissionContextV1")
        async with self._lock:
            now = self._clock()
            permit = job.resource_permit
            owning_session = job.owning_session
            can_complete = (
                isinstance(owning_session, ChatSession)
                and permit is not None
                and self._jobs.get(job.recognition_id) is job
                and job.state is RecognitionStateLiteV1.PROCESSING
                and now < job.expires_at_monotonic
                and self._owner_is_current_locked(job)
            )
            transitioned = False
            if not can_complete:
                if job.state is RecognitionStateLiteV1.PROCESSING:
                    transitioned = self._transition_processor_result_locked(
                        job,
                        state=RecognitionStateLiteV1.CANCELLED,
                        reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                        now=now,
                    )
            else:
                def complete_activation() -> bool:
                    nonlocal transitioned
                    transitioned = self._transition_processor_result_locked(
                        job,
                        state=RecognitionStateLiteV1.COMPLETED,
                        reason=None,
                        now=now,
                    )
                    return (
                        transitioned
                        and job.state is RecognitionStateLiteV1.COMPLETED
                    )

                committed = owning_session.commit_admission_context_activation(
                    permit,
                    admission_context,
                    complete_activation,
                )
                if not committed and job.state is RecognitionStateLiteV1.PROCESSING:
                    transitioned = self._transition_processor_result_locked(
                        job,
                        state=RecognitionStateLiteV1.CANCELLED,
                        reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                        now=now,
                    )
        if transitioned:
            from loguru import logger

            logger.info(
                "Admission Notice Lite job terminal recognition_id={} "
                "state={} active_count={}",
                job.recognition_id,
                job.state.value,
                self.active_job_count,
            )


__all__ = ["AdmissionNoticeSessionServiceLiteV1"]

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from loguru import logger

from service.admission_notice_lite_chat_context import AdmissionContextV1
from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    RecognitionErrorReasonLiteV1,
    RecognitionJobContextLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.admission_notice_lite_ocr import AdmissionNoticeOcrProcessorLiteV1
from service.admission_notice_lite_semantics import (
    recognize_admission_notice_semantics,
)


@dataclass(frozen=True, slots=True)
class AdmissionNoticeSemanticProcessorLiteV1:
    """Compose qualified OCR and pure semantics into one sanitized result."""

    ocr_processor: AdmissionNoticeOcrProcessorLiteV1

    async def prepare_for_ingestion(self) -> bool:
        return await self.ocr_processor.prepare_for_ingestion()

    async def process(
        self,
        context: RecognitionJobContextLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> AdmissionContextV1:
        batch = await self.ocr_processor.recognize_batch(context, frames)
        semantic_started = time.monotonic()
        semantic_failure_reason = None
        try:
            result = recognize_admission_notice_semantics(batch)
        except AdmissionNoticeLiteError as error:
            semantic_failure_reason = error.reason
            logger.info(
                "Admission Notice Lite semantics failed recognition_id={} reason={}",
                context.recognition_id,
                error.reason.value,
            )
        except Exception:  # noqa: BLE001 - sanitize the semantic task boundary
            semantic_failure_reason = RecognitionErrorReasonLiteV1.INTERNAL_ERROR
            logger.warning(
                "Admission Notice Lite semantics failed "
                "recognition_id={} reason=INTERNAL_ERROR",
                context.recognition_id,
            )
        finally:
            del batch
        if semantic_failure_reason is not None:
            frames = ()
            raise AdmissionNoticeLiteError(semantic_failure_reason)
        if (
            context.cancel_event.is_set()
            or not context.session_is_current()
            or time.monotonic() >= (context.expires_at_monotonic)
        ):
            del result
            raise asyncio.CancelledError
        admission_context = AdmissionContextV1.from_result(result)
        del result
        logger.info(
            "Admission Notice Lite semantics completed recognition_id={} "
            "duration_ms={:.1f}",
            context.recognition_id,
            (time.monotonic() - semantic_started) * 1000.0,
        )
        return admission_context


def compose_admission_notice_semantic_processor_lite_v1(
    ocr_processor: AdmissionNoticeOcrProcessorLiteV1 | None,
) -> AdmissionNoticeSemanticProcessorLiteV1 | None:
    if ocr_processor is None:
        return None
    return AdmissionNoticeSemanticProcessorLiteV1(ocr_processor)


__all__ = [
    "AdmissionNoticeSemanticProcessorLiteV1",
    "compose_admission_notice_semantic_processor_lite_v1",
]

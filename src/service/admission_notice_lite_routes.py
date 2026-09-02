from __future__ import annotations

import asyncio
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from loguru import logger

from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    RecognitionErrorReasonLiteV1,
    RecognitionJobLiteV1,
    RecognitionProcessorLiteV1,
    RecognitionStateLiteV1,
)
from service.admission_notice_lite_ingestion import (
    ingest_admission_frames,
    parse_admission_multipart_request_spec,
)
from service.admission_notice_lite_service import AdmissionNoticeLiteService
from service.admission_notice_lite_session_service import (
    AdmissionNoticeSessionServiceLiteV1,
)
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

_ROUTE_BASE = "/api/v1/sessions/{session_id}/admission-notice/recognitions"
_CONTENT_LENGTH_HEADER_DIGIT_LIMIT = 16
_CONTENT_LENGTH_PATTERN = re.compile(r"[0-9]+")
_ERROR_STATUS = {
    RecognitionErrorReasonLiteV1.INVALID_REQUEST: 400,
    RecognitionErrorReasonLiteV1.INVALID_IMAGE: 422,
    RecognitionErrorReasonLiteV1.IMAGE_TOO_LARGE: 413,
    RecognitionErrorReasonLiteV1.IMAGE_DIMENSIONS_UNSUPPORTED: 422,
    RecognitionErrorReasonLiteV1.TOO_MANY_FRAMES: 400,
    RecognitionErrorReasonLiteV1.UNSUPPORTED_MEDIA_TYPE: 415,
    RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND: 404,
    RecognitionErrorReasonLiteV1.RECOGNITION_ALREADY_ACTIVE: 409,
    RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE: 503,
    RecognitionErrorReasonLiteV1.SERVICE_BUSY: 503,
    RecognitionErrorReasonLiteV1.INTERNAL_ERROR: 500,
}


def _error_response(error: AdmissionNoticeLiteError) -> JSONResponse:
    return JSONResponse(
        status_code=_ERROR_STATUS.get(error.reason, 500),
        content={"reason": error.reason.value},
    )


def _internal_error_response() -> JSONResponse:
    logger.error("Admission Notice Lite route failed reason=INTERNAL_ERROR")
    return _error_response(
        AdmissionNoticeLiteError(RecognitionErrorReasonLiteV1.INTERNAL_ERROR)
    )


def _status_content(job: RecognitionJobLiteV1) -> dict[str, object]:
    content: dict[str, object] = {
        "recognition_id": job.recognition_id,
        "status": job.state.value.lower(),
    }
    if job.reason is not None:
        content["reason"] = job.reason.value
    if job.state is RecognitionStateLiteV1.COMPLETED:
        content["admission_context_active"] = True
    return content


def _has_unsupported_control_input(request: Request) -> bool:
    if request.query_params:
        return True
    if request.headers.getlist("transfer-encoding"):
        return True
    content_lengths = request.headers.getlist("content-length")
    if not content_lengths:
        return False
    if len(content_lengths) != 1:
        return True
    content_length = content_lengths[0]
    return (
        len(content_length) > _CONTENT_LENGTH_HEADER_DIGIT_LIMIT
        or _CONTENT_LENGTH_PATTERN.fullmatch(content_length) is None
        or int(content_length) != 0
    )


def register_admission_notice_lite_routes(
    *,
    app: FastAPI,
    chat_engine: Any,
    config: AdmissionNoticeLiteFeatureConfigV1,
    processor: RecognitionProcessorLiteV1 | None = None,
) -> AdmissionNoticeLiteService | None:
    """Register the L3 OCR-backed Lite routes when explicitly enabled."""

    if not config.enabled:
        return None

    service = AdmissionNoticeSessionServiceLiteV1(
        config=config,
        session_lookup=chat_engine.sessions.get,
        processor=processor,
    )
    chat_engine.add_session_stop_observer(service.notify_session_stopped)

    @app.post(_ROUTE_BASE, status_code=202)
    async def create_recognition(request: Request, session_id: str) -> Response:
        permit = None
        frames = ()
        try:
            if request.query_params:
                raise AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.INVALID_REQUEST
                )
            request_spec = parse_admission_multipart_request_spec(request)
            permit = await service.begin_ingestion(session_id)
            frames = await ingest_admission_frames(request, request_spec)
            job = await service.create_recognition(permit, frames)
            frames = ()
        except asyncio.CancelledError:
            cancel_reason = (
                service.ingestion_cancel_reason(permit) if permit is not None else None
            )
            task = asyncio.current_task()
            if cancel_reason is not None and task is not None and task.uncancel() == 0:
                return _error_response(AdmissionNoticeLiteError(cancel_reason))
            raise
        except AdmissionNoticeLiteError as error:
            return _error_response(error)
        except Exception:  # noqa: BLE001 - sanitize the public route boundary
            return _internal_error_response()
        finally:
            frames = ()
            if permit is not None:
                service.release_ingestion(permit)
        return JSONResponse(status_code=202, content=_status_content(job))

    @app.get(f"{_ROUTE_BASE}/{{recognition_id}}")
    async def get_recognition(
        request: Request, session_id: str, recognition_id: str
    ) -> Response:
        if _has_unsupported_control_input(request):
            return _error_response(
                AdmissionNoticeLiteError(RecognitionErrorReasonLiteV1.INVALID_REQUEST)
            )
        try:
            job = await service.get_recognition(session_id, recognition_id)
        except AdmissionNoticeLiteError as error:
            return _error_response(error)
        except Exception:  # noqa: BLE001 - sanitize the public route boundary
            return _internal_error_response()
        return JSONResponse(status_code=200, content=_status_content(job))

    @app.delete(f"{_ROUTE_BASE}/{{recognition_id}}")
    async def cancel_recognition(
        request: Request, session_id: str, recognition_id: str
    ) -> Response:
        if _has_unsupported_control_input(request):
            return _error_response(
                AdmissionNoticeLiteError(RecognitionErrorReasonLiteV1.INVALID_REQUEST)
            )
        try:
            await service.cancel_recognition(session_id, recognition_id)
        except AdmissionNoticeLiteError as error:
            return _error_response(error)
        except Exception:  # noqa: BLE001 - sanitize the public route boundary
            return _internal_error_response()
        return Response(status_code=204)

    return service

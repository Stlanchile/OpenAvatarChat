"""Existing-ChatAgent bridge for one Admission Notice Lite L5 turn."""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from chat_engine.core.chat_session import ChatSession
from chat_engine.data_models.chat_data_type import ChatDataType
from handlers.agent.chat_agent_handler import ChatAgentContext, ChatAgentHandler
from service.admission_notice_lite_chat_context import (
    AdmissionNoticeContextLiteV1,
)
from service.admission_notice_lite_contracts import (
    RecognitionJobContextLiteV1,
)
from service.admission_notice_lite_semantics import AdmissionNoticeResultLiteV1


class AdmissionNoticePersonalizerProtocolLiteV1(Protocol):
    async def personalize(
        self,
        job_context: RecognitionJobContextLiteV1,
        result: AdmissionNoticeResultLiteV1,
    ) -> bool:
        """Publish one normal ChatAgent response or fail without retaining input."""


@dataclass(frozen=True, slots=True)
class AdmissionNoticeChatPersonalizerLiteV1:
    """Locate the exact owner's existing ChatAgent and invoke it once."""

    async def personalize(
        self,
        job_context: RecognitionJobContextLiteV1,
        result: AdmissionNoticeResultLiteV1,
    ) -> bool:
        if type(job_context) is not RecognitionJobContextLiteV1:
            raise TypeError("expected exact RecognitionJobContextLiteV1")
        admission_context = AdmissionNoticeContextLiteV1.from_result(result)
        cancel_check = lambda: (
            job_context.cancel_event.is_set()
            or time.monotonic() >= job_context.expires_at_monotonic
            or not job_context.session_is_current()
        )
        if cancel_check():
            raise asyncio.CancelledError

        owning_session = job_context.owning_session
        if not isinstance(owning_session, ChatSession):
            return False

        matches = [
            record.env
            for record in owning_session.handlers.values()
            if isinstance(record.env.handler, ChatAgentHandler)
            and isinstance(record.env.context, ChatAgentContext)
        ]
        if len(matches) != 1:
            return False
        handler_env = matches[0]
        output_definitions = (
            handler_env.handler_output_info or handler_env.output_info or {}
        )
        if ChatDataType.AVATAR_TEXT not in output_definitions:
            return False
        if cancel_check():
            raise asyncio.CancelledError

        loop = asyncio.get_running_loop()
        worker_result = loop.create_future()

        def complete_worker(
            succeeded: bool | None,
            error: BaseException | None,
        ) -> None:
            if worker_result.done():
                return
            if error is not None:
                worker_result.set_exception(error)
            else:
                worker_result.set_result(succeeded)

        def run_worker() -> None:
            try:
                succeeded = handler_env.handler.personalize_admission_notice_lite_v1(
                    handler_env.context,
                    admission_context,
                    output_definitions,
                    cancel_check=cancel_check,
                    publication_lock=job_context.publication_lock,
                    request_deadline_monotonic=job_context.expires_at_monotonic,
                )
            except BaseException as error:  # noqa: BLE001 - transfer to owner loop
                loop.call_soon_threadsafe(complete_worker, None, error)
            else:
                loop.call_soon_threadsafe(complete_worker, succeeded, None)

        worker_thread = threading.Thread(
            target=run_worker,
            name="admission-lite-chatagent",
            daemon=False,
        )
        worker_thread.start()
        try:
            succeeded = await asyncio.shield(worker_result)
        except asyncio.CancelledError:
            job_context.cancel_event.set()
            while not worker_result.done():
                try:
                    await asyncio.shield(worker_result)
                except asyncio.CancelledError:
                    continue
                except Exception:  # noqa: BLE001 - drain before sanitized cancellation
                    break
            if worker_result.done() and not worker_result.cancelled():
                with suppress(BaseException):
                    worker_result.result()
            raise
        except BaseException:  # noqa: BLE001 - return only a sanitized failure bit
            return False
        finally:
            worker_thread.join()
        if cancel_check():
            raise asyncio.CancelledError
        return succeeded


__all__ = [
    "AdmissionNoticeChatPersonalizerLiteV1",
    "AdmissionNoticePersonalizerProtocolLiteV1",
]

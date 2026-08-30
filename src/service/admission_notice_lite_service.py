from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from service.admission_notice_lite_contracts import (
    AdmissionNoticeLiteError,
    RecognitionErrorReasonLiteV1,
    RecognitionJobContextLiteV1,
    RecognitionJobLiteV1,
    RecognitionProcessorLiteV1,
    RecognitionStateLiteV1,
    ValidatedAdmissionFrameLiteV1,
)
from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)

_ACTIVE_STATES = frozenset(
    (RecognitionStateLiteV1.CREATED, RecognitionStateLiteV1.PROCESSING)
)
_TERMINAL_RETENTION_SECONDS = 30.0
_MAX_RETAINED_TERMINAL_JOBS = 64
_SHUTDOWN_WAIT_SECONDS = 1.0


@dataclass(slots=True)
class _RecognitionIngestionPermitLiteV1:
    owning_session_id: str
    owning_session: object = field(repr=False)
    owner_key: int
    ingestion_task: asyncio.Task[Any] | None = field(repr=False)
    cancel_reason: RecognitionErrorReasonLiteV1 | None = None
    transferred: bool = False
    released: bool = False


@dataclass(slots=True)
class _RecognitionJobRuntimeLiteV1:
    recognition_id: str
    owning_session_id: str
    owning_session: object = field(repr=False)
    owner_key: int
    state: RecognitionStateLiteV1
    created_at_monotonic: float
    expires_at_monotonic: float
    cancel_event: asyncio.Event = field(repr=False)
    frames: tuple[ValidatedAdmissionFrameLiteV1, ...] = field(repr=False)
    resource_permit: _RecognitionIngestionPermitLiteV1 | None = field(repr=False)
    reason: RecognitionErrorReasonLiteV1 | None = None
    terminal_at_monotonic: float | None = None
    retain_until_monotonic: float | None = None
    active_slot_released: bool = False
    supervisor_task: asyncio.Task[None] | None = field(default=None, repr=False)
    processor_task: asyncio.Task[None] | None = field(default=None, repr=False)
    retention_handle: asyncio.TimerHandle | None = field(default=None, repr=False)

    def snapshot(self) -> RecognitionJobLiteV1:
        return RecognitionJobLiteV1(
            recognition_id=self.recognition_id,
            owning_session_id=self.owning_session_id,
            state=self.state,
            created_at_monotonic=self.created_at_monotonic,
            expires_at_monotonic=self.expires_at_monotonic,
            reason=self.reason,
        )


class AdmissionNoticeLiteService:
    """Process-local owner for Admission Notice Lite recognition jobs."""

    def __init__(
        self,
        *,
        config: AdmissionNoticeLiteFeatureConfigV1,
        session_lookup: Callable[[str], object | None],
        processor: RecognitionProcessorLiteV1 | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not config.enabled:
            raise ValueError("Admission Notice Lite service requires enabled config")

        self._config = config
        self._session_lookup = session_lookup
        self._processor = processor
        self._clock = clock
        self._lock = asyncio.Lock()
        self._jobs: dict[str, _RecognitionJobRuntimeLiteV1] = {}
        self._active_by_owner: dict[int, str] = {}
        self._resource_permits_by_owner: dict[
            int, _RecognitionIngestionPermitLiteV1
        ] = {}
        self._invalidated_owner_keys: set[int] = set()
        self._owned_tasks: set[asyncio.Task[Any]] = set()
        self._accepting = True
        self._event_loop: asyncio.AbstractEventLoop | None = None

    @property
    def accepting(self) -> bool:
        return self._accepting

    @property
    def active_job_count(self) -> int:
        return len(self._active_by_owner)

    @property
    def retained_job_count(self) -> int:
        return len(self._jobs)

    @property
    def active_ingestion_count(self) -> int:
        return sum(
            not permit.transferred
            for permit in self._resource_permits_by_owner.values()
        )

    @property
    def resource_slot_count(self) -> int:
        return len(self._resource_permits_by_owner)

    @property
    def retained_frame_count(self) -> int:
        return sum(len(job.frames) for job in self._jobs.values())

    @property
    def owned_task_count(self) -> int:
        return len(self._owned_tasks)

    def _bind_event_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._event_loop is None:
            self._event_loop = loop
        elif self._event_loop is not loop:
            raise RuntimeError("Admission Notice Lite service cannot span event loops")
        return loop

    def _track_task(self, task: asyncio.Task[Any]) -> None:
        self._owned_tasks.add(task)
        task.add_done_callback(self._on_task_done)

    def _track_job_task(
        self,
        task: asyncio.Task[Any],
        job: _RecognitionJobRuntimeLiteV1,
    ) -> None:
        self._track_task(task)
        task.add_done_callback(
            lambda finished_task: self._on_job_task_done(job, finished_task)
        )

    def _on_task_done(self, task: asyncio.Task[Any]) -> None:
        self._owned_tasks.discard(task)
        if task.cancelled():
            return
        try:
            task.exception()
        except asyncio.CancelledError:
            return

    def _on_job_task_done(
        self,
        job: _RecognitionJobRuntimeLiteV1,
        task: asyncio.Task[Any],
    ) -> None:
        del task
        self._maybe_release_job_resources(job)

    def _release_resource_permit(
        self, permit: _RecognitionIngestionPermitLiteV1
    ) -> None:
        if permit.released:
            return
        if self._resource_permits_by_owner.get(permit.owner_key) is not permit:
            raise RuntimeError("Admission Notice Lite resource permit mismatch")
        self._resource_permits_by_owner.pop(permit.owner_key, None)
        self._invalidated_owner_keys.discard(permit.owner_key)
        permit.ingestion_task = None
        permit.released = True

    def _maybe_release_job_resources(
        self,
        job: _RecognitionJobRuntimeLiteV1,
        *,
        supervisor_unwinding: bool = False,
    ) -> None:
        supervisor = job.supervisor_task
        processor = job.processor_task
        if (
            not supervisor_unwinding
            and supervisor is not None
            and not supervisor.done()
        ):
            return
        if processor is not None and not processor.done():
            return
        job.frames = ()
        permit = job.resource_permit
        job.resource_permit = None
        if permit is not None:
            self._release_resource_permit(permit)

    def _discard_job_locked(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        if self._jobs.get(job.recognition_id) is not job:
            return
        self._jobs.pop(job.recognition_id, None)
        if job.retention_handle is not None:
            job.retention_handle.cancel()
            job.retention_handle = None

    def _schedule_terminal_retention_locked(
        self, job: _RecognitionJobRuntimeLiteV1
    ) -> None:
        loop = self._event_loop
        retain_until = job.retain_until_monotonic
        if loop is None or retain_until is None:
            return
        if job.retention_handle is not None:
            job.retention_handle.cancel()
        delay = max(0.0, retain_until - self._clock())
        job.retention_handle = loop.call_later(
            delay, self._terminal_retention_timer_fired, job
        )

    def _terminal_retention_timer_fired(
        self, job: _RecognitionJobRuntimeLiteV1
    ) -> None:
        job.retention_handle = None
        loop = self._event_loop
        if loop is None or loop.is_closed():
            return
        task = loop.create_task(
            self._purge_retained_job(job),
            name="admission-lite-terminal-retention",
        )
        self._track_task(task)

    async def _purge_retained_job(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        async with self._lock:
            if self._jobs.get(job.recognition_id) is not job:
                return
            retain_until = job.retain_until_monotonic
            if job.state in _ACTIVE_STATES or retain_until is None:
                return
            if self._clock() < retain_until:
                self._schedule_terminal_retention_locked(job)
                return
            self._discard_job_locked(job)

    def _new_recognition_id_locked(self) -> str:
        for _ in range(4):
            recognition_id = f"arn1_{secrets.token_urlsafe(18)}"
            if recognition_id not in self._jobs:
                return recognition_id
        raise RuntimeError("Recognition identifier collision")

    def _release_active_slot_locked(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        if job.active_slot_released:
            return
        if self._active_by_owner.get(job.owner_key) == job.recognition_id:
            self._active_by_owner.pop(job.owner_key, None)
        job.active_slot_released = True

    def _owner_is_current_locked(self, job: _RecognitionJobRuntimeLiteV1) -> bool:
        return (
            job.owner_key not in self._invalidated_owner_keys
            and self._session_lookup(job.owning_session_id) is job.owning_session
        )

    def _transition_terminal_locked(
        self,
        job: _RecognitionJobRuntimeLiteV1,
        *,
        state: RecognitionStateLiteV1,
        reason: RecognitionErrorReasonLiteV1 | None,
        now: float,
    ) -> bool:
        if self._jobs.get(job.recognition_id) is not job:
            return False
        if job.state not in _ACTIVE_STATES:
            return False

        job.state = state
        job.reason = reason
        job.terminal_at_monotonic = now
        job.retain_until_monotonic = now + min(
            _TERMINAL_RETENTION_SECONDS,
            float(self._config.recognition_ttl_seconds),
        )
        job.frames = ()
        self._release_active_slot_locked(job)
        self._schedule_terminal_retention_locked(job)
        self._trim_terminal_jobs_locked()
        return True

    def _trim_terminal_jobs_locked(self) -> None:
        terminal_jobs = [
            job for job in self._jobs.values() if job.state not in _ACTIVE_STATES
        ]
        overflow = len(terminal_jobs) - _MAX_RETAINED_TERMINAL_JOBS
        if overflow <= 0:
            return

        terminal_jobs.sort(
            key=lambda job: (
                job.terminal_at_monotonic
                if job.terminal_at_monotonic is not None
                else float("inf")
            )
        )
        for job in terminal_jobs[:overflow]:
            self._discard_job_locked(job)

    def _purge_terminal_jobs_locked(self, now: float) -> None:
        for job in tuple(self._jobs.values()):
            retain_until = job.retain_until_monotonic
            if (
                job.state not in _ACTIVE_STATES
                and retain_until is not None
                and now >= retain_until
            ):
                self._discard_job_locked(job)

    def _transition_processor_result_locked(
        self,
        job: _RecognitionJobRuntimeLiteV1,
        *,
        state: RecognitionStateLiteV1,
        reason: RecognitionErrorReasonLiteV1 | None,
        now: float,
    ) -> bool:
        if not self._owner_is_current_locked(job):
            state = RecognitionStateLiteV1.CANCELLED
            reason = RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED
        elif now >= job.expires_at_monotonic:
            state = RecognitionStateLiteV1.EXPIRED
            reason = RecognitionErrorReasonLiteV1.RECOGNITION_EXPIRED
        return self._transition_terminal_locked(
            job,
            state=state,
            reason=reason,
            now=now,
        )

    def _expire_due_jobs_locked(self, now: float) -> list[asyncio.Task[Any]]:
        tasks_to_cancel: list[asyncio.Task[Any]] = []
        for job in tuple(self._jobs.values()):
            if job.state not in _ACTIVE_STATES:
                continue
            if now < job.expires_at_monotonic:
                continue
            if self._transition_processor_result_locked(
                job,
                state=RecognitionStateLiteV1.EXPIRED,
                reason=RecognitionErrorReasonLiteV1.RECOGNITION_EXPIRED,
                now=now,
            ):
                job.cancel_event.set()
                for task in (job.supervisor_task, job.processor_task):
                    if task is not None and not task.done():
                        tasks_to_cancel.append(task)
        return tasks_to_cancel

    @staticmethod
    def _cancel_tasks(tasks: list[asyncio.Task[Any]]) -> None:
        current = asyncio.current_task()
        for task in tasks:
            if task is not current and not task.done():
                task.cancel()

    async def _processor_ready_for_ingestion(self) -> bool:
        processor = self._processor
        if processor is None:
            return False
        readiness = getattr(processor, "prepare_for_ingestion", None)
        if readiness is None:
            return True
        try:
            return await readiness() is True
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - sanitize the readiness boundary
            logger.warning(
                "Admission Notice Lite processor unavailable reason=SERVICE_UNAVAILABLE"
            )
            return False

    async def begin_ingestion(
        self, owning_session_id: str
    ) -> _RecognitionIngestionPermitLiteV1:
        self._bind_event_loop()
        owning_session = self._session_lookup(owning_session_id)
        if owning_session is None:
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            )

        processor_ready = await self._processor_ready_for_ingestion()
        now = self._clock()
        tasks_to_cancel: list[asyncio.Task[Any]]
        async with self._lock:
            tasks_to_cancel = self._expire_due_jobs_locked(now)
            self._purge_terminal_jobs_locked(now)
            if not self._accepting or self._processor is None or not processor_ready:
                error = AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE
                )
            elif self._session_lookup(owning_session_id) is not owning_session:
                error = AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
                )
            else:
                owner_key = id(owning_session)
                if owner_key in self._resource_permits_by_owner:
                    error = AdmissionNoticeLiteError(
                        RecognitionErrorReasonLiteV1.RECOGNITION_ALREADY_ACTIVE
                    )
                elif (
                    len(self._resource_permits_by_owner)
                    >= self._config.max_global_recognition_jobs
                ):
                    error = AdmissionNoticeLiteError(
                        RecognitionErrorReasonLiteV1.SERVICE_BUSY
                    )
                else:
                    permit = _RecognitionIngestionPermitLiteV1(
                        owning_session_id=owning_session_id,
                        owning_session=owning_session,
                        owner_key=owner_key,
                        ingestion_task=asyncio.current_task(),
                    )
                    self._resource_permits_by_owner[owner_key] = permit
                    error = None

        self._cancel_tasks(tasks_to_cancel)
        if error is not None:
            raise error
        return permit

    def release_ingestion(self, permit: _RecognitionIngestionPermitLiteV1) -> None:
        if not permit.transferred:
            self._release_resource_permit(permit)

    @staticmethod
    def ingestion_cancel_reason(
        permit: _RecognitionIngestionPermitLiteV1,
    ) -> RecognitionErrorReasonLiteV1 | None:
        return permit.cancel_reason

    async def create_recognition(
        self,
        permit: _RecognitionIngestionPermitLiteV1,
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...],
    ) -> RecognitionJobLiteV1:
        if (
            type(frames) is not tuple
            or not 1 <= len(frames) <= 3
            or any(
                not isinstance(frame, ValidatedAdmissionFrameLiteV1) for frame in frames
            )
            or tuple(frame.frame_index for frame in frames)
            != tuple(range(1, len(frames) + 1))
        ):
            raise ValueError("frames must be a contiguous validated tuple")

        loop = self._bind_event_loop()
        now = self._clock()
        tasks_to_cancel: list[asyncio.Task[Any]]
        async with self._lock:
            tasks_to_cancel = self._expire_due_jobs_locked(now)
            self._purge_terminal_jobs_locked(now)

            if (
                permit.released
                or permit.transferred
                or self._resource_permits_by_owner.get(permit.owner_key) is not permit
                or not self._accepting
                or self._processor is None
            ):
                error = AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE
                )
            elif (
                permit.owner_key in self._invalidated_owner_keys
                or self._session_lookup(permit.owning_session_id)
                is not permit.owning_session
            ):
                error = AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
                )
            elif permit.owner_key in self._active_by_owner:
                error = AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.RECOGNITION_ALREADY_ACTIVE
                )
            elif len(self._active_by_owner) >= self._config.max_global_recognition_jobs:
                error = AdmissionNoticeLiteError(
                    RecognitionErrorReasonLiteV1.SERVICE_BUSY
                )
            else:
                owning_session_id = permit.owning_session_id
                owning_session = permit.owning_session
                owner_key = permit.owner_key
                recognition_id = self._new_recognition_id_locked()
                job = _RecognitionJobRuntimeLiteV1(
                    recognition_id=recognition_id,
                    owning_session_id=owning_session_id,
                    owning_session=owning_session,
                    owner_key=owner_key,
                    state=RecognitionStateLiteV1.CREATED,
                    created_at_monotonic=now,
                    expires_at_monotonic=(now + self._config.recognition_ttl_seconds),
                    cancel_event=asyncio.Event(),
                    frames=frames,
                    resource_permit=permit,
                )
                self._jobs[recognition_id] = job
                self._active_by_owner[owner_key] = recognition_id
                job_coroutine = self._run_job(job)
                try:
                    supervisor = loop.create_task(
                        job_coroutine,
                        name=f"admission-lite-job-{recognition_id}",
                    )
                except RuntimeError:
                    job_coroutine.close()
                    self._jobs.pop(recognition_id, None)
                    self._active_by_owner.pop(owner_key, None)
                    error = AdmissionNoticeLiteError(
                        RecognitionErrorReasonLiteV1.INTERNAL_ERROR
                    )
                else:
                    permit.transferred = True
                    permit.ingestion_task = None
                    job.supervisor_task = supervisor
                    self._track_job_task(supervisor, job)
                    snapshot = job.snapshot()
                    error = None

        self._cancel_tasks(tasks_to_cancel)
        if error is not None:
            raise error
        return snapshot

    async def _run_job(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        processor_task: asyncio.Task[None] | None = None
        cancel_waiter: asyncio.Task[bool] | None = None
        frames: tuple[ValidatedAdmissionFrameLiteV1, ...] = ()
        try:
            async with self._lock:
                now = self._clock()
                if job.state is not RecognitionStateLiteV1.CREATED:
                    return
                if not self._accepting:
                    self._transition_terminal_locked(
                        job,
                        state=RecognitionStateLiteV1.CANCELLED,
                        reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                        now=now,
                    )
                    job.cancel_event.set()
                    return
                if not self._owner_is_current_locked(job):
                    self._transition_terminal_locked(
                        job,
                        state=RecognitionStateLiteV1.CANCELLED,
                        reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                        now=now,
                    )
                    job.cancel_event.set()
                    return
                if now >= job.expires_at_monotonic:
                    self._transition_terminal_locked(
                        job,
                        state=RecognitionStateLiteV1.EXPIRED,
                        reason=RecognitionErrorReasonLiteV1.RECOGNITION_EXPIRED,
                        now=now,
                    )
                    job.cancel_event.set()
                    return
                job.state = RecognitionStateLiteV1.PROCESSING
                frames = job.frames
                if not frames:
                    self._transition_terminal_locked(
                        job,
                        state=RecognitionStateLiteV1.FAILED,
                        reason=RecognitionErrorReasonLiteV1.INTERNAL_ERROR,
                        now=now,
                    )
                    return

            context = RecognitionJobContextLiteV1(
                recognition_id=job.recognition_id,
                expires_at_monotonic=job.expires_at_monotonic,
                cancel_event=job.cancel_event,
            )
            processor = self._processor
            if processor is None:
                await self._finish_failed(
                    job, RecognitionErrorReasonLiteV1.SERVICE_UNAVAILABLE
                )
                return

            loop = self._bind_event_loop()
            processor_task = loop.create_task(
                processor.process(context, frames),
                name=f"admission-lite-processor-{job.recognition_id}",
            )
            job.processor_task = processor_task
            self._track_job_task(processor_task, job)
            cancel_waiter = loop.create_task(job.cancel_event.wait())
            self._track_task(cancel_waiter)

            remaining = max(0.0, job.expires_at_monotonic - self._clock())
            done, _ = await asyncio.wait(
                (processor_task, cancel_waiter),
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )

            if processor_task in done:
                try:
                    processor_task.result()
                except asyncio.CancelledError:
                    await self._cancel_if_active(job)
                except Exception:  # noqa: BLE001 - sanitize the processor boundary
                    logger.warning(
                        "Admission Notice Lite processor failed "
                        "recognition_id={} reason=INTERNAL_ERROR",
                        job.recognition_id,
                    )
                    await self._finish_failed(
                        job, RecognitionErrorReasonLiteV1.INTERNAL_ERROR
                    )
                else:
                    await self._finish_completed(job)
            elif cancel_waiter in done:
                await self._cancel_if_active(job)
            else:
                await self._expire_job(job)
        except asyncio.CancelledError:
            await self._cancel_if_active(job)
            raise
        except Exception:  # noqa: BLE001 - terminalize unexpected task failures
            logger.warning(
                "Admission Notice Lite job failed "
                "recognition_id={} reason=INTERNAL_ERROR",
                job.recognition_id,
            )
            await self._finish_failed(job, RecognitionErrorReasonLiteV1.INTERNAL_ERROR)
        finally:
            for task in (cancel_waiter, processor_task):
                if task is not None and not task.done():
                    task.cancel()
            frames = ()
            self._maybe_release_job_resources(
                job,
                supervisor_unwinding=True,
            )

    async def _finish_completed(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        async with self._lock:
            now = self._clock()
            transitioned = self._transition_processor_result_locked(
                job,
                state=RecognitionStateLiteV1.COMPLETED,
                reason=None,
                now=now,
            )
        if transitioned:
            logger.info(
                "Admission Notice Lite job terminal recognition_id={} "
                "state={} active_count={}",
                job.recognition_id,
                job.state.value,
                self.active_job_count,
            )

    async def _finish_failed(
        self,
        job: _RecognitionJobRuntimeLiteV1,
        reason: RecognitionErrorReasonLiteV1,
    ) -> None:
        async with self._lock:
            now = self._clock()
            self._transition_processor_result_locked(
                job,
                state=RecognitionStateLiteV1.FAILED,
                reason=reason,
                now=now,
            )

    async def _expire_job(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        async with self._lock:
            transitioned = self._transition_processor_result_locked(
                job,
                state=RecognitionStateLiteV1.EXPIRED,
                reason=RecognitionErrorReasonLiteV1.RECOGNITION_EXPIRED,
                now=self._clock(),
            )
            if transitioned:
                job.cancel_event.set()

    async def _cancel_if_active(self, job: _RecognitionJobRuntimeLiteV1) -> None:
        async with self._lock:
            transitioned = self._transition_terminal_locked(
                job,
                state=RecognitionStateLiteV1.CANCELLED,
                reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                now=self._clock(),
            )
            if transitioned:
                job.cancel_event.set()

    async def get_recognition(
        self, owning_session_id: str, recognition_id: str
    ) -> RecognitionJobLiteV1:
        self._bind_event_loop()
        owning_session = self._session_lookup(owning_session_id)
        if owning_session is None:
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            )

        async with self._lock:
            now = self._clock()
            tasks_to_cancel = self._expire_due_jobs_locked(now)
            self._purge_terminal_jobs_locked(now)
            job = self._jobs.get(recognition_id)
            if (
                job is None
                or job.owning_session is not owning_session
                or not self._owner_is_current_locked(job)
            ):
                snapshot = None
            else:
                snapshot = job.snapshot()

        self._cancel_tasks(tasks_to_cancel)
        if snapshot is None:
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            )
        return snapshot

    async def cancel_recognition(
        self, owning_session_id: str, recognition_id: str
    ) -> None:
        self._bind_event_loop()
        owning_session = self._session_lookup(owning_session_id)
        if owning_session is None:
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            )

        tasks_to_cancel: list[asyncio.Task[Any]] = []
        async with self._lock:
            now = self._clock()
            tasks_to_cancel.extend(self._expire_due_jobs_locked(now))
            self._purge_terminal_jobs_locked(now)
            job = self._jobs.get(recognition_id)
            if (
                job is None
                or job.owning_session is not owning_session
                or not self._owner_is_current_locked(job)
            ):
                found = False
            else:
                found = True
                if self._transition_terminal_locked(
                    job,
                    state=RecognitionStateLiteV1.CANCELLED,
                    reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                    now=now,
                ):
                    job.cancel_event.set()
                    for task in (job.supervisor_task, job.processor_task):
                        if task is not None and not task.done():
                            tasks_to_cancel.append(task)

        self._cancel_tasks(tasks_to_cancel)
        if not found:
            raise AdmissionNoticeLiteError(
                RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            )

    def notify_session_stopped(
        self, owning_session_id: str, owning_session: object
    ) -> None:
        """Schedule exact-session cancellation from the synchronous engine hook."""

        del owning_session_id
        owner_key = id(owning_session)
        permit = self._resource_permits_by_owner.get(owner_key)
        if permit is None:
            return
        self._invalidated_owner_keys.add(owner_key)
        if not permit.transferred:
            permit.cancel_reason = RecognitionErrorReasonLiteV1.RECOGNITION_NOT_FOUND
            ingestion_task = permit.ingestion_task
            loop = self._event_loop
            if (
                ingestion_task is None
                or ingestion_task.done()
                or loop is None
                or loop.is_closed()
            ):
                return

            def cancel_ingestion() -> None:
                if not ingestion_task.done():
                    ingestion_task.cancel()

            try:
                if asyncio.get_running_loop() is loop:
                    if asyncio.current_task() is not ingestion_task:
                        cancel_ingestion()
                else:
                    loop.call_soon_threadsafe(cancel_ingestion)
            except RuntimeError:
                loop.call_soon_threadsafe(cancel_ingestion)
            return
        if owner_key not in self._active_by_owner:
            return

        loop = self._event_loop
        if loop is None or loop.is_closed() or not self._accepting:
            return

        def schedule() -> None:
            task = loop.create_task(
                self._cancel_stopped_session(owning_session),
                name="admission-lite-session-stop",
            )
            self._track_task(task)

        try:
            if asyncio.get_running_loop() is loop:
                schedule()
            else:
                loop.call_soon_threadsafe(schedule)
        except RuntimeError:
            loop.call_soon_threadsafe(schedule)

    async def _cancel_stopped_session(self, owning_session: object) -> None:
        tasks_to_cancel: list[asyncio.Task[Any]] = []
        async with self._lock:
            recognition_id = self._active_by_owner.get(id(owning_session))
            job = self._jobs.get(recognition_id) if recognition_id is not None else None
            if job is None or job.owning_session is not owning_session:
                return
            if self._transition_terminal_locked(
                job,
                state=RecognitionStateLiteV1.CANCELLED,
                reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                now=self._clock(),
            ):
                job.cancel_event.set()
                for task in (job.supervisor_task, job.processor_task):
                    if task is not None and not task.done():
                        tasks_to_cancel.append(task)
        self._cancel_tasks(tasks_to_cancel)

    async def shutdown(self, *, wait_seconds: float = _SHUTDOWN_WAIT_SECONDS) -> None:
        self._bind_event_loop()
        tasks_to_cancel: list[asyncio.Task[Any]] = []
        async with self._lock:
            self._accepting = False
            now = self._clock()
            for job in tuple(self._jobs.values()):
                if self._transition_terminal_locked(
                    job,
                    state=RecognitionStateLiteV1.CANCELLED,
                    reason=RecognitionErrorReasonLiteV1.RECOGNITION_CANCELLED,
                    now=now,
                ):
                    job.cancel_event.set()
            tasks_to_cancel.extend(
                task for task in self._owned_tasks if not task.done()
            )
            tasks_to_cancel.extend(
                permit.ingestion_task
                for permit in self._resource_permits_by_owner.values()
                if not permit.transferred
                and permit.ingestion_task is not None
                and not permit.ingestion_task.done()
            )

        self._cancel_tasks(tasks_to_cancel)
        current = asyncio.current_task()
        waitable = tuple(task for task in tasks_to_cancel if task is not current)
        if waitable:
            _, pending = await asyncio.wait(
                waitable,
                timeout=max(0.0, wait_seconds),
            )
            for task in pending:
                task.cancel()

        async with self._lock:
            for job in tuple(self._jobs.values()):
                self._discard_job_locked(job)
                self._maybe_release_job_resources(job)
            for permit in tuple(self._resource_permits_by_owner.values()):
                task = permit.ingestion_task
                if not permit.transferred and (task is None or task.done()):
                    self._release_resource_permit(permit)
            self._active_by_owner.clear()
            self._invalidated_owner_keys.intersection_update(
                self._resource_permits_by_owner
            )

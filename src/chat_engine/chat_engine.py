import asyncio
import inspect
import os
import threading
import time
import uuid
from _thread import LockType
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Optional

from dotenv import load_dotenv
from fastapi import HTTPException, Request
from loguru import logger

from chat_engine.common.client_handler_base import ClientHandlerBase
from chat_engine.contexts.session_context import SessionContext
from chat_engine.core.chat_session import ChatSession
from chat_engine.core.handler_manager import HandlerManager
from chat_engine.core.logic_manager import LogicManager
from chat_engine.data_models.chat_engine_config_data import ChatEngineConfigModel
from chat_engine.data_models.session_info_data import SessionInfoData
from engine_utils.directory_info import DirectoryInfo
from service.service_security.certificate_session_control import (
    CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
)
from service.service_security.manager_authorization import (
    require_manager_http_authorization_v1,
)

if TYPE_CHECKING:
    from service.service_security.certificate_session_authority import (
        ConsumedSessionAdmissionV1,
    )


OPEN_AVATAR_CHAT_VERSION = "0.6.0"


@dataclass
class ChatEngineBaseStates:
    inited: bool = False


class ChatEngine(object):
    def __init__(self):
        self.engine_config: Optional[ChatEngineConfigModel] = None
        self.handler_manager: HandlerManager = HandlerManager(self)
        self.logic_manager: LogicManager = LogicManager(self)
        self.states = ChatEngineBaseStates()
        self._certificate_capture_enabled_v1 = False

        self.sessions: Dict[str, ChatSession] = {}
        self._sessions_lock_v1 = threading.RLock()
        self._stopping_session_ids_v1: set[str] = set()
        self._transport_retirement_ids_v1: set[str] = set()
        self._session_stop_events_v1: dict[str, threading.Event] = {}
        self._quarantined_transports_v1: dict[
            str, list[tuple[str, object]]
        ] = {}
        self._transport_teardown_tasks_v1: dict[
            tuple[str, str, int], asyncio.Task
        ] = {}
        self._transport_teardown_threads_v1: dict[
            tuple[str, str, int],
            tuple[threading.Thread, threading.Event],
        ] = {}
        self._transport_teardown_state_lock_v1 = threading.RLock()
        self._transport_teardown_session_locks_v1: dict[
            str, LockType
        ] = {}

    def initialize(self, engine_config: ChatEngineConfigModel, app=None, ui=None, parent_block=None):
        if self.states.inited:
            return

        load_dotenv()
        self._certificate_capture_enabled_v1 = bool(
            app is not None
            and getattr(
                app.state,
                "certificate_capture_enabled_v1",
                False,
            )
        )

        if app:
            @app.get("/version")
            async def root(request: Request):
                await require_manager_http_authorization_v1(app, request)
                return {"version": OPEN_AVATAR_CHAT_VERSION}

            @app.get("/liveness")
            async def check_liveness(request: Request):
                await require_manager_http_authorization_v1(app, request)
                return {"status": "ok"}

            @app.get("/readiness")
            async def check_readiness(request: Request):
                await require_manager_http_authorization_v1(app, request)
                if not self.states.inited:
                    raise HTTPException(status_code=500, detail="Chat engine is not ready yet.")
                return {"status": "ok"}

        self.engine_config = engine_config
        if not os.path.isabs(engine_config.model_root):
            engine_config.model_root = os.path.join(DirectoryInfo.get_project_dir(), engine_config.model_root)
        self.handler_manager.initialize(engine_config)
        self.logic_manager.initialize(engine_config)
        self.handler_manager.load_handlers(engine_config, app, ui, parent_block)
        self.logic_manager.load_logics(engine_config)
        if self._certificate_capture_enabled_v1 and app is not None:
            existing_lifecycle = getattr(
                app.state,
                CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
                None,
            )
            if existing_lifecycle not in {None, self}:
                raise RuntimeError(
                    "secure session lifecycle already installed"
                )
            setattr(
                app.state,
                CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
                self,
            )
        self.states.inited = True

    def _create_session(
        self,
        session_info: SessionInfoData,
        session_admission: "ConsumedSessionAdmissionV1 | None" = None,
    ):
        if (
            self._certificate_capture_enabled_v1
            and session_admission is None
        ):
            raise RuntimeError(
                "secure dispatch requires authenticated session admission"
            )
        with self._sessions_lock_v1:
            if not session_info.session_id:
                session_info.session_id = str(uuid.uuid4())
            if (
                session_info.session_id in self.sessions
                or session_info.session_id in self._stopping_session_ids_v1
                or session_info.session_id
                in self._transport_retirement_ids_v1
            ):
                raise RuntimeError(
                    f"session {session_info.session_id} already exists"
                )

            session_context = SessionContext(
                session_info=session_info,
                session_admission=session_admission,
                certificate_capture_enabled_v1=(
                    self._certificate_capture_enabled_v1
                ),
            )

            session = ChatSession(session_context, self.engine_config)
            handlers = self.handler_manager.get_enabled_handler_registries()
            for registry in handlers:
                if isinstance(registry.handler, ClientHandlerBase):
                    # Client context and sinks are created by the transport
                    # after the shared session handlers are ready.
                    continue
                session.prepare_handler(
                    registry.handler,
                    registry.base_info,
                    registry.handler_config,
                )
            logics = self.logic_manager.get_enabled_logics()
            # TODO
            # for registry in logics:
            #     session.create_logic_contexts(handlers, registry.logic, registry.base_info, registry.logic_config)
            self.sessions[session_info.session_id] = session
            return session

    def create_client_session(
        self,
        session_info: SessionInfoData,
        client_handler: ClientHandlerBase,
        session_admission: "ConsumedSessionAdmissionV1 | None" = None,
    ):
        # TODO currently multi client in one session is not allowed.
        with self._sessions_lock_v1:
            if (
                session_info.session_id in self.sessions
                or session_info.session_id in self._stopping_session_ids_v1
                or session_info.session_id
                in self._transport_retirement_ids_v1
            ):
                msg = f"Session {session_info.session_id} already exists."
                raise RuntimeError(msg)

            session = self._create_session(
                session_info,
                session_admission=session_admission,
            )

            registry = self.handler_manager.find_client_handler(client_handler)
            if registry is None:
                raise RuntimeError(
                    f"client handler {client_handler} not found"
                )

            handler_env = session.prepare_handler(
                client_handler,
                registry.base_info,
                registry.handler_config,
            )
            return session, handler_env

    def stop_session(self, session_id: str):
        with self._sessions_lock_v1:
            session = self.sessions.get(session_id)
            if session is None:
                logger.warning(
                    f"Session {session_id} already stopped or not found."
                )
                return
            if (
                session._work_controller_v1 is not None
                and not session._stop_complete_event_v1.is_set()
            ):
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError(
                        "secure session stop requires await stop_session_async()"
                    )
            stop_event = self._session_stop_events_v1.get(session_id)
            owns_stop = stop_event is None
            if owns_stop:
                stop_event = threading.Event()
                self._session_stop_events_v1[session_id] = stop_event
                self._stopping_session_ids_v1.add(session_id)
        assert stop_event is not None
        if not owns_stop:
            stop_event.wait()
            if not session._stop_complete_event_v1.is_set():
                raise RuntimeError("session stop did not complete")
            return
        try:
            session.stop()
        finally:
            with self._sessions_lock_v1:
                if (
                    session._stop_complete_event_v1.is_set()
                    and session.is_fully_quiesced_v1()
                    and self.sessions.get(session_id) is session
                ):
                    self.sessions.pop(session_id, None)
                self._stopping_session_ids_v1.discard(session_id)
                self._session_stop_events_v1.pop(session_id, None)
                stop_event.set()

    async def stop_session_async(self, session_id: str):
        with self._sessions_lock_v1:
            session = self.sessions.get(session_id)
            if session is None:
                logger.warning(
                    f"Session {session_id} already stopped or not found."
                )
                return
            stop_event = self._session_stop_events_v1.get(session_id)
            owns_stop = stop_event is None
            if owns_stop:
                stop_event = threading.Event()
                self._session_stop_events_v1[session_id] = stop_event
                self._stopping_session_ids_v1.add(session_id)
        assert stop_event is not None
        if not owns_stop:
            while not stop_event.is_set():
                await asyncio.sleep(0.01)
            if not session._stop_complete_event_v1.is_set():
                raise RuntimeError("session stop did not complete")
            return
        try:
            await session.stop_async()
        finally:
            with self._sessions_lock_v1:
                if (
                    session._stop_complete_event_v1.is_set()
                    and session.is_fully_quiesced_v1()
                    and self.sessions.get(session_id) is session
                ):
                    self.sessions.pop(session_id, None)
                self._stopping_session_ids_v1.discard(session_id)
                self._session_stop_events_v1.pop(session_id, None)
                stop_event.set()

    async def _teardown_session_transports_v1(
        self,
        session_id: str,
        deadline_monotonic: float | None = None,
    ) -> bool:
        claim = self._try_claim_transport_teardown_v1(
            session_id
        )
        if claim is None:
            return False
        try:
            return await self._teardown_session_transports_owned_v1(
                session_id,
                deadline_monotonic,
            )
        finally:
            self._release_transport_teardown_claim_v1(
                session_id,
                claim,
            )

    def _try_claim_transport_teardown_v1(
        self,
        session_id: str,
    ) -> LockType | None:
        with self._transport_teardown_state_lock_v1:
            claim = self._transport_teardown_session_locks_v1.get(
                session_id
            )
            if claim is None:
                claim = threading.Lock()
                self._transport_teardown_session_locks_v1[
                    session_id
                ] = claim
            if not claim.acquire(blocking=False):
                return None
            return claim

    def _release_transport_teardown_claim_v1(
        self,
        session_id: str,
        claim: LockType,
    ) -> None:
        with self._transport_teardown_state_lock_v1:
            claim.release()
            if (
                self._transport_teardown_session_locks_v1.get(
                    session_id
                )
                is not claim
            ):
                return
            if not self._quarantined_transports_v1.get(
                session_id
            ):
                self._transport_teardown_session_locks_v1.pop(
                    session_id,
                    None,
                )

    async def _teardown_session_transports_owned_v1(
        self,
        session_id: str,
        deadline_monotonic: float | None = None,
    ) -> bool:
        """Tear down client transports after fenced session cleanup."""

        async def await_bounded_v1(
            target_kind: str,
            target: object,
            action,
            reason_code: str,
        ) -> bool:
            task_key = (session_id, target_kind, id(target))
            thread_state = self._transport_teardown_threads_v1.get(
                task_key
            )
            if thread_state is not None:
                worker, failed = thread_state
                if worker.is_alive():
                    logger.error(reason_code)
                    return False
                self._transport_teardown_threads_v1.pop(
                    task_key,
                    None,
                )
                if not failed.is_set():
                    return True
            task = self._transport_teardown_tasks_v1.get(
                task_key
            )
            if task is None:
                async def invoke_action_v1() -> None:
                    if inspect.iscoroutinefunction(action):
                        result = action()
                    else:
                        result = await asyncio.to_thread(action)
                    if inspect.isawaitable(result):
                        await result

                task = asyncio.create_task(invoke_action_v1())
                self._transport_teardown_tasks_v1[task_key] = task
            await asyncio.sleep(0)
            remaining = (
                max(0.0, deadline_monotonic - time.monotonic())
                if deadline_monotonic is not None
                else None
            )
            done, pending = await asyncio.wait(
                (task,),
                timeout=remaining,
            )
            if pending:
                task.cancel()
                logger.error(reason_code)
                return False
            for completed in done:
                try:
                    completed.result()
                except asyncio.CancelledError:
                    self._transport_teardown_tasks_v1.pop(
                        task_key,
                        None,
                    )
                    logger.error(reason_code)
                    return False
                except Exception:  # noqa: BLE001 - payload-free teardown
                    self._transport_teardown_tasks_v1.pop(
                        task_key,
                        None,
                    )
                    logger.error(reason_code)
                    return False
            self._transport_teardown_tasks_v1.pop(
                task_key,
                None,
            )
            return True

        targets = self._quarantined_transports_v1.pop(
            session_id,
            [],
        )
        registries = self.handler_manager.get_enabled_handler_registries()
        for registry in registries:
            handler = registry.handler
            if not isinstance(handler, ClientHandlerBase):
                continue
            delegate_manager = handler.handler_delegate
            session_delegate = (
                delegate_manager.session_delegates.pop(
                    session_id,
                    None,
                )
            )

            stream_factory = getattr(
                handler,
                "rtc_streamer_factory",
                None,
            )
            streams = getattr(stream_factory, "streams", None)
            stream = (
                streams.get(session_id)
                if isinstance(streams, dict)
                else None
            )
            if stream is not None:
                targets.append(("stream", stream))
            if session_delegate is not None:
                targets.append(("delegate", session_delegate))

        quarantined: list[tuple[str, object]] = []
        seen_targets: set[int] = set()
        for target_kind, target in targets:
            if id(target) in seen_targets:
                continue
            seen_targets.add(id(target))
            succeeded = True
            if target_kind == "stream":
                target.owns_session = False
                shutdown_async = getattr(
                    target,
                    "shutdown_async",
                    None,
                )
                if callable(shutdown_async):
                    try:
                        succeeded = await await_bounded_v1(
                            target_kind,
                            target,
                            shutdown_async,
                            "RTC_TRANSPORT_SHUTDOWN_FAILED_V1",
                        )
                    except Exception:  # noqa: BLE001
                        succeeded = False
                else:
                    shutdown = getattr(target, "shutdown", None)
                    if callable(shutdown):
                        try:
                            succeeded = await await_bounded_v1(
                                target_kind,
                                target,
                                shutdown,
                                "RTC_TRANSPORT_SHUTDOWN_FAILED_V1",
                            )
                        except Exception:  # noqa: BLE001
                            succeeded = False
            else:
                retire_transport = getattr(
                    target,
                    "retire_transport_async_v1",
                    None,
                )
                if callable(retire_transport):
                    try:
                        succeeded = await await_bounded_v1(
                            target_kind,
                            target,
                            retire_transport,
                            "CLIENT_TRANSPORT_SHUTDOWN_FAILED_V1",
                        )
                    except Exception:  # noqa: BLE001
                        succeeded = False
                else:
                    clear_data = getattr(
                        target,
                        "clear_data",
                        None,
                    )
                    if callable(clear_data):
                        try:
                            succeeded = await await_bounded_v1(
                                target_kind,
                                target,
                                clear_data,
                                "CLIENT_TRANSPORT_SHUTDOWN_FAILED_V1",
                            )
                        except Exception:  # noqa: BLE001
                            succeeded = False
                transport_tasks = (
                    *getattr(target, "primary_tasks", ()),
                    *getattr(
                        target,
                        "_quarantined_connection_tasks_v1",
                        (),
                    ),
                )
                if any(not task.done() for task in transport_tasks):
                    succeeded = False
            if not succeeded:
                quarantined.append((target_kind, target))

        if quarantined:
            self._quarantined_transports_v1[session_id] = quarantined
            return False
        return True

    def _teardown_session_transports_sync_v1(
        self,
        session_id: str,
        deadline_monotonic: float | None = None,
    ) -> bool:
        claim = self._try_claim_transport_teardown_v1(
            session_id
        )
        if claim is None:
            return False
        try:
            return self._teardown_session_transports_owned_sync_v1(
                session_id,
                deadline_monotonic,
            )
        finally:
            self._release_transport_teardown_claim_v1(
                session_id,
                claim,
            )

    def _teardown_session_transports_owned_sync_v1(
        self,
        session_id: str,
        deadline_monotonic: float | None = None,
    ) -> bool:
        def invoke_bounded_v1(
            target_kind: str,
            target: object,
            action,
            reason_code: str,
        ) -> bool:
            thread_key = (session_id, target_kind, id(target))
            async_task = self._transport_teardown_tasks_v1.get(
                thread_key
            )
            if async_task is not None:
                if not async_task.done():
                    logger.error(reason_code)
                    return False
                self._transport_teardown_tasks_v1.pop(
                    thread_key,
                    None,
                )
                try:
                    async_task.result()
                except asyncio.CancelledError:
                    pass
                except Exception:  # noqa: BLE001 - payload-free retry state
                    pass
                else:
                    return True
            existing = self._transport_teardown_threads_v1.get(
                thread_key
            )
            if existing is not None:
                worker, failed = existing
                if worker.is_alive():
                    logger.error(reason_code)
                    return False
                self._transport_teardown_threads_v1.pop(
                    thread_key,
                    None,
                )
                if not failed.is_set():
                    return True

            failed = threading.Event()

            def invoke() -> None:
                try:
                    action()
                except Exception:  # noqa: BLE001 - payload-free teardown
                    failed.set()
                    logger.error(reason_code)

            worker = threading.Thread(
                target=invoke,
                name="secure_transport_cleanup_v1",
                daemon=True,
            )
            self._transport_teardown_threads_v1[thread_key] = (
                worker,
                failed,
            )
            worker.start()
            worker.join(
                timeout=(
                    max(
                        0.0,
                        deadline_monotonic - time.monotonic(),
                    )
                    if deadline_monotonic is not None
                    else None
                )
            )
            if worker.is_alive():
                logger.error(reason_code)
                return False
            self._transport_teardown_threads_v1.pop(
                thread_key,
                None,
            )
            return not failed.is_set()

        targets = self._quarantined_transports_v1.pop(
            session_id,
            [],
        )
        for registry in self.handler_manager.get_enabled_handler_registries():
            handler = registry.handler
            if not isinstance(handler, ClientHandlerBase):
                continue
            delegate_manager = handler.handler_delegate
            session_delegate = (
                delegate_manager.session_delegates.pop(
                    session_id,
                    None,
                )
            )
            stream_factory = getattr(
                handler,
                "rtc_streamer_factory",
                None,
            )
            streams = getattr(stream_factory, "streams", None)
            stream = (
                streams.get(session_id)
                if isinstance(streams, dict)
                else None
            )
            if stream is not None:
                targets.append(("stream", stream))
            if session_delegate is not None:
                targets.append(("delegate", session_delegate))

        quarantined: list[tuple[str, object]] = []
        seen_targets: set[int] = set()
        for target_kind, target in targets:
            if id(target) in seen_targets:
                continue
            seen_targets.add(id(target))
            succeeded = True
            if target_kind == "stream":
                target.owns_session = False
                shutdown = getattr(target, "shutdown", None)
                if callable(shutdown):
                    succeeded = invoke_bounded_v1(
                        target_kind,
                        target,
                        shutdown,
                        "RTC_TRANSPORT_SHUTDOWN_FAILED_V1",
                    )
            else:
                quit_event = getattr(target, "quit", None)
                if quit_event is not None:
                    quit_event.set()
                clear_data = getattr(
                    target,
                    "clear_data",
                    None,
                )
                if callable(clear_data):
                    succeeded = invoke_bounded_v1(
                        target_kind,
                        target,
                        clear_data,
                        "CLIENT_TRANSPORT_SHUTDOWN_FAILED_V1",
                    )
                transport_tasks = (
                    *getattr(target, "primary_tasks", ()),
                    *getattr(
                        target,
                        "_quarantined_connection_tasks_v1",
                        (),
                    ),
                )
                if any(not task.done() for task in transport_tasks):
                    succeeded = False
            if not succeeded:
                quarantined.append((target_kind, target))

        if quarantined:
            self._quarantined_transports_v1[session_id] = quarantined
            return False
        return True

    def retire_secure_session_sync_v1(self, session_id: str) -> None:
        with self._sessions_lock_v1:
            session = self.sessions.get(session_id)
            self._transport_retirement_ids_v1.add(session_id)
        self.stop_session(session_id)
        transport_succeeded = self._teardown_session_transports_sync_v1(
            session_id,
            (
                session.shutdown_deadline_monotonic_v1()
                if session is not None
                else None
            ),
        )
        with self._sessions_lock_v1:
            if (
                session is not None
                and (
                    not session.is_fully_quiesced_v1()
                    or not transport_succeeded
                )
            ):
                self.sessions.setdefault(session_id, session)
            if transport_succeeded:
                self._transport_retirement_ids_v1.discard(
                    session_id
                )

    async def retire_secure_session_v1(self, session_id: str) -> None:
        """Retire/cancel work, then tear down the owning client transport."""

        with self._sessions_lock_v1:
            session = self.sessions.get(session_id)
            self._transport_retirement_ids_v1.add(session_id)
        await self.stop_session_async(session_id)
        transport_succeeded = await self._teardown_session_transports_v1(
            session_id,
            (
                session.shutdown_deadline_monotonic_v1()
                if session is not None
                else None
            ),
        )
        with self._sessions_lock_v1:
            if (
                session is not None
                and (
                    not session.is_fully_quiesced_v1()
                    or not transport_succeeded
                )
            ):
                self.sessions.setdefault(session_id, session)
            if transport_succeeded:
                self._transport_retirement_ids_v1.discard(
                    session_id
                )

    def shutdown(self) -> bool:
        logger.info("Shutting down chat engine...")
        with self._sessions_lock_v1:
            secure_session_ids = tuple(
                session_id
                for session_id, session in self.sessions.items()
                if session._work_controller_v1 is not None
            )
        for session_id in secure_session_ids:
            self.retire_secure_session_sync_v1(session_id)
        with self._sessions_lock_v1:
            if any(
                session._work_controller_v1 is not None
                and not session.is_fully_quiesced_v1()
                for session in self.sessions.values()
            ) or self._quarantined_transports_v1 or (
                self._transport_retirement_ids_v1
            ) or self._transport_teardown_tasks_v1 or (
                self._transport_teardown_threads_v1
            ):
                logger.error("SECURE_SESSION_MANAGER_TEARDOWN_BLOCKED_V1")
                return False
        self.logic_manager.destroy()
        self.handler_manager.destroy()
        return True

    async def shutdown_async(self) -> bool:
        logger.info("Shutting down chat engine...")
        with self._sessions_lock_v1:
            secure_session_ids = tuple(
                session_id
                for session_id, session in self.sessions.items()
                if session._work_controller_v1 is not None
            )
        for session_id in secure_session_ids:
            await self.retire_secure_session_v1(session_id)
        with self._sessions_lock_v1:
            if any(
                session._work_controller_v1 is not None
                and not session.is_fully_quiesced_v1()
                for session in self.sessions.values()
            ) or self._quarantined_transports_v1 or (
                self._transport_retirement_ids_v1
            ) or self._transport_teardown_tasks_v1 or (
                self._transport_teardown_threads_v1
            ):
                logger.error("SECURE_SESSION_MANAGER_TEARDOWN_BLOCKED_V1")
                return False
        self.logic_manager.destroy()
        self.handler_manager.destroy()
        return True

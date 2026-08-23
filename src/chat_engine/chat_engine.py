import asyncio
import inspect
import os
import threading
import uuid
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
from service.service_security.manager_authorization import (
    require_manager_http_authorization_v1,
)
from service.service_security.certificate_session_control import (
    CERTIFICATE_SESSION_WORK_LIFECYCLE_ATTRIBUTE_V1,
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
        self._session_stop_events_v1: dict[str, threading.Event] = {}

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
                    and self.sessions.get(session_id) is session
                ):
                    self.sessions.pop(session_id, None)
                self._stopping_session_ids_v1.discard(session_id)
                self._session_stop_events_v1.pop(session_id, None)
                stop_event.set()

    async def _teardown_session_transports_v1(
        self,
        session_id: str,
    ) -> None:
        """Tear down client transports after fenced session cleanup."""

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
                shutdown_async = getattr(
                    stream,
                    "shutdown_async",
                    None,
                )
                if callable(shutdown_async):
                    result = shutdown_async()
                    if inspect.isawaitable(result):
                        await result
                else:
                    shutdown = getattr(stream, "shutdown", None)
                    if callable(shutdown):
                        result = shutdown()
                        if inspect.isawaitable(result):
                            await result

            if session_delegate is not None:
                retire_transport = getattr(
                    session_delegate,
                    "retire_transport_async_v1",
                    None,
                )
                if callable(retire_transport):
                    result = retire_transport()
                    if inspect.isawaitable(result):
                        await result
                else:
                    clear_data = getattr(
                        session_delegate,
                        "clear_data",
                        None,
                    )
                    if callable(clear_data):
                        clear_data()

    def _teardown_session_transports_sync_v1(
        self,
        session_id: str,
    ) -> None:
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
                shutdown = getattr(stream, "shutdown", None)
                if callable(shutdown):
                    shutdown()
            if session_delegate is not None:
                quit_event = getattr(session_delegate, "quit", None)
                if quit_event is not None:
                    quit_event.set()
                clear_data = getattr(
                    session_delegate,
                    "clear_data",
                    None,
                )
                if callable(clear_data):
                    clear_data()

    def retire_secure_session_sync_v1(self, session_id: str) -> None:
        self.stop_session(session_id)
        self._teardown_session_transports_sync_v1(session_id)

    async def retire_secure_session_v1(self, session_id: str) -> None:
        """Retire/cancel work, then tear down the owning client transport."""

        await self.stop_session_async(session_id)
        await self._teardown_session_transports_v1(session_id)
    
    def shutdown(self):
        logger.info("Shutting down chat engine...")
        with self._sessions_lock_v1:
            secure_session_ids = tuple(
                session_id
                for session_id, session in self.sessions.items()
                if session._work_controller_v1 is not None
            )
        for session_id in secure_session_ids:
            self.retire_secure_session_sync_v1(session_id)
        self.logic_manager.destroy()
        self.handler_manager.destroy()

    async def shutdown_async(self):
        logger.info("Shutting down chat engine...")
        with self._sessions_lock_v1:
            secure_session_ids = tuple(
                session_id
                for session_id, session in self.sessions.items()
                if session._work_controller_v1 is not None
            )
        for session_id in secure_session_ids:
            await self.retire_secure_session_v1(session_id)
        self.logic_manager.destroy()
        self.handler_manager.destroy()

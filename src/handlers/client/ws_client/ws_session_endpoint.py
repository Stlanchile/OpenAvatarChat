from __future__ import annotations

from fastapi import FastAPI, WebSocketDisconnect
from loguru import logger
from starlette.websockets import WebSocket, WebSocketState

from chat_engine.common.client_handler_base import (
    ClientHandlerDelegate,
    ClientSessionDelegate,
)
from service.service_security.certificate_session_authority import (
    session_admission_ownership_matches_v1,
)
from service.service_security.websocket_session_admission import (
    WebSocketAdmissionErrorV1,
    WebSocketAdmissionReasonV1,
    WebSocketSessionAdmissionGuardV1,
    reject_websocket_admission_v1,
    websocket_session_admission_guard_v1,
)

_SESSION_WEBSOCKET_ROUTE_V1 = "/ws/session/{session_id}"


def register_ws_session_endpoint(
    app: FastAPI,
    handler_delegate: ClientHandlerDelegate,
    expected_delegate_type: type[ClientSessionDelegate],
) -> None:
    """Register the legacy or certificate-gated session WebSocket route."""

    @app.websocket(_SESSION_WEBSOCKET_ROUTE_V1)
    async def ws_session_endpoint(websocket: WebSocket, session_id: str):
        try:
            admission_guard = websocket_session_admission_guard_v1(app)
        except Exception:  # noqa: BLE001
            await reject_websocket_admission_v1(
                websocket,
                _authority_unavailable_error(),
            )
            return
        if admission_guard is None:
            await _serve_legacy_websocket(
                websocket,
                session_id,
                handler_delegate,
                expected_delegate_type,
            )
            return
        await _serve_authenticated_websocket(
            websocket,
            session_id,
            handler_delegate,
            expected_delegate_type,
            admission_guard,
        )


async def _serve_authenticated_websocket(
    websocket: WebSocket,
    session_id: str,
    handler_delegate: ClientHandlerDelegate,
    expected_delegate_type: type[ClientSessionDelegate],
    admission_guard: WebSocketSessionAdmissionGuardV1,
) -> None:
    created_session = False
    session_delegate = None
    accepted = False
    try:
        async with admission_guard.serialized_transition():
            session_admission = admission_guard.consume(websocket, session_id)
            try:
                session_delegate = handler_delegate.find_session_delegate(
                    session_id
                )
                if session_delegate is None:
                    session_delegate = handler_delegate.start_session(
                        session_id,
                        session_admission=session_admission,
                    )
                    created_session = True
                else:
                    established_admission = (
                        handler_delegate.find_session_admission(session_id)
                    )
                    # Each transport has already consumed its own channel-bound
                    # ticket. Existing application state may therefore have
                    # been created by RTC while still naming the exact same
                    # authority-owned session and principal.
                    if not session_admission_ownership_matches_v1(
                        established_admission,
                        session_admission,
                    ):
                        raise _admission_denied_error()

                if not isinstance(session_delegate, expected_delegate_type):
                    if created_session:
                        _stop_session_after_failed_handshake(
                            handler_delegate,
                            session_id,
                        )
                    raise _admission_denied_error()
            except WebSocketAdmissionErrorV1:
                raise
            except Exception:  # noqa: BLE001
                if session_delegate is None or created_session:
                    _stop_session_after_failed_handshake(
                        handler_delegate,
                        session_id,
                    )
                raise _authority_unavailable_error() from None

            try:
                await websocket.accept()
                accepted = True
            except Exception:  # noqa: BLE001
                return
            finally:
                if not accepted and created_session:
                    _stop_session_after_failed_handshake(
                        handler_delegate,
                        session_id,
                    )
    except WebSocketAdmissionErrorV1 as error:
        await reject_websocket_admission_v1(websocket, error)
        return
    except Exception:  # noqa: BLE001
        if accepted:
            if created_session:
                _stop_session_after_failed_handshake(
                    handler_delegate,
                    session_id,
                )
            try:
                await websocket.close(
                    code=1011,
                    reason=WebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE.value,
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "Authenticated session authority-failure close failed."
                )
            return
        await reject_websocket_admission_v1(
            websocket,
            _authority_unavailable_error(),
        )
        return

    logger.info("Authenticated session WebSocket connected.")
    should_stop = False
    try:
        should_stop = await session_delegate.serve_websocket(websocket)
    except WebSocketDisconnect:
        logger.info("Authenticated session WebSocket disconnected.")
    except Exception:  # noqa: BLE001
        logger.error("Authenticated session WebSocket failed.")
    finally:
        if should_stop:
            try:
                handler_delegate.stop_session(session_id)
                logger.info("Authenticated session stopped.")
            except Exception:  # noqa: BLE001
                logger.error("Authenticated session cleanup failed.")

        try:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                await websocket.close()
        except Exception:  # noqa: BLE001
            logger.debug("Authenticated session WebSocket close failed.")


async def _serve_legacy_websocket(
    websocket: WebSocket,
    session_id: str,
    handler_delegate: ClientHandlerDelegate,
    expected_delegate_type: type[ClientSessionDelegate],
) -> None:
    await websocket.accept()
    logger.info(f"Session WebSocket connected: session_id={session_id}")

    should_stop = False
    try:
        session_delegate = handler_delegate.find_session_delegate(session_id)
        if session_delegate is None:
            logger.info(f"Creating new session: {session_id}")
            session_delegate = handler_delegate.start_session(session_id)

        if not isinstance(session_delegate, expected_delegate_type):
            logger.error(f"Invalid session delegate type: {type(session_delegate)}")
            await websocket.close(code=1003, reason="Invalid session")
            return

        should_stop = await session_delegate.serve_websocket(websocket)
    except WebSocketDisconnect:
        logger.info(f"Session WebSocket disconnected: session_id={session_id}")
    except Exception as exception:  # noqa: BLE001
        logger.error(f"Error in session WebSocket: {exception}")
    finally:
        if should_stop:
            try:
                handler_delegate.stop_session(session_id)
                logger.info(f"Session stopped: {session_id}")
            except Exception as exception:  # noqa: BLE001
                logger.error(f"Error stopping session: {exception}")

        try:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                await websocket.close()
        except Exception:  # noqa: BLE001
            logger.debug("Session WebSocket close failed.")


def _stop_session_after_failed_handshake(
    handler_delegate: ClientHandlerDelegate,
    session_id: str,
) -> None:
    try:
        handler_delegate.stop_session(session_id)
    except Exception:  # noqa: BLE001
        logger.error("Authenticated session handshake cleanup failed.")


def _admission_denied_error() -> WebSocketAdmissionErrorV1:
    return WebSocketAdmissionErrorV1(
        WebSocketAdmissionReasonV1.ADMISSION_DENIED,
        status_code=403,
    )


def _authority_unavailable_error() -> WebSocketAdmissionErrorV1:
    return WebSocketAdmissionErrorV1(
        WebSocketAdmissionReasonV1.AUTHORITY_UNAVAILABLE,
        status_code=503,
    )

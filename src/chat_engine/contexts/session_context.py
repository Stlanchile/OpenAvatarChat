from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from chat_engine.contexts.session_clock import SessionClock
from chat_engine.contexts.session_history import HistoryConfig, SessionHistory
from chat_engine.data_models.session_info_data import SessionInfoData

if TYPE_CHECKING:
    from service.service_security.certificate_session_authority import (
        ConsumedSessionAdmissionV1,
    )


@dataclass
class SharedStates:
    active: bool = False


class SessionContext(object):
    def __init__(
        self,
        session_info: SessionInfoData,
        history_config: Optional[HistoryConfig] = None,
        session_admission: "ConsumedSessionAdmissionV1 | None" = None,
        certificate_capture_enabled_v1: bool = False,
    ):
        if certificate_capture_enabled_v1 and session_admission is None:
            raise RuntimeError(
                "secure dispatch requires authenticated session admission"
            )
        self.session_info = session_info
        self.session_admission = session_admission
        # Admission is installed only by the Milestone 1 authenticated
        # transport seam. Secure sessions must never fall back to naked queues.
        self.secure_dispatch_enabled_v1 = (
            certificate_capture_enabled_v1
            or session_admission is not None
        )
        self.session_clock: SessionClock = SessionClock(self.session_info.timestamp_base)
        self.shared_states = SharedStates()
        # Global session history for full-duplex conversation support
        self.session_history: SessionHistory = SessionHistory(history_config)

    def cleanup(self):
        pass

    def get_clock(self):
        return self.session_clock
    
    def get_history(self) -> SessionHistory:
        """Get the session history for event tracking."""
        return self.session_history

"""Capability-bound access to generic SessionHistory."""

from __future__ import annotations

from typing import Any

from chat_engine.contexts.session_history import HistoryEvent, SessionHistory
from chat_engine.security.dispatch import ProducerAuthorityReferenceV1


class SessionHistoryConsumerViewV1:
    """Expose legacy reads while binding every mutation to producer authority."""

    __slots__ = ("__history", "__producer_ref")
    _READ_METHODS_V1 = frozenset(
        {
            "export_for_summary",
            "get_accumulated_data",
            "get_active_avatar_stream",
            "get_active_avatar_streams",
            "get_event",
            "get_recent_dialog",
            "get_recent_events",
            "get_related_events",
            "get_stream_start_time",
            "is_avatar_speaking",
            "was_avatar_speaking_at",
        }
    )

    def __init__(
        self,
        history: SessionHistory,
        producer_ref: ProducerAuthorityReferenceV1,
    ):
        self.__history = history
        self.__producer_ref = producer_ref

    def __repr__(self) -> str:
        return "SessionHistoryConsumerViewV1(<bound>)"

    def __getattr__(self, name: str) -> Any:
        if name not in self._READ_METHODS_V1:
            raise AttributeError(name)
        return getattr(self.__history, name)

    def accumulate_stream_data(
        self,
        stream_key: str,
        text: str,
        chunk_id: str | None = None,
    ) -> bool:
        return self.__history.accumulate_stream_data(
            stream_key,
            text,
            chunk_id,
            _security_writer_v1=self.__producer_ref,
        )

    def finalize_stream_accumulator(self, stream_key: str) -> str | None:
        return self.__history.finalize_stream_accumulator(
            stream_key,
            _security_writer_v1=self.__producer_ref,
        )

    def add_event(self, event: HistoryEvent) -> str | None:
        return self.__history.add_event(
            event,
            _security_writer_v1=self.__producer_ref,
        )

    def create_and_add_event(self, **kwargs: Any) -> str | None:
        return self.__history.create_and_add_event(
            **kwargs,
            _security_writer_v1=self.__producer_ref,
        )

    def revoke_event(self, event_id: str, owner: str) -> bool:
        return self.__history.revoke_event(
            event_id,
            owner,
            _security_writer_v1=self.__producer_ref,
        )

    def revoke_by_owner(
        self,
        owner: str,
        since_timestamp: float | None = None,
    ) -> int:
        return self.__history.revoke_by_owner(
            owner,
            since_timestamp,
            _security_writer_v1=self.__producer_ref,
        )

    def link_events(self, event_id: str, related_event_id: str) -> None:
        self.__history.link_events(
            event_id,
            related_event_id,
            _security_writer_v1=self.__producer_ref,
        )

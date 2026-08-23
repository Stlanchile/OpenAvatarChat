"""Trusted test-only seam for synthetic private canaries.

This test module is intentionally absent from the production package and is
not wired to HTTP, WebSocket, RTC, configuration, or handler metadata.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from chat_engine.common.handler_base import HandlerBase
from chat_engine.data_models.chat_data.chat_data_model import ChatData
from chat_engine.data_models.chat_engine_config_data import HandlerBaseConfigModel
from chat_engine.data_models.internal.handler_definition_data import (
    HandlerBaseInfo,
    HandlerDataInfo,
)
from chat_engine.security.dispatch import (
    ConsumerCapabilityV1,
    PrivateTestIssuerCapabilityV1,
    SecurityEnvelopeReferenceV1,
)
from chat_engine.security.envelope import (
    SecurityClassificationV1,
    SecurityEnvelopeV1,
)

if TYPE_CHECKING:
    from chat_engine.core.chat_session import ChatSession


class SecurityTestHarnessV1:
    """Core-adjacent test harness; never expose this object to handlers."""

    def __init__(
        self,
        session: ChatSession,
        private_issuer: PrivateTestIssuerCapabilityV1,
    ):
        if session._security_authority is None:
            raise RuntimeError("security test harness requires a secure session")
        self._session = session
        self._authority = session._security_authority
        self._private_issuer = private_issuer

    def issue_public_envelope(
        self,
    ) -> SecurityEnvelopeReferenceV1:
        envelope_ref = self._authority._issue_public_root_for_test_v1(
            self._private_issuer
        )
        if envelope_ref is None:
            raise RuntimeError("public test envelope unavailable")
        return envelope_ref

    def issue_private_envelope(
        self,
    ) -> SecurityEnvelopeReferenceV1:
        envelope_ref = self._authority._issue_private_root_for_test_v1(
            self._private_issuer
        )
        if envelope_ref is None:
            raise RuntimeError("private test envelope unavailable")
        return envelope_ref

    def derive_envelope(
        self,
        parent_refs: tuple[SecurityEnvelopeReferenceV1, ...],
        *,
        requested_classification: SecurityClassificationV1 | None = None,
    ) -> SecurityEnvelopeReferenceV1 | None:
        return self._authority.derive_envelope_v1(
            parent_refs,
            requested_classification=requested_classification,
        )

    def envelope(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> SecurityEnvelopeV1 | None:
        return self._authority.envelope_v1(envelope_ref)

    def issue_public_capability(self) -> ConsumerCapabilityV1:
        capability = self._authority._issue_public_test_consumer_capability_v1(
            self._private_issuer
        )
        if capability is None:
            raise RuntimeError("public test capability unavailable")
        return capability

    def issue_private_capability(self) -> ConsumerCapabilityV1:
        capability = self._authority._issue_private_test_consumer_capability_v1(
            self._private_issuer
        )
        if capability is None:
            raise RuntimeError("private test capability unavailable")
        return capability

    def register_private_handler(
        self,
        handler: HandlerBase,
        handler_info: HandlerBaseInfo,
        handler_config: HandlerBaseConfigModel,
    ):
        capability = self.issue_private_capability()
        return self._session.prepare_handler(
            handler,
            handler_info,
            handler_config,
            _consumer_capability_v1=capability,
        )

    def dispatch_private(
        self,
        chat_data: ChatData,
        *,
        finish_stream: bool | None = True,
    ) -> None:
        envelope_ref = self.issue_private_envelope()
        producer_authority = self._authority._issue_test_producer_authority_v1(
            self._private_issuer,
            envelope_ref,
        )
        if producer_authority is None:
            raise RuntimeError("private test producer unavailable")
        definition = chat_data.data.definition if chat_data.data is not None else None
        streamer = self._session.stream_manager.create_streamer(
            data_info=HandlerDataInfo(
                type=chat_data.type,
                definition=definition,
            ),
            data_sinks=self._session.data_sinks,
            producer_name="core_synthetic_private_v1",
            producer_authority=producer_authority,
        )
        streamer.stream_data(
            chat_data,
            finish_stream=finish_stream,
        )

    def dispatch_public(
        self,
        chat_data: ChatData,
        *,
        finish_stream: bool | None = True,
    ) -> None:
        envelope_ref = self.issue_public_envelope()
        producer_authority = self._authority._issue_test_producer_authority_v1(
            self._private_issuer,
            envelope_ref,
        )
        if producer_authority is None:
            raise RuntimeError("public test producer unavailable")
        definition = chat_data.data.definition if chat_data.data is not None else None
        streamer = self._session.stream_manager.create_streamer(
            data_info=HandlerDataInfo(
                type=chat_data.type,
                definition=definition,
            ),
            data_sinks=self._session.data_sinks,
            producer_name="core_synthetic_public_v1",
            producer_authority=producer_authority,
        )
        streamer.stream_data(
            chat_data,
            finish_stream=finish_stream,
        )

    def create_public_streamer(
        self,
        *,
        data_info: HandlerDataInfo,
        data_sinks,
        producer_name: str,
    ):
        envelope_ref = self.issue_public_envelope()
        producer_authority = self._authority._issue_test_producer_authority_v1(
            self._private_issuer,
            envelope_ref,
        )
        if producer_authority is None:
            raise RuntimeError("public test producer unavailable")
        return self._session.stream_manager.create_streamer(
            data_info=data_info,
            data_sinks=data_sinks,
            producer_name=producer_name,
            producer_authority=producer_authority,
        )

    def classification_for_stream(
        self,
        stream_id,
    ) -> SecurityClassificationV1 | None:
        stream = self._session.stream_manager.find_stream(stream_id)
        if stream is None or stream.security_stream_ref is None:
            return None
        envelope = self._authority.envelope_v1(stream.security_stream_ref.envelope_ref)
        return envelope.classification if envelope is not None else None

    def audit_events(self):
        return self._authority.audit_events_v1()

    def fail_registry(self) -> None:
        self._authority._fail_registry_for_test_v1()

    def remove_envelope(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> None:
        self._authority._remove_envelope_for_test_v1(envelope_ref)

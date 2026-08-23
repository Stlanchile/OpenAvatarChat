"""Authenticated internal references and authorized dispatch wrappers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_signal_type import (
    ChatSignalSourceType,
    ChatSignalType,
)
from chat_engine.security.envelope import (
    EgressPolicyV1,
    SecurityClassificationV1,
)


@dataclass(frozen=True, slots=True, repr=False)
class SecurityEnvelopeReferenceV1:
    authority_id: str
    envelope_id: str
    authenticator: bytes

    def __repr__(self) -> str:
        return "SecurityEnvelopeReferenceV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class ConsumerCapabilityV1:
    authority_id: str
    capability_id: str
    allowed_classifications: frozenset[SecurityClassificationV1]
    allowed_egress_policies: frozenset[EgressPolicyV1]
    authenticator: bytes

    def __repr__(self) -> str:
        return "ConsumerCapabilityV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class PrivateTestIssuerCapabilityV1:
    authority_id: str
    issuer_id: str
    authenticator: bytes

    def __repr__(self) -> str:
        return "PrivateTestIssuerCapabilityV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class CoreRegistrarCapabilityV1:
    """Construction-time authority; never placed in handler-facing objects."""

    authority_id: str
    registrar_id: str
    authenticator: bytes

    def __repr__(self) -> str:
        return "CoreRegistrarCapabilityV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerAuthorityReferenceV1:
    """Core-issued identity for one handler or trusted ingress producer."""

    authority_id: str
    producer_authority_id: str
    consumer_capability_id: str
    authenticator: bytes

    def __repr__(self) -> str:
        return "ProducerAuthorityReferenceV1(<opaque>)"


@dataclass(frozen=True, slots=True)
class TrustedStreamIdentityV1:
    data_type: ChatDataType
    builder_id: int
    stream_id: int
    name: str | None
    producer_name: str | None


@dataclass(frozen=True, slots=True, repr=False)
class SecurityStreamReferenceV1:
    authority_id: str
    stream_authority_id: str
    envelope_ref: SecurityEnvelopeReferenceV1
    identity: TrustedStreamIdentityV1
    authenticator: bytes

    def __repr__(self) -> str:
        return "SecurityStreamReferenceV1(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizedDispatchV1:
    authority_id: str
    dispatch_id: str
    envelope_ref: SecurityEnvelopeReferenceV1
    stream_ref: SecurityStreamReferenceV1
    consumer_capability: ConsumerCapabilityV1
    trusted_data_type: ChatDataType
    trusted_source: str | None
    trusted_lineage_digest: bytes
    payload: Any
    authenticator: bytes
    # Separate core-owned temporal carrier. It is not payload/stream
    # metadata and is validated only by SessionWorkControllerV1.
    work_item_v1: Any = None

    def __repr__(self) -> str:
        return "AuthorizedDispatchV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedDispatchV1:
    dispatch_id: str
    envelope_ref: SecurityEnvelopeReferenceV1
    stream_ref: SecurityStreamReferenceV1
    classification: SecurityClassificationV1
    egress_policy: EgressPolicyV1
    trusted_data_type: ChatDataType
    trusted_source: str | None
    payload: Any

    def __repr__(self) -> str:
        return "ValidatedDispatchV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizedSignalEmissionV1:
    authority_id: str
    emission_id: str
    envelope_ref: SecurityEnvelopeReferenceV1
    stream_ref: SecurityStreamReferenceV1 | None
    trusted_signal_type: ChatSignalType | None
    trusted_source_type: ChatSignalSourceType | None
    trusted_source_name: str | None
    trusted_lineage_digest: bytes
    payload: Any
    authenticator: bytes
    work_item_v1: Any = None

    def __repr__(self) -> str:
        return "AuthorizedSignalEmissionV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedSignalEmissionV1:
    emission_id: str
    envelope_ref: SecurityEnvelopeReferenceV1
    stream_ref: SecurityStreamReferenceV1 | None
    classification: SecurityClassificationV1
    trusted_signal_type: ChatSignalType | None
    trusted_source_type: ChatSignalSourceType | None
    trusted_source_name: str | None
    payload: Any

    def __repr__(self) -> str:
        return "ValidatedSignalEmissionV1(<redacted>)"

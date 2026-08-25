"""Trusted M2-backed authority for the internal private evidence service."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum

from chat_engine.security.authority import SecurityAuthorityV1
from chat_engine.security.dispatch import (
    ConsumerCapabilityV1,
    CoreRegistrarCapabilityV1,
    SecurityEnvelopeReferenceV1,
)
from chat_engine.security.ids import new_uuid7_v1

_PRIVATE_AUTHORITY_CONSTRUCTION_V1 = object()


class PrivateEvidenceAccessKindV1(str, Enum):
    WRITE = "WRITE"
    READ = "READ"
    DELETE = "DELETE"
    CLEANUP = "CLEANUP"


@dataclass(frozen=True, slots=True, repr=False)
class PrivateEvidenceAccessV1:
    """Opaque store-specific registration, never a client capability."""

    authority_id: uuid.UUID
    access_id: uuid.UUID
    kind: PrivateEvidenceAccessKindV1

    def __post_init__(self) -> None:
        for name, value in (
            ("authority_id", self.authority_id),
            ("access_id", self.access_id),
        ):
            if (
                not isinstance(value, uuid.UUID)
                or value.version != 7
                or value.variant != uuid.RFC_4122
            ):
                raise ValueError(f"{name} must be an RFC 9562 UUIDv7")
        if not isinstance(self.kind, PrivateEvidenceAccessKindV1):
            raise TypeError("kind must be PrivateEvidenceAccessKindV1")

    def __repr__(self) -> str:
        return "PrivateEvidenceAccessV1(<opaque>)"


class PrivateEvidenceAuthorityV1:
    """Compose one narrow store registration with the session's M2 authority."""

    __slots__ = (
        "_accesses",
        "_authority_id",
        "_closed",
        "_consumer_capability",
        "_security_authority",
        "_security_envelope_ref",
    )

    def __init__(
        self,
        *,
        _construction_authority_v1: object,
        security_authority: SecurityAuthorityV1,
        security_envelope_ref: SecurityEnvelopeReferenceV1,
        consumer_capability: ConsumerCapabilityV1,
    ) -> None:
        if _construction_authority_v1 is not _PRIVATE_AUTHORITY_CONSTRUCTION_V1:
            raise RuntimeError("private evidence authority construction denied")
        self._security_authority = security_authority
        self._security_envelope_ref = security_envelope_ref
        self._consumer_capability = consumer_capability
        self._authority_id = new_uuid7_v1()
        self._closed = False
        self._accesses = {
            kind: PrivateEvidenceAccessV1(
                authority_id=self._authority_id,
                access_id=new_uuid7_v1(),
                kind=kind,
            )
            for kind in PrivateEvidenceAccessKindV1
        }

    @classmethod
    def _create_for_session_v1(
        cls,
        *,
        security_authority: SecurityAuthorityV1,
        registrar: CoreRegistrarCapabilityV1,
    ) -> PrivateEvidenceAuthorityV1:
        """Register the private store before ChatSession closes M2 issuance."""

        if not isinstance(security_authority, SecurityAuthorityV1):
            raise TypeError("security_authority must be SecurityAuthorityV1")
        if not isinstance(registrar, CoreRegistrarCapabilityV1):
            raise TypeError("registrar must be CoreRegistrarCapabilityV1")
        envelope_ref = (
            security_authority._issue_certificate_private_root_v1(registrar)
        )
        consumer = (
            security_authority
            ._issue_certificate_private_consumer_capability_v1(registrar)
        )
        if envelope_ref is None or consumer is None:
            raise RuntimeError("private evidence M2 registration unavailable")
        authority = cls(
            _construction_authority_v1=_PRIVATE_AUTHORITY_CONSTRUCTION_V1,
            security_authority=security_authority,
            security_envelope_ref=envelope_ref,
            consumer_capability=consumer,
        )
        if not authority.is_usable_v1():
            authority.close_v1()
            raise RuntimeError("private evidence M2 registration unavailable")
        return authority

    def _access_for_core_v1(
        self,
        kind: PrivateEvidenceAccessKindV1,
    ) -> PrivateEvidenceAccessV1:
        if self._closed:
            raise RuntimeError("private evidence authority unavailable")
        return self._accesses[kind]

    def authorizes_v1(
        self,
        access: object,
        kind: PrivateEvidenceAccessKindV1,
        *,
        audit_denial: bool = True,
    ) -> bool:
        if (
            self._closed
            or not isinstance(kind, PrivateEvidenceAccessKindV1)
            or access is not self._accesses.get(kind)
        ):
            return False
        return self._security_authority.consumer_is_authorized_v1(
            self._security_envelope_ref,
            self._consumer_capability,
            audit_denial=audit_denial,
        )

    def _is_canonical_access_v1(
        self,
        access: object,
        kind: PrivateEvidenceAccessKindV1,
    ) -> bool:
        """Owner-cleanup identity check that survives M2 session revocation."""

        return bool(
            not self._closed
            and isinstance(kind, PrivateEvidenceAccessKindV1)
            and access is self._accesses.get(kind)
        )

    def is_usable_v1(self) -> bool:
        if self._closed or not self._security_authority.is_usable_v1():
            return False
        return self._security_authority.consumer_is_authorized_v1(
            self._security_envelope_ref,
            self._consumer_capability,
            audit_denial=False,
        )

    def close_v1(self) -> None:
        self._closed = True
        self._accesses.clear()

    def __repr__(self) -> str:
        return "PrivateEvidenceAuthorityV1(<opaque>)"


__all__ = [
    "PrivateEvidenceAccessKindV1",
    "PrivateEvidenceAccessV1",
    "PrivateEvidenceAuthorityV1",
]

"""Immutable, server-owned SecurityEnvelopeV1 contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SecurityClassificationV1(str, Enum):
    """V1 security classifications, ordered by restrictiveness in policy.py."""

    PUBLIC_CHAT = "PUBLIC_CHAT"
    CERTIFICATE_PRIVATE = "CERTIFICATE_PRIVATE"


class EgressPolicyV1(str, Enum):
    """Where an envelope may be delivered."""

    GENERIC = "GENERIC"
    OWNING_CLIENT_PRIVATE = "OWNING_CLIENT_PRIVATE"
    INTERNAL_ONLY = "INTERNAL_ONLY"


class RetentionPolicyV1(str, Enum):
    """Retention behavior attached by core policy, never by payload metadata."""

    LEGACY_SESSION = "LEGACY_SESSION"
    EPHEMERAL_NO_GENERIC_RETENTION = "EPHEMERAL_NO_GENERIC_RETENTION"


@dataclass(frozen=True, slots=True)
class TrustedLineageV1:
    """Immutable direct-parent and transitive envelope ancestry."""

    parent_envelope_ids: tuple[str, ...] = ()
    ancestor_envelope_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class SecurityEnvelopeV1:
    """Core-issued classification and egress authority.

    The corresponding authenticated reference remains inside the engine core.
    Handlers receive only an isolated payload view.
    """

    envelope_id: str
    classification: SecurityClassificationV1
    owning_session_authority_ref: str
    retention_policy: RetentionPolicyV1
    egress_policy: EgressPolicyV1
    lineage: TrustedLineageV1

    def __repr__(self) -> str:
        return (
            "SecurityEnvelopeV1("
            f"envelope_id={self.envelope_id!r}, "
            f"classification={self.classification.value!r}, "
            f"retention_policy={self.retention_policy.value!r}, "
            f"egress_policy={self.egress_policy.value!r}, "
            "owning_session_authority_ref=<opaque>, "
            "lineage=<opaque>)"
        )

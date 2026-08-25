"""Session-scoped authority registry for envelopes, streams, and consumers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import weakref
from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from chat_engine.data_models.chat_data_type import ChatDataType
from chat_engine.data_models.chat_signal_type import (
    ChatSignalSourceType,
    ChatSignalType,
)
from chat_engine.data_models.chat_stream import ChatStreamIdentity
from chat_engine.security.audit_events import (
    CoreSecurityAuditV1,
    SecurityAuditEventCodeV1,
    SecurityAuditEventV1,
)
from chat_engine.security.dispatch import (
    AuthorizedDispatchV1,
    AuthorizedSignalEmissionV1,
    ConsumerCapabilityV1,
    CoreRegistrarCapabilityV1,
    PrivateTestIssuerCapabilityV1,
    ProducerAuthorityReferenceV1,
    SecurityEnvelopeReferenceV1,
    SecurityStreamReferenceV1,
    TrustedStreamIdentityV1,
    ValidatedDispatchV1,
    ValidatedSignalEmissionV1,
)
from chat_engine.security.envelope import (
    EgressPolicyV1,
    SecurityClassificationV1,
    SecurityEnvelopeV1,
    TrustedLineageV1,
)
from chat_engine.security.policy import (
    egress_policy_for_v1,
    most_restrictive_classification_v1,
    retention_policy_for_v1,
)


class SecurityAuthorityUnavailableV1(RuntimeError):
    """Stable, payload-free internal authority failure."""


@dataclass(frozen=True, slots=True)
class _ProducerEnvelopeStateV1:
    envelope_ref: SecurityEnvelopeReferenceV1
    end_mark: float | None = None


@dataclass(frozen=True, slots=True)
class _ProducerAuthorityStateV1:
    reference: ProducerAuthorityReferenceV1
    envelope_refs: tuple[_ProducerEnvelopeStateV1, ...]


@dataclass(frozen=True, slots=True)
class _RegisteredConsumerCapabilityStateV1:
    authority_id: str
    capability_id: str
    allowed_classifications: frozenset[SecurityClassificationV1]
    allowed_egress_policies: frozenset[EgressPolicyV1]
    authenticator: bytes

    @classmethod
    def from_capability(
        cls,
        capability: ConsumerCapabilityV1,
    ) -> _RegisteredConsumerCapabilityStateV1:
        return cls(
            authority_id=capability.authority_id,
            capability_id=capability.capability_id,
            allowed_classifications=frozenset(
                capability.allowed_classifications
            ),
            allowed_egress_policies=frozenset(
                capability.allowed_egress_policies
            ),
            authenticator=bytes(capability.authenticator),
        )

    def token(self) -> ConsumerCapabilityV1:
        return ConsumerCapabilityV1(
            authority_id=self.authority_id,
            capability_id=self.capability_id,
            allowed_classifications=self.allowed_classifications,
            allowed_egress_policies=self.allowed_egress_policies,
            authenticator=self.authenticator,
        )


def _consumer_capability_state_accessors_v1():
    """Keep canonical capability grants outside handler-reachable objects."""

    stores: weakref.WeakKeyDictionary[
        SecurityAuthorityV1,
        dict[str, _RegisteredConsumerCapabilityStateV1],
    ] = weakref.WeakKeyDictionary()

    def initialize(authority: SecurityAuthorityV1) -> None:
        stores.setdefault(authority, {})

    def register(
        authority: SecurityAuthorityV1,
        capability: ConsumerCapabilityV1,
        issuance_authority: object,
    ) -> bool:
        if not (
            authority._validate_registrar_locked(issuance_authority)
            or authority._validate_private_test_issuer_locked(issuance_authority)
        ):
            return False
        store = stores.setdefault(authority, {})
        if capability.capability_id in store:
            return False
        store[capability.capability_id] = (
            _RegisteredConsumerCapabilityStateV1.from_capability(capability)
        )
        return True

    def get(
        authority: SecurityAuthorityV1,
        capability_id: str,
    ) -> ConsumerCapabilityV1 | None:
        state = stores.get(authority, {}).get(capability_id)
        return state.token() if state is not None else None

    def clear(authority: SecurityAuthorityV1) -> None:
        stores.pop(authority, None)

    return initialize, register, get, clear


(
    _initialize_consumer_capability_state_v1,
    _register_consumer_capability_v1,
    _get_registered_consumer_capability_v1,
    _clear_consumer_capability_state_v1,
) = _consumer_capability_state_accessors_v1()


def _authority_mac_key_accessors_v1():
    """Keep session signing keys outside handler-reachable authority fields."""

    keys: weakref.WeakKeyDictionary[
        SecurityAuthorityV1,
        bytes,
    ] = weakref.WeakKeyDictionary()

    def initialize(authority: SecurityAuthorityV1) -> None:
        keys.setdefault(authority, secrets.token_bytes(32))

    def sign(authority: SecurityAuthorityV1, message: bytes) -> bytes:
        key = keys.get(authority)
        if key is None:
            raise SecurityAuthorityUnavailableV1(
                "security authority unavailable"
            )
        return hmac.new(key, message, hashlib.sha256).digest()

    def rotate(authority: SecurityAuthorityV1) -> None:
        if authority in keys:
            keys[authority] = secrets.token_bytes(32)

    return initialize, sign, rotate


(
    _initialize_authority_mac_key_v1,
    _sign_authority_message_v1,
    _rotate_authority_mac_key_v1,
) = _authority_mac_key_accessors_v1()


def _authority_registration_accessors_v1():
    """Keep construction authority monotonic and outside instance mutation."""

    states: weakref.WeakKeyDictionary[
        SecurityAuthorityV1,
        dict[str, object],
    ] = weakref.WeakKeyDictionary()

    def initialize(
        authority: SecurityAuthorityV1,
        *,
        test_mode: bool,
    ) -> None:
        if authority in states:
            return
        states[authority] = {
            "registrar_id": _opaque_id_v1("crv1_"),
            "registration_open": True,
            "test_issuer_id": (
                _opaque_id_v1("ptiv1_")
                if test_mode
                else None
            ),
            "test_issuer_exported": False,
        }

    def registrar_token(
        authority: SecurityAuthorityV1,
    ) -> CoreRegistrarCapabilityV1:
        state = states[authority]
        registrar_id = str(state["registrar_id"])
        authority_id = authority.authority_id
        return CoreRegistrarCapabilityV1(
            authority_id=authority_id,
            registrar_id=registrar_id,
            authenticator=authority._mac(
                b"core-registrar-v1",
                authority_id,
                registrar_id,
            ),
        )

    def validate_registrar(
        authority: SecurityAuthorityV1,
        registrar: object,
    ) -> bool:
        state = states.get(authority)
        if (
            state is None
            or not state["registration_open"]
            or not isinstance(registrar, CoreRegistrarCapabilityV1)
        ):
            return False
        authority_id = authority.authority_id
        registrar_id = str(state["registrar_id"])
        if (
            registrar.authority_id != authority_id
            or registrar.registrar_id != registrar_id
        ):
            return False
        return hmac.compare_digest(
            registrar.authenticator,
            authority._mac(
                b"core-registrar-v1",
                authority_id,
                registrar_id,
            ),
        )

    def close_registration(authority: SecurityAuthorityV1) -> None:
        state = states.get(authority)
        if state is None:
            return
        state["registration_open"] = False
        state["registrar_id"] = _opaque_id_v1("closed_crv1_")

    def test_issuer_token(
        authority: SecurityAuthorityV1,
    ) -> PrivateTestIssuerCapabilityV1 | None:
        state = states.get(authority)
        issuer_id = state.get("test_issuer_id") if state is not None else None
        if (
            not isinstance(issuer_id, str)
            or bool(state["test_issuer_exported"])
        ):
            return None
        state["test_issuer_exported"] = True
        authority_id = authority.authority_id
        return PrivateTestIssuerCapabilityV1(
            authority_id=authority_id,
            issuer_id=issuer_id,
            authenticator=authority._mac(
                b"private-test-issuer-v1",
                authority_id,
                issuer_id,
            ),
        )

    def validate_test_issuer(
        authority: SecurityAuthorityV1,
        issuer: object,
    ) -> bool:
        state = states.get(authority)
        registered_id = (
            state.get("test_issuer_id")
            if state is not None
            else None
        )
        if (
            not isinstance(registered_id, str)
            or not isinstance(issuer, PrivateTestIssuerCapabilityV1)
            or issuer.authority_id != authority.authority_id
            or issuer.issuer_id != registered_id
        ):
            return False
        return hmac.compare_digest(
            issuer.authenticator,
            authority._mac(
                b"private-test-issuer-v1",
                issuer.authority_id,
                issuer.issuer_id,
            ),
        )

    def revoke(authority: SecurityAuthorityV1) -> None:
        state = states.get(authority)
        if state is None:
            return
        state["registration_open"] = False
        state["registrar_id"] = _opaque_id_v1("closed_crv1_")
        state["test_issuer_id"] = None

    return (
        initialize,
        registrar_token,
        validate_registrar,
        close_registration,
        test_issuer_token,
        validate_test_issuer,
        revoke,
    )


(
    _initialize_authority_registration_v1,
    _authority_registrar_token_v1,
    _validate_authority_registrar_v1,
    _close_authority_registration_v1,
    _authority_test_issuer_token_v1,
    _validate_authority_test_issuer_v1,
    _revoke_authority_registration_v1,
) = _authority_registration_accessors_v1()


def _producer_state_accessors_v1():
    """Expose only monotonic producer-lineage transitions."""

    stores: weakref.WeakKeyDictionary[
        SecurityAuthorityV1,
        dict[str, _ProducerAuthorityStateV1],
    ] = weakref.WeakKeyDictionary()

    def initialize(authority: SecurityAuthorityV1) -> None:
        stores.setdefault(authority, {})

    def get(
        authority: SecurityAuthorityV1,
        producer_authority_id: str,
    ) -> _ProducerAuthorityStateV1 | None:
        return stores.get(authority, {}).get(producer_authority_id)

    def register(
        authority: SecurityAuthorityV1,
        reference: ProducerAuthorityReferenceV1,
        issuance_authority: object,
    ) -> bool:
        if not (
            authority._validate_registrar_locked(issuance_authority)
            or authority._validate_private_test_issuer_locked(issuance_authority)
        ):
            return False
        store = stores.setdefault(authority, {})
        if reference.producer_authority_id in store:
            return False
        store[reference.producer_authority_id] = _ProducerAuthorityStateV1(
            reference=reference,
            envelope_refs=(),
        )
        return True

    def append_envelope(
        authority: SecurityAuthorityV1,
        reference: ProducerAuthorityReferenceV1,
        envelope_state: _ProducerEnvelopeStateV1,
    ) -> bool:
        store = stores.get(authority)
        if store is None:
            return False
        state = store.get(reference.producer_authority_id)
        if state is None or state.reference != reference:
            return False
        states = list(state.envelope_refs)
        for index, existing in enumerate(states):
            if (
                existing.envelope_ref.envelope_id
                == envelope_state.envelope_ref.envelope_id
            ):
                states[index] = replace(
                    existing,
                    end_mark=(envelope_state.end_mark or existing.end_mark),
                )
                break
        else:
            states.append(envelope_state)
        store[reference.producer_authority_id] = replace(
            state,
            envelope_refs=tuple(states),
        )
        return True

    def clear(authority: SecurityAuthorityV1) -> None:
        stores.pop(authority, None)

    return initialize, get, register, append_envelope, clear


(
    _initialize_producer_state_v1,
    _get_producer_state_v1,
    _register_producer_state_v1,
    _append_producer_envelope_v1,
    _clear_producer_state_v1,
) = _producer_state_accessors_v1()


def _opaque_id_v1(prefix: str) -> str:
    return f"{prefix}{secrets.token_urlsafe(18)}"


def _part_bytes_v1(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, Enum):
        return str(value.value).encode("utf-8")
    return str(value).encode("utf-8")


class SecurityAuthorityV1:
    """Core-owned registry and policy enforcement for one secure chat session.

    References are authenticated with a session-local key and checked against
    registry state. Python object identity is never the sole authorization
    primitive.
    """

    def __init__(self, *, _test_mode_v1: bool = False):
        self._authority_id = _opaque_id_v1("saa1_")
        self._owning_session_authority_ref = _opaque_id_v1("sar1_")
        self._lock = threading.RLock()
        self._closed = False
        self._failed = False
        self._envelopes: dict[str, SecurityEnvelopeV1] = {}
        self._envelope_refs: dict[str, SecurityEnvelopeReferenceV1] = {}
        self._stream_refs: dict[str, SecurityStreamReferenceV1] = {}
        self._audit = CoreSecurityAuditV1()
        _initialize_authority_mac_key_v1(self)
        _initialize_authority_registration_v1(
            self,
            test_mode=_test_mode_v1,
        )
        _initialize_consumer_capability_state_v1(self)
        _initialize_producer_state_v1(self)

    @classmethod
    def create_v1(
        cls,
    ) -> tuple[SecurityAuthorityV1, CoreRegistrarCapabilityV1]:
        """Construct a production registry and core-only registrar."""

        authority = cls()
        return authority, authority._new_registrar_v1()

    @classmethod
    def _create_for_test_v1(
        cls,
    ) -> tuple[
        SecurityAuthorityV1,
        CoreRegistrarCapabilityV1,
        PrivateTestIssuerCapabilityV1,
    ]:
        """Test-only bootstrap; callers must keep the issuer outside sessions."""

        authority = cls(_test_mode_v1=True)
        issuer = _authority_test_issuer_token_v1(authority)
        if issuer is None:
            raise RuntimeError("private test issuer unavailable")
        return authority, authority._new_registrar_v1(), issuer

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def _mac(self, label: bytes, *parts: object) -> bytes:
        message = bytearray(label)
        for part in parts:
            encoded = _part_bytes_v1(part)
            message.extend(len(encoded).to_bytes(8, "big"))
            message.extend(encoded)
        return _sign_authority_message_v1(self, bytes(message))

    def _new_registrar_v1(self) -> CoreRegistrarCapabilityV1:
        return _authority_registrar_token_v1(self)

    def _validate_registrar_locked(
        self,
        registrar: object,
    ) -> bool:
        return _validate_authority_registrar_v1(self, registrar)

    def close_registration_v1(
        self,
        registrar: CoreRegistrarCapabilityV1,
    ) -> bool:
        """Irreversibly revoke construction-time issuance authority."""

        with self._lock:
            if self._closed or self._failed:
                _close_authority_registration_v1(self)
                self._record(SecurityAuditEventCodeV1.REGISTRY_FAILURE)
                return True
            if not self._validate_registrar_locked(registrar):
                self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                return False
            _close_authority_registration_v1(self)
            return True

    def _ensure_available_locked(self) -> None:
        if self._closed or self._failed:
            raise SecurityAuthorityUnavailableV1("security authority unavailable")

    def _record(
        self,
        code: SecurityAuditEventCodeV1,
        *,
        envelope_id: str | None = None,
        consumer_capability_id: str | None = None,
        dispatch_id: str | None = None,
    ) -> None:
        self._audit.record(
            code,
            envelope_id=envelope_id,
            consumer_capability_id=consumer_capability_id,
            dispatch_id=dispatch_id,
        )

    def audit_registry_failure_v1(self) -> None:
        self._record(SecurityAuditEventCodeV1.REGISTRY_FAILURE)

    def audit_events_v1(self) -> tuple[SecurityAuditEventV1, ...]:
        return self._audit.snapshot()

    def is_usable_v1(self) -> bool:
        """Return only whether this session-local M2 authority remains live."""

        with self._lock:
            return not self._closed and not self._failed

    def close(self) -> None:
        with self._lock:
            self._closed = True
            _revoke_authority_registration_v1(self)
            _rotate_authority_mac_key_v1(self)
            self._envelopes.clear()
            self._envelope_refs.clear()
            _clear_consumer_capability_state_v1(self)
            _clear_producer_state_v1(self)
            self._stream_refs.clear()

    # ------------------------------------------------------------------
    # Envelope issuance and immutable lineage
    # ------------------------------------------------------------------

    def _lineage_digest(self, envelope: SecurityEnvelopeV1) -> bytes:
        digest = hashlib.sha256()
        digest.update(envelope.envelope_id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(envelope.classification.value.encode("ascii"))
        for parent_id in envelope.lineage.parent_envelope_ids:
            digest.update(b"\1")
            digest.update(parent_id.encode("utf-8"))
        for ancestor_id in envelope.lineage.ancestor_envelope_ids:
            digest.update(b"\2")
            digest.update(ancestor_id.encode("utf-8"))
        return digest.digest()

    def _new_envelope_locked(
        self,
        classification: SecurityClassificationV1,
        parent_envelopes: tuple[SecurityEnvelopeV1, ...],
        *,
        root_authority: object = None,
        private_core_root: bool = False,
    ) -> SecurityEnvelopeReferenceV1 | None:
        if parent_envelopes:
            classification = most_restrictive_classification_v1(
                parent.classification for parent in parent_envelopes
            )
        else:
            root_allowed = (
                self._validate_registrar_locked(root_authority)
                and (
                    classification is SecurityClassificationV1.PUBLIC_CHAT
                    or (
                        private_core_root
                        and classification
                        is SecurityClassificationV1.CERTIFICATE_PRIVATE
                    )
                )
            ) or self._validate_private_test_issuer_locked(root_authority)
            if not root_allowed and isinstance(
                root_authority,
                ProducerAuthorityReferenceV1,
            ):
                producer_state = self._validate_producer_authority_locked(
                    root_authority
                )
                root_allowed = (
                    producer_state is not None
                    and not producer_state.envelope_refs
                    and classification is SecurityClassificationV1.PUBLIC_CHAT
                )
            if not root_allowed:
                self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                return None
        envelope_id = _opaque_id_v1("sev1_")
        parent_ids: list[str] = []
        ancestor_ids: list[str] = []
        seen_parents: set[str] = set()
        seen_ancestors: set[str] = set()

        for parent in parent_envelopes:
            if parent.envelope_id not in seen_parents:
                seen_parents.add(parent.envelope_id)
                parent_ids.append(parent.envelope_id)
            if parent.envelope_id not in seen_ancestors:
                seen_ancestors.add(parent.envelope_id)
                ancestor_ids.append(parent.envelope_id)
            for ancestor_id in parent.lineage.ancestor_envelope_ids:
                if ancestor_id not in seen_ancestors:
                    seen_ancestors.add(ancestor_id)
                    ancestor_ids.append(ancestor_id)

        envelope = SecurityEnvelopeV1(
            envelope_id=envelope_id,
            classification=classification,
            owning_session_authority_ref=self._owning_session_authority_ref,
            retention_policy=retention_policy_for_v1(classification),
            egress_policy=egress_policy_for_v1(classification),
            lineage=TrustedLineageV1(
                parent_envelope_ids=tuple(parent_ids),
                ancestor_envelope_ids=tuple(ancestor_ids),
            ),
        )
        envelope_ref = SecurityEnvelopeReferenceV1(
            authority_id=self._authority_id,
            envelope_id=envelope_id,
            authenticator=self._mac(
                b"envelope-reference-v1",
                self._authority_id,
                envelope_id,
                envelope.classification,
                envelope.egress_policy,
                self._lineage_digest(envelope),
            ),
        )
        self._envelopes[envelope_id] = envelope
        self._envelope_refs[envelope_id] = envelope_ref
        return envelope_ref

    def _issue_public_root_v1(
        self,
        registrar: CoreRegistrarCapabilityV1,
    ) -> SecurityEnvelopeReferenceV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_registrar_locked(registrar):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                return self._new_envelope_locked(
                    SecurityClassificationV1.PUBLIC_CHAT,
                    (),
                    root_authority=registrar,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _issue_public_root_for_test_v1(
        self,
        issuer: PrivateTestIssuerCapabilityV1,
    ) -> SecurityEnvelopeReferenceV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_private_test_issuer_locked(issuer):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                return self._new_envelope_locked(
                    SecurityClassificationV1.PUBLIC_CHAT,
                    (),
                    root_authority=issuer,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _validate_private_test_issuer_locked(
        self,
        issuer: object,
    ) -> bool:
        return _validate_authority_test_issuer_v1(self, issuer)

    def _issue_private_root_for_test_v1(
        self,
        issuer: PrivateTestIssuerCapabilityV1,
    ) -> SecurityEnvelopeReferenceV1 | None:
        """Trusted test seam. ChatSession does not expose this to handlers."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_private_test_issuer_locked(issuer):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                return self._new_envelope_locked(
                    SecurityClassificationV1.CERTIFICATE_PRIVATE,
                    (),
                    root_authority=issuer,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _issue_certificate_private_root_v1(
        self,
        registrar: CoreRegistrarCapabilityV1,
    ) -> SecurityEnvelopeReferenceV1 | None:
        """Issue the core-only root used by the private evidence service.

        This construction-time seam is intentionally separate from generic
        producer and stream registration. It is consumed only before the
        session registrar is irreversibly closed.
        """

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_registrar_locked(registrar):
                    self._record(
                        SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
                    )
                    return None
                return self._new_envelope_locked(
                    SecurityClassificationV1.CERTIFICATE_PRIVATE,
                    (),
                    root_authority=registrar,
                    private_core_root=True,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def derive_envelope_v1(
        self,
        parent_refs: Iterable[SecurityEnvelopeReferenceV1],
        *,
        requested_classification: SecurityClassificationV1 | None = None,
    ) -> SecurityEnvelopeReferenceV1 | None:
        """Derive immutable authority from trusted parents without declassification."""

        try:
            with self._lock:
                self._ensure_available_locked()
                parent_envelopes: list[SecurityEnvelopeV1] = []
                seen_ids: set[str] = set()
                for parent_ref in parent_refs:
                    parent = self._validate_envelope_ref_locked(parent_ref)
                    if parent is None:
                        self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                        return None
                    if parent.envelope_id not in seen_ids:
                        seen_ids.add(parent.envelope_id)
                        parent_envelopes.append(parent)

                inherited = most_restrictive_classification_v1(
                    parent.classification for parent in parent_envelopes
                )
                classification = inherited
                if requested_classification is not None:
                    if (
                        requested_classification is SecurityClassificationV1.PUBLIC_CHAT
                        and inherited is SecurityClassificationV1.CERTIFICATE_PRIVATE
                    ):
                        self._record(
                            SecurityAuditEventCodeV1.ILLEGAL_CLASSIFICATION_DOWNGRADE,
                            envelope_id=parent_envelopes[0].envelope_id,
                        )
                    elif (
                        requested_classification
                        is SecurityClassificationV1.CERTIFICATE_PRIVATE
                        and inherited is SecurityClassificationV1.PUBLIC_CHAT
                    ):
                        # Only the dedicated private-root test seam may originate
                        # private authority. Ordinary derivation cannot upgrade a
                        # public or empty lineage based on a caller request.
                        self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                        return None
                    else:
                        classification = requested_classification

                return self._new_envelope_locked(
                    classification,
                    tuple(parent_envelopes),
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def envelope_v1(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> SecurityEnvelopeV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                return self._validate_envelope_ref_locked(envelope_ref)
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _validate_envelope_ref_locked(
        self,
        envelope_ref: object,
    ) -> SecurityEnvelopeV1 | None:
        if not isinstance(envelope_ref, SecurityEnvelopeReferenceV1):
            return None
        if envelope_ref.authority_id != self._authority_id:
            return None
        envelope = self._envelopes.get(envelope_ref.envelope_id)
        registered_ref = self._envelope_refs.get(envelope_ref.envelope_id)
        if envelope is None or registered_ref is None:
            return None
        expected = self._mac(
            b"envelope-reference-v1",
            self._authority_id,
            envelope.envelope_id,
            envelope.classification,
            envelope.egress_policy,
            self._lineage_digest(envelope),
        )
        if not hmac.compare_digest(expected, envelope_ref.authenticator):
            return None
        if not hmac.compare_digest(
            registered_ref.authenticator,
            envelope_ref.authenticator,
        ):
            return None
        return envelope

    def envelope_covers_parents_v1(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1,
        parent_refs: Iterable[SecurityEnvelopeReferenceV1],
    ) -> bool:
        try:
            with self._lock:
                self._ensure_available_locked()
                envelope = self._validate_envelope_ref_locked(envelope_ref)
                if envelope is None:
                    return False
                covered_ids = {
                    envelope.envelope_id,
                    *envelope.lineage.ancestor_envelope_ids,
                }
                for parent_ref in parent_refs:
                    parent = self._validate_envelope_ref_locked(parent_ref)
                    if parent is None or parent.envelope_id not in covered_ids:
                        return False
                return True
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False

    # ------------------------------------------------------------------
    # Consumer capabilities
    # ------------------------------------------------------------------

    def _issue_capability_locked(
        self,
        *,
        classifications: frozenset[SecurityClassificationV1],
        egress_policies: frozenset[EgressPolicyV1],
        issuance_authority: object,
    ) -> ConsumerCapabilityV1 | None:
        if not (
            self._validate_registrar_locked(issuance_authority)
            or self._validate_private_test_issuer_locked(issuance_authority)
        ):
            self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
            return None
        capability_id = _opaque_id_v1("ccv1_")
        capability = ConsumerCapabilityV1(
            authority_id=self._authority_id,
            capability_id=capability_id,
            allowed_classifications=classifications,
            allowed_egress_policies=egress_policies,
            authenticator=b"",
        )
        authenticator = self._mac(
            b"consumer-capability-v1",
            capability.authority_id,
            capability.capability_id,
            ",".join(sorted(item.value for item in classifications)),
            ",".join(sorted(item.value for item in egress_policies)),
        )
        capability = replace(capability, authenticator=authenticator)
        if not _register_consumer_capability_v1(
            self,
            capability,
            issuance_authority,
        ):
            self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
            return None
        return capability

    def _issue_public_consumer_capability_v1(
        self,
        registrar: CoreRegistrarCapabilityV1,
    ) -> ConsumerCapabilityV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_registrar_locked(registrar):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                return self._issue_capability_locked(
                    classifications=frozenset({SecurityClassificationV1.PUBLIC_CHAT}),
                    egress_policies=frozenset({EgressPolicyV1.GENERIC}),
                    issuance_authority=registrar,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _issue_private_test_consumer_capability_v1(
        self,
        issuer: PrivateTestIssuerCapabilityV1,
    ) -> ConsumerCapabilityV1 | None:
        """Trusted test seam for broad synthetic private-flow coverage."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_private_test_issuer_locked(issuer):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                return self._issue_capability_locked(
                    classifications=frozenset(
                        {
                            SecurityClassificationV1.PUBLIC_CHAT,
                            SecurityClassificationV1.CERTIFICATE_PRIVATE,
                        }
                    ),
                    egress_policies=frozenset(
                        {
                            EgressPolicyV1.GENERIC,
                            EgressPolicyV1.INTERNAL_ONLY,
                        }
                    ),
                    issuance_authority=issuer,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _issue_certificate_private_consumer_capability_v1(
        self,
        registrar: CoreRegistrarCapabilityV1,
    ) -> ConsumerCapabilityV1 | None:
        """Issue the narrow internal-only private evidence-store grant."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_registrar_locked(registrar):
                    self._record(
                        SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED
                    )
                    return None
                return self._issue_capability_locked(
                    classifications=frozenset(
                        {SecurityClassificationV1.CERTIFICATE_PRIVATE}
                    ),
                    egress_policies=frozenset(
                        {EgressPolicyV1.INTERNAL_ONLY}
                    ),
                    issuance_authority=registrar,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _issue_public_test_consumer_capability_v1(
        self,
        issuer: PrivateTestIssuerCapabilityV1,
    ) -> ConsumerCapabilityV1 | None:
        """Test-only public consumer capability."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_private_test_issuer_locked(issuer):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                return self._issue_capability_locked(
                    classifications=frozenset({SecurityClassificationV1.PUBLIC_CHAT}),
                    egress_policies=frozenset({EgressPolicyV1.GENERIC}),
                    issuance_authority=issuer,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _validate_capability_locked(
        self,
        capability: object,
    ) -> ConsumerCapabilityV1 | None:
        if not isinstance(capability, ConsumerCapabilityV1):
            return None
        if capability.authority_id != self._authority_id:
            return None
        registered = _get_registered_consumer_capability_v1(
            self,
            capability.capability_id,
        )
        if registered is None:
            return None
        expected = self._mac(
            b"consumer-capability-v1",
            capability.authority_id,
            capability.capability_id,
            ",".join(sorted(item.value for item in capability.allowed_classifications)),
            ",".join(sorted(item.value for item in capability.allowed_egress_policies)),
        )
        if not hmac.compare_digest(expected, capability.authenticator):
            return None
        if not hmac.compare_digest(
            registered.authenticator,
            capability.authenticator,
        ):
            return None
        if (
            registered.allowed_classifications != capability.allowed_classifications
            or registered.allowed_egress_policies != capability.allowed_egress_policies
        ):
            return None
        return registered

    def consumer_is_authorized_v1(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1,
        capability: ConsumerCapabilityV1,
        *,
        audit_denial: bool = True,
    ) -> bool:
        try:
            with self._lock:
                self._ensure_available_locked()
                envelope = self._validate_envelope_ref_locked(envelope_ref)
                registered = self._validate_capability_locked(capability)
                if envelope is None:
                    if audit_denial:
                        self._record(SecurityAuditEventCodeV1.ENVELOPE_MISSING)
                    return False
                if registered is None:
                    if audit_denial:
                        self._record(
                            SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                            envelope_id=envelope.envelope_id,
                        )
                    return False
                if envelope.classification not in registered.allowed_classifications:
                    if audit_denial:
                        self._record(
                            SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                            envelope_id=envelope.envelope_id,
                            consumer_capability_id=registered.capability_id,
                        )
                    return False
                if envelope.egress_policy not in registered.allowed_egress_policies:
                    if audit_denial:
                        self._record(
                            SecurityAuditEventCodeV1.PRIVATE_EGRESS_DENIED,
                            envelope_id=envelope.envelope_id,
                            consumer_capability_id=registered.capability_id,
                        )
                    return False
                return True
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False

    # ------------------------------------------------------------------
    # Core-owned producer authority and active trusted lineage
    # ------------------------------------------------------------------

    def _issue_producer_authority_v1(
        self,
        registrar: CoreRegistrarCapabilityV1,
        consumer_capability: ConsumerCapabilityV1,
    ) -> ProducerAuthorityReferenceV1 | None:
        """Bind one producer to an already core-issued consumer capability."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_registrar_locked(registrar):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                capability = self._validate_capability_locked(consumer_capability)
                if capability is None:
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                producer_authority_id = _opaque_id_v1("pav1_")
                reference = ProducerAuthorityReferenceV1(
                    authority_id=self._authority_id,
                    producer_authority_id=producer_authority_id,
                    consumer_capability_id=capability.capability_id,
                    authenticator=self._mac(
                        b"producer-authority-reference-v1",
                        self._authority_id,
                        producer_authority_id,
                        capability.capability_id,
                    ),
                )
                if not _register_producer_state_v1(
                    self,
                    reference,
                    registrar,
                ):
                    self._record(SecurityAuditEventCodeV1.REGISTRY_FAILURE)
                    return None
                return reference
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _validate_producer_authority_locked(
        self,
        producer_ref: object,
    ) -> _ProducerAuthorityStateV1 | None:
        if not isinstance(producer_ref, ProducerAuthorityReferenceV1):
            return None
        if producer_ref.authority_id != self._authority_id:
            return None
        state = _get_producer_state_v1(
            self,
            producer_ref.producer_authority_id,
        )
        if state is None:
            return None
        expected = self._mac(
            b"producer-authority-reference-v1",
            producer_ref.authority_id,
            producer_ref.producer_authority_id,
            producer_ref.consumer_capability_id,
        )
        if not hmac.compare_digest(expected, producer_ref.authenticator):
            return None
        registered = state.reference
        if (
            registered.consumer_capability_id != producer_ref.consumer_capability_id
            or not hmac.compare_digest(
                registered.authenticator,
                producer_ref.authenticator,
            )
        ):
            return None
        return state

    def producer_authority_is_valid_v1(
        self,
        producer_ref: ProducerAuthorityReferenceV1,
    ) -> bool:
        try:
            with self._lock:
                self._ensure_available_locked()
                return (
                    self._validate_producer_authority_locked(producer_ref) is not None
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False

    def producer_can_access_envelope_v1(
        self,
        producer_ref: ProducerAuthorityReferenceV1,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> bool:
        """Authorize a producer-bound inspection of trusted stream state."""

        try:
            with self._lock:
                self._ensure_available_locked()
                producer_state = self._validate_producer_authority_locked(producer_ref)
                if producer_state is None:
                    return False
                capability = _get_registered_consumer_capability_v1(
                    self,
                    producer_state.reference.consumer_capability_id
                )
                if capability is None:
                    return False
                return self.consumer_is_authorized_v1(
                    envelope_ref,
                    capability,
                    audit_denial=False,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False

    def record_dispatch_for_producer_v1(
        self,
        producer_ref: ProducerAuthorityReferenceV1,
        expected_capability: ConsumerCapabilityV1,
        validated_dispatch: ValidatedDispatchV1,
    ) -> bool:
        """Record validated input ancestry in registry-owned producer state."""

        try:
            with self._lock:
                self._ensure_available_locked()
                producer_state = self._validate_producer_authority_locked(producer_ref)
                capability = self._validate_capability_locked(expected_capability)
                envelope = self._validate_envelope_ref_locked(
                    validated_dispatch.envelope_ref
                )
                validated_stream = self._validate_stream_ref_locked(
                    validated_dispatch.stream_ref
                )
                if (
                    producer_state is None
                    or capability is None
                    or envelope is None
                    or validated_stream is None
                    or producer_state.reference.consumer_capability_id
                    != capability.capability_id
                    or validated_stream[1].envelope_id != envelope.envelope_id
                ):
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        dispatch_id=validated_dispatch.dispatch_id,
                    )
                    return False
                payload = validated_dispatch.payload
                end_mark = (
                    time.monotonic()
                    if bool(getattr(payload, "is_last_data", False))
                    else None
                )
                if not _append_producer_envelope_v1(
                    self,
                    producer_ref,
                    _ProducerEnvelopeStateV1(
                        envelope_ref=validated_dispatch.envelope_ref,
                        end_mark=end_mark,
                    ),
                ):
                    self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                    return False
                return True
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False
        except Exception:  # noqa: BLE001 - fail closed without payload repr
            self.audit_registry_failure_v1()
            return False

    def record_signal_for_producer_v1(
        self,
        producer_ref: ProducerAuthorityReferenceV1,
        expected_capability: ConsumerCapabilityV1,
        envelope_ref: SecurityEnvelopeReferenceV1,
        *,
        dispatch_id: str,
    ) -> bool:
        """Attach trusted signal ancestry before invoking a handler callback."""

        try:
            with self._lock:
                self._ensure_available_locked()
                producer_state = self._validate_producer_authority_locked(producer_ref)
                capability = self._validate_capability_locked(expected_capability)
                envelope = self._validate_envelope_ref_locked(envelope_ref)
                if (
                    producer_state is None
                    or capability is None
                    or envelope is None
                    or producer_state.reference.consumer_capability_id
                    != capability.capability_id
                ):
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        dispatch_id=dispatch_id,
                    )
                    return False
                if not _append_producer_envelope_v1(
                    self,
                    producer_ref,
                    _ProducerEnvelopeStateV1(envelope_ref=envelope_ref),
                ):
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        dispatch_id=dispatch_id,
                    )
                    return False
                return True
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False

    def producer_parent_refs_v1(
        self,
        producer_ref: ProducerAuthorityReferenceV1,
    ) -> tuple[SecurityEnvelopeReferenceV1, ...] | None:
        """Resolve active parents from core-owned state.

        Ancestry is intentionally sticky for V1 because no declassification
        API exists. Functional stream timing remains separate legacy state.
        """

        try:
            with self._lock:
                self._ensure_available_locked()
                producer_state = self._validate_producer_authority_locked(producer_ref)
                if producer_state is None:
                    self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                    return None
                refs: list[SecurityEnvelopeReferenceV1] = []
                for state in producer_state.envelope_refs:
                    envelope_id = state.envelope_ref.envelope_id
                    envelope = self._validate_envelope_ref_locked(state.envelope_ref)
                    if envelope is None:
                        self._record(
                            SecurityAuditEventCodeV1.INVALID_LINEAGE,
                            envelope_id=envelope_id,
                        )
                        return None
                    refs.append(state.envelope_ref)
                return tuple(refs)
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def envelope_for_producer_v1(
        self,
        producer_ref: ProducerAuthorityReferenceV1,
        additional_parent_refs: Iterable[SecurityEnvelopeReferenceV1] = (),
    ) -> SecurityEnvelopeReferenceV1 | None:
        """Create output authority from registry-owned producer ancestry."""

        try:
            with self._lock:
                self._ensure_available_locked()
                producer_state = self._validate_producer_authority_locked(producer_ref)
                if producer_state is None:
                    self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                    return None
                parent_envelopes: list[SecurityEnvelopeV1] = []
                seen: set[str] = set()
                refs = [state.envelope_ref for state in producer_state.envelope_refs]
                refs.extend(additional_parent_refs)
                for envelope_ref in refs:
                    envelope = self._validate_envelope_ref_locked(envelope_ref)
                    if envelope is None:
                        self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                        return None
                    if envelope.envelope_id in seen:
                        continue
                    seen.add(envelope.envelope_id)
                    parent_envelopes.append(envelope)
                if not parent_envelopes:
                    return self._new_envelope_locked(
                        SecurityClassificationV1.PUBLIC_CHAT,
                        (),
                        root_authority=producer_ref,
                    )
                classification = most_restrictive_classification_v1(
                    envelope.classification for envelope in parent_envelopes
                )
                return self._new_envelope_locked(
                    classification,
                    tuple(parent_envelopes),
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def history_writer_is_authorized_v1(self, writer_ref: object) -> bool:
        """Allow generic history only to public-only core/producer authority."""

        try:
            with self._lock:
                self._ensure_available_locked()
                producer_state = self._validate_producer_authority_locked(writer_ref)
                if producer_state is None:
                    return False
                capability = _get_registered_consumer_capability_v1(
                    self,
                    producer_state.reference.consumer_capability_id
                )
                return (
                    capability is not None
                    and SecurityClassificationV1.CERTIFICATE_PRIVATE
                    not in capability.allowed_classifications
                    and EgressPolicyV1.GENERIC in capability.allowed_egress_policies
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return False

    def _issue_test_producer_authority_v1(
        self,
        issuer: PrivateTestIssuerCapabilityV1,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> ProducerAuthorityReferenceV1 | None:
        """Test-only producer seeded with one trusted synthetic root."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not self._validate_private_test_issuer_locked(issuer):
                    self._record(SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED)
                    return None
                envelope = self._validate_envelope_ref_locked(envelope_ref)
                if envelope is None:
                    self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                    return None
                capability = self._issue_capability_locked(
                    classifications=frozenset(
                        {
                            SecurityClassificationV1.PUBLIC_CHAT,
                            SecurityClassificationV1.CERTIFICATE_PRIVATE,
                        }
                    ),
                    egress_policies=frozenset(
                        {
                            EgressPolicyV1.GENERIC,
                            EgressPolicyV1.INTERNAL_ONLY,
                        }
                    ),
                    issuance_authority=issuer,
                )
                if capability is None:
                    return None
                producer_authority_id = _opaque_id_v1("pav1_")
                producer_ref = ProducerAuthorityReferenceV1(
                    authority_id=self._authority_id,
                    producer_authority_id=producer_authority_id,
                    consumer_capability_id=capability.capability_id,
                    authenticator=self._mac(
                        b"producer-authority-reference-v1",
                        self._authority_id,
                        producer_authority_id,
                        capability.capability_id,
                    ),
                )
                if not _register_producer_state_v1(
                    self,
                    producer_ref,
                    issuer,
                ):
                    return None
                if not _append_producer_envelope_v1(
                    self,
                    producer_ref,
                    _ProducerEnvelopeStateV1(envelope_ref=envelope_ref),
                ):
                    return None
                producer_state = self._validate_producer_authority_locked(producer_ref)
                if producer_state is None:
                    return None
                return producer_ref
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    # ------------------------------------------------------------------
    # Trusted stream binding
    # ------------------------------------------------------------------

    @staticmethod
    def _trusted_identity_v1(
        identity: ChatStreamIdentity,
    ) -> TrustedStreamIdentityV1:
        return TrustedStreamIdentityV1(
            data_type=identity.data_type,
            builder_id=identity.builder_id,
            stream_id=identity.stream_id,
            name=identity.name,
            producer_name=identity.producer_name,
        )

    def bind_stream_v1(
        self,
        identity: ChatStreamIdentity,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> SecurityStreamReferenceV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                envelope = self._validate_envelope_ref_locked(envelope_ref)
                if envelope is None or identity.key is None:
                    self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                    return None
                stream_authority_id = _opaque_id_v1("ssv1_")
                trusted_identity = self._trusted_identity_v1(identity)
                stream_ref = SecurityStreamReferenceV1(
                    authority_id=self._authority_id,
                    stream_authority_id=stream_authority_id,
                    envelope_ref=envelope_ref,
                    identity=trusted_identity,
                    authenticator=self._mac(
                        b"stream-reference-v1",
                        self._authority_id,
                        stream_authority_id,
                        envelope.envelope_id,
                        trusted_identity.data_type,
                        trusted_identity.builder_id,
                        trusted_identity.stream_id,
                        trusted_identity.name,
                        trusted_identity.producer_name,
                    ),
                )
                self._stream_refs[stream_authority_id] = stream_ref
                return stream_ref
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def _validate_stream_ref_locked(
        self,
        stream_ref: object,
    ) -> tuple[SecurityStreamReferenceV1, SecurityEnvelopeV1] | None:
        if not isinstance(stream_ref, SecurityStreamReferenceV1):
            return None
        if stream_ref.authority_id != self._authority_id:
            return None
        registered = self._stream_refs.get(stream_ref.stream_authority_id)
        if registered is None:
            return None
        envelope = self._validate_envelope_ref_locked(stream_ref.envelope_ref)
        if envelope is None:
            return None
        identity = stream_ref.identity
        expected = self._mac(
            b"stream-reference-v1",
            self._authority_id,
            stream_ref.stream_authority_id,
            envelope.envelope_id,
            identity.data_type,
            identity.builder_id,
            identity.stream_id,
            identity.name,
            identity.producer_name,
        )
        if not hmac.compare_digest(expected, stream_ref.authenticator):
            return None
        if not hmac.compare_digest(
            registered.authenticator,
            stream_ref.authenticator,
        ):
            return None
        if registered.identity != stream_ref.identity:
            return None
        return registered, envelope

    def stream_envelope_ref_v1(
        self,
        stream_ref: SecurityStreamReferenceV1,
    ) -> SecurityEnvelopeReferenceV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                validated = self._validate_stream_ref_locked(stream_ref)
                return validated[0].envelope_ref if validated is not None else None
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    # ------------------------------------------------------------------
    # Authorized data dispatch
    # ------------------------------------------------------------------

    def authorize_dispatch_v1(
        self,
        *,
        stream_ref: SecurityStreamReferenceV1,
        consumer_capability: ConsumerCapabilityV1,
        trusted_data_type: ChatDataType,
        trusted_source: str | None,
        payload: Any,
    ) -> AuthorizedDispatchV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                validated_stream = self._validate_stream_ref_locked(stream_ref)
                if validated_stream is None:
                    self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                    return None
                registered_stream, envelope = validated_stream
                if not self.consumer_is_authorized_v1(
                    registered_stream.envelope_ref,
                    consumer_capability,
                ):
                    return None
                registered_capability = self._validate_capability_locked(
                    consumer_capability
                )
                if registered_capability is None:
                    self._record(
                        SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                        envelope_id=envelope.envelope_id,
                    )
                    return None
                dispatch_id = _opaque_id_v1("adv1_")
                lineage_digest = self._lineage_digest(envelope)
                authenticator = self._mac(
                    b"authorized-dispatch-v1",
                    self._authority_id,
                    dispatch_id,
                    envelope.envelope_id,
                    registered_stream.stream_authority_id,
                    registered_capability.capability_id,
                    trusted_data_type,
                    trusted_source,
                    lineage_digest,
                )
                return AuthorizedDispatchV1(
                    authority_id=self._authority_id,
                    dispatch_id=dispatch_id,
                    envelope_ref=registered_stream.envelope_ref,
                    stream_ref=registered_stream,
                    consumer_capability=registered_capability,
                    trusted_data_type=trusted_data_type,
                    trusted_source=trusted_source,
                    trusted_lineage_digest=lineage_digest,
                    payload=payload,
                    authenticator=authenticator,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def validate_dequeued_dispatch_v1(
        self,
        queued_item: object,
        expected_capability: ConsumerCapabilityV1,
    ) -> ValidatedDispatchV1 | None:
        """First post-dequeue operation for secure handler queues."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not isinstance(queued_item, AuthorizedDispatchV1):
                    self._record(SecurityAuditEventCodeV1.ENVELOPE_MISSING)
                    return None
                if queued_item.authority_id != self._authority_id:
                    self._record(
                        SecurityAuditEventCodeV1.ENVELOPE_MISSING,
                        dispatch_id=queued_item.dispatch_id,
                    )
                    return None
                registered_expected = self._validate_capability_locked(
                    expected_capability
                )
                registered_embedded = self._validate_capability_locked(
                    queued_item.consumer_capability
                )
                if (
                    registered_expected is None
                    or registered_embedded is None
                    or registered_expected.capability_id
                    != registered_embedded.capability_id
                ):
                    self._record(
                        SecurityAuditEventCodeV1.CONSUMER_NOT_AUTHORIZED,
                        dispatch_id=queued_item.dispatch_id,
                    )
                    return None
                validated_stream = self._validate_stream_ref_locked(
                    queued_item.stream_ref
                )
                if validated_stream is None:
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        dispatch_id=queued_item.dispatch_id,
                    )
                    return None
                registered_stream, envelope = validated_stream
                if (
                    queued_item.envelope_ref.envelope_id != envelope.envelope_id
                    or queued_item.envelope_ref.authority_id != self._authority_id
                ):
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        dispatch_id=queued_item.dispatch_id,
                    )
                    return None
                lineage_digest = self._lineage_digest(envelope)
                if not hmac.compare_digest(
                    lineage_digest,
                    queued_item.trusted_lineage_digest,
                ):
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        envelope_id=envelope.envelope_id,
                        dispatch_id=queued_item.dispatch_id,
                    )
                    return None
                expected_mac = self._mac(
                    b"authorized-dispatch-v1",
                    self._authority_id,
                    queued_item.dispatch_id,
                    envelope.envelope_id,
                    registered_stream.stream_authority_id,
                    registered_expected.capability_id,
                    queued_item.trusted_data_type,
                    queued_item.trusted_source,
                    lineage_digest,
                )
                if not hmac.compare_digest(
                    expected_mac,
                    queued_item.authenticator,
                ):
                    self._record(
                        SecurityAuditEventCodeV1.DISPATCH_DENIED,
                        envelope_id=envelope.envelope_id,
                        consumer_capability_id=registered_expected.capability_id,
                        dispatch_id=queued_item.dispatch_id,
                    )
                    return None
                if not self.consumer_is_authorized_v1(
                    registered_stream.envelope_ref,
                    registered_expected,
                ):
                    return None
                return ValidatedDispatchV1(
                    dispatch_id=queued_item.dispatch_id,
                    envelope_ref=registered_stream.envelope_ref,
                    stream_ref=registered_stream,
                    classification=envelope.classification,
                    egress_policy=envelope.egress_policy,
                    trusted_data_type=queued_item.trusted_data_type,
                    trusted_source=queued_item.trusted_source,
                    payload=queued_item.payload,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None
        except Exception:  # noqa: BLE001 - fail closed without payload repr
            # Never surface payload-bearing exception representations.
            self.audit_registry_failure_v1()
            return None

    # ------------------------------------------------------------------
    # Authorized signal emission
    # ------------------------------------------------------------------

    def authorize_signal_emission_v1(
        self,
        *,
        envelope_ref: SecurityEnvelopeReferenceV1,
        stream_ref: SecurityStreamReferenceV1 | None,
        trusted_signal_type: ChatSignalType | None,
        trusted_source_type: ChatSignalSourceType | None,
        trusted_source_name: str | None,
        payload: Any,
    ) -> AuthorizedSignalEmissionV1 | None:
        try:
            with self._lock:
                self._ensure_available_locked()
                envelope = self._validate_envelope_ref_locked(envelope_ref)
                if envelope is None:
                    self._record(SecurityAuditEventCodeV1.ENVELOPE_MISSING)
                    return None
                registered_stream = None
                if stream_ref is not None:
                    validated_stream = self._validate_stream_ref_locked(stream_ref)
                    if validated_stream is None:
                        self._record(SecurityAuditEventCodeV1.INVALID_LINEAGE)
                        return None
                    registered_stream, stream_envelope = validated_stream
                    if (
                        stream_envelope.envelope_id != envelope.envelope_id
                        and stream_envelope.envelope_id
                        not in envelope.lineage.ancestor_envelope_ids
                    ):
                        self._record(
                            SecurityAuditEventCodeV1.INVALID_LINEAGE,
                            envelope_id=envelope.envelope_id,
                        )
                        return None
                emission_id = _opaque_id_v1("asev1_")
                lineage_digest = self._lineage_digest(envelope)
                stream_authority_id = (
                    registered_stream.stream_authority_id
                    if registered_stream is not None
                    else None
                )
                authenticator = self._mac(
                    b"authorized-signal-emission-v1",
                    self._authority_id,
                    emission_id,
                    envelope.envelope_id,
                    stream_authority_id,
                    trusted_signal_type,
                    trusted_source_type,
                    trusted_source_name,
                    lineage_digest,
                )
                return AuthorizedSignalEmissionV1(
                    authority_id=self._authority_id,
                    emission_id=emission_id,
                    envelope_ref=envelope_ref,
                    stream_ref=registered_stream,
                    trusted_signal_type=trusted_signal_type,
                    trusted_source_type=trusted_source_type,
                    trusted_source_name=trusted_source_name,
                    trusted_lineage_digest=lineage_digest,
                    payload=payload,
                    authenticator=authenticator,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None

    def validate_dequeued_signal_emission_v1(
        self,
        queued_item: object,
    ) -> ValidatedSignalEmissionV1 | None:
        """First post-dequeue operation for secure signal queues."""

        try:
            with self._lock:
                self._ensure_available_locked()
                if not isinstance(queued_item, AuthorizedSignalEmissionV1):
                    self._record(SecurityAuditEventCodeV1.ENVELOPE_MISSING)
                    return None
                if queued_item.authority_id != self._authority_id:
                    self._record(
                        SecurityAuditEventCodeV1.ENVELOPE_MISSING,
                        dispatch_id=queued_item.emission_id,
                    )
                    return None
                envelope = self._validate_envelope_ref_locked(queued_item.envelope_ref)
                if envelope is None:
                    self._record(
                        SecurityAuditEventCodeV1.ENVELOPE_MISSING,
                        dispatch_id=queued_item.emission_id,
                    )
                    return None
                registered_stream = None
                if queued_item.stream_ref is not None:
                    validated_stream = self._validate_stream_ref_locked(
                        queued_item.stream_ref
                    )
                    if validated_stream is None:
                        self._record(
                            SecurityAuditEventCodeV1.INVALID_LINEAGE,
                            dispatch_id=queued_item.emission_id,
                        )
                        return None
                    registered_stream, stream_envelope = validated_stream
                    if (
                        stream_envelope.envelope_id != envelope.envelope_id
                        and stream_envelope.envelope_id
                        not in envelope.lineage.ancestor_envelope_ids
                    ):
                        self._record(
                            SecurityAuditEventCodeV1.INVALID_LINEAGE,
                            dispatch_id=queued_item.emission_id,
                        )
                        return None
                lineage_digest = self._lineage_digest(envelope)
                if not hmac.compare_digest(
                    lineage_digest,
                    queued_item.trusted_lineage_digest,
                ):
                    self._record(
                        SecurityAuditEventCodeV1.INVALID_LINEAGE,
                        envelope_id=envelope.envelope_id,
                        dispatch_id=queued_item.emission_id,
                    )
                    return None
                stream_authority_id = (
                    registered_stream.stream_authority_id
                    if registered_stream is not None
                    else None
                )
                expected_mac = self._mac(
                    b"authorized-signal-emission-v1",
                    self._authority_id,
                    queued_item.emission_id,
                    envelope.envelope_id,
                    stream_authority_id,
                    queued_item.trusted_signal_type,
                    queued_item.trusted_source_type,
                    queued_item.trusted_source_name,
                    lineage_digest,
                )
                if not hmac.compare_digest(
                    expected_mac,
                    queued_item.authenticator,
                ):
                    self._record(
                        SecurityAuditEventCodeV1.DISPATCH_DENIED,
                        envelope_id=envelope.envelope_id,
                        dispatch_id=queued_item.emission_id,
                    )
                    return None
                return ValidatedSignalEmissionV1(
                    emission_id=queued_item.emission_id,
                    envelope_ref=queued_item.envelope_ref,
                    stream_ref=registered_stream,
                    classification=envelope.classification,
                    trusted_signal_type=queued_item.trusted_signal_type,
                    trusted_source_type=queued_item.trusted_source_type,
                    trusted_source_name=queued_item.trusted_source_name,
                    payload=queued_item.payload,
                )
        except SecurityAuthorityUnavailableV1:
            self.audit_registry_failure_v1()
            return None
        except Exception:  # noqa: BLE001 - fail closed without payload repr
            self.audit_registry_failure_v1()
            return None

    # ------------------------------------------------------------------
    # Test-only corruption controls, reached only from the test harness
    # ------------------------------------------------------------------

    def _fail_registry_for_test_v1(self) -> None:
        with self._lock:
            self._failed = True

    def _remove_envelope_for_test_v1(
        self,
        envelope_ref: SecurityEnvelopeReferenceV1,
    ) -> None:
        with self._lock:
            self._envelopes.pop(envelope_ref.envelope_id, None)
            self._envelope_refs.pop(envelope_ref.envelope_id, None)

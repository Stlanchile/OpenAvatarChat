"""Digest-only capture-scoped bearer capability authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from certificate_capture.epochs import CaptureEpochV1

CAPTURE_CAPABILITY_HEADER_V1 = "X-Certificate-Capture-Capability"
CAPTURE_CAPABILITY_RANDOM_BYTES_V1 = 32
CAPTURE_CAPABILITY_PURPOSE_V1 = "certificate_capture"

_CAPTURE_CAPABILITY_PREFIX_V1 = "ccp1_"
_OPAQUE_VALUE_ENCODED_CHARACTERS_V1 = 43
_OPAQUE_VALUE_PATTERN_V1 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_SESSION_ID_UTF8_BYTES_V1 = 256
_MAX_OWNER_PART_UTF8_BYTES_V1 = 4096


@dataclass(frozen=True, slots=True, repr=False)
class CaptureCapabilityBindingV1:
    """Non-secret binding inputs retained only for bounded control replay."""

    session_id_digest: bytes
    owner_digest: bytes
    capture_epoch: CaptureEpochV1
    expires_at_epoch_seconds: float
    expires_at_monotonic: float
    purpose: str = CAPTURE_CAPABILITY_PURPOSE_V1

    def __repr__(self) -> str:
        return "CaptureCapabilityBindingV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ActiveCaptureCapabilityV1:
    """The active authority stores a keyed digest, never the bearer value."""

    binding: CaptureCapabilityBindingV1
    capability_digest: bytes

    def __repr__(self) -> str:
        return "ActiveCaptureCapabilityV1(<redacted>)"


class CaptureCapabilityAuthorityV1:
    """Session-local PRF authority for one current capture at a time."""

    __slots__ = (
        "_closed",
        "_derivation_key",
        "_digest_key",
        "_dummy_digest",
    )

    def __init__(
        self,
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._derivation_key = self._random_key_v1(random_bytes)
        self._digest_key = self._random_key_v1(random_bytes)
        if hmac.compare_digest(self._derivation_key, self._digest_key):
            raise RuntimeError("capture capability authority unavailable")
        self._dummy_digest = self._digest_v1(
            bytes(CAPTURE_CAPABILITY_RANDOM_BYTES_V1)
        )
        self._closed = False

    @staticmethod
    def _random_key_v1(random_bytes: Callable[[int], bytes]) -> bytes:
        try:
            value = random_bytes(CAPTURE_CAPABILITY_RANDOM_BYTES_V1)
        except Exception:  # noqa: BLE001 - stable fail-closed boundary
            raise RuntimeError("capture capability authority unavailable") from None
        if (
            not isinstance(value, bytes)
            or len(value) != CAPTURE_CAPABILITY_RANDOM_BYTES_V1
        ):
            raise RuntimeError("capture capability authority unavailable")
        return value

    def create_binding_v1(
        self,
        *,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        capture_epoch: CaptureEpochV1,
        expires_at_epoch_seconds: float,
        expires_at_monotonic: float,
    ) -> CaptureCapabilityBindingV1:
        self._ensure_open_v1()
        if not isinstance(capture_epoch, CaptureEpochV1):
            raise TypeError("capture_epoch must be CaptureEpochV1")
        if (
            isinstance(expires_at_epoch_seconds, bool)
            or not isinstance(expires_at_epoch_seconds, (int, float))
            or not math.isfinite(expires_at_epoch_seconds)
            or isinstance(expires_at_monotonic, bool)
            or not isinstance(expires_at_monotonic, (int, float))
            or not math.isfinite(expires_at_monotonic)
        ):
            raise RuntimeError("capture capability authority unavailable")
        session_material = self._bounded_utf8_v1(
            session_id,
            _MAX_SESSION_ID_UTF8_BYTES_V1,
        )
        owner_material = self._owner_material_v1(owner_issuer, owner_subject)
        return CaptureCapabilityBindingV1(
            session_id_digest=self._binding_digest_v1(
                b"capture-session-id-v1",
                session_material,
            ),
            owner_digest=self._binding_digest_v1(
                b"capture-owner-v1",
                owner_material,
            ),
            capture_epoch=capture_epoch,
            expires_at_epoch_seconds=float(expires_at_epoch_seconds),
            expires_at_monotonic=float(expires_at_monotonic),
        )

    def activate_v1(
        self,
        binding: CaptureCapabilityBindingV1,
    ) -> tuple[ActiveCaptureCapabilityV1, str]:
        entropy = self._derive_entropy_v1(binding)
        capability = self._encode_v1(entropy)
        return (
            ActiveCaptureCapabilityV1(
                binding=binding,
                capability_digest=self._digest_v1(entropy),
            ),
            capability,
        )

    def render_for_replay_v1(
        self,
        binding: CaptureCapabilityBindingV1,
    ) -> str:
        """Recreate the original bearer response without retaining plaintext."""

        return self._encode_v1(self._derive_entropy_v1(binding))

    def authorizes_v1(
        self,
        active: ActiveCaptureCapabilityV1 | None,
        *,
        presented_capability: object,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        capture_epoch: CaptureEpochV1,
        now_epoch_seconds: float,
        now_monotonic: float,
    ) -> bool:
        if self._closed:
            return False
        entropy = self._decode_v1(presented_capability)
        presented_digest = (
            self._digest_v1(entropy)
            if entropy is not None
            else self._dummy_digest
        )
        expected_digest = (
            active.capability_digest
            if isinstance(active, ActiveCaptureCapabilityV1)
            else self._dummy_digest
        )
        capability_matches = hmac.compare_digest(
            expected_digest,
            presented_digest,
        )

        binding = active.binding if active is not None else None
        try:
            session_digest = self._binding_digest_v1(
                b"capture-session-id-v1",
                self._bounded_utf8_v1(
                    session_id,
                    _MAX_SESSION_ID_UTF8_BYTES_V1,
                ),
            )
            owner_digest = self._binding_digest_v1(
                b"capture-owner-v1",
                self._owner_material_v1(owner_issuer, owner_subject),
            )
        except RuntimeError:
            session_digest = bytes(32)
            owner_digest = bytes(32)

        return bool(
            binding is not None
            and capability_matches
            and hmac.compare_digest(binding.session_id_digest, session_digest)
            and hmac.compare_digest(binding.owner_digest, owner_digest)
            and binding.capture_epoch is capture_epoch
            and binding.purpose == CAPTURE_CAPABILITY_PURPOSE_V1
            and math.isfinite(now_epoch_seconds)
            and math.isfinite(now_monotonic)
            and now_epoch_seconds < binding.expires_at_epoch_seconds
            and now_monotonic < binding.expires_at_monotonic
        )

    def replay_capability_matches_v1(
        self,
        binding: CaptureCapabilityBindingV1,
        presented_capability: object,
    ) -> bool:
        """Authorize only retrieval of an already completed replay result."""

        entropy = self._decode_v1(presented_capability)
        presented_digest = (
            self._digest_v1(entropy)
            if entropy is not None
            else self._dummy_digest
        )
        expected_digest = self._digest_v1(self._derive_entropy_v1(binding))
        return hmac.compare_digest(expected_digest, presented_digest)

    def binding_is_live_v1(
        self,
        active: ActiveCaptureCapabilityV1 | None,
        *,
        binding: CaptureCapabilityBindingV1,
        session_id: str,
        owner_issuer: str,
        owner_subject: str,
        capture_epoch: CaptureEpochV1,
        now_epoch_seconds: float,
        now_monotonic: float,
    ) -> bool:
        """Validate a Begin replay binding without re-rendering its bearer."""

        if self._closed:
            return False
        try:
            session_digest = self._binding_digest_v1(
                b"capture-session-id-v1",
                self._bounded_utf8_v1(
                    session_id,
                    _MAX_SESSION_ID_UTF8_BYTES_V1,
                ),
            )
            owner_digest = self._binding_digest_v1(
                b"capture-owner-v1",
                self._owner_material_v1(owner_issuer, owner_subject),
            )
            expected_capability_digest = self._digest_v1(
                self._derive_entropy_v1(binding)
            )
        except (RuntimeError, TypeError, OverflowError):
            return False
        return bool(
            isinstance(active, ActiveCaptureCapabilityV1)
            and active.binding is binding
            and hmac.compare_digest(
                active.capability_digest,
                expected_capability_digest,
            )
            and hmac.compare_digest(binding.session_id_digest, session_digest)
            and hmac.compare_digest(binding.owner_digest, owner_digest)
            and binding.capture_epoch is capture_epoch
            and binding.purpose == CAPTURE_CAPABILITY_PURPOSE_V1
            and math.isfinite(now_epoch_seconds)
            and math.isfinite(now_monotonic)
            and now_epoch_seconds < binding.expires_at_epoch_seconds
            and now_monotonic < binding.expires_at_monotonic
        )

    def close_v1(self) -> None:
        self._derivation_key = bytes(len(self._derivation_key))
        self._digest_key = bytes(len(self._digest_key))
        self._dummy_digest = bytes(len(self._dummy_digest))
        self._closed = True

    def _derive_entropy_v1(
        self,
        binding: CaptureCapabilityBindingV1,
    ) -> bytes:
        self._ensure_open_v1()
        epoch = binding.capture_epoch
        message = (
            b"certificate-capture-capability-v1\x00"
            + binding.session_id_digest
            + binding.owner_digest
            + epoch.session_epoch.session_instance_id.bytes
            + epoch.session_epoch.generation.to_bytes(8, "big")
            + epoch.capture_id.bytes
            + epoch.capture_seq.to_bytes(8, "big")
            + binding.expires_at_epoch_seconds.hex().encode("ascii")
            + b"\x00"
            + binding.expires_at_monotonic.hex().encode("ascii")
            + b"\x00"
            + binding.purpose.encode("ascii")
        )
        return hmac.new(
            self._derivation_key,
            message,
            hashlib.sha256,
        ).digest()

    def _binding_digest_v1(self, context: bytes, value: bytes) -> bytes:
        return hmac.new(
            self._derivation_key,
            context + len(value).to_bytes(4, "big") + value,
            hashlib.sha256,
        ).digest()

    def _digest_v1(self, entropy: bytes) -> bytes:
        return hmac.new(
            self._digest_key,
            b"capture-capability-digest-v1" + entropy,
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _bounded_utf8_v1(value: object, limit: int) -> bytes:
        if not isinstance(value, str):
            raise TypeError("capture capability binding must be text")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise RuntimeError("capture capability authority unavailable") from None
        if not encoded or len(encoded) > limit:
            raise RuntimeError("capture capability authority unavailable")
        return encoded

    def _owner_material_v1(
        self,
        issuer: object,
        subject: object,
    ) -> bytes:
        issuer_bytes = self._bounded_utf8_v1(
            issuer,
            _MAX_OWNER_PART_UTF8_BYTES_V1,
        )
        subject_bytes = self._bounded_utf8_v1(
            subject,
            _MAX_OWNER_PART_UTF8_BYTES_V1,
        )
        return (
            len(issuer_bytes).to_bytes(4, "big")
            + issuer_bytes
            + len(subject_bytes).to_bytes(4, "big")
            + subject_bytes
        )

    @staticmethod
    def _encode_v1(entropy: bytes) -> str:
        encoded = base64.urlsafe_b64encode(entropy).rstrip(b"=").decode("ascii")
        return _CAPTURE_CAPABILITY_PREFIX_V1 + encoded

    @staticmethod
    def _decode_v1(value: object) -> bytes | None:
        if not isinstance(value, str) or not value.startswith(
            _CAPTURE_CAPABILITY_PREFIX_V1
        ):
            return None
        encoded = value[len(_CAPTURE_CAPABILITY_PREFIX_V1) :]
        if (
            len(encoded) != _OPAQUE_VALUE_ENCODED_CHARACTERS_V1
            or _OPAQUE_VALUE_PATTERN_V1.fullmatch(encoded) is None
        ):
            return None
        try:
            decoded = base64.b64decode(
                (encoded + "=").encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (UnicodeEncodeError, ValueError, binascii.Error):
            return None
        if (
            len(decoded) != CAPTURE_CAPABILITY_RANDOM_BYTES_V1
            or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
            != encoded
        ):
            return None
        return decoded

    def _ensure_open_v1(self) -> None:
        if self._closed:
            raise RuntimeError("capture capability authority unavailable")


__all__ = [
    "CAPTURE_CAPABILITY_HEADER_V1",
    "CAPTURE_CAPABILITY_PURPOSE_V1",
    "CAPTURE_CAPABILITY_RANDOM_BYTES_V1",
    "ActiveCaptureCapabilityV1",
    "CaptureCapabilityAuthorityV1",
    "CaptureCapabilityBindingV1",
]

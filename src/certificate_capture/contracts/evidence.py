"""Immutable capture and frame evidence metadata for Milestone 5A."""

from __future__ import annotations

import hashlib
import math
import uuid
from dataclasses import dataclass

from certificate_capture.contracts.common import (
    canonical_json_bytes_v1,
    capture_epoch_object_v1,
    require_epoch_seconds_v1,
    require_sha256_hex_v1,
    require_text_v1,
    require_uuid7_v1,
)
from certificate_capture.epochs import CaptureEpochV1
from certificate_capture.protocol import MAX_CAPTURE_FRAMES_V1

CAPTURE_SET_SCHEMA_VERSION_V1 = "oac.capture-set.v1"
EVIDENCE_FRAME_SCHEMA_VERSION_V1 = "oac.evidence-frame.v1"


@dataclass(frozen=True, slots=True)
class CaptureWindowV1:
    """Bounded active capture window; inactivity may end it earlier."""

    opened_at_epoch_seconds: float
    maximum_expires_at_epoch_seconds: float

    def __post_init__(self) -> None:
        opened = require_epoch_seconds_v1(
            "opened_at_epoch_seconds",
            self.opened_at_epoch_seconds,
        )
        expires = require_epoch_seconds_v1(
            "maximum_expires_at_epoch_seconds",
            self.maximum_expires_at_epoch_seconds,
        )
        if expires <= opened:
            raise ValueError("capture window expiry must follow its opening")
        object.__setattr__(self, "opened_at_epoch_seconds", opened)
        object.__setattr__(
            self,
            "maximum_expires_at_epoch_seconds",
            expires,
        )

    def canonical_object_v1(self) -> dict[str, float]:
        return {
            "maximum_expires_at_epoch_seconds": (
                self.maximum_expires_at_epoch_seconds
            ),
            "opened_at_epoch_seconds": self.opened_at_epoch_seconds,
        }


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class CaptureSetV1:
    """One exact capture-private evidence domain.

    ``frame_record_ids`` contains server-owned ``EvidenceFrameV1.frame_id``
    values in ascending frame-sequence order.
    """

    capture_epoch: CaptureEpochV1
    profile_id: str
    capture_created_at_epoch_seconds: float
    capture_window: CaptureWindowV1
    frame_record_ids: tuple[uuid.UUID, ...] = ()
    inference_identity_ref: str | None = None
    calibration_dependency_ref: str | None = None
    schema_version: str = CAPTURE_SET_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != CAPTURE_SET_SCHEMA_VERSION_V1:
            raise ValueError("unsupported CaptureSetV1 schema version")
        if not isinstance(self.capture_epoch, CaptureEpochV1):
            raise TypeError("capture_epoch must be CaptureEpochV1")
        require_text_v1(
            "profile_id",
            self.profile_id,
            maximum_utf8_bytes=128,
        )
        created_at = require_epoch_seconds_v1(
            "capture_created_at_epoch_seconds",
            self.capture_created_at_epoch_seconds,
        )
        if not isinstance(self.capture_window, CaptureWindowV1):
            raise TypeError("capture_window must be CaptureWindowV1")
        if not math.isclose(
            created_at,
            self.capture_window.opened_at_epoch_seconds,
            rel_tol=0.0,
            abs_tol=0.0,
        ):
            raise ValueError("capture creation must equal capture-window opening")
        if not isinstance(self.frame_record_ids, tuple):
            raise TypeError("frame_record_ids must be an immutable tuple")
        if len(self.frame_record_ids) > MAX_CAPTURE_FRAMES_V1:
            raise ValueError("capture frame-record bound exceeded")
        normalized_ids = tuple(
            require_uuid7_v1("frame record ID", record_id)
            for record_id in self.frame_record_ids
        )
        if len(set(normalized_ids)) != len(normalized_ids):
            raise ValueError("frame record IDs must be unique")
        if self.inference_identity_ref is not None:
            require_sha256_hex_v1(
                "inference_identity_ref",
                self.inference_identity_ref,
            )
        if self.calibration_dependency_ref is not None:
            require_sha256_hex_v1(
                "calibration_dependency_ref",
                self.calibration_dependency_ref,
            )
        object.__setattr__(
            self,
            "capture_created_at_epoch_seconds",
            created_at,
        )

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "calibration_dependency_ref": self.calibration_dependency_ref,
            "capture_created_at_epoch_seconds": (
                self.capture_created_at_epoch_seconds
            ),
            "capture_epoch": capture_epoch_object_v1(self.capture_epoch),
            "capture_window": self.capture_window.canonical_object_v1(),
            "frame_record_ids": [
                str(record_id) for record_id in self.frame_record_ids
            ],
            "inference_identity_ref": self.inference_identity_ref,
            "profile_id": self.profile_id,
            "schema_version": self.schema_version,
        }

    def canonical_json_v1(self) -> bytes:
        return canonical_json_bytes_v1(self.canonical_object_v1())

    @property
    def capture_set_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json_v1()).hexdigest()

    def __repr__(self) -> str:
        return (
            "CaptureSetV1("
            f"schema_version={self.schema_version!r}, "
            f"capture_seq={self.capture_epoch.capture_seq}, "
            f"frame_count={len(self.frame_record_ids)}, "
            "private_refs=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class EvidenceFrameV1:
    """Metadata for one exact encrypted JPEG record."""

    frame_id: uuid.UUID
    frame_seq: int
    received_at_epoch_seconds: float
    encoded_size: int
    canonical_width: int
    canonical_height: int
    sha256: bytes
    capture_epoch: CaptureEpochV1
    encrypted_record_ref: uuid.UUID
    schema_version: str = EVIDENCE_FRAME_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != EVIDENCE_FRAME_SCHEMA_VERSION_V1:
            raise ValueError("unsupported EvidenceFrameV1 schema version")
        require_uuid7_v1("frame_id", self.frame_id)
        require_uuid7_v1("encrypted_record_ref", self.encrypted_record_ref)
        if (
            isinstance(self.frame_seq, bool)
            or not isinstance(self.frame_seq, int)
            or not 1 <= self.frame_seq <= MAX_CAPTURE_FRAMES_V1
        ):
            raise ValueError("frame_seq must be within the V1 capture bound")
        received = require_epoch_seconds_v1(
            "received_at_epoch_seconds",
            self.received_at_epoch_seconds,
        )
        if (
            isinstance(self.encoded_size, bool)
            or not isinstance(self.encoded_size, int)
            or self.encoded_size <= 0
        ):
            raise ValueError("encoded_size must be positive")
        for name, value in (
            ("canonical_width", self.canonical_width),
            ("canonical_height", self.canonical_height),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive")
        if not isinstance(self.sha256, bytes) or len(self.sha256) != 32:
            raise ValueError("sha256 must be exactly 32 bytes")
        if not isinstance(self.capture_epoch, CaptureEpochV1):
            raise TypeError("capture_epoch must be CaptureEpochV1")
        object.__setattr__(self, "received_at_epoch_seconds", received)

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "canonical_height": self.canonical_height,
            "canonical_width": self.canonical_width,
            "capture_epoch": capture_epoch_object_v1(self.capture_epoch),
            "encoded_size": self.encoded_size,
            "encrypted_record_ref": str(self.encrypted_record_ref),
            "frame_id": str(self.frame_id),
            "frame_seq": self.frame_seq,
            "received_at_epoch_seconds": self.received_at_epoch_seconds,
            "schema_version": self.schema_version,
            "sha256": self.sha256.hex(),
        }

    def canonical_json_v1(self) -> bytes:
        return canonical_json_bytes_v1(self.canonical_object_v1())

    @property
    def evidence_frame_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json_v1()).hexdigest()

    def __repr__(self) -> str:
        return (
            "EvidenceFrameV1("
            f"schema_version={self.schema_version!r}, "
            f"frame_seq={self.frame_seq}, "
            "frame_id=<opaque>, encrypted_record_ref=<opaque>, "
            "private_hash=<redacted>)"
        )


__all__ = [
    "CAPTURE_SET_SCHEMA_VERSION_V1",
    "EVIDENCE_FRAME_SCHEMA_VERSION_V1",
    "CaptureSetV1",
    "CaptureWindowV1",
    "EvidenceFrameV1",
]

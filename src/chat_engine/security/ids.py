"""Core-only identifier helpers for versioned session security authority."""

from __future__ import annotations

import secrets
import time
import uuid

UINT64_MAX_V1 = (1 << 64) - 1
_UUIDV7_TIMESTAMP_MAX_V1 = (1 << 48) - 1


def new_uuid7_v1() -> uuid.UUID:
    """Mint an RFC 9562 UUIDv7 using cryptographic random bits.

    UUIDv7 carries a 48-bit Unix-millisecond timestamp, a four-bit version,
    the RFC 4122 variant, and 74 cryptographically random bits. Epoch
    authorization never relies on timestamp ordering inside this identifier;
    the controller's uint64 generation is the monotonic authority.
    """

    unix_ms = time.time_ns() // 1_000_000
    if not 0 <= unix_ms <= _UUIDV7_TIMESTAMP_MAX_V1:
        raise RuntimeError("UUIDv7 timestamp is outside the supported range")

    random_bits = secrets.randbits(74)
    random_a = random_bits >> 62
    random_b = random_bits & ((1 << 62) - 1)
    value = (unix_ms << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    return uuid.UUID(int=value)

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal, Protocol

import aiohttp
import jwt
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
)
from jwt import PyJWK
from jwt.exceptions import (
    InvalidAlgorithmError,
    InvalidSignatureError,
    PyJWTError,
)

from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
    OidcResourceServerConfigV1,
)

JWKS_FETCH_TIMEOUT_SECONDS_V1 = 5.0
JWKS_MAX_RESPONSE_BYTES_V1 = 1024 * 1024
JWKS_CACHE_MAX_AGE_SECONDS_V1 = 5 * 60

OIDC_CERTIFICATE_CAPTURE_SCOPE_V1 = "certificate:capture"
OIDC_MANAGER_SCOPE_V1 = "oac:manager"
OidcRequiredScopeV1 = Literal["certificate:capture", "oac:manager"]

_JWKS_CONNECT_TIMEOUT_SECONDS_V1 = 2.0
_JWKS_MAX_KEYS_V1 = 128
_JWT_MAX_ENCODED_BYTES_V1 = 16 * 1024
_JWT_KID_MAX_CHARACTERS_V1 = 512
_JWT_SUBJECT_MAX_CHARACTERS_V1 = 1024
_JWT_SCOPE_MAX_CHARACTERS_V1 = 4096
_MAX_NUMERIC_DATE_V1 = (1 << 63) - 1

_JWT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_SCOPE_PATTERN = re.compile(
    r"^[\x21\x23-\x5B\x5D-\x7E]+"
    r"(?: [\x21\x23-\x5B\x5D-\x7E]+)*$"
)
_TOKEN_CONTROLLED_KEY_HEADERS = frozenset({"jku", "jwk", "x5u", "x5c"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
_ACCESS_TOKEN_TYPE_V1 = "at+jwt"
_EXPECTED_JWK_SHAPES: Mapping[str, tuple[str, frozenset[str] | None]] = {
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "ES256": ("EC", frozenset({"P-256"})),
    "ES384": ("EC", frozenset({"P-384"})),
    "ES512": ("EC", frozenset({"P-521"})),
    "EdDSA": ("OKP", frozenset({"Ed25519", "Ed448"})),
}


class OidcAuthenticationReasonV1(str, Enum):
    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_HEADER_INVALID = "TOKEN_HEADER_INVALID"
    ACCESS_TOKEN_FORM_INVALID = "ACCESS_TOKEN_FORM_INVALID"
    ALGORITHM_NONE = "ALGORITHM_NONE"
    ALGORITHM_NOT_ALLOWED = "ALGORITHM_NOT_ALLOWED"
    KID_MISSING = "KID_MISSING"
    KID_INVALID = "KID_INVALID"
    JWKS_UNAVAILABLE = "JWKS_UNAVAILABLE"
    JWKS_INVALID = "JWKS_INVALID"
    JWKS_RESPONSE_TOO_LARGE = "JWKS_RESPONSE_TOO_LARGE"
    SIGNING_KEY_NOT_FOUND = "SIGNING_KEY_NOT_FOUND"
    SIGNING_KEY_INVALID = "SIGNING_KEY_INVALID"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ISSUER_INVALID = "ISSUER_INVALID"
    AUDIENCE_INVALID = "AUDIENCE_INVALID"
    TEMPORAL_CLAIM_INVALID = "TEMPORAL_CLAIM_INVALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_NOT_YET_VALID = "TOKEN_NOT_YET_VALID"
    SUBJECT_INVALID = "SUBJECT_INVALID"
    SCOPE_INVALID = "SCOPE_INVALID"
    REQUIRED_SCOPE_MISSING = "REQUIRED_SCOPE_MISSING"
    AUTHENTICATION_UNAVAILABLE = "AUTHENTICATION_UNAVAILABLE"


class OidcAuthenticationErrorV1(RuntimeError):
    """A stable, value-free access-token validation failure."""

    __slots__ = ("reason_code",)

    def __init__(self, reason: OidcAuthenticationReasonV1):
        self.reason_code = reason.value
        super().__init__(f"OIDC access-token validation failed ({self.reason_code}).")


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedPrincipalV1:
    """The immutable identity retained after an access token is validated."""

    issuer: str
    subject: str
    scopes: frozenset[str]
    token_expiry_epoch_seconds: int

    def __repr__(self) -> str:
        return "AuthenticatedPrincipalV1(<redacted>)"


class JwksDocumentFetcherV1(Protocol):
    async def fetch(self, configured_jwks_url: str) -> bytes:
        """Fetch a configured JWKS document without using token metadata."""


class _JwksFetchUnavailableV1(RuntimeError):
    pass


class _JwksResponseTooLargeV1(RuntimeError):
    pass


class _InvalidJsonDocumentV1(ValueError):
    pass


class AiohttpJwksDocumentFetcherV1:
    """A bounded, redirect-free fetcher for the configured JWKS URL."""

    __slots__ = ()

    async def fetch(self, configured_jwks_url: str) -> bytes:
        timeout = aiohttp.ClientTimeout(
            total=JWKS_FETCH_TIMEOUT_SECONDS_V1,
            connect=_JWKS_CONNECT_TIMEOUT_SECONDS_V1,
            sock_connect=_JWKS_CONNECT_TIMEOUT_SECONDS_V1,
            sock_read=JWKS_FETCH_TIMEOUT_SECONDS_V1,
        )
        fetch_unavailable = False
        try:
            async with (
                aiohttp.ClientSession(
                    timeout=timeout,
                    trust_env=False,
                ) as session,
                session.get(
                    configured_jwks_url,
                    allow_redirects=False,
                    headers={"Accept": "application/json"},
                ) as response,
            ):
                if response.status != 200:
                    fetch_unavailable = True
                elif (
                    response.content_length is not None
                    and response.content_length > JWKS_MAX_RESPONSE_BYTES_V1
                ):
                    raise _JwksResponseTooLargeV1
                else:
                    body = bytearray()
                    async for chunk in response.content.iter_chunked(64 * 1024):
                        body.extend(chunk)
                        if len(body) > JWKS_MAX_RESPONSE_BYTES_V1:
                            raise _JwksResponseTooLargeV1
                    return bytes(body)
        except _JwksResponseTooLargeV1:
            raise
        except (aiohttp.ClientError, TimeoutError, OSError):
            fetch_unavailable = True

        if fetch_unavailable:
            raise _JwksFetchUnavailableV1
        raise _JwksFetchUnavailableV1


@dataclass(frozen=True, slots=True, repr=False)
class _JwksSnapshotV1:
    keys_by_id: Mapping[str, tuple[Mapping[str, Any], ...]]
    fetched_at_monotonic: float
    generation: int


@dataclass(frozen=True, slots=True)
class _ValidatedHeaderV1:
    algorithm: str
    key_id: str


class OidcAccessTokenValidatorV1:
    """Strict asymmetric JWT validator for the configured resource server."""

    __slots__ = (
        "_allowed_algorithms",
        "_cache_lock",
        "_config",
        "_jwks_fetcher",
        "_jwks_snapshot",
        "_monotonic_clock",
        "_wall_clock",
    )

    def __init__(
        self,
        config: OidcResourceServerConfigV1,
        *,
        jwks_fetcher: JwksDocumentFetcherV1 | None = None,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ):
        self._config = config
        self._allowed_algorithms = frozenset(config.allowed_algorithms)
        self._jwks_fetcher = (
            jwks_fetcher if jwks_fetcher is not None else AiohttpJwksDocumentFetcherV1()
        )
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._cache_lock = asyncio.Lock()
        self._jwks_snapshot: _JwksSnapshotV1 | None = None

    async def validate_access_token(
        self,
        encoded_access_token: str,
    ) -> AuthenticatedPrincipalV1:
        """Validate the configured certificate-capture resource scope."""

        return await self._validate_access_token_for_required_scope(
            encoded_access_token,
            self._config.required_scope,
        )

    async def validate_access_token_for_scope(
        self,
        encoded_access_token: str,
        required_scope: OidcRequiredScopeV1,
    ) -> AuthenticatedPrincipalV1:
        """Validate one explicitly supported resource-server scope."""

        if required_scope not in {
            OIDC_CERTIFICATE_CAPTURE_SCOPE_V1,
            OIDC_MANAGER_SCOPE_V1,
        }:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SCOPE_INVALID
            )
        return await self._validate_access_token_for_required_scope(
            encoded_access_token,
            required_scope,
        )

    async def _validate_access_token_for_required_scope(
        self,
        encoded_access_token: str,
        required_scope: OidcRequiredScopeV1,
    ) -> AuthenticatedPrincipalV1:
        header = self._validate_header(encoded_access_token)
        snapshot = await self._get_jwks_snapshot()
        matching_keys = snapshot.keys_by_id.get(header.key_id, ())

        if not matching_keys:
            snapshot = await self._get_jwks_snapshot(
                force_refresh=True,
                observed_generation=snapshot.generation,
            )
            matching_keys = snapshot.keys_by_id.get(header.key_id, ())

        if not matching_keys:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_NOT_FOUND
            )

        signing_key = self._prepare_signing_key(
            matching_keys,
            header,
        )
        claims = self._verify_signature_and_decode_claims(
            encoded_access_token,
            header,
            signing_key,
        )
        return self._validate_claims(claims, required_scope)

    def _validate_header(
        self,
        encoded_access_token: str,
    ) -> _ValidatedHeaderV1:
        segments = _split_compact_jwt(encoded_access_token)
        header = _decode_json_object_from_segment(segments[0])
        if header is None:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_MALFORMED)

        algorithm = header.get("alg")
        if algorithm == "none":
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.ALGORITHM_NONE)
        if not isinstance(algorithm, str) or not algorithm:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.TOKEN_HEADER_INVALID
            )
        if algorithm not in self._allowed_algorithms:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.ALGORITHM_NOT_ALLOWED
            )
        if not segments[2]:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_MALFORMED)

        if "kid" not in header:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.KID_MISSING)
        key_id = header["kid"]
        if not _is_valid_key_id(key_id):
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.KID_INVALID)

        if "crit" in header or any(
            field in header for field in _TOKEN_CONTROLLED_KEY_HEADERS
        ):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.TOKEN_HEADER_INVALID
            )
        if "b64" in header and header["b64"] is not True:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.TOKEN_HEADER_INVALID
            )

        token_type = header.get("typ")
        if (
            not isinstance(token_type, str)
            or token_type.casefold() != _ACCESS_TOKEN_TYPE_V1
        ):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.ACCESS_TOKEN_FORM_INVALID
            )

        return _ValidatedHeaderV1(
            algorithm=algorithm,
            key_id=key_id,
        )

    async def _get_jwks_snapshot(
        self,
        *,
        force_refresh: bool = False,
        observed_generation: int | None = None,
    ) -> _JwksSnapshotV1:
        snapshot = self._jwks_snapshot
        if not force_refresh and self._snapshot_is_fresh(snapshot):
            return snapshot

        async with self._cache_lock:
            snapshot = self._jwks_snapshot
            if not force_refresh and self._snapshot_is_fresh(snapshot):
                return snapshot
            if (
                force_refresh
                and observed_generation is not None
                and snapshot is not None
                and snapshot.generation != observed_generation
                and self._snapshot_is_fresh(snapshot)
            ):
                return snapshot

            body = await self._fetch_jwks_document()
            keys_by_id = _parse_jwks_document(body)
            next_generation = 1 if snapshot is None else snapshot.generation + 1
            refreshed = _JwksSnapshotV1(
                keys_by_id=keys_by_id,
                fetched_at_monotonic=self._monotonic_clock(),
                generation=next_generation,
            )
            self._jwks_snapshot = refreshed
            return refreshed

    def _snapshot_is_fresh(
        self,
        snapshot: _JwksSnapshotV1 | None,
    ) -> bool:
        if snapshot is None:
            return False
        age = self._monotonic_clock() - snapshot.fetched_at_monotonic
        return 0 <= age < JWKS_CACHE_MAX_AGE_SECONDS_V1

    async def _fetch_jwks_document(self) -> bytes:
        fetch_failed = False
        response_too_large = False
        try:
            body = await self._jwks_fetcher.fetch(self._config.jwks_url)
        except _JwksResponseTooLargeV1:
            response_too_large = True
            body = b""
        # A custom fetcher must not let transport internals escape the
        # authentication boundary.
        except Exception:  # noqa: BLE001
            fetch_failed = True
            body = b""

        if response_too_large:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.JWKS_RESPONSE_TOO_LARGE
            )
        if fetch_failed:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.JWKS_UNAVAILABLE)
        if not isinstance(body, bytes) or len(body) > JWKS_MAX_RESPONSE_BYTES_V1:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.JWKS_RESPONSE_TOO_LARGE
            )
        return body

    def _prepare_signing_key(
        self,
        matching_keys: tuple[Mapping[str, Any], ...],
        header: _ValidatedHeaderV1,
    ) -> PyJWK:
        if len(matching_keys) != 1:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )

        jwk = matching_keys[0]
        expected_key_type, expected_curves = _EXPECTED_JWK_SHAPES[header.algorithm]
        if (
            jwk.get("kid") != header.key_id
            or jwk.get("kty") != expected_key_type
            or any(member in jwk for member in _PRIVATE_JWK_MEMBERS)
        ):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )

        declared_algorithm = jwk.get("alg")
        if declared_algorithm is not None and declared_algorithm != header.algorithm:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )
        public_key_use = jwk.get("use")
        if public_key_use is not None and public_key_use != "sig":
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )
        key_operations = jwk.get("key_ops")
        if key_operations is not None and (
            not isinstance(key_operations, list)
            or len(key_operations) != 1
            or any(not isinstance(operation, str) for operation in key_operations)
            or set(key_operations) != {"verify"}
        ):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )
        if expected_curves is not None and jwk.get("crv") not in (expected_curves):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )

        key_invalid = False
        try:
            signing_key = PyJWK.from_dict(
                dict(jwk),
                algorithm=header.algorithm,
            )
        # Key parser failures must remain value-free at the auth boundary.
        except Exception:  # noqa: BLE001
            key_invalid = True
            signing_key = None

        if key_invalid or signing_key is None:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )
        if not _key_matches_algorithm(signing_key, header.algorithm):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNING_KEY_INVALID
            )
        return signing_key

    def _verify_signature_and_decode_claims(
        self,
        encoded_access_token: str,
        header: _ValidatedHeaderV1,
        signing_key: PyJWK,
    ) -> Mapping[str, Any]:
        signature_invalid = False
        token_malformed = False
        algorithm_invalid = False
        try:
            decoded = jwt.api_jws.decode_complete(
                encoded_access_token,
                key=signing_key,
                algorithms=[header.algorithm],
                options={"verify_signature": True},
            )
        except InvalidSignatureError:
            signature_invalid = True
            decoded = None
        except InvalidAlgorithmError:
            algorithm_invalid = True
            decoded = None
        except (PyJWTError, TypeError, ValueError):
            token_malformed = True
            decoded = None

        if signature_invalid:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.SIGNATURE_INVALID
            )
        if algorithm_invalid:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.ALGORITHM_NOT_ALLOWED
            )
        if token_malformed or decoded is None:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_MALFORMED)

        payload = decoded.get("payload")
        claims = _decode_json_object(payload)
        if claims is None:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_MALFORMED)
        return claims

    def _validate_claims(
        self,
        claims: Mapping[str, Any],
        required_scope: OidcRequiredScopeV1,
    ) -> AuthenticatedPrincipalV1:
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer != self._config.issuer:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.ISSUER_INVALID)

        if not _audience_matches(
            claims.get("aud"),
            self._config.audience,
        ):
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.AUDIENCE_INVALID)

        expiration = _strict_numeric_date(claims, "exp")
        not_before = _strict_numeric_date(claims, "nbf")
        issued_at = _strict_numeric_date(claims, "iat")
        if (
            expiration is None
            or not_before is None
            or issued_at is None
            or not_before >= expiration
            or issued_at >= expiration
        ):
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.TEMPORAL_CLAIM_INVALID
            )

        try:
            now = self._wall_clock()
        # A clock failure is an availability failure, never a fail-open path.
        except Exception:  # noqa: BLE001
            clock_unavailable = True
            now = 0.0
        else:
            clock_unavailable = (
                isinstance(now, bool)
                or not isinstance(now, (int, float))
                or not math.isfinite(now)
            )
        if clock_unavailable:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.AUTHENTICATION_UNAVAILABLE
            )
        if expiration <= now:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_EXPIRED)
        if not_before > now or issued_at > now:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.TOKEN_NOT_YET_VALID
            )

        subject = claims.get("sub")
        if (
            not isinstance(subject, str)
            or not subject
            or subject != subject.strip()
            or len(subject) > _JWT_SUBJECT_MAX_CHARACTERS_V1
        ):
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.SUBJECT_INVALID)

        if "scope" not in claims:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING
            )
        scopes = _parse_scope_claim(claims.get("scope"))
        if scopes is None:
            raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.SCOPE_INVALID)
        if required_scope not in scopes:
            raise OidcAuthenticationErrorV1(
                OidcAuthenticationReasonV1.REQUIRED_SCOPE_MISSING
            )

        return AuthenticatedPrincipalV1(
            issuer=issuer,
            subject=subject,
            scopes=scopes,
            token_expiry_epoch_seconds=expiration,
        )


def create_oidc_access_token_validator_v1(
    feature_config: CertificateCaptureFeatureConfigV1,
    *,
    jwks_fetcher: JwksDocumentFetcherV1 | None = None,
    wall_clock: Callable[[], float] = time.time,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> OidcAccessTokenValidatorV1 | None:
    """Create the validator only for enabled certificate-capture mode."""

    if not feature_config.enabled:
        return None
    if feature_config.oidc is None:
        raise RuntimeError("Enabled certificate capture requires OIDC config.")
    return OidcAccessTokenValidatorV1(
        feature_config.oidc,
        jwks_fetcher=jwks_fetcher,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
    )


def _split_compact_jwt(encoded_access_token: str) -> tuple[str, str, str]:
    if (
        not isinstance(encoded_access_token, str)
        or not encoded_access_token
        or len(encoded_access_token) > _JWT_MAX_ENCODED_BYTES_V1
    ):
        raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_MALFORMED)

    segments = encoded_access_token.split(".")
    if (
        len(segments) != 3
        or not segments[0]
        or not segments[1]
        or not _JWT_SEGMENT_PATTERN.fullmatch(segments[0])
        or not _JWT_SEGMENT_PATTERN.fullmatch(segments[1])
        or (segments[2] and not _JWT_SEGMENT_PATTERN.fullmatch(segments[2]))
    ):
        raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.TOKEN_MALFORMED)
    return segments[0], segments[1], segments[2]


def _decode_json_object_from_segment(
    encoded_segment: str,
) -> Mapping[str, Any] | None:
    try:
        padded = encoded_segment + "=" * (-len(encoded_segment) % 4)
        decoded = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError, binascii.Error):
        decoded = None
    if decoded is None:
        return None
    canonical_segment = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical_segment != encoded_segment:
        return None
    return _decode_json_object(decoded)


def _decode_json_object(
    encoded_json: Any,
) -> Mapping[str, Any] | None:
    if not isinstance(encoded_json, bytes):
        return None
    try:
        decoded_text = encoded_json.decode("utf-8", errors="strict")
        decoded = json.loads(
            decoded_text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _InvalidJsonDocumentV1,
        RecursionError,
    ):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def _unique_json_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJsonDocumentV1
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise _InvalidJsonDocumentV1


def _is_valid_key_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _JWT_KID_MAX_CHARACTERS_V1
        and not value.isspace()
        and all(
            ord(character) >= 0x20 and ord(character) != 0x7F for character in value
        )
    )


def _parse_jwks_document(
    body: bytes,
) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
    document = _decode_json_object(body)
    if document is None:
        raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.JWKS_INVALID)
    keys = document.get("keys")
    if (
        not isinstance(keys, list)
        or len(keys) > _JWKS_MAX_KEYS_V1
        or any(not isinstance(key, dict) for key in keys)
    ):
        raise OidcAuthenticationErrorV1(OidcAuthenticationReasonV1.JWKS_INVALID)

    keys_by_id: dict[str, list[Mapping[str, Any]]] = {}
    for key in keys:
        key_id = key.get("kid")
        if not _is_valid_key_id(key_id):
            continue
        keys_by_id.setdefault(key_id, []).append(MappingProxyType(dict(key)))
    return MappingProxyType(
        {key_id: tuple(matching_keys) for key_id, matching_keys in keys_by_id.items()}
    )


def _key_matches_algorithm(signing_key: PyJWK, algorithm: str) -> bool:
    key = signing_key.key
    if algorithm.startswith(("RS", "PS")):
        return isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048
    if algorithm == "ES256":
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            key.curve,
            ec.SECP256R1,
        )
    if algorithm == "ES384":
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            key.curve,
            ec.SECP384R1,
        )
    if algorithm == "ES512":
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            key.curve,
            ec.SECP521R1,
        )
    if algorithm == "EdDSA":
        return isinstance(
            key,
            (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
        )
    return False


def _audience_matches(value: Any, configured_audience: str) -> bool:
    if isinstance(value, str):
        return bool(value) and value == configured_audience
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(audience, str) or not audience for audience in value)
        or len(set(value)) != len(value)
    ):
        return False
    return configured_audience in value


def _strict_numeric_date(
    claims: Mapping[str, Any],
    claim_name: str,
) -> int | None:
    value = claims.get(claim_name)
    if type(value) is not int or value < 0 or value > _MAX_NUMERIC_DATE_V1:
        return None
    return value


def _parse_scope_claim(value: Any) -> frozenset[str] | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _JWT_SCOPE_MAX_CHARACTERS_V1
        or not _SCOPE_PATTERN.fullmatch(value)
    ):
        return None
    scopes = value.split(" ")
    if len(set(scopes)) != len(scopes):
        return None
    return frozenset(scopes)

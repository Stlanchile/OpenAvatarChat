from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import aiohttp
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from loguru import logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
    OidcResourceServerConfigV1,
)
from service.service_security import oidc_resource_server
from service.service_security.oidc_resource_server import (
    JWKS_CACHE_MAX_AGE_SECONDS_V1,
    JWKS_FETCH_TIMEOUT_SECONDS_V1,
    JWKS_MAX_RESPONSE_BYTES_V1,
    OIDC_MANAGER_SCOPE_V1,
    AuthenticatedPrincipalV1,
    OidcAccessTokenValidatorV1,
    OidcAuthenticationErrorV1,
    create_oidc_access_token_validator_v1,
)

ISSUER = "https://issuer.example.test"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
AUDIENCE = "open-avatar-chat"
REQUIRED_SCOPE = "certificate:capture"
NOW = 2_000_000_000
_MISSING = object()


class FakeJwksFetcher:
    def __init__(self, responses: list[bytes | BaseException]):
        self._responses = list(responses)
        self.calls: list[str] = []

    async def fetch(self, configured_jwks_url: str) -> bytes:
        self.calls.append(configured_jwks_url)
        if not self._responses:
            raise AssertionError("unexpected JWKS fetch")
        response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class BlockingRefreshJwksFetcher:
    def __init__(self, initial: bytes, refreshed: bytes):
        self._initial = initial
        self._refreshed = refreshed
        self.calls: list[str] = []
        self.refresh_started = asyncio.Event()
        self.release_refresh = asyncio.Event()

    async def fetch(self, configured_jwks_url: str) -> bytes:
        self.calls.append(configured_jwks_url)
        if len(self.calls) == 1:
            return self._initial
        if len(self.calls) == 2:
            self.refresh_started.set()
            await self.release_refresh.wait()
            return self._refreshed
        raise AssertionError("unexpected JWKS fetch")


class FakeResponseContent:
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    async def iter_chunked(self, _: int):
        for chunk in self._chunks:
            yield chunk


class FakeAiohttpResponse:
    def __init__(
        self,
        *,
        status: int,
        chunks: list[bytes],
        content_length: int | None,
    ):
        self.status = status
        self.content_length = content_length
        self.content = FakeResponseContent(chunks)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False


class FakeAiohttpSession:
    def __init__(
        self,
        response: FakeAiohttpResponse,
        session_calls: list[dict[str, Any]],
        request_calls: list[tuple[str, dict[str, Any]]],
        **session_options: Any,
    ):
        session_calls.append(session_options)
        self._request_calls = request_calls
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False

    def get(
        self,
        configured_jwks_url: str,
        **request_options: Any,
    ) -> FakeAiohttpResponse:
        self._request_calls.append((configured_jwks_url, request_options))
        return self._response


@pytest.fixture(scope="module")
def signing_material() -> dict[str, Any]:
    first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return {
        "first_private": first,
        "first_jwk": _public_jwk(first, "key-1"),
        "second_private": second,
        "second_jwk": _public_jwk(second, "key-2"),
        "attacker_private": attacker,
    }


def _public_jwk(
    private_key: rsa.RSAPrivateKey,
    key_id: str,
) -> dict[str, Any]:
    jwk = RSAAlgorithm.to_jwk(
        private_key.public_key(),
        as_dict=True,
    )
    jwk.update(
        {
            "alg": "RS256",
            "kid": key_id,
            "key_ops": ["verify"],
            "use": "sig",
        }
    )
    return jwk


def _jwks(*keys: dict[str, Any]) -> bytes:
    return json.dumps(
        {"keys": list(keys)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _oidc_config(
    *,
    allowed_algorithms: tuple[str, ...] = ("RS256",),
) -> OidcResourceServerConfigV1:
    return OidcResourceServerConfigV1.model_validate(
        {
            "issuer": ISSUER,
            "jwks_url": JWKS_URL,
            "audience": AUDIENCE,
            "allowed_algorithms": allowed_algorithms,
            "required_scope": REQUIRED_SCOPE,
        }
    )


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "nbf": NOW - 10,
        "iat": NOW - 10,
        "sub": "principal-123",
        "scope": f"openid {REQUIRED_SCOPE}",
    }
    for name, value in overrides.items():
        if value is _MISSING:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


def _signed_token(
    private_key: rsa.RSAPrivateKey,
    *,
    key_id: Any = "key-1",
    claims: dict[str, Any] | None = None,
    algorithm: str = "RS256",
    token_type: str = "at+jwt",
    extra_headers: dict[str, Any] | None = None,
) -> str:
    headers: dict[str, Any] = {"kid": key_id, "typ": token_type}
    if extra_headers:
        headers.update(extra_headers)
    return jwt.encode(
        claims if claims is not None else _claims(),
        private_key,
        algorithm=algorithm,
        headers=headers,
    )


def _replace_unverified_header(
    token: str,
    header: dict[str, Any],
) -> str:
    encoded_header = jwt.utils.base64url_encode(
        json.dumps(
            header,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    return ".".join([encoded_header, *token.split(".")[1:]])


def _validator(
    fetcher: FakeJwksFetcher,
    *,
    monotonic_clock=lambda: 100.0,
) -> OidcAccessTokenValidatorV1:
    return OidcAccessTokenValidatorV1(
        _oidc_config(),
        jwks_fetcher=fetcher,
        wall_clock=lambda: NOW,
        monotonic_clock=monotonic_clock,
    )


async def _assert_rejected(
    validator: OidcAccessTokenValidatorV1,
    token: str,
    reason_code: str,
) -> OidcAuthenticationErrorV1:
    with pytest.raises(OidcAuthenticationErrorV1) as exception:
        await validator.validate_access_token(token)
    assert exception.value.reason_code == reason_code
    assert exception.value.__cause__ is None
    assert exception.value.__context__ is None
    return exception.value


@pytest.mark.asyncio
async def test_valid_token_returns_immutable_redacted_principal(
    signing_material,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(signing_material["first_private"])

    principal = await validator.validate_access_token(token)

    assert principal == AuthenticatedPrincipalV1(
        issuer=ISSUER,
        subject="principal-123",
        scopes=frozenset({"openid", REQUIRED_SCOPE}),
        token_expiry_epoch_seconds=NOW + 300,
    )
    assert repr(principal) == "AuthenticatedPrincipalV1(<redacted>)"
    assert fetcher.calls == [JWKS_URL]
    with pytest.raises(FrozenInstanceError):
        principal.subject = "replacement"


@pytest.mark.asyncio
async def test_purpose_specific_scope_validation_never_treats_scopes_as_or():
    signing_material = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    signing_jwk = _public_jwk(signing_material, "scope-key")
    fetcher = FakeJwksFetcher([_jwks(signing_jwk)])
    validator = _validator(fetcher)
    certificate_only = _signed_token(
        signing_material,
        key_id="scope-key",
        claims=_claims(scope=REQUIRED_SCOPE),
    )
    manager_only = _signed_token(
        signing_material,
        key_id="scope-key",
        claims=_claims(scope=OIDC_MANAGER_SCOPE_V1),
    )
    both = _signed_token(
        signing_material,
        key_id="scope-key",
        claims=_claims(scope=f"{REQUIRED_SCOPE} {OIDC_MANAGER_SCOPE_V1}"),
    )

    certificate_principal = await validator.validate_access_token(
        certificate_only
    )
    manager_principal = await validator.validate_access_token_for_scope(
        manager_only,
        OIDC_MANAGER_SCOPE_V1,
    )
    both_certificate = await validator.validate_access_token(both)
    both_manager = await validator.validate_access_token_for_scope(
        both,
        OIDC_MANAGER_SCOPE_V1,
    )

    assert certificate_principal.scopes == frozenset({REQUIRED_SCOPE})
    assert manager_principal.scopes == frozenset({OIDC_MANAGER_SCOPE_V1})
    assert both_certificate == both_manager
    with pytest.raises(OidcAuthenticationErrorV1) as manager_denied:
        await validator.validate_access_token(manager_only)
    with pytest.raises(OidcAuthenticationErrorV1) as certificate_denied:
        await validator.validate_access_token_for_scope(
            certificate_only,
            OIDC_MANAGER_SCOPE_V1,
        )
    assert manager_denied.value.reason_code == "REQUIRED_SCOPE_MISSING"
    assert certificate_denied.value.reason_code == "REQUIRED_SCOPE_MISSING"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_kind", "reason_code"),
    [
        ("signature", "SIGNATURE_INVALID"),
        ("issuer", "ISSUER_INVALID"),
        ("audience", "AUDIENCE_INVALID"),
        ("expiry", "TOKEN_EXPIRED"),
    ],
)
async def test_manager_scope_keeps_existing_cryptographic_and_claim_failures(
    signing_material,
    failure_kind,
    reason_code,
):
    claims = _claims(scope=OIDC_MANAGER_SCOPE_V1)
    private_key = signing_material["first_private"]
    if failure_kind == "signature":
        private_key = signing_material["attacker_private"]
    elif failure_kind == "issuer":
        claims["iss"] = "https://wrong-issuer.example.test"
    elif failure_kind == "audience":
        claims["aud"] = "wrong-audience"
    elif failure_kind == "expiry":
        claims["exp"] = NOW
    token = _signed_token(
        private_key,
        key_id="key-1",
        claims=claims,
    )
    validator = _validator(
        FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    )

    with pytest.raises(OidcAuthenticationErrorV1) as exception:
        await validator.validate_access_token_for_scope(
            token,
            OIDC_MANAGER_SCOPE_V1,
        )

    assert exception.value.reason_code == reason_code


@pytest.mark.asyncio
async def test_bad_signature_is_rejected(signing_material):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["attacker_private"],
        key_id="key-1",
    )

    await _assert_rejected(validator, token, "SIGNATURE_INVALID")


@pytest.mark.asyncio
async def test_alg_none_is_rejected_before_jwks_fetch(signing_material):
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)
    token = jwt.encode(
        _claims(),
        key="",
        algorithm="none",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )

    await _assert_rejected(validator, token, "ALGORITHM_NONE")
    assert fetcher.calls == []


@pytest.mark.asyncio
async def test_hmac_rsa_algorithm_confusion_is_rejected_before_fetch(
    signing_material,
):
    public_der = (
        signing_material["first_private"]
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    token = jwt.encode(
        _claims(),
        public_der,
        algorithm="HS256",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)

    await _assert_rejected(
        validator,
        token,
        "ALGORITHM_NOT_ALLOWED",
    )
    assert fetcher.calls == []


@pytest.mark.asyncio
async def test_jwk_algorithm_confusion_is_rejected(signing_material):
    confused_jwk = dict(signing_material["first_jwk"])
    confused_jwk["alg"] = "HS256"
    fetcher = FakeJwksFetcher([_jwks(confused_jwk)])
    validator = _validator(fetcher)
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(
        validator,
        token,
        "SIGNING_KEY_INVALID",
    )


@pytest.mark.asyncio
async def test_disallowed_asymmetric_algorithm_is_rejected_before_fetch(
    signing_material,
):
    token = _signed_token(
        signing_material["first_private"],
        algorithm="PS256",
    )
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)

    await _assert_rejected(
        validator,
        token,
        "ALGORITHM_NOT_ALLOWED",
    )
    assert fetcher.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        "",
        "opaque-access-token",
        "a.b.c",
        "a.b.c.d.e",
        "eyJhbGciOiJSUzI1NiJ9..signature",
    ],
)
async def test_malformed_jwts_are_rejected_without_fetch(token):
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)

    await _assert_rejected(validator, token, "TOKEN_MALFORMED")
    assert fetcher.calls == []


@pytest.mark.asyncio
async def test_token_controlled_key_url_is_rejected_without_fetch(
    signing_material,
):
    token = _signed_token(
        signing_material["first_private"],
        extra_headers={
            "jku": "https://attacker.invalid/keys",
        },
    )
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)

    await _assert_rejected(
        validator,
        token,
        "TOKEN_HEADER_INVALID",
    )
    assert fetcher.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("token_type", [None, "JWT", "application/at+jwt"])
async def test_non_access_token_type_is_rejected_without_fetch(
    signing_material,
    token_type,
):
    if token_type is None:
        token = _replace_unverified_header(
            _signed_token(signing_material["first_private"]),
            {"alg": "RS256", "kid": "key-1"},
        )
    else:
        token = _signed_token(
            signing_material["first_private"],
            token_type=token_type,
        )
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)

    await _assert_rejected(
        validator,
        token,
        "ACCESS_TOKEN_FORM_INVALID",
    )
    assert fetcher.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim_overrides", "reason_code"),
    [
        ({"iss": "https://other.example.test"}, "ISSUER_INVALID"),
        ({"aud": "other-resource"}, "AUDIENCE_INVALID"),
        ({"aud": ["other-resource", "another"]}, "AUDIENCE_INVALID"),
    ],
)
async def test_issuer_and_audience_mismatches_are_rejected(
    signing_material,
    claim_overrides,
    reason_code,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(**claim_overrides),
    )

    await _assert_rejected(validator, token, reason_code)


@pytest.mark.asyncio
async def test_expired_token_is_rejected_at_the_exact_boundary(
    signing_material,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(exp=NOW),
    )

    await _assert_rejected(validator, token, "TOKEN_EXPIRED")


@pytest.mark.asyncio
async def test_nbf_and_iat_exact_boundaries_are_valid(signing_material):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(nbf=NOW, iat=NOW, exp=NOW + 1),
    )

    principal = await validator.validate_access_token(token)

    assert principal.subject == "principal-123"


@pytest.mark.asyncio
@pytest.mark.parametrize("future_claim", ["nbf", "iat"])
async def test_future_nbf_or_iat_is_rejected(
    signing_material,
    future_claim,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(**{future_claim: NOW + 1}),
    )

    await _assert_rejected(
        validator,
        token,
        "TOKEN_NOT_YET_VALID",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("claim_name", ["exp", "nbf", "iat"])
@pytest.mark.parametrize(
    "malformed_value",
    [_MISSING, None, True, "2000000300", 2_000_000_300.5],
)
async def test_missing_or_malformed_temporal_claims_are_rejected(
    signing_material,
    claim_name,
    malformed_value,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(**{claim_name: malformed_value}),
    )

    await _assert_rejected(
        validator,
        token,
        "TEMPORAL_CLAIM_INVALID",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "subject",
    [_MISSING, None, "", "   ", " surrounded ", 123],
)
async def test_missing_or_malformed_subject_is_rejected(
    signing_material,
    subject,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(sub=subject),
    )

    await _assert_rejected(validator, token, "SUBJECT_INVALID")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scope", "reason_code"),
    [
        (_MISSING, "REQUIRED_SCOPE_MISSING"),
        ("openid profile", "REQUIRED_SCOPE_MISSING"),
        (["openid", REQUIRED_SCOPE], "SCOPE_INVALID"),
        (f"openid  {REQUIRED_SCOPE}", "SCOPE_INVALID"),
    ],
)
async def test_missing_required_or_malformed_scope_is_rejected(
    signing_material,
    scope,
    reason_code,
):
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(scope=scope),
    )

    await _assert_rejected(validator, token, reason_code)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key_id", "reason_code"),
    [
        (_MISSING, "KID_MISSING"),
        ("", "KID_INVALID"),
        (123, "KID_INVALID"),
    ],
)
async def test_missing_or_invalid_kid_is_rejected_without_fetch(
    signing_material,
    key_id,
    reason_code,
):
    if key_id is _MISSING:
        token = jwt.encode(
            _claims(),
            signing_material["first_private"],
            algorithm="RS256",
            headers={"typ": "at+jwt"},
        )
    elif not isinstance(key_id, str):
        token = _replace_unverified_header(
            _signed_token(signing_material["first_private"]),
            {
                "alg": "RS256",
                "kid": key_id,
                "typ": "at+jwt",
            },
        )
    else:
        token = _signed_token(
            signing_material["first_private"],
            key_id=key_id,
        )
    fetcher = FakeJwksFetcher([])
    validator = _validator(fetcher)

    await _assert_rejected(validator, token, reason_code)
    assert fetcher.calls == []


@pytest.mark.asyncio
async def test_unknown_kid_succeeds_after_exactly_one_refresh(
    signing_material,
):
    fetcher = FakeJwksFetcher(
        [
            _jwks(signing_material["first_jwk"]),
            _jwks(
                signing_material["first_jwk"],
                signing_material["second_jwk"],
            ),
        ]
    )
    validator = _validator(fetcher)
    first_token = _signed_token(signing_material["first_private"])
    rotated_token = _signed_token(
        signing_material["second_private"],
        key_id="key-2",
    )

    await validator.validate_access_token(first_token)
    principal = await validator.validate_access_token(rotated_token)

    assert principal.subject == "principal-123"
    assert fetcher.calls == [JWKS_URL, JWKS_URL]


@pytest.mark.asyncio
async def test_unknown_kid_fails_after_one_refresh(signing_material):
    fetcher = FakeJwksFetcher(
        [
            _jwks(signing_material["first_jwk"]),
            _jwks(signing_material["first_jwk"]),
        ]
    )
    validator = _validator(fetcher)
    await validator.validate_access_token(
        _signed_token(signing_material["first_private"])
    )
    unknown_token = _signed_token(
        signing_material["second_private"],
        key_id="key-2",
    )

    await _assert_rejected(
        validator,
        unknown_token,
        "SIGNING_KEY_NOT_FOUND",
    )
    assert fetcher.calls == [JWKS_URL, JWKS_URL]


@pytest.mark.asyncio
async def test_concurrent_unknown_kid_requests_share_one_refresh(
    signing_material,
):
    fetcher = BlockingRefreshJwksFetcher(
        _jwks(signing_material["first_jwk"]),
        _jwks(
            signing_material["first_jwk"],
            signing_material["second_jwk"],
        ),
    )
    validator = OidcAccessTokenValidatorV1(
        _oidc_config(),
        jwks_fetcher=fetcher,
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 100.0,
    )
    await validator.validate_access_token(
        _signed_token(signing_material["first_private"])
    )
    rotated_token = _signed_token(
        signing_material["second_private"],
        key_id="key-2",
    )

    first = asyncio.create_task(validator.validate_access_token(rotated_token))
    await fetcher.refresh_started.wait()
    second = asyncio.create_task(validator.validate_access_token(rotated_token))
    await asyncio.sleep(0)
    fetcher.release_refresh.set()
    principals = await asyncio.gather(first, second)

    assert [principal.subject for principal in principals] == [
        "principal-123",
        "principal-123",
    ]
    assert fetcher.calls == [JWKS_URL, JWKS_URL]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("jwks_body", "reason_code"),
    [
        (b'{"keys":"not-a-list"}', "JWKS_INVALID"),
        (b'{"keys":[42]}', "JWKS_INVALID"),
        (b'{"keys":[],"keys":[]}', "JWKS_INVALID"),
    ],
)
async def test_malformed_jwks_is_rejected(
    signing_material,
    jwks_body,
    reason_code,
):
    fetcher = FakeJwksFetcher([jwks_body])
    validator = _validator(fetcher)
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(validator, token, reason_code)


@pytest.mark.asyncio
async def test_malformed_matching_key_is_rejected(signing_material):
    malformed_key = dict(signing_material["first_jwk"])
    malformed_key.pop("n")
    fetcher = FakeJwksFetcher([_jwks(malformed_key)])
    validator = _validator(fetcher)
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(
        validator,
        token,
        "SIGNING_KEY_INVALID",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fetch_failure",
    [
        TimeoutError(),
        aiohttp.ClientConnectionError(),
        OSError(),
    ],
)
async def test_timeout_and_fetch_failures_are_authentication_unavailable(
    signing_material,
    fetch_failure,
):
    fetcher = FakeJwksFetcher([fetch_failure])
    validator = _validator(fetcher)
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(validator, token, "JWKS_UNAVAILABLE")


@pytest.mark.asyncio
async def test_default_fetcher_rejects_redirects_and_uses_bounded_timeout(
    signing_material,
    monkeypatch,
):
    session_calls: list[dict[str, Any]] = []
    request_calls: list[tuple[str, dict[str, Any]]] = []
    response = FakeAiohttpResponse(
        status=302,
        chunks=[],
        content_length=0,
    )

    def session_factory(**session_options):
        return FakeAiohttpSession(
            response,
            session_calls,
            request_calls,
            **session_options,
        )

    monkeypatch.setattr(
        oidc_resource_server.aiohttp,
        "ClientSession",
        session_factory,
    )
    validator = OidcAccessTokenValidatorV1(
        _oidc_config(),
        wall_clock=lambda: NOW,
    )
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(validator, token, "JWKS_UNAVAILABLE")

    assert len(session_calls) == 1
    timeout = session_calls[0]["timeout"]
    assert timeout.total == JWKS_FETCH_TIMEOUT_SECONDS_V1
    assert timeout.connect <= timeout.total
    assert session_calls[0]["trust_env"] is False
    assert request_calls == [
        (
            JWKS_URL,
            {
                "allow_redirects": False,
                "headers": {"Accept": "application/json"},
            },
        )
    ]


@pytest.mark.asyncio
async def test_oversized_jwks_response_is_rejected(signing_material):
    fetcher = FakeJwksFetcher([b" " * (JWKS_MAX_RESPONSE_BYTES_V1 + 1)])
    validator = _validator(fetcher)
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(
        validator,
        token,
        "JWKS_RESPONSE_TOO_LARGE",
    )


@pytest.mark.asyncio
async def test_streamed_oversized_jwks_without_content_length_is_rejected(
    signing_material,
    monkeypatch,
):
    response = FakeAiohttpResponse(
        status=200,
        chunks=[b"x" * (64 * 1024) for _ in range(17)],
        content_length=None,
    )

    def session_factory(**session_options):
        return FakeAiohttpSession(
            response,
            [],
            [],
            **session_options,
        )

    monkeypatch.setattr(
        oidc_resource_server.aiohttp,
        "ClientSession",
        session_factory,
    )
    validator = OidcAccessTokenValidatorV1(
        _oidc_config(),
        wall_clock=lambda: NOW,
    )
    token = _signed_token(signing_material["first_private"])

    await _assert_rejected(
        validator,
        token,
        "JWKS_RESPONSE_TOO_LARGE",
    )


@pytest.mark.asyncio
async def test_expired_jwks_cache_is_never_used_as_fallback(
    signing_material,
):
    monotonic = [10.0]
    fetcher = FakeJwksFetcher(
        [
            _jwks(signing_material["first_jwk"]),
            TimeoutError(),
        ]
    )
    validator = _validator(
        fetcher,
        monotonic_clock=lambda: monotonic[0],
    )
    token = _signed_token(signing_material["first_private"])
    await validator.validate_access_token(token)
    monotonic[0] += JWKS_CACHE_MAX_AGE_SECONDS_V1

    await _assert_rejected(validator, token, "JWKS_UNAVAILABLE")
    assert fetcher.calls == [JWKS_URL, JWKS_URL]


@pytest.mark.asyncio
async def test_authentication_failures_do_not_expose_token_claims_or_keys(
    signing_material,
    capsys,
):
    subject_canary = "subject-canary-never-log"
    claim_canary = "claim-canary-never-log"
    token = _signed_token(
        signing_material["first_private"],
        claims=_claims(
            iss="https://wrong.example.test",
            sub=subject_canary,
            private_claim=claim_canary,
        ),
    )
    key_canary = signing_material["first_jwk"]["n"]
    fetcher = FakeJwksFetcher([_jwks(signing_material["first_jwk"])])
    validator = _validator(fetcher)
    log_messages: list[str] = []
    sink_id = logger.add(
        lambda message: log_messages.append(str(message)),
        level="TRACE",
    )
    try:
        exception = await _assert_rejected(
            validator,
            token,
            "ISSUER_INVALID",
        )
    finally:
        logger.remove(sink_id)

    captured = capsys.readouterr()
    visible_output = (
        str(exception)
        + repr(exception)
        + captured.out
        + captured.err
        + "".join(log_messages)
    )
    canaries = [
        token,
        *token.split("."),
        subject_canary,
        claim_canary,
        key_canary,
    ]
    assert all(canary not in visible_output for canary in canaries)


@pytest.mark.asyncio
async def test_disabled_mode_creates_no_validator_or_jwks_work():
    feature_config = CertificateCaptureFeatureConfigV1()
    fetcher = FakeJwksFetcher([b'{"keys":[]}'])

    validator = create_oidc_access_token_validator_v1(
        feature_config,
        jwks_fetcher=fetcher,
    )
    await asyncio.sleep(0)

    assert validator is None
    assert fetcher.calls == []


def test_enabled_factory_is_lazy_and_uses_bounded_v1_limits():
    feature_config = CertificateCaptureFeatureConfigV1.model_validate(
        {
            "enabled": True,
            "oidc": {
                "issuer": ISSUER,
                "jwks_url": JWKS_URL,
                "audience": AUDIENCE,
                "allowed_algorithms": ["RS256"],
                "required_scope": REQUIRED_SCOPE,
            },
        }
    )
    fetcher = FakeJwksFetcher([b'{"keys":[]}'])

    validator = create_oidc_access_token_validator_v1(
        feature_config,
        jwks_fetcher=fetcher,
    )

    assert isinstance(validator, OidcAccessTokenValidatorV1)
    assert fetcher.calls == []
    assert 0 < JWKS_FETCH_TIMEOUT_SECONDS_V1 <= 5
    assert JWKS_MAX_RESPONSE_BYTES_V1 == 1024 * 1024
    assert JWKS_CACHE_MAX_AGE_SECONDS_V1 == 5 * 60

from typing import Literal
from urllib.parse import urlsplit

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

AsymmetricJwtAlgorithmV1 = Literal[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
]

_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


class OidcResourceServerConfigV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    issuer: StrictStr = Field(min_length=1, max_length=2048, repr=False)
    jwks_url: StrictStr = Field(min_length=1, max_length=2048, repr=False)
    audience: StrictStr = Field(min_length=1, max_length=2048, repr=False)
    allowed_algorithms: tuple[AsymmetricJwtAlgorithmV1, ...] = Field(
        min_length=1,
        max_length=10,
    )
    required_scope: Literal["certificate:capture"] = Field(repr=False)

    @field_validator("issuer", "jwks_url")
    @classmethod
    def validate_https_url(cls, value: str) -> str:
        if value != value.strip() or any(character.isspace() for character in value):
            raise ValueError("must be an absolute HTTPS URL")

        try:
            validated_url = _HTTP_URL_ADAPTER.validate_python(
                value,
                strict=True,
            )
            parsed = urlsplit(value)
        except (ValidationError, ValueError):
            invalid_url = True
        else:
            invalid_url = False

        if invalid_url:
            raise ValueError("must be an absolute HTTPS URL")

        if (
            validated_url.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("must be an absolute HTTPS URL")
        return value

    @field_validator("issuer")
    @classmethod
    def validate_issuer_identifier(cls, value: str) -> str:
        if urlsplit(value).query:
            raise ValueError("issuer URL must not contain a query")
        return value

    @field_validator("audience")
    @classmethod
    def validate_audience(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("audience must not contain surrounding whitespace")
        return value

    @field_validator("allowed_algorithms")
    @classmethod
    def validate_unique_algorithms(
        cls,
        value: tuple[AsymmetricJwtAlgorithmV1, ...],
    ) -> tuple[AsymmetricJwtAlgorithmV1, ...]:
        if len(set(value)) != len(value):
            raise ValueError("allowed algorithms must be unique")
        return value


class CertificateCaptureFeatureConfigV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    enabled: StrictBool = False
    oidc: OidcResourceServerConfigV1 | None = None

    @model_validator(mode="after")
    def require_oidc_when_enabled(self) -> "CertificateCaptureFeatureConfigV1":
        if self.enabled and self.oidc is None:
            raise ValueError(
                "OIDC resource-server configuration is required when enabled"
            )
        return self

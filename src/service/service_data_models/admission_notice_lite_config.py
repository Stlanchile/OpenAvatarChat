import os

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
)


class AdmissionNoticeLiteFeatureConfigV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    enabled: StrictBool = False
    recognition_ttl_seconds: StrictInt = Field(default=120, ge=1, le=3600)
    max_global_recognition_jobs: StrictInt = Field(default=1, ge=1, le=32)
    ocr_socket_path: StrictStr = "/run/openavatarchat-admission-lite/ocr.sock"
    ocr_connect_timeout_seconds: StrictFloat = Field(default=1.0, ge=0.05, le=2.0)
    ocr_timeout_seconds: StrictFloat = Field(default=30.0, ge=1.0, le=60.0)

    @field_validator("ocr_socket_path")
    @classmethod
    def validate_ocr_socket_path(cls, value: str) -> str:
        if (
            not value
            or "\x00" in value
            or not os.path.isabs(value)
            or len(os.fsencode(value)) > 100
        ):
            raise ValueError("ocr_socket_path must be a bounded absolute Unix path")
        return value

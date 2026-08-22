from pydantic import BaseModel, ConfigDict, Field

from service.service_data_models.certificate_capture_config import (
    CertificateCaptureFeatureConfigV1,
)


class ServiceConfigData(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080)
    cert_file: str | None = Field(default=None)
    cert_key: str | None = Field(default=None)
    workers: int = Field(default=1, ge=1, strict=True)
    certificate_capture: CertificateCaptureFeatureConfigV1 = Field(
        default_factory=CertificateCaptureFeatureConfigV1
    )

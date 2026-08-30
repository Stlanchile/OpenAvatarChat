from typing import Optional, Dict

from pydantic import BaseModel, Field

from service.service_data_models.admission_notice_lite_config import (
    AdmissionNoticeLiteFeatureConfigV1,
)


class ServiceConfigData(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080)
    cert_file: Optional[str] = Field(default=None)
    cert_key: Optional[str] = Field(default=None)
    admission_notice_lite: AdmissionNoticeLiteFeatureConfigV1 = Field(
        default_factory=AdmissionNoticeLiteFeatureConfigV1
    )

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt


class AdmissionNoticeLiteFeatureConfigV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    enabled: StrictBool = False
    recognition_ttl_seconds: StrictInt = Field(default=120, ge=1, le=3600)
    max_global_recognition_jobs: StrictInt = Field(default=1, ge=1, le=32)

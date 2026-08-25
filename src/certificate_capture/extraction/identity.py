"""Fixed identity for the Milestone 6B deterministic extraction rules."""

from certificate_capture.contracts.admission_notice import (
    AdmissionNoticeExtractionIdentityV1,
)

ADMISSION_NOTICE_EXTRACTOR_ID_V1 = "admission-notice-extractor.v1"
ADMISSION_NOTICE_RULE_SET_VERSION_V1 = "admission-notice-rules.v1"
ADMISSION_NOTICE_NORMALIZATION_VERSION_V1 = "admission-notice-normalization.v1"

DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1 = AdmissionNoticeExtractionIdentityV1(
    extractor_id=ADMISSION_NOTICE_EXTRACTOR_ID_V1,
    rule_set_version=ADMISSION_NOTICE_RULE_SET_VERSION_V1,
    normalization_version=ADMISSION_NOTICE_NORMALIZATION_VERSION_V1,
)

__all__ = [
    "ADMISSION_NOTICE_EXTRACTOR_ID_V1",
    "ADMISSION_NOTICE_NORMALIZATION_VERSION_V1",
    "ADMISSION_NOTICE_RULE_SET_VERSION_V1",
    "DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1",
]

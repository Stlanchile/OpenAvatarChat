"""Private deterministic admission-notice extraction for Milestone 6B."""

from certificate_capture.extraction.admission_notice import (
    AdmissionNoticeExtractorV1,
)
from certificate_capture.extraction.identity import (
    ADMISSION_NOTICE_EXTRACTOR_ID_V1,
    ADMISSION_NOTICE_NORMALIZATION_VERSION_V1,
    ADMISSION_NOTICE_RULE_SET_VERSION_V1,
    DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1,
)

__all__ = [
    "ADMISSION_NOTICE_EXTRACTOR_ID_V1",
    "ADMISSION_NOTICE_NORMALIZATION_VERSION_V1",
    "ADMISSION_NOTICE_RULE_SET_VERSION_V1",
    "DEFAULT_ADMISSION_NOTICE_EXTRACTION_IDENTITY_V1",
    "AdmissionNoticeExtractorV1",
]

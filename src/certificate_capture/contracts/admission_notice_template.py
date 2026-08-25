"""Single-school admission-notice template contract for Milestone 6C."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

ADMISSION_NOTICE_TEMPLATE_DESCRIPTOR_SCHEMA_VERSION_V1 = (
    "oac.admission-notice-template.v1"
)
ADMISSION_NOTICE_TEMPLATE_MATCH_SCHEMA_VERSION_V1 = (
    "oac.admission-notice-template-match.v1"
)

HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1 = "hbtc_admission_notice_v1"
HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1 = "湖北交通职业技术学院"
HBTC_ADMISSION_NOTICE_EXTRACTOR_ID_V1 = "admission-notice-extractor.v1"
HBTC_ADMISSION_NOTICE_TEMPLATE_MATCH_RULE_VERSION_V1 = (
    "hbtc-admission-notice-template-match.v1"
)

INSTITUTION_HEADING_ANCHOR_ID_V1 = "institution-heading"
STUDENT_SALUTATION_ANCHOR_ID_V1 = "student-salutation"
ADMISSION_COMMITTEE_ANCHOR_ID_V1 = "admission-committee"
ADMISSION_BODY_ANCHOR_ID_V1 = "admission-body"
MAJOR_STUDY_ANCHOR_ID_V1 = "major-study"

ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1 = (
    INSTITUTION_HEADING_ANCHOR_ID_V1,
    STUDENT_SALUTATION_ANCHOR_ID_V1,
    ADMISSION_COMMITTEE_ANCHOR_ID_V1,
    ADMISSION_BODY_ANCHOR_ID_V1,
    MAJOR_STUDY_ANCHOR_ID_V1,
)
ADMISSION_NOTICE_BODY_ANCHOR_IDS_V1 = (
    STUDENT_SALUTATION_ANCHOR_ID_V1,
    ADMISSION_COMMITTEE_ANCHOR_ID_V1,
    ADMISSION_BODY_ANCHOR_ID_V1,
    MAJOR_STUDY_ANCHOR_ID_V1,
)
MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1 = 3


class AdmissionNoticeTemplateMatchStatusV1(str, Enum):
    """Closed parsing-compatibility status vocabulary."""

    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass(frozen=True, slots=True)
class AdmissionNoticeTemplateV1:
    """The only trusted server-owned admission-notice template in V1."""

    template_id: str = HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
    institution_name: str = HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
    extractor_id: str = HBTC_ADMISSION_NOTICE_EXTRACTOR_ID_V1
    schema_version: str = ADMISSION_NOTICE_TEMPLATE_DESCRIPTOR_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ADMISSION_NOTICE_TEMPLATE_DESCRIPTOR_SCHEMA_VERSION_V1
            or self.template_id != HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
            or self.institution_name != HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1
            or self.extractor_id != HBTC_ADMISSION_NOTICE_EXTRACTOR_ID_V1
        ):
            raise ValueError("unsupported admission-notice template")

    def canonical_object_v1(self) -> dict[str, str]:
        return {
            "extractor_id": self.extractor_id,
            "institution_name": self.institution_name,
            "schema_version": self.schema_version,
            "template_id": self.template_id,
        }


HBTC_ADMISSION_NOTICE_TEMPLATE_V1 = AdmissionNoticeTemplateV1()


@dataclass(frozen=True, slots=True, kw_only=True)
class AdmissionNoticeTemplateMatchV1:
    """A deterministic parsing-compatibility decision.

    ``MATCHED`` means only that OCR text and layout are compatible with the
    fixed extractor. It does not establish authenticity, validity, issuance,
    or issuer verification.
    """

    status: AdmissionNoticeTemplateMatchStatusV1
    matched_anchor_ids: tuple[str, ...]
    template_id: str = HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1
    schema_version: str = ADMISSION_NOTICE_TEMPLATE_MATCH_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != ADMISSION_NOTICE_TEMPLATE_MATCH_SCHEMA_VERSION_V1:
            raise ValueError("unsupported template-match schema")
        if self.template_id != HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1:
            raise ValueError("unsupported admission-notice template")
        if not isinstance(self.status, AdmissionNoticeTemplateMatchStatusV1):
            raise TypeError("status must be AdmissionNoticeTemplateMatchStatusV1")
        if (
            not isinstance(self.matched_anchor_ids, tuple)
            or len(set(self.matched_anchor_ids)) != len(self.matched_anchor_ids)
            or any(
                not isinstance(anchor_id, str)
                or anchor_id not in ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1
                for anchor_id in self.matched_anchor_ids
            )
            or self.matched_anchor_ids
            != tuple(
                anchor_id
                for anchor_id in ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1
                if anchor_id in self.matched_anchor_ids
            )
        ):
            raise ValueError("template-match anchor IDs are invalid")
        body_count = sum(
            anchor_id in self.matched_anchor_ids
            for anchor_id in ADMISSION_NOTICE_BODY_ANCHOR_IDS_V1
        )
        matched_policy_satisfied = bool(
            INSTITUTION_HEADING_ANCHOR_ID_V1 in self.matched_anchor_ids
            and body_count >= MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1
        )
        if (
            self.status is AdmissionNoticeTemplateMatchStatusV1.MATCHED
            and not matched_policy_satisfied
        ):
            raise ValueError("MATCHED template result lacks required anchors")
        if (
            self.status is AdmissionNoticeTemplateMatchStatusV1.INSUFFICIENT
            and matched_policy_satisfied
        ):
            raise ValueError("INSUFFICIENT template result satisfies match policy")
        if (
            self.status is AdmissionNoticeTemplateMatchStatusV1.NOT_MATCHED
            and self.matched_anchor_ids
        ):
            raise ValueError("NOT_MATCHED template result must not retain anchors")

    def canonical_object_v1(self) -> dict[str, object]:
        return {
            "matched_anchor_ids": list(self.matched_anchor_ids),
            "schema_version": self.schema_version,
            "status": self.status.value,
            "template_id": self.template_id,
        }


__all__ = [
    "ADMISSION_BODY_ANCHOR_ID_V1",
    "ADMISSION_COMMITTEE_ANCHOR_ID_V1",
    "ADMISSION_NOTICE_BODY_ANCHOR_IDS_V1",
    "ADMISSION_NOTICE_TEMPLATE_ANCHOR_IDS_V1",
    "ADMISSION_NOTICE_TEMPLATE_DESCRIPTOR_SCHEMA_VERSION_V1",
    "ADMISSION_NOTICE_TEMPLATE_MATCH_SCHEMA_VERSION_V1",
    "HBTC_ADMISSION_NOTICE_EXTRACTOR_ID_V1",
    "HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1",
    "HBTC_ADMISSION_NOTICE_TEMPLATE_ID_V1",
    "HBTC_ADMISSION_NOTICE_TEMPLATE_MATCH_RULE_VERSION_V1",
    "HBTC_ADMISSION_NOTICE_TEMPLATE_V1",
    "INSTITUTION_HEADING_ANCHOR_ID_V1",
    "MAJOR_STUDY_ANCHOR_ID_V1",
    "MINIMUM_ADMISSION_NOTICE_BODY_ANCHORS_V1",
    "STUDENT_SALUTATION_ANCHOR_ID_V1",
    "AdmissionNoticeTemplateMatchStatusV1",
    "AdmissionNoticeTemplateMatchV1",
    "AdmissionNoticeTemplateV1",
]

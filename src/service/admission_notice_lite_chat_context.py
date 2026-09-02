"""Sanitized structured result exposed by Admission Notice Lite recognition."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

from service.admission_notice_lite_major_catalog import (
    SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1,
    SupportedTrafficInformationMajorLiteV1,
)
from service.admission_notice_lite_semantics import (
    COLLEGE_NAME_LITE_V1,
    INSTITUTION_NAME_LITE_V1,
    AdmissionNoticeResultLiteV1,
)

ADMISSION_CONTEXT_SCHEMA_VERSION_V1 = "admission_context_v1"

_MAX_NAME_CHARACTERS = 32
_MAX_PROVINCE_CHARACTERS = 16


def _contains_forbidden_control(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _validate_optional_field(
    value: str | None,
    *,
    field_name: str,
    max_characters: int,
) -> None:
    if value is None:
        return
    if (
        type(value) is not str
        or not 1 <= len(value) <= max_characters
        or _contains_forbidden_control(value)
    ):
        raise ValueError(f"admission-notice {field_name} is invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class AdmissionContextV1:
    """Immutable public DTO containing only the sanitized L4 projection."""

    schema_version: str = field(repr=False)
    institution_name: str = field(repr=False)
    college: str = field(repr=False)
    name: str | None = field(repr=False)
    source_province: str | None = field(repr=False)
    major: SupportedTrafficInformationMajorLiteV1 = field(repr=False)

    def __post_init__(self) -> None:
        if self.schema_version != ADMISSION_CONTEXT_SCHEMA_VERSION_V1:
            raise ValueError("admission context schema version is invalid")
        if type(self.institution_name) is not str or (
            self.institution_name != INSTITUTION_NAME_LITE_V1
        ):
            raise ValueError("trusted admission-notice institution is invalid")
        if type(self.college) is not str or self.college != COLLEGE_NAME_LITE_V1:
            raise ValueError("trusted admission-notice college is invalid")
        _validate_optional_field(
            self.name,
            field_name="name",
            max_characters=_MAX_NAME_CHARACTERS,
        )
        _validate_optional_field(
            self.source_province,
            field_name="source province",
            max_characters=_MAX_PROVINCE_CHARACTERS,
        )
        if (
            type(self.major) is not str
            or self.major not in SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1
        ):
            raise ValueError("admission-notice major is unsupported")

    @classmethod
    def from_result(
        cls,
        result: AdmissionNoticeResultLiteV1,
    ) -> AdmissionContextV1:
        if type(result) is not AdmissionNoticeResultLiteV1:
            raise TypeError("expected exact AdmissionNoticeResultLiteV1")
        return cls(
            schema_version=ADMISSION_CONTEXT_SCHEMA_VERSION_V1,
            institution_name=result.institution_name,
            college=result.college,
            name=result.name,
            source_province=result.source_province,
            major=result.major,
        )

    def to_public_dict(self) -> dict[str, str]:
        fields = {
            "schema_version": self.schema_version,
            "institution_name": self.institution_name,
            "college": self.college,
        }
        if self.name is not None:
            fields["name"] = self.name
        if self.source_province is not None:
            fields["source_province"] = self.source_province
        fields["major"] = self.major
        return fields


__all__ = [
    "ADMISSION_CONTEXT_SCHEMA_VERSION_V1",
    "AdmissionContextV1",
]

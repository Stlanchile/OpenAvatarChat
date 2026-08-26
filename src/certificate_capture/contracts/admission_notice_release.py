"""Public-safe, single-purpose admission-notice release contract."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from certificate_capture.contracts.admission_notice import (
    MAX_ADMISSION_COLLEGE_CODEPOINTS_V1,
    MAX_ADMISSION_MAJOR_CODEPOINTS_V1,
    MAX_ADMISSION_NAME_CODEPOINTS_V1,
    MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1,
)
from certificate_capture.contracts.admission_notice_template import (
    HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1,
)
from chat_engine.security.envelope import (
    ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1,
)

SANITIZED_ADMISSION_CONTEXT_SCHEMA_VERSION_V1 = "oac.sanitized-admission-context.v1"


def _require_released_text_v1(
    name: str,
    value: object,
    maximum_codepoints: int,
) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be non-empty text")
    if len(value) > maximum_codepoints:
        raise ValueError(f"{name} exceeds its field bound")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError(f"{name} contains invalid Unicode") from None
    if len(encoded) > 4 * maximum_codepoints:
        raise ValueError(f"{name} exceeds its byte bound")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError(f"{name} contains a control character")
    return value


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class SanitizedAdmissionContextV1:
    """The complete allowlist that may cross the M7 release boundary."""

    institution_name: str
    name: str | None = None
    source_province: str | None = None
    college: str | None = None
    major: str | None = None
    schema_version: str = SANITIZED_ADMISSION_CONTEXT_SCHEMA_VERSION_V1

    def __post_init__(self) -> None:
        if self.schema_version != SANITIZED_ADMISSION_CONTEXT_SCHEMA_VERSION_V1:
            raise ValueError("unsupported sanitized admission schema")
        if self.institution_name != HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1:
            raise ValueError("unsupported trusted institution")
        _require_released_text_v1(
            "institution_name",
            self.institution_name,
            len(HBTC_ADMISSION_NOTICE_INSTITUTION_NAME_V1),
        )
        if all(
            value is None
            for value in (
                self.name,
                self.source_province,
                self.college,
                self.major,
            )
        ):
            raise ValueError("sanitized admission context requires one field")
        for field_name, value, maximum in (
            ("name", self.name, MAX_ADMISSION_NAME_CODEPOINTS_V1),
            (
                "source_province",
                self.source_province,
                MAX_ADMISSION_SOURCE_PROVINCE_CODEPOINTS_V1,
            ),
            ("college", self.college, MAX_ADMISSION_COLLEGE_CODEPOINTS_V1),
            ("major", self.major, MAX_ADMISSION_MAJOR_CODEPOINTS_V1),
        ):
            if value is not None:
                _require_released_text_v1(
                    field_name,
                    value,
                    maximum,
                )

    @property
    def released_field_count_v1(self) -> int:
        return sum(
            value is not None
            for value in (
                self.name,
                self.source_province,
                self.college,
                self.major,
            )
        )

    def canonical_object_v1(self) -> dict[str, str]:
        result = {
            "institution_name": self.institution_name,
            "schema_version": self.schema_version,
        }
        for field_name in (
            "name",
            "source_province",
            "college",
            "major",
        ):
            value = getattr(self, field_name)
            if value is not None:
                result[field_name] = value
        return result

    def __repr__(self) -> str:
        return (
            "SanitizedAdmissionContextV1("
            f"schema_version={self.schema_version!r}, "
            f"released_field_count={self.released_field_count_v1}, "
            "values=<redacted>)"
        )


__all__ = [
    "ADMISSION_NOTICE_SAFE_RELEASE_POLICY_VERSION_V1",
    "SANITIZED_ADMISSION_CONTEXT_SCHEMA_VERSION_V1",
    "SanitizedAdmissionContextV1",
]

from __future__ import annotations

from typing import Literal, TypeAlias, cast

SupportedTrafficInformationMajorLiteV1: TypeAlias = Literal[
    "人工智能技术应用",
    "计算机网络技术",
    "物联网应用技术",
    "计算机网络技术(3+2)",
    "智能交通技术(专本联合培养)",
    "智能交通技术",
    "电子商务(3+2)",
]

SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1 = (
    "人工智能技术应用",
    "计算机网络技术",
    "物联网应用技术",
    "计算机网络技术(3+2)",
    "智能交通技术(专本联合培养)",
    "智能交通技术",
    "电子商务(3+2)",
)

_SUPPORTED_MAJOR_SET_V1 = frozenset(SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1)
_STRUCTURAL_TRANSLATION_V1 = str.maketrans(
    {
        "（": "(",
        "）": ")",
        "２": "2",
        "３": "3",
        "＋": "+",
    }
)
_STRUCTURAL_CHARACTERS_V1 = frozenset("()+23")


def normalize_supported_major_candidate_lite_v1(
    candidate: str,
) -> str:
    """Apply only the closed structural normalization allowed by Lite v1."""

    if type(candidate) is not str:
        raise TypeError("major candidate must be a string")
    translated = candidate.translate(_STRUCTURAL_TRANSLATION_V1).strip()
    normalized: list[str] = []
    for index, character in enumerate(translated):
        if character.isspace():
            previous = translated[index - 1] if index else ""
            following = translated[index + 1] if index + 1 < len(translated) else ""
            if (
                previous in _STRUCTURAL_CHARACTERS_V1
                or following in _STRUCTURAL_CHARACTERS_V1
            ):
                continue
        normalized.append(character)
    return "".join(normalized)


def canonical_supported_major_lite_v1(
    candidate: str,
) -> SupportedTrafficInformationMajorLiteV1 | None:
    normalized = normalize_supported_major_candidate_lite_v1(candidate)
    if normalized not in _SUPPORTED_MAJOR_SET_V1:
        return None
    return cast(SupportedTrafficInformationMajorLiteV1, normalized)


__all__ = [
    "SUPPORTED_TRAFFIC_INFORMATION_MAJORS_V1",
    "SupportedTrafficInformationMajorLiteV1",
    "canonical_supported_major_lite_v1",
    "normalize_supported_major_candidate_lite_v1",
]

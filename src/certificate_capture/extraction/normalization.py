"""Closed conservative normalization rules for admission notices."""

from __future__ import annotations

import unicodedata

_ANCHOR_TRANSLATION_V1 = str.maketrans(
    {
        "：": ":",
        "﹕": ":",
        "（": "(",
        "）": ")",
        "﹙": "(",
        "﹚": ")",
        "，": ",",
        "﹐": ",",
    }
)

_STRUCTURAL_SURROUNDING_PUNCTUATION_V1 = frozenset(
    {
        " ",
        "\t",
        "\r",
        "\n",
        ":",
        "：",
        "﹕",
        ",",
        "，",
        "﹐",
        "。",
        ";",
        "；",
        "、",
    }
)


def is_unicode_whitespace_v1(character: str) -> bool:
    return character.isspace() or unicodedata.category(character) == "Zs"


def normalize_layout_text_v1(value: str) -> str:
    """Collapse Unicode layout whitespace without changing other characters."""

    pieces: list[str] = []
    pending_space = False
    for character in value:
        if is_unicode_whitespace_v1(character):
            pending_space = bool(pieces)
            continue
        if pending_space:
            pieces.append(" ")
            pending_space = False
        pieces.append(character)
    return "".join(pieces)


def canonical_anchor_character_v1(character: str) -> str:
    """Canonicalize only the allowlisted structural punctuation."""

    return character.translate(_ANCHOR_TRANSLATION_V1)


def canonical_anchor_text_v1(value: str) -> str:
    """Remove layout whitespace and canonicalize closed anchor punctuation."""

    return "".join(
        canonical_anchor_character_v1(character)
        for character in value
        if not is_unicode_whitespace_v1(character)
    )


def strip_structural_surrounding_v1(value: str) -> str:
    """Strip only allowlisted surrounding layout punctuation."""

    start = 0
    end = len(value)
    while start < end and value[start] in _STRUCTURAL_SURROUNDING_PUNCTUATION_V1:
        start += 1
    while end > start and value[end - 1] in _STRUCTURAL_SURROUNDING_PUNCTUATION_V1:
        end -= 1
    return value[start:end]


def normalize_candidate_whitespace_v1(value: str) -> str:
    """Collapse source whitespace while preserving one internal ASCII space."""

    return strip_structural_surrounding_v1(normalize_layout_text_v1(value))


def contains_forbidden_control_v1(value: str) -> bool:
    """Reject controls, surrogates, private-use, and formatting controls."""

    return any(unicodedata.category(character).startswith("C") for character in value)


def is_han_character_v1(character: str) -> bool:
    codepoint = ord(character)
    return bool(
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x20000 <= codepoint <= 0x2FA1F
    )


__all__ = [
    "canonical_anchor_character_v1",
    "canonical_anchor_text_v1",
    "contains_forbidden_control_v1",
    "is_han_character_v1",
    "is_unicode_whitespace_v1",
    "normalize_candidate_whitespace_v1",
    "normalize_layout_text_v1",
    "strip_structural_surrounding_v1",
]

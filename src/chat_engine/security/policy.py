"""Pure V1 classification and consumer authorization policy."""

from __future__ import annotations

from collections.abc import Iterable

from chat_engine.security.envelope import (
    EgressPolicyV1,
    RetentionPolicyV1,
    SecurityClassificationV1,
)

_CLASSIFICATION_RANK_V1 = {
    SecurityClassificationV1.PUBLIC_CHAT: 0,
    SecurityClassificationV1.CERTIFICATE_PRIVATE: 1,
}


def most_restrictive_classification_v1(
    classifications: Iterable[SecurityClassificationV1],
) -> SecurityClassificationV1:
    """Return the most restrictive V1 classification, defaulting to public."""

    result = SecurityClassificationV1.PUBLIC_CHAT
    for classification in classifications:
        if _CLASSIFICATION_RANK_V1[classification] > _CLASSIFICATION_RANK_V1[result]:
            result = classification
    return result


def classification_is_at_least_v1(
    candidate: SecurityClassificationV1,
    required: SecurityClassificationV1,
) -> bool:
    return _CLASSIFICATION_RANK_V1[candidate] >= _CLASSIFICATION_RANK_V1[required]


def retention_policy_for_v1(
    classification: SecurityClassificationV1,
) -> RetentionPolicyV1:
    if classification is SecurityClassificationV1.CERTIFICATE_PRIVATE:
        return RetentionPolicyV1.EPHEMERAL_NO_GENERIC_RETENTION
    return RetentionPolicyV1.LEGACY_SESSION


def egress_policy_for_v1(
    classification: SecurityClassificationV1,
) -> EgressPolicyV1:
    if classification is SecurityClassificationV1.CERTIFICATE_PRIVATE:
        return EgressPolicyV1.INTERNAL_ONLY
    return EgressPolicyV1.GENERIC
